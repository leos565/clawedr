#!/usr/bin/env python3
"""
ClawEDR macOS Shield Log Tailer.

Monitors the macOS Unified Log for Seatbelt sandbox violations and
watches for policy updates.

Because sandbox-exec profiles are bound at process start, macOS cannot
hot-reload — this script notifies the user to restart OpenClaw when new
threat intelligence is available.

Integrates with the OpenClaw alert dispatcher to push violation alerts
into the active OpenClaw session.
"""

import json
import logging
import os
import re
import subprocess
import sys
import time

# Add parent directory to path so we can import shared modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.alert_dispatcher import dispatch_alert_async

logger = logging.getLogger("clawedr.log_tailer")

# Subsystem for macOS Console.app filtering (e.g. predicate: subsystem == "com.clawedr.shield")
OSLOG_SUBSYSTEM = "com.clawedr.shield"
OSLOG_CATEGORY = "log_tailer"

POLICY_PATH = os.environ.get(
    "CLAWEDR_POLICY_PATH", "/usr/local/share/clawedr/compiled_policy.json"
)
SEATBELT_PROFILE = os.environ.get(
    "CLAWEDR_SB_PATH", "/usr/local/share/clawedr/clawedr.sb"
)
POLL_INTERVAL = int(os.environ.get("CLAWEDR_POLL_INTERVAL", "10"))

# Regex to extract blocked path/process from sandbox violation log lines
_DENY_RE = re.compile(r"deny\(?\d*\)?\s+([\w\-\*]+)\s+(.*)", re.IGNORECASE)


def _load_policy_rule_index() -> dict:
    """Load compiled_policy.json to allow cross-referencing sandbox violations."""
    try:
        with open(POLICY_PATH) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        logger.warning("Could not load policy for rule index: %s", exc)
        return {}


def tail_sandbox_log():
    """Poll macOS sandbox violation events from the Unified Log."""
    rule_index = _load_policy_rule_index()
    seen_events = set()
    logger.info("Starting log show polling for sandbox reporting...")

    from datetime import datetime, timedelta
    import time

    while True:
        try:
            # Check the last 15 seconds to overlap and avoid missing events
            start_time_str = (datetime.now() - timedelta(seconds=15)).strftime("%Y-%m-%d %H:%M:%S")
            cmd = [
                "log", "show", "--style", "compact",
                "--predicate", 'subsystem == "com.apple.sandbox.reporter" OR subsystem == "com.apple.sandbox.reporting"',
                "--start", start_time_str
            ]
            
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            
            for line in proc.stdout.splitlines():
                line = line.strip()
                # Skip meaningless or already processed lines
                if not line or "Filtering the log data" in line or line in seen_events:
                    continue
                
                seen_events.add(line)
                # Keep the set size manageable
                if len(seen_events) > 5000:
                    seen_events.clear()

                logger.info("SANDBOX EVENT: %s", line)

                # Try to extract what was denied and dispatch an alert
                match = _DENY_RE.search(line)
                if match:
                    action = match.group(1)  # e.g. "file-read-data"
                    target = match.group(2).strip()  # e.g. "/Users/leo/.ssh/id_rsa"

                    # Try to find a matching Rule ID based on strict policy boundaries
                    rule_id = None
                    
                    # 1. Check paths (target must be inside the directory)
                    for rid, path in rule_index.get("blocked_paths", {}).get("macos", {}).items():
                        if target.startswith(path):
                            rule_id = rid
                            break
                    
                    # 2. Check executables (target must be the exact file or end with /file)
                    if not rule_id:
                        for rid, name in rule_index.get("blocked_executables", {}).items():
                            if target == name or target.endswith("/" + name):
                                rule_id = rid
                                break
                                
                    # 3. Check custom deny rules (loose match for fallback custom macros inside strings)
                    if not rule_id:
                        for rid, directive in rule_index.get("deny_rules", {}).get("macos", {}).items():
                            if isinstance(directive, str) and target in directive:
                                rule_id = rid
                                break

                    # Discard system-wide sandbox noise that isn't ours
                    if not rule_id:
                        continue

                    # Log the blocked event in the format expected by the dashboard
                    logger.warning("BLOCKED [%s] action=%s target=%s", rule_id, action, target)

                    dispatch_alert_async(
                        rule_id=rule_id,
                        action=action,
                        target=target,
                    )
        except Exception as e:
            logger.error("Error polling log show: %s", str(e))
        
        time.sleep(5)


def check_for_policy_update(last_mtime: float) -> tuple[bool, float]:
    """Check if the policy file has been updated since last_mtime."""
    try:
        mtime = os.path.getmtime(POLICY_PATH)
        return (mtime != last_mtime, mtime)
    except FileNotFoundError:
        return (False, last_mtime)


def notify_user(message: str) -> None:
    """Send a macOS notification."""
    try:
        subprocess.run(
            [
                "osascript", "-e",
                f'display notification "{message}" with title "ClawEDR"',
            ],
            check=True,
            capture_output=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.warning("Could not send macOS notification, logging instead")
    logger.info("NOTIFICATION: %s", message)


def monitor_policy_updates() -> None:
    """Poll for policy updates and notify the user."""
    last_mtime = 0.0
    logger.info("Monitoring policy at %s (poll every %ds)", POLICY_PATH, POLL_INTERVAL)

    while True:
        changed, last_mtime = check_for_policy_update(last_mtime)
        if changed:
            notify_user(
                "New Threat Intelligence Available. "
                "Please restart OpenClaw to apply kernel-level updates."
            )
        time.sleep(POLL_INTERVAL)


def _configure_logging() -> None:
    """Configure logging to stderr and optionally macOS Console.app."""
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")

    # Always log to stderr (goes to /tmp/clawedr_log_tailer.log when run by shield_mac.sh)
    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(fmt)
    root.addHandler(stream)

    try:
        import pyoslog
        if pyoslog.is_supported():
            handler = pyoslog.Handler()
            handler.setSubsystem(OSLOG_SUBSYSTEM, OSLOG_CATEGORY)
            root.addHandler(handler)
    except ImportError:
        pass


def main() -> int:
    _configure_logging()
    logger.info("ClawEDR macOS Log Tailer starting")

    import threading
    policy_thread = threading.Thread(target=monitor_policy_updates, daemon=True)
    policy_thread.start()

    tail_sandbox_log()
    return 0


if __name__ == "__main__":
    sys.exit(main())
