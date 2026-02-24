#!/usr/bin/env python3
"""
ClawEDR macOS Shield Log Tailer.

Monitors the macOS Unified Log for Seatbelt sandbox violations and
watches for policy updates.

Because sandbox-exec profiles are bound at process start, macOS cannot
hot-reload — this script notifies the user to restart OpenClaw when new
threat intelligence is available.
"""

import json
import logging
import os
import subprocess
import sys
import time

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


def tail_sandbox_log():
    """Stream macOS sandbox violation events from the Unified Log."""
    cmd = [
        "log", "stream", "--style", "compact",
        "--predicate", 'subsystem == "com.apple.sandbox.reporter"',
    ]
    logger.info("Starting log stream: %s", " ".join(cmd))

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        for line in proc.stdout:
            line = line.strip()
            if line:
                logger.info("SANDBOX EVENT: %s", line)
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()


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
    """Configure logging to macOS Console.app via os_log when pyoslog is available."""
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")

    try:
        import pyoslog
        if pyoslog.is_supported():
            handler = pyoslog.Handler()
            handler.setSubsystem(OSLOG_SUBSYSTEM, OSLOG_CATEGORY)
            root.addHandler(handler)
            return
    except ImportError:
        pass

    # Fallback: stderr (goes to /tmp/clawedr_log_tailer.log when run by shield_mac.sh)
    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(fmt)
    root.addHandler(stream)


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
