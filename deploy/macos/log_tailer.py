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
from shared.user_rules import get_custom_rules, USER_RULES_PATH

logger = logging.getLogger("clawedr.log_tailer")
block_logger = logging.getLogger("clawedr.blocked")

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
BLOCK_LOG_FILE = "/var/log/clawedr.log"

# Regex to extract blocked path/process from sandbox violation log lines
_DENY_RE = re.compile(r"deny\(?\d*\)?\s+([\w\-\*]+)\s+(.*)", re.IGNORECASE)


def _load_policy_rule_index() -> dict:
    """Load compiled_policy.json to allow cross-referencing sandbox violations."""
    try:
        with open(POLICY_PATH) as f:
            policy = json.load(f)
            
        # Merge in custom user rules to the runtime mapping payload
        custom_rules = get_custom_rules()
        for rule in custom_rules:
            rid = rule.get("id", "")
            rtype = rule.get("type", "")
            val = rule.get("value", "")
            plat = rule.get("platform", "both")
            if plat not in ("both", "macos") or not rid:
                continue
                
            if rtype == "executable":
                policy.setdefault("blocked_executables", {})[rid] = val
            elif rtype == "argument":
                policy.setdefault("deny_rules", {}).setdefault("macos", {})[rid] = val
                
        return policy
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        logger.warning("Could not load policy for rule index: %s", exc)
        return {}


def tail_sandbox_log():
    """Poll macOS sandbox violation events from the Unified Log."""
    last_mtime = 0.0
    rule_index = _load_policy_rule_index()
    seen_events = set()
    logger.info("Starting log show polling for sandbox reporting...")

    from datetime import datetime, timedelta
    import time

    while True:
        try:
            # Refresh rule index if policy or user rules changed
            changed, last_mtime = check_for_policy_update(last_mtime)
            if changed:
                logger.info("Policy or user rules updated, reloading rule index...")
                rule_index = _load_policy_rule_index()

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

                logger.debug("SANDBOX EVENT: %s", line)

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
                    block_logger.warning("BLOCKED [%s] action=%s target=%s", rule_id, action, target)

                    dispatch_alert_async(
                        rule_id=rule_id,
                        action=action,
                        target=target,
                    )
        except Exception as e:
            logger.error("Error polling log show: %s", str(e))
        
        time.sleep(5)


def check_for_policy_update(last_mtime: float) -> tuple[bool, float]:
    """Check if the system policy or user rules have been updated since last_mtime."""
    mtimes = []
    
    for path in (POLICY_PATH, USER_RULES_PATH):
        try:
            mtimes.append(os.path.getmtime(path))
        except FileNotFoundError:
            pass
            
    if not mtimes:
        return (False, last_mtime)
        
    current_max_mtime = max(mtimes)
    
    if current_max_mtime != last_mtime:
        return (True, current_max_mtime)
        
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

    # Dedicated alert logging to /var/log/clawedr.log (persistent)
    block_logger.setLevel(logging.WARNING)
    block_logger.propagate = False
    block_logger.addHandler(stream) # Also log to stderr for visibility in /tmp log
    try:
        block_fh = logging.FileHandler(BLOCK_LOG_FILE)
        block_fh.setFormatter(fmt)
        block_logger.addHandler(block_fh)
    except PermissionError:
        logger.warning("Cannot write to %s — block file logging disabled", BLOCK_LOG_FILE)

    try:
        import pyoslog
        if pyoslog.is_supported():
            handler = pyoslog.Handler()
            handler.setSubsystem(OSLOG_SUBSYSTEM, OSLOG_CATEGORY)
            root.addHandler(handler)
    except ImportError:
        pass


def monitor_network_connections() -> None:
    """Poll OpenClaw's network connections via lsof and check against blocked domains/IPs.

    This is a monitoring-only capability on macOS since Seatbelt cannot
    filter by specific IP or hostname. We discover OpenClaw PIDs, list
    their TCP connections, do reverse DNS on the destination IPs, and
    raise alerts for any connections to blocked domains or IPs.
    """
    import socket

    NET_POLL_INTERVAL = 10  # seconds between network checks
    rule_index: dict = {}
    blocked_domains: dict = {}  # DOM-xxx -> hostname
    blocked_ips: dict = {}      # IP-xxx -> ip string
    # Also include custom user rules of type "domain"
    seen_alerts: set = set()    # (rule_id, ip) -> avoid repeated alerts
    last_mtime = 0.0

    logger.info("Network connection monitor starting (poll every %ds)", NET_POLL_INTERVAL)

    while True:
        try:
            # Reload policy if changed
            changed, last_mtime = check_for_policy_update(last_mtime)
            if changed or not blocked_domains:
                try:
                    with open(POLICY_PATH) as f:
                        policy = json.load(f)
                    blocked_domains = policy.get("blocked_domains", {})
                    blocked_ips = policy.get("blocked_ips", {})
                    # Add custom user domain rules
                    for rule in get_custom_rules():
                        if rule.get("type") == "domain" and rule.get("value"):
                            rid = rule.get("id", "USR-DOM-?")
                            val = rule["value"]
                            # If it looks like an IP, add to blocked_ips
                            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val):
                                blocked_ips[rid] = val
                            else:
                                blocked_domains[rid] = val
                    logger.info(
                        "Network monitor loaded %d blocked domains, %d blocked IPs",
                        len(blocked_domains), len(blocked_ips),
                    )
                except Exception as e:
                    logger.warning("Could not reload policy for network monitor: %s", e)

            if not blocked_domains and not blocked_ips:
                time.sleep(NET_POLL_INTERVAL)
                continue

            # Discover OpenClaw PIDs
            try:
                pids_out = subprocess.run(
                    ["pgrep", "-f", "openclaw"],
                    capture_output=True, text=True,
                )
                pids = [p.strip() for p in pids_out.stdout.strip().splitlines() if p.strip()]
            except Exception:
                pids = []

            if not pids:
                time.sleep(NET_POLL_INTERVAL)
                continue

            # Get network connections for those PIDs
            try:
                lsof_cmd = ["lsof", "-i", "-P", "-n"] + [
                    arg for pid in pids for arg in ["-p", pid]
                ]
                lsof_out = subprocess.run(
                    lsof_cmd, capture_output=True, text=True, timeout=10,
                )
            except Exception as e:
                logger.debug("lsof failed: %s", e)
                time.sleep(NET_POLL_INTERVAL)
                continue

            # Parse lsof output for ESTABLISHED TCP connections
            # Format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
            # NAME looks like: 1.2.3.4:443->5.6.7.8:12345 (ESTABLISHED)
            ip_re = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)")

            for line in lsof_out.stdout.splitlines():
                if "TCP" not in line:
                    continue
                parts = line.split()
                if len(parts) < 9:
                    continue
                name = parts[-1] if parts[-1] != "(ESTABLISHED)" else parts[-2]
                # Extract remote IP from "local->remote" format
                if "->" in name:
                    remote_part = name.split("->")[1]
                else:
                    remote_part = name
                m = ip_re.search(remote_part)
                if not m:
                    continue
                remote_ip = m.group(1)

                # Skip loopback and private
                if remote_ip.startswith("127.") or remote_ip.startswith("0."):
                    continue

                # 1. Check direct IP match
                for rid, blocked_ip in blocked_ips.items():
                    if remote_ip == blocked_ip:
                        alert_key = (rid, remote_ip)
                        if alert_key not in seen_alerts:
                            seen_alerts.add(alert_key)
                            block_logger.warning(
                                "BLOCKED [%s] action=network-connect target=%s (IP match)",
                                rid, remote_ip,
                            )
                            dispatch_alert_async(
                                rule_id=rid,
                                action="network-connect",
                                target=f"{remote_ip} (direct IP match)",
                            )

                # 2. Reverse DNS and check against blocked domains
                try:
                    hostname, _, _ = socket.gethostbyaddr(remote_ip)
                    hostname = hostname.lower()
                except (socket.herror, socket.gaierror, OSError):
                    hostname = ""

                if hostname:
                    for rid, blocked_domain in blocked_domains.items():
                        if hostname == blocked_domain or hostname.endswith("." + blocked_domain):
                            alert_key = (rid, remote_ip)
                            if alert_key not in seen_alerts:
                                seen_alerts.add(alert_key)
                                block_logger.warning(
                                    "BLOCKED [%s] action=dns-lookup target=%s (resolved from %s)",
                                    rid, blocked_domain, remote_ip,
                                )
                                dispatch_alert_async(
                                    rule_id=rid,
                                    action="dns-lookup",
                                    target=f"{blocked_domain} ({remote_ip})",
                                )

            # Prevent seen_alerts from growing unbounded
            if len(seen_alerts) > 2000:
                seen_alerts.clear()

        except Exception as e:
            logger.error("Network monitor error: %s", e)

        time.sleep(NET_POLL_INTERVAL)


def main() -> int:
    _configure_logging()
    logger.info("ClawEDR macOS Log Tailer starting")

    import threading
    policy_thread = threading.Thread(target=monitor_policy_updates, daemon=True)
    policy_thread.start()

    network_thread = threading.Thread(target=monitor_network_connections, daemon=True)
    network_thread.start()

    tail_sandbox_log()
    return 0


if __name__ == "__main__":
    sys.exit(main())
