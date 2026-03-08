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
from shared.policy_verify import verify_policy

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
        ok, msg = verify_policy(policy)
        if not ok:
            logger.error("Policy verification failed in rule index load: %s — using empty index", msg)
            return {}
        logger.debug("Policy verification: %s", msg)
            
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
                # Evict oldest half when set grows too large to prevent unbounded memory use.
                if len(seen_events) > 5000:
                    evict = list(seen_events)[:2500]
                    for e in evict:
                        seen_events.discard(e)

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
                        expanded_path = __import__('os').path.expanduser(path)
                        if target.startswith(expanded_path):
                            rule_id = rid
                            break
                    
                    # 2. Check executables (target must be the exact file or end with /file)
                    if not rule_id:
                        for rid, name in rule_index.get("blocked_executables", {}).items():
                            if target == name or target.endswith("/" + name):
                                rule_id = rid
                                break
                                
                    # 3. Check custom deny rules: the sandbox logs the blocked
                    # target (e.g. a port number or process path). Check whether
                    # the directive contains the target as a meaningful substring,
                    # but only after stripping Seatbelt LISP syntax so we match
                    # on the actual value, not accidentally on punctuation.
                    if not rule_id:
                        import re as _re
                        for rid, directive in rule_index.get("deny_rules", {}).get("macos", {}).items():
                            if not isinstance(directive, str):
                                continue
                            # Extract quoted values from the Seatbelt directive
                            # e.g. (deny network-outbound (remote tcp "*:4444"))
                            # → ["*:4444"]
                            quoted = _re.findall(r'"([^"]+)"', directive)
                            for qval in quoted:
                                # Match if the sandbox target ends with or equals
                                # the directive value (after glob expansion)
                                qval_plain = qval.lstrip("*")
                                if qval_plain and target.endswith(qval_plain):
                                    rule_id = rid
                                    break
                            if rule_id:
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


def _is_private_ip(ip: str) -> bool:
    """Return True for loopback and RFC-1918 private addresses."""
    return (
        ip.startswith("127.")
        or ip.startswith("0.")
        or ip.startswith("10.")
        or ip.startswith("169.254.")  # link-local
        or ip.startswith("::1")
        or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)
        or ip.startswith("192.168.")
    )


def monitor_network_connections() -> None:
    """Poll OpenClaw's network connections via lsof and check against blocked domains/IPs.

    This is a monitoring-only capability on macOS since Seatbelt cannot
    filter by specific IP or hostname. We discover OpenClaw PIDs, list
    their TCP connections, do reverse DNS on the destination IPs, and
    raise alerts for any connections to blocked domains or IPs.
    """
    import socket

    NET_POLL_INTERVAL = 10  # seconds between network checks
    # Max PIDs to pass to a single lsof invocation (prevents unbounded command length)
    _MAX_LSOF_PIDS = 20
    blocked_domains: dict = {}  # DOM-xxx -> hostname
    blocked_ips: dict = {}      # IP-xxx -> ip string
    # (rule_id, ip) -> expiry timestamp; avoids repeated alerts for the same connection
    seen_alerts: dict[tuple, float] = {}
    _ALERT_TTL = 300.0  # seconds before re-alerting on the same (rule, ip) pair
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
                    ok, msg = verify_policy(policy)
                    if not ok:
                        logger.error("Policy verification failed in network monitor: %s — skipping reload", msg)
                        time.sleep(NET_POLL_INTERVAL)
                        continue
                    blocked_domains = policy.get("blocked_domains", {})
                    blocked_ips = policy.get("blocked_ips", {})
                    # Add custom user domain and IP rules
                    for rule in get_custom_rules():
                        rtype = rule.get("type")
                        val = rule.get("value")
                        if not val:
                            continue
                        rid = rule.get("id", "USR-?")
                        if rtype == "domain":
                            blocked_domains[rid] = val
                        elif rtype == "ip":
                            blocked_ips[rid] = val
                    logger.info(
                        "Network monitor loaded %d blocked domains, %d blocked IPs",
                        len(blocked_domains), len(blocked_ips),
                    )
                except Exception as e:
                    logger.warning("Could not reload policy for network monitor: %s", e)

            if not blocked_domains and not blocked_ips:
                time.sleep(NET_POLL_INTERVAL)
                continue

            # Expire old seen_alerts entries
            now = time.monotonic()
            seen_alerts = {k: v for k, v in seen_alerts.items() if v > now}

            # Discover OpenClaw PIDs — match on the full binary path to avoid false
            # positives from filenames containing "openclaw" (e.g. in editor buffers).
            try:
                pids_out = subprocess.run(
                    ["pgrep", "-x", "OpenClaw"],
                    capture_output=True, text=True,
                )
                if not pids_out.stdout.strip():
                    # Fallback: match process name containing openclaw (case-insensitive)
                    pids_out = subprocess.run(
                        ["pgrep", "-fi", "/openclaw"],
                        capture_output=True, text=True,
                    )
                pids = [p.strip() for p in pids_out.stdout.strip().splitlines() if p.strip()]
            except Exception:
                pids = []

            if not pids:
                time.sleep(NET_POLL_INTERVAL)
                continue

            # Batch lsof invocations to avoid unbounded command-line length
            all_lsof_output: list[str] = []
            for i in range(0, min(len(pids), _MAX_LSOF_PIDS), 20):
                batch = pids[i:i + 20]
                try:
                    lsof_cmd = ["lsof", "-i", "-P", "-n"] + [
                        arg for pid in batch for arg in ["-p", pid]
                    ]
                    lsof_out = subprocess.run(
                        lsof_cmd, capture_output=True, text=True, timeout=10,
                    )
                    all_lsof_output.extend(lsof_out.stdout.splitlines())
                except Exception as e:
                    logger.debug("lsof batch failed: %s", e)

            if len(pids) > _MAX_LSOF_PIDS:
                logger.warning("Found %d OpenClaw PIDs; only checking first %d", len(pids), _MAX_LSOF_PIDS)

            # Parse lsof output for TCP connections (any state)
            # Format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME (STATE)
            # NAME looks like: 192.168.1.1:54321->104.22.10.63:443
            # STATE can be: (ESTABLISHED), (SYN_SENT), (CLOSE_WAIT), (LISTEN), etc.
            ip_re = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)")

            for line in all_lsof_output:
                if "TCP" not in line:
                    continue
                # Skip LISTEN sockets (incoming, not outbound connections)
                if "(LISTEN)" in line:
                    continue
                parts = line.split()
                if len(parts) < 9:
                    continue
                # The connection info is the second-to-last field if state is present,
                # or the last field if no state. State is always in parens.
                name = parts[-2] if parts[-1].startswith("(") else parts[-1]
                # Extract remote IP from "local->remote" format
                if "->" in name:
                    remote_part = name.split("->")[1]
                else:
                    remote_part = name
                m = ip_re.search(remote_part)
                if not m:
                    continue
                remote_ip = m.group(1)

                # Skip loopback and all RFC-1918 / link-local private ranges
                if _is_private_ip(remote_ip):
                    continue

                # 1. Check direct IP match
                for rid, blocked_ip in blocked_ips.items():
                    if remote_ip == blocked_ip:
                        alert_key = (rid, remote_ip)
                        if alert_key not in seen_alerts:
                            seen_alerts[alert_key] = now + _ALERT_TTL
                            block_logger.warning(
                                "WARNING [%s] action=network-connect target=%s (IP match, monitoring-only)",
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
                                seen_alerts[alert_key] = now + _ALERT_TTL
                                block_logger.warning(
                                    "WARNING [%s] action=dns-lookup target=%s (resolved from %s, monitoring-only)",
                                    rid, blocked_domain, remote_ip,
                                )
                                dispatch_alert_async(
                                    rule_id=rid,
                                    action="dns-lookup",
                                    target=f"{blocked_domain} ({remote_ip})",
                                )

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
