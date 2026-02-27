"""
ClawEDR Alert Dispatcher — out-of-band OpenClaw chat integration.

Pushes EDR violation alerts into the active OpenClaw session via the
``openclaw agent --deliver`` CLI. Works identically on Linux and macOS.

The dispatcher discovers the most recently active OpenClaw session by
querying ``openclaw sessions --active 5 --json`` and uses its session ID
to route the alert.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import threading
import time

logger = logging.getLogger("clawedr.alert_dispatcher")

POLICY_PATH = os.environ.get(
    "CLAWEDR_POLICY_PATH", "/usr/local/share/clawedr/compiled_policy.json"
)

# Minimum interval between two dispatches (rate-limit, seconds)
_MIN_DISPATCH_INTERVAL = 2.0
_last_dispatch: float = 0.0
_lock = threading.Lock()


def _find_openclaw() -> str | None:
    """Return the path to the openclaw CLI, or None."""
    return shutil.which("openclaw")


def _get_openclaw_cmd(base_cmd: list[str], as_root: bool = False) -> tuple[list[str], dict | None]:
    """Return (cmd, env) to run openclaw. as_root=True skips sudo (for root-run gateways)."""
    import os, pwd, platform as _platform
    cmd = base_cmd.copy()
    env = None
    if as_root or os.getuid() != 0:
        return cmd, env
    run_user = os.environ.get("SUDO_USER")
    if not run_user:
        for pw in pwd.getpwall():
            if pw.pw_uid >= 500 and pw.pw_uid < 65534 and pw.pw_shell not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin"):
                run_user = pw.pw_name
                break
    if run_user:
        pw = pwd.getpwnam(run_user)
        env = os.environ.copy()
        env["HOME"] = pw.pw_dir
        env["USER"] = run_user
        if _platform.system() == "Linux":
            cmd = ["sudo", "-u", run_user, "--"] + cmd
    return cmd, env


def _get_rule_metadata(rule_id: str) -> tuple[str | None, str | None]:
    """Load policy and return (description, severity) for rule_id.

    For user-generated custom rules (USR-*), metadata is read from user_rules.yaml.
    For built-in rules, metadata comes from compiled_policy.json.
    """
    # User-generated custom rules: metadata from user_rules.yaml
    if rule_id.startswith("USR-"):
        try:
            from shared.user_rules import get_custom_rule_metadata
            return get_custom_rule_metadata(rule_id)
        except ImportError:
            pass

    # Built-in rules: metadata from compiled policy
    try:
        with open(POLICY_PATH) as f:
            policy = json.load(f)
        meta = policy.get("rule_metadata", {}).get(rule_id, {})
        if isinstance(meta, dict):
            return meta.get("description"), meta.get("severity")
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return None, None


def _get_active_session() -> tuple[dict | None, bool]:
    """Query OpenClaw for the most recently active session.

    Returns (session_dict, use_root) or (None, False).
    When running as root, tries root's sessions first (gateway often runs as root
    in server/VM setups). use_root indicates which context to use for dispatch.
    """
    openclaw = _find_openclaw()
    if not openclaw:
        return None, False

    # When root: try root first (common when gateway runs as root), then try run_user
    attempts = []
    if os.getuid() == 0:
        attempts.append((True,))   # as_root=True
    attempts.append((False,))      # as_root=False

    for (as_root,) in attempts:
        try:
            cmd, env = _get_openclaw_cmd(
                [openclaw, "sessions", "--active", "1440", "--json"],
                as_root=as_root,
            )
            result = subprocess.run(
                cmd,
                env=env,
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0:
                continue

            data = json.loads(result.stdout)
            sessions = data.get("sessions", [])
            if not sessions:
                continue

            return sessions[0], as_root
        except Exception as exc:
            logger.debug("Failed to query OpenClaw sessions (as_root=%s): %s", as_root, exc)
            continue

    return None, False


def dispatch_alert(
    rule_id: str,
    action: str,
    target: str,
    pid: int | None = None,
    comm: str | None = None,
) -> bool:
    """Send an EDR alert to the active OpenClaw session.

    Args:
        rule_id: The Rule ID that caused the block (e.g. BIN-001).
        action:  What was blocked (e.g. "execve", "file-read", "deny_rule").
        target:  The blocked file/executable/command.
        pid:     PID of the blocked process (optional).
        comm:    Command name of the blocked process (optional).

    Returns True if the alert was dispatched, False otherwise.
    """
    global _last_dispatch

    with _lock:
        now = time.monotonic()
        if now - _last_dispatch < _MIN_DISPATCH_INTERVAL:
            logger.debug("Rate-limited, skipping alert dispatch")
            return False
        _last_dispatch = now

    openclaw = _find_openclaw()
    if not openclaw:
        logger.debug("openclaw CLI not found — alert dispatch skipped")
        return False

    session, use_root = _get_active_session()
    if not session:
        logger.debug("No active OpenClaw session — alert dispatch skipped")
        return False

    description, severity = _get_rule_metadata(rule_id)
    severity_label = f"[{severity.upper()}]" if severity else ""

    # Build alert message
    parts = [f"🚨 **ClawEDR Alert** {severity_label} [{rule_id}]: Blocked `{action}` → `{target}`"]
    if description:
        parts.append(f"**Why blocked:** {description}")
    if pid is not None:
        parts.append(f"PID={pid}")
    if comm:
        parts.append(f"comm={comm}")
    message = "\n".join(parts)

    # Build CLI command (use same user context as session lookup)
    base_cmd = [
        openclaw, "agent",
        "--message", message,
        "--deliver",
        "--session-id", str(session.get("sessionId", session.get("id", ""))),
    ]
    channel = session.get("channel")
    if channel:
        base_cmd.extend(["--reply-channel", channel])

    cmd, env = _get_openclaw_cmd(base_cmd, as_root=use_root)

    try:
        subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        logger.info("Alert dispatched to session %s: %s", session.get("id"), message)
        return True
    except Exception as exc:
        logger.warning("Failed to dispatch alert: %s", exc)
        return False


def dispatch_alert_async(
    rule_id: str,
    action: str,
    target: str,
    pid: int | None = None,
    comm: str | None = None,
) -> None:
    """Fire-and-forget version of dispatch_alert (runs in a thread)."""
    t = threading.Thread(
        target=dispatch_alert,
        args=(rule_id, action, target, pid, comm),
        daemon=True,
    )
    t.start()
