#!/usr/bin/env python3
"""
ClawEDR Local Dashboard — FastAPI backend.

Serves a browser-based UI for viewing alerts, managing rules, and
controlling user exemptions.

Endpoints:
  GET  /                — Dashboard UI
  GET  /api/alerts      — Recent blocked actions from logs
  GET  /api/rules       — Current compiled policy with Rule IDs
  GET  /api/user-rules  — User exemptions from ~/.clawedr/user_rules.yaml
  POST /api/user-rules  — Update user exemptions
  GET  /api/status      — Shield health status
"""

from __future__ import annotations

import json
import logging
import os
import re
import signal
import sys
from pathlib import Path

from typing import Optional
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

# Add parent directory to path so we can import shared modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.user_rules import (
    load_user_rules, save_user_rules, USER_RULES_PATH,
    add_custom_rule, update_custom_rule, delete_custom_rule,
    get_custom_rules, get_custom_rule_metadata, CUSTOM_RULE_TYPES,
)

logger = logging.getLogger("clawedr.dashboard")

app = FastAPI(title="ClawEDR Dashboard", version="1.0.0")

POLICY_PATH = os.environ.get(
    "CLAWEDR_POLICY_PATH", "/usr/local/share/clawedr/compiled_policy.json"
)
# Fallback to the deploy directory for development
if not os.path.exists(POLICY_PATH):
    POLICY_PATH = os.path.join(os.path.dirname(__file__), "..", "compiled_policy.json")

BLOCK_LOG_PATHS = [
    "/var/log/clawedr.log",
    os.path.expanduser("~/Library/Logs/clawedr.log"),
    "/tmp/clawedr_log_tailer.log",
]

_BLOCK_LINE_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[,.]?\d*)\s+"
    r"WARNING\s+\[[\w.]+\]\s+"
    r"(?:BLOCKED|WARNING)\s+\[([A-Z0-9_-]+)\]\s+(.*)"
)


def _load_rule_metadata() -> dict:
    """Load rule_metadata from compiled policy, merged with user custom rule metadata."""
    metadata: dict = {}
    try:
        with open(POLICY_PATH) as f:
            policy = json.load(f)
        metadata = dict(policy.get("rule_metadata", {}))
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    # Merge in metadata for user-generated custom rules (USR-*)
    for rule in get_custom_rules():
        rid = rule.get("id")
        if rid and rid.startswith("USR-"):
            desc = rule.get("description")
            sev = rule.get("severity")
            if desc or sev:
                metadata[rid] = {
                    "description": desc or "",
                    "severity": sev or "unknown",
                }
    return metadata


def _find_openclaw() -> Optional[str]:
    """Find the openclaw executable, falling back to typical install paths."""
    import shutil
    import os
    oc = shutil.which("openclaw")
    if oc:
        return oc
    for p in ["/usr/local/bin/openclaw", "/opt/homebrew/bin/openclaw"]:
        if os.path.exists(p) and os.access(p, os.X_OK):
            return p
    return None


def _parse_log_lines(max_lines: int = 1000) -> list[dict]:
    """Parse recent BLOCKED entries from the log files."""
    import datetime
    alerts: list[dict] = []
    for log_path in BLOCK_LOG_PATHS:
        if not os.path.exists(log_path):
            continue
        try:
            with open(log_path) as f:
                lines = f.readlines()
            for line in lines[-max_lines:]:
                m = _BLOCK_LINE_RE.search(line)
                if m:
                    alerts.append({
                        "timestamp": m.group(1),
                        "rule_id": m.group(2),
                        "details": m.group(3).strip(),
                    })
        except (PermissionError, OSError):
            continue

    # Deduplicate (same event may appear in multiple log files)
    seen: set[tuple] = set()
    unique: list[dict] = []
    for a in alerts:
        key = (a["timestamp"], a["rule_id"], a["details"])
        if key not in seen:
            seen.add(key)
            unique.append(a)
    alerts = unique

    # Sort by timestamp descending (newest first)
    def _parse_ts(ts_str: str) -> datetime.datetime:
        try:
            cleaned = re.sub(r"[,.]\d+$", "", ts_str)
            return datetime.datetime.strptime(cleaned, "%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            return datetime.datetime.min

    alerts.sort(key=lambda a: _parse_ts(a.get("timestamp", "")), reverse=True)

    # Collapse rapid duplicates: same rule_id + normalized details (ignore pid)
    # keeps one per "event type" to avoid flooding from burst blocks
    def _norm(s: str) -> str:
        return re.sub(r"pid=\d+", "pid=*", s)

    seen_norm: set[tuple] = set()
    collapsed: list[dict] = []
    for a in alerts:
        nkey = (a["rule_id"], _norm(a["details"]))
        if nkey not in seen_norm:
            seen_norm.add(nkey)
            collapsed.append(a)
    alerts = collapsed
    return alerts[:100]  # Cap at 100 most recent


@app.get("/api/alerts")
async def get_alerts(
    limit: int = 50,
    severity: Optional[str] = None,
    rule_id: Optional[str] = None,
    since_hours: Optional[float] = None,
):
    """Return recent blocked actions, optionally filtered by severity and time."""
    import datetime

    alerts = _parse_log_lines()
    metadata = _load_rule_metadata()

    # Enrich with description and severity
    for a in alerts:
        meta = metadata.get(a["rule_id"], {})
        if isinstance(meta, dict):
            a["description"] = meta.get("description", "")
            a["severity"] = meta.get("severity", "unknown")
        else:
            a["description"] = ""
            a["severity"] = "unknown"

    # Filter by severity (e.g. ?severity=critical,high)
    if severity:
        allowed = {s.strip().lower() for s in severity.split(",")}
        alerts = [a for a in alerts if a.get("severity", "unknown").lower() in allowed]

    # Filter by time (e.g. ?since_hours=24)
    if since_hours is not None and since_hours > 0:
        try:
            cutoff = datetime.datetime.now() - datetime.timedelta(hours=since_hours)
            filtered = []
            for a in alerts:
                ts_str = a.get("timestamp", "")
                # Parse "2024-02-25 12:34:56" or "2024-02-25 12:34:56.123"
                ts_str = re.sub(r"[,.]\d+$", "", ts_str)
                try:
                    ts = datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                    if ts >= cutoff:
                        filtered.append(a)
                except ValueError:
                    filtered.append(a)  # Keep if unparseable
            alerts = filtered
        except Exception:
            pass

    return JSONResponse({"alerts": alerts, "count": len(alerts)})


@app.get("/api/rules")
async def get_rules():
    """Return the current compiled policy."""
    try:
        with open(POLICY_PATH) as f:
            policy = json.load(f)
        return JSONResponse(policy)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


@app.get("/api/user-rules")
async def get_user_rules():
    """Return the user's rule exemptions."""
    rules = load_user_rules()
    return JSONResponse({
        "path": str(USER_RULES_PATH),
        "rules": rules,
    })


@app.post("/api/user-rules")
async def update_user_rules(request: Request):
    """Update the user's rule exemptions (preserves custom_rules)."""
    try:
        body = await request.json()
        # Preserve existing custom_rules when only exemptions are being saved
        existing = load_user_rules()
        if "custom_rules" not in body and "custom_rules" in existing:
            body["custom_rules"] = existing["custom_rules"]
        save_user_rules(body)
        _trigger_enforcement()
        return JSONResponse({
            "status": "ok", 
            "path": str(USER_RULES_PATH),
            "message": _get_enforcement_message()
        })
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


def _trigger_enforcement():
    """Trigger background daemon/policy hot reloads when user rules change."""
    import platform
    import subprocess
    import threading

    def _run():
        if platform.system() == "Darwin":
            # Re-generate the Seatbelt profile and notify user
            # Try both the development layout and the installed flat layout
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            candidates = [
                os.path.join(base_dir, "macos", "apply_macos_policy.py"),
                os.path.join(base_dir, "apply_macos_policy.py"),
            ]
            apply_script = None
            for c in candidates:
                if os.path.exists(c):
                    apply_script = c
                    break
            
            if apply_script:
                try:
                    subprocess.run(["python3", apply_script], check=True, capture_output=True)
                    logger.info("Triggered macOS policy applicator: %s", apply_script)
                except subprocess.CalledProcessError as e:
                    logger.error("Failed to apply macOS policy: %s", e.stderr.decode() if e.stderr else str(e))
        else:
            # On Linux, monitor.py reloads on mtime changes (poll every 2s) and on SIGHUP.
            # Touch file and send SIGHUP for immediate reload of custom IP/domain rules.
            if USER_RULES_PATH.exists():
                os.utime(USER_RULES_PATH, None)
            try:
                r = subprocess.run(
                    ["systemctl", "kill", "clawedr-monitor", "-s", "SIGHUP"],
                    capture_output=True, timeout=2,
                )
                if r.returncode != 0:
                    # Fallback: send SIGHUP to monitor.py process
                    pid_out = subprocess.run(
                        ["pgrep", "-f", "monitor.py"],
                        capture_output=True, text=True, timeout=2,
                    )
                    if pid_out.returncode == 0 and pid_out.stdout.strip():
                        for pid in pid_out.stdout.strip().split():
                            try:
                                os.kill(int(pid), signal.SIGHUP)
                            except (ValueError, ProcessLookupError, OSError):
                                pass
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass
            logger.info("Triggered Linux monitor reload")

    threading.Thread(target=_run, daemon=True).start()


def _get_enforcement_message():
    """Return a human-readable message about enforcement latency/actions."""
    import platform
    if platform.system() == "Darwin":
        return "Changes applied. Please restart OpenClaw to enforce new kernel-level rules."
    return "Changes applied and effective immediately."


@app.get("/api/custom-rules")
async def list_custom_rules():
    """Return all user-defined custom blocking rules."""
    from shared.user_rules import VALID_SEVERITIES
    return JSONResponse({
        "custom_rules": get_custom_rules(),
        "supported_types": list(CUSTOM_RULE_TYPES.keys()),
        "supported_severities": sorted(VALID_SEVERITIES),
    })


@app.post("/api/custom-rules")
async def create_custom_rule(request: Request):
    """Create a new custom blocking rule."""
    try:
        body = await request.json()
        rule_type = body.get("type", "")
        value = body.get("value", "")
        platform = body.get("platform", "both")
        description = body.get("description")
        severity = body.get("severity")
        rule, err = add_custom_rule(
            rule_type, value, platform,
            description=description,
            severity=severity,
        )
        if err:
            return JSONResponse({"error": err}, status_code=400)
        
        _trigger_enforcement()
        return JSONResponse({
            "status": "ok", 
            "rule": rule,
            "message": _get_enforcement_message()
        })
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


@app.put("/api/custom-rules/{rule_id}")
async def modify_custom_rule(rule_id: str, request: Request):
    """Update an existing custom rule."""
    try:
        body = await request.json()
        rule, err = update_custom_rule(
            rule_id,
            value=body.get("value"),
            platform=body.get("platform"),
            description=body.get("description"),
            severity=body.get("severity"),
        )
        if err:
            return JSONResponse({"error": err}, status_code=400)
        
        _trigger_enforcement()
        return JSONResponse({
            "status": "ok", 
            "rule": rule,
            "message": _get_enforcement_message()
        })
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


@app.delete("/api/custom-rules/{rule_id}")
async def remove_custom_rule(rule_id: str):
    """Delete a custom rule."""
    ok, err = delete_custom_rule(rule_id)
    if not ok:
        return JSONResponse({"error": err}, status_code=404)
        
    _trigger_enforcement()
    return JSONResponse({
        "status": "ok", 
        "deleted": rule_id,
        "message": _get_enforcement_message()
    })


def _get_process_info(pid: int) -> dict | None:
    """Get process info for a PID. Returns dict with comm, cmdline, ppid, from_openclaw; or None if not found."""
    import platform
    import subprocess

    pid = int(pid)
    if pid <= 0:
        return None

    info: dict = {"pid": pid, "comm": "", "cmdline": "", "ppid": None, "from_openclaw": False}

    if platform.system() == "Linux":
        proc = Path(f"/proc/{pid}")
        if not proc.exists():
            return None
        try:
            info["comm"] = (proc / "comm").read_text().strip()
            raw = (proc / "cmdline").read_bytes()
            info["cmdline"] = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
            for line in (proc / "status").read_text().splitlines():
                if line.startswith("PPid:"):
                    info["ppid"] = int(line.split()[1])
                    break
        except (OSError, ValueError):
            return info
    else:
        # macOS: use ps
        try:
            comm_out = subprocess.run(
                ["ps", "-o", "comm=", "-p", str(pid)],
                capture_output=True, text=True, timeout=2,
            )
            if comm_out.returncode == 0 and comm_out.stdout.strip():
                info["comm"] = comm_out.stdout.strip().split("/")[-1]
            args_out = subprocess.run(
                ["ps", "-o", "args=", "-p", str(pid)],
                capture_output=True, text=True, timeout=2,
            )
            if args_out.returncode == 0:
                info["cmdline"] = args_out.stdout.strip()
            ppid_out = subprocess.run(
                ["ps", "-o", "ppid=", "-p", str(pid)],
                capture_output=True, text=True, timeout=2,
            )
            if ppid_out.returncode == 0:
                info["ppid"] = int(ppid_out.stdout.strip() or 0)
        except (subprocess.TimeoutExpired, ValueError, OSError):
            pass

    # Walk parent chain to detect openclaw ancestry
    def _get_ppid(p: int) -> int | None:
        if platform.system() == "Linux":
            try:
                for line in (Path(f"/proc/{p}") / "status").read_text().splitlines():
                    if line.startswith("PPid:"):
                        return int(line.split()[1])
            except (OSError, ValueError):
                return None
        else:
            try:
                out = subprocess.run(
                    ["ps", "-o", "ppid=", "-p", str(p)],
                    capture_output=True, text=True, timeout=2,
                )
                return int(out.stdout.strip() or 0) if out.returncode == 0 else None
            except (ValueError, OSError):
                return None

    def _is_openclaw(p: int) -> bool:
        if platform.system() == "Linux":
            try:
                pcomm = (Path(f"/proc/{p}") / "comm").read_text().strip().lower()
                if "openclaw" in pcomm:
                    return True
                raw = (Path(f"/proc/{p}") / "cmdline").read_bytes()
                return b"openclaw" in raw.lower()
            except (OSError, ValueError):
                return False
        else:
            try:
                out = subprocess.run(
                    ["ps", "-o", "args=", "-p", str(p)],
                    capture_output=True, text=True, timeout=2,
                )
                return "openclaw" in (out.stdout or "").lower() if out.returncode == 0 else False
            except (OSError, ValueError):
                return False

    seen: set[int] = set()
    cur = pid
    for _ in range(64):  # Max depth
        if cur in seen or cur <= 0:
            break
        seen.add(cur)
        if _is_openclaw(cur):
            info["from_openclaw"] = True
            break
        ppid = _get_ppid(cur)
        if ppid is None or ppid <= 0:
            break
        cur = ppid

    return info


@app.get("/api/process/{pid}")
async def get_process(pid: int):
    """Return process info for a PID, including whether it originated from openclaw."""
    info = _get_process_info(pid)
    if info is None:
        return JSONResponse({"error": "Process not found"}, status_code=404)
    return JSONResponse(info)


@app.get("/api/status")
async def get_status():
    """Return Shield health status."""
    import platform
    import shutil

    status = {
        "os": platform.system(),
        "policy_exists": os.path.exists(POLICY_PATH),
        "user_rules_exists": USER_RULES_PATH.exists(),
        "openclaw_available": _find_openclaw() is not None,
    }
    return JSONResponse(status)


@app.get("/api/sessions")
async def get_sessions():
    """Return active OpenClaw sessions."""
    import shutil
    import subprocess
    import platform as _platform
    import pwd

    openclaw = _find_openclaw()
    if not openclaw:
        return JSONResponse({"sessions": [], "error": "openclaw not found"})

    try:
        # When running as root (systemd/launchd), we need to query the real
        # user's sessions.  Discover who that is via SUDO_USER or by finding
        # the first login user with a home directory.
        cmd = [openclaw, "sessions", "--active", "1440", "--json"]
        env = None
        run_user = None

        if os.getuid() == 0:
            run_user = os.environ.get("SUDO_USER")
            if not run_user:
                # Find first non-root human user (uid >= 500)
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

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5, env=env,
        )
        if result.returncode != 0:
            return JSONResponse({"sessions": [], "error": result.stderr.strip()})

        data = json.loads(result.stdout)
        return JSONResponse(data)
    except Exception as exc:
        return JSONResponse({"sessions": [], "error": str(exc)})


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the Dashboard UI."""
    template_path = Path(__file__).parent / "templates" / "index.html"
    if template_path.exists():
        return HTMLResponse(template_path.read_text())
    return HTMLResponse("<h1>ClawEDR Dashboard</h1><p>Template not found.</p>")


def main():
    import uvicorn
    port = int(os.environ.get("CLAWEDR_DASHBOARD_PORT", "8477"))
    logger.info("Starting ClawEDR Dashboard on http://localhost:%d", port)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
