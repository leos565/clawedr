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
from fastapi import FastAPI, Request  # pyre-ignore[21]
from fastapi.responses import HTMLResponse, JSONResponse  # pyre-ignore[21]
from fastapi.staticfiles import StaticFiles  # pyre-ignore[21]
from starlette.middleware.base import BaseHTTPMiddleware  # pyre-ignore[21]

# Add parent directory to path so we can import shared modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.user_rules import (  # pyre-ignore[21]
    load_user_rules, save_user_rules, USER_RULES_PATH,
    add_custom_rule, update_custom_rule, delete_custom_rule,
    get_custom_rules, get_custom_rule_metadata, CUSTOM_RULE_TYPES,
    load_settings, save_settings, get_dashboard_token,
    get_heuristic_overrides, save_heuristic_overrides, set_group_heuristic_mode,
    get_rule_mode_overrides, save_rule_mode_overrides,
    VALID_HEURISTIC_MODES,
)
from shared.rule_updater import check_for_updates, download_and_apply  # pyre-ignore[21]

logger = logging.getLogger("clawedr.dashboard")

app = FastAPI(title="ClawEDR Dashboard", version="1.0.0")


# ---------------------------------------------------------------------------
# Token Authentication Middleware
# ---------------------------------------------------------------------------

# Paths that don't require authentication (login UI + auth check endpoint)
_AUTH_EXEMPT_PATHS = {"/", "/api/auth/check", "/api/auth/token", "/favicon.ico"}


class TokenAuthMiddleware(BaseHTTPMiddleware):
    """Require a bearer token for all API requests.

    Token can be provided as:
      - Authorization: Bearer <token>
      - Query param: ?token=<token>
      - Cookie: clawedr_token=<token>
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path.rstrip("/") or "/"

        # Allow login page and auth endpoints through
        if path in _AUTH_EXEMPT_PATHS:
            return await call_next(request)

        # Check token
        expected = get_dashboard_token()
        token = None

        # 1. Authorization header
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()

        # 2. Query param
        if not token:
            token = request.query_params.get("token")

        # 3. Cookie
        if not token:
            token = request.cookies.get("clawedr_token")

        if token == expected:
            return await call_next(request)

        return JSONResponse({"error": "Unauthorized"}, status_code=401)


app.add_middleware(TokenAuthMiddleware)

# Cached result from background update check (macOS banner)
_pending_updates: dict | None = None

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
    r"(BLOCKED|ALERT|WARNING)\s+\[([A-Z0-9_-]+)\]\s+(.*)"
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
                metadata[rid] = {  # pyre-ignore[16]
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
            for line in lines[-max_lines:]:  # pyre-ignore[9]: slice
                m = _BLOCK_LINE_RE.search(line)
                if m:
                    kind = m.group(2).upper()  # BLOCKED, ALERT, WARNING
                    alerts.append({
                        "timestamp": m.group(1),
                        "rule_id": m.group(3),
                        "details": m.group(4).strip(),
                        "blocked": kind != "ALERT",
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
    return alerts[:100]  # pyre-ignore[9]: slice


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
        assert isinstance(severity, str)  # pyre narrow
        allowed = {s.strip().lower() for s in severity.split(",")}
        alerts = [a for a in alerts if a.get("severity", "unknown").lower() in allowed]

    # Filter by time (e.g. ?since_hours=24)
    if since_hours is not None:
        assert isinstance(since_hours, int)  # pyre narrow
        if since_hours > 0:
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
    """Update the user's rule exemptions (preserves custom_rules and heuristic_overrides)."""
    try:
        body = await request.json()
        # Preserve existing when not in body
        existing = load_user_rules()
        if "custom_rules" not in body and "custom_rules" in existing:
            body["custom_rules"] = existing["custom_rules"]
        if "heuristic_overrides" not in body and "heuristic_overrides" in existing:
            body["heuristic_overrides"] = existing["heuristic_overrides"]
        if "rule_mode_overrides" not in body and "rule_mode_overrides" in existing:
            body["rule_mode_overrides"] = existing["rule_mode_overrides"]
        # Sync exempted_rule_ids from rule_mode_overrides (disabled = exempted)
        if "rule_mode_overrides" in body and isinstance(body["rule_mode_overrides"], dict):
            exempted = set(existing.get("exempted_rule_ids", []))
            for rid, m in body["rule_mode_overrides"].items():
                if m == "disabled":
                    exempted.add(rid)
                else:
                    exempted.discard(rid)
            body["exempted_rule_ids"] = list(exempted)
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
                assert isinstance(apply_script, str)  # pyre
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
    from shared.user_rules import VALID_SEVERITIES  # pyre-ignore[21]
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


# ---------------------------------------------------------------------------
# Heuristic Overrides & Group Toggle
# ---------------------------------------------------------------------------

@app.get("/api/heuristic-overrides")
async def get_heuristic_overrides_endpoint():
    """Return the user's heuristic enforcement overrides."""
    return JSONResponse({
        "overrides": get_heuristic_overrides(),
        "valid_modes": sorted(VALID_HEURISTIC_MODES),
    })


@app.post("/api/heuristic-overrides")
async def save_heuristic_overrides_endpoint(request: Request):
    """Save heuristic enforcement overrides.

    Body: { "overrides": { "HEU-XXX-NNN": "disabled"|"alert"|"enforce", ... } }
    """
    try:
        body = await request.json()
        overrides = body.get("overrides", {})
        if not isinstance(overrides, dict):
            return JSONResponse({"error": "overrides must be a dict"}, status_code=400)
        save_heuristic_overrides(overrides)
        _trigger_enforcement()
        return JSONResponse({
            "status": "ok",
            "count": len(overrides),
            "message": _get_enforcement_message(),
        })
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


@app.post("/api/group-toggle")
async def group_toggle(request: Request):
    """Toggle all heuristic rules in a subcategory to the same mode.

    Body: { "rule_ids": ["HEU-GOG-001", ...], "mode": "alert" }
    """
    try:
        body = await request.json()
        rule_ids = body.get("rule_ids", [])
        mode = body.get("mode", "")
        if not rule_ids or not mode:
            return JSONResponse({"error": "rule_ids and mode are required"}, status_code=400)
        changed, err = set_group_heuristic_mode(rule_ids, mode)
        if err:
            return JSONResponse({"error": err}, status_code=400)
        _trigger_enforcement()
        return JSONResponse({
            "status": "ok",
            "changed": changed,
            "message": _get_enforcement_message(),
        })
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


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


# ---------------------------------------------------------------------------
# Settings & Rule Updates
# ---------------------------------------------------------------------------

@app.get("/api/auth/check")
async def auth_check(request: Request):
    """Check if a token is valid. Used by the login page."""
    token = request.query_params.get("token", "")
    if not token:
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()
    if not token:
        token = request.cookies.get("clawedr_token", "")
    expected = get_dashboard_token()
    if token == expected:
        return JSONResponse({"authenticated": True})
    return JSONResponse({"authenticated": False}, status_code=401)


@app.get("/api/auth/token")
async def get_auth_info():
    """Return info about how to find the token. Does NOT return the token itself."""
    from shared.user_rules import SETTINGS_PATH  # pyre-ignore[21]
    return JSONResponse({
        "message": "Token is stored in your ClawEDR settings file. Check the console output when the dashboard starts.",
        "settings_path": str(SETTINGS_PATH),
    })


@app.get("/api/settings")
async def get_settings():
    """Return dashboard settings (auto-update toggle, bind addresses, etc.)."""
    settings = load_settings()
    # Don't expose the token in the settings API
    safe = {k: v for k, v in settings.items() if k != "dashboard_token"}
    return JSONResponse(safe)


@app.post("/api/settings")
async def post_settings(request: Request):
    """Update dashboard settings."""
    try:
        body = await request.json()
        settings = load_settings()
        if "auto_update_rules" in body:
            settings["auto_update_rules"] = bool(body["auto_update_rules"])
        if "dashboard_bind_addresses" in body:
            addrs = body["dashboard_bind_addresses"]
            if isinstance(addrs, list):
                settings["dashboard_bind_addresses"] = [str(a).strip() for a in addrs if str(a).strip()]
        save_settings(settings)
        return JSONResponse({"status": "ok", "settings": {k: v for k, v in settings.items() if k != "dashboard_token"}})
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


@app.get("/api/updates")
async def get_updates():
    """Check for rule updates from the registry. Returns has_updates, change_count, etc."""
    global _pending_updates
    result = check_for_updates()
    if result.get("has_updates"):
        _pending_updates = result
    else:
        _pending_updates = None
    return JSONResponse(result)


@app.get("/api/updates/cached")
async def get_updates_cached():
    """Return cached update result from background check (for lightweight polling)."""
    return JSONResponse(_pending_updates or {"has_updates": False})


@app.post("/api/updates/apply")
async def apply_updates():
    """Download and apply rule updates. Linux: hot-reload. macOS: replace files, user must restart."""
    ok, msg = download_and_apply()
    if ok:
        global _pending_updates
        _pending_updates = None
        # Update last_check timestamp
        settings = load_settings()
        from datetime import datetime
        settings["last_update_check"] = datetime.utcnow().isoformat() + "Z"
        save_settings(settings)
        return JSONResponse({"status": "ok", "message": msg})
    return JSONResponse({"error": msg}, status_code=500)


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


def _run_update_check():
    """Background task: hourly check for rule updates."""
    import platform
    import time
    global _pending_updates
    CHECK_INTERVAL = 3600  # 1 hour
    time.sleep(60)  # Defer first check to avoid startup load
    while True:
        try:
            settings = load_settings()
            if not settings.get("auto_update_rules", True):
                continue
            result = check_for_updates()
            if result.get("error"):
                continue
            if not result.get("has_updates"):
                _pending_updates = None
                continue
            if platform.system() == "Linux":
                ok, msg = download_and_apply()
                if ok:
                    logger.info("Auto-applied rule update: %s", msg)
                    _pending_updates = None
                    settings = load_settings()
                    from datetime import datetime
                    settings["last_update_check"] = datetime.utcnow().isoformat() + "Z"
                    save_settings(settings)
            else:
                # macOS: cache for banner, user must restart
                _pending_updates = result
                logger.info("Rule updates available (%d changes). Restart OpenClaw to enforce.", result.get("change_count", 0))
        except Exception as e:
            logger.exception("Update check failed: %s", e)
        time.sleep(CHECK_INTERVAL)


def main():
    import threading
    import uvicorn  # pyre-ignore[21]
    t = threading.Thread(target=_run_update_check, daemon=True)
    t.start()
    port = int(os.environ.get("CLAWEDR_DASHBOARD_PORT", "8477"))

    # Print the dashboard token for the user
    token = get_dashboard_token()
    logger.info("Starting ClawEDR Dashboard on http://127.0.0.1:%d", port)
    logger.info("Dashboard token: %s", token)
    logger.info("Use this token to log in to the dashboard.")
    # Also print to stderr for visibility in service logs
    print(f"\n  ClawEDR Dashboard: http://127.0.0.1:{port}")
    print(f"  Dashboard Token:  {token}\n", flush=True)

    # Determine bind host: 127.0.0.1 by default, additional addresses from settings
    settings = load_settings()
    extra_addrs = settings.get("dashboard_bind_addresses", [])
    if extra_addrs:
        # If user added addresses, bind to 0.0.0.0 (let firewall handle)
        bind_host = "0.0.0.0"
        logger.info("Additional bind addresses configured: %s — binding to 0.0.0.0", extra_addrs)
    else:
        bind_host = "127.0.0.1"
    uvicorn.run(app, host=bind_host, port=port, log_level="info")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
