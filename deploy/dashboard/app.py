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
import sys
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

# Add parent directory to path so we can import shared modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.user_rules import load_user_rules, save_user_rules, USER_RULES_PATH

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
    "/tmp/clawedr_log_tailer.log",
    os.path.expanduser("~/Library/Logs/clawedr.log"),
]

_BLOCK_LINE_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[,.]?\d*)\s+"
    r"WARNING\s+\[[\w.]+\]\s+"
    r"BLOCKED\s+\[([A-Z0-9_-]+)\]\s+(.*)"
)


def _parse_log_lines(max_lines: int = 200) -> list[dict]:
    """Parse recent BLOCKED entries from the log files."""
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
    return alerts[-100:]  # Cap at 100 most recent


@app.get("/api/alerts")
async def get_alerts():
    """Return recent blocked actions."""
    alerts = _parse_log_lines()
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
    """Update the user's rule exemptions."""
    try:
        body = await request.json()
        save_user_rules(body)
        return JSONResponse({"status": "ok", "path": str(USER_RULES_PATH)})
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


@app.get("/api/status")
async def get_status():
    """Return Shield health status."""
    import platform
    import shutil

    status = {
        "os": platform.system(),
        "policy_exists": os.path.exists(POLICY_PATH),
        "user_rules_exists": USER_RULES_PATH.exists(),
        "openclaw_available": shutil.which("openclaw") is not None,
    }
    return JSONResponse(status)


@app.get("/api/sessions")
async def get_sessions():
    """Return active OpenClaw sessions."""
    import shutil
    import subprocess

    openclaw = shutil.which("openclaw")
    if not openclaw:
        return JSONResponse({"sessions": [], "error": "openclaw not found"})

    try:
        result = subprocess.run(
            [openclaw, "sessions", "--active", "5", "--json"],
            capture_output=True, text=True, timeout=5,
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
