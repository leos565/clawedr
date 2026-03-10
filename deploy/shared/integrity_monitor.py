"""
ClawEDR Cognitive Integrity Monitor.

Tracks SHA-256 checksums of OpenClaw configuration files to detect
prompt-injection-driven tampering. If an agent is compromised and
instructed to "update your SOUL.md", this catches it.

Baseline stored in /etc/clawedr/integrity.json, HMAC-protected.
Rule ID prefix: INT-*
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger("clawedr.integrity")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_BASELINE_PATH = Path("/etc/clawedr/integrity.json")
_FALLBACK_BASELINE_PATH = Path(os.path.expanduser("~/.clawedr/integrity.json"))

# Monitored files and their Rule IDs
MONITORED_FILES: dict[str, str] = {
    "INT-001": "~/.openclaw/SOUL.md",
    "INT-002": "~/.openclaw/IDENTITY.md",
    "INT-003": "~/.openclaw/TOOLS.md",
    "INT-004": "~/.openclaw/AGENTS.md",
    "INT-005": "~/.openclaw/openclaw.json",
    "INT-006": "~/.clawedr/user_rules.yaml",
}


def _get_baseline_path() -> Path:
    if _BASELINE_PATH.parent.exists() and os.access(str(_BASELINE_PATH.parent), os.W_OK):
        return _BASELINE_PATH
    return _FALLBACK_BASELINE_PATH


# ---------------------------------------------------------------------------
# HMAC helpers
# ---------------------------------------------------------------------------

def _get_hmac_key() -> str:
    """Derive the HMAC key from the dashboard token or machine ID."""
    try:
        from shared.user_rules import load_settings  # type: ignore[import]
        settings = load_settings()
        token = settings.get("dashboard_token", "")
        if token:
            return token
    except Exception:
        pass
    try:
        return Path("/etc/machine-id").read_text().strip()
    except Exception:
        return "clawedr-integrity-fallback-key"


def _hmac_sign(data: str, key: str) -> str:
    return hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# File hashing
# ---------------------------------------------------------------------------

def _sha256_file(path: str) -> Optional[str]:
    """Compute SHA-256 hex of a file. Returns None if absent or unreadable."""
    expanded = os.path.expanduser(path)
    if not os.path.exists(expanded):
        return None
    try:
        h = hashlib.sha256()
        with open(expanded, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError as exc:
        logger.debug("Cannot read %s for integrity check: %s", expanded, exc)
        return None


def compute_checksums(files: Optional[dict[str, str]] = None) -> dict[str, Optional[str]]:
    """Compute SHA-256 for all monitored files. Returns {rule_id: hash_or_None}."""
    target = files if files is not None else MONITORED_FILES
    return {rule_id: _sha256_file(path) for rule_id, path in target.items()}


# ---------------------------------------------------------------------------
# Baseline management
# ---------------------------------------------------------------------------

def initialize_baseline(files: Optional[dict[str, str]] = None) -> dict[str, Optional[str]]:
    """Compute current checksums and save as the integrity baseline.

    Returns the saved checksum dict.
    """
    target = files if files is not None else MONITORED_FILES
    checksums = compute_checksums(target)

    key = _get_hmac_key()
    payload = json.dumps(
        {"files": target, "checksums": checksums, "ts": time.time()},
        sort_keys=True,
    )
    sig = _hmac_sign(payload, key)
    data = {"payload": payload, "sig": sig}

    bp = _get_baseline_path()
    bp.parent.mkdir(parents=True, exist_ok=True)
    bp.write_text(json.dumps(data, indent=2))
    try:
        os.chmod(str(bp), 0o600)
    except OSError:
        pass

    present = sum(1 for v in checksums.values() if v is not None)
    logger.info("Integrity baseline initialized: %d/%d files hashed", present, len(target))
    return checksums


def load_baseline() -> Optional[dict[str, Optional[str]]]:
    """Load and verify baseline. Returns {rule_id: hash_or_None} or None on failure."""
    bp = _get_baseline_path()
    if not bp.exists():
        return None
    try:
        data = json.loads(bp.read_text())
        payload = data["payload"]
        sig = data["sig"]
        key = _get_hmac_key()
        expected_sig = _hmac_sign(payload, key)
        if not hmac.compare_digest(sig, expected_sig):
            logger.warning(
                "Integrity baseline HMAC verification FAILED — baseline may be tampered or key rotated"
            )
            return None
        parsed = json.loads(payload)
        return parsed.get("checksums", {})
    except Exception as exc:
        logger.warning("Failed to load integrity baseline: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Integrity checking
# ---------------------------------------------------------------------------

def check_integrity(files: Optional[dict[str, str]] = None) -> list[dict]:
    """Compare current file hashes to the baseline.

    Returns a list of tamper event dicts. Empty list = all OK.
    Each event dict contains: rule_id, path, event, baseline_hash, current_hash.
    """
    baseline = load_baseline()
    if baseline is None:
        return []

    target = files if files is not None else MONITORED_FILES
    current = compute_checksums(target)
    events: list[dict] = []

    for rule_id, current_hash in current.items():
        baseline_hash = baseline.get(rule_id)
        path = target.get(rule_id, "")

        if baseline_hash is None and current_hash is not None:
            events.append({
                "rule_id": rule_id,
                "path": path,
                "event": "file_appeared",
                "baseline_hash": None,
                "current_hash": current_hash,
            })
        elif baseline_hash is not None and current_hash is None:
            events.append({
                "rule_id": rule_id,
                "path": path,
                "event": "file_deleted",
                "baseline_hash": baseline_hash,
                "current_hash": None,
            })
        elif baseline_hash is not None and current_hash is not None and baseline_hash != current_hash:
            events.append({
                "rule_id": rule_id,
                "path": path,
                "event": "file_modified",
                "baseline_hash": baseline_hash,
                "current_hash": current_hash,
            })

    return events


# ---------------------------------------------------------------------------
# Status snapshot
# ---------------------------------------------------------------------------

def get_status() -> dict:
    """Return full integrity status: baseline metadata + per-file state."""
    bp = _get_baseline_path()
    has_baseline = bp.exists()
    baseline_ts: Optional[float] = None
    baseline_valid = False

    if has_baseline:
        try:
            raw = json.loads(bp.read_text())
            parsed = json.loads(raw.get("payload", "{}"))
            baseline_ts = parsed.get("ts")
            # Verify HMAC
            key = _get_hmac_key()
            sig = _hmac_sign(raw["payload"], key)
            baseline_valid = hmac.compare_digest(sig, raw.get("sig", ""))
        except Exception:
            pass

    current = compute_checksums()
    baseline = load_baseline() or {}

    files_status: list[dict] = []
    for rule_id, path in MONITORED_FILES.items():
        expanded = os.path.expanduser(path)
        current_hash = current.get(rule_id)
        baseline_hash = baseline.get(rule_id)

        if baseline_hash is None and current_hash is None:
            status = "absent"
        elif baseline_hash is None and current_hash is not None:
            status = "untracked"
        elif baseline_hash is not None and current_hash is None:
            status = "missing"
        elif baseline_hash == current_hash:
            status = "ok"
        else:
            status = "tampered"

        files_status.append({
            "rule_id": rule_id,
            "path": path,
            "exists": os.path.exists(expanded),
            "status": status,
            "current_hash": current_hash,
            "baseline_hash": baseline_hash,
        })

    return {
        "has_baseline": has_baseline,
        "baseline_valid": baseline_valid,
        "baseline_ts": baseline_ts,
        "baseline_path": str(bp),
        "files": files_status,
        "ok_count": sum(1 for f in files_status if f["status"] == "ok"),
        "tampered_count": sum(1 for f in files_status if f["status"] == "tampered"),
        "missing_count": sum(1 for f in files_status if f["status"] in ("missing", "deleted")),
    }
