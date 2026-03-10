"""
ClawEDR Audit Log — HMAC-chained tamper-evident audit trail.

Every monitored action (not just blocks) is written as a JSON-lines entry.
Each entry's HMAC covers its own fields plus the previous entry's HMAC,
forming a chain that makes silent deletion or modification detectable.

The HMAC key is a per-install 32-byte secret stored in
~/.clawedr/audit_key (auto-generated on first use, mode 0600).
The log is written to ~/.clawedr/audit.jsonl (append-only).

Usage:
    from shared.audit_log import get_audit_log
    log = get_audit_log()
    log.append("execve_blocked", "BIN-001", pid=1234, comm="nc", details={})
    broken = log.verify_chain()   # [] → intact
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("clawedr.audit_log")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _default_clawedr_dir() -> Path:
    """Return ~/.clawedr (or /etc/clawedr when root and it already exists)."""
    etc = Path("/etc/clawedr")
    if os.getuid() == 0 and etc.exists():
        return etc
    return Path.home() / ".clawedr"


_CLAWEDR_DIR = _default_clawedr_dir()
DEFAULT_AUDIT_PATH = _CLAWEDR_DIR / "audit.jsonl"
_AUDIT_KEY_PATH = _CLAWEDR_DIR / "audit_key"


# ---------------------------------------------------------------------------
# HMAC helpers
# ---------------------------------------------------------------------------

def _load_or_create_key(key_path: Path) -> bytes:
    """Return the 32-byte hex audit key, generating it if absent."""
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if key_path.exists():
        try:
            raw = key_path.read_text().strip()
            if len(raw) == 64:          # 32 bytes → 64 hex chars
                return bytes.fromhex(raw)
            logger.warning("audit_key at %s has unexpected length; regenerating", key_path)
        except Exception as exc:
            logger.warning("Failed to read audit_key (%s); regenerating", exc)

    key_bytes = secrets.token_bytes(32)
    key_path.write_text(key_bytes.hex())
    os.chmod(key_path, 0o600)
    logger.info("Generated new audit HMAC key at %s", key_path)
    return key_bytes


def _compute_hmac(key: bytes, entry_id: str, timestamp: str, event_type: str,
                  rule_id: str | None, pid: int, comm: str, prev_hmac: str,
                  details: dict) -> str:
    """Return hex HMAC-SHA256 over the canonical entry fields."""
    msg = (
        f"{entry_id}|{timestamp}|{event_type}|{rule_id}|{pid}|{comm}"
        f"|{prev_hmac}|{json.dumps(details, sort_keys=True)}"
    )
    return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class AuditEntry:
    id: str                         # UUID4 string
    timestamp: str                  # ISO-8601 UTC
    event_type: str                 # e.g. "execve_blocked", "file_read_blocked"
    rule_id: str | None             # Rule ID or None for non-rule events
    pid: int
    comm: str
    details: dict = field(default_factory=dict)
    prev_hmac: str = ""             # HMAC of the previous entry ("" for first)
    entry_hmac: str = ""            # HMAC of this entry (set after construction)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# AuditLog
# ---------------------------------------------------------------------------

class AuditLog:
    """Append-only, HMAC-chained audit log stored as JSON-lines."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or DEFAULT_AUDIT_PATH
        self._key_path = self._path.parent / "audit_key"
        self._lock = threading.Lock()
        self._key: bytes = _load_or_create_key(self._key_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hmac: str = self._read_last_hmac()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _read_last_hmac(self) -> str:
        """Scan to the last line of the log and return its entry_hmac."""
        if not self._path.exists():
            return ""
        last_hmac = ""
        try:
            with open(self._path, "rb") as fh:
                # Efficiently seek to the last non-empty line
                fh.seek(0, 2)
                size = fh.tell()
                if size == 0:
                    return ""
                # Walk backwards to find the last newline
                buf_size = min(4096, size)
                fh.seek(max(0, size - buf_size))
                tail = fh.read()
                lines = tail.splitlines()
                for raw in reversed(lines):
                    line = raw.strip()
                    if line:
                        obj = json.loads(line)
                        last_hmac = obj.get("entry_hmac", "")
                        break
        except Exception as exc:
            logger.warning("Could not read last HMAC from audit log: %s", exc)
        return last_hmac

    def _write_entry(self, entry: AuditEntry) -> None:
        """Append one JSON line to the log file."""
        line = json.dumps(entry.to_dict(), separators=(",", ":")) + "\n"
        with open(self._path, "a") as fh:
            fh.write(line)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def append(
        self,
        event_type: str,
        rule_id: str | None,
        pid: int,
        comm: str,
        details: dict | None = None,
    ) -> AuditEntry:
        """Create and persist an audit entry. Thread-safe.

        Returns the completed AuditEntry (with entry_hmac set).
        """
        if details is None:
            details = {}

        with self._lock:
            entry_id = str(uuid.uuid4())
            timestamp = datetime.now(timezone.utc).isoformat(timespec="microseconds")
            prev_hmac = self._last_hmac

            mac = _compute_hmac(
                self._key, entry_id, timestamp, event_type,
                rule_id, pid, comm, prev_hmac, details,
            )

            entry = AuditEntry(
                id=entry_id,
                timestamp=timestamp,
                event_type=event_type,
                rule_id=rule_id,
                pid=pid,
                comm=comm,
                details=details,
                prev_hmac=prev_hmac,
                entry_hmac=mac,
            )

            self._write_entry(entry)
            self._last_hmac = mac

            logger.debug(
                "Audit entry %s: event=%s rule=%s pid=%d comm=%s",
                entry_id, event_type, rule_id, pid, comm,
            )
            return entry

    def verify_chain(self) -> list[int]:
        """Verify HMAC chain integrity.

        Returns a list of 0-based line positions where the chain is broken.
        An empty list means the log is intact.
        """
        if not self._path.exists():
            return []

        broken: list[int] = []
        prev_hmac = ""

        try:
            with open(self._path) as fh:
                for pos, line in enumerate(fh):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        logger.warning("Audit log line %d is not valid JSON", pos)
                        broken.append(pos)
                        continue

                    # Recompute expected HMAC
                    expected = _compute_hmac(
                        self._key,
                        obj.get("id", ""),
                        obj.get("timestamp", ""),
                        obj.get("event_type", ""),
                        obj.get("rule_id"),
                        int(obj.get("pid", 0)),
                        obj.get("comm", ""),
                        obj.get("prev_hmac", ""),
                        obj.get("details", {}),
                    )

                    stored = obj.get("entry_hmac", "")

                    # Check HMAC matches
                    if not hmac.compare_digest(expected, stored):
                        logger.warning("Audit chain broken at line %d (HMAC mismatch)", pos)
                        broken.append(pos)
                        # Don't bail out — keep checking the rest
                        prev_hmac = stored
                        continue

                    # Check chain linkage (prev_hmac field matches previous entry's HMAC)
                    if obj.get("prev_hmac", "") != prev_hmac:
                        logger.warning(
                            "Audit chain linkage broken at line %d (prev_hmac mismatch)", pos
                        )
                        if pos not in broken:
                            broken.append(pos)

                    prev_hmac = stored

        except Exception as exc:
            logger.error("Error verifying audit chain: %s", exc)

        return sorted(broken)

    def get_recent(
        self,
        limit: int = 200,
        since_ts: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return up to *limit* recent entries as dicts, newest first.

        Args:
            limit:    Maximum number of entries to return.
            since_ts: ISO-8601 timestamp; only entries with timestamp >= since_ts
                      are included.
        """
        if not self._path.exists():
            return []

        entries: list[dict[str, Any]] = []
        try:
            with open(self._path) as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if since_ts is not None:
                        ts = obj.get("timestamp", "")
                        if ts < since_ts:       # ISO strings compare lexicographically
                            continue
                    entries.append(obj)
        except Exception as exc:
            logger.error("Error reading audit log: %s", exc)
            return []

        # Newest first, bounded by limit
        return list(reversed(entries))[:limit]

    def export_jsonl(self, dest_path: Path) -> None:
        """Copy the current audit log to *dest_path* (atomic-ish via temp file)."""
        import shutil
        dest_path = Path(dest_path)
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest_path.with_suffix(".tmp")
        with self._lock:
            if self._path.exists():
                shutil.copy2(self._path, tmp)
            else:
                tmp.write_text("")
        tmp.replace(dest_path)
        logger.info("Audit log exported to %s", dest_path)


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_audit_log_instance: AuditLog | None = None
_singleton_lock = threading.Lock()


def get_audit_log(path: Path | None = None) -> AuditLog:
    """Return the process-wide AuditLog singleton.

    On first call, the instance is created with *path* (default:
    ~/.clawedr/audit.jsonl).  Subsequent calls ignore *path*.
    """
    global _audit_log_instance
    if _audit_log_instance is None:
        with _singleton_lock:
            if _audit_log_instance is None:
                _audit_log_instance = AuditLog(path)
    return _audit_log_instance
