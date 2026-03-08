"""
ClawEDR Rule Updater — fetch and compare threat rules from the GitHub registry.

Queries the public deploy/ artifacts for updated compiled_policy.json.
Used by the dashboard for hourly checks and manual updates.

- Linux: Download and replace policy; monitor.py hot-reloads automatically.
- macOS: Show banner with change count; user must restart OpenClaw to enforce.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("clawedr.rule_updater")

REGISTRY_URL = os.environ.get(
    "CLAWEDR_REGISTRY_URL",
    os.environ.get("CLAWEDR_BASE_URL", "https://raw.githubusercontent.com/leos565/clawedr/main/deploy"),
)
POLICY_PATH = os.environ.get(
    "CLAWEDR_POLICY_PATH", "/usr/local/share/clawedr/compiled_policy.json"
)
SB_PATH = os.environ.get(
    "CLAWEDR_SB_PATH", "/usr/local/share/clawedr/clawedr.sb"
)

_ALLOWED_REGISTRY_HOSTS = frozenset({
    "raw.githubusercontent.com",
    "github.com",
    "api.github.com",
    "clawsec.prompt.security",
})

# Seatbelt profile must contain these markers to be considered valid
_SB_REQUIRED_MARKERS = ("(version 1)", "(allow default)")
_SB_MAX_BYTES = 2 * 1024 * 1024  # 2 MB sanity cap


def _validate_registry_url(url: str) -> None:
    """Raise ValueError if the registry URL is not HTTPS from an allowed host."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(
            f"CLAWEDR_REGISTRY_URL must use HTTPS, got scheme '{parsed.scheme}'"
        )
    if parsed.hostname not in _ALLOWED_REGISTRY_HOSTS:
        raise ValueError(
            f"CLAWEDR_REGISTRY_URL host '{parsed.hostname}' is not in the allowlist "
            f"({', '.join(sorted(_ALLOWED_REGISTRY_HOSTS))}). "
            "Set CLAWEDR_REGISTRY_URL to an approved host."
        )


def _fetch_json(url: str) -> dict[str, Any] | None:
    """Fetch JSON from URL. Returns None on failure."""
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "ClawEDR-Updater/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        logger.warning("Failed to fetch %s: %s", url, e)
        return None


def _fetch_text(url: str, max_bytes: int = _SB_MAX_BYTES) -> str | None:
    """Fetch plain text from URL with a size cap. Returns None on failure."""
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "ClawEDR-Updater/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read(max_bytes + 1)
            if len(data) > max_bytes:
                logger.warning("Response from %s exceeds %d bytes — rejecting", url, max_bytes)
                return None
            return data.decode()
    except Exception as e:
        logger.warning("Failed to fetch %s: %s", url, e)
        return None


def _validate_seatbelt_profile(content: str) -> tuple[bool, str]:
    """Basic sanity check for a Seatbelt profile before writing it to disk."""
    if not content or not content.strip():
        return False, "Seatbelt profile is empty"
    for marker in _SB_REQUIRED_MARKERS:
        if marker not in content:
            return False, f"Seatbelt profile is missing required marker: {marker!r}"
    # Reject profiles that remove the (allow default) baseline protection
    # (i.e., have a bare (deny default) which would block everything)
    if "(deny default)" in content and "(allow default)" not in content:
        return False, "Seatbelt profile uses (deny default) without (allow default)"
    return True, "ok"


def _rule_ids_from_policy(policy: dict[str, Any]) -> set[str]:
    """Extract all Rule IDs from a compiled policy."""
    ids: set[str] = set()
    for key in ("blocked_executables", "blocked_domains", "blocked_ips", "malicious_hashes"):
        ids.update(policy.get(key, {}).keys())
    for os_key, items in policy.get("blocked_paths", {}).items():
        if isinstance(items, dict):
            ids.update(items.keys())
    for os_key, items in policy.get("deny_rules", {}).items():
        if isinstance(items, dict):
            ids.update(items.keys())
    return ids


def _content_hash(policy: dict[str, Any]) -> str:
    """Compute a stable hash of policy rule content only.

    Excludes _meta and _signature so that signing a policy locally does not
    spuriously change the content hash used for update comparisons.
    """
    copy = {k: v for k, v in policy.items() if k not in ("_meta", "_signature")}
    canonical = json.dumps(copy, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def check_for_updates() -> dict[str, Any]:
    """
    Compare local policy with remote registry. Returns:
      has_updates: bool
      change_count: int (added + removed + modified)
      added: list[str] — Rule IDs in remote but not local
      removed: list[str] — Rule IDs in local but not remote
      modified: list[str] — Rule IDs in both but value changed
      remote_hash: str | None
      local_hash: str | None
      error: str | None — if fetch failed
    """
    result: dict[str, Any] = {
        "has_updates": False,
        "change_count": 0,
        "added": [],
        "removed": [],
        "modified": [],
        "remote_hash": None,
        "local_hash": None,
        "error": None,
    }

    try:
        _validate_registry_url(REGISTRY_URL)
    except ValueError as e:
        result["error"] = str(e)
        return result

    # Fetch remote policy
    policy_url = f"{REGISTRY_URL.rstrip('/')}/compiled_policy.json"
    remote = _fetch_json(policy_url)
    if not remote:
        result["error"] = "Failed to fetch remote policy"
        return result

    result["remote_hash"] = _content_hash(remote)

    # Load local policy
    local: dict[str, Any] = {}
    if os.path.exists(POLICY_PATH):
        try:
            with open(POLICY_PATH) as f:
                local = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            result["error"] = f"Failed to read local policy: {e}"
            return result

    result["local_hash"] = _content_hash(local) if local else ""

    if not local:
        # No local policy — treat entire remote as "added"
        result["added"] = sorted(_rule_ids_from_policy(remote))
        result["has_updates"] = len(result["added"]) > 0
        result["change_count"] = len(result["added"])
        return result

    remote_ids = _rule_ids_from_policy(remote)
    local_ids = _rule_ids_from_policy(local)

    added = sorted(remote_ids - local_ids)
    removed = sorted(local_ids - remote_ids)

    # Check for modified (same ID, different value)
    modified: list[str] = []
    for key in ("blocked_executables", "blocked_domains", "blocked_ips", "malicious_hashes"):
        rv = remote.get(key, {})
        lv = local.get(key, {})
        for rid in set(rv.keys()) & set(lv.keys()):
            if rv.get(rid) != lv.get(rid):
                modified.append(rid)
    for os_key in ("linux", "macos"):
        rp = remote.get("blocked_paths", {}).get(os_key, {})
        lp = local.get("blocked_paths", {}).get(os_key, {})
        for rid in set(rp.keys()) & set(lp.keys()):
            if rp.get(rid) != lp.get(rid):
                modified.append(rid)
    for os_key in ("linux", "macos"):
        rd = remote.get("deny_rules", {}).get(os_key, {})
        ld = local.get("deny_rules", {}).get(os_key, {})
        for rid in set(rd.keys()) & set(ld.keys()):
            if rd.get(rid) != ld.get(rid):
                modified.append(rid)
    modified = sorted(set(modified))

    result["added"] = added
    result["removed"] = removed
    result["modified"] = modified
    result["change_count"] = len(added) + len(removed) + len(modified)
    result["has_updates"] = result["change_count"] > 0 or result["remote_hash"] != result["local_hash"]

    return result


def download_and_apply() -> tuple[bool, str]:
    """
    Download compiled_policy.json from registry and write to local path.
    On macOS, also downloads and validates clawedr.sb before writing.
    Returns (success, message).
    """
    import platform

    try:
        _validate_registry_url(REGISTRY_URL)
    except ValueError as e:
        return False, str(e)

    policy_url = f"{REGISTRY_URL.rstrip('/')}/compiled_policy.json"
    remote = _fetch_json(policy_url)
    if not remote:
        return False, "Failed to fetch remote policy"

    # Verify signature if a local signing key exists.
    # Remote policies distributed via the registry may not be signed with the
    # local installation key; if no key is configured, verification passes with
    # a warning. If a key IS present and verification fails, abort — this
    # indicates either a tampered policy or a key mismatch that needs attention.
    try:
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from policy_verify import verify_policy
        ok, msg = verify_policy(remote)
        if not ok:
            logger.error(
                "Remote policy signature verification failed: %s — refusing to apply. "
                "If you recently rotated your signing key, re-publish the policy.",
                msg,
            )
            return False, f"Policy signature verification failed: {msg}"
        if "no signing key" in msg:
            logger.warning(
                "No local signing key configured — applying remote policy without "
                "signature verification. Run `./main.py compile` to generate a key."
            )
        else:
            logger.info("Remote policy signature verified: %s", msg)
    except ImportError:
        logger.warning("policy_verify unavailable — skipping signature check")

    dest = Path(POLICY_PATH)
    dest.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Write atomically via temp file
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json", dir=dest.parent)
        try:
            with os.fdopen(tmp_fd, "w") as f:
                json.dump(remote, f, indent=2)
            os.replace(tmp_path, dest)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        logger.info("Policy updated from registry: %s", dest)

        # On macOS, also update clawedr.sb so it's ready after restart.
        # Validate content before writing — a permissive or empty profile would
        # remove sandbox protections.
        if platform.system() == "Darwin":
            sb_url = f"{REGISTRY_URL.rstrip('/')}/macos/clawedr.sb"
            sb_content = _fetch_text(sb_url)
            if sb_content:
                valid, reason = _validate_seatbelt_profile(sb_content)
                if not valid:
                    logger.warning(
                        "Remote clawedr.sb failed validation (%s) — keeping existing profile",
                        reason,
                    )
                else:
                    sb_dest = Path(SB_PATH)
                    sb_dest.parent.mkdir(parents=True, exist_ok=True)
                    # Atomic write for the profile too
                    tmp_sb_fd, tmp_sb = tempfile.mkstemp(suffix=".sb", dir=sb_dest.parent)
                    try:
                        with os.fdopen(tmp_sb_fd, "w") as f:
                            f.write(sb_content)
                        os.replace(tmp_sb, sb_dest)
                        logger.info("Seatbelt profile updated: %s", sb_dest)
                    except Exception:
                        try:
                            os.unlink(tmp_sb)
                        except OSError:
                            pass
                        raise
            else:
                logger.warning("Could not fetch remote clawedr.sb — keeping existing profile")

        return True, "Policy updated successfully. " + (
            "Restart OpenClaw to enforce on macOS." if platform.system() == "Darwin"
            else "Changes are effective immediately (Linux hot-reload)."
        )
    except Exception as e:
        logger.exception("Failed to apply policy update")
        return False, str(e)
