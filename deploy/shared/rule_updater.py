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
from pathlib import Path
from typing import Any

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
    """Compute a stable hash of policy content (excluding _meta)."""
    # Exclude _meta for comparison; we care about actual rules
    copy = {k: v for k, v in policy.items() if k != "_meta"}
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
    On Linux, also downloads clawedr.sb for macOS users who may switch.
    Returns (success, message).
    """
    import platform
    import shutil
    import tempfile

    policy_url = f"{REGISTRY_URL.rstrip('/')}/compiled_policy.json"
    remote = _fetch_json(policy_url)
    if not remote:
        return False, "Failed to fetch remote policy"

    dest = Path(POLICY_PATH)
    dest.parent.mkdir(parents=True, exist_ok=True)

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, dir=dest.parent
        ) as tmp:
            json.dump(remote, tmp, indent=2)
            tmp_path = tmp.name

        shutil.move(tmp_path, dest)
        logger.info("Policy updated from registry: %s", dest)

        # On macOS, also update clawedr.sb so it's ready after restart
        if platform.system() == "Darwin":
            sb_url = f"{REGISTRY_URL.rstrip('/')}/macos/clawedr.sb"
            try:
                import urllib.request
                req = urllib.request.Request(sb_url, headers={"User-Agent": "ClawEDR-Updater/1.0"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    sb_content = resp.read().decode()
                sb_dest = Path(SB_PATH)
                sb_dest.parent.mkdir(parents=True, exist_ok=True)
                sb_dest.write_text(sb_content)
                logger.info("Seatbelt profile updated: %s", sb_dest)
            except Exception as e:
                logger.warning("Could not update clawedr.sb: %s", e)

        return True, "Policy updated successfully. " + (
            "Restart OpenClaw to enforce on macOS." if platform.system() == "Darwin"
            else "Changes are effective immediately (Linux hot-reload)."
        )
    except Exception as e:
        logger.exception("Failed to apply policy update")
        return False, str(e)
