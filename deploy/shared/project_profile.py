"""
ClawEDR Project Profiles — per-project security configuration.

A profile captures a named set of rule overrides, heuristic settings,
module toggles, and custom rules. When a profile is active its values
take precedence over the global settings. Profiles are stored as
individual JSON files under ~/.clawedr/profiles/<id>.json.

This module also provides settings-backup / restore helpers for
portable export/import of the full ClawEDR user configuration.

Usage:
    from shared.project_profile import ProfileManager
    pm = ProfileManager()
    profile_id = pm.save_profile({
        "name": "DevOps Project",
        "description": "Relaxed rules for infra work",
        "egress_mode": "allowlist",
        "allowed_domains": ["registry.terraform.io"],
    })
    print(pm.list_profiles())

    backup = pm.export_settings_backup()
    pm.import_settings_backup(backup)
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("clawedr.project_profile")

SCHEMA_VERSION = "1"

# ---------------------------------------------------------------------------
# Configuration paths
# ---------------------------------------------------------------------------

def _default_clawedr_dir() -> Path:
    etc = Path("/etc/clawedr")
    if os.getuid() == 0 and etc.exists():
        return etc
    return Path.home() / ".clawedr"


_CLAWEDR_DIR = _default_clawedr_dir()
_PROFILES_DIR = _CLAWEDR_DIR / "profiles"

# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class ProjectProfile:
    """Security profile for a single project or context."""

    name: str
    description: str
    created_at: str
    updated_at: str

    # Rule overrides
    rule_mode_overrides: dict[str, str] = field(default_factory=dict)
    heuristic_overrides: dict[str, str] = field(default_factory=dict)
    heuristic_threshold_overrides: dict[str, dict] = field(default_factory=dict)
    exempted_rule_ids: list[str] = field(default_factory=list)

    # Module settings (None = inherit global)
    output_scanner_enabled: bool | None = None
    injection_detection_enabled: bool | None = None
    egress_mode: str | None = None          # "allowlist" | "blocklist" | None
    allowed_domains: list[str] | None = None
    risk_profile: str | None = None         # "hobbyist"|"professional"|"military"|None

    # Extra custom rules active for this project
    custom_rules: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProjectProfile":
        known_fields = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_VALID_MODES = frozenset({"enforce", "alert", "disabled"})
_VALID_EGRESS = frozenset({"allowlist", "blocklist"})
_VALID_RISK = frozenset({"hobbyist", "professional", "military"})


def _validate_profile_data(data: dict[str, Any]) -> tuple[bool, str]:
    """Return (ok, error_message) after basic structural validation."""
    name = data.get("name", "")
    if not isinstance(name, str) or not name.strip():
        return False, "Profile 'name' must be a non-empty string"

    for field_name in ("rule_mode_overrides", "heuristic_overrides"):
        val = data.get(field_name)
        if val is not None:
            if not isinstance(val, dict):
                return False, f"'{field_name}' must be a dict"
            for k, v in val.items():
                if v not in _VALID_MODES:
                    return False, (
                        f"Invalid mode '{v}' for {field_name}['{k}']. "
                        f"Must be one of: {', '.join(sorted(_VALID_MODES))}"
                    )

    egress = data.get("egress_mode")
    if egress is not None and egress not in _VALID_EGRESS:
        return False, f"Invalid egress_mode '{egress}'. Must be one of: {', '.join(_VALID_EGRESS)}"

    risk = data.get("risk_profile")
    if risk is not None and risk not in _VALID_RISK:
        return False, f"Invalid risk_profile '{risk}'. Must be one of: {', '.join(sorted(_VALID_RISK))}"

    allowed = data.get("allowed_domains")
    if allowed is not None and not isinstance(allowed, list):
        return False, "'allowed_domains' must be a list"

    custom = data.get("custom_rules")
    if custom is not None and not isinstance(custom, list):
        return False, "'custom_rules' must be a list"

    return True, ""


# ---------------------------------------------------------------------------
# ProfileManager
# ---------------------------------------------------------------------------

class ProfileManager:
    """CRUD interface for per-project security profiles."""

    def __init__(self, profiles_dir: Path | None = None) -> None:
        self._dir = profiles_dir or _PROFILES_DIR
        self._dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _profile_path(self, profile_id: str) -> Path:
        # Sanitise the id to prevent path traversal
        safe_id = profile_id.replace("/", "").replace("..", "").strip()
        return self._dir / f"{safe_id}.json"

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    @staticmethod
    def _short_id() -> str:
        """Return an 8-character hex prefix of a UUID4."""
        return str(uuid.uuid4()).replace("-", "")[:8]

    def _read_profile_file(self, path: Path) -> dict[str, Any]:
        with open(path) as fh:
            return json.load(fh)

    def _write_profile_file(self, path: Path, data: dict[str, Any]) -> None:
        tmp = path.with_suffix(".tmp")
        with open(tmp, "w") as fh:
            json.dump(data, fh, indent=2)
        tmp.replace(path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_profiles(self) -> list[dict[str, Any]]:
        """Return summary dicts {id, name, description, created_at, updated_at}."""
        results: list[dict[str, Any]] = []
        for p in sorted(self._dir.glob("*.json")):
            profile_id = p.stem
            try:
                data = self._read_profile_file(p)
                results.append({
                    "id": profile_id,
                    "name": data.get("name", ""),
                    "description": data.get("description", ""),
                    "created_at": data.get("created_at", ""),
                    "updated_at": data.get("updated_at", ""),
                })
            except Exception as exc:
                logger.warning("Could not read profile %s: %s", p, exc)
        return results

    def get_profile(self, profile_id: str) -> dict[str, Any]:
        """Return the full profile dict.

        Raises FileNotFoundError if the profile does not exist.
        """
        path = self._profile_path(profile_id)
        if not path.exists():
            raise FileNotFoundError(f"Profile '{profile_id}' not found")
        data = self._read_profile_file(path)
        data["id"] = profile_id
        return data

    def save_profile(self, data: dict[str, Any]) -> str:
        """Upsert a profile. Returns the profile id.

        If *data* contains an ``id`` key and the corresponding file exists,
        the profile is updated in place. Otherwise a new id is generated.
        """
        ok, err = _validate_profile_data(data)
        if not ok:
            raise ValueError(f"Invalid profile: {err}")

        now = self._now_iso()
        profile_id = data.get("id") or ""

        # Check whether we're updating an existing profile
        if profile_id:
            existing_path = self._profile_path(profile_id)
            if not existing_path.exists():
                profile_id = ""       # treat as new

        if not profile_id:
            profile_id = self._short_id()
            # Ensure uniqueness (astronomically unlikely collision, but be safe)
            while self._profile_path(profile_id).exists():
                profile_id = self._short_id()
            data["created_at"] = data.get("created_at") or now

        data["updated_at"] = now
        data["id"] = profile_id

        # Build a clean ProjectProfile to normalise missing fields
        defaults = asdict(ProjectProfile(
            name=data.get("name", ""),
            description=data.get("description", ""),
            created_at=data.get("created_at", now),
            updated_at=now,
        ))
        merged = {**defaults, **data}
        # Remove the synthetic 'id' key from the stored file (id is the filename)
        stored = {k: v for k, v in merged.items() if k != "id"}

        self._write_profile_file(self._profile_path(profile_id), stored)
        logger.info("Saved profile '%s' (id=%s)", data.get("name"), profile_id)
        return profile_id

    def delete_profile(self, profile_id: str) -> None:
        """Delete a profile by id.

        Raises FileNotFoundError if the profile does not exist.
        """
        path = self._profile_path(profile_id)
        if not path.exists():
            raise FileNotFoundError(f"Profile '{profile_id}' not found")
        path.unlink()
        logger.info("Deleted profile id=%s", profile_id)

    def export_profile(self, profile_id: str) -> dict[str, Any]:
        """Return the full profile dict including id, suitable for JSON download."""
        data = self.get_profile(profile_id)
        return data

    def import_profile(self, data: dict[str, Any]) -> str:
        """Validate *data* and save as a new profile. Returns the new id.

        Any existing ``id`` in *data* is stripped — imports always create a
        new entry to avoid silently overwriting an existing profile.
        """
        ok, err = _validate_profile_data(data)
        if not ok:
            raise ValueError(f"Invalid profile data: {err}")

        # Strip id so save_profile always generates a fresh one
        clean = {k: v for k, v in data.items() if k != "id"}
        # Strip timestamps so they're regenerated fresh
        clean.pop("created_at", None)
        clean.pop("updated_at", None)

        profile_id = self.save_profile(clean)
        logger.info("Imported profile '%s' as id=%s", data.get("name"), profile_id)
        return profile_id

    # ------------------------------------------------------------------
    # Settings backup / restore
    # ------------------------------------------------------------------

    def export_settings_backup(self) -> dict[str, Any]:
        """Export current user_rules + settings as a portable backup dict.

        The dashboard_token is redacted from the export — it is a
        per-installation secret and must not roam between machines.
        """
        from shared.user_rules import load_settings, load_user_rules

        user_rules = load_user_rules()
        settings = load_settings()

        # Redact the dashboard token
        redacted_settings = dict(settings)
        redacted_settings["dashboard_token"] = None

        return {
            "schema_version": SCHEMA_VERSION,
            "exported_at": self._now_iso(),
            "user_rules": user_rules,
            "settings": redacted_settings,
        }

    def import_settings_backup(self, data: dict[str, Any]) -> None:
        """Restore user_rules + settings from a backup dict.

        Validates schema_version. Merges carefully:
        - Never overwrites dashboard_token.
        - Never overwrites alert_api_keys (per-install secrets).
        - user_rules is replaced wholesale (safe because it contains no
          install-specific secrets).
        - settings keys are merged one-by-one, skipping protected fields.

        Raises ValueError for unknown schema versions.
        """
        from shared.user_rules import (
            load_settings,
            save_settings,
            save_user_rules,
        )

        version = str(data.get("schema_version", ""))
        if version != SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported backup schema_version '{version}'. "
                f"Expected '{SCHEMA_VERSION}'."
            )

        # --- Restore user_rules ---
        incoming_rules = data.get("user_rules")
        if isinstance(incoming_rules, dict):
            save_user_rules(incoming_rules)
            logger.info("Restored user_rules from backup")
        else:
            logger.warning("Backup contains no valid user_rules; skipping")

        # --- Merge settings (never overwrite protected fields) ---
        _PROTECTED_SETTINGS = frozenset({"dashboard_token", "alert_api_keys"})

        incoming_settings = data.get("settings")
        if isinstance(incoming_settings, dict):
            current = load_settings()
            for key, value in incoming_settings.items():
                if key in _PROTECTED_SETTINGS:
                    logger.debug(
                        "Skipping protected settings key '%s' during backup restore", key
                    )
                    continue
                current[key] = value
            save_settings(current)
            logger.info("Restored settings from backup (protected fields preserved)")
        else:
            logger.warning("Backup contains no valid settings; skipping")
