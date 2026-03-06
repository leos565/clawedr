"""
ClawEDR User Rules — runtime overrides and custom rules.

Reads ~/.clawedr/user_rules.yaml and provides helpers for the Shield
daemons to check whether a Rule ID has been exempted by the user,
and to manage user-defined custom blocking rules.

This module has no third-party dependencies (PyYAML is optional; falls
back to a minimal inline parser for the simple list format we use).

Schema:
    exempted_rule_ids:
      - "BIN-001"
    heuristic_overrides:
      HEU-GOG-001: enforce
      HEU-NET-001: alert
      HEU-FS-002: disabled
    rule_mode_overrides:
      BIN-001: alert
      DOM-001: enforce
      USR-BIN-001: disabled
      # Applies to security + custom rules. disabled|alert|enforce.
    custom_rules:
      - id: USR-BIN-001
        type: executable
        value: terraform
        description: "Optional human-readable reason for blocking"
        severity: high
      - id: USR-DOM-001
        type: domain
        value: evil.com
      - id: USR-PATH-001
        type: path
        value: /var/secrets
        platform: linux

  severity: critical | high | medium | low | info
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger("clawedr.user_rules")

# System-wide path for rules (standardized to avoid home-dir ambiguity)
USER_RULES_DIR = Path("/etc/clawedr")
USER_RULES_PATH = USER_RULES_DIR / "user_rules.yaml"

# Fallback for development/non-root environments
if not os.access("/", os.W_OK) and not USER_RULES_DIR.exists():
     USER_RULES_DIR = Path(os.path.expanduser("~/.clawedr"))
     USER_RULES_PATH = USER_RULES_DIR / "user_rules.yaml"

SETTINGS_PATH = USER_RULES_DIR / "settings.yaml"

# Valid severity values (matches master_rules.yaml rule_metadata)
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})

# Valid custom rule types and their ID prefixes
CUSTOM_RULE_TYPES = {
    "executable": "USR-BIN",
    "domain": "USR-DOM",
    "ip": "USR-IP",
    "hash": "USR-HASH",
    "path": "USR-PATH",
    "argument": "USR-ARG",
}

# Validation patterns
_HASH_RE = re.compile(r"^(sha256:)?[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(
    r"^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_IP_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)

# Executables that should never be blocked (footgun protection)
_PROTECTED_EXECUTABLES = frozenset({
    "python3", "python", "node", "sh", "bash", "zsh", "env",
    "git", "ssh", "scp", "ls", "cat", "echo", "grep", "find",
    "cp", "mv", "rm", "mkdir", "chmod", "chown",
})


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load a YAML file, trying PyYAML first then falling back."""
    try:
        import yaml
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        pass

    import json
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, ValueError):
        pass

    # Last resort: line-by-line parse for simple key: list format
    result: dict[str, Any] = {}
    current_key: str | None = None
    with open(path) as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.endswith(":"):
                current_key = stripped[:-1].strip()
                result[current_key] = []
            elif stripped.startswith("- ") and current_key is not None:
                content = stripped[2:].strip()
                if ":" in content:
                    # Simple dict item within list: "- key: val"
                    k, v = content.split(":", 1)
                    result[current_key].append({k.strip(): v.strip().strip("\"'")})
                else:
                    result[current_key].append(content.strip("\"'"))
            elif ":" in stripped and current_key is not None and isinstance(result[current_key], list) and len(result[current_key]) > 0:
                # Continuation of a dict item: "  key: val" (indented)
                k, v = stripped.split(":", 1)
                last_item = result[current_key][-1]
                if isinstance(last_item, dict):
                    last_item[k.strip()] = v.strip().strip("\"'")
    return result


def load_user_rules() -> dict[str, Any]:
    """Load user rules from ~/.clawedr/user_rules.yaml."""
    if not USER_RULES_PATH.exists():
        logger.info("No user rules file at %s", USER_RULES_PATH)
        return {}

    try:
        rules = _load_yaml(USER_RULES_PATH)
        logger.info(
            "Loaded user rules: %d exempted, %d custom",
            len(rules.get("exempted_rule_ids", [])),
            len(rules.get("custom_rules", [])),
        )
        return rules
    except Exception as exc:
        logger.warning("Failed to load user rules from %s: %s", USER_RULES_PATH, exc)
        return {}


def get_exempted_rule_ids() -> set[str]:
    """Return the set of Rule IDs the user has exempted (disabled)."""
    rules = load_user_rules()
    exempted = set(rules.get("exempted_rule_ids", []))
    # Include rules with mode=disabled from rule_mode_overrides
    overrides = rules.get("rule_mode_overrides", {})
    if isinstance(overrides, dict):
        exempted.update(rid for rid, m in overrides.items() if m == "disabled")
    return exempted


def get_custom_rules() -> list[dict[str, Any]]:
    """Return the list of user-defined custom blocking rules."""
    rules = load_user_rules()
    return list(rules.get("custom_rules", []))


# Valid heuristic enforcement modes (three-tier hierarchy)
VALID_HEURISTIC_MODES = frozenset({"disabled", "alert", "enforce"})


def get_heuristic_overrides() -> dict[str, str]:
    """Return heuristic overrides: { 'HEU-XXX-NNN': 'disabled'|'alert'|'enforce' }."""
    rules = load_user_rules()
    overrides = rules.get("heuristic_overrides", {})
    if not isinstance(overrides, dict):
        return {}
    # Validate values
    return {k: v for k, v in overrides.items() if v in VALID_HEURISTIC_MODES}


def save_heuristic_overrides(overrides: dict[str, str]) -> None:
    """Save heuristic overrides to user_rules.yaml."""
    # Validate all values
    clean = {k: v for k, v in overrides.items() if v in VALID_HEURISTIC_MODES}
    rules = load_user_rules()
    rules["heuristic_overrides"] = clean
    save_user_rules(rules)
    logger.info("Saved %d heuristic overrides", len(clean))


def get_rule_mode_overrides() -> dict[str, str]:
    """Return rule mode overrides for security + custom rules: { rule_id: 'disabled'|'alert'|'enforce' }."""
    rules = load_user_rules()
    overrides = rules.get("rule_mode_overrides", {})
    if not isinstance(overrides, dict):
        return {}
    return {k: v for k, v in overrides.items() if v in VALID_HEURISTIC_MODES}


def save_rule_mode_overrides(overrides: dict[str, str]) -> None:
    """Save rule mode overrides for security + custom rules."""
    clean = {k: v for k, v in overrides.items() if v in VALID_HEURISTIC_MODES}
    rules = load_user_rules()
    rules["rule_mode_overrides"] = clean
    # Sync exempted_rule_ids: disabled = exempted, alert/enforce = not exempted
    exempted = set(rules.get("exempted_rule_ids", []))
    for rid, m in clean.items():
        if m == "disabled":
            exempted.add(rid)
        else:
            exempted.discard(rid)
    rules["exempted_rule_ids"] = list(exempted)
    save_user_rules(rules)
    logger.info("Saved %d rule mode overrides", len(clean))


def get_rule_mode(rule_id: str) -> str:
    """Return effective mode for a rule: disabled|alert|enforce.
    For HEU-* rules uses heuristic_overrides; for others uses rule_mode_overrides + exempted_rule_ids."""
    if rule_id.startswith("HEU-"):
        overrides = get_heuristic_overrides()
        return overrides.get(rule_id, "enforce")
    exempted = get_exempted_rule_ids()
    if rule_id in exempted:
        return "disabled"
    overrides = get_rule_mode_overrides()
    return overrides.get(rule_id, "enforce")


def set_group_heuristic_mode(
    rule_ids: list[str],
    mode: str,
) -> tuple[int, str]:
    """Set a batch of heuristic rules to the same enforcement mode.

    Returns (count_changed, error_message).
    """
    if mode not in VALID_HEURISTIC_MODES:
        return 0, f"Invalid mode: {mode}. Must be one of: {', '.join(sorted(VALID_HEURISTIC_MODES))}"

    overrides = get_heuristic_overrides()
    changed = 0
    for rid in rule_ids:
        if rid.startswith("HEU-"):
            if overrides.get(rid) != mode:
                overrides[rid] = mode
                changed += 1
    save_heuristic_overrides(overrides)
    return changed, ""


def get_custom_rule_metadata(rule_id: str) -> tuple[str | None, str | None]:
    """Return (description, severity) for a custom rule by ID, or (None, None) if not found."""
    if not rule_id.startswith("USR-"):
        return None, None
    for r in get_custom_rules():
        if r.get("id") == rule_id:
            desc = r.get("description")
            sev = r.get("severity")
            return (
                str(desc).strip() if desc else None,
                sev if sev in VALID_SEVERITIES else None,
            )
    return None, None


def save_user_rules(rules: dict[str, Any]) -> None:
    """Write user rules to ~/.clawedr/user_rules.yaml."""
    USER_RULES_DIR.mkdir(parents=True, exist_ok=True)
    try:
        import yaml
        with open(USER_RULES_PATH, "w") as f:
            yaml.dump(rules, f, default_flow_style=False, sort_keys=False)
    except ImportError:
        import json
        with open(USER_RULES_PATH, "w") as f:
            json.dump(rules, f, indent=2)
    logger.info("User rules saved to %s", USER_RULES_PATH)


def load_settings() -> dict[str, Any]:
    """Load dashboard settings from settings.yaml."""
    if not SETTINGS_PATH.exists():
        return {"auto_update_rules": True, "last_update_check": None}
    try:
        data = _load_yaml(SETTINGS_PATH)
        return {
            "auto_update_rules": data.get("auto_update_rules", True),
            "last_update_check": data.get("last_update_check"),
        }
    except Exception as exc:
        logger.warning("Failed to load settings from %s: %s", SETTINGS_PATH, exc)
        return {"auto_update_rules": True, "last_update_check": None}


def save_settings(settings: dict[str, Any]) -> None:
    """Write dashboard settings to settings.yaml."""
    USER_RULES_DIR.mkdir(parents=True, exist_ok=True)
    try:
        import yaml
        with open(SETTINGS_PATH, "w") as f:
            yaml.dump(settings, f, default_flow_style=False, sort_keys=False)
    except ImportError:
        import json
        with open(SETTINGS_PATH, "w") as f:
            json.dump(settings, f, indent=2)
    logger.info("Settings saved to %s", SETTINGS_PATH)


def _next_id(custom_rules: list[dict], rule_type: str) -> str:
    """Generate the next USR-xxx-NNN ID for a given rule type."""
    prefix = CUSTOM_RULE_TYPES[rule_type]
    existing_nums = []
    for r in custom_rules:
        rid = r.get("id", "")
        if rid.startswith(prefix + "-"):
            try:
                existing_nums.append(int(rid.split("-")[-1]))
            except ValueError:
                pass
    next_num = max(existing_nums, default=0) + 1
    return f"{prefix}-{next_num:03d}"


def validate_custom_rule(
    rule_type: str, value: str, platform: str | None = None
) -> tuple[bool, str]:
    """Validate a custom rule. Returns (ok, error_message)."""
    if rule_type not in CUSTOM_RULE_TYPES:
        return False, f"Invalid rule type: {rule_type}. Must be one of: {', '.join(CUSTOM_RULE_TYPES)}"

    if not value or not value.strip():
        return False, "Value cannot be empty"

    value = value.strip()

    if rule_type == "hash":
        if not _HASH_RE.match(value):
            return False, "Hash must be 64 hex characters (sha256), optionally prefixed with 'sha256:'"

    elif rule_type == "domain":
        if not _DOMAIN_RE.match(value):
            if "://" in value:
                return False, "Enter a domain name, not a URL (e.g. 'evil.com' not 'https://evil.com')"
            if _IP_RE.match(value):
                return False, "Use the IP rule type for IP addresses, not Domain"
            return False, "Invalid domain format (e.g. evil.com)"

    elif rule_type == "ip":
        if not _IP_RE.match(value):
            return False, "Invalid IPv4 address format (e.g. 192.168.1.1)"

    elif rule_type == "executable":
        if "/" in value:
            return False, "Enter an executable name, not a path (e.g. 'terraform' not '/usr/bin/terraform')"
        if value in _PROTECTED_EXECUTABLES:
            return False, f"Cannot block '{value}' — it is a protected system executable"

    elif rule_type == "path":
        if not (value.startswith("/") or value.startswith("~/")):
            return False, "Path must be absolute (start with /) or home-relative (start with ~/)"
        if value in ("/", "~", "~/"):
            return False, "Cannot block the root or home directory"

    elif rule_type == "argument":
        # Validate as regex
        try:
            re.compile(value)
        except re.error as e:
            return False, f"Invalid regex pattern: {e}"

    if platform and platform not in ("linux", "macos", "both"):
        return False, f"Invalid platform: {platform}. Must be 'linux', 'macos', or 'both'"

    return True, ""


def _validate_severity(severity: str | None) -> tuple[bool, str]:
    """Validate severity. Returns (ok, error_message)."""
    if severity is None or severity == "":
        return True, ""
    s = str(severity).strip().lower()
    if s in VALID_SEVERITIES:
        return True, ""
    return False, f"Invalid severity: {severity}. Must be one of: {', '.join(sorted(VALID_SEVERITIES))}"


def add_custom_rule(
    rule_type: str,
    value: str,
    platform: str = "both",
    description: str | None = None,
    severity: str | None = None,
) -> tuple[dict[str, Any] | None, str]:
    """Add a custom blocking rule. Returns (rule_dict, error_message)."""
    ok, err = validate_custom_rule(rule_type, value, platform)
    if not ok:
        return None, err
    ok, err = _validate_severity(severity)
    if not ok:
        return None, err

    rules = load_user_rules()
    custom = list(rules.get("custom_rules", []))

    # Check for duplicates
    for existing in custom:
        if existing.get("type") == rule_type and existing.get("value") == value.strip():
            return None, f"Duplicate: a {rule_type} rule for '{value}' already exists ({existing['id']})"

    new_id = _next_id(custom, rule_type)
    new_rule: dict[str, Any] = {
        "id": new_id,
        "type": rule_type,
        "value": value.strip(),
    }
    if platform != "both":
        new_rule["platform"] = platform
    if description is not None and str(description).strip():
        new_rule["description"] = str(description).strip()
    if severity is not None and str(severity).strip().lower() in VALID_SEVERITIES:
        new_rule["severity"] = str(severity).strip().lower()

    custom.append(new_rule)
    rules["custom_rules"] = custom
    save_user_rules(rules)
    logger.info("Added custom rule %s: %s = %s", new_id, rule_type, value)
    return new_rule, ""


def update_custom_rule(
    rule_id: str,
    value: str | None = None,
    platform: str | None = None,
    description: str | None = None,
    severity: str | None = None,
) -> tuple[dict[str, Any] | None, str]:
    """Update an existing custom rule by ID."""
    rules = load_user_rules()
    custom = list(rules.get("custom_rules", []))

    target = None
    for r in custom:
        if r.get("id") == rule_id:
            target = r
            break

    if target is None:
        return None, f"Rule {rule_id} not found"

    if value is not None:
        ok, err = validate_custom_rule(target["type"], value, platform or target.get("platform"))
        if not ok:
            return None, err
        target["value"] = value.strip()

    if platform is not None:
        if platform == "both":
            target.pop("platform", None)
        else:
            target["platform"] = platform

    if description is not None:
        if str(description).strip():
            target["description"] = str(description).strip()
        else:
            target.pop("description", None)

    if severity is not None:
        ok, err = _validate_severity(severity)
        if not ok:
            return None, err
        if str(severity).strip().lower() in VALID_SEVERITIES:
            target["severity"] = str(severity).strip().lower()
        else:
            target.pop("severity", None)

    rules["custom_rules"] = custom
    save_user_rules(rules)
    logger.info("Updated custom rule %s", rule_id)
    return target, ""


def delete_custom_rule(rule_id: str) -> tuple[bool, str]:
    """Delete a custom rule by ID."""
    rules = load_user_rules()
    custom = list(rules.get("custom_rules", []))

    original_len = len(custom)
    custom = [r for r in custom if r.get("id") != rule_id]

    if len(custom) == original_len:
        return False, f"Rule {rule_id} not found"

    rules["custom_rules"] = custom
    save_user_rules(rules)
    logger.info("Deleted custom rule %s", rule_id)
    return True, ""
