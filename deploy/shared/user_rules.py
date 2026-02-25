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
    custom_rules:
      - id: USR-BIN-001
        type: executable
        value: terraform
      - id: USR-DOM-001
        type: domain
        value: evil.com
      - id: USR-HASH-001
        type: hash
        value: "sha256:a1b2c3..."
      - id: USR-PATH-001
        type: path
        value: /var/secrets
        platform: linux
      - id: USR-ARG-001
        type: argument
        value: "--password"
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger("clawedr.user_rules")

USER_RULES_DIR = Path(os.path.expanduser("~/.clawedr"))
USER_RULES_PATH = USER_RULES_DIR / "user_rules.yaml"

# Valid custom rule types and their ID prefixes
CUSTOM_RULE_TYPES = {
    "executable": "USR-BIN",
    "domain": "USR-DOM",
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
                val = stripped[2:].strip().strip("\"'")
                result[current_key].append(val)
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
    """Return the set of Rule IDs the user has exempted."""
    rules = load_user_rules()
    return set(rules.get("exempted_rule_ids", []))


def get_custom_rules() -> list[dict[str, Any]]:
    """Return the list of user-defined custom blocking rules."""
    rules = load_user_rules()
    return list(rules.get("custom_rules", []))


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
        if not (_DOMAIN_RE.match(value) or _IP_RE.match(value)):
            if "://" in value:
                return False, "Enter a domain name, not a URL (e.g. 'evil.com' not 'https://evil.com')"
            return False, "Invalid domain or IP address format"

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


def add_custom_rule(
    rule_type: str, value: str, platform: str = "both"
) -> tuple[dict[str, Any] | None, str]:
    """Add a custom blocking rule. Returns (rule_dict, error_message)."""
    ok, err = validate_custom_rule(rule_type, value, platform)
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

    custom.append(new_rule)
    rules["custom_rules"] = custom
    save_user_rules(rules)
    logger.info("Added custom rule %s: %s = %s", new_id, rule_type, value)
    return new_rule, ""


def update_custom_rule(
    rule_id: str, value: str | None = None, platform: str | None = None
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
