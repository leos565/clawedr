"""
ClawEDR User Rules — runtime overrides.

Reads ~/.clawedr/user_rules.yaml and provides helpers for the Shield
daemons to check whether a Rule ID has been exempted by the user.

This module has no third-party dependencies (PyYAML is optional; falls
back to a minimal inline parser for the simple list format we use).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger("clawedr.user_rules")

USER_RULES_DIR = Path(os.path.expanduser("~/.clawedr"))
USER_RULES_PATH = USER_RULES_DIR / "user_rules.yaml"


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load a YAML file, trying PyYAML first then falling back to JSON."""
    try:
        import yaml
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        pass

    # Minimal fallback: the user_rules.yaml is simple enough to parse
    # as a list of "- value" lines under a single key.
    import json
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, ValueError):
        pass

    # Last resort: line-by-line parse
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
    """Load user rules from ~/.clawedr/user_rules.yaml.

    Returns an empty dict if the file doesn't exist.
    """
    if not USER_RULES_PATH.exists():
        logger.info("No user rules file at %s", USER_RULES_PATH)
        return {}

    try:
        rules = _load_yaml(USER_RULES_PATH)
        logger.info(
            "Loaded user rules: %d exempted rule IDs",
            len(rules.get("exempted_rule_ids", [])),
        )
        return rules
    except Exception as exc:
        logger.warning("Failed to load user rules from %s: %s", USER_RULES_PATH, exc)
        return {}


def get_exempted_rule_ids() -> set[str]:
    """Return the set of Rule IDs the user has exempted."""
    rules = load_user_rules()
    return set(rules.get("exempted_rule_ids", []))


def save_user_rules(rules: dict[str, Any]) -> None:
    """Write user rules to ~/.clawedr/user_rules.yaml."""
    USER_RULES_DIR.mkdir(parents=True, exist_ok=True)
    try:
        import yaml
        with open(USER_RULES_PATH, "w") as f:
            yaml.dump(rules, f, default_flow_style=False, sort_keys=False)
    except ImportError:
        # Fallback: write a simple YAML-compatible format
        with open(USER_RULES_PATH, "w") as f:
            f.write("# ClawEDR User Rules\n")
            f.write("# Managed by the ClawEDR Dashboard\n\n")
            for key, values in rules.items():
                f.write(f"{key}:\n")
                if isinstance(values, list):
                    for v in values:
                        f.write(f'  - "{v}"\n')
                f.write("\n")
    logger.info("User rules saved to %s", USER_RULES_PATH)
