"""
ClawEDR Threat Aggregator — the "Intelligence Bridge".

Downloads the ClawSec advisory feed, extracts threat indicators,
and merges them with the local master_rules.yaml to produce a
unified threat-data object consumed by the compiler.

Rule IDs:
  - Manual rules use explicit IDs (BIN-xxx, LIN-xxx, etc.)
  - Feed-sourced rules get deterministic IDs prefixed with THRT-
    (e.g. THRT-BIN-a1b2c3d4) based on a hash of the payload.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

import requests
import yaml

logger = logging.getLogger(__name__)

CLAWSEC_FEED_URL = "https://clawsec.prompt.security/advisories/feed.json"
BUILDER_DIR = Path(__file__).resolve().parent
MASTER_RULES_PATH = BUILDER_DIR / "master_rules.yaml"
MERGED_RULES_PATH = BUILDER_DIR / ".merged_rules.json"


def _thrt_id(prefix: str, value: str) -> str:
    """Generate a deterministic threat-feed Rule ID from a prefix and value."""
    h = hashlib.sha256(value.encode()).hexdigest()[:8]
    return f"THRT-{prefix}-{h}"


def fetch_feed(url: str = CLAWSEC_FEED_URL, timeout: int = 30) -> dict[str, Any]:
    """Download and return the ClawSec advisory feed as a dict."""
    logger.info("Fetching ClawSec feed from %s", url)
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    feed = resp.json()
    logger.info("Feed fetched — %d advisories", len(feed.get("advisories", [])))
    return feed


def parse_feed(feed: dict[str, Any]) -> dict[str, Any]:
    """Extract threat indicators from the raw feed.

    Returns a dict with keys:
        affected_skills  — list[str]
        malicious_hashes — dict[str, str]  (rule_id -> hash)
        blocked_domains  — dict[str, str]  (rule_id -> domain)
        blocked_paths    — dict[str, dict[str, str]]  (per-OS, rule_id -> path)
    """
    advisories = feed.get("advisories", [])
    affected_skills: list[str] = []
    malicious_hashes: dict[str, str] = {}
    blocked_domains: dict[str, str] = {}
    blocked_paths: dict[str, dict[str, str]] = {"macos": {}, "linux": {}}

    for adv in advisories:
        affected_skills.extend(adv.get("affected_skills", []))

        for h in adv.get("malicious_hashes", []):
            malicious_hashes[_thrt_id("HASH", h)] = h

        for d in adv.get("blocked_domains", []):
            blocked_domains[_thrt_id("DOM", d)] = d

        for os_key in ("macos", "linux"):
            for p in adv.get("blocked_paths", {}).get(os_key, []):
                blocked_paths[os_key][_thrt_id("PATH", p)] = p

    return {
        "affected_skills": sorted(set(affected_skills)),
        "malicious_hashes": malicious_hashes,
        "blocked_domains": blocked_domains,
        "blocked_paths": blocked_paths,
    }


def load_master_rules(path: Path = MASTER_RULES_PATH) -> dict[str, Any]:
    """Load the local master_rules.yaml."""
    logger.info("Loading master rules from %s", path)
    with open(path) as f:
        return yaml.safe_load(f) or {}


def merge(master: dict[str, Any], feed_data: dict[str, Any]) -> dict[str, Any]:
    """Merge community feed data ON TOP of manual master rules.

    Feed entries *add to* (never replace) manual rules.
    All values are now dicts keyed by Rule ID.
    """
    merged: dict[str, Any] = {
        "version": master.get("version", "2.0"),
        "blocked_paths": {},
        "blocked_domains": {},
        "blocked_executables": dict(master.get("blocked_executables", {})),
        "malicious_hashes": {},
        "affected_skills": list(feed_data.get("affected_skills", [])),
        "custom_deny_rules": master.get("custom_deny_rules", {}),
    }

    # Merge blocked_paths per OS
    for os_key in ("macos", "linux"):
        master_paths = dict(master.get("blocked_paths", {}).get(os_key, {}))
        feed_paths = dict(feed_data.get("blocked_paths", {}).get(os_key, {}))
        merged["blocked_paths"][os_key] = {**master_paths, **feed_paths}

    # Merge blocked_domains
    master_domains = dict(master.get("blocked_domains", {}))
    feed_domains = dict(feed_data.get("blocked_domains", {}))
    merged["blocked_domains"] = {**master_domains, **feed_domains}

    # Merge malicious_hashes
    master_hashes = dict(master.get("malicious_hashes", {}))
    feed_hashes = dict(feed_data.get("malicious_hashes", {}))
    merged["malicious_hashes"] = {**master_hashes, **feed_hashes}

    return merged


def save_merged(merged: dict[str, Any], path: Path = MERGED_RULES_PATH) -> Path:
    """Write the merged rules to disk as JSON."""
    with open(path, "w") as f:
        json.dump(merged, f, indent=2)
    logger.info("Merged rules written to %s", path)
    return path


def sync(feed_url: str = CLAWSEC_FEED_URL) -> dict[str, Any]:
    """Full sync pipeline: fetch -> parse -> merge -> save. Returns merged data."""
    feed = fetch_feed(feed_url)
    feed_data = parse_feed(feed)
    master = load_master_rules()
    merged = merge(master, feed_data)
    save_merged(merged)
    return merged


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    data = sync()
    print(json.dumps(data, indent=2))
