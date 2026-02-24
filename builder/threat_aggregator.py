"""
ClawEDR Threat Aggregator — the "Intelligence Bridge".

Downloads the ClawSec advisory feed, extracts threat indicators,
and merges them with the local master_rules.yaml to produce a
unified threat-data object consumed by the compiler.
"""

from __future__ import annotations

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
        malicious_hashes — list[str]
        blocked_domains  — list[str]
        blocked_paths    — dict[str, list[str]]  (per-OS)
    """
    advisories = feed.get("advisories", [])
    affected_skills: list[str] = []
    malicious_hashes: list[str] = []
    blocked_domains: list[str] = []
    blocked_paths: dict[str, list[str]] = {"macos": [], "linux": []}

    for adv in advisories:
        affected_skills.extend(adv.get("affected_skills", []))
        malicious_hashes.extend(adv.get("malicious_hashes", []))
        blocked_domains.extend(adv.get("blocked_domains", []))
        for os_key in ("macos", "linux"):
            blocked_paths[os_key].extend(
                adv.get("blocked_paths", {}).get(os_key, [])
            )

    return {
        "affected_skills": sorted(set(affected_skills)),
        "malicious_hashes": sorted(set(malicious_hashes)),
        "blocked_domains": sorted(set(blocked_domains)),
        "blocked_paths": {k: sorted(set(v)) for k, v in blocked_paths.items()},
    }


def load_master_rules(path: Path = MASTER_RULES_PATH) -> dict[str, Any]:
    """Load the local master_rules.yaml."""
    logger.info("Loading master rules from %s", path)
    with open(path) as f:
        return yaml.safe_load(f) or {}


def merge(master: dict[str, Any], feed_data: dict[str, Any]) -> dict[str, Any]:
    """Merge community feed data ON TOP of manual master rules.

    Feed entries *add to* (never replace) manual rules.
    """
    merged: dict[str, Any] = {
        "version": master.get("version", "2.0"),
        "blocked_paths": {},
        "blocked_domains": [],
        "blocked_executables": list(master.get("blocked_executables", [])),
        "malicious_hashes": [],
        "affected_skills": list(feed_data.get("affected_skills", [])),
        "custom_deny_rules": master.get("custom_deny_rules", {}),
    }

    for os_key in ("macos", "linux"):
        master_paths = set(master.get("blocked_paths", {}).get(os_key, []))
        feed_paths = set(feed_data.get("blocked_paths", {}).get(os_key, []))
        merged["blocked_paths"][os_key] = sorted(master_paths | feed_paths)

    master_domains = set(master.get("blocked_domains", []))
    feed_domains = set(feed_data.get("blocked_domains", []))
    merged["blocked_domains"] = sorted(master_domains | feed_domains)

    master_hashes = set(master.get("malicious_hashes", []))
    feed_hashes = set(feed_data.get("malicious_hashes", []))
    merged["malicious_hashes"] = sorted(master_hashes | feed_hashes)

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
