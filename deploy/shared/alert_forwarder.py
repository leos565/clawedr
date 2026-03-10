"""
ClawEDR Alert Forwarder — webhook dispatch and REST API key management.

Webhooks receive a signed HTTP POST for every alert that meets their
configured minimum severity. Delivery is fire-and-forget (daemon thread)
with one automatic retry on transient failure.

API key management stores a single active token in settings.yaml under
the key ``alert_api_keys``. The raw key is only returned at generation
time; subsequent reads return a masked version (first 8 chars + "...").

Settings integration: all state is persisted via load_settings() /
save_settings() from shared.user_rules, so it survives daemon restarts
and is co-located with the rest of the ClawEDR configuration.

Example webhook configuration (in settings.yaml):
    webhooks:
      - url: https://example.com/clawedr-hook
        secret: s3cr3t
        min_severity: high
        enabled: true
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import threading
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("clawedr.alert_forwarder")

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
    "unknown": -1,
}

_DEFAULT_MIN_SEVERITY = "info"


def _severity_rank(s: str | None) -> int:
    return SEVERITY_RANK.get((s or "").lower(), -1)


# ---------------------------------------------------------------------------
# Settings helpers (lazy import to avoid circular deps at module load time)
# ---------------------------------------------------------------------------

def _load() -> dict[str, Any]:
    from shared.user_rules import load_settings
    return load_settings()


def _save(settings: dict[str, Any]) -> None:
    from shared.user_rules import save_settings
    save_settings(settings)


# ---------------------------------------------------------------------------
# Webhook forwarding
# ---------------------------------------------------------------------------

def _sign_body(secret: str, body: bytes) -> str:
    """Return ``sha256=<hex>`` HMAC signature over *body* using *secret*."""
    mac = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={mac}"


def _send_webhook(url: str, payload: dict[str, Any], secret: str | None) -> bool:
    """POST *payload* to *url* with optional HMAC signature header.

    Returns True on HTTP 2xx, False otherwise.
    """
    body = json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "ClawEDR-AlertForwarder/1.0",
        },
    )
    if secret:
        req.add_header("X-ClawEDR-Signature", _sign_body(secret, body))

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            status = resp.status
            logger.debug("Webhook %s responded with HTTP %d", url, status)
            return 200 <= status < 300
    except urllib.error.HTTPError as exc:
        logger.warning("Webhook %s returned HTTP %d: %s", url, exc.code, exc.reason)
        return False
    except Exception as exc:
        logger.warning("Webhook delivery to %s failed: %s", url, exc)
        return False


def _deliver_to_webhook(
    webhook: dict[str, Any],
    payload: dict[str, Any],
) -> None:
    """Deliver *payload* to one webhook with a single retry on failure."""
    url = webhook.get("url", "")
    secret = webhook.get("secret") or None

    if not url:
        return

    success = _send_webhook(url, payload, secret)
    if not success:
        logger.debug("Retrying webhook %s …", url)
        success = _send_webhook(url, payload, secret)

    if success:
        logger.info("Alert forwarded to webhook %s", url)
    else:
        logger.warning("Alert delivery to webhook %s failed after retry", url)


def forward_alert(alert: dict[str, Any]) -> None:
    """Dispatch *alert* to all enabled, qualifying webhooks.

    Each webhook is contacted in its own daemon thread (fire-and-forget).

    Expected alert keys:
        timestamp, rule_id, severity, details, blocked, fp (fingerprint)
    """
    settings = _load()
    webhooks: list[dict[str, Any]] = settings.get("webhooks", [])
    if not webhooks:
        return

    alert_severity = (alert.get("severity") or "").lower()
    alert_rank = _severity_rank(alert_severity)

    payload: dict[str, Any] = {
        "event": "alert",
        "timestamp": alert.get("timestamp"),
        "rule_id": alert.get("rule_id"),
        "severity": alert_severity or "unknown",
        "details": alert.get("details", {}),
        "blocked": bool(alert.get("blocked", False)),
        "fingerprint": alert.get("fp") or alert.get("fingerprint"),
    }

    for wh in webhooks:
        if not wh.get("enabled", True):
            continue
        min_sev = (wh.get("min_severity") or _DEFAULT_MIN_SEVERITY).lower()
        if alert_rank < _severity_rank(min_sev):
            logger.debug(
                "Skipping webhook %s (alert severity %s < min %s)",
                wh.get("url"), alert_severity, min_sev,
            )
            continue

        t = threading.Thread(
            target=_deliver_to_webhook,
            args=(wh, payload),
            daemon=True,
        )
        t.start()


# ---------------------------------------------------------------------------
# REST API key management
# ---------------------------------------------------------------------------

_KEYS_SETTING = "alert_api_keys"


def generate_api_key(name: str) -> dict[str, Any]:
    """Create a new API key, replacing any existing one.

    Returns the full key record (including the raw ``key`` value — this is
    the only time the unmasked key is returned).
    """
    raw_key = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    record: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "key": raw_key,
        "name": name.strip(),
        "created_at": now,
        "last_used_at": None,
    }

    settings = _load()
    settings[_KEYS_SETTING] = [record]   # enforce max 1 active key
    _save(settings)

    logger.info("Generated new API key '%s' (id=%s)", record["name"], record["id"])
    return record


def get_api_keys() -> list[dict[str, Any]]:
    """Return all stored API key records with the raw key masked.

    The ``key`` field is replaced with ``<first-8-chars>...``.
    """
    settings = _load()
    keys: list[dict[str, Any]] = settings.get(_KEYS_SETTING, [])
    masked: list[dict[str, Any]] = []
    for k in keys:
        rec = dict(k)
        raw = rec.get("key", "")
        rec["key"] = raw[:8] + "..." if len(raw) >= 8 else "***"
        masked.append(rec)
    return masked


def get_active_api_key() -> str | None:
    """Return the raw (unmasked) key for the single active API key, or None."""
    settings = _load()
    keys: list[dict[str, Any]] = settings.get(_KEYS_SETTING, [])
    if not keys:
        return None
    return keys[0].get("key") or None


def validate_api_key(provided: str) -> bool:
    """Return True if *provided* matches the active API key (timing-safe).

    Also updates ``last_used_at`` on a successful match.
    """
    active = get_active_api_key()
    if not active or not provided:
        return False

    match = hmac.compare_digest(
        active.encode("utf-8"),
        provided.encode("utf-8"),
    )

    if match:
        # Best-effort: update last_used_at without raising on failure
        try:
            settings = _load()
            keys: list[dict[str, Any]] = settings.get(_KEYS_SETTING, [])
            if keys:
                keys[0]["last_used_at"] = datetime.now(timezone.utc).isoformat(
                    timespec="seconds"
                )
                settings[_KEYS_SETTING] = keys
                _save(settings)
        except Exception as exc:
            logger.debug("Could not update last_used_at: %s", exc)

    return match
