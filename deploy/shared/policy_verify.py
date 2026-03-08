"""
ClawEDR Policy Signature Verification.

Verifies the integrity of compiled_policy.json using HMAC-SHA256 signatures.
The signature file (compiled_policy.json.sig) contains a hex-encoded HMAC
computed over the canonical JSON content.

Key management:
  - On first install, a random signing key is generated and stored at
    /etc/clawedr/policy_key (readable only by root).
  - The Forge (builder) signs policies during `./main.py publish`.
  - The Shield verifies before applying updates from the registry.

If no key exists (fresh install), verification is skipped and a warning
is logged. This avoids breaking upgrades from unsigned versions.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger("clawedr.policy_verify")

KEY_PATH = Path(os.environ.get("CLAWEDR_POLICY_KEY", "/etc/clawedr/policy_key"))


def _canonical_json(policy: dict[str, Any]) -> bytes:
    """Produce a stable JSON representation for signing (excludes _meta)."""
    copy = {k: v for k, v in policy.items() if k != "_meta" and k != "_signature"}
    return json.dumps(copy, sort_keys=True, separators=(",", ":")).encode()


def _decode_key(raw: bytes) -> bytes:
    """Decode a key that may be stored as hex-encoded text.

    The key file stores a hex string (64 ASCII chars for a 32-byte key).
    Raises ValueError if the content cannot be decoded to exactly 32 bytes.
    """
    text = raw.strip().decode("ascii")
    key = bytes.fromhex(text)
    if len(key) != 32:
        raise ValueError(f"Policy key must be 32 bytes; got {len(key)}")
    return key


def _load_key() -> bytes | None:
    """Load and decode the signing key from disk. Returns None if not found."""
    try:
        raw = KEY_PATH.read_bytes()
    except (FileNotFoundError, PermissionError):
        return None
    try:
        return _decode_key(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        logger.error("Policy key at %s is corrupt: %s", KEY_PATH, exc)
        return None


def generate_key() -> bytes:
    """Generate a new signing key and save it with restrictive permissions."""
    key = secrets.token_bytes(32)
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    KEY_PATH.write_bytes(key.hex().encode() + b"\n")
    os.chmod(KEY_PATH, 0o600)
    logger.info("Generated new policy signing key at %s", KEY_PATH)
    return key


def sign_policy(policy: dict[str, Any], key: bytes | None = None) -> str:
    """Compute HMAC-SHA256 signature for a policy dict. Returns hex string."""
    if key is None:
        key = _load_key()
    if key is None:
        key = generate_key()
    canonical = _canonical_json(policy)
    return hmac.new(key, canonical, hashlib.sha256).hexdigest()


def verify_policy(policy: dict[str, Any], signature: str | None = None) -> tuple[bool, str]:
    """Verify a policy's HMAC-SHA256 signature.

    Args:
        policy: The policy dict to verify.
        signature: Hex-encoded HMAC. If None, looks for _signature in policy.

    Returns:
        (ok, message) — ok=True if verified, False if failed.
        If no key exists, returns (True, "no key") to allow unsigned operation.
    """
    key = _load_key()
    if key is None:
        return True, "no signing key configured — skipping verification"

    if signature is None:
        signature = policy.get("_signature", "")

    if not signature:
        logger.warning("Policy has no signature — cannot verify integrity")
        return False, "policy has no signature"

    canonical = _canonical_json(policy)
    expected = hmac.new(key, canonical, hashlib.sha256).hexdigest()

    if hmac.compare_digest(expected, signature):
        return True, "signature valid"
    return False, "signature mismatch — policy may have been tampered with"


def sign_policy_file(policy_path: str) -> None:
    """Read a policy file, sign it, and atomically replace the file."""
    path = Path(policy_path)
    with open(path) as f:
        policy = json.load(f)

    # Remove old signature before computing new one
    policy.pop("_signature", None)
    sig = sign_policy(policy)
    policy["_signature"] = sig

    # Write to a temp file in the same directory, then atomically rename.
    # This prevents a race where another process reads a partially-written file.
    tmp_fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "w") as f:
            json.dump(policy, f, indent=2)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    logger.info("Signed policy at %s", path)
