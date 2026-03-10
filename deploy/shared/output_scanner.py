"""
ClawEDR Output Scanner — Pattern library for secrets and PII detection.

Scans content captured from OpenClaw's stdout for secrets and PII before
they reach the user or are written to disk.

Rule ID prefix: OUT-* (output scan) / INJ-* (injection detection)
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Scan match result
# ---------------------------------------------------------------------------

@dataclass
class ScanMatch:
    rule_id: str
    category: str
    description: str
    matched_value: str  # Truncated + partially redacted for safe logging
    start: int
    end: int


# ---------------------------------------------------------------------------
# Output scanner patterns (secrets / PII in LLM responses)
# ---------------------------------------------------------------------------

# Each entry: (rule_id, category, description, regex_pattern)
_OUTPUT_PATTERN_DEFS: list[tuple[str, str, str, str]] = [
    # Cloud credentials
    ("OUT-001", "cloud_credentials", "AWS Access Key ID",
     r"AKIA[0-9A-Z]{16}"),
    ("OUT-002", "cloud_credentials", "AWS Secret Access Key",
     r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    ("OUT-003", "cloud_credentials", "Azure Connection String",
     r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,};"),
    # VCS / developer tokens
    ("OUT-004", "vcs_tokens", "GitHub Token",
     r"gh[opsp]_[A-Za-z0-9]{36,}"),
    ("OUT-005", "vcs_tokens", "npm Token",
     r"npm_[A-Za-z0-9]{36}"),
    ("OUT-006", "vcs_tokens", "GitLab PAT",
     r"glpat-[A-Za-z0-9_-]{20,}"),
    # API keys
    ("OUT-007", "api_keys", "OpenAI API Key",
     r"sk-[A-Za-z0-9]{48}"),
    ("OUT-008", "api_keys", "Anthropic API Key",
     r"sk-ant-api\d{2}-[A-Za-z0-9_-]{90,}"),
    ("OUT-009", "api_keys", "Google API Key",
     r"AIza[0-9A-Za-z_-]{35}"),
    ("OUT-010", "api_keys", "Slack Token",
     r"xox[baprs]-[0-9A-Za-z]{10,48}"),
    ("OUT-011", "api_keys", "Stripe Secret Key",
     r"sk_live_[0-9a-zA-Z]{24,}"),
    ("OUT-012", "api_keys", "Twilio Account SID",
     r"AC[a-zA-Z0-9]{32}"),
    # Private keys
    ("OUT-013", "private_keys", "Private Key Block",
     r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"),
    # PII
    ("OUT-014", "pii", "Social Security Number",
     r"\b\d{3}-\d{2}-\d{4}\b"),
    ("OUT-015", "pii", "Credit Card Number (Visa/MC/Amex/Discover)",
     r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
    ("OUT-016", "pii", "Bulk Email Addresses",
     r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
]

# Category display names
CATEGORY_LABELS: dict[str, str] = {
    "cloud_credentials": "Cloud Credentials",
    "api_keys": "API Keys",
    "vcs_tokens": "VCS / Dev Tokens",
    "private_keys": "Private Keys",
    "pii": "PII / Personal Data",
}

# Compiled pattern cache: rule_id -> (category, description, compiled_re)
_COMPILED_OUTPUT: dict[str, tuple[str, str, re.Pattern]] = {}

def _ensure_compiled() -> None:
    for rule_id, category, description, pattern in _OUTPUT_PATTERN_DEFS:
        if rule_id not in _COMPILED_OUTPUT:
            _COMPILED_OUTPUT[rule_id] = (category, description, re.compile(pattern))


# ---------------------------------------------------------------------------
# Injection detection patterns (content flowing INTO the agent)
# ---------------------------------------------------------------------------

_INJECTION_PATTERN_DEFS: list[tuple[str, str, str, str]] = [
    ("INJ-001", "instruction_override", "Ignore Previous Instructions",
     r"(?i)ignore\s+(all\s+)?previous\s+instructions?"),
    ("INJ-002", "instruction_override", "Override System Prompt",
     r"(?i)override\s+(the\s+)?system\s+prompt"),
    ("INJ-003", "hidden_directive", "Hidden User Directive",
     r"(?i)DO\s+NOT\s+(?:DISPLAY|SHOW)\s+(?:THIS\s+)?(?:TO\s+)?(?:THE\s+)?USER"),
    ("INJ-004", "persona_hijack", "Mode Switching Injection",
     r"(?i)you\s+are\s+now\s+(?:in\s+)?\w[\w\s]*\s+mode"),
    ("INJ-005", "persona_hijack", "New Task Injection",
     r"(?i)your\s+new\s+(?:task|instructions?|role|objective)\s+is"),
    ("INJ-006", "steganography", "Zero-Width Unicode Steganography",
     r"[\u200b\u200c\u200d\ufeff\u2060\u00ad]"),
    ("INJ-007", "instruction_override", "Disregard Constraints",
     r"(?i)(?:disregard|forget|ignore)\s+(?:all\s+)?(?:previous\s+)?(?:instructions?|constraints?|rules?|guidelines?)"),
    ("INJ-008", "persona_hijack", "Act As Persona Injection",
     r"(?i)(?:act|behave|respond)\s+as\s+(?:if\s+(?:you\s+are\s+)?)?a\s+\w[\w\s]*"),
    ("INJ-009", "data_exfil", "Exfiltration Instruction",
     r"(?i)(?:send|transmit|upload|exfiltrate|leak)\s+(?:all\s+)?(?:this\s+)?(?:data|information|files?|secrets?)\s+to"),
    ("INJ-010", "instruction_override", "Jailbreak Instruction",
     r"(?i)(?:jailbreak|DAN|developer\s+mode|unrestricted\s+mode)"),
]

_COMPILED_INJECTION: dict[str, tuple[str, str, re.Pattern]] = {}

def _ensure_injection_compiled() -> None:
    for rule_id, category, description, pattern in _INJECTION_PATTERN_DEFS:
        if rule_id not in _COMPILED_INJECTION:
            _COMPILED_INJECTION[rule_id] = (category, description, re.compile(pattern))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_output(data: bytes, enabled_categories: set[str] | None = None) -> list[ScanMatch]:
    """Scan LLM output content for secrets and PII.

    Args:
        data: Raw bytes from stdout capture.
        enabled_categories: If set, only scan patterns in these categories.

    Returns:
        List of ScanMatch objects, one per match found.
    """
    _ensure_compiled()
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return []

    matches: list[ScanMatch] = []
    for rule_id, (category, description, compiled_re) in _COMPILED_OUTPUT.items():
        if enabled_categories and category not in enabled_categories:
            continue
        for m in compiled_re.finditer(text):
            raw = m.group(0)
            redacted = _redact(raw)
            matches.append(ScanMatch(
                rule_id=rule_id,
                category=category,
                description=description,
                matched_value=redacted,
                start=m.start(),
                end=m.end(),
            ))
    return matches


def scan_for_injection(data: bytes, enabled_categories: set[str] | None = None) -> list[ScanMatch]:
    """Scan tool result / file content flowing into the agent for injection patterns.

    Args:
        data: Raw bytes from a child subprocess stdout write.
        enabled_categories: If set, only scan patterns in these categories.

    Returns:
        List of ScanMatch objects, one per match found.
    """
    _ensure_injection_compiled()
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return []

    matches: list[ScanMatch] = []
    for rule_id, (category, description, compiled_re) in _COMPILED_INJECTION.items():
        if enabled_categories and category not in enabled_categories:
            continue
        for m in compiled_re.finditer(text):
            raw = m.group(0)
            redacted = _redact(raw)
            matches.append(ScanMatch(
                rule_id=rule_id,
                category=category,
                description=description,
                matched_value=redacted,
                start=m.start(),
                end=m.end(),
            ))
    return matches


def get_output_patterns() -> list[dict]:
    """Return all output scanner pattern definitions (for API/UI)."""
    return [
        {
            "rule_id": rule_id,
            "category": category,
            "description": description,
        }
        for rule_id, category, description, _ in _OUTPUT_PATTERN_DEFS
    ]


def get_injection_patterns() -> list[dict]:
    """Return all injection detection pattern definitions (for API/UI)."""
    return [
        {
            "rule_id": rule_id,
            "category": category,
            "description": description,
        }
        for rule_id, category, description, _ in _INJECTION_PATTERN_DEFS
    ]


def _redact(value: str) -> str:
    """Truncate and partially redact a matched value for safe logging."""
    if len(value) <= 8:
        return value[:4] + "***"
    return value[:6] + "..." + value[-3:]
