"""Secret detection patterns for DLP.

Detects common secret/credential patterns in tool output:
- API keys (AWS, OpenAI, Stripe, GitHub, Google, Slack, etc.)
- Private keys (RSA, EC, OPENSSH)
- JWT tokens
- Database connection strings
- Generic high-entropy strings
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from enum import StrEnum


class SecretType(StrEnum):
    """Types of secrets that can be detected."""

    AWS_KEY = "aws_key"
    AWS_SECRET = "aws_secret"
    OPENAI_KEY = "openai_key"
    ANTHROPIC_KEY = "anthropic_key"
    STRIPE_KEY = "stripe_key"
    GITHUB_TOKEN = "github_token"
    GOOGLE_API_KEY = "google_api_key"
    SLACK_TOKEN = "slack_token"
    PRIVATE_KEY = "private_key"
    JWT = "jwt"
    DB_CONNECTION = "db_connection"
    GENERIC_SECRET = "generic_secret"


@dataclass(frozen=True)
class SecretPattern:
    """A compiled secret detection pattern."""

    secret_type: SecretType
    pattern: re.Pattern[str]
    severity: str  # "critical", "high", "medium"


_SECRET_PATTERNS: list[SecretPattern] = [
    # AWS Access Key ID
    SecretPattern(
        secret_type=SecretType.AWS_KEY,
        pattern=re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        severity="critical",
    ),
    # AWS Secret Access Key (40 char base64)
    SecretPattern(
        secret_type=SecretType.AWS_SECRET,
        pattern=re.compile(
            r"(?:aws_secret_access_key|secret_key|aws_secret)"
            r"[\s]*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
        severity="critical",
    ),
    # Anthropic API key (before OpenAI — more specific prefix)
    SecretPattern(
        secret_type=SecretType.ANTHROPIC_KEY,
        pattern=re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{20,})\b"),
        severity="critical",
    ),
    # OpenAI API key (exclude sk-ant- which is Anthropic)
    SecretPattern(
        secret_type=SecretType.OPENAI_KEY,
        pattern=re.compile(r"\b(sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,})\b"),
        severity="critical",
    ),
    # Stripe API keys
    SecretPattern(
        secret_type=SecretType.STRIPE_KEY,
        pattern=re.compile(r"\b((?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,})\b"),
        severity="critical",
    ),
    # GitHub tokens
    SecretPattern(
        secret_type=SecretType.GITHUB_TOKEN,
        pattern=re.compile(
            r"\b(gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"
        ),
        severity="critical",
    ),
    # Google API key
    SecretPattern(
        secret_type=SecretType.GOOGLE_API_KEY,
        pattern=re.compile(r"\b(AIza[A-Za-z0-9_-]{35})\b"),
        severity="high",
    ),
    # Slack tokens
    SecretPattern(
        secret_type=SecretType.SLACK_TOKEN,
        pattern=re.compile(r"\b(xox[bpras]-[A-Za-z0-9-]{10,})\b"),
        severity="critical",
    ),
    # Private keys
    SecretPattern(
        secret_type=SecretType.PRIVATE_KEY,
        pattern=re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
        ),
        severity="critical",
    ),
    # JWT tokens
    SecretPattern(
        secret_type=SecretType.JWT,
        pattern=re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
        ),
        severity="high",
    ),
    # Database connection strings
    SecretPattern(
        secret_type=SecretType.DB_CONNECTION,
        pattern=re.compile(
            r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql)"
            r"://[^\s'\"]{10,}"
        ),
        severity="high",
    ),
]


@dataclass
class SecretMatch:
    """A detected secret occurrence."""

    secret_type: SecretType
    value: str
    masked: str
    start: int
    end: int
    severity: str


def _mask_secret(value: str, secret_type: SecretType) -> str:
    """Create a masked version of a secret value."""
    if secret_type == SecretType.PRIVATE_KEY:
        return "-----BEGIN ***PRIVATE KEY***-----"
    if secret_type == SecretType.DB_CONNECTION:
        # Show protocol, mask credentials
        match = re.match(r"(\w+://)[^\s]+", value)
        return f"{match.group(1)}***" if match else "***://***"
    if secret_type == SecretType.JWT:
        return f"{value[:10]}...{value[-6:]}"
    # For API keys: show prefix, mask rest
    if len(value) > 8:
        return f"{value[:8]}...{'*' * min(8, len(value) - 8)}"
    return "***"


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


# High-entropy generic secret pattern (base64-ish, length > 32)
# Excludes = and + to avoid matching assignment expressions like KEY=value
_HIGH_ENTROPY_PATTERN = re.compile(r"\b[A-Za-z0-9/_-]{32,}\b")
_ENTROPY_THRESHOLD = 4.0  # bits per character


def detect_secrets(text: str) -> list[SecretMatch]:
    """Scan text for secret/credential patterns.

    Returns a list of SecretMatch objects for each detected occurrence.
    """
    matches: list[SecretMatch] = []
    seen_spans: set[tuple[int, int]] = set()

    for pattern_def in _SECRET_PATTERNS:
        for m in pattern_def.pattern.finditer(text):
            # Use first capture group if present, else full match
            value = m.group(1) if m.lastindex else m.group()
            start = m.start(1) if m.lastindex else m.start()
            end = m.end(1) if m.lastindex else m.end()

            span = (start, end)
            if span in seen_spans:
                continue
            seen_spans.add(span)

            matches.append(SecretMatch(
                secret_type=pattern_def.secret_type,
                value=value,
                masked=_mask_secret(value, pattern_def.secret_type),
                start=start,
                end=end,
                severity=pattern_def.severity,
            ))

    # Generic high-entropy detection (only if no specific pattern matched)
    for m in _HIGH_ENTROPY_PATTERN.finditer(text):
        value = m.group()
        span = (m.start(), m.end())

        # Skip if overlapping with any specific pattern match
        if any(
            s[0] < span[1] and span[0] < s[1]
            for s in seen_spans
        ):
            continue

        entropy = _shannon_entropy(value)
        if entropy >= _ENTROPY_THRESHOLD:
            matches.append(SecretMatch(
                secret_type=SecretType.GENERIC_SECRET,
                value=value,
                masked=f"{value[:6]}...{'*' * 8}",
                start=m.start(),
                end=m.end(),
                severity="medium",
            ))

    return matches
