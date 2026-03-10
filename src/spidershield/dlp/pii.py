"""PII (Personally Identifiable Information) detection patterns.

Detects common PII types in text output from tool calls:
- Credit card numbers (Visa, Mastercard, Amex, Discover)
- SSN (US Social Security Numbers)
- Email addresses
- Phone numbers (US/international)
- IP addresses (with internal network flagging)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class PIIType(StrEnum):
    """Types of PII that can be detected."""

    CREDIT_CARD = "credit_card"
    SSN = "ssn"
    EMAIL = "email"
    PHONE = "phone"
    IP_ADDRESS = "ip_address"
    IP_INTERNAL = "ip_internal"


@dataclass(frozen=True)
class PIIPattern:
    """A compiled PII detection pattern."""

    pii_type: PIIType
    pattern: re.Pattern[str]
    severity: str  # "high", "medium", "low"
    validator: str = ""  # optional validator function name


# Luhn checksum for credit card validation
def _luhn_check(number: str) -> bool:
    """Validate a number string using the Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _is_internal_ip(ip: str) -> bool:
    """Check if an IP address is in a private/internal range."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    # 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if octets[0] == 127:
        return True
    return False


# Pattern definitions
_PII_PATTERNS: list[PIIPattern] = [
    # Credit cards: 13-19 digits, optionally separated by spaces or dashes
    PIIPattern(
        pii_type=PIIType.CREDIT_CARD,
        pattern=re.compile(
            r"\b(?:"
            r"4[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{1,4}"  # Visa
            r"|5[1-5][0-9]{2}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}"  # MC
            r"|3[47][0-9]{1,2}[\s-]?[0-9]{4,6}[\s-]?[0-9]{4,5}"  # Amex
            r"|6(?:011|5[0-9]{2})[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}"  # Disc
            r")\b"
        ),
        severity="high",
        validator="luhn",
    ),
    # US SSN: xxx-xx-xxxx
    PIIPattern(
        pii_type=PIIType.SSN,
        pattern=re.compile(
            r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"
        ),
        severity="high",
    ),
    # Email addresses
    PIIPattern(
        pii_type=PIIType.EMAIL,
        pattern=re.compile(
            r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
        ),
        severity="medium",
    ),
    # Phone numbers (US format and international)
    PIIPattern(
        pii_type=PIIType.PHONE,
        pattern=re.compile(
            r"(?:\+?1[-.\s]?)?"
            r"\(?[2-9]\d{2}\)?[-.\s]?"
            r"\d{3}[-.\s]?"
            r"\d{4}\b"
        ),
        severity="medium",
    ),
    # IP addresses (IPv4)
    PIIPattern(
        pii_type=PIIType.IP_ADDRESS,
        pattern=re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        severity="low",
    ),
]


@dataclass
class PIIMatch:
    """A detected PII occurrence."""

    pii_type: PIIType
    value: str
    masked: str
    start: int
    end: int
    severity: str


def _mask_value(value: str, pii_type: PIIType) -> str:
    """Create a masked version of a PII value."""
    if pii_type == PIIType.CREDIT_CARD:
        digits = re.sub(r"[\s-]", "", value)
        return f"****-****-****-{digits[-4:]}"
    if pii_type == PIIType.SSN:
        return f"***-**-{value[-4:]}"
    if pii_type == PIIType.EMAIL:
        local, domain = value.split("@", 1)
        return f"{local[0]}***@{domain}"
    if pii_type == PIIType.PHONE:
        digits = re.sub(r"[^\d]", "", value)
        return f"***-***-{digits[-4:]}"
    if pii_type in (PIIType.IP_ADDRESS, PIIType.IP_INTERNAL):
        parts = value.split(".")
        return f"{parts[0]}.{parts[1]}.*.*"
    return "***"


def detect_pii(text: str) -> list[PIIMatch]:
    """Scan text for PII patterns.

    Returns a list of PIIMatch objects for each detected occurrence.
    """
    matches: list[PIIMatch] = []

    for pattern_def in _PII_PATTERNS:
        for m in pattern_def.pattern.finditer(text):
            value = m.group()

            # Credit card Luhn validation
            if pattern_def.validator == "luhn":
                digits = re.sub(r"[\s-]", "", value)
                if not _luhn_check(digits):
                    continue

            # Classify internal IPs separately
            pii_type = pattern_def.pii_type
            if pii_type == PIIType.IP_ADDRESS and _is_internal_ip(value):
                pii_type = PIIType.IP_INTERNAL

            matches.append(PIIMatch(
                pii_type=pii_type,
                value=value,
                masked=_mask_value(value, pii_type),
                start=m.start(),
                end=m.end(),
                severity="medium" if pii_type == PIIType.IP_INTERNAL else pattern_def.severity,
            ))

    return matches
