"""Prompt Injection Detector — scans tool outputs for injection attacks.

Detects attempts to hijack the agent through tool call results.
This is the key runtime defense: even if a tool is allowed, its OUTPUT
may contain prompt injection that tries to manipulate the agent.

Attack categories:
    1. Instruction Override — "ignore previous instructions", "you are now..."
    2. ASCII Smuggling — invisible Unicode characters hiding payloads
    3. System Prompt Markers — <system>, [INST], <|im_start|>system
    4. Tool Manipulation — attempts to make agent call specific tools
    5. Context Hijacking — attempts to redefine agent's role/goals

Patterns ported from SpiderShield (TS-E007, TS-E009, TS-E010) plus
runtime-specific patterns for tool output scanning.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class PICategory(StrEnum):
    """Prompt injection attack category."""

    INSTRUCTION_OVERRIDE = "instruction_override"
    ASCII_SMUGGLING = "ascii_smuggling"
    SYSTEM_PROMPT = "system_prompt"
    TOOL_MANIPULATION = "tool_manipulation"
    CONTEXT_HIJACK = "context_hijack"


@dataclass
class PIMatch:
    """A prompt injection detection match."""

    category: PICategory
    pattern_name: str
    matched_text: str
    start: int
    end: int
    severity: str  # "critical" or "high"
    description: str


# --- Pattern Definitions ---
# Each: (name, category, regex, severity, description)

_PI_PATTERNS: list[tuple[str, PICategory, str, str, str]] = [
    # === Instruction Override (from SpiderShield TS-E007) ===
    (
        "ignore_instructions",
        PICategory.INSTRUCTION_OVERRIDE,
        r"(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|all|above|your)\s+"
        r"(?:instructions?|prompts?|rules?|constraints?|guidelines?)",
        "critical",
        "Attempts to override agent instructions",
    ),
    (
        "new_identity",
        PICategory.INSTRUCTION_OVERRIDE,
        r"(?:you\s+are\s+now\s+|new\s+system\s+prompt|"
        r"override\s+(?:your|the)\s+instructions?)",
        "critical",
        "Attempts to assign new identity or system prompt",
    ),
    (
        "remove_restrictions",
        PICategory.INSTRUCTION_OVERRIDE,
        r"(?:pretend\s+you\s+(?:are|have)\s+(?:an?\s+)?(?:AI|model|assistant)\s+"
        r"(?:without|with\s+no)|"
        r"act\s+as\s+if\s+you\s+have\s+no\s+"
        r"(?:restrictions?|limitations?|rules?|guardrails?))",
        "critical",
        "Attempts to remove safety restrictions",
    ),
    # === ASCII Smuggling (from SpiderShield TS-E009) ===
    (
        "invisible_unicode",
        PICategory.ASCII_SMUGGLING,
        r"[\u200b\u200c\u200d\u2060\ufeff]",
        "high",
        "Invisible Unicode characters (potential hidden payload)",
    ),
    (
        "unicode_tag_chars",
        PICategory.ASCII_SMUGGLING,
        r"[\U000e0001-\U000e007f]",
        "high",
        "Unicode tag characters used for ASCII smuggling",
    ),
    # === System Prompt Markers (from SpiderShield TS-E010) ===
    (
        "system_prompt_tags",
        PICategory.SYSTEM_PROMPT,
        r"(?:<system>|</system>|<\|im_start\|>system|<\|system\|>|"
        r"\[INST\]|\[/INST\]|\[SYS\]|<\|assistant\|>|<\|user\|>)",
        "critical",
        "LLM-specific prompt format markers in tool output",
    ),
    (
        "xml_injection_tags",
        PICategory.SYSTEM_PROMPT,
        r"<(?:system[-_]?prompt|internal[-_]?instructions|"
        r"hidden[-_]?instructions|secret[-_]?prompt)>",
        "critical",
        "XML tags attempting to inject system-level directives",
    ),
    # === Tool Manipulation (runtime-specific) ===
    (
        "tool_call_injection",
        PICategory.TOOL_MANIPULATION,
        r"(?:(?:now|next|please|must|should)\s+(?:call|use|execute|run|invoke)\s+"
        r"(?:the\s+)?(?:tool|function|command)\s+)",
        "high",
        "Attempts to make agent call specific tools",
    ),
    (
        "function_call_json",
        PICategory.TOOL_MANIPULATION,
        r'\{\s*"(?:tool|function|tool_name|action)"\s*:\s*"[^"]+"\s*,\s*'
        r'"(?:arguments|args|parameters|params)"\s*:',
        "high",
        "Embedded tool call JSON in output (potential injection)",
    ),
    # === Context Hijacking (runtime-specific) ===
    (
        "role_reassignment",
        PICategory.CONTEXT_HIJACK,
        r"(?:from\s+now\s+on|starting\s+now|henceforth)\s+(?:you|your)\s+"
        r"(?:will|must|should|are|primary)",
        "critical",
        "Attempts to redefine agent's role or behavior",
    ),
    (
        "goal_override",
        PICategory.CONTEXT_HIJACK,
        r"(?:your\s+(?:new|real|true|actual|primary)\s+"
        r"(?:goal|objective|purpose|mission|task)\s+is)",
        "critical",
        "Attempts to override agent's goals",
    ),
]

# Pre-compile patterns
_COMPILED_PATTERNS: list[tuple[str, PICategory, re.Pattern[str], str, str]] = [
    (name, cat, re.compile(pattern, re.IGNORECASE | re.DOTALL), sev, desc)
    for name, cat, pattern, sev, desc in _PI_PATTERNS
]


def detect_prompt_injection(text: str) -> list[PIMatch]:
    """Scan text for prompt injection patterns.

    Args:
        text: The text to scan (typically tool output).

    Returns:
        List of PIMatch objects for each detection.
    """
    if not text or len(text) < 3:
        return []

    matches: list[PIMatch] = []

    for name, category, pattern, severity, description in _COMPILED_PATTERNS:
        for m in pattern.finditer(text):
            matches.append(PIMatch(
                category=category,
                pattern_name=name,
                matched_text=m.group()[:100],  # truncate for safety
                start=m.start(),
                end=m.end(),
                severity=severity,
                description=description,
            ))

    return matches
