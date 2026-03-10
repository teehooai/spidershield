"""Quality gate for LLM-generated security fix suggestions."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class FixResult:
    """Result of fix quality evaluation."""

    passed: bool
    suggestion: str
    code_fix: str | None = None
    rejection_reason: str | None = None
    confidence: float = 0.0  # 0.0-1.0


def score_fix(
    category: str,
    file_path: str,
    original_code: str,
    suggestion: str,
    code_fix: str | None = None,
) -> FixResult:
    """Score a generated fix suggestion for quality.

    Checks:
    1. Suggestion is non-empty and specific (not generic filler)
    2. Code fix (if any) is syntactically plausible
    3. Code fix preserves original functionality (doesn't delete too much)
    4. Fix addresses the stated category
    """
    if not suggestion.strip():
        return FixResult(
            passed=False, suggestion=suggestion,
            rejection_reason="empty suggestion",
        )

    # Reject generic filler
    filler_patterns = [
        r"^(fix|update|change|modify) (the|this) (code|file|issue)\.?$",
        r"^consider (fixing|updating|changing)",
        r"^TODO",
    ]
    for pat in filler_patterns:
        if re.match(pat, suggestion.strip(), re.IGNORECASE):
            return FixResult(
                passed=False, suggestion=suggestion,
                rejection_reason="generic filler suggestion",
            )

    confidence = 0.5  # base confidence for having a suggestion

    # Check category relevance
    category_keywords = {
        "credential": {"env", "secret", "key", "credential", "password", "token", "environ"},
        "path_traversal": {"path", "resolve", "relative", "directory", "traversal", "sanitize"},
        "sql_injection": {"parameterize", "placeholder", "prepared", "bind", "sql", "query"},
        "truncation": {"limit", "truncat", "max", "bound", "pagina"},
        "read_only": {"read", "only", "readonly", "write", "delete", "insert", "update"},
    }
    keywords = category_keywords.get(category, set())
    suggestion_lower = suggestion.lower()
    if keywords and any(kw in suggestion_lower for kw in keywords):
        confidence += 0.2

    # Score code fix quality
    if code_fix:
        code_fix = code_fix.strip()
        if len(code_fix) < 10:
            return FixResult(
                passed=False, suggestion=suggestion, code_fix=code_fix,
                rejection_reason="code fix too short",
            )

        # Check it doesn't just delete everything
        if code_fix.startswith("# ") and "\n" not in code_fix:
            return FixResult(
                passed=False, suggestion=suggestion, code_fix=code_fix,
                rejection_reason="code fix is just a comment",
            )

        # Check it contains actual code (not just prose)
        has_code = bool(re.search(
            r"(import |def |class |if |for |return |=\s|\.|\()",
            code_fix,
        ))
        if has_code:
            confidence += 0.2

        # Check it preserves some original structure
        if original_code:
            orig_lines = set(original_code.strip().splitlines())
            fix_lines = set(code_fix.strip().splitlines())
            if orig_lines and fix_lines:
                preserved = len(orig_lines & fix_lines) / len(orig_lines)
                if preserved < 0.1 and len(orig_lines) > 3:
                    return FixResult(
                        passed=False, suggestion=suggestion, code_fix=code_fix,
                        rejection_reason=f"code fix removes too much ({preserved:.0%} preserved)",
                    )
                confidence += min(0.1, preserved * 0.2)

    return FixResult(
        passed=True,
        suggestion=suggestion,
        code_fix=code_fix,
        confidence=round(min(1.0, confidence), 2),
    )


def diagnose_fix(category: str, suggestion: str, code_fix: str | None) -> list[str]:
    """Identify what's missing from a fix suggestion for retry feedback."""
    hints = []

    if not code_fix:
        hints.append(
            "Missing CODE FIX: Provide a concrete code snippet showing the fix. "
            "Include the fixed version of the affected code."
        )

    suggestion_lower = suggestion.lower()

    if "before" not in suggestion_lower and "after" not in suggestion_lower:
        hints.append(
            "Missing BEFORE/AFTER: Explain what changes from the original code."
        )

    if (
        category == "credential"
        and "env" not in suggestion_lower
        and "environ" not in suggestion_lower
    ):
        hints.append(
            "Missing ENV VAR guidance: Specify which environment variable name to use."
        )

    if category == "sql_injection" and "?" not in (code_fix or "") and "$" not in (code_fix or ""):
        hints.append(
            "Missing PARAMETERIZED QUERY: Show the query with ? or $1 placeholders."
        )

    if category == "path_traversal" and "resolve" not in (code_fix or "").lower():
        hints.append(
            "Missing PATH RESOLUTION: Show path.resolve() + startsWith/is_relative_to check."
        )

    return hints
