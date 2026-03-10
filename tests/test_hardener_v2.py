"""Tests for hardener v2: LLM mode, quality gate, self-check loop."""

from __future__ import annotations

from pathlib import Path

from spidershield.hardener.prompt import HARDEN_SYSTEM_PROMPT, build_harden_prompt
from spidershield.hardener.quality_gate import diagnose_fix, score_fix
from spidershield.hardener.runner import (
    HardenFinding,
    _enhance_with_llm,
    _parse_fix_response,
    _scan_issues,
)

# --- Quality Gate Tests ---


class TestFixQualityGate:
    def test_rejects_empty_suggestion(self) -> None:
        result = score_fix("credential", "server.py", "", "")
        assert not result.passed
        assert result.rejection_reason == "empty suggestion"

    def test_rejects_generic_filler(self) -> None:
        result = score_fix("credential", "server.py", "", "Fix the code.")
        assert not result.passed
        assert "generic" in result.rejection_reason

    def test_rejects_short_code_fix(self) -> None:
        result = score_fix("credential", "server.py", "", "Move to env.", code_fix="x=1")
        assert not result.passed
        assert "too short" in result.rejection_reason

    def test_rejects_comment_only_fix(self) -> None:
        result = score_fix(
            "credential", "server.py", "",
            "Move credentials to env.",
            code_fix="# Use env vars instead",
        )
        assert not result.passed
        assert "comment" in result.rejection_reason

    def test_accepts_good_suggestion(self) -> None:
        result = score_fix(
            "credential", "server.py", "",
            "Move API key to environment variable for security.",
        )
        assert result.passed
        assert result.confidence >= 0.5

    def test_higher_confidence_with_category_keywords(self) -> None:
        base = score_fix("credential", "server.py", "", "Some generic suggestion.")
        enhanced = score_fix(
            "credential", "server.py", "",
            "Move secret key to environment variable.",
        )
        assert enhanced.confidence > base.confidence

    def test_code_fix_boosts_confidence(self) -> None:
        no_code = score_fix(
            "sql_injection", "db.py", "",
            "Use parameterized queries for SQL safety.",
        )
        with_code = score_fix(
            "sql_injection", "db.py", "",
            "Use parameterized queries for SQL safety.",
            code_fix='cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        )
        assert with_code.confidence > no_code.confidence

    def test_rejects_destructive_fix(self) -> None:
        original = "\n".join(f"line {i}" for i in range(10))
        result = score_fix(
            "credential", "server.py", original,
            "Remove all credential handling.",
            code_fix="# removed",
        )
        assert not result.passed


# --- Diagnose Tests ---


class TestDiagnoseFix:
    def test_missing_code_fix(self) -> None:
        hints = diagnose_fix("credential", "Move to env.", None)
        assert any("CODE FIX" in h for h in hints)

    def test_missing_env_for_credential(self) -> None:
        hints = diagnose_fix("credential", "Move the key somewhere safe.", "x = get_key()")
        assert any("ENV VAR" in h for h in hints)

    def test_missing_parameterized_query(self) -> None:
        hints = diagnose_fix("sql_injection", "Use safe queries.", "cursor.execute(query)")
        assert any("PARAMETERIZED" in h for h in hints)

    def test_missing_path_resolve(self) -> None:
        hints = diagnose_fix("path_traversal", "Validate paths.", "open(user_path)")
        assert any("PATH RESOLUTION" in h for h in hints)

    def test_no_hints_for_good_fix(self) -> None:
        hints = diagnose_fix(
            "credential",
            "Before: hardcoded key. After: uses env var.",
            'api_key = os.environ.get("API_KEY")',
        )
        assert len(hints) == 0


# --- Prompt Tests ---


class TestHardenPrompt:
    def test_system_prompt_has_categories(self) -> None:
        assert "credential" in HARDEN_SYSTEM_PROMPT
        assert "path_traversal" in HARDEN_SYSTEM_PROMPT
        assert "sql_injection" in HARDEN_SYSTEM_PROMPT
        assert "truncation" in HARDEN_SYSTEM_PROMPT
        assert "read_only" in HARDEN_SYSTEM_PROMPT

    def test_system_prompt_has_format(self) -> None:
        assert "EXPLANATION:" in HARDEN_SYSTEM_PROMPT
        assert "CODE_FIX:" in HARDEN_SYSTEM_PROMPT

    def test_build_prompt_includes_context(self) -> None:
        system, user = build_harden_prompt(
            category="sql_injection",
            file_path="db.py",
            code_context='cursor.execute(f"SELECT * FROM {table}")',
            template_suggestion="Use parameterized queries",
        )
        assert "sql_injection" in user
        assert "db.py" in user
        assert "cursor.execute" in user


# --- Response Parsing Tests ---


class TestParseFixResponse:
    def test_structured_format(self) -> None:
        raw = (
            "EXPLANATION: The API key is hardcoded.\n"
            "CODE_FIX:\n"
            'api_key = os.environ.get("API_KEY")'
        )
        explanation, code_fix = _parse_fix_response(raw)
        assert "hardcoded" in explanation
        assert "os.environ" in code_fix

    def test_strips_markdown_fences(self) -> None:
        raw = (
            "EXPLANATION: Fix the query.\n"
            "CODE_FIX:\n"
            "```python\n"
            'cursor.execute("SELECT ?", (id,))\n'
            "```"
        )
        _, code_fix = _parse_fix_response(raw)
        assert "```" not in code_fix
        assert "cursor.execute" in code_fix

    def test_fallback_unstructured(self) -> None:
        raw = "Just move the API key to an environment variable."
        explanation, code_fix = _parse_fix_response(raw)
        assert "API key" in explanation
        assert code_fix is None


# --- Template Scan Tests ---


class TestTemplateScan:
    def test_finds_credential_issue(self, tmp_path: Path) -> None:
        (tmp_path / "server.py").write_text('key = os.environ["API_KEY"]')
        findings = _scan_issues(tmp_path, read_only=False, truncate_limit=100)
        assert any(f.category == "credential" for f in findings)

    def test_finds_sql_injection(self, tmp_path: Path) -> None:
        (tmp_path / "db.py").write_text('cursor.execute(f"SELECT * FROM {table}")')
        findings = _scan_issues(tmp_path, read_only=False, truncate_limit=100)
        assert any(f.category == "sql_injection" for f in findings)

    def test_finds_truncation_issue(self, tmp_path: Path) -> None:
        (tmp_path / "query.py").write_text("rows = cursor.fetchall()")
        findings = _scan_issues(tmp_path, read_only=False, truncate_limit=100)
        assert any(f.category == "truncation" for f in findings)

    def test_finds_read_only_issue(self, tmp_path: Path) -> None:
        (tmp_path / "write.py").write_text('cursor.execute("INSERT INTO users VALUES (?)")')
        findings = _scan_issues(tmp_path, read_only=True, truncate_limit=100)
        assert any(f.category == "read_only" for f in findings)

    def test_clean_server_no_findings(self, tmp_path: Path) -> None:
        (tmp_path / "clean.py").write_text("print('hello')")
        findings = _scan_issues(tmp_path, read_only=True, truncate_limit=100)
        assert len(findings) == 0


# --- LLM Self-Check Loop Tests ---


class TestHardenSelfCheck:
    def test_llm_enhance_with_retry(self, tmp_path: Path) -> None:
        """Mock provider that improves on retry."""
        (tmp_path / "server.py").write_text('key = os.environ["SECRET"]')

        call_count = 0

        class MockProvider:
            def complete(self, system: str, user: str, max_tokens: int = 800) -> str:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    # First: no code fix
                    return "EXPLANATION: Move key to env.\nCODE_FIX:\n# todo"
                else:
                    # Retry: proper fix
                    return (
                        "EXPLANATION: Before: hardcoded. After: uses environ var.\n"
                        "CODE_FIX:\n"
                        'import os\napi_key = os.environ.get("SECRET_KEY", "")'
                    )

        finding = HardenFinding(
            category="credential",
            file="server.py",
            suggestion="Plain env var credential",
        )

        result = _enhance_with_llm(finding, tmp_path, MockProvider(), max_retries=1)
        assert call_count == 2  # retried once
        assert result.code_fix is not None
        assert "os.environ" in result.code_fix

    def test_llm_no_retry_if_good(self, tmp_path: Path) -> None:
        """Good response on first try -> no retry."""
        (tmp_path / "db.py").write_text('cursor.execute(f"SELECT * FROM {t}")')

        call_count = 0

        class MockProvider:
            def complete(self, system: str, user: str, max_tokens: int = 800) -> str:
                nonlocal call_count
                call_count += 1
                return (
                    "EXPLANATION: Before: f-string SQL. After: parameterized query.\n"
                    "CODE_FIX:\n"
                    'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
                )

        finding = HardenFinding(
            category="sql_injection",
            file="db.py",
            suggestion="Use parameterized queries",
        )

        result = _enhance_with_llm(finding, tmp_path, MockProvider(), max_retries=1)
        assert call_count == 1
        assert result.code_fix is not None

    def test_llm_failure_preserves_template(self, tmp_path: Path) -> None:
        """If LLM fails, original template suggestion preserved."""
        (tmp_path / "server.py").write_text('key = os.environ["KEY"]')

        class FailProvider:
            def complete(self, system: str, user: str, max_tokens: int = 800) -> str:
                raise ConnectionError("API down")

        finding = HardenFinding(
            category="credential",
            file="server.py",
            suggestion="Original template suggestion",
        )

        result = _enhance_with_llm(finding, tmp_path, FailProvider())
        assert result.suggestion == "Original template suggestion"
        assert result.code_fix is None
