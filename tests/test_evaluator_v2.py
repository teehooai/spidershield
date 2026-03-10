"""Tests for evaluator v2: LLM retry logic."""

from __future__ import annotations

from spidershield.evaluator.runner import _fuzzy_match_tool, _llm_select_with_retry


def _make_mock_client(responses: list[str]):
    """Build a mock Anthropic client returning given responses in order."""
    call_count = {"n": 0}

    class _Resp:
        def __init__(self, text: str) -> None:
            self.content = [type("T", (), {"text": text})()]

    class Messages:
        @staticmethod
        def create(**kwargs):
            idx = min(call_count["n"], len(responses) - 1)
            call_count["n"] += 1
            return _Resp(responses[idx])

    class Client:
        messages = Messages()

    return Client(), call_count


def _make_failing_client():
    """Build a mock client that always raises."""
    class Messages:
        @staticmethod
        def create(**kwargs):
            raise ConnectionError("API down")

    class Client:
        messages = Messages()

    return Client()


class TestFuzzyMatch:
    def test_exact_match(self) -> None:
        assert _fuzzy_match_tool("list_tables", ["list_tables", "query"]) == "list_tables"

    def test_case_insensitive(self) -> None:
        assert _fuzzy_match_tool("List_Tables", ["list_tables", "query"]) == "list_tables"

    def test_partial_match(self) -> None:
        assert _fuzzy_match_tool("list", ["list_tables", "query"]) == "list_tables"

    def test_no_match_returns_input(self) -> None:
        assert _fuzzy_match_tool("unknown", ["list_tables", "query"]) == "unknown"

    def test_dash_underscore_normalization(self) -> None:
        assert _fuzzy_match_tool("list-tables", ["list_tables", "query"]) == "list_tables"


class TestLLMSelectWithRetry:
    def test_valid_first_attempt(self) -> None:
        """LLM returns valid tool name on first try."""
        client, counts = _make_mock_client(["list_tables"])

        result = _llm_select_with_retry(
            client, "model", "- list_tables: List tables",
            ["list_tables", "query"], "Show me the tables",
        )
        assert result == "list_tables"
        assert counts["n"] == 1

    def test_retry_on_invalid_response(self) -> None:
        """LLM returns gibberish, then valid on retry."""
        client, counts = _make_mock_client([
            "I think you should use...",
            "list_tables",
        ])

        result = _llm_select_with_retry(
            client, "model", "- list_tables: List tables",
            ["list_tables", "query"], "Show me the tables",
        )
        assert result == "list_tables"
        assert counts["n"] == 2

    def test_api_error_returns_error(self) -> None:
        """API failure returns 'error' gracefully."""
        client = _make_failing_client()

        result = _llm_select_with_retry(
            client, "model", "- list_tables: List tables",
            ["list_tables"], "Show me the tables",
        )
        assert result == "error"

    def test_max_retries_respected(self) -> None:
        """If always invalid, doesn't loop forever."""
        client, counts = _make_mock_client(["gibberish"])

        _llm_select_with_retry(
            client, "model", "- list_tables: List tables",
            ["list_tables"], "Show tables",
            max_retries=1,
        )
        assert counts["n"] == 2  # 1 initial + 1 retry
