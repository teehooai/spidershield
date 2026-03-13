"""Tests for input validation in the secure demo MCP server."""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from server import _validate_path, _MAX_PATH_LEN, _MAX_PATTERN_LEN


class TestValidatePath:
    """Tests for the _validate_path helper."""

    def test_valid_path(self) -> None:
        assert _validate_path("src/main.py") is None

    def test_empty_path(self) -> None:
        result = _validate_path("")
        assert result is not None
        assert "Error" in result

    def test_null_bytes(self) -> None:
        result = _validate_path("file\x00.txt")
        assert result is not None
        assert "null" in result

    def test_too_long(self) -> None:
        result = _validate_path("a" * (_MAX_PATH_LEN + 1))
        assert result is not None
        assert "Error" in result

    def test_max_length_ok(self) -> None:
        assert _validate_path("a" * _MAX_PATH_LEN) is None
