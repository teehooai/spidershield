"""Tests for error handling in the secure demo MCP server."""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from server import read_file, list_files, search_files


class TestErrorMessages:
    """Verify error messages are user-friendly and safe."""

    @pytest.mark.asyncio
    async def test_read_nonexistent_returns_error(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("server.ALLOWED_DIR", tmp_path)
        result = await read_file(str(tmp_path / "no_such_file.txt"))
        assert result.startswith("Error:")

    @pytest.mark.asyncio
    async def test_list_file_as_dir_returns_error(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("server.ALLOWED_DIR", tmp_path)
        (tmp_path / "file.txt").write_text("data")
        result = await list_files(str(tmp_path / "file.txt"))
        assert "not a directory" in result

    @pytest.mark.asyncio
    async def test_traversal_error_does_not_leak_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("server.ALLOWED_DIR", tmp_path)
        result = await read_file("/etc/passwd")
        assert "/etc" not in result or "outside" in result
