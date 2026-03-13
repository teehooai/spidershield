"""Security-focused tests for the secure demo MCP server."""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from server import read_file, list_files, search_files


class TestPathTraversal:
    """Verify path traversal attacks are blocked."""

    @pytest.mark.asyncio
    async def test_dotdot_in_read(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("server.ALLOWED_DIR", tmp_path)
        result = await read_file("../../etc/passwd")
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_dotdot_in_list(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("server.ALLOWED_DIR", tmp_path)
        result = await list_files("../../")
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_absolute_path_outside(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("server.ALLOWED_DIR", tmp_path)
        try:
            result = await read_file("/etc/shadow")
        except Exception:
            result = "Error: unexpected exception"
        assert "Error" in result


class TestInputBoundaries:
    """Verify input boundary conditions."""

    @pytest.mark.asyncio
    async def test_empty_pattern(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("server.ALLOWED_DIR", tmp_path)
        result = await search_files("")
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_oversized_pattern(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("server.ALLOWED_DIR", tmp_path)
        result = await search_files("*" * 300)
        assert "Error" in result
