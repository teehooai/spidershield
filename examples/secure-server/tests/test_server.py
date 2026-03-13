"""Tests for the secure demo MCP server."""

from pathlib import Path
import tempfile

import pytest

# Import the tool functions directly for unit testing
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from server import read_file, list_files, search_files, ALLOWED_DIR


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """Create a temporary workspace with sample files."""
    try:
        (tmp_path / "hello.txt").write_text("Hello, world!")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.py").write_text("print('hello')")
        (tmp_path / "src" / "util.py").write_text("def helper(): pass")
    except OSError as exc:
        pytest.fail(f"Failed to set up workspace: {exc}")
    return tmp_path


class TestReadFile:
    """Tests for the read_file tool."""

    @pytest.mark.asyncio
    async def test_read_existing_file(self, workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("server.ALLOWED_DIR", workspace)
        result = await read_file(str(workspace / "hello.txt"))
        assert result == "Hello, world!"

    @pytest.mark.asyncio
    async def test_read_nonexistent_file(self, workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("server.ALLOWED_DIR", workspace)
        result = await read_file(str(workspace / "missing.txt"))
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_path_traversal_blocked(self, workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("server.ALLOWED_DIR", workspace)
        result = await read_file(str(workspace / ".." / "etc" / "passwd"))
        assert "Error" in result


class TestListFiles:
    """Tests for the list_files tool."""

    @pytest.mark.asyncio
    async def test_list_root(self, workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("server.ALLOWED_DIR", workspace)
        result = await list_files(str(workspace))
        assert "hello.txt" in result

    @pytest.mark.asyncio
    async def test_list_subdirectory(self, workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("server.ALLOWED_DIR", workspace)
        result = await list_files(str(workspace / "src"))
        assert "main.py" in result


class TestSearchFiles:
    """Tests for the search_files tool."""

    @pytest.mark.asyncio
    async def test_search_by_extension(self, workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("server.ALLOWED_DIR", workspace)
        result = await search_files("*.py")
        assert "main.py" in result

    @pytest.mark.asyncio
    async def test_search_no_matches(self, workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("server.ALLOWED_DIR", workspace)
        result = await search_files("*.rs")
        assert result == ""
