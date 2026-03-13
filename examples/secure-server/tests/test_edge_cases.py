"""Edge case tests for the secure demo MCP server."""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from server import read_file, list_files, search_files


class TestEdgeCases:
    """Unusual but valid inputs."""

    @pytest.mark.asyncio
    async def test_read_binary_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("server.ALLOWED_DIR", tmp_path)
        try:
            (tmp_path / "data.bin").write_bytes(b"\x00\x01\x02")
        except OSError:
            pytest.skip("Cannot write binary test file")
        result = await read_file(str(tmp_path / "data.bin"))
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_list_empty_directory(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("server.ALLOWED_DIR", tmp_path)
        (tmp_path / "empty").mkdir()
        result = await list_files(str(tmp_path / "empty"))
        assert result == ""

    @pytest.mark.asyncio
    async def test_search_deeply_nested(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("server.ALLOWED_DIR", tmp_path)
        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        (deep / "found.txt").write_text("found")
        result = await search_files("**/found.txt")
        assert "found.txt" in result

    @pytest.mark.asyncio
    async def test_unicode_filename(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("server.ALLOWED_DIR", tmp_path)
        try:
            (tmp_path / "日本語.txt").write_text("hello")
        except OSError:
            pytest.skip("Filesystem does not support Unicode filenames")
        result = await read_file(str(tmp_path / "日本語.txt"))
        assert result == "hello"
