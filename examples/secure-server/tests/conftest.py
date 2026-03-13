"""Shared test fixtures for the secure demo MCP server."""

import sys
from pathlib import Path

import pytest

# Ensure the server module is importable
sys.path.insert(0, str(Path(__file__).parent.parent))


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
