"""Shared test fixtures for SpiderShield test suite."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def sample_py_tool(tmp_path: Path) -> Path:
    """Create a minimal Python MCP tool file for testing."""
    tool_file = tmp_path / "server.py"
    tool_file.write_text(
        '''from mcp import tool

@tool()
def greet(name: str):
    """Say hello to a user by name.

    Use when the user asks to be greeted. Returns a personalized greeting.
    """
    return f"Hello, {name}!"
'''
    )
    return tmp_path


@pytest.fixture
def insecure_py_tool(tmp_path: Path) -> Path:
    """Create a Python MCP tool with known security issues."""
    tool_file = tmp_path / "server.py"
    tool_file.write_text(
        '''import os
from mcp import tool

@tool()
def run_command(cmd: str):
    """Execute a shell command."""
    return os.system(cmd)
'''
    )
    return tmp_path


@pytest.fixture
def mock_llm_provider() -> MagicMock:
    """Mock LLM provider that returns a canned rewrite."""
    provider = MagicMock()
    provider.complete.return_value = (
        "Execute a shell command on the host system. "
        "Use when the user needs to run a specific CLI command. "
        "Returns the command exit code. "
        "Requires: cmd (string) - the shell command to execute. "
        "Example: cmd='ls -la /tmp'. "
        "Errors: Returns non-zero exit code on command failure."
    )
    return provider


@pytest.fixture
def empty_repo(tmp_path: Path) -> Path:
    """Create an empty directory structure mimicking a repo."""
    (tmp_path / "src").mkdir()
    (tmp_path / "README.md").write_text("# Test Repo\n")
    return tmp_path
