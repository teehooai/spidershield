"""Example secure MCP server -- for SpiderShield demo purposes."""

from pathlib import Path

from mcp.server import Server

server = Server("secure-demo")

ALLOWED_DIR = Path("/workspace")

_MAX_PATH_LEN = 4096
_MAX_PATTERN_LEN = 256


def _validate_path(value: str) -> str | None:
    """Validate a path string. Returns error message or None if valid."""
    if not value or len(value) > _MAX_PATH_LEN:
        return f"Error: path must be 1-{_MAX_PATH_LEN} characters."
    if "\x00" in value:
        return "Error: path contains null bytes."
    return None


@server.tool()
async def read_file(path: str) -> str:
    """Read a file within the workspace directory. Use when the user wants to
    view file contents or inspect source code. Accepts `path` — a relative
    or absolute file path (e.g., 'src/main.py', '/workspace/config.yaml').
    Only reads files inside the allowed workspace; paths outside will be
    rejected with an error. Returns the full text content of the file.
    If the file does not exist or the path is invalid, returns an error message."""
    if err := _validate_path(path):
        return err
    try:
        target = Path(path).resolve()
    except (OSError, ValueError):
        return f"Error: invalid path: {path}"
    if not target.is_relative_to(ALLOWED_DIR):
        return "Error: path is outside the allowed workspace directory."
    if not target.exists():
        return f"Error: file not found: {path}"
    return target.read_text()


@server.tool()
async def list_files(directory: str = ".") -> str:
    """List files in a workspace directory. Use when the user wants to browse
    available files or explore project structure. Accepts `directory` — a
    relative path within the workspace (e.g., 'src', 'tests/unit'). Returns
    one filename per line, limited to 100 entries. If the path is outside
    the workspace or not a directory, returns an error message."""
    if err := _validate_path(directory):
        return err
    try:
        target = (ALLOWED_DIR / directory).resolve()
    except (OSError, ValueError):
        return f"Error: invalid directory: {directory}"
    if not target.is_relative_to(ALLOWED_DIR):
        return "Error: path is outside the allowed workspace directory."
    if not target.is_dir():
        return f"Error: not a directory: {directory}"
    return "\n".join(f.name for f in sorted(target.iterdir())[:100])


@server.tool()
async def search_files(pattern: str) -> str:
    """Search for files matching a glob pattern within the workspace.
    Use when the user wants to find files by name, extension, or prefix
    (e.g., '*.py', 'test_*', 'config.*'). Accepts `pattern` — a standard
    glob expression. Returns matching file paths relative to workspace root,
    limited to 50 results. Returns an error if the pattern is invalid or
    empty. If no files match, returns an empty string."""
    if not pattern or len(pattern) > _MAX_PATTERN_LEN:
        return f"Error: pattern must be 1-{_MAX_PATTERN_LEN} characters."
    try:
        matches = list(ALLOWED_DIR.rglob(pattern))[:50]
    except (OSError, ValueError):
        return f"Error: invalid glob pattern: {pattern}"
    return "\n".join(str(m.relative_to(ALLOWED_DIR)) for m in matches)
