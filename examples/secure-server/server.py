"""Example secure MCP server -- for TeeShield demo purposes."""

from pathlib import Path

from mcp.server import Server

server = Server("secure-demo")

ALLOWED_DIR = Path("/workspace")


@server.tool()
async def read_file(path: str) -> str:
    """Read a file within the workspace directory. Use when the user wants to
    view file contents. Only reads files inside the allowed workspace --
    paths outside will be rejected. Returns the full text content of the file.
    If the file does not exist, returns an error message."""
    target = Path(path).resolve()
    if not target.is_relative_to(ALLOWED_DIR):
        return "Error: path is outside the allowed workspace directory."
    if not target.exists():
        return f"Error: file not found: {path}"
    return target.read_text()


@server.tool()
async def list_files(directory: str = ".") -> str:
    """List files in a workspace directory. Use when the user wants to see
    what files are available. Only lists files within the allowed workspace.
    Returns one filename per line. Use read_file to view a specific file."""
    target = (ALLOWED_DIR / directory).resolve()
    if not target.is_relative_to(ALLOWED_DIR):
        return "Error: path is outside the allowed workspace directory."
    if not target.is_dir():
        return f"Error: not a directory: {directory}"
    return "\n".join(f.name for f in sorted(target.iterdir())[:100])


@server.tool()
async def search_files(pattern: str) -> str:
    """Search for files matching a glob pattern within the workspace.
    Use when the user wants to find files by name or extension
    (e.g., '*.py', 'test_*'). Returns matching file paths, limited
    to 50 results. Use read_file to view a match."""
    matches = list(ALLOWED_DIR.rglob(pattern))[:50]
    return "\n".join(str(m.relative_to(ALLOWED_DIR)) for m in matches)
