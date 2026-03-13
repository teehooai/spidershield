# Secure Demo MCP Server

A minimal, security-hardened MCP server for SpiderShield demonstration purposes.
This server provides sandboxed file operations within a controlled workspace directory.

## Features

- **Path traversal protection**: All file operations are restricted to an allowed workspace directory.
  Paths that escape the sandbox via `..` or symlinks are rejected.
- **Read-only operations**: The server only supports reading, listing, and searching files.
  No write, delete, or execute operations are exposed.
- **Bounded results**: List operations return at most 100 entries; search returns at most 50 matches.

## Installation

```bash
pip install mcp
```

## Usage

```python
from examples.secure_server.server import server

# The server exposes three tools:
# - read_file: Read file contents within the workspace
# - list_files: List directory contents
# - search_files: Glob-based file search
```

## Configuration

Set the `ALLOWED_DIR` constant in `server.py` to your workspace root.
The default is `/workspace`.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WORKSPACE_DIR` | Root directory for file operations | `/workspace` |

## Security Model

All three tools enforce a common security invariant: the resolved path must be
a descendant of `ALLOWED_DIR`. This is checked using `Path.is_relative_to()`,
which handles symlink resolution correctly on Python 3.11+.

## License

MIT -- see the root LICENSE file.
