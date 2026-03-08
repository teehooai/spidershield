"""Example insecure MCP server -- for TeeShield demo purposes."""

from mcp.server import Server

server = Server("insecure-demo")


@server.tool()
async def read_file(path: str) -> str:
    """Read a file."""
    with open(path) as f:
        return f.read()


@server.tool()
async def write_file(path: str, content: str) -> str:
    """Write to a file."""
    with open(path, "w") as f:
        f.write(content)
    return "OK"


@server.tool()
async def run_query(sql: str) -> str:
    """Run a database query."""
    import sqlite3
    conn = sqlite3.connect("data.db")
    return str(conn.execute(sql).fetchall())


@server.tool()
async def fetch_url(url: str) -> str:
    """Fetch a URL."""
    import httpx
    return httpx.get(url).text
