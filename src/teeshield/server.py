"""TeeShield MCP Server -- exposes scan/rewrite/harden as MCP tools."""

from __future__ import annotations

import logging

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from teeshield.scanner.runner import run_scan_report

logger = logging.getLogger("teeshield.server")

app = Server("teeshield")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="scan_mcp_server",
            description=(
                "Scan an MCP server for security vulnerabilities, description quality, "
                "and architecture issues. Returns a security rating (F/C/B/A/A+) with "
                "actionable recommendations. Use when evaluating whether an MCP server "
                "is safe to install or deploy."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "GitHub repo URL or local directory path of the MCP server to scan",
                    }
                },
                "required": ["target"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "scan_mcp_server":
        target = arguments.get("target", "")
        if not target:
            return [TextContent(type="text", text="Error: 'target' argument is required")]

        try:
            report = run_scan_report(target)
            result = report.model_dump_json(indent=2)
            return [TextContent(type="text", text=result)]
        except Exception as e:
            logger.exception("Scan failed")
            return [TextContent(type="text", text=f"Scan failed: {e}")]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


def run():
    """Synchronous entry point for the console script."""
    import asyncio

    asyncio.run(main())


if __name__ == "__main__":
    run()
