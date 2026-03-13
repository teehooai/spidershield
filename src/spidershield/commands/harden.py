"""Harden command -- security hardening suggestions for MCP servers."""

import click


@click.command()
@click.argument("server_path")
@click.option("--read-only/--no-read-only", default=True, help="Enable read-only defaults")
@click.option("--truncate-limit", default=100, help="Max rows/items in tool responses")
@click.option(
    "--engine", type=click.Choice(["template", "llm", "auto"]), default="auto",
    help="Fix engine: template (free), llm (generates code fixes), auto (detect)",
)
@click.option(
    "--provider", "provider_name",
    type=click.Choice(["claude", "openai", "gemini"]),
    default=None, help="LLM provider (auto-detected from env vars if not set)",
)
def harden(
    server_path: str,
    read_only: bool,
    truncate_limit: int,
    engine: str,
    provider_name: str | None,
):
    """Suggest security hardening for an MCP server (advisory only).

    Scans for: insecure credential handling, missing input validation,
    unbounded query results, and write operations that should default
    to read-only. Prints suggestions but does not modify any files.

    With --engine llm, generates concrete code fix suggestions using
    an LLM with self-check validation.
    """
    from spidershield.hardener.runner import run_harden

    run_harden(
        server_path, read_only=read_only, truncate_limit=truncate_limit,
        engine=engine, provider_name=provider_name,
    )
