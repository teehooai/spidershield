"""Rewrite command -- LLM-optimized tool description rewriting."""

import click


@click.command()
@click.argument("server_path")
@click.option("--model", default=None, help="Model name (auto-detected per provider if not set)")
@click.option("--dry-run", is_flag=True, help="Preview changes without writing")
@click.option("--output", "-o", default=None, help="Save rewrites to JSON file")
@click.option(
    "--engine", type=click.Choice(["template", "llm", "auto"]), default="auto",
    help="Rewrite engine: template (free), llm (API key needed), auto (detect)",
)
@click.option(
    "--provider", "provider_name",
    type=click.Choice(["claude", "openai", "gemini"]),
    default=None, help="LLM provider (auto-detected from env vars if not set)",
)
@click.option("--tools-json", default=None, help="Pre-extracted tools JSON (MCP tools/list format)")
@click.option("--no-cache", "no_cache", is_flag=True, help="Skip LLM rewrite cache")
def rewrite(
    server_path: str,
    model: str | None,
    dry_run: bool,
    output: str | None,
    engine: str,
    provider_name: str | None,
    tools_json: str | None,
    no_cache: bool,
):
    """Rewrite tool descriptions for LLM-optimized selection.

    Transforms API-doc-style descriptions into action-oriented,
    scenario-triggered descriptions that agents can use effectively.

    Uses template-based rewriting by default. Set ANTHROPIC_API_KEY,
    OPENAI_API_KEY, or GEMINI_API_KEY for higher-quality LLM-powered rewrites.
    """
    from spidershield.rewriter.runner import run_rewrite

    run_rewrite(
        server_path,
        model=model or "claude-sonnet-4-20250514",
        dry_run=dry_run,
        output_path=output,
        engine=engine,
        provider_name=provider_name,
        tools_json=tools_json,
        use_cache=not no_cache,
    )
