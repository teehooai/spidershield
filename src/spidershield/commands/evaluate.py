"""Eval command -- compare tool selection accuracy before/after improvements."""

import click


@click.command(name="eval")
@click.argument("original")
@click.argument("improved")
@click.option("--scenarios", "-s", default=None, help="Path to test scenarios YAML")
@click.option("--models", "-m", multiple=True, default=["claude-sonnet-4-20250514"])
@click.option("--llm", is_flag=True, help="Use LLM for evaluation (requires ANTHROPIC_API_KEY)")
@click.option(
    "--tools-json", default=None,
    help="Pre-extracted tools JSON (overrides source extraction)",
)
def evaluate(
    original: str, improved: str, scenarios: str | None,
    models: tuple[str, ...], llm: bool, tools_json: str | None,
):
    """Compare tool selection accuracy before and after improvements.

    Uses heuristic keyword matching by default (free, no API key needed).
    Add --llm to use Claude for higher-quality evaluation.
    """
    from spidershield.evaluator.runner import run_eval

    run_eval(
        original, improved, scenarios_path=scenarios,
        models=list(models), use_llm=llm, tools_json=tools_json,
    )
