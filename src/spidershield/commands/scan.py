"""Scan command -- analyze MCP servers for security and description quality."""

import click
from rich.console import Console

console = Console()


@click.command()
@click.argument("target")
@click.option("--output", "-o", default=None, help="Output report path (JSON/SARIF)")
@click.option(
    "--format", "fmt",
    type=click.Choice(["table", "json", "sarif", "spiderrating"]),
    default="table",
)
@click.option("--tools-json", default=None, help="Pre-extracted tools JSON (MCP tools/list format)")
def scan(target: str, output: str | None, fmt: str, tools_json: str | None):
    """Scan an MCP server for security issues and description quality.

    TARGET can be a GitHub repo URL or a local directory path.

    Use --format spiderrating to output in SpiderRating-compatible JSON
    (description 35% + security 35% + metadata 30%, F/D/C/B/A grades).
    """
    if fmt == "sarif":
        from pathlib import Path

        from spidershield.agent.sarif import sarif_to_json, scan_report_to_sarif
        from spidershield.scanner.runner import run_scan_report

        report = run_scan_report(target, tools_json=tools_json)
        sarif = scan_report_to_sarif(report)
        sarif_json = sarif_to_json(sarif)
        if output:
            Path(output).write_text(sarif_json, encoding="utf-8")
            Console(stderr=True).print(f"[green]SARIF report written to {output}[/green]")
        else:
            console.print(sarif_json)
    elif fmt == "spiderrating":
        import json
        from pathlib import Path as SpiderPath

        from spidershield.scanner.runner import run_scan_report

        report = run_scan_report(target, tools_json=tools_json)
        report_dict = json.loads(report.model_dump_json())

        from spidershield.spiderrating import convert, parse_owner_repo

        try:
            owner, repo = parse_owner_repo(target)
        except ValueError:
            owner, repo = "local", SpiderPath(target).name

        result = convert(report_dict, owner, repo)
        json_str = json.dumps(result, indent=2)

        if output:
            SpiderPath(output).write_text(json_str, encoding="utf-8")
            Console(stderr=True).print(f"[green]SpiderRating JSON written to {output}[/green]")
        else:
            # Use plain print (not Rich console.print) to avoid Rich markup processing
            # corrupting JSON bracket sequences like ["tool", "[arg]"]
            print(json_str)
    else:
        from spidershield.scanner.runner import run_scan

        run_scan(target, output_path=output, output_format=fmt, tools_json=tools_json)
