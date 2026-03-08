"""Scanner runner -- orchestrates all scan stages."""

from __future__ import annotations

import json
from pathlib import Path

import sys

from rich.console import Console
from rich.table import Table

from teeshield.models import ScanReport
from teeshield.scanner.license_check import check_license
from teeshield.scanner.security_scan import scan_security
from teeshield.scanner.description_quality import score_descriptions
from teeshield.scanner.architecture_check import check_architecture

console = Console()
stderr_console = Console(file=sys.stderr)


def resolve_target(target: str) -> Path:
    """Resolve target to a local path. Clone from GitHub if needed."""
    path = Path(target)
    if path.exists():
        return path

    if target.startswith(("http://", "https://", "git@", "github.com")):
        import subprocess

        clone_dir = Path("./tmp_scan") / target.split("/")[-1].replace(".git", "")
        if clone_dir.exists():
            import shutil

            shutil.rmtree(clone_dir)
        subprocess.run(["git", "clone", "--depth", "1", target, str(clone_dir)], check=True)
        return clone_dir

    console.print(f"[red]Target not found: {target}[/red]")
    raise SystemExit(1)


def run_scan_report(target: str) -> ScanReport:
    """Run a full scan and return the report object."""
    path = resolve_target(target)

    license_info, license_ok = check_license(path)
    security_score, security_issues = scan_security(path)
    desc_score, tool_scores, tool_names = score_descriptions(path)
    arch_score, has_tests, has_error_handling = check_architecture(path)

    overall = (security_score * 0.4 + desc_score * 0.35 + arch_score * 0.25)
    improvement_potential = 10.0 - overall

    from teeshield.models import Rating

    if any(i.severity == "critical" for i in security_issues):
        rating = Rating.F
    elif overall >= 9.0:
        rating = Rating.A_PLUS
    elif overall >= 8.0:
        rating = Rating.A
    elif overall >= 6.0:
        rating = Rating.B
    elif overall >= 4.0:
        rating = Rating.C
    else:
        rating = Rating.F

    recommendations = []
    if desc_score < 6.0:
        worst = sorted(tool_scores, key=lambda s: s.overall_score)[:3]
        worst_names = ", ".join(f"`{s.tool_name}` ({s.overall_score}/10)" for s in worst)
        recommendations.append(f"Run `teeshield rewrite` -- worst tools: {worst_names}")
        # Actionable hints based on what's missing across tools
        missing = {"verb": 0, "scenario": 0, "params": 0, "examples": 0}
        for s in tool_scores:
            if not s.has_action_verb:
                missing["verb"] += 1
            if not s.has_scenario_trigger:
                missing["scenario"] += 1
            if not s.has_param_docs:
                missing["params"] += 1
            if not s.has_param_examples:
                missing["examples"] += 1
        top_missing = sorted(missing.items(), key=lambda x: -x[1])[:2]
        hints = {"verb": "start with an action verb", "scenario": "add 'Use when...' guidance",
                 "params": "document parameters", "examples": "add concrete examples"}
        for key, count in top_missing:
            if count > 0:
                recommendations.append(f"  {count}/{len(tool_scores)} tools: {hints[key]}")
    if security_score < 6.0:
        crit = [i for i in security_issues if i.severity == "critical"]
        if crit:
            categories = set(i.category for i in crit)
            recommendations.append(
                f"Run `teeshield harden` -- {len(crit)} critical: {', '.join(categories)}"
            )
        else:
            recommendations.append("Run `teeshield harden` to fix security issues")
    if len(tool_names) > 40:
        recommendations.append(
            f"Too many tools ({len(tool_names)}). Consider splitting into multiple servers"
        )
    if not has_tests:
        recommendations.append("Add automated tests for reliability")

    return ScanReport(
        target=target,
        license=license_info,
        license_ok=license_ok,
        tool_count=len(tool_names),
        tool_names=tool_names,
        security_score=round(security_score, 1),
        security_issues=security_issues,
        description_score=round(desc_score, 1),
        tool_scores=tool_scores,
        architecture_score=round(arch_score, 1),
        has_tests=has_tests,
        has_error_handling=has_error_handling,
        overall_score=round(overall, 1),
        improvement_potential=round(improvement_potential, 1),
        rating=rating,
        recommendations=recommendations,
    )


def run_scan(target: str, output_path: str | None = None, output_format: str = "table"):
    """Run a full scan on an MCP server."""
    # Use stderr for progress when outputting JSON to stdout
    log = stderr_console if (output_format == "json" and not output_path) else console
    log.print(f"\n[bold]Scanning:[/bold] {target}\n")

    log.print("[dim]Stage 1/4: License check...[/dim]")
    log.print("[dim]Stage 2/4: Security scan...[/dim]")
    log.print("[dim]Stage 3/4: Description quality...[/dim]")
    log.print("[dim]Stage 4/4: Architecture check...[/dim]")

    report = run_scan_report(target)

    if output_format == "json" or output_path:
        json_str = report.model_dump_json(indent=2)
        if output_path:
            Path(output_path).write_text(json_str)
            console.print(f"\n[green]Report saved to {output_path}[/green]")
        else:
            console.print(json_str)
    else:
        _print_table(report)


def _score_color(score: float) -> str:
    """Return a Rich color tag for a numeric score."""
    if score >= 8.0:
        return "green"
    if score >= 5.0:
        return "yellow"
    return "red"


def _severity_color(severity: str) -> str:
    """Return a Rich color tag for a severity level."""
    return {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim"}.get(severity, "dim")


def _print_table(report: ScanReport):
    """Print a rich table summary."""
    # --- Summary table ---
    table = Table(title=f"TeeShield Scan Report - {report.target}")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_column("Score", justify="right")

    ok = "[green]OK[/green]"
    fail = "[red]FAIL[/red]"
    warn = "[yellow]WARN[/yellow]"
    table.add_row("License", report.license or "Unknown", ok if report.license_ok else fail)
    table.add_row("Tools", str(report.tool_count), warn if report.tool_count > 40 else ok)

    sc = _score_color(report.security_score)
    table.add_row("Security", f"{len(report.security_issues)} issues", f"[{sc}]{report.security_score}/10[/{sc}]")
    dc = _score_color(report.description_score)
    table.add_row("Descriptions", "", f"[{dc}]{report.description_score}/10[/{dc}]")
    ac = _score_color(report.architecture_score)
    table.add_row("Architecture", "", f"[{ac}]{report.architecture_score}/10[/{ac}]")
    table.add_row("Tests", "Yes" if report.has_tests else "No", ok if report.has_tests else fail)
    table.add_row("", "", "")

    oc = _score_color(report.overall_score)
    table.add_row(
        "[bold]Overall[/bold]",
        f"Rating: [{oc}]{report.rating.value}[/{oc}]",
        f"[bold {oc}]{report.overall_score}/10[/bold {oc}]",
    )

    console.print(table)

    # --- Per-tool description scores ---
    if report.tool_scores:
        tool_table = Table(title="Tool Description Quality")
        tool_table.add_column("Tool", style="bold")
        tool_table.add_column("Score", justify="right")
        tool_table.add_column("Verb")
        tool_table.add_column("Scenario")
        tool_table.add_column("Params")
        tool_table.add_column("Examples")
        tool_table.add_column("Errors")

        check = "[green]Y[/green]"
        cross = "[red]N[/red]"
        for ts in sorted(report.tool_scores, key=lambda s: s.overall_score):
            c = _score_color(ts.overall_score)
            tool_table.add_row(
                ts.tool_name,
                f"[{c}]{ts.overall_score}[/{c}]",
                check if ts.has_action_verb else cross,
                check if ts.has_scenario_trigger else cross,
                check if ts.has_param_docs else cross,
                check if ts.has_param_examples else cross,
                check if ts.has_error_guidance else cross,
            )
        console.print(tool_table)

    # --- Security issues ---
    if report.security_issues:
        console.print(f"\n[yellow]Security Issues ({len(report.security_issues)}):[/yellow]")
        for issue in report.security_issues[:15]:
            sc = _severity_color(issue.severity)
            console.print(
                f"  [{sc}]{issue.severity.upper():8s}[/{sc}] "
                f"{issue.category} -- {issue.file}:{issue.line}"
            )
            if issue.fix_suggestion:
                console.print(f"           [dim]Fix: {issue.fix_suggestion}[/dim]")

    # --- Recommendations ---
    if report.recommendations:
        console.print("\n[bold]Recommendations:[/bold]")
        for rec in report.recommendations:
            console.print(f"  > {rec}")

    console.print()
