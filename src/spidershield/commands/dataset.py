"""Dataset commands -- manage the local security dataset."""

from pathlib import Path

import click
from rich.console import Console

console = Console()


@click.group(name="dataset")
def dataset():
    """Manage the local security dataset."""


@dataset.command(name="stats")
def dataset_stats():
    """Show dataset statistics."""
    from spidershield.dataset.db import get_stats

    stats = get_stats()
    if not stats["db_exists"]:
        console.print(
            "[dim]No dataset yet. Run `spidershield scan`"
            " to start collecting data.[/dim]"
        )
        return

    console.print("\n[bold]SpiderShield Security Dataset[/bold]")
    console.print(f"  Location: [dim]{stats['db_path']}[/dim]")
    console.print(f"  Size: {stats['db_size_kb']} KB\n")
    console.print(
        f"  Scans: {stats['total_scans']}"
        f" ({stats['unique_targets']} unique targets)"
    )
    console.print(f"  Security issues: {stats['total_issues']}")
    console.print(f"  Tool descriptions: {stats['total_descriptions']}")
    console.print(f"  Hardener fixes: {stats['total_fixes']}")
    if stats.get("total_agent_scans"):
        console.print(
            f"  Agent scans: {stats['total_agent_scans']}"
            f" ({stats['total_agent_findings']} findings)"
        )
    if stats.get("total_prs"):
        console.print(
            f"  Pull requests: {stats['total_prs']}"
            f" ({stats['pr_tools_changed']} tools changed)"
        )

    if stats.get("pr_status_distribution"):
        console.print("\n  [bold]PR status:[/bold]")
        status_colors = {
            "open": "yellow", "merged": "green",
            "closed": "red", "rejected": "red",
        }
        for st, count in stats["pr_status_distribution"].items():
            c = status_colors.get(st, "dim")
            console.print(f"    [{c}]{st}[/{c}]: {count}")

    if stats.get("rating_distribution"):
        console.print("\n  [bold]Rating distribution:[/bold]")
        for rating, count in stats["rating_distribution"].items():
            console.print(f"    {rating}: {count}")

    if stats.get("top_issue_categories"):
        console.print("\n  [bold]Top issue categories:[/bold]")
        for cat in stats["top_issue_categories"]:
            console.print(f"    {cat['category']}: {cat['count']}")

    console.print()


@dataset.command(name="export")
@click.argument("output_path")
@click.option(
    "--format", "fmt",
    type=click.Choice(["json", "csv"]),
    default="json",
    help="Export format",
)
def dataset_export(output_path: str, fmt: str):
    """Export dataset to JSON or CSV."""
    import json

    from spidershield.dataset.db import DEFAULT_DB_PATH, get_connection

    if not DEFAULT_DB_PATH.exists():
        console.print("[red]No dataset found. Run scans first.[/red]")
        raise SystemExit(1)

    with get_connection() as conn:
        scans = [
            dict(r) for r in conn.execute("SELECT * FROM scans").fetchall()
        ]
        issues = [
            dict(r)
            for r in conn.execute("SELECT * FROM security_issues").fetchall()
        ]
        descriptions = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM tool_descriptions"
            ).fetchall()
        ]
        fixes = [
            dict(r)
            for r in conn.execute("SELECT * FROM hardener_fixes").fetchall()
        ]
        prs = [
            dict(r)
            for r in conn.execute("SELECT * FROM pull_requests").fetchall()
        ]
        agent_scans_data = [
            dict(r)
            for r in conn.execute("SELECT * FROM agent_scans").fetchall()
        ]
        agent_findings_data = [
            dict(r)
            for r in conn.execute("SELECT * FROM agent_findings").fetchall()
        ]

    if fmt == "json":
        data = {
            "version": 3,
            "scans": scans,
            "security_issues": issues,
            "tool_descriptions": descriptions,
            "hardener_fixes": fixes,
            "pull_requests": prs,
            "agent_scans": agent_scans_data,
            "agent_findings": agent_findings_data,
        }
        Path(output_path).write_text(
            json.dumps(data, indent=2, default=str), encoding="utf-8",
        )
    elif fmt == "csv":
        import csv

        if scans:
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=scans[0].keys())
                writer.writeheader()
                writer.writerows(scans)

    console.print(f"[green]Dataset exported to {output_path}[/green]")


@dataset.command(name="reset")
@click.confirmation_option(
    prompt="This will delete all collected data. Are you sure?",
)
def dataset_reset():
    """Delete all collected dataset data."""
    from spidershield.dataset.db import DEFAULT_DB_PATH

    if DEFAULT_DB_PATH.exists():
        DEFAULT_DB_PATH.unlink()
        console.print("[green]Dataset reset.[/green]")
    else:
        console.print("[dim]No dataset to reset.[/dim]")


@dataset.command(name="pr-add")
@click.argument("repo")
@click.argument("pr_number", type=int)
@click.option("--title", "-t", required=True, help="PR title")
@click.option(
    "--status", "-s",
    type=click.Choice(["open", "merged", "closed", "rejected"]),
    default="open",
)
@click.option("--strategy", default=None, help="PR strategy (hand-crafted, template)")
@click.option("--tools", "tools_changed", type=int, default=0, help="Tools changed")
@click.option("--engine", default=None, help="Engine used (template/llm)")
@click.option("--date", "submitted_at", default=None, help="Submit date (YYYY-MM-DD)")
@click.option("--notes", default=None, help="Additional notes")
@click.option("--rejection-reason", default=None, help="Why rejected/closed")
def dataset_pr_add(
    repo: str,
    pr_number: int,
    title: str,
    status: str,
    strategy: str | None,
    tools_changed: int,
    engine: str | None,
    submitted_at: str | None,
    notes: str | None,
    rejection_reason: str | None,
):
    """Add or update a PR in the dataset."""
    from spidershield.dataset.collector import record_pr

    merged_at = submitted_at if status == "merged" else None
    closed_at = submitted_at if status in ("closed", "rejected") else None

    pr_id = record_pr(
        repo=repo,
        pr_number=pr_number,
        title=title,
        status=status,
        strategy=strategy,
        tools_changed=tools_changed,
        engine=engine,
        submitted_at=submitted_at,
        merged_at=merged_at,
        closed_at=closed_at,
        rejection_reason=rejection_reason,
        notes=notes,
    )
    if pr_id:
        console.print(
            f"[green]Recorded:[/green] {repo}#{pr_number}"
            f" [{status}]"
        )
    else:
        console.print("[red]Failed to record PR.[/red]")


@dataset.command(name="pr-list")
@click.option(
    "--status", "-s",
    type=click.Choice(["open", "merged", "closed", "rejected"]),
    default=None,
    help="Filter by status",
)
def dataset_pr_list(status: str | None):
    """List tracked PRs."""
    from rich.table import Table

    from spidershield.dataset.collector import get_prs

    prs = get_prs(status=status)
    if not prs:
        console.print("[dim]No PRs tracked yet.[/dim]")
        return

    table = Table(title="Tracked Pull Requests")
    table.add_column("Repo", style="bold")
    table.add_column("#", justify="right")
    table.add_column("Title", width=40)
    table.add_column("Status")
    table.add_column("Tools")
    table.add_column("Strategy")
    table.add_column("Date")

    status_colors = {
        "open": "yellow", "merged": "green",
        "closed": "red", "rejected": "red",
    }
    for pr in prs:
        c = status_colors.get(pr["status"], "dim")
        date = (pr.get("submitted_at") or "")[:10]
        table.add_row(
            pr["repo"],
            str(pr["pr_number"]),
            pr["title"][:40],
            f"[{c}]{pr['status']}[/{c}]",
            str(pr["tools_changed"]),
            pr.get("strategy") or "-",
            date,
        )

    console.print(table)


@dataset.command(name="benchmark-add")
@click.argument("target")
@click.option("--expected-rating", "-r", required=True, help="Expected rating (A/B/C/D/F)")
@click.option("--expected-min-score", "-s", type=float, default=None, help="Expected minimum score")
@click.option("--expected-max-score", type=float, default=None, help="Expected maximum score")
@click.option("--category", "-c", default="general", help="Benchmark category")
@click.option("--description", "-d", default=None, help="Description of this benchmark")
def dataset_benchmark_add(
    target: str,
    expected_rating: str,
    expected_min_score: float | None,
    expected_max_score: float | None,
    category: str,
    description: str | None,
):
    """Add a benchmark server (known-good or known-bad).

    \b
    Examples:
      spidershield dataset benchmark-add /path/to/good-server -r A -s 8.5 -c known-good
      spidershield dataset benchmark-add /path/to/bad-server -r F -c known-bad
    """
    from spidershield.dataset.db import get_connection, init_db

    init_db()
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO benchmarks "
            "(target, expected_rating, expected_min_score, "
            "expected_max_score, category, description) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (target, expected_rating.upper(), expected_min_score,
             expected_max_score, category, description),
        )
    console.print(f"[green]Benchmark added:[/green] {target} (expected {expected_rating.upper()})")


@dataset.command(name="benchmark-list")
@click.option("--category", "-c", default=None, help="Filter by category")
def dataset_benchmark_list(category: str | None):
    """List benchmark servers."""
    from rich.table import Table

    from spidershield.dataset.db import get_connection, init_db

    init_db()
    with get_connection() as conn:
        if category:
            rows = conn.execute(
                "SELECT * FROM benchmarks WHERE category = ? ORDER BY target",
                (category,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM benchmarks ORDER BY category, target"
            ).fetchall()

    if not rows:
        console.print("[dim]No benchmarks registered yet.[/dim]")
        return

    table = Table(title="Benchmark Servers")
    table.add_column("Target", style="bold")
    table.add_column("Expected")
    table.add_column("Score Range")
    table.add_column("Category")
    table.add_column("Last Result")
    table.add_column("Pass?")

    for r in rows:
        score_range = ""
        if r["expected_min_score"] is not None:
            score_range = f">={r['expected_min_score']}"
        if r["expected_max_score"] is not None:
            score_range += f" <={r['expected_max_score']}"
        last = r["last_actual_rating"] or "-"
        passed = r["passing"]
        pass_str = (
            "[green]YES[/green]" if passed == 1
            else "[red]NO[/red]" if passed == 0
            else "-"
        )
        table.add_row(
            r["target"], r["expected_rating"],
            score_range.strip() or "-", r["category"],
            last, pass_str,
        )
    console.print(table)


@dataset.command(name="benchmark-run")
@click.option("--category", "-c", default=None, help="Run only benchmarks in category")
def dataset_benchmark_run(category: str | None):
    """Run all benchmarks and check results against expectations."""
    from spidershield.dataset.db import get_connection, init_db
    from spidershield.scanner.runner import run_scan_report

    init_db()
    with get_connection() as conn:
        if category:
            benchmarks = conn.execute(
                "SELECT * FROM benchmarks WHERE category = ?",
                (category,),
            ).fetchall()
        else:
            benchmarks = conn.execute("SELECT * FROM benchmarks").fetchall()

    if not benchmarks:
        console.print("[dim]No benchmarks to run.[/dim]")
        return

    passed = 0
    failed = 0
    for bm in benchmarks:
        target = bm["target"]
        try:
            report = run_scan_report(target)
        except (SystemExit, Exception) as e:
            console.print(f"  [red]ERROR[/red] {target}: {e}")
            failed += 1
            continue

        actual_rating = report.rating.value
        ok = actual_rating == bm["expected_rating"]
        if bm["expected_min_score"] is not None and report.overall_score < bm["expected_min_score"]:
            ok = False
        if bm["expected_max_score"] is not None and report.overall_score > bm["expected_max_score"]:
            ok = False

        status = "[green]PASS[/green]" if ok else "[red]FAIL[/red]"
        console.print(
            f"  {status} {target}: "
            f"{actual_rating} ({report.overall_score}) "
            f"(expected {bm['expected_rating']})"
        )

        with get_connection() as conn:
            conn.execute(
                "UPDATE benchmarks SET last_actual_rating = ?, "
                "last_actual_score = ?, passing = ?, "
                "last_verified_at = datetime('now') WHERE id = ?",
                (actual_rating, report.overall_score, int(ok), bm["id"]),
            )

        if ok:
            passed += 1
        else:
            failed += 1

    console.print(f"\n[bold]Results:[/bold] {passed} passed, {failed} failed")


@dataset.command(name="calibrate")
@click.argument("scan_id", type=int)
@click.option("--rating", "-r", required=True, help="Ground truth rating (A/B/C/D/F)")
@click.option("--confidence", type=float, default=0.8, help="Confidence level (0-1)")
@click.option("--notes", "-n", default=None, help="Notes about this labeling")
def dataset_calibrate(scan_id: int, rating: str, confidence: float, notes: str | None):
    """Label a scan with ground truth rating for calibration.

    \b
    Examples:
      spidershield dataset calibrate 42 -r B --confidence 0.9
      spidershield dataset calibrate 15 -r F -n "Known malicious server"
    """
    from spidershield.dataset.db import get_connection, init_db

    init_db()
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id FROM scoring_calibration WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()
        if not row:
            console.print(f"[red]No calibration entry for scan_id={scan_id}[/red]")
            return
        conn.execute(
            "UPDATE scoring_calibration SET "
            "ground_truth_rating = ?, confidence = ?, "
            "labeled_at = datetime('now'), notes = ? "
            "WHERE scan_id = ?",
            (rating.upper(), confidence, notes, scan_id),
        )
    console.print(
        f"[green]Labeled scan {scan_id}:[/green] "
        f"ground truth = {rating.upper()} (confidence {confidence})"
    )


@dataset.command(name="calibrate-report")
def dataset_calibrate_report():
    """Show scoring calibration accuracy report."""
    from rich.table import Table

    from spidershield.dataset.db import get_connection, init_db

    init_db()
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT predicted_rating, ground_truth_rating, confidence, "
            "scoring_version, target "
            "FROM scoring_calibration "
            "WHERE ground_truth_rating IS NOT NULL "
            "ORDER BY labeled_at DESC"
        ).fetchall()

    if not rows:
        console.print("[dim]No labeled calibration data yet.[/dim]")
        console.print(
            "Use [bold]spidershield dataset calibrate <scan_id> -r <rating>[/bold]"
            " to label scans."
        )
        return

    correct = sum(1 for r in rows if r["predicted_rating"] == r["ground_truth_rating"])
    total = len(rows)
    accuracy = correct / total * 100

    console.print(f"\n[bold]Calibration Report[/bold] ({total} labeled scans)\n")
    console.print(f"  Accuracy: [bold]{accuracy:.1f}%[/bold] ({correct}/{total})")

    table = Table(title="Labeled Scans")
    table.add_column("Target")
    table.add_column("Predicted")
    table.add_column("Actual")
    table.add_column("Match?")
    table.add_column("Version")

    for r in rows:
        match = r["predicted_rating"] == r["ground_truth_rating"]
        match_str = "[green]YES[/green]" if match else "[red]NO[/red]"
        table.add_row(
            r["target"][:40], r["predicted_rating"],
            r["ground_truth_rating"], match_str,
            r["scoring_version"] or "-",
        )
    console.print(table)
