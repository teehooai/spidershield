"""Audit commands -- view and analyze security guard audit logs."""

from pathlib import Path

import click
from rich.console import Console

console = Console()


@click.group(name="audit")
@click.option(
    "--audit-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Audit log directory (default: ~/.spidershield/audit/)",
)
@click.pass_context
def audit_group(ctx: click.Context, audit_dir: Path | None) -> None:
    """View and analyze audit logs from the security guard."""
    ctx.ensure_object(dict)
    ctx.obj["audit_dir"] = audit_dir


@audit_group.command(name="show")
@click.option("--last", "last_hours", type=float, default=None, help="Last N hours")
@click.option("--session", "session_id", default=None, help="Filter by session ID")
@click.option("--tool", "tool_name", default=None, help="Filter by tool name (substring match)")
@click.option(
    "--decision",
    type=click.Choice(["allow", "deny", "escalate"], case_sensitive=False),
    default=None,
    help="Filter by decision",
)
@click.option("--limit", type=int, default=50, help="Max entries to show (default: 50)")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def audit_show(
    ctx: click.Context,
    last_hours: float | None,
    session_id: str | None,
    tool_name: str | None,
    decision: str | None,
    limit: int,
    json_output: bool,
) -> None:
    """Show recent audit log entries.

    \b
    Examples:
      spidershield audit show                        # Last 50 entries
      spidershield audit show --last 24              # Last 24 hours
      spidershield audit show --decision deny        # Only denials
      spidershield audit show --tool read_file       # Filter by tool
      spidershield audit show --json                 # JSON output
    """
    import json as json_mod

    from spidershield.audit.storage import AuditQuery

    audit_dir = ctx.obj.get("audit_dir")
    if audit_dir is None:
        audit_dir = Path.home() / ".spidershield" / "audit"

    query = AuditQuery(audit_dir)
    entries = list(query.iter_entries(
        last_hours=last_hours,
        session_id=session_id,
        tool_name=tool_name,
        decision=decision,
        phase="before_call",
    ))

    if not entries:
        click.echo("No audit entries found.")
        return

    entries = entries[-limit:]

    if json_output:
        click.echo(json_mod.dumps(entries, indent=2, ensure_ascii=False, default=str))
        return

    from rich.table import Table

    table = Table(title=f"Audit Log ({len(entries)} entries)")
    table.add_column("Time", style="dim", width=19)
    table.add_column("Session", style="dim", width=12)
    table.add_column("Tool", style="cyan")
    table.add_column("Decision")
    table.add_column("Reason")
    table.add_column("Policy", style="dim")

    decision_styles = {"allow": "green", "deny": "red", "escalate": "yellow"}

    for e in entries:
        ts = e.get("timestamp", "")[:19]
        sid = e.get("session_id", "")[:12]
        tn = e.get("tool_name", "")
        dec = e.get("decision", "")
        reason = e.get("reason", "")[:60]
        pol = e.get("policy_matched", "") or ""
        style = decision_styles.get(dec, "white")
        table.add_row(ts, sid, tn, f"[{style}]{dec.upper()}[/{style}]", reason, pol)

    console.print(table)


@audit_group.command(name="stats")
@click.option("--last", "last_hours", type=float, default=None, help="Stats from last N hours")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def audit_stats(
    ctx: click.Context,
    last_hours: float | None,
    json_output: bool,
) -> None:
    """Show aggregate audit statistics.

    \b
    Examples:
      spidershield audit stats               # All-time stats
      spidershield audit stats --last 24     # Last 24 hours
      spidershield audit stats --json        # JSON output
    """
    import json as json_mod

    from spidershield.audit.storage import AuditQuery

    audit_dir = ctx.obj.get("audit_dir")
    if audit_dir is None:
        audit_dir = Path.home() / ".spidershield" / "audit"

    query = AuditQuery(audit_dir)
    stats = query.stats(last_hours=last_hours)

    if stats.total_calls == 0:
        click.echo("No audit data found.")
        return

    if json_output:
        d = {
            "total_calls": stats.total_calls,
            "allowed": stats.allowed,
            "denied": stats.denied,
            "escalated": stats.escalated,
            "denied_pct": round(stats.denied_pct, 1),
            "escalated_pct": round(stats.escalated_pct, 1),
            "pii_detections": stats.pii_detections,
            "top_denied_tools": stats.top_denied_tools,
            "top_triggered_rules": stats.top_triggered_rules,
        }
        click.echo(json_mod.dumps(d, indent=2, ensure_ascii=False))
        return

    from rich.table import Table

    period = f" (last {last_hours}h)" if last_hours else " (all time)"
    console.print(f"\n[bold]Audit Statistics{period}[/bold]\n")

    st = Table(show_header=False, box=None, padding=(0, 2))
    st.add_column("Metric", style="cyan")
    st.add_column("Value", justify="right")
    st.add_row("Total calls", str(stats.total_calls))
    st.add_row("Allowed", f"[green]{stats.allowed}[/green]")
    st.add_row("Denied", f"[red]{stats.denied}[/red] ({stats.denied_pct:.1f}%)")
    st.add_row("Escalated", f"[yellow]{stats.escalated}[/yellow] ({stats.escalated_pct:.1f}%)")
    st.add_row("PII detections", str(stats.pii_detections))
    console.print(st)

    if stats.top_denied_tools:
        console.print("\n[bold]Top Denied Tools[/bold]")
        for tool, count in stats.top_denied_tools[:5]:
            console.print(f"  {tool}: {count}")

    if stats.top_triggered_rules:
        console.print("\n[bold]Top Triggered Rules[/bold]")
        for rule, count in stats.top_triggered_rules[:5]:
            console.print(f"  {rule}: {count}")

    console.print()
