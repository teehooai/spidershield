"""Agent commands -- agent-check and agent-pin for AI agent security scanning."""

from pathlib import Path

import click
from rich.console import Console

console = Console()


@click.command(name="agent-check")
@click.argument("agent_dir", required=False, default=None)
@click.option("--skills/--no-skills", default=True, help="Include skill scanning")
@click.option("--verify", is_flag=True, help="Verify pinned skills (rug pull detection)")
@click.option("--fix", is_flag=True, help="Auto-fix fixable issues")
@click.option("--dry-run", is_flag=True, help="Preview fixes without applying")
@click.option(
    "--format", "fmt",
    type=click.Choice(["text", "json", "sarif", "spiderrating"]),
    default="text",
    help="Output format (spiderrating outputs SpiderRating-compatible JSON)",
)
@click.option(
    "--ignore", "ignore_codes", multiple=True,
    help="Issue codes or pattern names to ignore (e.g. TS-W001, typosquat)",
)
@click.option(
    "--policy", "policy",
    type=click.Choice(["strict", "balanced", "permissive"]),
    default=None,
    help="Scan policy preset (strict=all, balanced=default, permissive=errors only)",
)
@click.option(
    "--allowlist", "allowlist_path",
    default=None,
    help="Path to approved skills JSON (skills not listed get TS-W011)",
)
def agent_check(
    agent_dir: str | None,
    skills: bool,
    verify: bool,
    fix: bool,
    dry_run: bool,
    fmt: str,
    ignore_codes: tuple[str, ...],
    policy: str | None,
    allowlist_path: str | None,
):
    """Scan an AI agent installation for security issues.

    Checks agent config, installed skills for malicious patterns,
    and optionally verifies pinned skills for rug pull detection.

    AGENT_DIR defaults to ~/.openclaw if not specified.
    """
    from spidershield.agent.issue_codes import resolve_codes
    from spidershield.agent.scanner import scan_config
    from spidershield.agent.skill_scanner import scan_skills

    # Resolve --ignore codes
    ignored = resolve_codes(list(ignore_codes)) if ignore_codes else set()

    # Apply policy preset (permissive ignores all warnings)
    if policy == "permissive":
        from spidershield.agent.issue_codes import SKILL_WARNING_CODES
        ignored |= set(SKILL_WARNING_CODES.keys())

    agent_path = Path(agent_dir) if agent_dir else None
    result = scan_config(agent_path, ignore_patterns=ignored)

    if skills:
        result.skill_findings.extend(scan_skills(agent_path, ignore_patterns=ignored))

    if verify:
        from spidershield.agent.pinning import verify_all_skills
        pin_findings = verify_all_skills(agent_path)
        result.skill_findings.extend(pin_findings)

    if allowlist_path and "not_in_allowlist" not in ignored:
        from spidershield.agent.allowlist import check_allowlist, load_allowlist
        allowlist = load_allowlist(Path(allowlist_path))
        installed_names = [sf.skill_name for sf in result.skill_findings]
        result.skill_findings.extend(check_allowlist(installed_names, allowlist))

    # Populate audit framework coverage
    result.audit_framework.source_checked = verify or allowlist_path is not None
    result.audit_framework.code_checked = skills
    result.audit_framework.permission_checked = True  # config scanner always checks
    result.audit_framework.risk_checked = True  # verdict/severity always computed

    # Record to dataset (best-effort)
    from spidershield.dataset.collector import record_agent_scan
    record_agent_scan(result, policy=policy)

    if fix or dry_run:
        from spidershield.agent.fixer import fix_findings
        from spidershield.agent.report import print_fix_report
        fixes = fix_findings(result.findings, agent_path, dry_run=dry_run or not fix)
        if fmt == "text":
            print_fix_report(fixes)
        else:
            import json
            click.echo(json.dumps({"fixes": fixes}, indent=2))
        return

    if fmt == "text":
        from spidershield.agent.report import print_report
        print_report(result)
    elif fmt == "json":
        import dataclasses
        import json
        click.echo(json.dumps(dataclasses.asdict(result), indent=2))
    elif fmt == "sarif":
        from spidershield.agent.sarif import sarif_to_json, scan_result_to_sarif
        sarif = scan_result_to_sarif(result)
        click.echo(sarif_to_json(sarif))
    elif fmt == "spiderrating":
        import dataclasses
        import json

        from spidershield.spiderrating import convert_skill

        result_dict = dataclasses.asdict(result)

        # Read SKILL.md content for description scoring
        skill_content = ""
        effective_path = Path(agent_dir) if agent_dir else Path.home() / ".openclaw"
        for skill_dir in [effective_path / "skills", effective_path / "workspace" / "skills"]:
            if skill_dir.exists():
                for p in skill_dir.rglob("SKILL.md"):
                    try:
                        skill_content = p.read_text(encoding="utf-8")
                    except OSError:
                        pass
                    break

        # Try to extract owner/repo from agent_dir or first skill path
        owner, repo = "local", effective_path.name
        if result.skill_findings:
            skill_name = result.skill_findings[0].skill_name
        else:
            skill_name = repo

        sr = convert_skill(result_dict, skill_name, owner, repo, skill_content=skill_content)
        click.echo(json.dumps(sr, indent=2))

    # Exit codes based on policy
    from spidershield.agent.models import Severity, SkillVerdict
    if any(sf.verdict == SkillVerdict.TAMPERED for sf in result.skill_findings):
        raise SystemExit(2)
    if any(f.severity == Severity.CRITICAL for f in result.findings):
        raise SystemExit(1)
    if any(sf.verdict == SkillVerdict.MALICIOUS for sf in result.skill_findings):
        raise SystemExit(1)
    # Strict: exit 1 on any finding (HIGH, MEDIUM, LOW, suspicious)
    if policy == "strict":
        if result.findings or any(
            sf.verdict == SkillVerdict.SUSPICIOUS for sf in result.skill_findings
        ):
            raise SystemExit(1)


# --- Agent Pin subgroup ---


@click.group(name="agent-pin")
def agent_pin():
    """Manage skill pins for rug pull detection."""


@agent_pin.command(name="add")
@click.argument("skill_path")
@click.option("--pin-dir", default=None, help="Pin storage directory")
def pin_add(skill_path: str, pin_dir: str | None):
    """Pin a single skill by recording its content hash."""
    from spidershield.agent.pinning import pin_skill

    pin_path = Path(pin_dir) if pin_dir else None
    result = pin_skill(Path(skill_path), pin_path)
    console.print(f"[green]Pinned:[/green] {result['skill_name']} ({result['hash'][:16]}...)")


@agent_pin.command(name="add-all")
@click.argument("agent_dir", required=False, default=None)
@click.option("--pin-dir", default=None, help="Pin storage directory")
def pin_add_all(agent_dir: str | None, pin_dir: str | None):
    """Pin all installed skills."""
    from spidershield.agent.pinning import pin_all_skills

    agent_path = Path(agent_dir) if agent_dir else None
    pin_path = Path(pin_dir) if pin_dir else None
    results = pin_all_skills(agent_path, pin_path)
    for r in results:
        console.print(f"[green]Pinned:[/green] {r['skill_name']} ({r['hash'][:16]}...)")
    console.print(f"\n{len(results)} skill(s) pinned.")


@agent_pin.command(name="list")
@click.option("--pin-dir", default=None, help="Pin storage directory")
def pin_list(pin_dir: str | None):
    """List all pinned skills."""
    from spidershield.agent.pinning import list_pins

    pin_path = Path(pin_dir) if pin_dir else None
    pins = list_pins(pin_path)
    if not pins:
        console.print("[dim]No skills pinned yet.[/dim]")
        return
    for name, data in pins.items():
        console.print(f"  {name}: {data['hash'][:16]}... (pinned {data.get('pinned_at', '?')})")


@agent_pin.command(name="verify")
@click.argument("agent_dir", required=False, default=None)
@click.option("--pin-dir", default=None, help="Pin storage directory")
def pin_verify(agent_dir: str | None, pin_dir: str | None):
    """Verify all pinned skills against their recorded hashes."""
    from spidershield.agent.models import SkillVerdict
    from spidershield.agent.pinning import verify_all_skills

    agent_path = Path(agent_dir) if agent_dir else None
    pin_path = Path(pin_dir) if pin_dir else None
    findings = verify_all_skills(agent_path, pin_path)

    if not findings:
        console.print("[dim]No pins to verify.[/dim]")
        return

    tampered = False
    for f in findings:
        if f.verdict == SkillVerdict.SAFE:
            console.print(f"  [green]OK[/green] {f.skill_name}")
        elif f.verdict == SkillVerdict.TAMPERED:
            console.print(f"  [bold red]TAMPERED[/bold red] {f.skill_name}")
            for issue in f.issues:
                console.print(f"    {issue}")
            tampered = True
        else:
            console.print(f"  [dim]UNKNOWN[/dim] {f.skill_name}")
            for issue in f.issues:
                console.print(f"    {issue}")

    if tampered:
        raise SystemExit(2)


@agent_pin.command(name="remove")
@click.argument("skill_name")
@click.option("--pin-dir", default=None, help="Pin storage directory")
def pin_remove(skill_name: str, pin_dir: str | None):
    """Remove a skill's pin."""
    from spidershield.agent.pinning import unpin_skill

    pin_path = Path(pin_dir) if pin_dir else None
    if unpin_skill(skill_name, pin_path):
        console.print(f"[green]Unpinned:[/green] {skill_name}")
    else:
        console.print(f"[yellow]Not found:[/yellow] {skill_name}")
