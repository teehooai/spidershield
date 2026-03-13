"""Guard and proxy commands -- runtime security for MCP servers."""

from pathlib import Path

import click


@click.command()
@click.argument("server_cmd", nargs=-1, required=True)
@click.option(
    "--policy",
    default="balanced",
    help="Policy preset (strict/balanced/permissive) or YAML file path",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose logging to stderr")
@click.option(
    "--audit-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Custom audit log directory",
)
@click.option("--no-audit", is_flag=True, help="Disable audit logging")
@click.option("--dry-run", is_flag=True, help="Log decisions but don't enforce denials")
def guard(
    server_cmd: tuple[str, ...],
    policy: str,
    verbose: bool,
    audit_dir: Path | None,
    no_audit: bool,
    dry_run: bool,
) -> None:
    """Wrap any subprocess with security guard (standalone mode).

    Scans stdout for tool call JSON patterns and evaluates them.

    \b
    Examples:
      spidershield guard -- python my_agent.py
      spidershield guard --policy strict -- node agent.js
      spidershield guard --dry-run -- python my_agent.py
    """
    from spidershield.adapters.standalone import run_standalone_guard

    if verbose:
        click.echo(f"[SpiderShield] Policy: {policy}", err=True)
        click.echo(f"[SpiderShield] Command: {' '.join(server_cmd)}", err=True)
        if dry_run:
            click.echo("[SpiderShield] DRY-RUN mode", err=True)

    try:
        rc = run_standalone_guard(
            server_cmd=list(server_cmd),
            policy=policy,
            verbose=verbose,
            audit_dir=str(audit_dir) if audit_dir else None,
            no_audit=no_audit,
            dry_run=dry_run,
        )
        raise SystemExit(rc)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        raise SystemExit(1)


@click.command()
@click.argument("server_cmd", nargs=-1, required=True)
@click.option(
    "--policy",
    default="balanced",
    help="Policy preset (strict/balanced/permissive) or YAML file path",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose logging to stderr")
@click.option(
    "--audit-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Custom audit log directory (default: ~/.spidershield/audit/)",
)
@click.option("--no-audit", is_flag=True, help="Disable audit logging")
@click.option("--dry-run", is_flag=True, help="Log decisions but don't enforce denials")
def proxy(
    server_cmd: tuple[str, ...],
    policy: str,
    verbose: bool,
    audit_dir: Path | None,
    no_audit: bool,
    dry_run: bool,
) -> None:
    """Start MCP proxy with security guard.

    Sits between MCP client (Claude Desktop / Cursor) and server.
    Intercepts tool calls and enforces security policies.

    \b
    Examples:
      spidershield proxy -- npx @modelcontextprotocol/server-filesystem /tmp
      spidershield proxy --policy strict -- npx server-filesystem /tmp
      spidershield proxy --policy ./my-policy.yaml -- python my_server.py
      spidershield proxy -v -- npx server-everything
      spidershield proxy --dry-run -- npx server-filesystem /tmp

    \b
    Claude Desktop config:
      {
        "mcpServers": {
          "filesystem": {
            "command": "spidershield",
            "args": ["proxy", "--policy", "strict", "--",
                     "npx", "@modelcontextprotocol/server-filesystem", "/tmp"]
          }
        }
      }
    """
    from spidershield.adapters.mcp_proxy import run_mcp_proxy

    if verbose:
        click.echo(f"[SpiderShield] Policy: {policy}", err=True)
        click.echo(f"[SpiderShield] Server: {' '.join(server_cmd)}", err=True)
        if dry_run:
            click.echo("[SpiderShield] DRY-RUN mode: logging only, no enforcement", err=True)

    try:
        rc = run_mcp_proxy(
            server_cmd=list(server_cmd),
            policy=policy,
            verbose=verbose,
            audit_dir=str(audit_dir) if audit_dir else None,
            no_audit=no_audit,
            dry_run=dry_run,
        )
        raise SystemExit(rc)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        raise SystemExit(1)
