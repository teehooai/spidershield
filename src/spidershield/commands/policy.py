"""Policy commands -- manage security policies."""

from pathlib import Path

import click
from rich.console import Console

console = Console()


@click.group(name="policy")
def policy_group() -> None:
    """Manage security policies."""


@policy_group.command(name="list")
def policy_list() -> None:
    """List available policy presets."""
    from rich.table import Table

    table = Table(title="Policy Presets")
    table.add_column("Name", style="cyan")
    table.add_column("Description")
    table.add_row("strict", "Production/enterprise: deny shell, restrict fs, escalate writes")
    table.add_row("balanced", "Development (default): block dangerous patterns, escalate")
    table.add_row("permissive", "Trusted/debug: only block known-malicious, allow everything else")
    console.print(table)


@policy_group.command(name="show")
@click.argument("name")
def policy_show(name: str) -> None:
    """Show the contents of a policy preset or file."""
    from spidershield.guard.policy import _PRESET_NAMES

    if name in _PRESET_NAMES:
        preset_file = Path(__file__).parent.parent / "guard" / "presets" / f"{name}.yaml"
        click.echo(preset_file.read_text())
    elif Path(name).exists():
        click.echo(Path(name).read_text())
    else:
        click.echo(f"Error: '{name}' is not a preset or existing file", err=True)
        raise SystemExit(1)


@policy_group.command(name="validate")
@click.argument("policy_file", type=click.Path(exists=True, path_type=Path))
def policy_validate(policy_file: Path) -> None:
    """Validate a custom policy YAML file.

    Checks that the file is valid YAML and all rules have required fields.

    \b
    Example:
      spidershield policy validate ./my-policy.yaml
    """
    import yaml

    from spidershield.guard.decision import Decision

    try:
        with open(policy_file) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        click.echo(f"Error: Invalid YAML — {e}", err=True)
        raise SystemExit(1)

    if not isinstance(data, dict) or "policies" not in data:
        click.echo("Error: Missing 'policies' key at top level", err=True)
        raise SystemExit(1)

    policies = data["policies"]
    if not isinstance(policies, list):
        click.echo("Error: 'policies' must be a list", err=True)
        raise SystemExit(1)

    valid_actions = {d.value for d in Decision}
    errors: list[str] = []

    for i, item in enumerate(policies):
        prefix = f"Rule #{i + 1}"
        if not isinstance(item, dict):
            errors.append(f"{prefix}: must be a mapping")
            continue
        if "name" not in item:
            errors.append(f"{prefix}: missing 'name'")
        if "action" not in item:
            errors.append(f"{prefix} ({item.get('name', '?')}): missing 'action'")
        elif item["action"] not in valid_actions:
            errors.append(
                f"{prefix} ({item.get('name', '?')}): invalid action '{item['action']}' "
                f"(must be one of {', '.join(valid_actions)})"
            )
        match = item.get("match", {})
        if not match.get("tool") and not match.get("any_tool"):
            errors.append(
                f"{prefix} ({item.get('name', '?')}): match must have 'tool' or 'any_tool: true'"
            )

    if errors:
        click.echo(f"Validation failed ({len(errors)} error(s)):", err=True)
        for err in errors:
            click.echo(f"  - {err}", err=True)
        raise SystemExit(1)

    try:
        from spidershield.guard.policy import PolicyEngine
        engine = PolicyEngine.from_yaml(data)
        click.echo(f"Valid: {len(engine.rules)} rule(s) loaded from {policy_file.name}")
    except Exception as e:
        click.echo(f"Error loading policy: {e}", err=True)
        raise SystemExit(1)
