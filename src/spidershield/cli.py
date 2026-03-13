"""SpiderShield CLI -- scan, improve, certify, and guard MCP servers."""

import click

from spidershield.commands import (
    agent_check,
    agent_pin,
    audit_group,
    dataset,
    evaluate,
    guard,
    harden,
    policy_group,
    proxy,
    rewrite,
    scan,
)


@click.group()
@click.version_option()
def main():
    """SpiderShield -- Scan, improve, and certify MCP servers."""


# Register all commands and groups
main.add_command(scan)
main.add_command(rewrite)
main.add_command(harden)
main.add_command(evaluate)
main.add_command(agent_check)
main.add_command(agent_pin)
main.add_command(dataset)
main.add_command(guard)
main.add_command(proxy)
main.add_command(policy_group)
main.add_command(audit_group)
