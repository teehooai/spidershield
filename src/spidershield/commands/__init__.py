"""CLI command modules for SpiderShield."""

from spidershield.commands.agent import agent_check, agent_pin
from spidershield.commands.audit import audit_group
from spidershield.commands.check import check
from spidershield.commands.dataset import dataset
from spidershield.commands.evaluate import evaluate
from spidershield.commands.guard import guard, proxy
from spidershield.commands.harden import harden
from spidershield.commands.policy import policy_group
from spidershield.commands.rewrite import rewrite
from spidershield.commands.scan import scan

__all__ = [
    "agent_check",
    "agent_pin",
    "audit_group",
    "check",
    "dataset",
    "evaluate",
    "guard",
    "harden",
    "policy_group",
    "proxy",
    "rewrite",
    "scan",
]
