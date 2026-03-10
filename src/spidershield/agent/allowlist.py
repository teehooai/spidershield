"""Allowlist mode -- only approved skills pass without warning.

Usage:
    spidershield agent-check --allowlist approved.json

approved.json format:
{
    "skills": {
        "my-skill": {"approved_by": "admin", "approved_at": "2026-03-08"},
        "another-skill": {"approved_by": "admin"}
    }
}

Skills not in the allowlist get a TS-W011 warning.
Skills in the allowlist with a hash field also get pin-verified.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import SkillFinding, SkillVerdict


def load_allowlist(path: Path) -> dict[str, dict]:
    """Load an allowlist JSON file.

    Returns dict of skill_name → metadata.
    Raises FileNotFoundError or json.JSONDecodeError on failure.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("skills", {})


def check_allowlist(
    skill_names: list[str],
    allowlist: dict[str, dict],
) -> list[SkillFinding]:
    """Check installed skills against allowlist.

    Returns findings for skills NOT in the allowlist.
    """
    findings: list[SkillFinding] = []

    for name in skill_names:
        if name not in allowlist:
            findings.append(SkillFinding(
                skill_name=name,
                skill_path="",
                verdict=SkillVerdict.SUSPICIOUS,
                issues=[f"[TS-W011] Skill '{name}' not in approved allowlist"],
                matched_patterns=["not_in_allowlist"],
            ))

    return findings
