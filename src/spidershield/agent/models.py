"""Data models for agent security findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    OK = "ok"


@dataclass
class Finding:
    """A single security finding."""

    check_id: str
    title: str
    severity: Severity
    description: str
    fix_hint: str = ""
    auto_fixable: bool = False
    current_value: str = ""


class SkillVerdict(StrEnum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    TAMPERED = "tampered"
    UNKNOWN = "unknown"


@dataclass
class SkillFinding:
    """Security finding for a single skill."""

    skill_name: str
    skill_path: str
    verdict: SkillVerdict
    issues: list[str] = field(default_factory=list)
    matched_patterns: list[str] = field(default_factory=list)


@dataclass
class AuditFramework:
    """4-step audit coverage assessment (inspired by Skill Vetter protocol).

    Tracks which security audit dimensions were performed:
    - source: Provenance / origin verification (pinning, allowlist)
    - code: Static code/content analysis (pattern matching, toxic flow)
    - permission: Permission scope assessment (excessive_permissions, sandbox)
    - risk: Risk classification and scoring (verdict, severity)
    """

    source_checked: bool = False
    code_checked: bool = False
    permission_checked: bool = False
    risk_checked: bool = False

    @property
    def coverage(self) -> int:
        """Number of audit dimensions covered (0-4)."""
        return sum([
            self.source_checked,
            self.code_checked,
            self.permission_checked,
            self.risk_checked,
        ])

    @property
    def coverage_pct(self) -> int:
        """Coverage as percentage."""
        return self.coverage * 25


@dataclass
class ScanResult:
    """Complete scan result for an agent installation."""

    config_path: str
    version: str = "unknown"
    findings: list[Finding] = field(default_factory=list)
    skill_findings: list[SkillFinding] = field(default_factory=list)
    audit_framework: AuditFramework = field(default_factory=AuditFramework)

    @property
    def score(self) -> int:
        """Security score 0-10. Starts at 10, deduct per finding."""
        score = 10
        for f in self.findings:
            if f.severity == Severity.CRITICAL:
                score -= 3
            elif f.severity == Severity.HIGH:
                score -= 2
            elif f.severity == Severity.MEDIUM:
                score -= 1
        for sf in self.skill_findings:
            if sf.verdict == SkillVerdict.MALICIOUS:
                score -= 2
            elif sf.verdict == SkillVerdict.SUSPICIOUS:
                score -= 1
        return max(0, min(10, score))

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)
