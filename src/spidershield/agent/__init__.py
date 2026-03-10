"""SpiderShield Agent Security Module.

Scans AI agent configurations, skills/tools for malicious patterns,
and provides auto-fix capabilities. Ported from SpiderShield.
"""

from .models import (
    AuditFramework,
    Finding,
    ScanResult,
    Severity,
    SkillFinding,
    SkillVerdict,
)

__all__ = [
    "AuditFramework",
    "Finding",
    "ScanResult",
    "Severity",
    "SkillFinding",
    "SkillVerdict",
]
