"""Data collector -- saves scan/rewrite/harden results to local SQLite.

All writes are best-effort: if the DB is unavailable or locked,
operations silently degrade (no scan/rewrite/harden will ever fail
because of dataset recording).
"""

from __future__ import annotations

import logging
from pathlib import Path

from .db import get_connection, init_db

logger = logging.getLogger(__name__)


def _safe_record(func):
    """Decorator: swallow all exceptions so dataset recording never breaks core ops."""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.debug("Dataset recording failed: %s", e)
            return None
    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper


@_safe_record
def record_scan(report, db_path: Path | None = None) -> int | None:
    """Record a scan report to the dataset. Returns scan_id or None."""
    init_db(db_path)

    with get_connection(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO scans "
            "(target, tool_count, security_score, description_score, "
            "architecture_score, overall_score, rating, license, "
            "license_ok, has_tests, has_error_handling) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                report.target,
                report.tool_count,
                report.security_score,
                report.description_score,
                report.architecture_score,
                report.overall_score,
                report.rating.value if hasattr(report.rating, "value") else str(report.rating),
                report.license,
                int(report.license_ok),
                int(report.has_tests),
                int(report.has_error_handling),
            ),
        )
        scan_id = cur.lastrowid

        # Record security issues
        for issue in report.security_issues:
            conn.execute(
                "INSERT INTO security_issues "
                "(scan_id, severity, category, file, line, "
                "description, fix_suggestion) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    issue.severity,
                    issue.category,
                    issue.file,
                    issue.line,
                    issue.description,
                    issue.fix_suggestion,
                ),
            )

        # Record tool description scores
        for ts in report.tool_scores:
            conn.execute(
                "INSERT INTO tool_descriptions "
                "(scan_id, target, tool_name, original_description, "
                "original_score) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    scan_id,
                    report.target,
                    ts.tool_name,
                    ts.suggested_rewrite or "",
                    ts.overall_score,
                ),
            )

        return scan_id


@_safe_record
def record_rewrite(
    target: str,
    tool_name: str,
    original: str,
    rewritten: str,
    original_score: float,
    rewritten_score: float,
    engine: str,
    passed: bool,
    db_path: Path | None = None,
) -> int | None:
    """Record a single tool description rewrite pair."""
    init_db(db_path)

    with get_connection(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO tool_descriptions "
            "(target, tool_name, original_description, "
            "rewritten_description, original_score, rewritten_score, "
            "engine, quality_gate_passed) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                target,
                tool_name,
                original,
                rewritten,
                original_score,
                rewritten_score,
                engine,
                int(passed),
            ),
        )
        return cur.lastrowid


@_safe_record
def record_hardener_fix(
    target: str,
    category: str,
    file: str,
    suggestion: str,
    code_fix: str | None = None,
    confidence: float = 0.0,
    line: int | None = None,
    engine: str = "template",
    db_path: Path | None = None,
) -> int | None:
    """Record a single hardener finding/fix."""
    init_db(db_path)

    with get_connection(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO hardener_fixes "
            "(target, category, file, line, suggestion, "
            "code_fix, confidence, engine) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                target,
                category,
                file,
                line,
                suggestion,
                code_fix,
                confidence,
                engine,
            ),
        )
        return cur.lastrowid


@_safe_record
def record_pr(
    repo: str,
    pr_number: int,
    title: str,
    status: str = "open",
    strategy: str | None = None,
    tools_changed: int = 0,
    engine: str | None = None,
    submitted_at: str | None = None,
    merged_at: str | None = None,
    closed_at: str | None = None,
    rejection_reason: str | None = None,
    notes: str | None = None,
    db_path: Path | None = None,
) -> int | None:
    """Record or update a PR. Uses UPSERT on (repo, pr_number)."""
    init_db(db_path)

    with get_connection(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO pull_requests "
            "(repo, pr_number, title, status, strategy, "
            "tools_changed, engine, submitted_at, merged_at, "
            "closed_at, rejection_reason, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, "
            "COALESCE(?, datetime('now')), ?, ?, ?, ?) "
            "ON CONFLICT(repo, pr_number) DO UPDATE SET "
            "status=excluded.status, "
            "title=excluded.title, "
            "tools_changed=excluded.tools_changed, "
            "updated_at=datetime('now'), "
            "merged_at=COALESCE(excluded.merged_at, merged_at), "
            "closed_at=COALESCE(excluded.closed_at, closed_at), "
            "rejection_reason="
            "COALESCE(excluded.rejection_reason, rejection_reason), "
            "notes=COALESCE(excluded.notes, notes)",
            (
                repo,
                pr_number,
                title,
                status,
                strategy,
                tools_changed,
                engine,
                submitted_at,
                merged_at,
                closed_at,
                rejection_reason,
                notes,
            ),
        )
        return cur.lastrowid


@_safe_record
def record_pr_tool_change(
    pr_id: int,
    tool_name: str,
    original_description: str | None = None,
    proposed_description: str | None = None,
    accepted: bool | None = None,
    db_path: Path | None = None,
) -> int | None:
    """Record a tool description change within a PR."""
    init_db(db_path)

    with get_connection(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO pr_tool_changes "
            "(pr_id, tool_name, original_description, "
            "proposed_description, accepted) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                pr_id,
                tool_name,
                original_description,
                proposed_description,
                int(accepted) if accepted is not None else None,
            ),
        )
        return cur.lastrowid


@_safe_record
def record_agent_scan(result, policy: str | None = None, db_path: Path | None = None) -> int | None:
    """Record an agent-check scan result to the dataset. Returns agent_scan_id or None."""
    from teeshield.agent.models import SkillVerdict

    init_db(db_path)

    with get_connection(db_path) as conn:
        skill_findings = result.skill_findings
        malicious = sum(1 for sf in skill_findings if sf.verdict == SkillVerdict.MALICIOUS)
        suspicious = sum(1 for sf in skill_findings if sf.verdict == SkillVerdict.SUSPICIOUS)
        safe = sum(1 for sf in skill_findings if sf.verdict == SkillVerdict.SAFE)

        cur = conn.execute(
            "INSERT INTO agent_scans "
            "(target, security_score, config_findings, critical_count, "
            "high_count, skill_count, malicious_skills, suspicious_skills, "
            "safe_skills, audit_coverage_pct, policy) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                result.config_path,
                result.score,
                len(result.findings),
                result.critical_count,
                result.high_count,
                len(skill_findings),
                malicious,
                suspicious,
                safe,
                result.audit_framework.coverage_pct,
                policy,
            ),
        )
        agent_scan_id = cur.lastrowid

        # Record config findings
        for f in result.findings:
            conn.execute(
                "INSERT INTO agent_findings "
                "(agent_scan_id, finding_type, check_id, severity, "
                "title, description, auto_fixable) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    agent_scan_id,
                    "config",
                    f.check_id,
                    f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    f.title,
                    f.description,
                    int(f.auto_fixable),
                ),
            )

        # Record skill findings
        for sf in skill_findings:
            conn.execute(
                "INSERT INTO agent_findings "
                "(agent_scan_id, finding_type, verdict, "
                "title, description, skill_name, matched_patterns) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    agent_scan_id,
                    "skill",
                    sf.verdict.value if hasattr(sf.verdict, "value") else str(sf.verdict),
                    sf.skill_name,
                    "; ".join(sf.issues) if sf.issues else "",
                    sf.skill_name,
                    ",".join(sf.matched_patterns) if sf.matched_patterns else "",
                ),
            )

        return agent_scan_id


def get_prs(
    status: str | None = None,
    db_path: Path | None = None,
) -> list[dict]:
    """Get all PRs, optionally filtered by status."""
    init_db(db_path)

    with get_connection(db_path) as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM pull_requests "
                "WHERE status = ? ORDER BY submitted_at DESC",
                (status,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM pull_requests "
                "ORDER BY submitted_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]
