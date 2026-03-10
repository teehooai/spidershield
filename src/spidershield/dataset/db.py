"""SQLite database manager for SpiderShield security dataset.

All data stays local and private. No network calls, no cloud sync.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path

# Default DB location: ~/.spidershield/dataset.db
DEFAULT_DB_DIR = Path.home() / ".spidershield"
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "dataset.db"

SCHEMA_VERSION = 3

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    scanned_at TEXT NOT NULL DEFAULT (datetime('now')),
    tool_count INTEGER NOT NULL DEFAULT 0,
    security_score REAL NOT NULL DEFAULT 0.0,
    description_score REAL NOT NULL DEFAULT 0.0,
    architecture_score REAL NOT NULL DEFAULT 0.0,
    overall_score REAL NOT NULL DEFAULT 0.0,
    rating TEXT NOT NULL DEFAULT 'C',
    license TEXT,
    license_ok INTEGER NOT NULL DEFAULT 1,
    has_tests INTEGER NOT NULL DEFAULT 0,
    has_error_handling INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS security_issues (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER,
    description TEXT NOT NULL,
    fix_suggestion TEXT
);

CREATE TABLE IF NOT EXISTS tool_descriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    recorded_at TEXT NOT NULL DEFAULT (datetime('now')),
    target TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    original_description TEXT NOT NULL DEFAULT '',
    rewritten_description TEXT,
    original_score REAL,
    rewritten_score REAL,
    engine TEXT,
    quality_gate_passed INTEGER
);

CREATE TABLE IF NOT EXISTS hardener_fixes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    recorded_at TEXT NOT NULL DEFAULT (datetime('now')),
    target TEXT NOT NULL,
    category TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER,
    suggestion TEXT NOT NULL,
    code_fix TEXT,
    confidence REAL NOT NULL DEFAULT 0.0,
    engine TEXT
);

CREATE TABLE IF NOT EXISTS pull_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo TEXT NOT NULL,
    pr_number INTEGER NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    strategy TEXT,
    tools_changed INTEGER NOT NULL DEFAULT 0,
    engine TEXT,
    submitted_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    merged_at TEXT,
    closed_at TEXT,
    rejection_reason TEXT,
    notes TEXT,
    UNIQUE(repo, pr_number)
);

CREATE TABLE IF NOT EXISTS pr_tool_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pr_id INTEGER NOT NULL REFERENCES pull_requests(id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    original_description TEXT,
    proposed_description TEXT,
    accepted INTEGER
);

CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_rating ON scans(rating);
CREATE INDEX IF NOT EXISTS idx_issues_severity ON security_issues(severity);
CREATE INDEX IF NOT EXISTS idx_issues_category ON security_issues(category);
CREATE INDEX IF NOT EXISTS idx_descriptions_tool ON tool_descriptions(tool_name);
CREATE INDEX IF NOT EXISTS idx_fixes_category ON hardener_fixes(category);
CREATE INDEX IF NOT EXISTS idx_prs_repo ON pull_requests(repo);
CREATE INDEX IF NOT EXISTS idx_prs_status ON pull_requests(status);

CREATE TABLE IF NOT EXISTS agent_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    scanned_at TEXT NOT NULL DEFAULT (datetime('now')),
    security_score REAL NOT NULL DEFAULT 0.0,
    config_findings INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    skill_count INTEGER NOT NULL DEFAULT 0,
    malicious_skills INTEGER NOT NULL DEFAULT 0,
    suspicious_skills INTEGER NOT NULL DEFAULT 0,
    safe_skills INTEGER NOT NULL DEFAULT 0,
    audit_coverage_pct REAL NOT NULL DEFAULT 0.0,
    policy TEXT
);

CREATE TABLE IF NOT EXISTS agent_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_scan_id INTEGER NOT NULL REFERENCES agent_scans(id) ON DELETE CASCADE,
    finding_type TEXT NOT NULL,
    check_id TEXT,
    issue_code TEXT,
    severity TEXT,
    verdict TEXT,
    title TEXT NOT NULL,
    description TEXT,
    skill_name TEXT,
    matched_patterns TEXT,
    auto_fixable INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_agent_scans_target ON agent_scans(target);
CREATE INDEX IF NOT EXISTS idx_agent_findings_type ON agent_findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_agent_findings_severity ON agent_findings(severity);
"""


def _ensure_dir(db_path: Path) -> None:
    """Create parent directory if it doesn't exist."""
    db_path.parent.mkdir(parents=True, exist_ok=True)


def init_db(db_path: Path | None = None) -> Path:
    """Initialize the database schema. Returns the actual DB path used."""
    path = db_path or DEFAULT_DB_PATH
    _ensure_dir(path)

    conn = sqlite3.connect(str(path))
    try:
        conn.executescript(_SCHEMA_SQL)

        # Check/set schema version
        cur = conn.execute("SELECT COUNT(*) FROM schema_version")
        if cur.fetchone()[0] == 0:
            conn.execute(
                "INSERT INTO schema_version (version) VALUES (?)",
                (SCHEMA_VERSION,),
            )
        conn.commit()
    finally:
        conn.close()

    return path


@contextmanager
def get_connection(db_path: Path | None = None):
    """Context manager for database connections with WAL mode."""
    path = db_path or DEFAULT_DB_PATH
    _ensure_dir(path)

    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_stats(db_path: Path | None = None) -> dict:
    """Get dataset statistics."""
    path = db_path or DEFAULT_DB_PATH
    if not path.exists():
        return {
            "db_exists": False,
            "total_scans": 0,
            "total_issues": 0,
            "total_descriptions": 0,
            "total_fixes": 0,
        }

    with get_connection(path) as conn:
        scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        issues = conn.execute(
            "SELECT COUNT(*) FROM security_issues"
        ).fetchone()[0]
        descriptions = conn.execute(
            "SELECT COUNT(*) FROM tool_descriptions"
        ).fetchone()[0]
        fixes = conn.execute(
            "SELECT COUNT(*) FROM hardener_fixes"
        ).fetchone()[0]

        # Top categories
        top_cats = conn.execute(
            "SELECT category, COUNT(*) as cnt "
            "FROM security_issues GROUP BY category "
            "ORDER BY cnt DESC LIMIT 5"
        ).fetchall()

        # Rating distribution
        ratings = conn.execute(
            "SELECT rating, COUNT(*) as cnt "
            "FROM scans GROUP BY rating "
            "ORDER BY cnt DESC"
        ).fetchall()

        # Unique targets
        targets = conn.execute(
            "SELECT COUNT(DISTINCT target) FROM scans"
        ).fetchone()[0]

        # PR stats
        pr_total = conn.execute(
            "SELECT COUNT(*) FROM pull_requests"
        ).fetchone()[0]
        pr_by_status = conn.execute(
            "SELECT status, COUNT(*) as cnt "
            "FROM pull_requests GROUP BY status "
            "ORDER BY cnt DESC"
        ).fetchall()
        pr_tools = conn.execute(
            "SELECT COALESCE(SUM(tools_changed), 0) "
            "FROM pull_requests"
        ).fetchone()[0]

        # Agent-check stats
        agent_scans_total = conn.execute(
            "SELECT COUNT(*) FROM agent_scans"
        ).fetchone()[0]
        agent_findings_total = conn.execute(
            "SELECT COUNT(*) FROM agent_findings"
        ).fetchone()[0]
        agent_by_type = conn.execute(
            "SELECT finding_type, COUNT(*) as cnt "
            "FROM agent_findings GROUP BY finding_type "
            "ORDER BY cnt DESC"
        ).fetchall()

        return {
            "db_exists": True,
            "db_path": str(path),
            "db_size_kb": round(path.stat().st_size / 1024, 1),
            "total_scans": scans,
            "unique_targets": targets,
            "total_issues": issues,
            "total_descriptions": descriptions,
            "total_fixes": fixes,
            "total_prs": pr_total,
            "pr_tools_changed": pr_tools,
            "total_agent_scans": agent_scans_total,
            "total_agent_findings": agent_findings_total,
            "agent_finding_types": {r[0]: r[1] for r in agent_by_type},
            "top_issue_categories": [
                {"category": r[0], "count": r[1]} for r in top_cats
            ],
            "rating_distribution": {r[0]: r[1] for r in ratings},
            "pr_status_distribution": {r[0]: r[1] for r in pr_by_status},
        }
