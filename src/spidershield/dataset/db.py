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

SCHEMA_VERSION = 5

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
    has_error_handling INTEGER NOT NULL DEFAULT 0,
    scoring_version TEXT NOT NULL DEFAULT 'v2',
    scanner_version TEXT NOT NULL DEFAULT '0.3.0',
    pattern_set_hash TEXT,
    scan_duration_ms INTEGER,
    source_type TEXT NOT NULL DEFAULT 'local'
);

CREATE TABLE IF NOT EXISTS security_issues (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER,
    description TEXT NOT NULL,
    fix_suggestion TEXT,
    pattern_name TEXT,
    false_positive INTEGER,
    reviewed_at TEXT
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
    auto_fixable INTEGER NOT NULL DEFAULT 0,
    false_positive INTEGER,
    reviewed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_agent_scans_target ON agent_scans(target);
CREATE INDEX IF NOT EXISTS idx_agent_findings_type ON agent_findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_agent_findings_severity ON agent_findings(severity);

-- v4: Data flywheel tables

CREATE TABLE IF NOT EXISTS scoring_versions (
    version TEXT PRIMARY KEY,
    formula TEXT NOT NULL,
    weights_json TEXT NOT NULL,
    grade_boundaries_json TEXT NOT NULL,
    hard_constraints_json TEXT,
    introduced_at TEXT NOT NULL DEFAULT (datetime('now')),
    scanner_version TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS server_timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    scanned_at TEXT NOT NULL,
    scoring_version TEXT NOT NULL,
    overall_score REAL NOT NULL,
    security_score REAL NOT NULL,
    description_score REAL NOT NULL,
    architecture_score REAL NOT NULL,
    rating TEXT NOT NULL,
    tool_count INTEGER NOT NULL DEFAULT 0,
    issue_count INTEGER NOT NULL DEFAULT 0,
    delta_overall REAL,
    delta_security REAL,
    delta_description REAL,
    prev_scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_timeline_target
    ON server_timeline(target);
CREATE INDEX IF NOT EXISTS idx_timeline_date
    ON server_timeline(scanned_at);

CREATE TABLE IF NOT EXISTS pattern_effectiveness (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_name TEXT NOT NULL,
    pattern_source TEXT NOT NULL DEFAULT 'python',
    total_fires INTEGER NOT NULL DEFAULT 0,
    confirmed_true INTEGER NOT NULL DEFAULT 0,
    confirmed_false INTEGER NOT NULL DEFAULT 0,
    unreviewed INTEGER NOT NULL DEFAULT 0,
    last_fired_at TEXT,
    last_reviewed_at TEXT,
    computed_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(pattern_name, pattern_source)
);

CREATE TABLE IF NOT EXISTS scoring_calibration (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    target TEXT NOT NULL,
    scoring_version TEXT NOT NULL,
    predicted_overall REAL NOT NULL,
    predicted_rating TEXT NOT NULL,
    ground_truth_rating TEXT,
    ground_truth_source TEXT,
    confidence REAL NOT NULL DEFAULT 0.0,
    labeled_at TEXT,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_cal_target
    ON scoring_calibration(target);
CREATE INDEX IF NOT EXISTS idx_cal_version
    ON scoring_calibration(scoring_version);

CREATE TABLE IF NOT EXISTS benchmarks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    expected_rating TEXT NOT NULL,
    expected_min_score REAL,
    expected_max_score REAL,
    category TEXT NOT NULL DEFAULT 'general',
    description TEXT,
    last_verified_at TEXT,
    last_actual_rating TEXT,
    last_actual_score REAL,
    passing INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(target, category)
);

CREATE INDEX IF NOT EXISTS idx_bench_category
    ON benchmarks(category);

CREATE TABLE IF NOT EXISTS pr_scan_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pr_id INTEGER NOT NULL
        REFERENCES pull_requests(id) ON DELETE CASCADE,
    scan_id INTEGER NOT NULL
        REFERENCES scans(id) ON DELETE CASCADE,
    scan_phase TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(pr_id, scan_id, scan_phase)
);

CREATE INDEX IF NOT EXISTS idx_psl_pr ON pr_scan_links(pr_id);

-- v5: Runtime guard telemetry
CREATE TABLE IF NOT EXISTS guard_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    session_id TEXT,
    agent_id TEXT,
    tool_name TEXT NOT NULL,
    call_index INTEGER NOT NULL DEFAULT 0,
    decision TEXT NOT NULL,
    reason TEXT,
    policy_matched TEXT,
    pii_types TEXT,
    dlp_action TEXT,
    policy_preset TEXT,
    framework TEXT,
    environment TEXT
);

CREATE INDEX IF NOT EXISTS idx_guard_tool
    ON guard_events(tool_name);
CREATE INDEX IF NOT EXISTS idx_guard_decision
    ON guard_events(decision);
CREATE INDEX IF NOT EXISTS idx_guard_session
    ON guard_events(session_id);
CREATE INDEX IF NOT EXISTS idx_guard_ts
    ON guard_events(timestamp);

-- v5: Aggregated guard session summaries
CREATE TABLE IF NOT EXISTS guard_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL UNIQUE,
    agent_id TEXT,
    policy_preset TEXT,
    started_at TEXT NOT NULL DEFAULT (datetime('now')),
    ended_at TEXT,
    total_calls INTEGER NOT NULL DEFAULT 0,
    allowed INTEGER NOT NULL DEFAULT 0,
    denied INTEGER NOT NULL DEFAULT 0,
    escalated INTEGER NOT NULL DEFAULT 0,
    pii_detections INTEGER NOT NULL DEFAULT 0,
    unique_tools INTEGER NOT NULL DEFAULT 0,
    top_denied_tool TEXT
);

CREATE INDEX IF NOT EXISTS idx_gsess_started
    ON guard_sessions(started_at);
"""


def _ensure_dir(db_path: Path) -> None:
    """Create parent directory if it doesn't exist."""
    db_path.parent.mkdir(parents=True, exist_ok=True)


def _has_column(conn: sqlite3.Connection, table: str, col: str) -> bool:
    """Check if a column exists in a table."""
    cols = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(c[1] == col for c in cols)


def _migrate_v3_to_v4(conn: sqlite3.Connection) -> None:
    """Migrate schema from v3 to v4: add data flywheel tables."""
    # Add new columns to existing tables (idempotent)
    alters = [
        ("scans", "scoring_version", "TEXT NOT NULL DEFAULT 'v1'"),
        ("scans", "scanner_version", "TEXT NOT NULL DEFAULT '0.2.0'"),
        ("scans", "pattern_set_hash", "TEXT"),
        ("scans", "scan_duration_ms", "INTEGER"),
        ("scans", "source_type", "TEXT NOT NULL DEFAULT 'local'"),
        ("security_issues", "pattern_name", "TEXT"),
        ("security_issues", "false_positive", "INTEGER"),
        ("security_issues", "reviewed_at", "TEXT"),
        ("agent_findings", "false_positive", "INTEGER"),
        ("agent_findings", "reviewed_at", "TEXT"),
    ]
    for table, col, col_type in alters:
        if not _has_column(conn, table, col):
            conn.execute(
                f"ALTER TABLE {table} ADD COLUMN {col} {col_type}"
            )

    # Backfill pattern_name from category
    conn.execute(
        "UPDATE security_issues "
        "SET pattern_name = category "
        "WHERE pattern_name IS NULL"
    )

    # Seed scoring versions registry
    conn.execute(
        "INSERT OR IGNORE INTO scoring_versions "
        "(version, formula, weights_json, "
        "grade_boundaries_json, scanner_version, notes) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            "v1",
            "sec*0.4 + desc*0.35 + arch*0.25",
            '{"security": 0.4, "description": 0.35, '
            '"architecture": 0.25}',
            '{"A": 8.0, "B": 6.0, "C": 4.0}',
            "0.1.0",
            "Original formula (F/C/B/A/A+)",
        ),
    )
    conn.execute(
        "INSERT OR IGNORE INTO scoring_versions "
        "(version, formula, weights_json, "
        "grade_boundaries_json, hard_constraints_json, "
        "scanner_version, notes) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            "v2",
            "desc*0.35 + sec_adj*0.35 + arch*0.30",
            '{"description": 0.35, "security_adjusted": 0.35, '
            '"architecture": 0.30}',
            '{"A": 8.5, "B": 7.0, "C": 5.0, "D": 3.0}',
            '["critical_vulnerability", "no_tools", '
            '"license_banned"]',
            "0.3.0",
            "SpiderRating unified (F/D/C/B/A)",
        ),
    )

    # Backfill server_timeline from existing scans
    rows = conn.execute(
        "SELECT id, target, scanned_at, scoring_version, "
        "overall_score, security_score, description_score, "
        "architecture_score, rating, tool_count "
        "FROM scans ORDER BY target, scanned_at"
    ).fetchall()

    prev_by_target: dict[str, tuple] = {}
    for row in rows:
        scan_id = row[0]
        target = row[1]
        issue_count = conn.execute(
            "SELECT COUNT(*) FROM security_issues "
            "WHERE scan_id = ?", (scan_id,)
        ).fetchone()[0]

        prev = prev_by_target.get(target)
        delta_o = round(row[4] - prev[4], 1) if prev else None
        delta_s = round(row[5] - prev[5], 1) if prev else None
        delta_d = round(row[6] - prev[6], 1) if prev else None
        prev_id = prev[0] if prev else None

        conn.execute(
            "INSERT OR IGNORE INTO server_timeline "
            "(target, scan_id, scanned_at, scoring_version, "
            "overall_score, security_score, description_score, "
            "architecture_score, rating, tool_count, "
            "issue_count, delta_overall, delta_security, "
            "delta_description, prev_scan_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                target, scan_id, row[2], row[3],
                row[4], row[5], row[6], row[7],
                row[8], row[9], issue_count,
                delta_o, delta_s, delta_d, prev_id,
            ),
        )
        prev_by_target[target] = row

    # Update schema version
    conn.execute("UPDATE schema_version SET version = 4")


def _migrate_v4_to_v5(conn: sqlite3.Connection) -> None:
    """Migrate schema from v4 to v5: add guard telemetry tables."""
    # Tables are created by _SCHEMA_SQL (CREATE IF NOT EXISTS),
    # so we just update the version marker.
    conn.execute("UPDATE schema_version SET version = 5")


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
        else:
            # Run migrations if needed
            ver = conn.execute(
                "SELECT version FROM schema_version"
            ).fetchone()[0]
            if ver < 4:
                _migrate_v3_to_v4(conn)
            if ver < 5:
                _migrate_v4_to_v5(conn)
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

        # Scoring version distribution
        scoring_vers = conn.execute(
            "SELECT scoring_version, COUNT(*) as cnt "
            "FROM scans GROUP BY scoring_version "
            "ORDER BY cnt DESC"
        ).fetchall()

        # FP review stats
        reviewed = conn.execute(
            "SELECT COUNT(*) FROM security_issues "
            "WHERE false_positive IS NOT NULL"
        ).fetchone()[0]
        fp_count = conn.execute(
            "SELECT COUNT(*) FROM security_issues "
            "WHERE false_positive = 1"
        ).fetchone()[0]

        # Benchmark stats
        bench_total = conn.execute(
            "SELECT COUNT(*) FROM benchmarks"
        ).fetchone()[0]
        bench_passing = conn.execute(
            "SELECT COUNT(*) FROM benchmarks "
            "WHERE passing = 1"
        ).fetchone()[0]

        # Timeline entries
        timeline_count = conn.execute(
            "SELECT COUNT(*) FROM server_timeline"
        ).fetchone()[0]

        # Calibration points
        cal_total = conn.execute(
            "SELECT COUNT(*) FROM scoring_calibration"
        ).fetchone()[0]
        cal_labeled = conn.execute(
            "SELECT COUNT(*) FROM scoring_calibration "
            "WHERE ground_truth_rating IS NOT NULL"
        ).fetchone()[0]

        # Guard telemetry stats
        guard_total = conn.execute(
            "SELECT COUNT(*) FROM guard_events"
        ).fetchone()[0]
        guard_denied = conn.execute(
            "SELECT COUNT(*) FROM guard_events "
            "WHERE decision = 'deny'"
        ).fetchone()[0]
        guard_sessions_total = conn.execute(
            "SELECT COUNT(*) FROM guard_sessions"
        ).fetchone()[0]

        return {
            "db_exists": True,
            "db_path": str(path),
            "db_size_kb": round(path.stat().st_size / 1024, 1),
            "schema_version": SCHEMA_VERSION,
            "total_scans": scans,
            "unique_targets": targets,
            "total_issues": issues,
            "total_descriptions": descriptions,
            "total_fixes": fixes,
            "total_prs": pr_total,
            "pr_tools_changed": pr_tools,
            "total_agent_scans": agent_scans_total,
            "total_agent_findings": agent_findings_total,
            "agent_finding_types": {
                r[0]: r[1] for r in agent_by_type
            },
            "top_issue_categories": [
                {"category": r[0], "count": r[1]}
                for r in top_cats
            ],
            "rating_distribution": {
                r[0]: r[1] for r in ratings
            },
            "pr_status_distribution": {
                r[0]: r[1] for r in pr_by_status
            },
            "scoring_version_distribution": {
                r[0]: r[1] for r in scoring_vers
            },
            "issues_reviewed": reviewed,
            "issues_false_positive": fp_count,
            "timeline_entries": timeline_count,
            "benchmarks_total": bench_total,
            "benchmarks_passing": bench_passing,
            "calibration_total": cal_total,
            "calibration_labeled": cal_labeled,
            "guard_events": guard_total,
            "guard_denied": guard_denied,
            "guard_sessions": guard_sessions_total,
        }
