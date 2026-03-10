"""Tests for the local security dataset module."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from spidershield.cli import main
from spidershield.dataset.collector import (
    get_prs,
    record_agent_scan,
    record_hardener_fix,
    record_pr,
    record_pr_tool_change,
    record_rewrite,
    record_scan,
)
from spidershield.dataset.db import get_connection, get_stats, init_db


class TestDatabase:
    def test_init_creates_db(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        result = init_db(db_path)
        assert result == db_path
        assert db_path.exists()

    def test_init_idempotent(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        init_db(db_path)
        init_db(db_path)  # Should not raise
        assert db_path.exists()

    def test_schema_version(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        init_db(db_path)
        with get_connection(db_path) as conn:
            ver = conn.execute(
                "SELECT version FROM schema_version"
            ).fetchone()[0]
            assert ver == 5

    def test_get_stats_no_db(self, tmp_path: Path) -> None:
        stats = get_stats(tmp_path / "nonexistent.db")
        assert stats["db_exists"] is False
        assert stats["total_scans"] == 0

    def test_get_stats_empty_db(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        init_db(db_path)
        stats = get_stats(db_path)
        assert stats["db_exists"] is True
        assert stats["total_scans"] == 0
        assert stats["total_issues"] == 0


class TestCollector:
    def _make_report(self):
        """Create a minimal ScanReport for testing."""
        from spidershield.models import Rating, ScanReport, SecurityIssue

        return ScanReport(
            target="/tmp/test-server",
            tool_count=3,
            security_score=7.5,
            description_score=6.0,
            architecture_score=5.0,
            overall_score=6.3,
            rating=Rating.B,
            license="MIT",
            license_ok=True,
            has_tests=True,
            has_error_handling=False,
            security_issues=[
                SecurityIssue(
                    severity="high",
                    category="sql_injection",
                    file="server.py",
                    line=42,
                    description="f-string in SQL execute",
                    fix_suggestion="Use parameterized queries",
                ),
            ],
        )

    def test_record_scan(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        report = self._make_report()
        scan_id = record_scan(report, db_path=db_path)
        assert scan_id is not None
        assert scan_id > 0

        stats = get_stats(db_path)
        assert stats["total_scans"] == 1
        assert stats["total_issues"] == 1

    def test_record_scan_preserves_data(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        report = self._make_report()
        scan_id = record_scan(report, db_path=db_path)

        with get_connection(db_path) as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
            assert row["target"] == "/tmp/test-server"
            assert row["security_score"] == 7.5
            assert row["rating"] == "B"

            issues = conn.execute(
                "SELECT * FROM security_issues WHERE scan_id = ?",
                (scan_id,),
            ).fetchall()
            assert len(issues) == 1
            assert issues[0]["category"] == "sql_injection"

    def test_record_rewrite(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        rid = record_rewrite(
            target="/tmp/test",
            tool_name="read_file",
            original="Read a file",
            rewritten="Read the contents of a file at the specified path.",
            original_score=3.0,
            rewritten_score=8.5,
            engine="template",
            passed=True,
            db_path=db_path,
        )
        assert rid is not None

        stats = get_stats(db_path)
        assert stats["total_descriptions"] == 1

    def test_record_hardener_fix(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        fid = record_hardener_fix(
            target="/tmp/test",
            category="sql_injection",
            file="server.py",
            suggestion="Use parameterized queries",
            code_fix="cursor.execute('SELECT ?', (val,))",
            confidence=0.85,
            engine="llm",
            db_path=db_path,
        )
        assert fid is not None

        stats = get_stats(db_path)
        assert stats["total_fixes"] == 1

    def test_record_scan_never_raises(self, tmp_path: Path) -> None:
        """Collector should silently handle errors."""
        # Pass a garbage object -- should return None, not raise
        result = record_scan("not a report", db_path=tmp_path / "test.db")
        assert result is None

    def test_multiple_scans_accumulate(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        report = self._make_report()
        record_scan(report, db_path=db_path)
        record_scan(report, db_path=db_path)
        record_scan(report, db_path=db_path)

        stats = get_stats(db_path)
        assert stats["total_scans"] == 3
        assert stats["total_issues"] == 3
        assert stats["unique_targets"] == 1


class TestDatasetCLI:
    def test_dataset_stats_empty(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(
            "spidershield.dataset.db.DEFAULT_DB_PATH",
            tmp_path / "nonexistent.db",
        )
        runner = CliRunner()
        result = runner.invoke(main, ["dataset", "stats"])
        assert result.exit_code == 0
        assert "No dataset" in result.output

    def test_dataset_stats_with_data(self, tmp_path: Path, monkeypatch) -> None:
        db_path = tmp_path / "test.db"
        monkeypatch.setattr(
            "spidershield.dataset.db.DEFAULT_DB_PATH", db_path,
        )
        # Seed some data
        from spidershield.models import Rating, ScanReport

        report = ScanReport(
            target="/tmp/test",
            tool_count=2,
            security_score=8.0,
            description_score=7.0,
            architecture_score=6.0,
            overall_score=7.2,
            rating=Rating.B,
        )
        record_scan(report, db_path=db_path)

        runner = CliRunner()
        result = runner.invoke(main, ["dataset", "stats"])
        assert result.exit_code == 0
        assert "Scans: 1" in result.output

    def test_dataset_export_json(self, tmp_path: Path, monkeypatch) -> None:
        db_path = tmp_path / "test.db"
        monkeypatch.setattr(
            "spidershield.dataset.db.DEFAULT_DB_PATH", db_path,
        )
        from spidershield.models import Rating, ScanReport

        report = ScanReport(
            target="/tmp/test",
            tool_count=1,
            security_score=9.0,
            description_score=8.0,
            architecture_score=7.0,
            overall_score=8.2,
            rating=Rating.A,
        )
        record_scan(report, db_path=db_path)

        out = tmp_path / "export.json"
        runner = CliRunner()
        result = runner.invoke(main, ["dataset", "export", str(out)])
        assert result.exit_code == 0
        assert out.exists()

        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["version"] == 3
        assert len(data["scans"]) == 1
        assert "pull_requests" in data
        assert "agent_scans" in data
        assert "agent_findings" in data

    def test_dataset_export_no_data(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(
            "spidershield.dataset.db.DEFAULT_DB_PATH",
            tmp_path / "nonexistent.db",
        )
        runner = CliRunner()
        result = runner.invoke(
            main, ["dataset", "export", str(tmp_path / "out.json")],
        )
        assert result.exit_code != 0

    def test_dataset_reset(self, tmp_path: Path, monkeypatch) -> None:
        db_path = tmp_path / "test.db"
        init_db(db_path)
        assert db_path.exists()

        monkeypatch.setattr(
            "spidershield.dataset.db.DEFAULT_DB_PATH", db_path,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["dataset", "reset"], input="y\n")
        assert result.exit_code == 0
        assert not db_path.exists()


class TestPRTracking:
    def test_record_pr(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        pr_id = record_pr(
            repo="org/repo",
            pr_number=42,
            title="Improve tool descriptions",
            status="open",
            strategy="hand-crafted",
            tools_changed=5,
            db_path=db_path,
        )
        assert pr_id is not None

    def test_record_pr_upsert(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        record_pr(
            repo="org/repo", pr_number=1, title="v1",
            status="open", db_path=db_path,
        )
        record_pr(
            repo="org/repo", pr_number=1, title="v2",
            status="merged", db_path=db_path,
        )
        prs = get_prs(db_path=db_path)
        assert len(prs) == 1
        assert prs[0]["status"] == "merged"
        assert prs[0]["title"] == "v2"

    def test_get_prs_filter(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        record_pr(
            repo="a/b", pr_number=1, title="Open PR",
            status="open", db_path=db_path,
        )
        record_pr(
            repo="c/d", pr_number=2, title="Merged PR",
            status="merged", db_path=db_path,
        )
        open_prs = get_prs(status="open", db_path=db_path)
        assert len(open_prs) == 1
        assert open_prs[0]["repo"] == "a/b"

    def test_record_pr_tool_change(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        pr_id = record_pr(
            repo="org/repo", pr_number=10, title="Test",
            status="open", tools_changed=1, db_path=db_path,
        )
        tc_id = record_pr_tool_change(
            pr_id=pr_id,
            tool_name="read_file",
            original_description="Read a file",
            proposed_description="Read the contents of a specific file.",
            accepted=True,
            db_path=db_path,
        )
        assert tc_id is not None

    def test_pr_stats_in_get_stats(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        record_pr(
            repo="org/repo", pr_number=1, title="PR 1",
            status="open", tools_changed=3, db_path=db_path,
        )
        record_pr(
            repo="org/repo", pr_number=2, title="PR 2",
            status="merged", tools_changed=5, db_path=db_path,
        )
        stats = get_stats(db_path)
        assert stats["total_prs"] == 2
        assert stats["pr_tools_changed"] == 8
        assert stats["pr_status_distribution"]["open"] == 1
        assert stats["pr_status_distribution"]["merged"] == 1

    def test_pr_add_cli(self, tmp_path: Path, monkeypatch) -> None:
        db_path = tmp_path / "test.db"
        monkeypatch.setattr(
            "spidershield.dataset.db.DEFAULT_DB_PATH", db_path,
        )
        runner = CliRunner()
        result = runner.invoke(main, [
            "dataset", "pr-add", "org/repo", "99",
            "-t", "Test PR", "-s", "open", "--tools", "3",
        ])
        assert result.exit_code == 0
        assert "Recorded" in result.output

    def test_pr_list_cli(self, tmp_path: Path, monkeypatch) -> None:
        db_path = tmp_path / "test.db"
        monkeypatch.setattr(
            "spidershield.dataset.db.DEFAULT_DB_PATH", db_path,
        )
        record_pr(
            repo="org/repo", pr_number=1, title="Test",
            status="open", db_path=db_path,
        )
        runner = CliRunner()
        result = runner.invoke(main, ["dataset", "pr-list"])
        assert result.exit_code == 0
        assert "Tracked Pull Requests" in result.output


class TestSchemaV4:
    """Tests for schema v4 data flywheel features."""

    def _make_report(self, target="/tmp/test-server", overall=6.3):
        from spidershield.models import Rating, ScanReport, SecurityIssue

        rating = (
            Rating.A if overall >= 8.5
            else Rating.B if overall >= 7.0
            else Rating.C if overall >= 5.0
            else Rating.D if overall >= 3.0
            else Rating.F
        )
        return ScanReport(
            target=target,
            tool_count=3,
            security_score=7.5,
            description_score=6.0,
            architecture_score=5.0,
            overall_score=overall,
            rating=rating,
            license="MIT",
            license_ok=True,
            has_tests=True,
            has_error_handling=False,
            security_issues=[
                SecurityIssue(
                    severity="high",
                    category="sql_injection",
                    file="server.py",
                    line=42,
                    description="f-string in SQL",
                    fix_suggestion="Use params",
                ),
            ],
        )

    def test_record_scan_with_scoring_version(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        report = self._make_report()
        scan_id = record_scan(
            report, db_path=db_path,
            scoring_version="v2",
            scanner_version="0.3.0",
            pattern_set_hash="abc123",
            scan_duration_ms=150,
            source_type="ci",
        )
        with get_connection(db_path) as conn:
            row = conn.execute(
                "SELECT scoring_version, scanner_version, "
                "pattern_set_hash, scan_duration_ms, source_type "
                "FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
            assert row["scoring_version"] == "v2"
            assert row["scanner_version"] == "0.3.0"
            assert row["pattern_set_hash"] == "abc123"
            assert row["scan_duration_ms"] == 150
            assert row["source_type"] == "ci"

    def test_security_issue_pattern_name(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        report = self._make_report()
        scan_id = record_scan(report, db_path=db_path)
        with get_connection(db_path) as conn:
            row = conn.execute(
                "SELECT pattern_name FROM security_issues "
                "WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            assert row["pattern_name"] == "sql_injection"

    def test_server_timeline_auto_insert(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        report = self._make_report()
        scan_id = record_scan(report, db_path=db_path, scoring_version="v2")
        with get_connection(db_path) as conn:
            row = conn.execute(
                "SELECT * FROM server_timeline WHERE scan_id = ?",
                (scan_id,)
            ).fetchone()
            assert row is not None
            assert row["target"] == "/tmp/test-server"
            assert row["overall_score"] == 6.3
            assert row["scoring_version"] == "v2"
            # First scan: no deltas
            assert row["delta_overall"] is None
            assert row["prev_scan_id"] is None

    def test_server_timeline_delta(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        r1 = self._make_report(overall=5.0)
        id1 = record_scan(r1, db_path=db_path)
        r2 = self._make_report(overall=7.0)
        id2 = record_scan(r2, db_path=db_path)
        with get_connection(db_path) as conn:
            row = conn.execute(
                "SELECT delta_overall, prev_scan_id "
                "FROM server_timeline WHERE scan_id = ?", (id2,)
            ).fetchone()
            assert row["delta_overall"] == 2.0
            assert row["prev_scan_id"] == id1

    def test_scoring_calibration_auto_insert(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        report = self._make_report(overall=8.0)
        scan_id = record_scan(report, db_path=db_path, scoring_version="v2")
        with get_connection(db_path) as conn:
            row = conn.execute(
                "SELECT * FROM scoring_calibration WHERE scan_id = ?",
                (scan_id,)
            ).fetchone()
            assert row is not None
            assert row["predicted_overall"] == 8.0
            assert row["predicted_rating"] == "B"
            assert row["scoring_version"] == "v2"

    def test_v4_tables_exist(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        init_db(db_path)
        with get_connection(db_path) as conn:
            tables = {
                row[0] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            for expected in [
                "scoring_versions", "server_timeline",
                "pattern_effectiveness", "scoring_calibration",
                "benchmarks", "pr_scan_links",
            ]:
                assert expected in tables, f"Missing table: {expected}"

    def test_flywheel_stats(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        report = self._make_report()
        record_scan(report, db_path=db_path, scoring_version="v2")
        stats = get_stats(db_path)
        assert "timeline_entries" in stats
        assert stats["timeline_entries"] == 1
        assert "calibration_total" in stats
        assert stats["calibration_total"] == 1


class TestBenchmarkCLI:
    def test_benchmark_add(self, tmp_path: Path, monkeypatch) -> None:
        db_path = tmp_path / "test.db"
        monkeypatch.setattr("spidershield.dataset.db.DEFAULT_DB_PATH", db_path)
        runner = CliRunner()
        result = runner.invoke(main, [
            "dataset", "benchmark-add", "/tmp/good-server",
            "-r", "A", "-s", "8.5", "-c", "known-good",
        ])
        assert result.exit_code == 0
        assert "Benchmark added" in result.output

    def test_benchmark_list_empty(self, tmp_path: Path, monkeypatch) -> None:
        db_path = tmp_path / "test.db"
        monkeypatch.setattr("spidershield.dataset.db.DEFAULT_DB_PATH", db_path)
        runner = CliRunner()
        result = runner.invoke(main, ["dataset", "benchmark-list"])
        assert result.exit_code == 0
        assert "No benchmarks" in result.output

    def test_benchmark_list_with_data(self, tmp_path: Path, monkeypatch) -> None:
        db_path = tmp_path / "test.db"
        monkeypatch.setattr("spidershield.dataset.db.DEFAULT_DB_PATH", db_path)
        runner = CliRunner()
        runner.invoke(main, [
            "dataset", "benchmark-add", "/tmp/server1",
            "-r", "B", "-c", "test",
        ])
        result = runner.invoke(main, ["dataset", "benchmark-list"])
        assert result.exit_code == 0
        assert "Benchmark Servers" in result.output

    def test_calibrate_no_scan(self, tmp_path: Path, monkeypatch) -> None:
        db_path = tmp_path / "test.db"
        monkeypatch.setattr("spidershield.dataset.db.DEFAULT_DB_PATH", db_path)
        init_db(db_path)
        runner = CliRunner()
        result = runner.invoke(main, [
            "dataset", "calibrate", "999", "-r", "A",
        ])
        assert result.exit_code == 0
        assert "No calibration entry" in result.output

    def test_calibrate_with_scan(self, tmp_path: Path, monkeypatch) -> None:
        db_path = tmp_path / "test.db"
        monkeypatch.setattr("spidershield.dataset.db.DEFAULT_DB_PATH", db_path)
        from spidershield.models import Rating, ScanReport
        report = ScanReport(
            target="/tmp/test",
            tool_count=2, security_score=8.0,
            description_score=7.0, architecture_score=6.0,
            overall_score=7.2, rating=Rating.B,
        )
        scan_id = record_scan(report, db_path=db_path)
        runner = CliRunner()
        result = runner.invoke(main, [
            "dataset", "calibrate", str(scan_id), "-r", "B",
        ])
        assert result.exit_code == 0
        assert "Labeled scan" in result.output

    def test_calibrate_report_empty(self, tmp_path: Path, monkeypatch) -> None:
        db_path = tmp_path / "test.db"
        monkeypatch.setattr("spidershield.dataset.db.DEFAULT_DB_PATH", db_path)
        init_db(db_path)
        runner = CliRunner()
        result = runner.invoke(main, ["dataset", "calibrate-report"])
        assert result.exit_code == 0
        assert "No labeled calibration" in result.output


class TestGuardDataset:
    """Tests for runtime guard telemetry in dataset."""

    def test_record_guard_event(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        from spidershield.dataset.collector import record_guard_event
        eid = record_guard_event(
            tool_name="read_file",
            decision="deny",
            session_id="sess-1",
            agent_id="claude",
            call_index=0,
            reason="SSH key access blocked",
            policy_matched="block-ssh-keys",
            policy_preset="strict",
            db_path=db_path,
        )
        assert eid is not None
        with get_connection(db_path) as conn:
            row = conn.execute(
                "SELECT * FROM guard_events WHERE id = ?", (eid,)
            ).fetchone()
            assert row["tool_name"] == "read_file"
            assert row["decision"] == "deny"
            assert row["policy_matched"] == "block-ssh-keys"

    def test_guard_session_upsert(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        from spidershield.dataset.collector import record_guard_event
        record_guard_event(
            tool_name="read_file", decision="allow",
            session_id="sess-2", db_path=db_path,
        )
        record_guard_event(
            tool_name="write_file", decision="deny",
            session_id="sess-2", db_path=db_path,
        )
        record_guard_event(
            tool_name="exec_cmd", decision="deny",
            session_id="sess-2", db_path=db_path,
        )
        with get_connection(db_path) as conn:
            row = conn.execute(
                "SELECT * FROM guard_sessions "
                "WHERE session_id = 'sess-2'"
            ).fetchone()
            assert row["total_calls"] == 3
            assert row["allowed"] == 1
            assert row["denied"] == 2

    def test_guard_event_with_pii(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        from spidershield.dataset.collector import record_guard_event
        eid = record_guard_event(
            tool_name="search",
            decision="dlp",
            pii_types=["email", "ssn"],
            session_id="sess-3",
            db_path=db_path,
        )
        with get_connection(db_path) as conn:
            row = conn.execute(
                "SELECT pii_types FROM guard_events WHERE id = ?",
                (eid,)
            ).fetchone()
            assert row["pii_types"] == "email,ssn"

    def test_guard_stats(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        from spidershield.dataset.collector import record_guard_event
        record_guard_event(
            tool_name="t1", decision="allow",
            session_id="s1", db_path=db_path,
        )
        record_guard_event(
            tool_name="t2", decision="deny",
            session_id="s1", db_path=db_path,
        )
        stats = get_stats(db_path)
        assert stats["guard_events"] == 2
        assert stats["guard_denied"] == 1
        assert stats["guard_sessions"] == 1

    def test_spiderguard_dataset_integration(self, tmp_path: Path, monkeypatch) -> None:
        """SpiderGuard with dataset=True writes to SQLite."""
        db_path = tmp_path / "test.db"
        monkeypatch.setattr("spidershield.dataset.db.DEFAULT_DB_PATH", db_path)
        from spidershield import SpiderGuard
        guard = SpiderGuard(policy="balanced", dataset=True)
        guard.check("read_file", {"path": "/etc/passwd"}, session_id="s1")
        guard.check("list_files", {"dir": "/tmp"}, session_id="s1")

        stats = get_stats(db_path)
        assert stats["guard_events"] >= 2

    def test_guard_never_raises(self, tmp_path: Path) -> None:
        """Record failure should not crash the guard."""
        from spidershield.dataset.collector import record_guard_event
        # Bad db_path should be silently handled
        result = record_guard_event(
            tool_name="test",
            decision="allow",
            db_path=tmp_path / "nonexistent_dir" / "sub" / "test.db",
        )
        # Should return None or an id, but never raise
        assert result is None or isinstance(result, int)


class TestAgentCheckDataset:
    def _make_scan_result(self):
        """Create a minimal ScanResult for testing."""
        from spidershield.agent.models import (
            AuditFramework,
            Finding,
            ScanResult,
            Severity,
            SkillFinding,
            SkillVerdict,
        )

        return ScanResult(
            config_path="/tmp/test-agent",
            version="1.0",
            findings=[
                Finding(
                    check_id="gateway.no_auth",
                    title="No authentication",
                    severity=Severity.CRITICAL,
                    description="[TS-C002] No auth configured",
                    fix_hint="Set a token",
                    auto_fixable=True,
                ),
                Finding(
                    check_id="sandbox.disabled",
                    title="Sandbox disabled",
                    severity=Severity.HIGH,
                    description="[TS-C005] Sandbox is off",
                    fix_hint="Enable sandbox",
                    auto_fixable=True,
                ),
            ],
            skill_findings=[
                SkillFinding(
                    skill_name="safe-skill",
                    skill_path="/skills/safe-skill",
                    verdict=SkillVerdict.SAFE,
                    issues=[],
                    matched_patterns=[],
                ),
                SkillFinding(
                    skill_name="evil-skill",
                    skill_path="/skills/evil-skill",
                    verdict=SkillVerdict.MALICIOUS,
                    issues=["[TS-E001] Base64 pipe to bash"],
                    matched_patterns=["base64_pipe_bash"],
                ),
                SkillFinding(
                    skill_name="sus-skill",
                    skill_path="/skills/sus-skill",
                    verdict=SkillVerdict.SUSPICIOUS,
                    issues=["[TS-W003] External binary download"],
                    matched_patterns=["external_binary"],
                ),
            ],
            audit_framework=AuditFramework(
                source_checked=True,
                code_checked=True,
                permission_checked=True,
                risk_checked=True,
            ),
        )

    def test_record_agent_scan(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        result = self._make_scan_result()
        scan_id = record_agent_scan(result, policy="strict", db_path=db_path)
        assert scan_id is not None
        assert scan_id > 0

    def test_record_agent_scan_data(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        result = self._make_scan_result()
        scan_id = record_agent_scan(result, policy="balanced", db_path=db_path)

        with get_connection(db_path) as conn:
            row = conn.execute(
                "SELECT * FROM agent_scans WHERE id = ?", (scan_id,)
            ).fetchone()
            assert row["target"] == "/tmp/test-agent"
            assert row["config_findings"] == 2
            assert row["critical_count"] == 1
            assert row["high_count"] == 1
            assert row["skill_count"] == 3
            assert row["malicious_skills"] == 1
            assert row["suspicious_skills"] == 1
            assert row["safe_skills"] == 1
            assert row["audit_coverage_pct"] == 100.0
            assert row["policy"] == "balanced"

    def test_record_agent_findings(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        result = self._make_scan_result()
        scan_id = record_agent_scan(result, db_path=db_path)

        with get_connection(db_path) as conn:
            findings = conn.execute(
                "SELECT * FROM agent_findings WHERE agent_scan_id = ?",
                (scan_id,),
            ).fetchall()
            # 2 config + 3 skill = 5 findings
            assert len(findings) == 5

            config_findings = [f for f in findings if f["finding_type"] == "config"]
            assert len(config_findings) == 2
            assert any(f["check_id"] == "gateway.no_auth" for f in config_findings)

            skill_findings = [f for f in findings if f["finding_type"] == "skill"]
            assert len(skill_findings) == 3
            mal = [f for f in skill_findings if f["verdict"] == "malicious"]
            assert len(mal) == 1
            assert mal[0]["skill_name"] == "evil-skill"
            assert "base64_pipe_bash" in mal[0]["matched_patterns"]

    def test_agent_stats(self, tmp_path: Path) -> None:
        db_path = tmp_path / "test.db"
        result = self._make_scan_result()
        record_agent_scan(result, db_path=db_path)

        stats = get_stats(db_path)
        assert stats["total_agent_scans"] == 1
        assert stats["total_agent_findings"] == 5
        assert "config" in stats["agent_finding_types"]
        assert "skill" in stats["agent_finding_types"]

    def test_record_agent_scan_never_raises(self, tmp_path: Path) -> None:
        """Collector should silently handle errors."""
        result = record_agent_scan("not a result", db_path=tmp_path / "test.db")
        assert result is None
