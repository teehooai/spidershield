"""Tests for allowlist mode and audit framework (M0.6a/b)."""

from __future__ import annotations

import json

import pytest

from spidershield.agent.allowlist import check_allowlist, load_allowlist
from spidershield.agent.models import AuditFramework, SkillVerdict


class TestLoadAllowlist:
    def test_load_valid(self, tmp_path) -> None:
        path = tmp_path / "approved.json"
        path.write_text(json.dumps({
            "skills": {
                "my-skill": {"approved_by": "admin"},
                "other-skill": {"approved_by": "admin", "approved_at": "2026-03-08"},
            }
        }))
        result = load_allowlist(path)
        assert "my-skill" in result
        assert "other-skill" in result

    def test_load_empty(self, tmp_path) -> None:
        path = tmp_path / "empty.json"
        path.write_text(json.dumps({"skills": {}}))
        result = load_allowlist(path)
        assert result == {}

    def test_load_missing_skills_key(self, tmp_path) -> None:
        path = tmp_path / "bad.json"
        path.write_text(json.dumps({"version": 1}))
        result = load_allowlist(path)
        assert result == {}

    def test_load_nonexistent_raises(self, tmp_path) -> None:
        with pytest.raises(FileNotFoundError):
            load_allowlist(tmp_path / "nope.json")


class TestCheckAllowlist:
    def test_all_approved(self) -> None:
        allowlist = {"a": {}, "b": {}}
        findings = check_allowlist(["a", "b"], allowlist)
        assert len(findings) == 0

    def test_one_not_approved(self) -> None:
        allowlist = {"a": {}}
        findings = check_allowlist(["a", "b"], allowlist)
        assert len(findings) == 1
        assert findings[0].skill_name == "b"
        assert findings[0].verdict == SkillVerdict.SUSPICIOUS
        assert "not_in_allowlist" in findings[0].matched_patterns

    def test_none_approved(self) -> None:
        allowlist = {}
        findings = check_allowlist(["x", "y"], allowlist)
        assert len(findings) == 2

    def test_empty_install(self) -> None:
        findings = check_allowlist([], {"a": {}})
        assert len(findings) == 0

    def test_issue_code_in_message(self) -> None:
        findings = check_allowlist(["unknown"], {})
        assert "[TS-W011]" in findings[0].issues[0]


class TestAuditFramework:
    def test_defaults(self) -> None:
        af = AuditFramework()
        assert af.coverage == 0
        assert af.coverage_pct == 0

    def test_full_coverage(self) -> None:
        af = AuditFramework(
            source_checked=True,
            code_checked=True,
            permission_checked=True,
            risk_checked=True,
        )
        assert af.coverage == 4
        assert af.coverage_pct == 100

    def test_partial_coverage(self) -> None:
        af = AuditFramework(
            source_checked=False,
            code_checked=True,
            permission_checked=True,
            risk_checked=True,
        )
        assert af.coverage == 3
        assert af.coverage_pct == 75

    def test_scan_result_has_audit_framework(self) -> None:
        from spidershield.agent.models import ScanResult
        result = ScanResult(config_path="test")
        assert result.audit_framework.coverage == 0

    def test_issue_code_exists(self) -> None:
        from spidershield.agent.issue_codes import get_issue_code
        assert get_issue_code("not_in_allowlist") == "TS-W011"
