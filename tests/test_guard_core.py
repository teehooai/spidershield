"""Tests for the RuntimeGuard core module."""

from textwrap import dedent

import pytest

from spidershield.guard import (
    CallContext,
    Decision,
    InterceptResult,
    PolicyEngine,
    PolicyRule,
    RuntimeGuard,
)


def _make_ctx(
    tool_name: str = "read_file",
    arguments: dict | None = None,
    token_spent: int = 0,
    call_chain: list | None = None,
) -> CallContext:
    return CallContext(
        session_id="test-session",
        agent_id="test-agent",
        tool_name=tool_name,
        arguments=arguments or {},
        call_chain=call_chain or [],
        token_spent=token_spent,
    )


# ---------------------------------------------------------------------------
# RuntimeGuard tests
# ---------------------------------------------------------------------------


class TestRuntimeGuard:
    def test_default_passthrough(self):
        guard = RuntimeGuard()
        ctx = _make_ctx()
        result = guard.before_call(ctx)
        assert result.decision == Decision.ALLOW

    def test_deny_with_policy(self):
        rule = PolicyRule(
            name="block-env",
            action=Decision.DENY,
            reason="sensitive file blocked",
            suggestion="Use files in /workspace/ instead",
            tool_match="read_file",
            args_patterns={"path": r"\.(env|key|pem)"},
        )
        engine = PolicyEngine([rule])
        guard = RuntimeGuard(policy_engine=engine)

        ctx = _make_ctx(arguments={"path": "/app/.env"})
        result = guard.before_call(ctx)
        assert result.decision == Decision.DENY
        assert result.reason == "sensitive file blocked"
        assert result.suggestion == "Use files in /workspace/ instead"
        assert result.policy_matched == "block-env"

    def test_allow_normal_file(self):
        rule = PolicyRule(
            name="block-env",
            action=Decision.DENY,
            reason="blocked",
            tool_match="read_file",
            args_patterns={"path": r"\.(env|key|pem)"},
        )
        engine = PolicyEngine([rule])
        guard = RuntimeGuard(policy_engine=engine)

        ctx = _make_ctx(arguments={"path": "/app/main.py"})
        result = guard.before_call(ctx)
        assert result.decision == Decision.ALLOW

    def test_escalate_decision(self):
        rule = PolicyRule(
            name="review-email",
            action=Decision.ESCALATE,
            reason="external email needs review",
            suggestion="Confirm recipient is intended",
            tool_match="send_email",
        )
        engine = PolicyEngine([rule])
        guard = RuntimeGuard(policy_engine=engine)

        ctx = _make_ctx(tool_name="send_email", arguments={"to": "ext@evil.com"})
        result = guard.before_call(ctx)
        assert result.decision == Decision.ESCALATE

    def test_audit_log_recorded(self):
        guard = RuntimeGuard()
        ctx = _make_ctx()
        guard.before_call(ctx)
        assert len(guard._audit_log) == 1
        assert guard._audit_log[0]["tool_name"] == "read_file"
        assert guard._audit_log[0]["phase"] == "before_call"

    def test_after_call_recorded(self):
        guard = RuntimeGuard()
        ctx = _make_ctx()
        guard.after_call(ctx, tool_result={"ok": True})
        assert len(guard._audit_log) == 1
        assert guard._audit_log[0]["phase"] == "after_call"

    def test_first_match_wins(self):
        rules = [
            PolicyRule(
                name="allow-src",
                action=Decision.ALLOW,
                reason="src is safe",
                tool_match="read_file",
                args_patterns={"path": r"^/app/src/"},
            ),
            PolicyRule(
                name="deny-all-reads",
                action=Decision.DENY,
                reason="block all reads",
                tool_match="read_file",
            ),
        ]
        engine = PolicyEngine(rules)
        guard = RuntimeGuard(policy_engine=engine)

        # /app/src/ → first rule → ALLOW
        ctx = _make_ctx(arguments={"path": "/app/src/main.py"})
        result = guard.before_call(ctx)
        assert result.decision == Decision.ALLOW
        assert result.policy_matched == "allow-src"

    def test_multiple_audit_entries(self):
        guard = RuntimeGuard()
        ctx1 = _make_ctx(tool_name="read_file")
        ctx2 = _make_ctx(tool_name="write_file")
        guard.before_call(ctx1)
        guard.before_call(ctx2)
        assert len(guard._audit_log) == 2
        assert guard._audit_log[0]["tool_name"] == "read_file"
        assert guard._audit_log[1]["tool_name"] == "write_file"


# ---------------------------------------------------------------------------
# PolicyRule.matches() tests
# ---------------------------------------------------------------------------


class TestPolicyRuleMatching:
    def test_any_tool_matches_everything(self):
        rule = PolicyRule(name="r", action=Decision.DENY, reason="r", any_tool=True)
        assert rule.matches(_make_ctx(tool_name="anything"))
        assert rule.matches(_make_ctx(tool_name="another_tool"))

    def test_tool_match_regex(self):
        rule = PolicyRule(name="r", action=Decision.DENY, reason="r", tool_match=r"^read_")
        assert rule.matches(_make_ctx(tool_name="read_file"))
        assert not rule.matches(_make_ctx(tool_name="write_file"))

    def test_no_tool_match_no_any_tool_never_matches(self):
        rule = PolicyRule(name="r", action=Decision.DENY, reason="r")
        assert not rule.matches(_make_ctx())

    def test_args_pattern_match(self):
        rule = PolicyRule(
            name="r", action=Decision.DENY, reason="r",
            tool_match="run", args_patterns={"cmd": r"rm\s+-rf"},
        )
        assert rule.matches(_make_ctx(tool_name="run", arguments={"cmd": "rm -rf /"}))
        assert not rule.matches(_make_ctx(tool_name="run", arguments={"cmd": "ls -la"}))

    def test_args_pattern_missing_arg_no_match(self):
        rule = PolicyRule(
            name="r", action=Decision.DENY, reason="r",
            tool_match="run", args_patterns={"cmd": r"rm"},
        )
        assert not rule.matches(_make_ctx(tool_name="run", arguments={}))

    def test_multiple_args_patterns_all_must_match(self):
        rule = PolicyRule(
            name="r", action=Decision.DENY, reason="r",
            tool_match="send",
            args_patterns={"to": r"@evil\.com", "subject": r"urgent"},
        )
        assert rule.matches(_make_ctx(
            tool_name="send",
            arguments={"to": "user@evil.com", "subject": "urgent request"},
        ))
        # Only one matches
        assert not rule.matches(_make_ctx(
            tool_name="send",
            arguments={"to": "user@evil.com", "subject": "normal"},
        ))

    def test_token_threshold_exceeded(self):
        rule = PolicyRule(
            name="cost", action=Decision.DENY, reason="over budget",
            any_tool=True, max_token_spent=50000,
        )
        assert rule.matches(_make_ctx(token_spent=60000))
        assert not rule.matches(_make_ctx(token_spent=30000))
        # Boundary: exactly at limit should not match (need to exceed)
        assert not rule.matches(_make_ctx(token_spent=50000))

    def test_chain_depth_exceeded(self):
        rule = PolicyRule(
            name="depth", action=Decision.DENY, reason="too deep",
            any_tool=True, max_chain_depth=3,
        )
        assert rule.matches(_make_ctx(call_chain=["a", "b", "c", "d"]))
        assert not rule.matches(_make_ctx(call_chain=["a", "b"]))
        assert not rule.matches(_make_ctx(call_chain=["a", "b", "c"]))

    def test_combined_tool_and_token(self):
        rule = PolicyRule(
            name="r", action=Decision.DENY, reason="r",
            tool_match="expensive_tool", max_token_spent=10000,
        )
        # Right tool, over budget
        assert rule.matches(_make_ctx(tool_name="expensive_tool", token_spent=20000))
        # Right tool, under budget
        assert not rule.matches(_make_ctx(tool_name="expensive_tool", token_spent=5000))
        # Wrong tool, over budget
        assert not rule.matches(_make_ctx(tool_name="cheap_tool", token_spent=20000))


# ---------------------------------------------------------------------------
# PolicyEngine tests
# ---------------------------------------------------------------------------


class TestPolicyEngine:
    def test_empty_engine_allows(self):
        engine = PolicyEngine()
        ctx = _make_ctx()
        decision, reason, policy_name, suggestion = engine.evaluate(ctx)
        assert decision == Decision.ALLOW
        assert policy_name is None

    def test_add_rule(self):
        engine = PolicyEngine()
        engine.add_rule(PolicyRule(
            name="deny-all", action=Decision.DENY, reason="nope", any_tool=True,
        ))
        assert len(engine.rules) == 1
        decision, _, name, _ = engine.evaluate(_make_ctx())
        assert decision == Decision.DENY
        assert name == "deny-all"

    def test_from_yaml(self):
        data = {
            "policies": [
                {
                    "name": "block-env",
                    "match": {"tool": "read_file", "args_pattern": {"path": r"\.env$"}},
                    "action": "deny",
                    "reason": "env files blocked",
                    "suggestion": "use config service",
                },
                {
                    "name": "cost-limit",
                    "match": {"any_tool": True},
                    "condition": {"token_spent_gt": 100000},
                    "action": "deny",
                    "reason": "budget exceeded",
                },
            ]
        }
        engine = PolicyEngine.from_yaml(data)
        assert len(engine.rules) == 2
        assert engine.rules[0].name == "block-env"
        assert engine.rules[0].args_patterns == {"path": r"\.env$"}
        assert engine.rules[1].max_token_spent == 100000

        # Verify the env rule triggers
        ctx = _make_ctx(arguments={"path": "/app/.env"})
        decision, reason, name, suggestion = engine.evaluate(ctx)
        assert decision == Decision.DENY
        assert name == "block-env"
        assert suggestion == "use config service"

    def test_from_yaml_file(self, tmp_path):
        yaml_content = dedent("""\
            policies:
              - name: test-rule
                match:
                  tool: write_file
                action: escalate
                reason: writes need review
        """)
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(yaml_content)

        engine = PolicyEngine.from_yaml_file(policy_file)
        assert len(engine.rules) == 1

        ctx = _make_ctx(tool_name="write_file")
        decision, _, _, _ = engine.evaluate(ctx)
        assert decision == Decision.ESCALATE

    def test_from_name_or_path_preset(self):
        engine = PolicyEngine.from_preset("strict")
        assert len(engine.rules) > 0

    def test_from_name_or_path_invalid(self):
        with pytest.raises(ValueError, match="Unknown preset"):
            PolicyEngine.from_preset("nonexistent")

    def test_from_name_or_path_file(self, tmp_path):
        policy_file = tmp_path / "custom.yaml"
        policy_file.write_text("policies:\n  - name: x\n    match:\n      any_tool: true\n    action: allow\n    reason: ok\n")
        engine = PolicyEngine.from_name_or_path(str(policy_file))
        assert len(engine.rules) == 1

    def test_from_name_or_path_invalid_path(self):
        with pytest.raises(ValueError, match="not a preset name"):
            PolicyEngine.from_name_or_path("/nonexistent/path.yaml")


# ---------------------------------------------------------------------------
# Decision & InterceptResult tests
# ---------------------------------------------------------------------------


class TestDecision:
    def test_decision_values(self):
        assert Decision.ALLOW == "allow"
        assert Decision.DENY == "deny"
        assert Decision.ESCALATE == "escalate"

    def test_intercept_result_denied_property(self):
        result = InterceptResult(decision=Decision.DENY, reason="test")
        assert result.denied is True

        result = InterceptResult(decision=Decision.ALLOW, reason="ok")
        assert result.denied is False

    def test_intercept_result_to_dict(self):
        result = InterceptResult(
            decision=Decision.DENY,
            reason="outside sandbox",
            suggestion="use /workspace/",
            policy_matched="sandbox-rule",
        )
        d = result.to_dict()
        assert d["decision"] == "deny"
        assert d["reason"] == "outside sandbox"
        assert d["suggestion"] == "use /workspace/"
        assert d["policy_matched"] == "sandbox-rule"

    def test_to_dict_minimal(self):
        result = InterceptResult(decision=Decision.ALLOW, reason="ok")
        d = result.to_dict()
        assert d == {"decision": "allow", "reason": "ok"}
        assert "suggestion" not in d

    def test_escalated_property(self):
        result = InterceptResult(decision=Decision.ESCALATE, reason="review")
        assert not result.denied
        assert result.decision == Decision.ESCALATE
