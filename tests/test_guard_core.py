"""Tests for the RuntimeGuard core module."""

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
