"""SpiderShield -- Scan, improve, certify, and guard MCP servers.

Public API:
    from spidershield import SpiderGuard, Decision

    guard = SpiderGuard(policy="balanced")
    result = guard.check(tool_name="read_file", arguments={"path": "/etc/passwd"})
    # result.decision == Decision.DENY
    # result.reason == "System file access blocked"
    # result.suggestion == "Use application-level files instead"

    # With audit logging:
    guard = SpiderGuard(policy="strict", audit=True)

    # MCP proxy shortcut:
    from spidershield import guard_mcp_server
    guard_mcp_server(["npx", "server-filesystem", "/tmp"], policy="balanced")
"""

__version__ = "0.3.0"

from .guard.context import CallContext
from .guard.core import RuntimeGuard
from .guard.decision import Decision, InterceptResult
from .guard.policy import PolicyEngine, PolicyRule


class SpiderGuard:
    """High-level API for SpiderShield Runtime Guard.

    Usage:
        guard = SpiderGuard(policy="balanced")
        result = guard.check("read_file", {"path": "/etc/passwd"})
        if result.denied:
            print(result.reason, result.suggestion)

    With audit logging:
        guard = SpiderGuard(policy="strict", audit=True)

    With DLP (redact secrets from tool output):
        guard = SpiderGuard(policy="strict", dlp="redact")
    """

    def __init__(
        self,
        policy: str = "balanced",
        *,
        audit: bool = False,
        audit_dir: str | None = None,
        dlp: str | None = None,
    ) -> None:
        engine = PolicyEngine.from_name_or_path(policy)

        logger = None
        if audit:
            from .audit.logger import AuditLogger
            logger = AuditLogger(audit_dir)

        dlp_engine = None
        if dlp:
            from .dlp.engine import DLPEngine
            dlp_engine = DLPEngine(action=dlp)

        self._guard = RuntimeGuard(
            policy_engine=engine,
            audit_logger=logger,
            dlp_engine=dlp_engine,
        )
        self._call_index = 0

    def check(
        self,
        tool_name: str,
        arguments: dict | None = None,
        *,
        session_id: str = "",
        agent_id: str = "",
    ) -> InterceptResult:
        """Check if a tool call is allowed (pre-execution)."""
        ctx = CallContext(
            session_id=session_id or "default",
            agent_id=agent_id or "default",
            tool_name=tool_name,
            arguments=arguments or {},
            call_index=self._call_index,
        )
        self._call_index += 1
        return self._guard.before_call(ctx)

    def after_check(
        self,
        tool_name: str,
        tool_result: object,
        *,
        session_id: str = "",
        agent_id: str = "",
        call_index: int | None = None,
    ) -> object:
        """Inspect tool output after execution (DLP scan)."""
        ctx = CallContext(
            session_id=session_id or "default",
            agent_id=agent_id or "default",
            tool_name=tool_name,
            arguments={},
            call_index=call_index if call_index is not None else self._call_index,
        )
        return self._guard.after_call(ctx, tool_result)

    @property
    def guard(self) -> RuntimeGuard:
        """Access the underlying RuntimeGuard for advanced usage."""
        return self._guard

    @property
    def policy_engine(self) -> PolicyEngine:
        """Access the policy engine for inspection."""
        return self._guard.policy_engine


def guard_mcp_server(
    server_cmd: list[str],
    *,
    policy: str = "balanced",
    verbose: bool = False,
    audit: bool = True,
    audit_dir: str | None = None,
) -> int:
    """Start an MCP proxy with security guard around a server.

    Usage:
        from spidershield import guard_mcp_server
        guard_mcp_server(["npx", "server-filesystem", "/tmp"], policy="balanced")

    Args:
        server_cmd: Command to start the real MCP server.
        policy: Policy preset (strict/balanced/permissive) or YAML file path.
        verbose: Enable verbose logging to stderr.
        audit: Enable audit logging (default: True).
        audit_dir: Custom audit log directory.

    Returns:
        Server process return code.
    """
    from .adapters.mcp_proxy import run_mcp_proxy

    return run_mcp_proxy(
        server_cmd=server_cmd,
        policy=policy,
        verbose=verbose,
        audit_dir=audit_dir,
        no_audit=not audit,
    )


__all__ = [
    # High-level API
    "SpiderGuard",
    "guard_mcp_server",
    # Core types
    "CallContext",
    "Decision",
    "InterceptResult",
    "PolicyEngine",
    "PolicyRule",
    "RuntimeGuard",
]
