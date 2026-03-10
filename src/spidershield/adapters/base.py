"""AdapterBase — abstract base for SpiderShield framework adapters.

All adapters bridge between an agent framework and the RuntimeGuard core.
Each adapter intercepts tool calls, evaluates them via the guard,
and returns results (or blocks them).

Concrete adapters:
    - MCPProxyGuard (mcp_proxy.py): stdio MCP proxy
    - StandaloneGuard (standalone.py): wraps any subprocess
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from typing import Any

from ..guard.context import CallContext
from ..guard.core import RuntimeGuard
from ..guard.decision import Decision, InterceptResult


class AdapterBase(ABC):
    """Abstract base class for SpiderShield adapters.

    Adapters sit between an agent framework and the RuntimeGuard.
    They intercept tool calls, evaluate them, and forward or block.
    """

    def __init__(
        self,
        guard: RuntimeGuard,
        *,
        session_id: str = "",
        verbose: bool = False,
        dry_run: bool = False,
    ) -> None:
        self._guard = guard
        self._session_id = session_id or uuid.uuid4().hex[:12]
        self._verbose = verbose
        self._dry_run = dry_run
        self._call_index = 0
        self._stats = AdapterStats()

    @property
    def guard(self) -> RuntimeGuard:
        return self._guard

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def stats(self) -> AdapterStats:
        return self._stats

    @abstractmethod
    def run(self, **kwargs: Any) -> int:
        """Start the adapter. Returns exit code."""
        ...

    def evaluate_tool_call(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> InterceptResult:
        """Evaluate a tool call against the guard.

        In dry-run mode, always allows but still logs the decision.
        """
        ctx = CallContext(
            session_id=self._session_id,
            agent_id="adapter",
            tool_name=tool_name,
            arguments=arguments,
            call_index=self._call_index,
            framework=self.framework_name,
        )
        self._call_index += 1
        result = self._guard.before_call(ctx)

        # Update stats
        self._stats.total_calls += 1
        if result.decision == Decision.ALLOW:
            self._stats.allowed += 1
        elif result.decision == Decision.DENY:
            self._stats.denied += 1
        elif result.decision == Decision.ESCALATE:
            self._stats.escalated += 1

        # In dry-run mode, log but don't enforce
        if self._dry_run and result.decision == Decision.DENY:
            self._log(f"DRY-RUN DENY (would block): {tool_name} — {result.reason}")
            return InterceptResult(
                decision=Decision.ALLOW,
                reason=f"[dry-run] {result.reason}",
                suggestion=result.suggestion,
                policy_matched=result.policy_matched,
            )

        return result

    def evaluate_tool_result(
        self, tool_name: str, tool_result: Any
    ) -> Any:
        """Evaluate tool output (DLP scan)."""
        ctx = CallContext(
            session_id=self._session_id,
            agent_id="adapter",
            tool_name=tool_name,
            arguments={},
            call_index=self._call_index,
            framework=self.framework_name,
        )
        return self._guard.after_call(ctx, tool_result)

    @property
    def framework_name(self) -> str:
        """Override in subclasses to identify the framework."""
        return "unknown"

    def _log(self, message: str) -> None:
        """Log to stderr if verbose."""
        if self._verbose:
            import sys
            print(f"[SpiderShield] {message}", file=sys.stderr)


class AdapterStats:
    """Simple counter for adapter-level statistics."""

    __slots__ = ("total_calls", "allowed", "denied", "escalated")

    def __init__(self) -> None:
        self.total_calls = 0
        self.allowed = 0
        self.denied = 0
        self.escalated = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "total_calls": self.total_calls,
            "allowed": self.allowed,
            "denied": self.denied,
            "escalated": self.escalated,
        }
