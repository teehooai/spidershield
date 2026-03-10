"""SpiderShield Runtime Guard — Agent Tool Security Layer.

Core API:
    guard = RuntimeGuard(policy_engine)
    result = guard.before_call(ctx)   # Pre-execution: ALLOW / DENY / ESCALATE
    ...tool execution...
    output = guard.after_call(ctx, result)  # Post-execution: DLP scan
"""

from .context import CallContext
from .core import RuntimeGuard
from .decision import Decision, InterceptResult
from .policy import PolicyEngine, PolicyRule

__all__ = [
    "CallContext",
    "Decision",
    "InterceptResult",
    "PolicyEngine",
    "PolicyRule",
    "RuntimeGuard",
]
