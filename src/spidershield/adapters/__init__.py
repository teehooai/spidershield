"""SpiderShield Framework Adapters.

Adapters bridge between agent frameworks and the RuntimeGuard core.
"""

from .base import AdapterBase, AdapterStats
from .mcp_proxy import MCPProxyGuard, run_mcp_proxy
from .standalone import StandaloneGuard, run_standalone_guard

__all__ = [
    "AdapterBase",
    "AdapterStats",
    "MCPProxyGuard",
    "StandaloneGuard",
    "run_mcp_proxy",
    "run_standalone_guard",
]
