"""Call context for the SpiderShield Runtime Guard."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CallContext:
    """Context for a single tool call within an agent session."""

    session_id: str
    agent_id: str
    tool_name: str
    arguments: dict[str, Any]
    call_chain: list[str] = field(default_factory=list)
    user_intent: str = ""
    token_spent: int = 0
    call_index: int = 0
    framework: str = ""
    environment: str = ""
