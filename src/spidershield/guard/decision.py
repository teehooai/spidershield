"""Decision types for the SpiderShield Runtime Guard."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"


@dataclass
class InterceptResult:
    """Result of the guard's interception decision."""

    decision: Decision
    reason: str
    suggestion: str = ""
    policy_matched: str | None = None
    pii_detected: list[str] = field(default_factory=list)

    @property
    def denied(self) -> bool:
        return self.decision == Decision.DENY

    def to_dict(self) -> dict:
        """Serialize to agent-consumable dict (actionable denial format)."""
        d: dict = {
            "decision": self.decision.value,
            "reason": self.reason,
        }
        if self.suggestion:
            d["suggestion"] = self.suggestion
        if self.policy_matched:
            d["policy_matched"] = self.policy_matched
        if self.pii_detected:
            d["pii_detected"] = self.pii_detected
        return d
