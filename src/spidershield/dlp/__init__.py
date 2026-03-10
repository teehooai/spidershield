"""SpiderShield DLP — Data Loss Prevention for AI Agent outputs.

Scans tool call results for:
- PII (credit cards, SSN, emails, phones, IPs)
- Secrets (API keys, private keys, JWTs, DB connection strings)
- Prompt injection (instruction override, ASCII smuggling, system markers)

Actions: LOG_ONLY | REDACT | MASK | BLOCK
"""

from .engine import DLPAction, DLPEngine, DLPFinding, DLPResult
from .pii import PIIType, detect_pii
from .prompt_injection import PICategory, detect_prompt_injection
from .secrets import SecretType, detect_secrets

__all__ = [
    "DLPAction",
    "DLPEngine",
    "DLPFinding",
    "DLPResult",
    "PICategory",
    "PIIType",
    "SecretType",
    "detect_pii",
    "detect_prompt_injection",
    "detect_secrets",
]
