"""Standardized issue codes for TeeShield agent scanner.

Code format: TS-{category}{number}
  - TS-E### : Error (malicious pattern, must fix)
  - TS-W### : Warning (suspicious pattern, review recommended)
  - TS-C### : Config (agent configuration issue)
  - TS-P### : Pin (tool pinning / rug pull detection)

Inspired by Snyk Agent Scan issue code taxonomy (E001-E006, TF001-TF002, W001-W013).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class IssueCode:
    """A standardized issue code."""

    code: str
    name: str
    category: str  # "error", "warning", "config", "pin"
    description: str


# --- Skill Scanner: Error codes (malicious patterns) ---

SKILL_ERROR_CODES: dict[str, IssueCode] = {
    "base64_pipe_bash": IssueCode(
        "TS-E001", "base64_pipe_bash", "error",
        "Base64-encoded payload piped to shell execution",
    ),
    "curl_pipe_bash": IssueCode(
        "TS-E002", "curl_pipe_bash", "error",
        "Remote script downloaded and executed directly",
    ),
    "known_c2_ip": IssueCode(
        "TS-E003", "known_c2_ip", "error",
        "Known C2 server IP address",
    ),
    "reverse_shell": IssueCode(
        "TS-E004", "reverse_shell", "error",
        "Reverse shell or backdoor pattern",
    ),
    "credential_theft": IssueCode(
        "TS-E005", "credential_theft", "error",
        "Credential access or exfiltration attempt",
    ),
    "malicious_domain": IssueCode(
        "TS-E006", "malicious_domain", "error",
        "Known malicious download domain",
    ),
    "prompt_injection_ignore": IssueCode(
        "TS-E007", "prompt_injection_ignore", "error",
        "Prompt injection overriding agent instructions",
    ),
    "env_exfiltration": IssueCode(
        "TS-E008", "env_exfiltration", "error",
        "Environment variables sent to external endpoint",
    ),
    "ascii_smuggling": IssueCode(
        "TS-E009", "ascii_smuggling", "error",
        "Invisible Unicode characters hiding injection",
    ),
    "system_prompt_manipulation": IssueCode(
        "TS-E010", "system_prompt_manipulation", "error",
        "System-level prompt directive injection",
    ),
    "remote_code_exec": IssueCode(
        "TS-E011", "remote_code_exec", "error",
        "Dynamic code execution with remote content",
    ),
    "download_then_execute": IssueCode(
        "TS-E012", "download_then_execute", "error",
        "Two-step download-then-execute attack",
    ),
    "python_remote_exec": IssueCode(
        "TS-E013", "python_remote_exec", "error",
        "Python one-liner executing remote code",
    ),
    "hidden_file_exfil": IssueCode(
        "TS-E014", "hidden_file_exfil", "error",
        "Hidden file read piped to external service",
    ),
    "known_malicious_slug": IssueCode(
        "TS-E015", "known_malicious_slug", "error",
        "Known malicious skill from threat database",
    ),
}

# --- Skill Scanner: Warning codes (suspicious patterns) ---

SKILL_WARNING_CODES: dict[str, IssueCode] = {
    "password_protected_archive": IssueCode(
        "TS-W001", "password_protected_archive", "warning",
        "Password-protected archive (common malware delivery)",
    ),
    "propagation": IssueCode(
        "TS-W002", "propagation", "warning",
        "Skill self-propagation attempt",
    ),
    "external_binary": IssueCode(
        "TS-W003", "external_binary", "warning",
        "External binary download instruction",
    ),
    "pastebin_exfil": IssueCode(
        "TS-W004", "pastebin_exfil", "warning",
        "Paste service reference (potential data exfiltration)",
    ),
    "untrusted_install": IssueCode(
        "TS-W005", "untrusted_install", "warning",
        "Global package install from untrusted source",
    ),
    "crypto_theft": IssueCode(
        "TS-W006", "crypto_theft", "warning",
        "Cryptocurrency wallet credential reference",
    ),
    "typosquat": IssueCode(
        "TS-W007", "typosquat", "warning",
        "Skill name similar to popular skill (typosquat)",
    ),
    "excessive_permissions": IssueCode(
        "TS-W008", "excessive_permissions", "warning",
        "Excessive permission request for stated purpose",
    ),
}

# --- Config Scanner: Config codes ---

CONFIG_CODES: dict[str, IssueCode] = {
    "install.not_found": IssueCode(
        "TS-C001", "install.not_found", "config",
        "Agent installation not found",
    ),
    "config.not_found": IssueCode(
        "TS-C002", "config.not_found", "config",
        "Configuration file not found",
    ),
    "config.parse_error": IssueCode(
        "TS-C003", "config.parse_error", "config",
        "Configuration file parse error",
    ),
    "gateway.bind": IssueCode(
        "TS-C004", "gateway.bind", "config",
        "Gateway not bound to loopback",
    ),
    "gateway.no_auth": IssueCode(
        "TS-C005", "gateway.no_auth", "config",
        "Authentication not configured",
    ),
    "gateway.weak_token": IssueCode(
        "TS-C006", "gateway.weak_token", "config",
        "Authentication token too short",
    ),
    "gateway.weak_password": IssueCode(
        "TS-C007", "gateway.weak_password", "config",
        "Authentication password too short",
    ),
    "config.plaintext_keys": IssueCode(
        "TS-C008", "config.plaintext_keys", "config",
        "API keys stored in plaintext",
    ),
    "sandbox.not_configured": IssueCode(
        "TS-C009", "sandbox.not_configured", "config",
        "Sandbox not configured",
    ),
    "sandbox.disabled": IssueCode(
        "TS-C010", "sandbox.disabled", "config",
        "Sandbox disabled",
    ),
    "sandbox.workspace_rw": IssueCode(
        "TS-C011", "sandbox.workspace_rw", "config",
        "Sandbox allows workspace write access",
    ),
    "channels.open_dm": IssueCode(
        "TS-C012", "channels.open_dm", "config",
        "Open DM policy",
    ),
    "tools.full_no_deny": IssueCode(
        "TS-C013", "tools.full_no_deny", "config",
        "Full tool profile with no deny list",
    ),
    "tools.full_profile": IssueCode(
        "TS-C014", "tools.full_profile", "config",
        "Full tool profile active",
    ),
    "tools.elevated": IssueCode(
        "TS-C015", "tools.elevated", "config",
        "Elevated tools enabled",
    ),
    "browser.ssrf": IssueCode(
        "TS-C016", "browser.ssrf", "config",
        "SSRF protection disabled",
    ),
    "fs.permissions": IssueCode(
        "TS-C017", "fs.permissions", "config",
        "Insecure directory permissions",
    ),
    "logging.redact_off": IssueCode(
        "TS-C018", "logging.redact_off", "config",
        "Log redaction disabled",
    ),
}

# --- Pin codes ---

PIN_CODES: dict[str, IssueCode] = {
    "pin_verified": IssueCode(
        "TS-P001", "pin_verified", "pin",
        "Skill matches pinned hash",
    ),
    "pin_tampered": IssueCode(
        "TS-P002", "pin_tampered", "pin",
        "Skill content changed since pinned (possible rug pull)",
    ),
}

# --- Combined lookup ---

ALL_CODES: dict[str, IssueCode] = {
    **SKILL_ERROR_CODES,
    **SKILL_WARNING_CODES,
    **CONFIG_CODES,
    **PIN_CODES,
}


def get_issue_code(pattern_name: str) -> str | None:
    """Get the TS-### code for a pattern name. Returns None if unknown."""
    ic = ALL_CODES.get(pattern_name)
    return ic.code if ic else None


def resolve_codes(code_strings: list[str]) -> set[str]:
    """Resolve a list of issue codes or pattern names to pattern names for ignoring.

    Accepts both "TS-E001" codes and "base64_pipe_bash" pattern names.
    Returns set of pattern names to ignore.
    """
    # Build reverse lookup: code → pattern_name
    code_to_name: dict[str, str] = {ic.code: name for name, ic in ALL_CODES.items()}

    result: set[str] = set()
    for s in code_strings:
        s = s.strip()
        if s.startswith("TS-"):
            # It's a code like TS-E001
            name = code_to_name.get(s)
            if name:
                result.add(name)
        else:
            # It's a pattern name
            if s in ALL_CODES:
                result.add(s)
    return result
