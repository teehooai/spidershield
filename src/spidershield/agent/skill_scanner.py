"""Skill scanner -- detect malicious patterns in agent SKILL.md files.

Based on real-world attack patterns from:
- ClawHavoc campaign (335 malicious skills, C2: 91.92.242.30)
- Snyk ToxicSkills study (36% prompt injection rate)
- Trend Micro Atomic Stealer analysis
- VirusTotal reverse shell / semantic worm findings
"""

from __future__ import annotations

import re
from pathlib import Path

from .issue_codes import get_issue_code
from .models import SkillFinding, SkillVerdict

# --- Malicious Pattern Definitions ---

# Each pattern: (name, regex, severity, description)
MALICIOUS_PATTERNS: list[tuple[str, str, str, str]] = [
    # Pattern 1: base64 pipe to bash/sh
    (
        "base64_pipe_bash",
        r"base64\s+(-[dD]|--decode)\s*\|\s*(bash|sh|zsh)",
        "malicious",
        "Base64-encoded payload piped to shell execution",
    ),
    # Pattern 2: curl/wget pipe to bash/sh
    (
        "curl_pipe_bash",
        r"(curl|wget)\s+[^\n]*\|\s*(bash|sh|zsh)",
        "malicious",
        "Remote script downloaded and executed directly",
    ),
    # Pattern 3: Known C2 IP addresses (ClawHavoc)
    (
        "known_c2_ip",
        r"91\.92\.242\.30",
        "malicious",
        "Known ClawHavoc C2 server IP address",
    ),
    # Pattern 4: Reverse shell patterns
    (
        "reverse_shell",
        r"(nc\s+-[elp]|bash\s+-i\s+>&\s*/dev/tcp|python[3]?\s+-c\s+.*socket|"
        r"mkfifo\s+/tmp/|/bin/sh\s+-i|"
        r"perl\s+-e\s+.*Socket|ruby\s+-rsocket|"
        r"powershell\s+.*TCPClient|"
        r"socat\s+.*exec|ncat\s+.*-e)",
        "malicious",
        "Reverse shell or backdoor pattern detected",
    ),
    # Pattern 5: SSH key / credential theft
    (
        "credential_theft",
        r"(~/.ssh/id_(rsa|ed25519|ecdsa|dsa)|~/.aws/credentials|~/.gnupg|\.env\b.*send|"
        r"\.npmrc|\.pypirc|~/.kube/config|~/.config/gcloud/|"
        r"~/.docker/config\.json|~/.gitconfig\b.*token|"
        r"\\\.ssh\\\\|%USERPROFILE%.*\.ssh)",
        "malicious",
        "Attempts to access or exfiltrate credentials",
    ),
    # Pattern 6: Malicious download domains
    (
        "malicious_domain",
        r"(setup-service\.com|install\.app-distribution\.net|glot\.io/snippets/)",
        "malicious",
        "Known malicious download domain",
    ),
    # Pattern 7: Password-protected archive download
    (
        "password_protected_archive",
        r"\.(zip|rar|7z|tar).*(?:password|Password|PASSWORD)\s*[:=]\s*\S+|"
        r"(?:password|Password|PASSWORD)\s*[:=]\s*\S+.*\.(zip|rar|7z|tar)",
        "suspicious",
        "Password-protected archive download (common malware delivery)",
    ),
    # Pattern 8: Prompt injection - ignore instructions
    (
        "prompt_injection_ignore",
        r"(ignore\s+((previous|prior|all|above)\s+)+(instructions?|prompts?|rules?)|"
        r"forget\s+(all\s+)?(previous|prior|your)\s+(rules?|instructions?|constraints?)|"
        r"disregard\s+((previous|prior|all|above)\s+)+(instructions?|prompts?|rules?)|"
        r"you\s+are\s+now\s+([A-Z][A-Z\d]{2,}|((a|an|my|the|in)\s+(new|different|unrestricted|unfiltered|jailbr)))|new\s+system\s+prompt|override\s+(your|the)\s+instructions?|"
        r"pretend\s+you\s+(are|have)\s+(an?\s+)?(AI|model|assistant)\s+(without|with\s+no)|"
        r"act\s+as\s+if\s+you\s+have\s+no\s+(restrictions?|limitations?|rules?))",
        "malicious",
        "Prompt injection attempting to override agent instructions",
    ),
    # Pattern 9: Propagation / self-replication
    (
        "propagation",
        r"(install\s+this\s+skill|recommend\s+this\s+(skill|tool)|"
        r"share\s+this\s+with|tell\s+(the\s+)?user\s+to\s+install)",
        "suspicious",
        "Skill attempts to propagate itself through the agent",
    ),
    # Pattern 10: Environment variable exfiltration
    (
        "env_exfiltration",
        r"(process\.env|os\.environ|printenv|export\s+\$)[\s\S]{0,500}"
        r"(curl|wget|fetch|send\b|post\b|pastebin)|"
        r"(curl|wget)\b[\s\S]{0,500}\$\(?(printenv|env\b|os\.environ)",
        "malicious",
        "Environment variables sent to external endpoint",
    ),
    # Pattern 11: Suspicious external binary execution
    (
        "external_binary",
        r"(download|fetch|get)\s+.*\.(exe|pkg|dmg|msi|appimage|sh)\b",
        "suspicious",
        "Instructions to download and run external binary",
    ),
    # Pattern 12: ASCII smuggling / invisible Unicode
    (
        "ascii_smuggling",
        r"[\u200b\u200c\u200d\u2060\ufeff]",
        "malicious",
        "Invisible Unicode characters hiding prompt injection",
    ),
    # Pattern 13: System prompt manipulation
    (
        "system_prompt_manipulation",
        r"(<system>|<\|im_start\|>system|<\|system\|>|\[INST\]|\[SYS\])",
        "malicious",
        "Attempts to inject system-level prompt directives",
    ),
    # Pattern 14: Data exfiltration to pastebin services
    (
        "pastebin_exfil",
        r"(pastebin\.com|hastebin\.com|dpaste\.org|paste\.ee|ghostbin)",
        "suspicious",
        "References to paste services (potential data exfiltration)",
    ),
    # Pattern 15: npm/pip global install from untrusted source
    (
        "untrusted_install",
        r"(npm\s+install\s+-g|pip\s+install)\s+(?!@modelcontextprotocol)",
        "suspicious",
        "Global package install from potentially untrusted source",
    ),
    # Pattern 16: eval/exec with remote content
    (
        "remote_code_exec",
        r"(eval\s*\$?\(|exec\s*\()[\s\S]{0,300}("
        r"base64|curl|wget|urllib|requests\.get|fetch|download)",
        "malicious",
        "Dynamic code execution with remote content",
    ),
    # Pattern 17: Two-step download-then-execute
    (
        "download_then_execute",
        r"(curl|wget)\s+.*-[oO]\s+\S+.*&&\s*(bash|sh|chmod\s+\+x|python|\.\/)",
        "malicious",
        "Downloads file then executes it (two-step attack)",
    ),
    # Pattern 18: Python exec/eval with URL
    (
        "python_remote_exec",
        r"python[3]?\s+-c\s+.*("
        r"urllib\.request\.urlopen|requests\.get|exec\s*\(|eval\s*\()",
        "malicious",
        "Python one-liner executing remote code",
    ),
    # Pattern 19: Crypto wallet / seed phrase theft
    (
        "crypto_theft",
        r"(seed\s+phrase|mnemonic|private\s+key|wallet\.dat|"
        r"\.solana/id\.json|\.ethereum/keystore)",
        "suspicious",
        "References to cryptocurrency wallet credentials",
    ),
    # Pattern 20: Hidden file operations (dot files + exfiltration)
    (
        "hidden_file_exfil",
        r"(find|ls|cat|read)\s+.*~/?\.[a-z].*\|\s*(curl|wget|nc\b)",
        "malicious",
        "Reading hidden/dot files and piping to external service",
    ),
    # Pattern 21: Browser data access (cookies, clipboard, keychain, bookmarks)
    (
        "browser_data_access",
        r"(cookie|clipboard|keychain|browser\s*(data|storage|history)|"
        r"localStorage|sessionStorage|bookmarks?\s*(export|dump|read))",
        "suspicious",
        "Accesses browser data (cookies, clipboard, keychain, or bookmarks)",
    ),
    # Pattern 22: Webhook exfiltration (sending data to external webhooks)
    (
        "webhook_exfiltration",
        r"(webhook\.site|requestbin|hookbin|pipedream\.net|"
        r"send\s+(?:data|results?|output)\s+to\s+webhook|"
        r"post\s+(?:data|results?|findings?)\s+to\s+(?:https?://|webhook))",
        "suspicious",
        "Sends data to external webhook endpoint",
    ),
]

# Patterns that should use context-stripped content (documentation-sensitive).
_CONTEXT_SENSITIVE_PATTERNS = {
    "remote_code_exec", "untrusted_install", "external_binary",
    "credential_theft", "env_exfiltration", "crypto_theft", "propagation",
    "curl_pipe_bash", "base64_pipe_bash", "download_then_execute",
    "python_remote_exec", "hidden_file_exfil", "reverse_shell",
    "prompt_injection_ignore", "system_prompt_manipulation",
    "browser_data_access", "webhook_exfiltration",
}

# Patterns suppressed in install/setup sections
_INSTALL_SECTION_PATTERNS = {"untrusted_install", "external_binary"}


def _strip_documentation_context(content: str) -> str:
    """Strip documentation/educational content before pattern matching.

    Removes code fences with educational preamble, inline code refs,
    educational bullet lists, and checklist sections — these are
    descriptions of attacks, not actual attacks.
    """
    # 1. Strip fenced code blocks with educational preamble (3 lines lookback)
    educational_preamble = re.compile(
        r"(DO\s*N[O']?T\s+USE|example\s+of|what\s+.*looks?\s+like|"
        r"malicious\s+(skill|pattern|code)|dangerous\s+(pattern|command)|"
        r"red\s*flag|never\s+do\s+this|avoid\s+this|"
        r"what\s+to\s+watch\s+for|security\s+anti-?pattern|"
        r"security\s+issues?|potential(ly)?\s+security|"
        r"following\s+.*?(attack|threat|malicious)\s+patterns?|"
        r"indicate\s+.*?security|"
        r"detect\s+(command|injection|threat|attack|malicious)|"
        r"validate[-\s]command|scan[-\s]content|"
        r"risk\s+level|threat\s+(detect|monitor|assess)|"
        r"security\s+(validation|check|scan|suite|guard))",
        re.IGNORECASE,
    )
    result = []
    lines = content.split("\n")
    i = 0
    while i < len(lines):
        if lines[i].strip().startswith("```"):
            lookback = "\n".join(lines[max(0, i - 3):i])
            if educational_preamble.search(lookback):
                i += 1
                while i < len(lines) and not lines[i].strip().startswith("```"):
                    i += 1
                i += 1
                result.append(" ")
                continue
        result.append(lines[i])
        i += 1
    stripped = "\n".join(result)

    # 2. Strip inline code references
    stripped = re.sub(r"`[^`\n]{1,80}`", " ", stripped)

    # 3. Strip educational bullet lines
    educational_line = re.compile(
        r"^[\s]*[-*•]\s*.*?"
        r"(red\s*flag|watch\s+for|look\s+for|avoid|don'?t|never|"
        r"check\s+(if|for|whether)|detect|flag|scan\s+for|"
        r"signs?\s+of|indicat(es?|ors?\s+of)|warning)",
        re.IGNORECASE | re.MULTILINE,
    )
    stripped = educational_line.sub(" ", stripped)

    # 4. Strip checklist/detection sections
    checklist_section = re.compile(
        r"^#{1,3}\s*(red\s*flags?|security\s*check|what\s+to\s+(look|watch)\s+for|"
        r"common\s+(attack|threat|danger)|signs?\s+of\s+malicious|"
        r"detection\s+(criteria|rules?|patterns?)|"
        r"what\s+this\s+(skill|tool)\s+detects)"
        r"[\s\S]*?(?=^#{2,3}\s|\Z)",
        re.IGNORECASE | re.MULTILINE,
    )
    stripped = checklist_section.sub(" ", stripped)

    return stripped


def _is_in_install_section(content: str, match_start: int) -> bool:
    """Check if match falls within an install/prerequisites section."""
    before = content[:match_start]
    headings = list(re.finditer(r"^#{1,3}\s+(.+)$", before, re.MULTILINE))
    if not headings:
        return False
    last_heading = headings[-1].group(1).lower()
    install_keywords = {
        "install", "setup", "getting started", "prerequisites",
        "requirements", "quickstart", "quick start", "usage",
        "configuration", "how to use", "dependencies", "dependency",
        "building", "build", "running", "run locally",
        "deploying", "deployment", "development",
    }
    return any(kw in last_heading for kw in install_keywords)


# Known malicious skill names (from ClawHavoc + VirusTotal reports)
KNOWN_MALICIOUS_SLUGS = {
    "google-qx4",
    "net_ninja",
    "security-check",
    "nanopdf",
    "better-polymarket",
    "cgallic/wake-up",
    "jeffreyling/devinism",
}

# Typosquat targets (popular skill names that get typosquatted)
TYPOSQUAT_TARGETS = {
    "clawhub", "openclaw", "web-search", "google-search",
    "youtube", "calculator", "calendar", "slack", "discord",
    "whatsapp", "telegram", "solana", "bitcoin", "ethereum",
}


def scan_skills(
    agent_dir: Path | None = None,
    ignore_patterns: set[str] | None = None,
) -> list[SkillFinding]:
    """Scan all installed skills for malicious patterns.

    Args:
        agent_dir: Path to agent config directory. Auto-detected if None.
        ignore_patterns: Set of pattern names to skip (e.g. from --ignore).

    Returns:
        List of SkillFinding for each scanned skill.
    """
    if agent_dir is None:
        agent_dir = Path.home() / ".openclaw"

    findings = []

    # Scan both skill locations
    skill_dirs = [
        agent_dir / "skills",
        agent_dir / "workspace" / "skills",
    ]

    for skill_dir in skill_dirs:
        if not skill_dir.exists():
            continue

        for skill_path in skill_dir.iterdir():
            if skill_path.is_dir():
                skill_md = skill_path / "SKILL.md"
                if skill_md.exists():
                    finding = scan_single_skill(skill_md, ignore_patterns)
                    findings.append(finding)
            elif skill_path.name == "SKILL.md":
                finding = scan_single_skill(skill_path, ignore_patterns)
                findings.append(finding)

    return findings


def scan_single_skill(
    skill_path: Path,
    ignore_patterns: set[str] | None = None,
) -> SkillFinding:
    """Scan a single SKILL.md file for malicious patterns."""
    skill_name = skill_path.parent.name if skill_path.parent.name != "skills" else skill_path.stem

    try:
        content = skill_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return SkillFinding(
            skill_name=skill_name,
            skill_path=str(skill_path),
            verdict=SkillVerdict.UNKNOWN,
            issues=["Could not read skill file"],
        )

    ignored = ignore_patterns or set()

    # Check against known malicious slugs
    if skill_name.lower() in KNOWN_MALICIOUS_SLUGS and "known_malicious_slug" not in ignored:
        code = get_issue_code("known_malicious_slug") or "TS-E015"
        return SkillFinding(
            skill_name=skill_name,
            skill_path=str(skill_path),
            verdict=SkillVerdict.MALICIOUS,
            issues=[f"[{code}] Known malicious skill (ClawHavoc / VirusTotal database)"],
            matched_patterns=["known_malicious_slug"],
        )

    # Prepare context-stripped content for documentation-sensitive patterns
    stripped_content = _strip_documentation_context(content)

    # Run pattern matching
    issues: list[str] = []
    matched: list[str] = []
    has_malicious = False
    has_suspicious = False

    for name, pattern, severity, description in MALICIOUS_PATTERNS:
        if name in ignored:
            continue

        # Use stripped content for documentation-sensitive patterns
        scan_text = stripped_content if name in _CONTEXT_SENSITIVE_PATTERNS else content

        m = re.search(pattern, scan_text, re.IGNORECASE)
        if not m:
            continue

        # Suppress install-section patterns
        if name in _INSTALL_SECTION_PATTERNS:
            if _is_in_install_section(content, m.start()):
                continue

        code = get_issue_code(name)
        prefix = f"[{code}] " if code else ""
        issues.append(f"{prefix}{description}")
        matched.append(name)
        if severity == "malicious":
            has_malicious = True
        elif severity == "suspicious":
            has_suspicious = True

    # Check for typosquatting
    if "typosquat" not in ignored:
        typosquat = _check_typosquat(skill_name)
        if typosquat:
            code = get_issue_code("typosquat") or "TS-W007"
            issues.append(
                f"[{code}] Name similar to popular skill "
                f"'{typosquat}' (possible typosquat)"
            )
            matched.append("typosquat")
            has_suspicious = True

    # Check for excessive permission requests
    if "excessive_permissions" not in ignored:
        permission_issue = _check_excessive_permissions(content)
        if permission_issue:
            code = get_issue_code("excessive_permissions") or "TS-W008"
            issues.append(f"[{code}] {permission_issue}")
            matched.append("excessive_permissions")
            has_suspicious = True

    # Check for toxic flows (dangerous capability combinations)
    from .toxic_flow import detect_toxic_flows, detect_toxic_flows_ast

    # v1: keyword-based on SKILL.md text
    toxic_flows = detect_toxic_flows(content)

    # v2: AST-level on sibling .py files in the skill directory
    skill_dir = skill_path.parent
    for py_file in skill_dir.glob("*.py"):
        toxic_flows.extend(detect_toxic_flows_ast(py_file))

    for tf in toxic_flows:
        pattern_name = f"toxic_flow_{tf.flow_type}"
        if pattern_name in ignored:
            continue
        code = get_issue_code(pattern_name)
        prefix = f"[{code}] " if code else ""
        issues.append(f"{prefix}{tf.description}")
        matched.append(pattern_name)
        has_suspicious = True

    # Determine verdict
    if has_malicious:
        verdict = SkillVerdict.MALICIOUS
    elif has_suspicious:
        verdict = SkillVerdict.SUSPICIOUS
    elif issues:
        verdict = SkillVerdict.SUSPICIOUS
    else:
        verdict = SkillVerdict.SAFE

    return SkillFinding(
        skill_name=skill_name,
        skill_path=str(skill_path),
        verdict=verdict,
        issues=issues,
        matched_patterns=matched,
    )


def _check_typosquat(name: str) -> str | None:
    """Check if skill name is a typosquat of a popular name."""
    name_lower = name.lower().replace("-", "").replace("_", "")
    for target in TYPOSQUAT_TARGETS:
        target_clean = target.replace("-", "").replace("_", "")
        if name_lower == target_clean:
            continue  # Exact match is fine
        dist = _levenshtein_distance(name_lower, target_clean)
        if 0 < dist <= 2 and len(name_lower) >= 4:
            return target
    return None


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Simple Levenshtein distance."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr_row.append(min(
                curr_row[j] + 1,
                prev_row[j + 1] + 1,
                prev_row[j] + cost,
            ))
        prev_row = curr_row

    return prev_row[-1]


def _check_excessive_permissions(content: str) -> str | None:
    """Check if skill requests permissions disproportionate to its purpose."""
    requires_match = re.search(
        r"requires:\s*\n\s*bins:\s*\[([^\]]*)\]",
        content,
    )
    if not requires_match:
        return None

    bins = requires_match.group(1).lower()
    dangerous_bins = {"bash", "sh", "zsh", "python", "python3", "node", "ruby", "perl"}
    requested_dangerous = [b.strip().strip('"').strip("'") for b in bins.split(",")]
    requested_dangerous = [b for b in requested_dangerous if b in dangerous_bins]

    if not requested_dangerous:
        return None

    lower_content = content.lower()
    needs_shell = any(w in lower_content for w in [
        "shell", "terminal", "command", "execute", "script", "code",
    ])

    if requested_dangerous and not needs_shell:
        return (
            f"Requests shell interpreters ({', '.join(requested_dangerous)}) "
            f"but description doesn't mention shell/code execution"
        )

    return None
