"""Static security scanning for MCP servers."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from teeshield.models import SecurityIssue

# Patterns that indicate security risks
DANGEROUS_PATTERNS = {
    "path_traversal": {
        "patterns": [
            r"os\.path\.join\([^)]*\.\.",
            r"open\([^)]*\+",
            r'Path\([^)]*\+',
        ],
        "severity": "high",
        "description": "Potential path traversal -- user input may escape intended directory",
        "fix": "Validate and resolve paths against an allowed base directory",
    },
    "command_injection": {
        "patterns": [
            r"os\.system\(",
            r"os\.popen\(",
            r"subprocess\.(?:call|run|Popen)\([^)]*shell\s*=\s*True",
        ],
        "severity": "critical",
        "description": "Potential command injection -- user input may be executed as shell command",
        "fix": "Use subprocess with shell=False and explicit argument lists",
    },
    "dangerous_eval": {
        "patterns": [
            # exec/eval with variable input (not string literals)
            r"exec\(\s*(?![\"\'])",
            r"eval\(\s*(?![\"\'])",
        ],
        "severity": "critical",
        "description": "Dynamic code execution -- user input may be executed as code",
        "fix": "Use ast.literal_eval for data parsing, or avoid eval/exec entirely",
    },
    "sql_injection": {
        "patterns": [
            r'f"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)',
            r"f'[^']*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)",
            r'\.execute\(\s*f"',
            r"\.execute\(\s*f'",
            r'\.execute\([^)]*%\s',
            r'\.execute\([^)]*\+',
        ],
        "severity": "critical",
        "description": "Potential SQL injection -- query built with string interpolation",
        "fix": "Use parameterized queries with placeholder syntax",
    },
    "hardcoded_credential": {
        "patterns": [
            # Only flag hardcoded secrets (string literals assigned to secret-like vars)
            r'(?:api_key|token|secret|password)\s*=\s*["\'][^"\']{8,}',
        ],
        "severity": "high",
        "description": "Hardcoded credential -- secret value embedded in source code",
        "fix": "Move secrets to environment variables or a secret manager",
    },
    "unsafe_deserialization": {
        "patterns": [
            r"pickle\.loads?\(",
            r"yaml\.load\(\s*(?!.*Loader\s*=\s*yaml\.SafeLoader)",
            r"yaml\.unsafe_load\(",
            r"marshal\.loads?\(",
            r"shelve\.open\(",
        ],
        "severity": "critical",
        "description": "Unsafe deserialization -- untrusted data may execute arbitrary code",
        "fix": "Use yaml.safe_load, json.loads, or other safe deserialization methods",
    },
    "ssrf": {
        "patterns": [
            r"requests\.(?:get|post|put|delete)\([^)]*(?:url|endpoint)",
            r"httpx\.(?:get|post|put|delete)\([^)]*(?:url|endpoint)",
            r"fetch\([^)]*(?:url|endpoint)",
        ],
        "severity": "medium",
        "description": "Potential SSRF -- unrestricted network requests with user-controlled URLs",
        "fix": "Validate URLs against an allowlist of permitted domains",
    },
    "no_input_validation": {
        "patterns": [
            # Only flag MCP tool handler functions that take raw string params
            # (functions decorated with @tool, @server.tool, or named call_tool/handle)
            r"@(?:mcp|server|app)\.tool\b.*\n\s*(?:async\s+)?def\s+\w+\(.*:\s*str[,\)]",
            r"@tool\b.*\n\s*(?:async\s+)?def\s+\w+\(.*:\s*str[,\)]",
        ],
        "severity": "low",
        "description": "MCP tool handler accepts raw string input without validation",
        "fix": "Add input validation (length limits, allowlists, sanitization)",
    },
}


def scan_security(path: Path) -> tuple[float, list[SecurityIssue]]:
    """Scan for security issues in Python and TypeScript files.

    Returns (security_score, list_of_issues).
    """
    issues: list[SecurityIssue] = []

    source_files = list(path.rglob("*.py")) + list(path.rglob("*.ts")) + list(path.rglob("*.js"))
    # Exclude non-source directories from security scanning
    exclude_dirs = {"node_modules", "__pycache__", "__tests__", "tests", "test", ".git", "dist", "build", ".venv", "venv", ".tox", ".mypy_cache"}
    source_files = [
        f for f in source_files
        if not any(part in exclude_dirs for part in f.parts)
        and not f.name.startswith("test_")
        and not f.name.endswith(".test.ts")
        and not f.name.endswith(".test.js")
        and not f.name.endswith(".spec.ts")
        and not f.name.endswith(".spec.js")
    ]

    for source_file in source_files:
        try:
            content = source_file.read_text(errors="ignore")
        except OSError:
            continue

        rel_path = str(source_file.relative_to(path))

        for category, config in DANGEROUS_PATTERNS.items():
            flags = re.IGNORECASE if category != "sql_injection" else 0
            for pattern in config["patterns"]:
                for match in re.finditer(pattern, content, flags):
                    line_num = content[:match.start()].count("\n") + 1
                    issues.append(
                        SecurityIssue(
                            severity=config["severity"],
                            category=category,
                            file=rel_path,
                            line=line_num,
                            description=config["description"],
                            fix_suggestion=config["fix"],
                        )
                    )

    # Calculate score
    if not source_files:
        return 5.0, issues

    severity_weights = {"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.5, "info": 0.1}
    total_penalty = sum(severity_weights.get(i.severity, 0.5) for i in issues)
    score = max(0.0, 10.0 - total_penalty)

    return round(score, 1), issues
