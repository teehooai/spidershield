"""Hardener runner -- suggests security fixes for MCP servers (advisory only).

Supports two modes:
- template: Fast, free pattern-based suggestions (default)
- llm: LLM-generated concrete code fixes with self-check loop
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console

console = Console()


@dataclass
class HardenFinding:
    """A single hardening suggestion."""

    category: str
    file: str
    suggestion: str
    code_fix: str | None = None
    confidence: float = 0.0
    line: int | None = None


def run_harden(
    server_path: str,
    read_only: bool = True,
    truncate_limit: int = 100,
    engine: str = "template",
    provider_name: str | None = None,
):
    """Suggest security hardening for an MCP server (advisory only, no files modified)."""
    path = Path(server_path)
    if not path.exists():
        console.print(f"[red]Path not found: {server_path}[/red]")
        raise SystemExit(1)

    # Detect LLM provider if needed
    llm_provider = None
    if engine in ("llm", "auto"):
        from spidershield.rewriter.providers import detect_provider
        llm_provider = detect_provider(provider=provider_name)

    use_llm = engine == "llm" or (engine == "auto" and llm_provider is not None)
    if engine == "llm" and llm_provider is None:
        console.print(
            "[red]LLM engine requested but no API key found. "
            "Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GEMINI_API_KEY.[/red]"
        )
        raise SystemExit(1)

    engine_label = f"LLM ({llm_provider.__class__.__name__})" if use_llm else "template"

    console.print(f"\n[bold]Security suggestions for:[/bold] {server_path}")
    console.print(
        f"[dim]Engine: {engine_label} | Read-only: {read_only}"
        f" | Truncate: {truncate_limit}[/dim]\n"
    )

    # Stage 1: Template-based scan (always runs, identifies issues)
    findings = _scan_issues(path, read_only, truncate_limit)

    if not findings:
        console.print("\n[green]No issues found.[/green]")
        return

    # Stage 2: If LLM available, enhance each finding with concrete code fixes
    if use_llm and llm_provider:
        console.print(f"[dim]Enhancing {len(findings)} findings with LLM code fixes...[/dim]\n")
        findings = [
            _enhance_with_llm(f, path, llm_provider)
            for f in findings
        ]

    # Record findings to local dataset
    from spidershield.dataset.collector import record_hardener_fix
    engine_name = "llm" if use_llm else "template"
    for f in findings:
        record_hardener_fix(
            target=server_path,
            category=f.category,
            file=f.file,
            suggestion=f.suggestion,
            code_fix=f.code_fix,
            confidence=f.confidence,
            line=f.line,
            engine=engine_name,
        )

    # Print results
    _print_findings(findings, use_llm)


def _scan_issues(
    path: Path,
    read_only: bool,
    truncate_limit: int,
) -> list[HardenFinding]:
    """Scan for hardening opportunities (template-based)."""
    findings: list[HardenFinding] = []

    for source_file in list(path.rglob("*.py")) + list(path.rglob("*.ts")):
        if "node_modules" in str(source_file) or "__pycache__" in str(source_file):
            continue
        try:
            content = source_file.read_text(errors="ignore")
        except OSError:
            continue

        rel = str(source_file.relative_to(path))

        # Check 1: Credential handling
        if "os.environ" in content or "os.getenv" in content or "process.env" in content:
            findings.append(HardenFinding(
                category="credential",
                file=rel,
                suggestion="Plain env var credential -- wrap with secret manager",
            ))

        # Check 2: Path traversal
        if re.search(r"open\(|Path\(", content) and ".." not in content:
            if "resolve" not in content and "is_relative_to" not in content:
                findings.append(HardenFinding(
                    category="path_traversal",
                    file=rel,
                    suggestion="Add path validation (resolve + is_relative_to check)",
                ))

        # Check 3: SQL injection
        if re.search(r'execute\(.*f["\']', content):
            findings.append(HardenFinding(
                category="sql_injection",
                file=rel,
                suggestion="Use parameterized queries instead of f-strings",
            ))

        # Check 4: Result truncation
        if "fetchall" in content or "SELECT" in content.upper():
            if "LIMIT" not in content.upper() and str(truncate_limit) not in content:
                findings.append(HardenFinding(
                    category="truncation",
                    file=rel,
                    suggestion=(
                        f"Add LIMIT {truncate_limit} to queries"
                        " to prevent context explosion"
                    ),
                ))

        # Check 5: Read-only defaults
        if read_only:
            dangerous_sql = re.compile(
                r"(?:INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE)", re.I,
            )
            if dangerous_sql.search(content):
                if "read_only" not in content and "readonly" not in content:
                    findings.append(HardenFinding(
                        category="read_only",
                        file=rel,
                        suggestion=(
                            "Add read-only mode"
                            " (block INSERT/UPDATE/DELETE/DROP by default)"
                        ),
                    ))

    return findings


def _extract_code_context(path: Path, file_rel: str, category: str) -> str:
    """Extract relevant code context around the vulnerability."""
    full_path = path / file_rel
    try:
        content = full_path.read_text(errors="ignore")
    except OSError:
        return ""

    lines = content.splitlines()
    # Find the most relevant line for this category
    target_patterns = {
        "credential": r"os\.environ|os\.getenv|process\.env",
        "path_traversal": r"open\(|Path\(",
        "sql_injection": r'execute\(.*f["\']',
        "truncation": r"fetchall|SELECT",
        "read_only": r"INSERT|UPDATE|DELETE|DROP",
    }
    pattern = target_patterns.get(category, "")
    if not pattern:
        return "\n".join(lines[:20])

    for i, line in enumerate(lines):
        if re.search(pattern, line, re.IGNORECASE):
            start = max(0, i - 3)
            end = min(len(lines), i + 7)
            return "\n".join(f"{j+1}: {lines[j]}" for j in range(start, end))

    return "\n".join(lines[:20])


def _enhance_with_llm(
    finding: HardenFinding,
    path: Path,
    provider,
    max_retries: int = 1,
) -> HardenFinding:
    """Enhance a finding with LLM-generated code fix + self-check loop."""
    from .prompt import build_harden_prompt
    from .quality_gate import diagnose_fix, score_fix

    code_context = _extract_code_context(path, finding.file, finding.category)
    if not code_context:
        return finding

    system_prompt, user_prompt = build_harden_prompt(
        category=finding.category,
        file_path=finding.file,
        code_context=code_context,
        template_suggestion=finding.suggestion,
    )

    # Generate -> Score -> Diagnose -> Retry loop
    try:
        raw = provider.complete(system_prompt, user_prompt, max_tokens=800)
    except Exception as e:
        console.print(f"[yellow]LLM failed for {finding.file}: {e}[/yellow]")
        return finding

    explanation, code_fix = _parse_fix_response(raw)

    result = score_fix(
        category=finding.category,
        file_path=finding.file,
        original_code=code_context,
        suggestion=explanation or finding.suggestion,
        code_fix=code_fix,
    )

    # Self-check retry loop
    for _attempt in range(max_retries):
        if result.passed and result.confidence >= 0.6:
            break

        hints = diagnose_fix(finding.category, result.suggestion, code_fix)
        if not hints:
            break

        feedback = (
            f"SELF-CHECK FAILED (confidence: {result.confidence:.0%}).\n"
            f"Issues:\n" + "\n".join(f"- {h}" for h in hints) + "\n\n"
            f"Previous attempt:\n{raw}\n\n"
            f"Fix ALL listed issues and return the improved version."
        )
        retry_prompt = f"{user_prompt}\n\n---\n\n{feedback}"

        try:
            raw = provider.complete(system_prompt, retry_prompt, max_tokens=800)
        except Exception:
            break

        explanation, code_fix = _parse_fix_response(raw)
        result = score_fix(
            category=finding.category,
            file_path=finding.file,
            original_code=code_context,
            suggestion=explanation or finding.suggestion,
            code_fix=code_fix,
        )

    # Apply results if quality gate passed
    if result.passed:
        finding.suggestion = explanation or finding.suggestion
        finding.code_fix = code_fix
        finding.confidence = result.confidence

    return finding


def _parse_fix_response(raw: str) -> tuple[str, str | None]:
    """Parse LLM response into (explanation, code_fix)."""
    explanation = ""
    code_fix = None

    # Try structured format
    expl_match = re.search(
        r"EXPLANATION:\s*(.+?)(?=\nCODE_FIX:|\Z)",
        raw, re.DOTALL,
    )
    code_match = re.search(
        r"CODE_FIX:\s*\n(.+)",
        raw, re.DOTALL,
    )

    if expl_match:
        explanation = expl_match.group(1).strip()
    if code_match:
        code_fix = code_match.group(1).strip()
        # Strip markdown fences if present
        code_fix = re.sub(r"^```\w*\n?", "", code_fix)
        code_fix = re.sub(r"\n?```$", "", code_fix)

    # Fallback: if no structured format, use whole response as explanation
    if not explanation and not code_fix:
        explanation = raw.strip()

    return explanation, code_fix


def _print_findings(findings: list[HardenFinding], use_llm: bool):
    """Print findings with optional code fixes."""
    console.print(f"\n[bold]Found {len(findings)} suggestion(s):[/bold]\n")

    for f in findings:
        confidence_str = ""
        if use_llm and f.confidence > 0:
            color = "green" if f.confidence >= 0.7 else "yellow" if f.confidence >= 0.5 else "red"
            confidence_str = f" [{color}]({f.confidence:.0%})[/{color}]"

        console.print(
            f"  [yellow]![/yellow] [{f.category}] {f.file}: "
            f"{f.suggestion}{confidence_str}"
        )

        if f.code_fix:
            console.print("    [dim]Suggested fix:[/dim]")
            for line in f.code_fix.splitlines()[:15]:
                console.print(f"    [green]{line}[/green]")
            extra = len(f.code_fix.splitlines()) - 15
            if extra > 0:
                console.print(f"    [dim]... ({extra} more lines)[/dim]")
            console.print()

    console.print("[dim]These are advisory suggestions. No files were modified.[/dim]")

    if use_llm:
        high_conf = sum(1 for f in findings if f.confidence >= 0.7)
        console.print(
            f"[dim]Confidence: {high_conf}/{len(findings)} high "
            f"(>= 70%)[/dim]"
        )
