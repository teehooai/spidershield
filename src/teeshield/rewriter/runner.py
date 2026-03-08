"""Rewriter runner -- transforms tool descriptions for LLM-optimized selection."""

from __future__ import annotations

import json
import re
from pathlib import Path

from rich.console import Console
from rich.table import Table

console = Console()

REWRITE_SYSTEM_PROMPT = """\
You are an expert at writing MCP tool descriptions that help AI agents select the correct tool.

Given an original tool description, rewrite it following these rules:
1. ACTION-ORIENTED: Start with a verb (e.g., "Query", "Create", "List")
2. SCENARIO TRIGGER: Include "Use when the user wants to..." guidance
3. PARAMETER EXAMPLES: Add concrete examples for key parameters
4. ERROR GUIDANCE: Mention common errors and how to handle them
5. DISAMBIGUATION: If similar tools exist, explain when to use THIS one vs others
6. CONCISE: Keep under 200 words

Return ONLY the improved description text, nothing else.
"""

# Template-based rewriting rules (no API needed)
VERB_MAP = {
    "read": "Read",
    "write": "Write",
    "create": "Create",
    "delete": "Delete",
    "remove": "Remove",
    "list": "List",
    "get": "Retrieve",
    "set": "Set",
    "update": "Update",
    "search": "Search",
    "find": "Find",
    "query": "Query",
    "execute": "Execute",
    "run": "Run",
    "show": "Show",
    "diff": "Compare",
    "add": "Add",
    "move": "Move",
    "copy": "Copy",
    "rename": "Rename",
    "edit": "Edit",
    "fetch": "Fetch",
    "checkout": "Switch",
    "commit": "Commit",
    "reset": "Reset",
    "log": "Show",
    "status": "Show",
    "open": "Open",
    "close": "Close",
}

# Scenario triggers based on tool name patterns
SCENARIO_TRIGGERS = {
    "read": "Use when the user needs to examine file contents or retrieve stored data.",
    "write": "Use when the user wants to create or overwrite a file with new content.",
    "create": "Use when the user wants to create a new resource that does not yet exist.",
    "delete": "Use when the user wants to permanently remove a resource.",
    "list": "Use when the user wants to see all available items in a collection or directory.",
    "search": "Use when the user wants to find items matching specific criteria or patterns.",
    "get": "Use when the user needs to retrieve a specific resource by identifier.",
    "edit": "Use when the user wants to modify part of an existing file without rewriting it entirely.",
    "move": "Use when the user wants to relocate or rename a file or resource.",
    "diff": "Use when the user wants to see what changed between two versions.",
    "add": "Use when the user wants to stage changes or append to an existing collection.",
    "commit": "Use when the user wants to save staged changes as a permanent snapshot.",
    "checkout": "Use when the user wants to switch to a different branch or restore files.",
    "log": "Use when the user wants to review history or past activity.",
    "status": "Use when the user wants to check the current state of the working environment.",
    "fetch": "Use when the user wants to retrieve content from a URL or remote source.",
    "query": "Use when the user wants to extract specific data using a structured query.",
    "reset": "Use when the user wants to undo staged changes or restore to a previous state.",
}

# NOTE: Generic error guidance removed (v0.2).
# Tautological boilerplate like "If the path does not exist, verify the path"
# was the #1 reason PRs got rejected. Error guidance must be domain-specific
# and is only appropriate in LLM-powered rewrites, not templates.



def _rewrite_local(tool: dict, all_tools: list[dict]) -> str:
    """Rewrite a tool description using template-based rules (no API needed)."""
    name = tool["name"]
    desc = tool.get("description", "")
    name_lower = name.lower()

    # 1. Build action-oriented opening
    first_word = name_lower.split("_")[0] if "_" in name_lower else name_lower
    verb = VERB_MAP.get(first_word, "")

    # Clean up original description -- strip any leading verb so we don't double-prefix
    clean_desc = desc.strip().rstrip(".")
    # Remove leading adverb + verb phrase (e.g. "Recursively search for..." -> "for files...")
    leading_verb = re.match(
        r'^(?:(?:Recursively|Safely|Securely|Efficiently)\s+)?'
        r'(?:Get|Show|List|Read|Write|Create|Delete|Move|Search|Find|Retrieve|'
        r'Execute|Run|Make|Return|Record|Unstage|Switch|Add|Fetch|Compare|Commit|'
        r'Reset|Edit|Copy|Rename|Open|Close|Set|Update|Remove|Query)(?:s|es|ed|ing)?\s+',
        clean_desc, re.IGNORECASE
    )
    if leading_verb:
        clean_desc = clean_desc[leading_verb.end():]

    # Avoid stuttering: if the verb (or a form of it) already appears near the
    # start of clean_desc, don't prepend it again.
    if verb and clean_desc:
        first_words = clean_desc.lower().split()[:5]
        verb_stem = verb.lower().rstrip("es").rstrip("s")
        already_has_verb = any(w.startswith(verb_stem) for w in first_words)
        if already_has_verb:
            # Capitalize first letter and use as-is
            opening = f"{clean_desc[0].upper()}{clean_desc[1:]}."
        else:
            opening = f"{verb} {clean_desc}."
    elif clean_desc:
        # No verb mapping found -- keep original description as-is
        opening = f"{desc.strip().rstrip('.')}."
    else:
        opening = f"{verb or 'Perform'} the {name.replace('_', ' ')} operation."

    # 2. Add scenario trigger (only from known patterns, never tautological)
    scenario = ""
    for key, trigger in SCENARIO_TRIGGERS.items():
        if key in name_lower:
            scenario = trigger
            break
    # NOTE: No fallback -- a tautological "Use when the user wants to
    # {name}" is worse than no scenario at all. Only LLM rewrites can
    # generate domain-aware scenarios for unknown tool names.

    # 3. Compose final description
    # NOTE: Mechanical disambiguation ("Unlike X, this tool specifically
    # handles Y") removed in v0.2 -- it was the #1 pattern flagged by
    # maintainers as tautological.  Genuine disambiguation requires
    # understanding what the tools actually do differently.
    parts = [opening]
    if scenario:
        parts.append(scenario)

    return " ".join(parts)


def run_rewrite(
    server_path: str,
    model: str = "claude-sonnet-4-20250514",
    dry_run: bool = False,
    output_path: str | None = None,
):
    """Rewrite tool descriptions in an MCP server."""
    path = Path(server_path)
    if not path.exists():
        console.print(f"[red]Path not found: {server_path}[/red]")
        raise SystemExit(1)

    # Extract tools
    from teeshield.scanner.description_quality import _extract_tools

    tools = _extract_tools(path)
    if not tools:
        console.print("[yellow]No tools found in this server.[/yellow]")
        return

    # Decide rewrite engine
    use_llm = _has_anthropic_key()
    engine = "Claude API" if use_llm else "template-based"

    console.print(f"\n[bold]Rewriting tool descriptions:[/bold] {server_path}")
    console.print(f"[dim]Engine: {engine} | Dry run: {dry_run}[/dim]")
    console.print(f"Found {len(tools)} tools to rewrite.\n")

    results = []
    for tool in tools:
        original = tool["description"]

        if use_llm:
            rewritten = _rewrite_llm(tool, tools, model)
        else:
            rewritten = _rewrite_local(tool, tools)

        results.append({
            "name": tool["name"],
            "original": original,
            "rewritten": rewritten,
        })

    # Print comparison table
    _print_comparison(results)

    # Output JSON if requested
    if output_path:
        Path(output_path).write_text(json.dumps(results, indent=2))
        console.print(f"\n[green]Rewrites saved to {output_path}[/green]")

    # Apply rewrites to source files
    if not dry_run:
        applied = _apply_rewrites(path, results)
        if applied:
            console.print(f"\n[green]Applied {applied} rewrites to source files.[/green]")
        else:
            console.print("\n[yellow]No rewrites could be applied to source files.[/yellow]")
    else:
        console.print("\n[dim]Dry run -- no files modified. Remove --dry-run to apply.[/dim]")

    if not use_llm:
        console.print("[dim]Tip: Set ANTHROPIC_API_KEY for higher-quality LLM-powered rewrites.[/dim]")

    console.print()


def _print_comparison(results: list[dict]):
    """Print a before/after comparison table."""

    table = Table(title="Description Rewrite Results", show_lines=True)
    table.add_column("Tool", style="bold", width=20)
    table.add_column("Original", width=40)
    table.add_column("Rewritten", width=50)

    for r in results:
        orig_preview = r["original"][:80] + "..." if len(r["original"]) > 80 else r["original"]
        new_preview = r["rewritten"][:80] + "..." if len(r["rewritten"]) > 80 else r["rewritten"]
        table.add_row(r["name"], f"[dim]{orig_preview}[/dim]", f"[green]{new_preview}[/green]")

    console.print(table)

    # Score comparison
    orig_scores = []
    new_scores = []
    for r in results:
        orig_scores.append(_quick_score(r["original"]))
        new_scores.append(_quick_score(r["rewritten"]))

    avg_orig = sum(orig_scores) / len(orig_scores) if orig_scores else 0
    avg_new = sum(new_scores) / len(new_scores) if new_scores else 0
    delta = avg_new - avg_orig

    console.print("\n[bold]Description Quality:[/bold]")
    console.print(f"  Before: {avg_orig:.1f}/10")
    console.print(f"  After:  {avg_new:.1f}/10")
    color = "green" if delta > 0 else "red"
    console.print(f"  Change: [{color}]{'+' if delta > 0 else ''}{delta:.1f}[/{color}]")


def _quick_score(desc: str) -> float:
    """Quick-score a description using the same criteria as the scanner."""
    from teeshield.scanner.description_quality import _ACTION_VERBS

    first_word = desc.split()[0].lower().rstrip("s") if desc.strip() else ""
    has_verb = first_word in _ACTION_VERBS or first_word.rstrip("e") in _ACTION_VERBS
    has_scenario = bool(re.search(r"(?:use (?:this )?when|use for|call this)", desc, re.I))
    has_examples = bool(re.search(r"(?:e\.g\.|example|for instance|such as|like )", desc, re.I))
    has_error = bool(
        re.search(r"(?:error|fail|common issue|if .* fails|troubleshoot|raise|exception|invalid)", desc, re.I)
    )
    has_param_docs = bool(re.search(
        r"(?:param(?:eter)?s?|input|argument|accepts?|takes?|requires?|expects?)\s*[:.)]", desc, re.I,
    )) or bool(re.search(r"`\w+`", desc))

    length_score = 1.0
    if len(desc) < 20:
        length_score = 0.2
    elif len(desc) < 50:
        length_score = 0.5
    elif len(desc) < 80:
        length_score = 0.7
    elif len(desc) > 500:
        length_score = 0.7

    score = (
        (1.0 if has_verb else 0.0) * 1.5
        + (1.0 if has_scenario else 0.0) * 3.0
        + (1.0 if has_param_docs else 0.0) * 1.5
        + (1.0 if has_examples else 0.0) * 1.5
        + (1.0 if has_error else 0.0) * 1.0
        + 1.0 * 1.0  # assume decent disambiguation for rewrites
        + length_score * 0.5
    )

    return round(min(10.0, score), 1)


def _apply_rewrites(path: Path, results: list[dict]) -> int:
    """Apply rewritten descriptions back to source files.

    Returns the number of rewrites successfully applied.
    """
    applied = 0

    # Build a lookup of tool name -> rewritten description
    rewrites = {r["name"]: r for r in results if r["original"] != r["rewritten"]}
    if not rewrites:
        return 0

    # Scan source files, excluding test/build/non-MCP directories
    skip_dirs = {
        "node_modules", "__pycache__", ".venv", "venv", ".git", "dist",
        "build", ".tox", ".mypy_cache", "__tests__", ".next", ".nuxt",
    }
    skip_file_patterns = re.compile(
        r'(?:^test_|_test\.py$|\.test\.[jt]sx?$|\.spec\.[jt]sx?$'
        r'|\.d\.ts$|\.config\.[jt]s$|\.stories\.[jt]sx?$)',
        re.IGNORECASE,
    )
    source_files = []
    for ext in ("*.py", "*.ts", "*.js"):
        for f in path.rglob(ext):
            if any(part in skip_dirs for part in f.parts):
                continue
            if skip_file_patterns.search(f.name):
                continue
            source_files.append(f)

    for source_file in source_files:
        try:
            content = source_file.read_text(errors="ignore")
        except OSError:
            continue

        original_content = content
        modified = False

        for tool_name, rewrite_info in rewrites.items():
            old_desc = rewrite_info["original"]
            new_desc = rewrite_info["rewritten"]

            if not old_desc or old_desc not in content:
                continue

            # Replace the description in the file
            content = content.replace(old_desc, new_desc, 1)
            if content != original_content:
                modified = True
                applied += 1
                console.print(f"  [green]+[/green] {tool_name} in {source_file.relative_to(path)}")
                original_content = content

        if modified:
            source_file.write_text(content)

    return applied


def _has_anthropic_key() -> bool:
    """Check if Anthropic API key is available."""
    import os
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def _rewrite_llm(
    tool: dict, all_tools: list[dict], model: str
) -> str:
    """Rewrite a single tool description using Claude API."""
    import anthropic

    other_tool_names = [t["name"] for t in all_tools if t["name"] != tool["name"]]

    user_prompt = f"""Tool name: {tool['name']}
Original description: {tool['description']}
Other tools in this server: {', '.join(other_tool_names)}

Rewrite the description following the rules."""

    client = anthropic.Anthropic()
    response = client.messages.create(
        model=model,
        max_tokens=500,
        system=REWRITE_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )

    return response.content[0].text.strip()
