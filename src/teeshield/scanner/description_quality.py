"""Analyze quality of MCP tool descriptions for LLM compatibility."""

from __future__ import annotations

import re
from pathlib import Path

from teeshield.models import ToolDescriptionScore

_ACTION_VERBS = (
    "read", "write", "create", "delete", "remove", "list", "get", "set",
    "update", "search", "find", "query", "fetch", "send", "run", "execute",
    "check", "validate", "show", "display", "add", "edit", "move", "copy",
    "rename", "monitor", "scan", "analyze", "parse", "convert", "generate",
    "deploy", "install", "configure", "connect", "disconnect", "start", "stop",
    "reset", "restore", "backup", "export", "import", "subscribe", "publish",
    "retrieve", "return", "compute", "calculate", "open", "close", "log",
    "commit", "push", "pull", "merge", "checkout", "diff", "apply", "revert",
    "compare", "switch", "expand", "stage", "unstage", "inspect", "browse",
    "download", "upload", "submit", "approve", "reject", "assign", "unassign",
    "pin", "unpin", "archive", "resolve", "test", "debug", "trace", "profile",
    "pause", "resume", "rebase", "squash", "cherry-pick", "stash", "tag",
    "obtain", "purchase", "request", "grant", "revoke", "invoke", "trigger",
    "schedule", "cancel", "retry", "abort", "suspend", "terminate", "restart",
    "migrate", "seed", "provision", "deprovision", "scale", "replicate",
    "confirm", "verify", "authenticate", "authorize", "register", "deregister",
    "rebuild", "redeploy", "rollback", "promote", "demote", "fork", "clone",
    "sync", "refresh", "flush", "clear", "purge", "truncate", "aggregate",
    "batch", "stream", "emit", "broadcast", "notify", "alert", "warn",
)


def load_tools_json(json_path: str) -> list[dict]:
    """Load tools from a JSON file (MCP tools/list format or rewrite output).

    Supports formats:
    - MCP tools/list: {"tools": [{"name": "...", "description": "...", ...}]}
    - Rewrite output: [{"name": "...", "original": "...", "rewritten": "..."}]
    - Plain list: [{"name": "...", "description": "..."}]
    """
    import json

    data = json.loads(Path(json_path).read_text(encoding="utf-8"))

    # MCP tools/list response: {"tools": [...]}
    if isinstance(data, dict) and "tools" in data:
        return [
            {"name": t["name"], "description": t.get("description", "")}
            for t in data["tools"]
        ]

    # List format
    if isinstance(data, list):
        tools = []
        for t in data:
            if not isinstance(t, dict) or "name" not in t:
                continue
            desc = t.get("description") or t.get("rewritten") or t.get("original", "")
            tools.append({"name": t["name"], "description": desc})
        return tools

    return []


def score_descriptions(
    path: Path,
    tools_json: str | None = None,
) -> tuple[float, list[ToolDescriptionScore], list[str]]:
    """Score the quality of tool descriptions in an MCP server.

    Returns (overall_score, per_tool_scores, tool_names).
    """
    tools = load_tools_json(tools_json) if tools_json else _extract_tools(path)
    if not tools:
        return 5.0, [], []

    tool_names = [t["name"] for t in tools]
    scores: list[ToolDescriptionScore] = []

    # Build stop-word set for disambiguation (words appearing in >50% of tools)
    all_words: dict[str, int] = {}
    for t in tools:
        for w in set(t.get("description", "").lower().split()):
            all_words[w] = all_words.get(w, 0) + 1
    half = max(1, len(tools) // 2)
    stop_words = {w for w, c in all_words.items() if c > half or len(w) <= 2}

    for tool in tools:
        name = tool["name"]
        desc = tool.get("description", "")

        # 1. Action verb: description starts with a verb (imperative mood)
        first_word = desc.split()[0].lower().rstrip("s") if desc.strip() else ""
        has_action_verb = first_word in _ACTION_VERBS or first_word.rstrip("e") in _ACTION_VERBS

        # 2. Scenario trigger: "Use when..." / "Use for..." / "Call this..."
        has_scenario = bool(re.search(r"(?:use (?:this )?when|use for|call this)", desc, re.I))

        # 3. Parameter examples: concrete examples of inputs
        has_examples = bool(re.search(r"(?:e\.g\.|example|for instance|such as|like )", desc, re.I))

        # 4. Error guidance: failure modes and troubleshooting
        error_pat = (
            r"(?:error|fail|common issue|if .* fails"
            r"|troubleshoot|raise|exception|invalid)"
        )
        has_error_guidance = bool(re.search(error_pat, desc, re.I))

        # 5. Parameter documentation: mentions input parameters or accepted values
        has_param_docs = bool(re.search(
            r"(?:param(?:eter)?s?|input|argument|accepts?|takes?|requires?|expects?)\s*[:.]",
            desc, re.I,
        )) or bool(re.search(r"`\w+`", desc)) or bool(  # backtick-quoted param names
            re.search(r"--\w+", desc)  # CLI-style --flag params
        )

        # 6. Disambiguation: specificity vs other tools (using content words only)
        disambiguation = 1.0
        for other in tools:
            if other["name"] != name:
                other_desc = other.get("description", "")
                overlap = _word_overlap(desc, other_desc, stop_words)
                if overlap > 0.5:
                    disambiguation = min(disambiguation, max(0.0, 1.0 - overlap))

        # 7. Length score: penalize very short or excessively long
        length_score = 1.0
        if len(desc) < 20:
            length_score = 0.2
        elif len(desc) < 50:
            length_score = 0.5
        elif len(desc) < 80:
            length_score = 0.7
        elif len(desc) > 500:
            length_score = 0.7

        # 8. Semantic density: penalize keyword-stuffing / low-content text
        semantic_density = _semantic_density(desc)

        # Weighted scoring -- total weights = 10.0
        # Core structure (must-have for good scores):
        #   action_verb: 1.5  -- descriptions MUST start with a verb
        #   scenario:    3.0  -- "use when" is the most impactful guidance
        #   param_docs:  1.5  -- parameters need documentation
        # Quality signals:
        #   examples:    1.5  -- concrete examples help LLMs
        #   error:       1.0  -- failure guidance
        # Context signals:
        #   disambig:    1.0  -- distinctness from sibling tools
        #   length:      0.5  -- adequate length
        raw_score = (
            (1.0 if has_action_verb else 0.0) * 1.5
            + (1.0 if has_scenario else 0.0) * 3.0
            + (1.0 if has_param_docs else 0.0) * 1.5
            + (1.0 if has_examples else 0.0) * 1.5
            + (1.0 if has_error_guidance else 0.0) * 1.0
            + disambiguation * 1.0
            + length_score * 0.5
        )
        # Semantic density acts as a multiplier -- keyword-stuffed garbage
        # gets scaled down proportionally
        overall = raw_score * semantic_density

        scores.append(
            ToolDescriptionScore(
                tool_name=name,
                has_action_verb=has_action_verb,
                has_scenario_trigger=has_scenario,
                has_param_examples=has_examples,
                has_error_guidance=has_error_guidance,
                has_param_docs=has_param_docs,
                disambiguation_score=round(disambiguation, 2),
                overall_score=round(min(10.0, overall), 1),
            )
        )

    avg_score = sum(s.overall_score for s in scores) / len(scores) if scores else 5.0
    return round(avg_score, 1), scores, tool_names


def _extract_tools(path: Path) -> list[dict]:
    """Extract tool definitions from Python or TypeScript MCP server code."""
    tools: list[dict] = []

    skip_dirs = {
        "node_modules", "__pycache__", ".venv", "venv", ".git",
        "dist", "build", ".tox", ".mypy_cache",
    }

    # Python: look for @tool or @server.tool decorators
    for py_file in path.rglob("*.py"):
        if any(part in skip_dirs for part in py_file.parts):
            continue
        try:
            content = py_file.read_text(errors="ignore")
        except OSError:
            continue

        # FastMCP style: @mcp.tool() or @server.tool()
        tool_pattern = re.finditer(
            r'@(?:mcp|server|app)\.tool\(?\)?\s*(?:async\s+)?def\s+(\w+)\s*\([^)]*\).*?"""(.*?)"""',
            content,
            re.DOTALL,
        )
        for match in tool_pattern:
            tools.append({"name": match.group(1), "description": match.group(2).strip()})

        # Decorated style: @tool
        tool_pattern2 = re.finditer(
            r'@tool\s*(?:\([^)]*\))?\s*(?:async\s+)?def\s+(\w+)\s*\([^)]*\).*?"""(.*?)"""',
            content,
            re.DOTALL,
        )
        for match in tool_pattern2:
            tools.append({"name": match.group(1), "description": match.group(2).strip()})

        # MCP SDK style: Tool(name="...", description="..." or """...""")
        tool_pattern3 = re.finditer(
            r'Tool\(\s*name\s*=\s*["\'](\w+)["\']\s*,\s*description\s*=\s*(?:"""(.*?)"""|["\']([^"\']+)["\'])',
            content,
            re.DOTALL,
        )
        for match in tool_pattern3:
            name = match.group(1)
            desc = (match.group(2) or match.group(3) or "").strip()
            if name not in [t["name"] for t in tools]:
                tools.append({"name": name, "description": desc})

        # MCP SDK style with enum: Tool(name=GitTools.STATUS, ...)
        # Extract the enum values first
        enum_values = dict(re.findall(r'(\w+)\s*=\s*["\'](\w+)["\']', content))
        tool_pattern4 = re.finditer(
            r'Tool\(\s*name\s*=\s*(\w+)\.(\w+)\s*,\s*description\s*=\s*["\']([^"\']+)["\']',
            content,
        )
        for match in tool_pattern4:
            enum_member = match.group(2)
            desc = match.group(3).strip()
            # Try to resolve enum value
            name = enum_values.get(enum_member, enum_member.lower())
            if name not in [t["name"] for t in tools]:
                tools.append({"name": name, "description": desc})

    # TypeScript: look for tool definitions in .ts/.js files
    for ts_file in list(path.rglob("*.ts")) + list(path.rglob("*.js")):
        if any(part in skip_dirs for part in ts_file.parts):
            continue
        try:
            content = ts_file.read_text(errors="ignore")
        except OSError:
            continue

        existing_names = {t["name"] for t in tools}

        # Build const variable map for resolving references like TOOL_NAME, TOOL_DESCRIPTION
        const_vars: dict[str, str] = {}
        for m in re.finditer(
            r"const\s+(\w+)\s*(?::\s*\w+)?\s*=\s*(?:'([^']*)'|\"([^\"]*)\"|`([^`]*)`)",
            content,
        ):
            const_vars[m.group(1)] = (m.group(2) or m.group(3) or m.group(4) or "").strip()

        # Pattern 1: server.tool("name", { description: "..." }) or description: `...`
        tool_pattern = re.finditer(
            r"server\.tool\(\s*['\"](\w+)['\"].*?description:\s*(?:'([^']*)'|\"([^\"]*)\"|`([^`]*)`)",
            content,
            re.DOTALL,
        )
        for match in tool_pattern:
            name = match.group(1)
            desc = (match.group(2) or match.group(3) or match.group(4) or "").strip()
            if name not in existing_names:
                tools.append({"name": name, "description": desc})
                existing_names.add(name)

        # Pattern 2: server.registerTool("name", { description: "..." })
        reg_pattern = re.finditer(
            r"server\.registerTool\(\s*['\"](\w+)['\"]\s*,\s*\{[^}]*?description:\s*\n?\s*((?:['\"][^'\"]*['\"](?:\s*\+\s*['\"][^'\"]*['\"])*)|['\"][^'\"]*['\"])",
            content,
            re.DOTALL,
        )
        for match in reg_pattern:
            name = match.group(1)
            raw_desc = match.group(2)
            desc = "".join(re.findall(r"['\"]([^'\"]*)['\"]", raw_desc))
            if name not in existing_names:
                tools.append({"name": name, "description": desc.strip()})
                existing_names.add(name)

        # Pattern 3: Object with name + description properties (Neon/PostgreSQL style)
        # Matches: { name: 'tool_name' (as const)?, ..., description: '...' | `...` }
        obj_tool_pattern = re.finditer(
            r"name:\s*(?:'([^']*)'|\"([^\"]*)\")\s*(?:as\s+const)?\s*,"
            r".*?description:\s*(?:'([^']*)'|\"([^\"]*)\"|`([^`]*)`)",
            content,
            re.DOTALL,
        )
        for match in obj_tool_pattern:
            name = (match.group(1) or match.group(2) or "").strip()
            desc = (match.group(3) or match.group(4) or match.group(5) or "").strip()
            # Clean up multi-line template literals
            desc = re.sub(r"\s*\n\s*", " ", desc).strip()
            # Skip names that look like display labels (contain spaces or special chars)
            # MCP tool names are identifiers: snake_case, kebab-case, or camelCase
            if not name or " " in name or not re.match(r'^[a-zA-Z_][\w.-]*$', name):
                continue
            if name not in existing_names:
                tools.append({"name": name, "description": desc})
                existing_names.add(name)

        # Pattern 4: Const variable resolution (git-mcp-server style)
        # Matches: { name: TOOL_NAME, description: TOOL_DESCRIPTION }
        const_ref_pattern = re.finditer(
            r"name:\s+(\w+)\s*,.*?description:\s+(\w+)\s*,",
            content,
            re.DOTALL,
        )
        for match in const_ref_pattern:
            name_var = match.group(1)
            desc_var = match.group(2)
            name = const_vars.get(name_var, "")
            desc = const_vars.get(desc_var, "")
            if name and desc and name not in existing_names:
                tools.append({"name": name, "description": desc})
                existing_names.add(name)

        # Pattern 5: Object literal tool defs (Supabase-style)
        # e.g. { tool_name: { description: '...', parameters: ... } }
        obj_pattern = re.finditer(
            r"(\w+)\s*:\s*\{\s*\n?\s*description\s*:\s*\n?\s*(?:'([^']*)'|\"([^\"]*)\"|`([^`]*)`)",
            content,
        )
        for match in obj_pattern:
            name = match.group(1)
            desc = (match.group(2) or match.group(3) or match.group(4) or "").strip()
            desc = re.sub(r"\s*\n\s*", " ", desc).strip()
            skip_names = {
                "type", "default", "title", "label", "name",
                "id", "key", "value", "message", "description",
                "scope", "inputSchema", "outputSchema", "annotations",
            }
            if name in skip_names:
                continue
            if name not in existing_names:
                tools.append({"name": name, "description": desc})
                existing_names.add(name)

    return tools


# Words that are scoring triggers -- don't count toward semantic content
_TRIGGER_WORDS = frozenset({
    "use", "when", "this", "for", "call", "the", "to", "a", "an", "is", "it",
    "e.g.", "example", "instance", "such", "as", "like",
    "error", "fail", "fails", "failed", "invalid", "exception", "raise",
    "troubleshoot", "common", "issue",
    "param", "parameter", "parameters", "input", "argument",
    "accepts", "takes", "requires", "expects",
    "if", "or", "and", "of", "in", "on", "by", "with", "from", "that",
    "not", "no", "do", "does", "did", "will", "can", "should", "may",
    "user", "wants",
})


def _semantic_density(desc: str) -> float:
    """Measure the ratio of meaningful content words vs trigger/filler words.

    Returns a multiplier between 0.3 and 1.0:
    - 1.0 = rich semantic content (most words carry meaning)
    - 0.3 = mostly trigger keywords with little real content

    This prevents keyword-stuffing from inflating scores.
    """
    if not desc.strip():
        return 1.0  # Don't penalize empty (already penalized by length)

    words = re.findall(r'[a-zA-Z_]\w*', desc.lower())
    if len(words) < 3:
        return 1.0  # Too short to judge density

    # Count unique content words (not trigger/filler)
    unique_content = {w for w in words if w not in _TRIGGER_WORDS and len(w) > 1}
    # Count total unique words
    unique_total = {w for w in words if len(w) > 1}

    if not unique_total:
        return 0.3

    density = len(unique_content) / len(unique_total)

    # Also penalize high word repetition (e.g. "read read read")
    if len(words) > 0:
        repetition_ratio = len(set(words)) / len(words)
    else:
        repetition_ratio = 1.0

    # Combine: low density OR high repetition = penalty
    combined = min(density, repetition_ratio)

    # Map to 0.3-1.0 range (never fully zero out a score)
    if combined >= 0.4:
        return 1.0
    elif combined >= 0.25:
        return 0.7
    else:
        return 0.3


def _word_overlap(a: str, b: str, stop_words: set[str] | None = None) -> float:
    """Calculate word overlap ratio between two strings, ignoring stop words."""
    words_a = set(a.lower().split()) - (stop_words or set())
    words_b = set(b.lower().split()) - (stop_words or set())
    if not words_a or not words_b:
        return 0.0
    intersection = words_a & words_b
    return len(intersection) / min(len(words_a), len(words_b))
