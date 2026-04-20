"""Analyze quality of MCP tool descriptions for LLM compatibility."""

from __future__ import annotations

import re
from pathlib import Path

from spidershield.models import ToolDescriptionScore

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
    "mark", "unmark", "complete", "finish", "finalize", "capture", "record",
    "extract", "inject", "intercept", "redirect", "forward", "navigate",
    "fill", "click", "hover", "drag", "press", "type", "select", "focus",
    "enable", "disable", "toggle", "lock", "unlock",
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
        # Use proper suffix stripping (not rstrip which strips characters)
        raw_word = desc.split()[0].lower() if desc.strip() else ""
        stems = {raw_word}
        if raw_word.endswith("es"):
            stems.add(raw_word[:-2])  # "processes" -> "process"
            stems.add(raw_word[:-1])  # "configures" -> "configure"
        elif raw_word.endswith("s"):
            stems.add(raw_word[:-1])  # "deletes" -> "delete"
        if raw_word.endswith("ing"):
            stems.add(raw_word[:-3])  # "creating" -> "creat" (won't match, harmless)
            stems.add(raw_word[:-3] + "e")  # "creating" -> "create"
        has_action_verb = bool(stems & set(_ACTION_VERBS))

        # 2. Scenario trigger: "Use when..." / "Use for..." / "Call this..."
        has_scenario = bool(re.search(r"(?:use (?:this )?when|use for|call this)", desc, re.I))

        # 3. Parameter examples: concrete examples of inputs
        has_examples = bool(re.search(r"(?:e\.g\.|example|for instance|such as|like )", desc, re.I))

        # 4. Error guidance: failure modes and troubleshooting
        # Require context words like "if", "when", "returns", "throws" near
        # error keywords, or explicit phrases like "fails with", "error if"
        error_pat = (
            r"(?:fails?\s+(?:with|if|when|on)"
            r"|error\s+(?:if|when|code|message)"
            r"|(?:if|when)\s+.*(?:fail|invalid|error|not found)"
            r"|(?:raise|throw)s?\s+\w*(?:Error|Exception)"
            r"|common\s+issue|troubleshoot)"
        )
        has_error_guidance = bool(re.search(error_pat, desc, re.I))

        # 5. Parameter documentation: mentions input parameters or accepted values
        has_param_docs = bool(re.search(
            r"(?:param(?:eter)?s?|input|argument|accepts?|takes?|requires?|expects?)\s*[:.]",
            desc, re.I,
        )) or bool(
            # Backtick-quoted param names: require snake_case or lowercase
            # to avoid matching technology names like `Redis`, `PostgreSQL`
            re.search(r"`[a-z][a-z0-9_]*`", desc)
        ) or bool(
            re.search(r"--\w+", desc)  # CLI-style --flag params
        )

        # 5b. Return value documentation: describes what the tool outputs
        return_pat = (
            r"(?:returns?\s|outputs?\s|produces?\s|yields?\s"
            r"|result(?:s| is| will be)"
            r"|response (?:is|contains|includes)"
            r"|→)"
        )
        has_return_docs = bool(re.search(return_pat, desc, re.I))

        # 6. Disambiguation: specificity vs other tools (using content words only)
        # Single-tool servers get partial credit (no disambiguation needed)
        disambiguation = 0.5 if len(tools) == 1 else 1.0
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
        #   action_verb:  1.5  -- descriptions MUST start with a verb
        #   scenario:     2.5  -- "use when" is the most impactful guidance
        #   param_docs:   1.5  -- parameters need documentation
        #   return_docs:  1.0  -- LLMs need to know what output to expect
        # Quality signals:
        #   examples:     1.0  -- concrete examples help LLMs
        #   error:        1.0  -- failure guidance
        # Context signals:
        #   disambig:     1.0  -- distinctness from sibling tools
        #   length:       0.5  -- adequate length
        raw_score = (
            (1.0 if has_action_verb else 0.0) * 1.5
            + (1.0 if has_scenario else 0.0) * 2.5
            + (1.0 if has_param_docs else 0.0) * 1.5
            + (1.0 if has_return_docs else 0.0) * 1.0
            + (1.0 if has_examples else 0.0) * 1.0
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
                description=desc[:500],
                has_action_verb=has_action_verb,
                has_scenario_trigger=has_scenario,
                has_param_examples=has_examples,
                has_error_guidance=has_error_guidance,
                has_param_docs=has_param_docs,
                has_return_docs=has_return_docs,
                disambiguation_score=round(disambiguation, 2),
                overall_score=round(min(10.0, overall), 1),
            )
        )

    avg_score = sum(s.overall_score for s in scores) / len(scores) if scores else 5.0
    return round(avg_score, 1), scores, tool_names


def _extract_fastmcp_kwarg_tools(content: str) -> list[dict]:
    """Extract tools from FastMCP @<name>.tool(...) decorator style.

    Handles real-world variants:
      1. description kwarg in the decorator
      2. description kwarg missing — fall back to the function docstring
      3. stacked decorators between @<name>.tool(...) and def
      4. non-canonical names (mcp_server, trading_server, my_mcp, etc.)
      5. multi-line decorator arguments with nested dicts/calls

    Uses paren-depth scanning instead of greedy regex to safely handle nested
    parentheses (e.g. annotations=ToolAnnotations(...)) without backtracking.
    """
    tools: list[dict] = []
    # Allow any identifier containing mcp/server/app/fastmcp as a substring
    # (covers mcp_server, trading_server, my_mcp, etc.) without matching
    # unrelated decorators like @logger.tool() or @config.tool().
    dec_pat = re.compile(r'@(?:\w*(?:mcp|server|app|fastmcp)\w*)\.tool\(')
    desc_pat = re.compile(r'description\s*=\s*(?:"""(.*?)"""|\'\'\'(.*?)\'\'\'|"([^"]*?)"|\'([^\']*?)\')', re.DOTALL)
    # Match def after skipping any additional stacked @decorator lines
    def_pat = re.compile(
        r'(?:@[\w.]+(?:\([^)]*\))?\s*)*'   # optional stacked decorators
        r'(?:async\s+)?def\s+(\w+)\s*\('
    )
    docstring_pat = re.compile(r'\)\s*(?:->\s*[^:]+)?:\s*(?:"""(.*?)"""|\'\'\'(.*?)\'\'\')', re.DOTALL)

    for dec_match in dec_pat.finditer(content):
        start = dec_match.end()  # position after opening '('
        # Scan forward tracking paren depth to find matching ')'
        depth = 1
        i = start
        while i < len(content) and depth > 0:
            ch = content[i]
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
            i += 1
        # content[start:i-1] is the decorator body
        dec_body = content[start:i - 1]

        # Try description= kwarg first
        desc = ""
        dm = desc_pat.search(dec_body)
        if dm is not None:
            desc = (dm.group(1) or dm.group(2) or dm.group(3) or dm.group(4) or "").strip()

        # Find def name, skipping any stacked decorators, within 500 chars
        after_dec = content[i:i + 500]
        fm = def_pat.search(after_dec)
        if fm is None:
            continue
        name = fm.group(1)
        if not name:
            continue

        # If no description from kwarg, fall back to function docstring
        if not desc:
            # Search for docstring after the function signature closes
            sig_start = i + fm.start()
            ds = docstring_pat.search(content[sig_start:sig_start + 2000])
            if ds is not None:
                desc = (ds.group(1) or ds.group(2) or "").strip()

        tools.append({"name": name, "description": desc})

    return tools


_SKIP_DIRS = frozenset({
    "node_modules", "__pycache__", ".venv", "venv", "env", ".env",
    ".git", "dist", "build", ".tox", ".mypy_cache",
    "site-packages", ".nox",
    # Exclude test directories to avoid extracting test fixtures as real tools
    "tests", "test", "__tests__", "spec", "fixtures", "fixture",
    "benchmarks", "benchmark", "testdata", "test_data",
    "e2e", "integration_tests",
})


def _iter_source_files(path: Path, ext: str) -> list[Path]:
    """Collect source files for a given extension, excluding skip dirs and test files."""
    files = []
    for f in path.rglob(f"*{ext}"):
        if any(part in _SKIP_DIRS for part in f.relative_to(path).parts):
            continue
        name = f.name
        if name.startswith("test_") or name.endswith("_test.py"):
            continue
        if name.endswith((".test.ts", ".test.js", ".spec.ts", ".spec.js", ".d.ts")):
            continue
        if name.endswith("_test.go"):
            continue
        files.append(f)
    return files


def _add_tool(tools: list[dict], seen: set[str], name: str, desc: str) -> None:
    """Append a tool if not already seen."""
    if name and name not in seen:
        tools.append({"name": name, "description": desc})
        seen.add(name)


def _extract_python_tools(path: Path, tools: list[dict], seen: set[str]) -> None:
    """Extract tool definitions from Python MCP server code."""
    for py_file in _iter_source_files(path, ".py"):
        try:
            content = py_file.read_text(errors="ignore")
        except OSError:
            continue

        # FastMCP style: @mcp.tool() or @server.tool() with description in docstring
        # Match from decorator through def name, then skip to the docstring.
        # Avoids [^)]* which breaks on type annotations like tuple[int, int].
        for match in re.finditer(
            r'@(?:\w*(?:mcp|server|app|fastmcp)\w*)\.tool\(?\)?\s*(?:async\s+)?def\s+(\w+)[^"\']*?"""(.*?)"""',
            content,
            re.DOTALL,
        ):
            _add_tool(tools, seen, match.group(1), match.group(2).strip())

        # FastMCP style with description kwarg: @mcp.tool(description="...", annotations=...)
        for fastmcp_tool in _extract_fastmcp_kwarg_tools(content):
            _add_tool(tools, seen, fastmcp_tool["name"], fastmcp_tool["description"])

        # Decorated style: @tool
        for match in re.finditer(
            r'@tool\s*(?:\([^)]*\))?\s*(?:async\s+)?def\s+(\w+)\s*\([^)]*\).*?"""(.*?)"""',
            content,
            re.DOTALL,
        ):
            _add_tool(tools, seen, match.group(1), match.group(2).strip())

        # MCP SDK style: Tool(name="...", description="..." or """...""")
        for match in re.finditer(
            r'Tool\(\s*name\s*=\s*["\'](\w+)["\']\s*,\s*description\s*=\s*(?:"""(.*?)"""|["\']([^"\']+)["\'])',
            content,
            re.DOTALL,
        ):
            desc = (match.group(2) or match.group(3) or "").strip()
            _add_tool(tools, seen, match.group(1), desc)

        # MCP SDK positional style: types.Tool("name", "description") or Tool("name", description="...")
        for match in re.finditer(
            r'(?:types\.)?Tool\(\s*["\']([a-zA-Z_][\w-]*)["\']'
            r'\s*,\s*(?:description\s*=\s*)?(?:"""(.*?)"""|"([^"]*(?:"\s*\n\s*"[^"]*)*)")',
            content,
            re.DOTALL,
        ):
            desc = (match.group(2) or match.group(3) or "").strip()
            # Clean up multi-line string concatenation: "line1"\n"line2" → "line1 line2"
            desc = re.sub(r'"\s*\n\s*"', " ", desc)
            if desc:
                _add_tool(tools, seen, match.group(1), desc)

        # MCP SDK style with enum: Tool(name=GitTools.STATUS, ...)
        enum_values = dict(re.findall(r'(\w+)\s*=\s*["\'](\w+)["\']', content))
        for match in re.finditer(
            r'Tool\(\s*name\s*=\s*(\w+)\.(\w+)\s*,\s*description\s*=\s*["\']([^"\']+)["\']',
            content,
        ):
            name = enum_values.get(match.group(2), match.group(2).lower())
            _add_tool(tools, seen, name, match.group(3).strip())


def _extract_ts_tools(path: Path, tools: list[dict], seen: set[str]) -> None:
    """Extract tool definitions from TypeScript/JavaScript MCP server code."""
    for ts_file in _iter_source_files(path, ".ts") + _iter_source_files(path, ".js"):
        try:
            content = ts_file.read_text(errors="ignore")
        except OSError:
            continue

        # Build const variable map for resolving references like TOOL_NAME, TOOL_DESCRIPTION
        const_vars: dict[str, str] = {}
        for m in re.finditer(
            r"const\s+(\w+)\s*(?::\s*\w+)?\s*=\s*(?:'([^']*)'|\"([^\"]*)\"|`([^`]*)`)",
            content,
        ):
            const_vars[m.group(1)] = (m.group(2) or m.group(3) or m.group(4) or "").strip()

        # Pattern 1: server.tool("name", { description: "..." }) or description: `...`
        for match in re.finditer(
            r"server\.tool\(\s*['\"](\w+)['\"].*?description:\s*(?:'([^']*)'|\"([^\"]*)\"|`([^`]*)`)",
            content,
            re.DOTALL,
        ):
            desc = (match.group(2) or match.group(3) or match.group(4) or "").strip()
            _add_tool(tools, seen, match.group(1), desc)

        # Pattern 2: server.registerTool("name", { description: "..." | `...` })
        for match in re.finditer(
            r"server\.registerTool\(\s*['\"]([a-zA-Z_][\w-]*)['\']"
            r"\s*,\s*\{[^}]*?description:\s*\n?\s*"
            r"(?:`([^`]+)`|((?:['\"][^'\"]*['\"](?:\s*\+\s*['\"][^'\"]*['\"])*))|['\"]([^'\"]*)['\"])",
            content,
            re.DOTALL,
        ):
            name = match.group(1)
            if match.group(2):  # backtick template literal
                desc = re.sub(r"\s*\n\s*", " ", match.group(2)).strip()
            elif match.group(3):  # concatenated strings
                desc = "".join(re.findall(r"['\"]([^'\"]*)['\"]", match.group(3)))
            else:  # simple quoted string
                desc = (match.group(4) or "").strip()
            _add_tool(tools, seen, name, desc.strip())

        # Pattern 3: Object with name + description properties (Neon/PostgreSQL style)
        for match in re.finditer(
            r"name:\s*(?:'([^']*)'|\"([^\"]*)\")\s*(?:as\s+const)?\s*,"
            r"(?:[^}]{0,400}?)description:\s*(?:'([^']*)'|\"([^\"]*)\"|`([^`]*)`)",
            content,
            re.DOTALL,
        ):
            name = (match.group(1) or match.group(2) or "").strip()
            desc = (match.group(3) or match.group(4) or match.group(5) or "").strip()
            desc = re.sub(r"\s*\n\s*", " ", desc).strip()
            if not name or " " in name or not re.match(r'^[a-zA-Z_][\w.-]*$', name):
                continue
            _add_tool(tools, seen, name, desc)

        # Pattern 4: Const variable resolution (git-mcp-server style)
        for match in re.finditer(
            r"name:\s+(\w+)\s*,.*?description:\s+(\w+)\s*,",
            content,
            re.DOTALL,
        ):
            name = const_vars.get(match.group(1), "")
            desc = const_vars.get(match.group(2), "")
            if name and desc:
                _add_tool(tools, seen, name, desc)

        # Pattern 5: Object literal tool defs (Supabase-style)
        _ts_skip_keys = {
            "type", "default", "title", "label", "name",
            "id", "key", "value", "message", "description",
            "scope", "inputSchema", "outputSchema", "annotations",
        }
        for match in re.finditer(
            r"(\w+)\s*:\s*\{\s*\n?\s*description\s*:\s*\n?\s*(?:'([^']*)'|\"([^\"]*)\"|`([^`]*)`)",
            content,
        ):
            name = match.group(1)
            desc = (match.group(2) or match.group(3) or match.group(4) or "").strip()
            desc = re.sub(r"\s*\n\s*", " ", desc).strip()
            if name not in _ts_skip_keys:
                _add_tool(tools, seen, name, desc)

        # Pattern 6: McpServer.tool() — @modelcontextprotocol/sdk pattern
        for match in re.finditer(
            r'\.tool\(\s*["\']([a-zA-Z_][\w-]*)["\']'
            r'\s*,\s*(?:["\']([^"\']+)["\']|`([^`]+)`)',
            content,
            re.DOTALL,
        ):
            desc = (match.group(2) or match.group(3) or "").strip()
            desc = re.sub(r"\s*\n\s*", " ", desc).strip()
            _add_tool(tools, seen, match.group(1), desc)

        # Pattern 7: zodFunction / z.object tool definitions
        for match in re.finditer(
            r'name:\s*["\']([a-zA-Z_][\w-]*)["\']'
            r'[^}]{0,300}?description:\s*["\']([^"\']+)["\']'
            r'[^}]{0,300}?(?:parameters|schema|inputSchema)\s*:',
            content,
            re.DOTALL,
        ):
            _add_tool(tools, seen, match.group(1), match.group(2).strip())

        # Pattern 8: const name = "tool-name"; server.registerTool(name, config, handler)
        if re.search(r'registerTool\(\s*\n?\s*name\s*,', content):
            name_match = re.search(r'const name\s*=\s*["\']([a-zA-Z_][\w-]*)["\']', content)
            desc_match = re.search(r'description:\s*["\']([^"\']+)["\']', content)
            if name_match:
                p8_desc = desc_match.group(1).strip() if desc_match else ""
                _add_tool(tools, seen, name_match.group(1), p8_desc)


def _extract_go_tools(path: Path, tools: list[dict], seen: set[str]) -> None:
    """Extract tool definitions from Go MCP server code."""
    for go_file in _iter_source_files(path, ".go"):
        try:
            content = go_file.read_text(errors="ignore")
        except OSError:
            continue

        # mcp.NewTool("name", mcp.WithDescription("..."))
        # Use {0,500} instead of .*? to avoid crossing into adjacent NewTool calls
        for match in re.finditer(
            r'mcp\.NewTool\(\s*["\']([a-zA-Z_][\w-]*)["\']'
            r'[\s\S]{0,500}?(?:WithDescription|mcp\.WithDescription)\(\s*["\']([^"\']+)["\']',
            content,
        ):
            _add_tool(tools, seen, match.group(1), match.group(2).strip())

        # mcp.Tool{Name: "...", Description: t("KEY", "desc")} or Description: "desc"
        for match in re.finditer(
            r'mcp\.Tool\s*\{[^}]*?Name:\s*(?:"([a-zA-Z_][\w-]*)"|`([a-zA-Z_][\w-]*)`)'
            r'[^}]*?Description:\s*(?:'
            r't\(\s*"[^"]*"\s*,\s*(?:"([^"]+)"|`([^`]+)`)\s*\)'
            r'|"([^"]+)"'
            r'|`([^`]+)`'
            r')',
            content,
            re.DOTALL,
        ):
            name = (match.group(1) or match.group(2) or "").strip()
            desc = (match.group(3) or match.group(4) or match.group(5) or match.group(6) or "").strip()
            desc = re.sub(r"\s*\n\s*", " ", desc).strip()
            if name and desc:
                _add_tool(tools, seen, name, desc)

        # server.AddTool(mcp.Tool{Name: "...", Description: "..."})
        for match in re.finditer(
            r'(?:mcp\.)?Tool\s*\{[^}]*?Name:\s*["\']([a-zA-Z_][\w-]*)["\']'
            r'[^}]*?Description:\s*["\']([^"\']+)["\']',
            content,
            re.DOTALL,
        ):
            _add_tool(tools, seen, match.group(1), match.group(2).strip())

        # s.AddTool("name", "description", handler)
        for match in re.finditer(
            r'\.(?:AddTool|RegisterTool)\(\s*["\']([a-zA-Z_][\w-]*)["\']'
            r'\s*,\s*["\']([^"\']+)["\']',
            content,
        ):
            _add_tool(tools, seen, match.group(1), match.group(2).strip())

        # pkg.MustTool("name", "description", handler)
        for match in re.finditer(
            r'\w+\.MustTool\(\s*"([a-zA-Z_][\w-]*)"\s*,\s*"([^"]+)"',
            content,
            re.DOTALL,
        ):
            _add_tool(tools, seen, match.group(1), match.group(2).strip())

        # ToolDefinition{Name: "...", Description: "..."}
        for match in re.finditer(
            r'ToolDefinition\s*\{[^}]*?Name:\s*["\']([a-zA-Z_][\w-]*)["\']'
            r'[^}]*?Description:\s*["\']([^"\']+)["\']',
            content,
            re.DOTALL,
        ):
            _add_tool(tools, seen, match.group(1), match.group(2).strip())


def _extract_rust_tools(path: Path, tools: list[dict], seen: set[str]) -> None:
    """Extract tool definitions from Rust MCP server code."""
    for rs_file in _iter_source_files(path, ".rs"):
        try:
            content = rs_file.read_text(errors="ignore")
        except OSError:
            continue

        # #[tool(description = "...")] or #[mcp_tool(...)] followed by fn tool_name(...)
        for match in re.finditer(
            r'#\[(?:tool|mcp_tool)\s*\([^)]*?description\s*=\s*"([^"]+)"[^)]*\)\]'
            r'\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)',
            content,
            re.DOTALL,
        ):
            _add_tool(tools, seen, match.group(2), match.group(1).strip())

        # Tool::new("name", "description")
        for match in re.finditer(
            r'Tool::new\(\s*"([a-zA-Z_][\w-]*)"\s*,\s*"([^"]+)"',
            content,
        ):
            _add_tool(tools, seen, match.group(1), match.group(2).strip())

        # ToolBuilder::new("name").description("...")
        for match in re.finditer(
            r'ToolBuilder::new\(\s*"([a-zA-Z_][\w-]*)"\s*\)'
            r'.*?\.description\(\s*"([^"]+)"',
            content,
            re.DOTALL,
        ):
            _add_tool(tools, seen, match.group(1), match.group(2).strip())


def _extract_java_tools(path: Path, tools: list[dict], seen: set[str]) -> None:
    """Extract tool definitions from Java/Kotlin MCP server code."""
    for ext in (".java", ".kt", ".kts"):
        for src_file in _iter_source_files(path, ext):
            try:
                content = src_file.read_text(errors="ignore")
            except OSError:
                continue

            # @Tool(description = "...") or @McpTool(description = "...")
            # followed by fun/public methodName(...)
            for match in re.finditer(
                r'@(?:Tool|McpTool)\s*\([^)]*?description\s*=\s*"([^"]+)"[^)]*\)'
                r'\s*(?:public\s+|private\s+|protected\s+)?(?:suspend\s+)?(?:fun\s+|[\w<>\[\]]+\s+)(\w+)\s*\(',
                content,
                re.DOTALL,
            ):
                _add_tool(tools, seen, match.group(2), match.group(1).strip())

            # Tool.builder().name("...").description("...")
            for match in re.finditer(
                r'Tool\.builder\(\)[\s\S]{0,200}?\.name\(\s*"([a-zA-Z_][\w-]*)"\s*\)'
                r'[\s\S]{0,200}?\.description\(\s*"([^"]+)"',
                content,
            ):
                _add_tool(tools, seen, match.group(1), match.group(2).strip())

            # new Tool("name", "description", ...) or Tool("name", "description")
            for match in re.finditer(
                r'new\s+Tool\(\s*"([a-zA-Z_][\w-]*)"\s*,\s*"([^"]+)"',
                content,
            ):
                _add_tool(tools, seen, match.group(1), match.group(2).strip())

            # server.addTool("name", "description", handler) / registerTool
            for match in re.finditer(
                r'\.(?:addTool|registerTool)\(\s*"([a-zA-Z_][\w-]*)"\s*,\s*"([^"]+)"',
                content,
            ):
                _add_tool(tools, seen, match.group(1), match.group(2).strip())

            # ToolSpecification("name", "description", ...)
            for match in re.finditer(
                r'ToolSpecification\(\s*"([a-zA-Z_][\w-]*)"\s*,\s*"([^"]+)"',
                content,
            ):
                _add_tool(tools, seen, match.group(1), match.group(2).strip())


def _extract_php_tools(path: Path, tools: list[dict], seen: set[str]) -> None:
    """Extract tool definitions from PHP MCP server code."""
    for php_file in _iter_source_files(path, ".php"):
        try:
            content = php_file.read_text(errors="ignore")
        except OSError:
            continue

        # #[Tool(name: 'tool_name', description: 'desc')]
        for match in re.finditer(
            r"#\[Tool\s*\([^)]*?name:\s*['\"]([a-zA-Z_][\w-]*)['\"]"
            r"[^)]*?description:\s*['\"]([^'\"]+)['\"]",
            content,
        ):
            _add_tool(tools, seen, match.group(1), match.group(2).strip())

        # $server->registerTool('name', 'description', ...) / addTool
        for match in re.finditer(
            r"->(?:registerTool|addTool)\(\s*['\"]([a-zA-Z_][\w-]*)['\"]"
            r"\s*,\s*['\"]([^'\"]+)['\"]",
            content,
        ):
            _add_tool(tools, seen, match.group(1), match.group(2).strip())

        # new Tool('name', 'description') or Tool::create('name', 'description')
        for match in re.finditer(
            r"(?:new\s+Tool|Tool::(?:create|make))\(\s*['\"]([a-zA-Z_][\w-]*)['\"]"
            r"\s*,\s*['\"]([^'\"]+)['\"]",
            content,
        ):
            _add_tool(tools, seen, match.group(1), match.group(2).strip())

        # ToolDefinition::fromName('name')->description('desc')
        for match in re.finditer(
            r"ToolDefinition::fromName\(\s*['\"]([a-zA-Z_][\w-]*)['\"]"
            r"[\s\S]{0,200}?->description\(\s*['\"]([^'\"]+)['\"]",
            content,
        ):
            _add_tool(tools, seen, match.group(1), match.group(2).strip())


def _extract_ruby_tools(path: Path, tools: list[dict], seen: set[str]) -> None:
    """Extract tool definitions from Ruby MCP server code."""
    for rb_file in _iter_source_files(path, ".rb"):
        try:
            content = rb_file.read_text(errors="ignore")
        except OSError:
            continue

        # tool "name", description: "desc"
        for match in re.finditer(
            r'tool\s+["\']([a-zA-Z_][\w-]*)["\']'
            r'\s*,\s*description:\s*["\']([^"\']+)["\']',
            content,
        ):
            _add_tool(tools, seen, match.group(1), match.group(2).strip())

        # register_tool("name", "description")
        for match in re.finditer(
            r'register_tool\(\s*["\']([a-zA-Z_][\w-]*)["\']'
            r'\s*,\s*["\']([^"\']+)["\']',
            content,
        ):
            _add_tool(tools, seen, match.group(1), match.group(2).strip())

        # name: "tool_name", description: "desc" (hash style)
        for match in re.finditer(
            r'name:\s*["\']([a-zA-Z_][\w-]*)["\']'
            r'\s*,\s*description:\s*["\']([^"\']+)["\']',
            content,
        ):
            _add_tool(tools, seen, match.group(1), match.group(2).strip())


def _extract_csharp_tools(path: Path, tools: list[dict], seen: set[str]) -> None:
    """Extract tool definitions from C#/.NET MCP server code."""
    for cs_file in _iter_source_files(path, ".cs"):
        try:
            content = cs_file.read_text(errors="ignore")
        except OSError:
            continue

        # [McpTool(Name = "name", Description = "desc")] or [Tool(...)]
        for match in re.finditer(
            r'\[(?:McpTool|Tool)\s*\([^)]*?(?:Name\s*=\s*"([a-zA-Z_][\w-]*)")[^)]*'
            r'(?:Description\s*=\s*"([^"]+)")',
            content,
        ):
            name = match.group(1) or ""
            desc = match.group(2) or ""
            if name and desc:
                _add_tool(tools, seen, name, desc.strip())

        # [Description("desc")] followed by public ... MethodName(
        for match in re.finditer(
            r'\[Description\("([^"]+)"\)\]\s*'
            r'(?:\[[\w\(\)\"=,\s]*\]\s*)*'
            r'public\s+\w+\s+(\w+)\s*\(',
            content,
        ):
            _add_tool(tools, seen, match.group(2), match.group(1).strip())


def _extract_tools(path: Path) -> list[dict]:
    """Extract tool definitions from an MCP server codebase.

    Orchestrates per-language extractors (Python, TypeScript, Go, Rust,
    Java, Kotlin, PHP, Ruby, C#) with a README fallback if no tools are
    found via code parsing.
    """
    tools: list[dict] = []
    seen: set[str] = set()

    _extract_python_tools(path, tools, seen)
    _extract_ts_tools(path, tools, seen)
    _extract_go_tools(path, tools, seen)
    _extract_rust_tools(path, tools, seen)
    _extract_java_tools(path, tools, seen)
    _extract_php_tools(path, tools, seen)
    _extract_ruby_tools(path, tools, seen)
    _extract_csharp_tools(path, tools, seen)

    # Fallback: if no tools found via code parsing, try README extraction
    if not tools:
        tools = _extract_tools_from_readme(path)

    return tools


def _find_mcp_subdirs(path: Path) -> list[Path]:
    """Detect monorepo structure and find MCP-related subdirectories."""
    # Look for subdirectories that contain MCP server code
    mcp_indicators = [
        "mcp", "server", "tool", "plugin",
    ]
    subdirs: list[Path] = []
    for child in path.iterdir():
        if not child.is_dir() or child.name.startswith("."):
            continue
        name_lower = child.name.lower()
        if any(ind in name_lower for ind in mcp_indicators):
            subdirs.append(child)
    return subdirs


def _extract_tools_from_readme(path: Path) -> list[dict]:
    """Fallback: extract tool names from README when code parsing fails.

    Many MCP servers document their tools in README with patterns like:
    - `tool_name` - Description
    - **tool_name**: Description
    - | tool_name | Description |
    """
    tools: list[dict] = []
    seen_names: set[str] = set()

    for readme_name in ("README.md", "readme.md", "README.rst"):
        readme = path / readme_name
        if not readme.exists():
            continue
        try:
            content = readme.read_text(errors="ignore")
        except OSError:
            continue

        # Look for a tools/commands section
        tools_section = re.search(
            r"(?:^#{1,3}\s+(?:Tools|Commands|Available Tools|API|Functions).*?\n)"
            r"(.*?)(?=\n#{1,3}\s|\Z)",
            content,
            re.MULTILINE | re.DOTALL | re.IGNORECASE,
        )
        if not tools_section:
            continue

        section = tools_section.group(1)

        # Pattern: `tool_name` - description  or  **tool_name** - description
        readme_tools = re.finditer(
            r"^\s*[-*]?\s*(?:`([a-zA-Z_][\w-]*)`|"
            r"\*\*([a-zA-Z_][\w-]*)\*\*)"
            r"\s*[-:–—]\s*(.+)",
            section,
            re.MULTILINE,
        )
        for match in readme_tools:
            name = (match.group(1) or match.group(2) or "").strip()
            desc = match.group(3).strip()
            if name and name not in seen_names and len(name) > 1:
                tools.append({"name": name, "description": desc})
                seen_names.add(name)

        # Pattern: markdown table | tool_name | description |
        table_tools = re.finditer(
            r"\|\s*`?([a-zA-Z_][\w-]*)`?\s*\|\s*([^|]+)\|",
            section,
        )
        for match in table_tools:
            name = match.group(1).strip()
            desc = match.group(2).strip()
            # Skip header rows
            if name.lower() in ("tool", "name", "command", "function", "---", ""):
                continue
            if name not in seen_names and len(name) > 1:
                tools.append({"name": name, "description": desc})
                seen_names.add(name)

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
