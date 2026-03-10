"""Structured prompt builder for LLM-powered description rewriting."""

from __future__ import annotations

REWRITE_SYSTEM_PROMPT = """\
You are an expert at writing MCP tool descriptions that help AI agents select \
the correct tool. Your rewrites will be scored on 7 criteria (weights in parentheses):

1. ACTION VERB (1.5): Start with an imperative verb (e.g., "Query", "Create", "List")
2. SCENARIO TRIGGER (3.0): Include "Use when..." guidance with 5+ words after "to" \
   (e.g., "Use when the user wants to retrieve data matching specific criteria.")
3. PARAMETER DOCS (1.5): Mention key parameters using `backtick` notation \
   (e.g., "Accepts `repo_owner` and `repo_name`.")
4. EXAMPLES (1.5): Add concrete examples with "e.g." or "such as"
5. ERROR GUIDANCE (1.0): Mention common failure modes \
   (e.g., "Raises an error if the table does not exist.")
6. DISAMBIGUATION (1.0): If similar tools exist, explain when to use THIS one
7. LENGTH (0.5): Aim for 80-200 words

CRITICAL ANTI-PATTERNS (from rejected PRs -- NEVER do these):
- NEVER write "Use when the user wants to {tool_name}" -- this is tautological
- NEVER add generic safety advice ("verify the path is within allowed directories")
- NEVER claim sorting, ordering, or return formats you cannot verify
- NEVER duplicate information that belongs in parameter descriptions
- NEVER broaden the tool's scope beyond what it actually does
- NEVER use "Unlike X, this tool specifically handles Y" -- mechanical disambiguation

CONSTRAINTS:
- Preserve the original tool's semantics exactly
- Be semantically NARROWER or more PRECISE than the original, never broader
- If you cannot improve the description, return it unchanged
- Return ONLY the improved description text, nothing else
- No markdown formatting, no bullet points, just flowing text
- Keep under 200 words\
"""


def build_rewrite_prompt(
    tool_name: str,
    original_description: str,
    parameters: list[dict] | None = None,
    sibling_tools: list[dict] | None = None,
) -> tuple[str, str]:
    """Build (system_prompt, user_prompt) for LLM rewriting.

    Args:
        tool_name: Name of the tool to rewrite.
        original_description: Current description text.
        parameters: List of dicts with keys: name, type, required, description.
        sibling_tools: List of dicts with keys: name, description.

    Returns:
        (system_prompt, user_prompt) tuple.
    """
    parts = [
        f"Tool name: {tool_name}",
        f"Original description: {original_description}",
    ]

    if parameters:
        param_lines = []
        for p in parameters:
            req = " (required)" if p.get("required") else " (optional)"
            desc = f" -- {p['description']}" if p.get("description") else ""
            param_lines.append(f"  - `{p['name']}`: {p.get('type', 'string')}{req}{desc}")
        parts.append("Parameters:\n" + "\n".join(param_lines))

    if sibling_tools:
        sibling_lines = []
        for s in sibling_tools:
            if s["name"] != tool_name:
                desc_preview = s.get("description", "")[:60]
                sibling_lines.append(f"  - {s['name']}: {desc_preview}")
        if sibling_lines:
            parts.append("Other tools in this server:\n" + "\n".join(sibling_lines[:15]))

    parts.append(
        "\nRewrite the description to maximize the 7 scoring criteria. "
        "If the original is already excellent, return it unchanged."
    )

    return REWRITE_SYSTEM_PROMPT, "\n\n".join(parts)
