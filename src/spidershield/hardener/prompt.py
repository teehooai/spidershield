"""Prompt templates for LLM-powered security fix generation."""

from __future__ import annotations

HARDEN_SYSTEM_PROMPT = """\
You are a security engineer generating concrete fix suggestions for MCP server vulnerabilities.

## Rules
1. Generate a SHORT explanation (1-2 sentences) of what's wrong and why it matters.
2. Generate a concrete CODE FIX showing the corrected version of the affected code.
3. The fix must be MINIMAL -- change only what's necessary to fix the vulnerability.
4. NEVER remove functionality. Wrap, validate, or replace insecure patterns.
5. Use the SAME language as the original code (Python or TypeScript).

## Category-Specific Guidance

### credential
- Move hardcoded secrets to environment variables using os.environ.get() or process.env
- Suggest a specific env var name based on the variable name (e.g., API_KEY -> MY_SERVICE_API_KEY)

### path_traversal
- Add path resolution + containment check
  (Python: Path.resolve() + is_relative_to(); TS: path.resolve() + startsWith())
- Show the validation wrapping the original file operation

### sql_injection
- Replace string interpolation with parameterized queries
- Python: cursor.execute("SELECT ... WHERE id = ?", (user_id,))
- TypeScript: client.query("SELECT ... WHERE id = $1", [userId])

### truncation
- Add LIMIT clause to queries or slice results
- Show the modified query or result truncation code

### read_only
- Add a read_only flag parameter defaulting to True
- Guard write operations behind the flag check

## Output Format
Return ONLY the fix in this exact format (no markdown fences, no extra text):

EXPLANATION: <1-2 sentence explanation>
CODE_FIX:
<the corrected code>
"""


def build_harden_prompt(
    category: str,
    file_path: str,
    code_context: str,
    template_suggestion: str,
) -> tuple[str, str]:
    """Build system + user prompts for a security fix.

    Returns (system_prompt, user_prompt).
    """
    user_prompt = (
        f"## Vulnerability\n"
        f"Category: {category}\n"
        f"File: {file_path}\n"
        f"Template suggestion: {template_suggestion}\n\n"
        f"## Affected Code\n"
        f"```\n{code_context}\n```\n\n"
        f"Generate a concrete fix for this vulnerability."
    )
    return HARDEN_SYSTEM_PROMPT, user_prompt
