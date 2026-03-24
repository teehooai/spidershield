#!/bin/bash
# SpiderShield PreToolUse Hook for Claude Code
# Checks MCP tool trust scores before execution
#
# Install: Add to ~/.claude/settings.json or .claude/settings.json:
#   {
#     "hooks": {
#       "PreToolUse": [{
#         "matcher": "mcp__.*",
#         "hooks": [{ "type": "command", "command": "/path/to/spidershield-hook.sh" }]
#       }]
#     }
#   }
#
# How it works:
#   1. Intercepts every MCP tool call (mcp__server__tool)
#   2. Queries SpiderRating Trust API for the server's security score
#   3. Blocks (exit 2) if score < 3.0 (Grade F — malicious)
#   4. Warns if score < 5.0 (Grade D — risky)
#   5. Allows if score >= 5.0 (Grade C+ — safe)

set -euo pipefail

# Read hook input from stdin
INPUT=$(cat)

# Extract tool name (e.g., mcp__context7__resolve_library_id)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty')

# Only check MCP tools (mcp__*)
if [[ ! "$TOOL_NAME" =~ ^mcp__ ]]; then
  exit 0
fi

# Query SpiderRating Trust API
API="https://spiderrating-api-production.up.railway.app/v1/public/check"
RESPONSE=$(curl -sf --max-time 2 "${API}?tool=${TOOL_NAME}" 2>/dev/null || echo '{"verdict":"unknown"}')

VERDICT=$(echo "$RESPONSE" | jq -r '.verdict // "unknown"')
SCORE=$(echo "$RESPONSE" | jq -r '.score // "?"')
GRADE=$(echo "$RESPONSE" | jq -r '.grade // "?"')
MESSAGE=$(echo "$RESPONSE" | jq -r '.message // ""')

case "$VERDICT" in
  malicious)
    # Exit 2 = block the tool call
    echo "SpiderShield: BLOCKED — ${MESSAGE}" >&2
    exit 2
    ;;
  risky)
    # Allow but warn (exit 0, message goes to stderr for logging)
    echo "SpiderShield: WARNING — ${MESSAGE}" >&2
    exit 0
    ;;
  safe|unknown)
    # Allow
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
