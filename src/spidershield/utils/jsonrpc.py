"""JSON-RPC message utilities for MCP protocol.

MCP uses JSON-RPC 2.0 over stdio. Messages are newline-delimited JSON.
"""

from __future__ import annotations

import json
from typing import Any


def parse_message(line: str) -> dict[str, Any] | None:
    """Parse a single JSON-RPC message from a line of text.

    Returns None if the line is not valid JSON.
    """
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def is_tool_call(msg: dict[str, Any]) -> bool:
    """Check if a JSON-RPC message is an MCP tools/call request."""
    return (
        msg.get("method") == "tools/call"
        and "params" in msg
    )


def extract_tool_info(msg: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Extract tool name and arguments from an MCP tools/call request.

    Returns (tool_name, arguments).
    """
    params = msg.get("params", {})
    tool_name = params.get("name", "")
    arguments = params.get("arguments", {})
    return tool_name, arguments


def make_error_response(
    request_id: Any,
    code: int,
    message: str,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a JSON-RPC error response.

    Used when the guard denies a tool call.
    """
    error: dict[str, Any] = {
        "code": code,
        "message": message,
    }
    if data:
        error["data"] = data
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": error,
    }


def make_denied_response(
    request_id: Any,
    reason: str,
    suggestion: str = "",
    policy_matched: str | None = None,
) -> dict[str, Any]:
    """Create an MCP error response for a denied tool call.

    Uses error code -32001 (SpiderShield: tool call denied).
    Includes actionable denial info in the error data.
    """
    data: dict[str, Any] = {
        "denied": True,
        "reason": reason,
    }
    if suggestion:
        data["suggestion"] = suggestion
    if policy_matched:
        data["policy_matched"] = policy_matched

    return make_error_response(
        request_id=request_id,
        code=-32001,
        message=f"SpiderShield: {reason}",
        data=data,
    )


def serialize_message(msg: dict[str, Any]) -> str:
    """Serialize a JSON-RPC message to a newline-terminated string."""
    return json.dumps(msg, ensure_ascii=False) + "\n"
