"""Shared MCP scanning protocol — request validation, response handling, escalation.

Changes when: MCP scanning protocol, policy engine interface, or escalation logic changes.
Used by all 4 transport modes.
"""

from __future__ import annotations

import logging
from typing import Any

from lumen_argus.mcp.scanner import MCPScanner

log = logging.getLogger("argus.mcp")


def _run_policy_engine(policy_engine: Any, tool_name: str, arguments: dict[str, Any]) -> list[Any]:
    """Run Pro policy engine on a tools/call request. Returns findings list.

    Returns empty list if no engine registered or engine raises.
    """
    if policy_engine is None:
        return []
    try:
        return policy_engine.evaluate(tool_name, arguments)  # type: ignore[no-any-return]
    except Exception as exc:
        log.warning("mcp: policy engine raised %s", exc)
        return []


def _signal_escalation(
    escalation_fn: Any, signal_type: str, session_id: str, details: dict[str, Any] | None = None
) -> str | None:
    """Feed a threat signal to Pro's adaptive enforcement. Returns enforcement level.

    Returns None if no escalation function registered or it raises.
    The session_id may be empty for stdio-based modes that have no session
    concept — Pro's escalation engine should treat empty session_id as a
    single implicit session.
    """
    if escalation_fn is None:
        return None
    try:
        level = escalation_fn(signal_type, session_id, details or {})
        if level and level != "normal":
            log.info("mcp: session escalation level: %s (signal=%s)", level, signal_type)
        return str(level) if level else None
    except Exception as exc:
        log.warning("mcp: session escalation raised %s", exc)
        return None


def _jsonrpc_error(msg_id: Any, message: str) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 error response."""
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -32600, "message": message},
    }


def _check_tools_call(
    msg: dict[str, Any],
    scanner: MCPScanner,
    action: str,
    policy_engine: Any,
    escalation_fn: Any,
    session_id: str = "",
) -> dict[str, Any] | None:
    """Validate a tools/call request: session binding -> policy engine -> scanner.

    Returns a JSON-RPC error dict if the call should be blocked, or None if
    it should be forwarded. Fires escalation signals as side effects.

    All 4 transport modes call this for tools/call requests.
    """
    msg_id = msg.get("id")
    tool_name = msg.get("params", {}).get("name", "")
    arguments = msg.get("params", {}).get("arguments", {})

    # Session binding check
    if scanner.session_binding and not scanner.session_binding.validate_tool(tool_name):
        _signal_escalation(escalation_fn, "unknown_tool", session_id, {"tool": tool_name})
        if scanner.session_binding.should_block:
            return _jsonrpc_error(msg_id, "Tool '%s' not in session baseline" % tool_name)

    # Pro policy engine check
    policy_findings = _run_policy_engine(policy_engine, tool_name, arguments)
    if policy_findings and any(f.action == "block" for f in policy_findings):
        _signal_escalation(escalation_fn, "block", session_id, {"tool": tool_name})
        return _jsonrpc_error(msg_id, "Request blocked by policy: %s" % policy_findings[0].type)

    # Scanner check
    findings = scanner.scan_request(msg)
    if findings and action == "block":
        _signal_escalation(escalation_fn, "block", session_id, {"tool": tool_name})
        return _jsonrpc_error(msg_id, "Request blocked by lumen-argus: sensitive data detected")

    # Not blocked — signal near_miss or clean
    if findings:
        _signal_escalation(escalation_fn, "near_miss", session_id, {"tool": tool_name})
    else:
        _signal_escalation(escalation_fn, "clean", session_id, {"tool": tool_name})
    return None


def _handle_response(
    msg: dict[str, Any],
    pending_requests: dict[Any, Any],
    scanner: MCPScanner,
    escalation_fn: Any,
    session_id: str = "",
) -> bool:
    """Process an MCP response: confused deputy check, response scan, tools/list handling.

    Returns True if the response should be forwarded, False if it should be dropped.

    All 4 transport modes call this for response messages.
    """
    msg_id = msg.get("id")

    # Confused deputy check
    if scanner.request_tracker and "result" in msg:
        if not scanner.request_tracker.validate(msg_id):
            if scanner.request_tracker.should_block:
                return False  # drop unsolicited response

    if "result" in msg:
        req_method = pending_requests.pop(msg_id, "")
        if req_method == "tools/call":
            findings = scanner.scan_response(msg, req_method)
            if findings:
                log.debug("mcp response findings: %d", len(findings))
        elif req_method == "tools/list":
            tools = msg.get("result", {}).get("tools", [])
            if isinstance(tools, list):
                log.debug("mcp: tools/list response: %d tools", len(tools))
                tl_findings = scanner.process_tools_list(tools)
                for f in tl_findings:
                    if f.type == "tool_drift":
                        _signal_escalation(escalation_fn, "drift", session_id, {"tool": f.location.rsplit(".", 1)[-1]})

    return True  # forward


def _track_outbound(msg: dict[str, Any], pending_requests: dict[Any, Any], scanner: MCPScanner) -> None:
    """Track an outbound request for confused deputy protection and method correlation."""
    method = msg.get("method", "")
    msg_id = msg.get("id")
    if msg_id is not None and method:
        pending_requests[msg_id] = method
    if scanner.request_tracker:
        scanner.request_tracker.track(msg_id)
