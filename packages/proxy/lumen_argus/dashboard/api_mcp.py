"""MCP tool list API handlers."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore
    from lumen_argus.config import Config

from lumen_argus.dashboard.api_helpers import json_response, parse_json_body, require_store

log = logging.getLogger("argus.dashboard.api")


def handle_mcp_tools_list(store: AnalyticsStore | None, config: Config | None) -> tuple[int, bytes]:
    """Return merged MCP tool lists (config + DB)."""
    log.debug("GET /api/v1/mcp/tools")
    if not store:
        return json_response(200, {"allowed": [], "blocked": []})

    try:
        db_lists = store.get_mcp_tool_lists()
    except Exception as e:
        log.warning("GET /api/v1/mcp/tools: DB error: %s", e)
        db_lists = {"allowed": [], "blocked": []}

    config_allowed: list[dict[str, str]] = []
    config_blocked: list[dict[str, str]] = []
    if config:
        mcp_cfg = getattr(config, "mcp", None)
        if mcp_cfg:
            config_allowed.extend({"tool_name": t, "source": "config"} for t in mcp_cfg.allowed_tools)
            config_blocked.extend({"tool_name": t, "source": "config"} for t in mcp_cfg.blocked_tools)

    return json_response(
        200,
        {
            "allowed": config_allowed + db_lists.get("allowed", []),
            "blocked": config_blocked + db_lists.get("blocked", []),
        },
    )


def handle_mcp_tools_add(body: bytes, store: AnalyticsStore | None) -> tuple[int, bytes]:
    """Add a tool to the allowed or blocked list."""
    store = require_store(store, "POST /api/v1/mcp/tools")

    data = parse_json_body(body, "POST /api/v1/mcp/tools")
    if isinstance(data, tuple):
        return data

    list_type = data.get("list_type", "")
    tool_name = data.get("tool_name", "")

    try:
        entry_id = store.add_mcp_tool_entry(list_type, tool_name)
    except ValueError as e:
        log.warning("POST /api/v1/mcp/tools: rejected '%s' %s (%s)", tool_name, list_type, e)
        return json_response(400, {"error": str(e)})

    if not entry_id:
        log.debug("POST /api/v1/mcp/tools: '%s' already in %s list", tool_name, list_type)
        return json_response(409, {"error": "tool already in list"})

    log.info("POST /api/v1/mcp/tools: added '%s' to %s list (id=%d)", tool_name, list_type, entry_id)
    return json_response(201, {"id": entry_id, "list_type": list_type, "tool_name": tool_name})


def handle_mcp_tools_delete(entry_id: int, store: AnalyticsStore | None) -> tuple[int, bytes]:
    """Remove an API-managed MCP tool list entry."""
    store = require_store(store, "DELETE /api/v1/mcp/tools/%d" % entry_id)

    deleted = store.delete_mcp_tool_entry(entry_id)
    if not deleted:
        log.debug("DELETE /api/v1/mcp/tools/%d: not found or config-managed", entry_id)
        return json_response(404, {"error": "entry not found or config-managed (read-only)"})

    log.info("DELETE /api/v1/mcp/tools/%d: deleted", entry_id)
    return json_response(200, {"deleted": True})
