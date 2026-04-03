"""MCP tool tracking repository — detected tools, call logging, and baselines."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from lumen_argus.analytics.base import BaseRepository

if TYPE_CHECKING:
    from lumen_argus.analytics.adapter import DatabaseAdapter

log = logging.getLogger("argus.analytics")


class MCPToolTrackingRepository(BaseRepository):
    """Repository for MCP tool detection, call logging, and drift baselines."""

    def __init__(self, adapter: DatabaseAdapter) -> None:
        super().__init__(adapter)

    # --- Detected tools ---

    def record_tool_seen(self, tool_name: str, description: str = "", input_schema: str = "") -> None:
        """Record a tool seen. Upserts call_count, conditionally updates metadata."""
        if not tool_name:
            return
        now = self._now()
        update_parts = ["last_seen = excluded.last_seen", "call_count = call_count + 1"]
        if description:
            update_parts.append("description = excluded.description")
        if input_schema:
            update_parts.append("input_schema = excluded.input_schema")
        with self._adapter.write_lock():
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO mcp_detected_tools "
                    "(tool_name, description, input_schema, first_seen, last_seen, call_count) "
                    "VALUES (?, ?, ?, ?, ?, 1) "
                    "ON CONFLICT(tool_name) DO UPDATE SET " + ", ".join(update_parts),
                    (tool_name, description or "", input_schema or "{}", now, now),
                )
        log.debug("mcp tool seen: %s", tool_name)

    def get_detected_tools(self) -> list[dict[str, Any]]:
        """Return all detected MCP tools with metadata and call counts."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT tool_name, description, input_schema, first_seen, last_seen, call_count "
                "FROM mcp_detected_tools ORDER BY call_count DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    # --- Tool call logging ---

    def record_tool_call(
        self,
        tool_name: str,
        session_id: str = "",
        status: str = "allowed",
        finding_count: int = 0,
        source: str = "proxy",
    ) -> None:
        """Log an MCP tool call for chain analysis."""
        if not tool_name:
            return
        now = self._now()
        with self._adapter.write_lock():
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO mcp_tool_calls "
                    "(tool_name, session_id, timestamp, status, finding_count, source) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (tool_name, session_id, now, status, finding_count, source),
                )
        log.debug("mcp tool call: %s status=%s findings=%d source=%s", tool_name, status, finding_count, source)

    def get_tool_calls(
        self,
        session_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return recent MCP tool calls, optionally filtered by session."""
        query = "SELECT id, tool_name, session_id, timestamp, status, finding_count, source FROM mcp_tool_calls"
        params: list[Any] = []
        if session_id:
            query += " WHERE session_id = ?"
            params.append(session_id)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def cleanup_tool_calls(self, retention_days: int = 30) -> int:
        """Delete MCP tool calls older than retention_days."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._adapter.write_lock():
            with self._connect() as conn:
                cursor = conn.execute("DELETE FROM mcp_tool_calls WHERE timestamp < ?", (cutoff,))
                deleted = cursor.rowcount
        if deleted:
            log.info("mcp tool calls cleanup: %d entries deleted (older than %d days)", deleted, retention_days)
        return deleted

    # --- Tool baselines (drift detection) ---

    def get_baseline(self, tool_name: str) -> dict[str, Any] | None:
        """Get stored baseline for a tool. Returns dict or None."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT tool_name, definition_hash, description, param_names, "
                "first_seen, last_seen, drift_count FROM mcp_tool_baselines WHERE tool_name = ?",
                (tool_name,),
            ).fetchone()
        return dict(row) if row else None

    def record_baseline(
        self,
        tool_name: str,
        definition_hash: str,
        description: str,
        param_names: list[str],
    ) -> None:
        """Insert or replace a tool baseline."""
        now = self._now()
        params_json = json.dumps(param_names)
        with self._adapter.write_lock():
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO mcp_tool_baselines (tool_name, definition_hash, description, "
                    "param_names, first_seen, last_seen, drift_count) VALUES (?, ?, ?, ?, ?, ?, 0) "
                    "ON CONFLICT(tool_name) DO UPDATE SET definition_hash=excluded.definition_hash, "
                    "description=excluded.description, param_names=excluded.param_names, last_seen=excluded.last_seen",
                    (tool_name, definition_hash, description, params_json, now, now),
                )

    def update_baseline_seen(self, tool_name: str) -> None:
        """Update last_seen timestamp for a tool baseline."""
        now = self._now()
        with self._adapter.write_lock():
            with self._connect() as conn:
                conn.execute(
                    "UPDATE mcp_tool_baselines SET last_seen = ? WHERE tool_name = ?",
                    (now, tool_name),
                )

    def increment_drift_count(self, tool_name: str) -> None:
        """Increment drift_count for a tool that changed."""
        with self._adapter.write_lock():
            with self._connect() as conn:
                conn.execute(
                    "UPDATE mcp_tool_baselines SET drift_count = drift_count + 1 WHERE tool_name = ?",
                    (tool_name,),
                )
