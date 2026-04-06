"""MCP tool policies repository — CRUD for policies, approvals, and risk classifications.

Community provides the storage layer. Pro implements evaluation, approval
workflow, and risk classification via extension hooks.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from lumen_argus.analytics.base import BaseRepository

if TYPE_CHECKING:
    from lumen_argus.analytics.adapter import DatabaseAdapter

log = logging.getLogger("argus.analytics")


class MCPPoliciesRepository(BaseRepository):
    """Repository for MCP tool policies, approval queue, and risk classifications."""

    def __init__(self, adapter: DatabaseAdapter) -> None:
        super().__init__(adapter)

    # --- Tool policies ---

    def get_policies(self, namespace_id: int = 1) -> list[dict[str, Any]]:
        """Return all tool policies ordered by priority (descending)."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM mcp_tool_policies WHERE namespace_id = ? ORDER BY priority DESC, name",
                (namespace_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def create_policy(
        self,
        name: str,
        match_json: str,
        action: str,
        reason: str = "",
        severity: str = "medium",
        priority: int = 0,
        source: str = "dashboard",
        namespace_id: int = 1,
    ) -> int | None:
        """Create a new tool policy. Returns ID or None if name exists."""
        if not name:
            raise ValueError("policy name is required")
        if action not in ("allow", "block", "alert", "approval"):
            raise ValueError("action must be allow, block, alert, or approval")
        now = self._now()
        with self._adapter.write_lock():
            with self._connect() as conn:
                try:
                    cur = conn.execute(
                        "INSERT INTO mcp_tool_policies"
                        " (namespace_id, name, match_json, action, reason,"
                        " severity, priority, source, created_at, updated_at)"
                        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (namespace_id, name, match_json, action, reason, severity, priority, source, now, now),
                    )
                    log.info("tool policy created: %s (action=%s)", name, action)
                    return cur.lastrowid
                except Exception:
                    log.debug("tool policy create conflict: %s", name)
                    return None

    def update_policy(
        self,
        name: str,
        match_json: str | None = None,
        action: str | None = None,
        reason: str | None = None,
        severity: str | None = None,
        priority: int | None = None,
        enabled: bool | None = None,
        namespace_id: int = 1,
    ) -> bool:
        """Update an existing tool policy. Returns True if found."""
        updates: list[str] = []
        params: list[Any] = []
        if match_json is not None:
            updates.append("match_json = ?")
            params.append(match_json)
        if action is not None:
            if action not in ("allow", "block", "alert", "approval"):
                raise ValueError("action must be allow, block, alert, or approval")
            updates.append("action = ?")
            params.append(action)
        if reason is not None:
            updates.append("reason = ?")
            params.append(reason)
        if severity is not None:
            updates.append("severity = ?")
            params.append(severity)
        if priority is not None:
            updates.append("priority = ?")
            params.append(priority)
        if enabled is not None:
            updates.append("enabled = ?")
            params.append(int(enabled))
        if not updates:
            return False
        updates.append("updated_at = ?")
        params.append(self._now())
        params.extend([name, namespace_id])

        with self._adapter.write_lock():
            with self._connect() as conn:
                cur = conn.execute(
                    "UPDATE mcp_tool_policies SET %s WHERE name = ? AND namespace_id = ?" % ", ".join(updates),
                    params,
                )
                found = cur.rowcount > 0
        if found:
            log.info("tool policy updated: %s", name)
        return found

    def delete_policy(self, name: str, namespace_id: int = 1) -> bool:
        """Delete a tool policy by name. Returns True if found."""
        with self._adapter.write_lock():
            with self._connect() as conn:
                cur = conn.execute(
                    "DELETE FROM mcp_tool_policies WHERE name = ? AND namespace_id = ?",
                    (name, namespace_id),
                )
                found = cur.rowcount > 0
        if found:
            log.info("tool policy deleted: %s", name)
        return found

    def increment_hit_count(self, name: str, namespace_id: int = 1) -> None:
        """Increment hit count for a policy (called on each match)."""
        with self._adapter.write_lock():
            with self._connect() as conn:
                conn.execute(
                    "UPDATE mcp_tool_policies SET hit_count = hit_count + 1 WHERE name = ? AND namespace_id = ?",
                    (name, namespace_id),
                )

    # --- Approval queue ---

    def create_approval(
        self,
        approval_id: str,
        tool_name: str,
        arguments_hash: str,
        policy_name: str,
        expires_at: str,
        arguments_preview: str = "",
        server_id: str = "",
        session_id: str = "",
        identity: str = "",
        risk_level: str = "",
        namespace_id: int = 1,
    ) -> None:
        """Create a pending approval request."""
        now = self._now()
        with self._adapter.write_lock():
            with self._connect() as conn:
                conn.execute(
                    """INSERT INTO mcp_approval_queue
                    (id, namespace_id, tool_name, arguments_hash, arguments_preview,
                     server_id, session_id, identity, policy_name, risk_level,
                     status, requested_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)""",
                    (
                        approval_id,
                        namespace_id,
                        tool_name,
                        arguments_hash,
                        arguments_preview,
                        server_id,
                        session_id,
                        identity,
                        policy_name,
                        risk_level,
                        now,
                        expires_at,
                    ),
                )
        log.info("approval request created: %s for tool %s", approval_id, tool_name)

    def get_approvals(self, status: str | None = None, limit: int = 50, namespace_id: int = 1) -> list[dict[str, Any]]:
        """Return approval requests, optionally filtered by status."""
        with self._connect() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM mcp_approval_queue"
                    " WHERE namespace_id = ? AND status = ?"
                    " ORDER BY requested_at DESC LIMIT ?",
                    (namespace_id, status, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM mcp_approval_queue WHERE namespace_id = ? ORDER BY requested_at DESC LIMIT ?",
                    (namespace_id, limit),
                ).fetchall()
        return [dict(r) for r in rows]

    def update_approval_status(
        self,
        approval_id: str,
        status: str,
        decided_by: str = "",
        reason: str = "",
        namespace_id: int = 1,
    ) -> bool:
        """Update an approval decision. Returns True if found."""
        if status not in ("approved", "denied", "expired"):
            raise ValueError("status must be approved, denied, or expired")
        now = self._now()
        with self._adapter.write_lock():
            with self._connect() as conn:
                cur = conn.execute(
                    "UPDATE mcp_approval_queue SET status = ?, decided_at = ?,"
                    " decided_by = ?, decision_reason = ?"
                    " WHERE id = ? AND namespace_id = ?",
                    (status, now, decided_by, reason, approval_id, namespace_id),
                )
                found = cur.rowcount > 0
        if found:
            log.info("approval %s: %s (by %s)", approval_id, status, decided_by or "system")
        return found

    def cleanup_expired_approvals(self, namespace_id: int = 1) -> int:
        """Mark pending approvals past their expires_at as expired. Returns count."""
        now = self._now()
        with self._adapter.write_lock():
            with self._connect() as conn:
                cur = conn.execute(
                    "UPDATE mcp_approval_queue SET status = 'expired'"
                    " WHERE status = 'pending' AND expires_at < ? AND namespace_id = ?",
                    (now, namespace_id),
                )
                count = cur.rowcount
        if count:
            log.info("expired %d pending approval(s)", count)
        return count

    # --- Risk classifications ---

    def get_risk(self, tool_name: str, server_id: str = "", namespace_id: int = 1) -> dict[str, Any] | None:
        """Get risk classification for a tool. Returns dict or None."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM mcp_tool_risk WHERE tool_name = ? AND server_id = ? AND namespace_id = ?",
                (tool_name, server_id, namespace_id),
            ).fetchone()
        return dict(row) if row else None

    def get_all_risks(self, namespace_id: int = 1) -> list[dict[str, Any]]:
        """Return all risk classifications."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM mcp_tool_risk WHERE namespace_id = ? ORDER BY tool_name",
                (namespace_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def upsert_risk(
        self,
        tool_name: str,
        risk_level: str,
        server_id: str = "",
        auto_generated: bool = True,
        override_by: str = "",
        scores_json: str = "{}",
        namespace_id: int = 1,
    ) -> None:
        """Insert or update a risk classification."""
        if risk_level not in ("critical", "high", "medium", "low"):
            raise ValueError("risk_level must be critical, high, medium, or low")
        now = self._now()
        with self._adapter.write_lock():
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO mcp_tool_risk"
                    " (namespace_id, tool_name, server_id, risk_level,"
                    " auto_generated, override_by, override_at, scores_json)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                    " ON CONFLICT(namespace_id, tool_name, server_id) DO UPDATE SET"
                    " risk_level = excluded.risk_level,"
                    " auto_generated = excluded.auto_generated,"
                    " override_by = excluded.override_by,"
                    " override_at = excluded.override_at,"
                    " scores_json = excluded.scores_json",
                    (
                        namespace_id,
                        tool_name,
                        server_id,
                        risk_level,
                        int(auto_generated),
                        override_by,
                        now,
                        scores_json,
                    ),
                )
        log.debug("risk classification: %s = %s", tool_name, risk_level)
