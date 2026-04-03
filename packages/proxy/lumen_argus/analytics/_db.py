"""Shared database utilities for analytics repositories."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lumen_argus.analytics.adapter import DBConnection


def scalar(conn: DBConnection, sql: str, params: tuple[object, ...] = ()) -> int:
    """Execute a query expected to return a single integer value (e.g. COUNT(*)).

    Returns 0 if the query returns no rows or a NULL value.
    """
    row: Any = conn.execute(sql, params).fetchone()
    return int(row[0]) if row and row[0] is not None else 0
