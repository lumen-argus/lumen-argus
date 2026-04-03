"""Base repository — shared database access for all analytics repositories.

Repos extend BaseRepository and receive the DatabaseAdapter directly.
No coupling to AnalyticsStore internals.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from lumen_argus_core.time_utils import now_iso

if TYPE_CHECKING:
    from lumen_argus.analytics.adapter import DatabaseAdapter, DBConnection


class BaseRepository:
    """Base class for analytics repositories.

    Provides direct adapter access: connections, write locking,
    SQL dialect methods, and timestamp generation.
    """

    def __init__(self, adapter: DatabaseAdapter) -> None:
        self._adapter = adapter

    def _connect(self) -> DBConnection:
        """Get a database connection from the adapter."""
        return self._adapter.connect()

    def _now(self) -> str:
        """Current ISO 8601 timestamp (second precision)."""
        return now_iso()
