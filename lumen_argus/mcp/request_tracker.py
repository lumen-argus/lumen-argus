"""Confused deputy protection — track outbound request IDs and reject unsolicited responses.

Prevents a malicious MCP server from injecting responses for requests
the client never sent. Uses FIFO eviction to bound memory.
"""

from __future__ import annotations

import json
import logging
from collections import OrderedDict
from typing import Any

log = logging.getLogger("argus.mcp")

_MAX_TRACKED = 10_000


class RequestTracker:
    """Track outgoing JSON-RPC request IDs and validate incoming response IDs.

    Args:
        action: What to do on unsolicited response — "warn" (log + forward)
                or "block" (drop + log). Default: "warn".
    """

    def __init__(self, action: str = "warn") -> None:
        self._pending: OrderedDict[str, bool] = OrderedDict()  # id_key -> True, insertion order
        self._seeded = False
        self._action = action

    def track(self, msg_id: Any) -> None:
        """Record an outbound request ID before forwarding to server.

        Null/None IDs are ignored (JSON-RPC notifications have no response).
        """
        if msg_id is None:
            return
        key = self._normalize_id(msg_id)
        self._pending[key] = True
        self._seeded = True
        # FIFO eviction
        while len(self._pending) > _MAX_TRACKED:
            self._pending.popitem(last=False)

    def validate(self, msg_id: Any) -> bool:
        """Check if an inbound response ID was previously tracked.

        Returns True if valid (ID was tracked, or validation not yet active).
        Returns False if unsolicited (ID was never tracked).

        One-shot: validated IDs are consumed (removed from tracking).
        Null/None IDs always pass (notifications).
        """
        if msg_id is None:
            return True
        if not self._seeded:
            return True  # grace period before first tracked request
        key = self._normalize_id(msg_id)
        if key in self._pending:
            del self._pending[key]
            return True
        log.warning("mcp: unsolicited response ID %s (not in tracked requests)", msg_id)
        return False

    @property
    def should_block(self) -> bool:
        """Whether unsolicited responses should be blocked (vs warned)."""
        return self._action == "block"

    @staticmethod
    def _normalize_id(msg_id: Any) -> str:
        """Normalize ID to string key for dict lookup.

        JSON-RPC IDs can be string, number, or null. We serialize to
        JSON to preserve type distinction (numeric 1 != string "1").
        """
        return json.dumps(msg_id, separators=(",", ":"))
