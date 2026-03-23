"""Session binding — validate tools/call requests against tool inventory.

Captures tool names from the first tools/list response as the session
baseline. Subsequent tools/call requests must reference a tool in this
baseline. Unknown tools trigger a configurable action (warn or block).
"""

import logging

log = logging.getLogger("argus.mcp")

_MAX_BASELINE_TOOLS = 10_000


class SessionBinding:
    """Validate tool calls against the session's known tool inventory.

    Args:
        action: What to do for unknown tools — "warn" or "block".
    """

    def __init__(self, action: str = "warn"):
        self._known_tools = None  # type: Optional[Set[str]]
        self._action = action

    @property
    def is_bound(self) -> bool:
        """Whether a baseline has been established."""
        return self._known_tools is not None

    def set_baseline(self, tool_names: list) -> None:
        """Lock the session's tool inventory from first tools/list response.

        Only the first call takes effect — subsequent calls are ignored
        (tool inventory should not change mid-session).
        """
        if self._known_tools is not None:
            # Check for new tools added after baseline
            new_set = set(tool_names)
            added = new_set - self._known_tools
            if added:
                log.warning(
                    "mcp: %d new tool(s) appeared after baseline: %s",
                    len(added),
                    ", ".join(sorted(added)[:5]),
                )
            return

        if len(tool_names) > _MAX_BASELINE_TOOLS:
            log.warning(
                "mcp: tools/list returned %d tools (cap %d), truncating baseline",
                len(tool_names),
                _MAX_BASELINE_TOOLS,
            )
            tool_names = tool_names[:_MAX_BASELINE_TOOLS]

        self._known_tools = set(tool_names)
        log.info("mcp: session binding established with %d tools", len(self._known_tools))

    def validate_tool(self, tool_name: str) -> bool:
        """Check if a tool name is in the session baseline.

        Returns True if:
        - No baseline yet (validation not active)
        - Tool is in the known set

        Returns False if tool is unknown (not in baseline).
        """
        if self._known_tools is None:
            return True  # no baseline yet
        if tool_name in self._known_tools:
            return True
        log.warning("mcp: unknown tool '%s' (not in session baseline of %d tools)", tool_name, len(self._known_tools))
        return False

    @property
    def should_block(self) -> bool:
        """Whether unknown tools should be blocked (vs warned)."""
        return self._action == "block"
