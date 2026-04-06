"""Fleet MCP policy loader — reads cached policies from disk.

Policies are pushed by the Pro proxy via enrollment config and heartbeat
responses, cached locally at ``~/.lumen-argus/mcp_policies.json`` by the
tray app or agent. This module provides read-only access to those policies
for use during MCP server wrapping (``setup --mcp``).

Policy file format::

    {
        "version": "2026-04-06T14:30:00Z",
        "source": "fleet",
        "server_policies": [
            {"server_name": "filesystem", "policy": "must_scan"},
            {"server_name": "internal-db", "policy": "blocked", "reason": "security risk"}
        ],
        "tool_policies": [...],
        "default_action": "allow"
    }

Server policy actions: ``allowed``, ``blocked``, ``must_scan``, ``review``.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field

log = logging.getLogger("argus.fleet_policies")

_POLICIES_PATH = "~/.lumen-argus/mcp_policies.json"

# Valid server policy values
_VALID_POLICIES = {"allowed", "blocked", "must_scan", "review"}

# Valid default_action values
_VALID_DEFAULT_ACTIONS = {"allow", "block"}


@dataclass(frozen=True)
class ServerPolicy:
    """A single fleet server policy entry."""

    server_name: str
    policy: str = "allowed"  # allowed | blocked | must_scan | review
    reason: str = ""


@dataclass
class FleetPolicies:
    """Fleet MCP policies loaded from disk."""

    version: str = ""
    source: str = ""
    server_policies: list[ServerPolicy] = field(default_factory=list)
    default_action: str = "allow"

    def get_server_policy(self, server_name: str) -> str | None:
        """Return the policy for a server name, or None if no match."""
        for sp in self.server_policies:
            if sp.server_name == server_name:
                return sp.policy
        return None


def load_fleet_policies(path: str | None = None) -> FleetPolicies | None:
    """Load fleet MCP policies from disk.

    Args:
        path: Override path (for testing). Defaults to ``~/.lumen-argus/mcp_policies.json``.

    Returns:
        FleetPolicies if file exists and is valid, None otherwise.
    """
    expanded = os.path.expanduser(path or _POLICIES_PATH)
    if not os.path.isfile(expanded):
        log.debug("no fleet policies at %s", expanded)
        return None

    try:
        with open(expanded, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        log.warning("could not read fleet policies from %s: %s", expanded, e)
        return None

    if not isinstance(data, dict):
        log.warning("fleet policies file is not a JSON object: %s", expanded)
        return None

    server_policies: list[ServerPolicy] = []
    raw_policies = data.get("server_policies", [])
    if not isinstance(raw_policies, list):
        log.warning("server_policies is not a list in %s", expanded)
        raw_policies = []

    for entry in raw_policies:
        if not isinstance(entry, dict):
            continue
        name = entry.get("server_name", "")
        policy = entry.get("policy", "")
        if not name or policy not in _VALID_POLICIES:
            log.warning("skipping invalid server policy: %s", entry)
            continue
        server_policies.append(
            ServerPolicy(
                server_name=name,
                policy=policy,
                reason=entry.get("reason", ""),
            )
        )

    default_action = data.get("default_action", "allow")
    if default_action not in _VALID_DEFAULT_ACTIONS:
        log.warning("invalid default_action %r — defaulting to 'allow'", default_action)
        default_action = "allow"

    policies = FleetPolicies(
        version=data.get("version", ""),
        source=data.get("source", ""),
        server_policies=server_policies,
        default_action=default_action,
    )

    log.info(
        "loaded fleet policies: %d server rule(s), version=%s",
        len(server_policies),
        policies.version,
    )
    return policies
