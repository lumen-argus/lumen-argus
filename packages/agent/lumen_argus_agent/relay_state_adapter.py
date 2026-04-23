"""Concrete relay-state provider for ``lumen-argus-agent``.

Delegates to :func:`lumen_argus_agent.relay.load_relay_state`. The module
self-registers on import so the agent package wires itself into the core
registry without an explicit init step — proxy-only consumers never
import this module and therefore see ``get_provider() is None``, which
:func:`lumen_argus_core.relay_service.get_service_status` treats as
"relay not installed".
"""

from __future__ import annotations

import logging
from typing import Any

from lumen_argus_agent.relay import load_relay_state
from lumen_argus_core.relay_state import register_provider

log = logging.getLogger("argus.agent.relay_state_adapter")


class _AgentRelayStateProvider:
    """Thin delegating provider. No state — safe to register as a singleton."""

    def load(self) -> dict[str, Any] | None:
        return load_relay_state()


_provider = _AgentRelayStateProvider()


def install() -> None:
    """Register the agent's relay-state provider with the core registry.

    Invoked at module import time; exposed as a public function so tests
    can re-install after explicit :func:`unregister_provider` teardown.
    """
    log.debug("installing agent relay-state provider into core registry")
    register_provider(_provider)


install()
