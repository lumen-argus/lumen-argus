"""Relay runtime-state provider registry.

:func:`lumen_argus_core.relay_service.get_service_status` needs the
running relay's port / upstream / PID without importing from the agent
package — core must not depend on agent (see ``test_module_boundaries``).
The agent package implements :class:`RelayStateProvider` and registers
it at import time; core reads through :func:`get_provider` and treats a
missing provider as "relay not installed".

Matches the inversion pattern used by
:mod:`lumen_argus_core.forward_proxy` for the setup-adapter registry.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol, runtime_checkable

log = logging.getLogger("argus.core.relay_state")


@runtime_checkable
class RelayStateProvider(Protocol):
    """Contract for reading the agent relay's runtime state from disk."""

    def load(self) -> dict[str, Any] | None:
        """Return the running relay's state dict, or ``None`` if not running.

        The provider is expected to validate the recorded PID and drop
        stale state so callers never observe a phantom relay.
        """


_provider: RelayStateProvider | None = None


def register_provider(provider: RelayStateProvider) -> None:
    """Register the relay-state provider.

    Called once at agent-package import time. Re-registration replaces
    the previous provider and logs the swap at DEBUG — normal during
    tests, a smell in production.
    """
    global _provider
    if _provider is not None and _provider is not provider:
        log.debug(
            "replacing relay-state provider: previous=%s new=%s",
            type(_provider).__name__,
            type(provider).__name__,
        )
    else:
        log.info("relay-state provider registered: %s", type(provider).__name__)
    _provider = provider


def unregister_provider() -> None:
    """Remove the registered provider. Intended for test teardown."""
    global _provider
    if _provider is not None:
        log.debug("relay-state provider unregistered: %s", type(_provider).__name__)
    _provider = None


def get_provider() -> RelayStateProvider | None:
    """Return the registered provider, or ``None`` when the agent is absent."""
    return _provider
