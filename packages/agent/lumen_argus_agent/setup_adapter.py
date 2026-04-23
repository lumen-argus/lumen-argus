"""Concrete forward-proxy setup adapter for ``lumen-argus-agent``.

Implements :class:`lumen_argus_core.forward_proxy.ForwardProxySetupAdapter`
by delegating to :mod:`lumen_argus_agent.ca`. The module self-registers on
import so that merely importing the agent package (which the agent CLI and
the agent PyInstaller bundle both do) wires forward-proxy setup into the
core wizard.

Proxy-only consumers (server/k8s PyInstaller bundle) never import this
module and therefore see ``get_adapter() is None`` — the wizard emits a
clean pointer to ``lumen-argus-agent`` instead of crashing.
"""

from __future__ import annotations

import logging

from lumen_argus_agent import ca
from lumen_argus_core.forward_proxy import ForwardProxySetupAdapter, register_adapter

log = logging.getLogger("argus.agent.setup_adapter")


class _AgentForwardProxyAdapter:
    """Thin delegating adapter. No state — safe to register as a singleton.

    Each method delegates to a single ``ca`` function. Exceptions propagate
    unchanged: the wizard layer logs and re-raises with context, so the
    adapter deliberately adds no try/except to avoid swallowing failures.
    """

    def ca_exists(self) -> bool:
        return ca.ca_exists()

    def ensure_ca(self) -> str:
        return ca.ensure_ca()

    def get_ca_cert_path(self) -> str:
        return ca.get_ca_cert_path()

    def is_ca_trusted(self) -> bool:
        return ca.is_ca_trusted()

    def install_ca_system(self) -> bool:
        return ca.install_ca_system()


_adapter: ForwardProxySetupAdapter = _AgentForwardProxyAdapter()


def install() -> None:
    """Register the agent's adapter with the core registry.

    Invoked at module import time; exposed as a public function so tests
    can re-install after explicit ``unregister_adapter`` teardown.
    """
    log.debug("installing agent forward-proxy adapter into core registry")
    register_adapter(_adapter)


install()
