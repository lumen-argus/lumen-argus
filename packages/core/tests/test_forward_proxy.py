"""Tests for the forward-proxy setup adapter registry.

The registry inverts the package dependency so core never imports the
agent package. These tests pin the public contract: registration,
unregistration, and the unavailable path that callers see when no
adapter has been installed (proxy-only PyInstaller bundles).
"""

from __future__ import annotations

import unittest

from lumen_argus_core import forward_proxy


class _StubAdapter:
    """Minimal adapter satisfying the Protocol for registry tests."""

    def __init__(self) -> None:
        self.ensure_calls = 0

    def ca_exists(self) -> bool:
        return True

    def ensure_ca(self) -> str:
        self.ensure_calls += 1
        return "/tmp/ca.pem"

    def get_ca_cert_path(self) -> str:
        return "/tmp/ca.pem"

    def is_ca_trusted(self) -> bool:
        return False

    def install_ca_system(self) -> bool:
        return True


class TestForwardProxyRegistry(unittest.TestCase):
    def setUp(self) -> None:
        # Save whatever the agent package registered at import time so
        # later tests (and other test modules) don't observe a wiped slate.
        self._saved = forward_proxy.get_adapter()
        forward_proxy.unregister_adapter()

    def tearDown(self) -> None:
        forward_proxy.unregister_adapter()
        if self._saved is not None:
            forward_proxy.register_adapter(self._saved)

    def test_get_adapter_returns_none_before_registration(self) -> None:
        self.assertIsNone(forward_proxy.get_adapter())

    def test_register_and_get_adapter(self) -> None:
        adapter = _StubAdapter()
        forward_proxy.register_adapter(adapter)
        self.assertIs(forward_proxy.get_adapter(), adapter)

    def test_register_replaces_previous_adapter(self) -> None:
        first = _StubAdapter()
        second = _StubAdapter()
        forward_proxy.register_adapter(first)
        forward_proxy.register_adapter(second)
        self.assertIs(forward_proxy.get_adapter(), second)

    def test_adapter_satisfies_protocol(self) -> None:
        """runtime_checkable Protocol allows isinstance check."""
        self.assertIsInstance(_StubAdapter(), forward_proxy.ForwardProxySetupAdapter)

    def test_unregister_clears_adapter(self) -> None:
        forward_proxy.register_adapter(_StubAdapter())
        forward_proxy.unregister_adapter()
        self.assertIsNone(forward_proxy.get_adapter())


if __name__ == "__main__":
    unittest.main()
