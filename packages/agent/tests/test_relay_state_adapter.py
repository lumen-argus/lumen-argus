"""Tests for the agent-side relay-state provider.

Covers registration (side effect of agent package import) and
delegation (each provider method calls the corresponding
:mod:`lumen_argus_agent.relay` function without adding logic of its
own).
"""

from __future__ import annotations

import unittest
from unittest import mock

from lumen_argus_agent import relay_state_adapter

from lumen_argus_core import relay_state


class TestRelayStateProviderRegistration(unittest.TestCase):
    def setUp(self) -> None:
        # Re-assert the import-time side-effect. Other test modules may
        # have unregistered it in teardown — each test here expresses the
        # post-import invariant independently.
        relay_state_adapter.install()

    def test_provider_registered_after_install(self) -> None:
        provider = relay_state.get_provider()
        self.assertIsNotNone(provider)
        self.assertIsInstance(provider, relay_state_adapter._AgentRelayStateProvider)

    def test_install_re_registers_after_teardown(self) -> None:
        relay_state.unregister_provider()
        self.assertIsNone(relay_state.get_provider())
        relay_state_adapter.install()
        self.assertIsNotNone(relay_state.get_provider())


class TestRelayStateProviderDelegation(unittest.TestCase):
    """``load()`` calls exactly one matching ``relay.load_relay_state`` call."""

    def setUp(self) -> None:
        self.provider = relay_state_adapter._AgentRelayStateProvider()

    def test_load_delegates_with_state(self) -> None:
        expected = {"port": 8070, "pid": 9999}
        with mock.patch("lumen_argus_agent.relay_state_adapter.load_relay_state", return_value=expected) as m:
            self.assertEqual(self.provider.load(), expected)
        m.assert_called_once_with()

    def test_load_delegates_with_none(self) -> None:
        with mock.patch("lumen_argus_agent.relay_state_adapter.load_relay_state", return_value=None) as m:
            self.assertIsNone(self.provider.load())
        m.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
