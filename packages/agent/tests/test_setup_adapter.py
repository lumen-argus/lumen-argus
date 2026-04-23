"""Tests for the agent-side forward-proxy setup adapter.

The agent package registers its adapter at import time so that the core
setup wizard finds it via ``lumen_argus_core.forward_proxy.get_adapter()``.
These tests cover the registration side-effect and verify each adapter
method delegates to the corresponding :mod:`lumen_argus_agent.ca` function
without adding logic of its own.
"""

from __future__ import annotations

import unittest
from unittest import mock

from lumen_argus_agent import setup_adapter

from lumen_argus_core import forward_proxy


class TestSetupAdapterRegistration(unittest.TestCase):
    def setUp(self) -> None:
        # Re-assert the import-time side-effect. Other test modules may
        # have unregistered the adapter in their teardown — we want each
        # test here to express the post-import invariant independently.
        setup_adapter.install()

    def test_adapter_registered_after_install(self) -> None:
        adapter = forward_proxy.get_adapter()
        self.assertIsNotNone(adapter)
        self.assertIsInstance(adapter, setup_adapter._AgentForwardProxyAdapter)

    def test_install_re_registers_after_teardown(self) -> None:
        forward_proxy.unregister_adapter()
        self.assertIsNone(forward_proxy.get_adapter())
        setup_adapter.install()
        self.assertIsNotNone(forward_proxy.get_adapter())


class TestSetupAdapterDelegation(unittest.TestCase):
    """Each adapter method must call exactly one matching ca.py function."""

    def setUp(self) -> None:
        self.adapter = setup_adapter._AgentForwardProxyAdapter()

    def test_ca_exists_delegates(self) -> None:
        with mock.patch("lumen_argus_agent.ca.ca_exists", return_value=True) as m:
            self.assertTrue(self.adapter.ca_exists())
        m.assert_called_once_with()

    def test_ensure_ca_delegates(self) -> None:
        with mock.patch("lumen_argus_agent.ca.ensure_ca", return_value="/tmp/x") as m:
            self.assertEqual(self.adapter.ensure_ca(), "/tmp/x")
        m.assert_called_once_with()

    def test_get_ca_cert_path_delegates(self) -> None:
        with mock.patch("lumen_argus_agent.ca.get_ca_cert_path", return_value="/tmp/c") as m:
            self.assertEqual(self.adapter.get_ca_cert_path(), "/tmp/c")
        m.assert_called_once_with()

    def test_is_ca_trusted_delegates(self) -> None:
        with mock.patch("lumen_argus_agent.ca.is_ca_trusted", return_value=True) as m:
            self.assertTrue(self.adapter.is_ca_trusted())
        m.assert_called_once_with()

    def test_install_ca_system_delegates(self) -> None:
        with mock.patch("lumen_argus_agent.ca.install_ca_system", return_value=True) as m:
            self.assertTrue(self.adapter.install_ca_system())
        m.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
