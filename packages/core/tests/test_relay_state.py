"""Tests for the relay-state provider registry.

The registry inverts the core→agent dependency for ``get_service_status``
— core never imports the agent package. Tests pin the public contract:
register / unregister / get-when-empty / replace. Agent-side adapter
tests live in ``packages/agent/tests/test_relay_state_adapter.py``.
"""

from __future__ import annotations

import unittest
from typing import Any

from lumen_argus_core import relay_state


class _StubProvider:
    """Minimal provider satisfying the Protocol."""

    def __init__(self, state: dict[str, Any] | None = None) -> None:
        self._state = state
        self.load_calls = 0

    def load(self) -> dict[str, Any] | None:
        self.load_calls += 1
        return self._state


class TestRelayStateRegistry(unittest.TestCase):
    def setUp(self) -> None:
        # Save whatever the agent package registered at import time so
        # other test modules don't observe a wiped slate.
        self._saved = relay_state.get_provider()
        relay_state.unregister_provider()

    def tearDown(self) -> None:
        relay_state.unregister_provider()
        if self._saved is not None:
            relay_state.register_provider(self._saved)

    def test_get_provider_returns_none_before_registration(self) -> None:
        self.assertIsNone(relay_state.get_provider())

    def test_register_and_get_provider(self) -> None:
        p = _StubProvider()
        relay_state.register_provider(p)
        self.assertIs(relay_state.get_provider(), p)

    def test_register_replaces_previous_provider(self) -> None:
        first = _StubProvider()
        second = _StubProvider()
        relay_state.register_provider(first)
        relay_state.register_provider(second)
        self.assertIs(relay_state.get_provider(), second)

    def test_provider_satisfies_protocol(self) -> None:
        self.assertIsInstance(_StubProvider(), relay_state.RelayStateProvider)

    def test_unregister_clears_provider(self) -> None:
        relay_state.register_provider(_StubProvider())
        relay_state.unregister_provider()
        self.assertIsNone(relay_state.get_provider())


class TestRelayServiceIntegration(unittest.TestCase):
    """``relay_service.get_service_status`` dispatches through the registry."""

    def setUp(self) -> None:
        self._saved = relay_state.get_provider()
        relay_state.unregister_provider()

    def tearDown(self) -> None:
        relay_state.unregister_provider()
        if self._saved is not None:
            relay_state.register_provider(self._saved)

    def test_no_provider_reports_running_unknown(self) -> None:
        from lumen_argus_core.relay_service import get_service_status

        status = get_service_status()
        self.assertEqual(status["running"], "unknown")

    def test_provider_returning_state_reports_running_true(self) -> None:
        from lumen_argus_core.relay_service import get_service_status

        relay_state.register_provider(_StubProvider({"port": 8070, "upstream_url": "http://proxy:8080", "pid": 1234}))
        status = get_service_status()
        self.assertEqual(status["running"], "true")
        self.assertEqual(status["port"], "8070")
        self.assertEqual(status["upstream_url"], "http://proxy:8080")
        self.assertEqual(status["pid"], "1234")

    def test_provider_returning_none_reports_running_false(self) -> None:
        from lumen_argus_core.relay_service import get_service_status

        relay_state.register_provider(_StubProvider(None))
        status = get_service_status()
        self.assertEqual(status["running"], "false")

    def test_provider_raising_reports_running_unknown(self) -> None:
        from lumen_argus_core.relay_service import get_service_status

        class _Broken:
            def load(self) -> dict[str, Any] | None:
                raise RuntimeError("disk error")

        relay_state.register_provider(_Broken())
        with self.assertLogs("argus.relay.service", level="WARNING"):
            status = get_service_status()
        self.assertEqual(status["running"], "unknown")


if __name__ == "__main__":
    unittest.main()
