"""Tests for MCP tool policy evaluator and approval gate integration in _check_tools_call."""

import asyncio
import unittest
from dataclasses import dataclass
from typing import Any

from lumen_argus.allowlist import AllowlistMatcher
from lumen_argus.mcp.proxy._scanning import _check_tools_call, _run_tool_policy_evaluator
from lumen_argus.mcp.scanner import MCPScanner


def _make_scanner(**kwargs: Any) -> MCPScanner:
    """Create a minimal MCPScanner for testing."""
    defaults: dict[str, Any] = {
        "detectors": [],
        "allowlist": AllowlistMatcher([]),
        "scan_arguments": False,
        "scan_responses": False,
    }
    defaults.update(kwargs)
    return MCPScanner(**defaults)


def _make_tools_call(tool_name: str = "write_file", arguments: dict | None = None) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments or {}},
    }


@dataclass
class FakePolicyDecision:
    action: str
    policy_name: str = ""
    reason: str = ""
    matched_policy: str = ""


@dataclass
class FakeApprovalDecision:
    status: str
    approval_id: str = "apr_test123"


class FakeEvaluator:
    """Fake tool policy evaluator for testing."""

    def __init__(self, decision: FakePolicyDecision) -> None:
        self.decision = decision
        self.calls: list[tuple] = []

    def evaluate(self, tool_name: str, arguments: dict, server_id: str, context: dict) -> FakePolicyDecision:
        self.calls.append((tool_name, arguments, server_id, context))
        return self.decision


class FakeApprovalGate:
    """Fake approval gate for testing."""

    def __init__(self, decision: FakeApprovalDecision) -> None:
        self.decision = decision
        self.calls: list[tuple] = []

    async def request_approval(
        self,
        tool_name: str,
        arguments: dict,
        server_id: str,
        session_id: str,
        identity: str,
        client_name: str,
        policy: Any,
    ) -> FakeApprovalDecision:
        self.calls.append((tool_name, arguments, server_id, session_id, identity, client_name, policy))
        return self.decision


class TestToolPolicyEvaluatorIntegration(unittest.TestCase):
    """Test ABAC tool policy evaluator in _check_tools_call pipeline."""

    def _run(self, coro: Any) -> Any:
        return asyncio.run(coro)

    def test_no_evaluator_passes_through(self):
        scanner = _make_scanner()
        msg = _make_tools_call()
        result = self._run(_check_tools_call(msg, scanner, "block", None, None))
        self.assertIsNone(result)

    def test_allow_decision_passes_through(self):
        scanner = _make_scanner()
        evaluator = FakeEvaluator(FakePolicyDecision(action="allow"))
        msg = _make_tools_call()
        result = self._run(_check_tools_call(msg, scanner, "block", None, None, tool_policy_evaluator=evaluator))
        self.assertIsNone(result)
        self.assertEqual(len(evaluator.calls), 1)
        self.assertEqual(evaluator.calls[0][0], "write_file")

    def test_block_decision_returns_error(self):
        scanner = _make_scanner()
        evaluator = FakeEvaluator(
            FakePolicyDecision(action="block", policy_name="no-fs-write", reason="File writes prohibited")
        )
        msg = _make_tools_call()
        result = self._run(_check_tools_call(msg, scanner, "block", None, None, tool_policy_evaluator=evaluator))
        self.assertIsNotNone(result)
        self.assertIn("error", result)
        self.assertIn("File writes prohibited", result["error"]["message"])

    def test_alert_decision_passes_through(self):
        scanner = _make_scanner()
        evaluator = FakeEvaluator(
            FakePolicyDecision(action="alert", policy_name="monitor-shell", reason="Shell access logged")
        )
        msg = _make_tools_call("execute_command")
        result = self._run(_check_tools_call(msg, scanner, "block", None, None, tool_policy_evaluator=evaluator))
        self.assertIsNone(result)

    def test_evaluator_receives_context(self):
        scanner = _make_scanner()
        evaluator = FakeEvaluator(FakePolicyDecision(action="allow"))
        msg = _make_tools_call("read_file", {"path": "/etc/passwd"})
        self._run(
            _check_tools_call(
                msg,
                scanner,
                "block",
                None,
                None,
                session_id="sess_abc",
                tool_policy_evaluator=evaluator,
            )
        )
        self.assertEqual(evaluator.calls[0][0], "read_file")
        self.assertEqual(evaluator.calls[0][1], {"path": "/etc/passwd"})
        self.assertEqual(evaluator.calls[0][3], {"session_id": "sess_abc"})

    def test_evaluator_exception_treated_as_allow(self):
        """Evaluator failure must not block tool calls (fail-open)."""
        scanner = _make_scanner()

        class BrokenEvaluator:
            def evaluate(self, *a: Any, **kw: Any) -> None:
                raise RuntimeError("evaluator crashed")

        msg = _make_tools_call()
        result = self._run(
            _check_tools_call(msg, scanner, "block", None, None, tool_policy_evaluator=BrokenEvaluator())
        )
        self.assertIsNone(result)

    def test_block_fires_escalation(self):
        scanner = _make_scanner()
        evaluator = FakeEvaluator(FakePolicyDecision(action="block", policy_name="deny-all", reason="Denied"))
        signals: list[tuple] = []

        def capture_escalation(signal_type: str, session_id: str, details: dict) -> str:
            signals.append((signal_type, session_id, details))
            return "normal"

        msg = _make_tools_call()
        self._run(
            _check_tools_call(
                msg,
                scanner,
                "block",
                None,
                capture_escalation,
                session_id="s1",
                tool_policy_evaluator=evaluator,
            )
        )
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0][0], "block")
        self.assertEqual(signals[0][2]["policy"], "deny-all")


class TestApprovalGateIntegration(unittest.TestCase):
    """Test approval gate in _check_tools_call pipeline."""

    def _run(self, coro: Any) -> Any:
        return asyncio.run(coro)

    def test_approval_action_approved_passes_through(self):
        scanner = _make_scanner()
        evaluator = FakeEvaluator(FakePolicyDecision(action="approval", policy_name="require-approval"))
        gate = FakeApprovalGate(FakeApprovalDecision(status="approved"))
        msg = _make_tools_call()
        result = self._run(
            _check_tools_call(
                msg,
                scanner,
                "block",
                None,
                None,
                tool_policy_evaluator=evaluator,
                approval_gate=gate,
            )
        )
        self.assertIsNone(result)
        self.assertEqual(len(gate.calls), 1)
        self.assertEqual(gate.calls[0][0], "write_file")

    def test_approval_action_denied_returns_error(self):
        scanner = _make_scanner()
        evaluator = FakeEvaluator(FakePolicyDecision(action="approval", policy_name="require-approval"))
        gate = FakeApprovalGate(FakeApprovalDecision(status="denied", approval_id="apr_xyz"))
        msg = _make_tools_call()
        result = self._run(
            _check_tools_call(
                msg,
                scanner,
                "block",
                None,
                None,
                tool_policy_evaluator=evaluator,
                approval_gate=gate,
            )
        )
        self.assertIsNotNone(result)
        self.assertIn("denied", result["error"]["message"])
        self.assertIn("apr_xyz", result["error"]["message"])

    def test_approval_action_expired_returns_error(self):
        scanner = _make_scanner()
        evaluator = FakeEvaluator(FakePolicyDecision(action="approval", policy_name="require-approval"))
        gate = FakeApprovalGate(FakeApprovalDecision(status="expired", approval_id="apr_exp"))
        msg = _make_tools_call()
        result = self._run(
            _check_tools_call(
                msg,
                scanner,
                "block",
                None,
                None,
                tool_policy_evaluator=evaluator,
                approval_gate=gate,
            )
        )
        self.assertIsNotNone(result)
        self.assertIn("expired", result["error"]["message"])

    def test_no_gate_with_approval_action_passes_through(self):
        """If evaluator says 'approval' but no gate is registered, pass through."""
        scanner = _make_scanner()
        evaluator = FakeEvaluator(FakePolicyDecision(action="approval", policy_name="require-approval"))
        msg = _make_tools_call()
        result = self._run(
            _check_tools_call(
                msg,
                scanner,
                "block",
                None,
                None,
                tool_policy_evaluator=evaluator,
                approval_gate=None,
            )
        )
        self.assertIsNone(result)

    def test_gate_exception_treated_as_allow(self):
        """Gate failure must not block tool calls (fail-open)."""
        scanner = _make_scanner()
        evaluator = FakeEvaluator(FakePolicyDecision(action="approval", policy_name="require-approval"))

        class BrokenGate:
            async def request_approval(self, *a: Any, **kw: Any) -> None:
                raise RuntimeError("gate crashed")

        msg = _make_tools_call()
        result = self._run(
            _check_tools_call(
                msg,
                scanner,
                "block",
                None,
                None,
                tool_policy_evaluator=evaluator,
                approval_gate=BrokenGate(),
            )
        )
        self.assertIsNone(result)

    def test_gate_receives_policy_name(self):
        scanner = _make_scanner()
        evaluator = FakeEvaluator(
            FakePolicyDecision(action="approval", policy_name="gate-fs-ops", matched_policy="gate-fs-ops")
        )
        gate = FakeApprovalGate(FakeApprovalDecision(status="approved"))
        msg = _make_tools_call()
        self._run(
            _check_tools_call(
                msg,
                scanner,
                "block",
                None,
                None,
                session_id="s1",
                tool_policy_evaluator=evaluator,
                approval_gate=gate,
            )
        )
        # policy arg should be the matched_policy
        self.assertEqual(gate.calls[0][6], "gate-fs-ops")


class TestPipelineOrder(unittest.TestCase):
    """Test that the pipeline stages execute in the correct order."""

    def _run(self, coro: Any) -> Any:
        return asyncio.run(coro)

    def test_policy_evaluator_runs_before_legacy_engine(self):
        """ABAC evaluator block should short-circuit before legacy engine runs."""
        scanner = _make_scanner()
        evaluator = FakeEvaluator(
            FakePolicyDecision(action="block", policy_name="abac-block", reason="Blocked by ABAC")
        )

        legacy_calls: list[tuple] = []

        class TrackingLegacyEngine:
            def evaluate(self, tool_name: str, arguments: dict) -> list:
                legacy_calls.append((tool_name, arguments))
                return []

        msg = _make_tools_call()
        result = self._run(
            _check_tools_call(
                msg,
                scanner,
                "block",
                TrackingLegacyEngine(),
                None,
                tool_policy_evaluator=evaluator,
            )
        )
        self.assertIsNotNone(result)
        self.assertEqual(len(legacy_calls), 0, "Legacy engine should not run when ABAC blocks")

    def test_allow_decision_continues_to_scanner(self):
        """ABAC allow should still run DLP scanning."""
        from lumen_argus.detectors.secrets import SecretsDetector

        scanner = _make_scanner(detectors=[SecretsDetector()], scan_arguments=True)
        evaluator = FakeEvaluator(FakePolicyDecision(action="allow"))

        msg = _make_tools_call("write_file", {"content": "AKIAIOSFODNN7EXAMPLE"})
        result = self._run(
            _check_tools_call(
                msg,
                scanner,
                "block",
                None,
                None,
                tool_policy_evaluator=evaluator,
            )
        )
        # DLP should catch the AWS key and block
        self.assertIsNotNone(result)
        self.assertIn("sensitive data", result["error"]["message"])


class TestRunToolPolicyEvaluator(unittest.TestCase):
    """Test _run_tool_policy_evaluator helper directly."""

    def test_none_evaluator(self):
        self.assertIsNone(_run_tool_policy_evaluator(None, "tool", {}, "", {}))

    def test_returns_decision(self):
        decision = FakePolicyDecision(action="block")
        evaluator = FakeEvaluator(decision)
        result = _run_tool_policy_evaluator(evaluator, "tool", {"a": 1}, "srv1", {"k": "v"})
        self.assertIs(result, decision)

    def test_exception_returns_none(self):
        class Bad:
            def evaluate(self, *a: Any, **kw: Any) -> None:
                raise ValueError("boom")

        self.assertIsNone(_run_tool_policy_evaluator(Bad(), "tool", {}, "", {}))


if __name__ == "__main__":
    unittest.main()
