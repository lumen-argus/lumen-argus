"""Tests for MCP tool approval infrastructure — schema, repository, config, 402 stubs."""

import unittest

from lumen_argus.config import Config
from lumen_argus.config._apply import _apply_config
from lumen_argus.dashboard.api import handle_community_api
from lumen_argus.extensions import ExtensionRegistry
from tests.helpers import StoreTestCase


class TestMCPPoliciesRepository(StoreTestCase):
    """Test MCPPoliciesRepository CRUD operations."""

    # --- Tool policies ---

    def test_create_policy(self):
        pid = self.store.mcp_policies.create_policy(
            name="block-shell",
            match_json='{"tool": ["execute_command"]}',
            action="block",
            reason="Shell execution prohibited",
        )
        self.assertIsNotNone(pid)

    def test_create_duplicate_returns_none(self):
        self.store.mcp_policies.create_policy(name="p1", match_json="{}", action="allow")
        dup = self.store.mcp_policies.create_policy(name="p1", match_json="{}", action="block")
        self.assertIsNone(dup)

    def test_create_invalid_action_raises(self):
        with self.assertRaises(ValueError):
            self.store.mcp_policies.create_policy(name="bad", match_json="{}", action="invalid")

    def test_create_empty_name_raises(self):
        with self.assertRaises(ValueError):
            self.store.mcp_policies.create_policy(name="", match_json="{}", action="allow")

    def test_get_policies(self):
        self.store.mcp_policies.create_policy(name="p1", match_json="{}", action="allow", priority=10)
        self.store.mcp_policies.create_policy(name="p2", match_json="{}", action="block", priority=20)
        policies = self.store.mcp_policies.get_policies()
        self.assertEqual(len(policies), 2)
        # Higher priority first
        self.assertEqual(policies[0]["name"], "p2")
        self.assertEqual(policies[1]["name"], "p1")

    def test_update_policy(self):
        self.store.mcp_policies.create_policy(name="p1", match_json="{}", action="allow")
        updated = self.store.mcp_policies.update_policy("p1", action="block", reason="changed")
        self.assertTrue(updated)
        policies = self.store.mcp_policies.get_policies()
        self.assertEqual(policies[0]["action"], "block")
        self.assertEqual(policies[0]["reason"], "changed")

    def test_update_nonexistent_returns_false(self):
        self.assertFalse(self.store.mcp_policies.update_policy("nope", action="block"))

    def test_update_invalid_action_raises(self):
        self.store.mcp_policies.create_policy(name="p1", match_json="{}", action="allow")
        with self.assertRaises(ValueError):
            self.store.mcp_policies.update_policy("p1", action="invalid")

    def test_delete_policy(self):
        self.store.mcp_policies.create_policy(name="p1", match_json="{}", action="allow")
        self.assertTrue(self.store.mcp_policies.delete_policy("p1"))
        self.assertEqual(len(self.store.mcp_policies.get_policies()), 0)

    def test_delete_nonexistent_returns_false(self):
        self.assertFalse(self.store.mcp_policies.delete_policy("nope"))

    def test_increment_hit_count(self):
        self.store.mcp_policies.create_policy(name="p1", match_json="{}", action="block")
        self.store.mcp_policies.increment_hit_count("p1")
        self.store.mcp_policies.increment_hit_count("p1")
        policies = self.store.mcp_policies.get_policies()
        self.assertEqual(policies[0]["hit_count"], 2)

    # --- Approval queue ---

    def test_create_and_get_approval(self):
        self.store.mcp_policies.create_approval(
            approval_id="apr_test123",
            tool_name="write_file",
            arguments_hash="abc123",
            policy_name="gate-fs-write",
            expires_at="2099-01-01T00:00:00Z",
        )
        approvals = self.store.mcp_policies.get_approvals()
        self.assertEqual(len(approvals), 1)
        self.assertEqual(approvals[0]["tool_name"], "write_file")
        self.assertEqual(approvals[0]["status"], "pending")

    def test_get_approvals_filter_by_status(self):
        self.store.mcp_policies.create_approval(
            approval_id="apr_1",
            tool_name="t1",
            arguments_hash="h1",
            policy_name="p1",
            expires_at="2099-01-01T00:00:00Z",
        )
        self.store.mcp_policies.update_approval_status("apr_1", "approved", decided_by="admin")

        pending = self.store.mcp_policies.get_approvals(status="pending")
        approved = self.store.mcp_policies.get_approvals(status="approved")
        self.assertEqual(len(pending), 0)
        self.assertEqual(len(approved), 1)

    def test_update_approval_status(self):
        self.store.mcp_policies.create_approval(
            approval_id="apr_2",
            tool_name="t",
            arguments_hash="h",
            policy_name="p",
            expires_at="2099-01-01T00:00:00Z",
        )
        result = self.store.mcp_policies.update_approval_status(
            "apr_2", "denied", decided_by="admin@co.com", reason="Too risky"
        )
        self.assertTrue(result)

        approvals = self.store.mcp_policies.get_approvals()
        self.assertEqual(approvals[0]["status"], "denied")
        self.assertEqual(approvals[0]["decided_by"], "admin@co.com")
        self.assertEqual(approvals[0]["decision_reason"], "Too risky")

    def test_update_approval_invalid_status_raises(self):
        with self.assertRaises(ValueError):
            self.store.mcp_policies.update_approval_status("apr_x", "invalid")

    def test_cleanup_expired_approvals(self):
        self.store.mcp_policies.create_approval(
            approval_id="apr_old",
            tool_name="t",
            arguments_hash="h",
            policy_name="p",
            expires_at="2020-01-01T00:00:00Z",
        )
        self.store.mcp_policies.create_approval(
            approval_id="apr_future",
            tool_name="t2",
            arguments_hash="h2",
            policy_name="p2",
            expires_at="2099-01-01T00:00:00Z",
        )
        expired = self.store.mcp_policies.cleanup_expired_approvals()
        self.assertEqual(expired, 1)
        remaining = self.store.mcp_policies.get_approvals(status="pending")
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]["id"], "apr_future")

    # --- Risk classifications ---

    def test_upsert_and_get_risk(self):
        self.store.mcp_policies.upsert_risk("write_file", "high")
        risk = self.store.mcp_policies.get_risk("write_file")
        self.assertIsNotNone(risk)
        self.assertEqual(risk["risk_level"], "high")
        self.assertEqual(risk["auto_generated"], 1)

    def test_upsert_risk_update(self):
        self.store.mcp_policies.upsert_risk("tool", "low")
        self.store.mcp_policies.upsert_risk("tool", "critical", auto_generated=False, override_by="admin")
        risk = self.store.mcp_policies.get_risk("tool")
        self.assertEqual(risk["risk_level"], "critical")
        self.assertEqual(risk["auto_generated"], 0)
        self.assertEqual(risk["override_by"], "admin")

    def test_upsert_risk_invalid_level_raises(self):
        with self.assertRaises(ValueError):
            self.store.mcp_policies.upsert_risk("tool", "extreme")

    def test_get_all_risks(self):
        self.store.mcp_policies.upsert_risk("tool_a", "low")
        self.store.mcp_policies.upsert_risk("tool_b", "high")
        risks = self.store.mcp_policies.get_all_risks()
        self.assertEqual(len(risks), 2)

    def test_get_risk_not_found(self):
        self.assertIsNone(self.store.mcp_policies.get_risk("nonexistent"))


class TestToolApprovalConfigParsing(unittest.TestCase):
    """Test YAML config parsing for tool approval fields."""

    def test_default_tool_action_parsed(self):
        config = Config()
        _apply_config(config, {"mcp": {"default_tool_action": "block"}})
        self.assertEqual(config.mcp.default_tool_action, "block")

    def test_enable_risk_classification_parsed(self):
        config = Config()
        _apply_config(config, {"mcp": {"enable_risk_classification": True}})
        self.assertTrue(config.mcp.enable_risk_classification)

    def test_approval_mode_parsed(self):
        config = Config()
        _apply_config(config, {"mcp": {"approval_mode": "webhook"}})
        self.assertEqual(config.mcp.approval_mode, "webhook")

    def test_defaults_unchanged(self):
        config = Config()
        self.assertEqual(config.mcp.default_tool_action, "allow")
        self.assertFalse(config.mcp.enable_risk_classification)
        self.assertEqual(config.mcp.approval_mode, "dashboard")


class TestPluginOnlyEndpointsAreUnknownInCommunity(StoreTestCase):
    """Plugin-owned MCP routes return 404 when no plugin handler intercepts them.

    Pro and other plugins register their handler via
    `extensions.register_dashboard_api(...)`; server.py runs the plugin
    handler before community's dispatcher, so the 404 only ever surfaces
    on a community-standalone install (no plugin loaded).
    """

    def _api(self, path, method="GET", body=b""):
        return handle_community_api(path, method, body, self.store)

    def test_policies_get_returns_404(self):
        status, _body = self._api("/api/v1/mcp/policies")
        self.assertEqual(status, 404)

    def test_policies_post_returns_404(self):
        status, _body = self._api("/api/v1/mcp/policies", "POST", b'{"name":"test"}')
        self.assertEqual(status, 404)

    def test_policies_put_returns_404(self):
        status, _body = self._api("/api/v1/mcp/policies/test", "PUT", b"{}")
        self.assertEqual(status, 404)

    def test_policies_delete_returns_404(self):
        status, _body = self._api("/api/v1/mcp/policies/test", "DELETE")
        self.assertEqual(status, 404)

    def test_approvals_get_returns_404(self):
        status, _body = self._api("/api/v1/mcp/approvals")
        self.assertEqual(status, 404)

    def test_approvals_approve_returns_404(self):
        status, _body = self._api("/api/v1/mcp/approvals/apr_123/approve", "POST", b"{}")
        self.assertEqual(status, 404)

    def test_approvals_deny_returns_404(self):
        status, _body = self._api("/api/v1/mcp/approvals/apr_123/deny", "POST", b"{}")
        self.assertEqual(status, 404)

    def test_risk_get_returns_404(self):
        status, _body = self._api("/api/v1/mcp/risk")
        self.assertEqual(status, 404)

    def test_risk_put_returns_404(self):
        status, _body = self._api("/api/v1/mcp/risk/write_file", "PUT", b"{}")
        self.assertEqual(status, 404)


class TestExtensionHooks(unittest.TestCase):
    """Test new extension hooks exist and work."""

    def test_tool_policy_evaluator_default_none(self):
        reg = ExtensionRegistry()
        self.assertIsNone(reg.get_tool_policy_evaluator())

    def test_tool_policy_evaluator_set_get(self):
        reg = ExtensionRegistry()
        sentinel = object()
        reg.set_tool_policy_evaluator(sentinel)
        self.assertIs(reg.get_tool_policy_evaluator(), sentinel)

    def test_approval_gate_default_none(self):
        reg = ExtensionRegistry()
        self.assertIsNone(reg.get_approval_gate())

    def test_approval_gate_set_get(self):
        reg = ExtensionRegistry()
        sentinel = object()
        reg.set_approval_gate(sentinel)
        self.assertIs(reg.get_approval_gate(), sentinel)


if __name__ == "__main__":
    unittest.main()
