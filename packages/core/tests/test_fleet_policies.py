"""Tests for fleet MCP policy loading and enforcement during setup."""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from lumen_argus_core.detect_models import MCPDetectionReport, MCPServerEntry
from lumen_argus_core.fleet_policies import FleetPolicies, ServerPolicy, load_fleet_policies
from lumen_argus_core.mcp_setup import _apply_fleet_policies, run_mcp_setup


class TestLoadFleetPolicies(unittest.TestCase):
    """Test load_fleet_policies from disk."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_policies(self, data):
        path = os.path.join(self.tmpdir, "mcp_policies.json")
        with open(path, "w") as f:
            json.dump(data, f)
        return path

    def test_loads_valid_policies(self):
        path = self._write_policies(
            {
                "version": "2026-04-06T14:30:00Z",
                "source": "fleet",
                "server_policies": [
                    {"server_name": "filesystem", "policy": "must_scan"},
                    {"server_name": "internal-db", "policy": "blocked", "reason": "security risk"},
                ],
                "default_action": "allow",
            }
        )

        policies = load_fleet_policies(path)

        self.assertIsNotNone(policies)
        self.assertEqual(policies.version, "2026-04-06T14:30:00Z")
        self.assertEqual(policies.source, "fleet")
        self.assertEqual(len(policies.server_policies), 2)
        self.assertEqual(policies.default_action, "allow")

        self.assertEqual(policies.server_policies[0].server_name, "filesystem")
        self.assertEqual(policies.server_policies[0].policy, "must_scan")
        self.assertEqual(policies.server_policies[1].server_name, "internal-db")
        self.assertEqual(policies.server_policies[1].policy, "blocked")
        self.assertEqual(policies.server_policies[1].reason, "security risk")

    def test_missing_file_returns_none(self):
        result = load_fleet_policies("/nonexistent/path.json")
        self.assertIsNone(result)

    def test_invalid_json_returns_none(self):
        path = os.path.join(self.tmpdir, "bad.json")
        with open(path, "w") as f:
            f.write("{invalid")
        result = load_fleet_policies(path)
        self.assertIsNone(result)

    def test_non_dict_returns_none(self):
        path = self._write_policies([1, 2, 3])
        result = load_fleet_policies(path)
        self.assertIsNone(result)

    def test_skips_invalid_policy_entries(self):
        path = self._write_policies(
            {
                "server_policies": [
                    {"server_name": "good", "policy": "must_scan"},
                    {"server_name": "", "policy": "blocked"},  # empty name
                    {"server_name": "bad", "policy": "invalid_action"},  # bad policy
                    "not a dict",
                ]
            }
        )

        policies = load_fleet_policies(path)
        self.assertEqual(len(policies.server_policies), 1)
        self.assertEqual(policies.server_policies[0].server_name, "good")

    def test_empty_server_policies(self):
        path = self._write_policies({"server_policies": []})
        policies = load_fleet_policies(path)
        self.assertIsNotNone(policies)
        self.assertEqual(len(policies.server_policies), 0)

    def test_missing_server_policies_key(self):
        path = self._write_policies({"version": "1.0"})
        policies = load_fleet_policies(path)
        self.assertIsNotNone(policies)
        self.assertEqual(len(policies.server_policies), 0)

    def test_invalid_default_action_falls_back(self):
        path = self._write_policies({"default_action": "allow_all", "server_policies": []})
        policies = load_fleet_policies(path)
        self.assertEqual(policies.default_action, "allow")

    def test_server_policies_null_treated_as_empty(self):
        path = self._write_policies({"server_policies": None})
        policies = load_fleet_policies(path)
        self.assertIsNotNone(policies)
        self.assertEqual(len(policies.server_policies), 0)


class TestGetServerPolicy(unittest.TestCase):
    """Test FleetPolicies.get_server_policy lookup."""

    def test_returns_matching_policy(self):
        policies = FleetPolicies(
            server_policies=[
                ServerPolicy(server_name="fs", policy="must_scan"),
                ServerPolicy(server_name="db", policy="blocked"),
            ]
        )
        self.assertEqual(policies.get_server_policy("fs"), "must_scan")
        self.assertEqual(policies.get_server_policy("db"), "blocked")

    def test_returns_none_for_unknown(self):
        policies = FleetPolicies(server_policies=[ServerPolicy(server_name="fs", policy="must_scan")])
        self.assertIsNone(policies.get_server_policy("unknown"))

    def test_returns_none_for_empty_policies(self):
        policies = FleetPolicies()
        self.assertIsNone(policies.get_server_policy("fs"))


class TestApplyFleetPolicies(unittest.TestCase):
    """Test _apply_fleet_policies partitioning."""

    def _server(self, name, transport="stdio"):
        return MCPServerEntry(name=name, transport=transport, command="npx" if transport == "stdio" else "")

    def test_no_policies_all_normal(self):
        servers = [self._server("fs"), self._server("db")]
        blocked, must_scan, normal = _apply_fleet_policies(servers, None)
        self.assertEqual(len(blocked), 0)
        self.assertEqual(len(must_scan), 0)
        self.assertEqual(len(normal), 2)

    def test_blocked_server_separated(self):
        servers = [self._server("fs"), self._server("danger")]
        policies = FleetPolicies(
            server_policies=[
                ServerPolicy(server_name="danger", policy="blocked", reason="not allowed"),
            ]
        )
        blocked, _must_scan, normal = _apply_fleet_policies(servers, policies)
        self.assertEqual(len(blocked), 1)
        self.assertEqual(blocked[0][0].name, "danger")
        self.assertEqual(blocked[0][1], "not allowed")
        self.assertEqual(len(normal), 1)
        self.assertEqual(normal[0].name, "fs")

    def test_must_scan_server_separated(self):
        servers = [self._server("fs"), self._server("critical")]
        policies = FleetPolicies(
            server_policies=[
                ServerPolicy(server_name="critical", policy="must_scan"),
            ]
        )
        _blocked, must_scan, normal = _apply_fleet_policies(servers, policies)
        self.assertEqual(len(must_scan), 1)
        self.assertEqual(must_scan[0].name, "critical")
        self.assertEqual(len(normal), 1)

    def test_allowed_server_treated_as_normal(self):
        servers = [self._server("fs")]
        policies = FleetPolicies(server_policies=[ServerPolicy(server_name="fs", policy="allowed")])
        blocked, must_scan, normal = _apply_fleet_policies(servers, policies)
        self.assertEqual(len(normal), 1)
        self.assertEqual(len(blocked), 0)
        self.assertEqual(len(must_scan), 0)

    def test_review_server_treated_as_normal(self):
        servers = [self._server("fs")]
        policies = FleetPolicies(server_policies=[ServerPolicy(server_name="fs", policy="review")])
        _blocked, _must_scan, normal = _apply_fleet_policies(servers, policies)
        self.assertEqual(len(normal), 1)

    def test_mixed_policies(self):
        servers = [self._server("fs"), self._server("db"), self._server("shell")]
        policies = FleetPolicies(
            server_policies=[
                ServerPolicy(server_name="fs", policy="must_scan"),
                ServerPolicy(server_name="shell", policy="blocked"),
            ]
        )
        blocked, must_scan, normal = _apply_fleet_policies(servers, policies)
        self.assertEqual(len(blocked), 1)
        self.assertEqual(blocked[0][0].name, "shell")
        self.assertEqual(len(must_scan), 1)
        self.assertEqual(must_scan[0].name, "fs")
        self.assertEqual(len(normal), 1)
        self.assertEqual(normal[0].name, "db")


class TestRunMCPSetupWithFleetPolicies(unittest.TestCase):
    """Test run_mcp_setup integration with fleet policies."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write_config(self, data, name="config.json"):
        path = os.path.join(self.tmpdir, name)
        with open(path, "w") as f:
            json.dump(data, f)
        return path

    def _read_config(self, path):
        with open(path) as f:
            return json.load(f)

    @patch("lumen_argus_core.mcp_setup._save_manifest")
    @patch("lumen_argus_core.mcp_setup._backup_file")
    @patch("lumen_argus_core.mcp_setup.load_fleet_policies")
    @patch("lumen_argus_core.mcp_setup.detect_mcp_servers")
    def test_blocked_server_not_wrapped(self, mock_detect, mock_policies, mock_backup, mock_manifest):
        mock_backup.return_value = "/tmp/backup"
        cfg_path = self._write_config({"mcpServers": {"danger": {"command": "npx", "args": ["danger-server"]}}})

        mock_detect.return_value = MCPDetectionReport(
            servers=[
                MCPServerEntry(
                    name="danger",
                    transport="stdio",
                    command="npx",
                    args=["danger-server"],
                    source_tool="test",
                    config_path=cfg_path,
                    scope="global",
                ),
            ],
            platform="test",
            total_detected=1,
            total_scanning=0,
        )
        mock_policies.return_value = FleetPolicies(
            server_policies=[ServerPolicy(server_name="danger", policy="blocked", reason="prohibited")]
        )

        with patch("lumen_argus_core.mcp_setup._get_json_key_for_config", return_value="mcpServers"):
            changes = run_mcp_setup(non_interactive=True)

        self.assertEqual(len(changes), 0)
        # Config should NOT be modified
        data = self._read_config(cfg_path)
        self.assertEqual(data["mcpServers"]["danger"]["command"], "npx")

    @patch("lumen_argus_core.mcp_setup._save_manifest")
    @patch("lumen_argus_core.mcp_setup._backup_file")
    @patch("lumen_argus_core.mcp_setup.load_fleet_policies")
    @patch("lumen_argus_core.mcp_setup.detect_mcp_servers")
    def test_must_scan_auto_wrapped(self, mock_detect, mock_policies, mock_backup, mock_manifest):
        """must_scan servers are wrapped without prompting even in interactive mode."""
        mock_backup.return_value = "/tmp/backup"
        cfg_path = self._write_config({"mcpServers": {"critical": {"command": "npx", "args": ["critical-server"]}}})

        mock_detect.return_value = MCPDetectionReport(
            servers=[
                MCPServerEntry(
                    name="critical",
                    transport="stdio",
                    command="npx",
                    args=["critical-server"],
                    source_tool="test",
                    config_path=cfg_path,
                    scope="global",
                ),
            ],
            platform="test",
            total_detected=1,
            total_scanning=0,
        )
        mock_policies.return_value = FleetPolicies(
            server_policies=[ServerPolicy(server_name="critical", policy="must_scan")]
        )

        with patch("lumen_argus_core.mcp_setup._get_json_key_for_config", return_value="mcpServers"):
            # Interactive mode (non_interactive=False) — must_scan should still wrap
            changes = run_mcp_setup(non_interactive=False)

        self.assertEqual(len(changes), 1)
        data = self._read_config(cfg_path)
        self.assertEqual(data["mcpServers"]["critical"]["command"], "lumen-argus")

    @patch("lumen_argus_core.mcp_setup._save_manifest")
    @patch("lumen_argus_core.mcp_setup._backup_file")
    @patch("lumen_argus_core.mcp_setup.load_fleet_policies")
    @patch("lumen_argus_core.mcp_setup.detect_mcp_servers")
    def test_no_policies_normal_flow(self, mock_detect, mock_policies, mock_backup, mock_manifest):
        """Without fleet policies, wrapping works as before."""
        mock_backup.return_value = "/tmp/backup"
        cfg_path = self._write_config({"mcpServers": {"fs": {"command": "npx", "args": ["@mcp/fs"]}}})

        mock_detect.return_value = MCPDetectionReport(
            servers=[
                MCPServerEntry(
                    name="fs",
                    transport="stdio",
                    command="npx",
                    args=["@mcp/fs"],
                    source_tool="test",
                    config_path=cfg_path,
                    scope="global",
                ),
            ],
            platform="test",
            total_detected=1,
            total_scanning=0,
        )
        mock_policies.return_value = None  # No policies file

        with patch("lumen_argus_core.mcp_setup._get_json_key_for_config", return_value="mcpServers"):
            changes = run_mcp_setup(non_interactive=True)

        self.assertEqual(len(changes), 1)

    @patch("lumen_argus_core.mcp_setup._save_manifest")
    @patch("lumen_argus_core.mcp_setup._backup_file")
    @patch("lumen_argus_core.mcp_setup.load_fleet_policies")
    @patch("lumen_argus_core.mcp_setup.detect_mcp_servers")
    def test_all_blocked_returns_empty(self, mock_detect, mock_policies, mock_backup, mock_manifest):
        """When all candidates are blocked by fleet policy, nothing is wrapped."""
        cfg_path = self._write_config(
            {
                "mcpServers": {
                    "danger1": {"command": "npx", "args": ["bad1"]},
                    "danger2": {"command": "npx", "args": ["bad2"]},
                }
            }
        )

        mock_detect.return_value = MCPDetectionReport(
            servers=[
                MCPServerEntry(
                    name="danger1",
                    transport="stdio",
                    command="npx",
                    args=["bad1"],
                    source_tool="test",
                    config_path=cfg_path,
                    scope="global",
                ),
                MCPServerEntry(
                    name="danger2",
                    transport="stdio",
                    command="npx",
                    args=["bad2"],
                    source_tool="test",
                    config_path=cfg_path,
                    scope="global",
                ),
            ],
            platform="test",
            total_detected=2,
            total_scanning=0,
        )
        mock_policies.return_value = FleetPolicies(
            server_policies=[
                ServerPolicy(server_name="danger1", policy="blocked"),
                ServerPolicy(server_name="danger2", policy="blocked"),
            ]
        )

        with patch("lumen_argus_core.mcp_setup._get_json_key_for_config", return_value="mcpServers"):
            changes = run_mcp_setup(non_interactive=True)

        self.assertEqual(len(changes), 0)
        mock_backup.assert_not_called()
        mock_manifest.assert_not_called()
        # Config should NOT be modified
        data = self._read_config(cfg_path)
        self.assertEqual(data["mcpServers"]["danger1"]["command"], "npx")
        self.assertEqual(data["mcpServers"]["danger2"]["command"], "npx")


if __name__ == "__main__":
    unittest.main()
