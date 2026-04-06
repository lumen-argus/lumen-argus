"""Tests for MCP server data in heartbeat payload."""

import unittest
from unittest.mock import patch

from lumen_argus_core.detect_models import MCPDetectionReport, MCPServerEntry
from lumen_argus_core.telemetry import _detect_mcp_for_heartbeat


class TestDetectMCPForHeartbeat(unittest.TestCase):
    """Test _detect_mcp_for_heartbeat — safe subset for heartbeat payload."""

    @patch("lumen_argus_core.detect.detect_mcp_servers")
    def test_returns_safe_fields(self, mock_detect):
        mock_detect.return_value = MCPDetectionReport(
            servers=[
                MCPServerEntry(
                    name="filesystem",
                    transport="stdio",
                    command="npx",
                    args=["-y", "@mcp/fs"],
                    env={"API_KEY": "secret"},
                    source_tool="claude_desktop",
                    config_path="/path/to/config.json",
                    scope="global",
                    scanning_enabled=False,
                ),
            ],
            platform="test",
            total_detected=1,
            total_scanning=0,
        )

        result = _detect_mcp_for_heartbeat()

        self.assertEqual(len(result), 1)
        entry = result[0]
        # Safe fields present
        self.assertEqual(entry["name"], "filesystem")
        self.assertEqual(entry["transport"], "stdio")
        self.assertEqual(entry["source_tool"], "claude_desktop")
        self.assertEqual(entry["scope"], "global")
        self.assertFalse(entry["scanning_enabled"])
        # Sensitive fields NOT present
        self.assertNotIn("command", entry)
        self.assertNotIn("args", entry)
        self.assertNotIn("env", entry)
        self.assertNotIn("url", entry)
        self.assertNotIn("config_path", entry)

    @patch("lumen_argus_core.detect.detect_mcp_servers")
    def test_wrapped_server_omits_command(self, mock_detect):
        """Wrapped servers should not expose the wrapper command."""
        mock_detect.return_value = MCPDetectionReport(
            servers=[
                MCPServerEntry(
                    name="fs",
                    transport="stdio",
                    command="",
                    scanning_enabled=True,
                    original_command="npx",
                    source_tool="test",
                    scope="global",
                ),
            ],
            platform="test",
            total_detected=1,
            total_scanning=1,
        )

        result = _detect_mcp_for_heartbeat()
        self.assertNotIn("command", result[0])
        self.assertTrue(result[0]["scanning_enabled"])

    @patch("lumen_argus_core.detect.detect_mcp_servers")
    def test_detection_failure_returns_empty(self, mock_detect):
        mock_detect.side_effect = RuntimeError("detection failed")
        result = _detect_mcp_for_heartbeat()
        self.assertEqual(result, [])

    @patch("lumen_argus_core.detect.detect_mcp_servers")
    def test_empty_report(self, mock_detect):
        mock_detect.return_value = MCPDetectionReport(
            servers=[],
            platform="test",
            total_detected=0,
            total_scanning=0,
        )
        result = _detect_mcp_for_heartbeat()
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
