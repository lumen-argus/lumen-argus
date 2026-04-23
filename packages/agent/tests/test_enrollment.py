"""Tests for agent enrollment and heartbeat — community side.

Tests that the agent CLI handles enrollment gracefully:
- Enrollment state management (save, load, delete, permissions)
- CLI error handling (not enrolled, no server, unreachable server)
- Enrollment config YAML parsing (defaults, custom values, minimum intervals)
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from unittest.mock import patch

from lumen_argus_core.enrollment import (
    _ENROLLMENT_IDENTITY_FIELDS,
    EnrollmentError,
    _save_enrollment,
    fetch_policy,
    is_enrolled,
    load_enrollment,
    policy_diff_fields,
    unenroll,
    update_enrollment_policy,
)


class TestEnrollmentState(unittest.TestCase):
    """Test enrollment state file management."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.enrollment_file = os.path.join(self.tmpdir, "enrollment.json")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_not_enrolled_by_default(self):
        with patch("lumen_argus_core.enrollment.ENROLLMENT_FILE", self.enrollment_file):
            self.assertFalse(is_enrolled())
            self.assertIsNone(load_enrollment())

    def test_save_and_load(self):
        state = {
            "server": "https://argus.corp.io",
            "proxy_url": "https://argus.corp.io:8080",
            "dashboard_url": "https://argus.corp.io:8081",
            "organization": "Acme Corp",
            "policy": {"fail_mode": "closed"},
            "enrolled_at": "2026-04-02T10:30:00Z",
            "agent_id": "agent_abc123",
            "machine_id": "mac_def456",
        }
        with (
            patch("lumen_argus_core.enrollment.ENROLLMENT_FILE", self.enrollment_file),
            patch("lumen_argus_core.enrollment._ARGUS_DIR", self.tmpdir),
        ):
            _save_enrollment(state)
            self.assertTrue(is_enrolled())
            loaded = load_enrollment()
            self.assertEqual(loaded["server"], "https://argus.corp.io")
            self.assertEqual(loaded["organization"], "Acme Corp")
            self.assertEqual(loaded["policy"]["fail_mode"], "closed")

    def test_file_permissions(self):
        state = {"server": "https://test.io", "agent_id": "a", "machine_id": "m", "enrolled_at": "now"}
        with (
            patch("lumen_argus_core.enrollment.ENROLLMENT_FILE", self.enrollment_file),
            patch("lumen_argus_core.enrollment._ARGUS_DIR", self.tmpdir),
        ):
            _save_enrollment(state)
            mode = os.stat(self.enrollment_file).st_mode & 0o777
            self.assertEqual(mode, 0o600, "enrollment.json must have 0600 permissions")

    def test_unenroll_when_not_enrolled(self):
        with patch("lumen_argus_core.enrollment.ENROLLMENT_FILE", self.enrollment_file):
            self.assertFalse(unenroll())

    def test_unenroll_removes_file(self):
        state = {"server": "https://test.io", "agent_id": "a", "machine_id": "m", "enrolled_at": "now"}
        with (
            patch("lumen_argus_core.enrollment.ENROLLMENT_FILE", self.enrollment_file),
            patch("lumen_argus_core.enrollment._ARGUS_DIR", self.tmpdir),
            patch("lumen_argus_core.enrollment._CA_CERT_FILE", os.path.join(self.tmpdir, "ca.pem")),
            patch("lumen_argus_core.enrollment.deregister_agent"),
        ):
            _save_enrollment(state)
            self.assertTrue(is_enrolled())
            self.assertTrue(unenroll())
            self.assertFalse(is_enrolled())
            self.assertFalse(os.path.exists(self.enrollment_file))

    def test_load_corrupted_file(self):
        with open(self.enrollment_file, "w") as f:
            f.write("not json")
        with patch("lumen_argus_core.enrollment.ENROLLMENT_FILE", self.enrollment_file):
            self.assertIsNone(load_enrollment())


class TestAgentCLIEnrollment(unittest.TestCase):
    """Test agent CLI enrollment commands via subprocess."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _run(self, *args):
        env = {**os.environ, "HOME": self.tmpdir, "USERPROFILE": self.tmpdir}
        return subprocess.run(
            [sys.executable, "-m", "lumen_argus_agent", *args],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )

    def test_heartbeat_not_enrolled(self):
        result = self._run("heartbeat")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Not enrolled", result.stderr)

    def test_enroll_no_server(self):
        result = self._run("enroll", "--non-interactive")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--server", result.stderr)

    def test_unenroll_when_not_enrolled(self):
        result = self._run("enroll", "--undo")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Not currently enrolled", result.stdout)

    def test_enroll_unreachable_server(self):
        result = self._run("enroll", "--server", "http://127.0.0.1:1", "--non-interactive")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failed", result.stderr.lower())


class TestHeartbeat(unittest.TestCase):
    """Test heartbeat telemetry logic."""

    @staticmethod
    def _mock_urlopen_response(body: bytes = b"{}"):
        """Create a mock urlopen return value that works as context manager."""
        resp = unittest.mock.MagicMock()
        resp.__enter__ = lambda s: resp
        resp.__exit__ = lambda s, *a: None
        resp.read.return_value = body
        return resp

    def test_heartbeat_not_enrolled_returns_false(self):
        from lumen_argus_core.telemetry import send_heartbeat

        with patch("lumen_argus_core.telemetry.load_enrollment", return_value=None):
            self.assertFalse(send_heartbeat())

    def test_heartbeat_sends_correct_payload(self):
        from lumen_argus_core.telemetry import send_heartbeat

        enrollment = {
            "server": "https://argus.corp.io",
            "proxy_url": "https://argus.corp.io:8080",
            "dashboard_url": "https://argus.corp.io:8081",
            "agent_id": "agent_test123",
            "enrolled_at": "2026-04-02T10:30:00Z",
        }

        mock_report = unittest.mock.MagicMock()
        mock_report.clients = []

        mock_resp = self._mock_urlopen_response()

        with (
            patch("lumen_argus_core.telemetry.load_enrollment", return_value=enrollment),
            patch("lumen_argus_core.detect.detect_installed_clients", return_value=mock_report),
            patch("lumen_argus_core.setup.protection.protection_status", return_value={"enabled": True}),
            patch("lumen_argus_core.telemetry.urllib.request.urlopen", return_value=mock_resp) as mock_urlopen,
        ):
            result = send_heartbeat()
            self.assertTrue(result)
            req = mock_urlopen.call_args[0][0]
            self.assertIn("/api/v1/enrollment/heartbeat", req.full_url)
            import json

            payload = json.loads(req.data)
            self.assertEqual(payload["agent_id"], "agent_test123")
            self.assertTrue(payload["protection_enabled"])
            self.assertIn("heartbeat_at", payload)

    def test_heartbeat_payload_includes_tool_detail(self):
        """Heartbeat tools array includes display_name, install_method, proxy_config_type."""
        from lumen_argus_core.detect_models import DetectedClient
        from lumen_argus_core.telemetry import send_heartbeat

        client = DetectedClient(
            client_id="claude",
            display_name="Claude Code",
            installed=True,
            version="1.2.0",
            install_method="binary",
            proxy_configured=True,
            routing_active=True,
            proxy_config_type="env_var",
        )

        enrollment = {
            "server": "https://argus.corp.io",
            "proxy_url": "https://argus.corp.io:8080",
            "dashboard_url": "https://argus.corp.io:8081",
            "agent_id": "agent_test123",
            "enrolled_at": "2026-04-02T10:30:00Z",
        }

        mock_report = unittest.mock.MagicMock()
        mock_report.clients = [client]
        mock_resp = self._mock_urlopen_response()

        with (
            patch("lumen_argus_core.telemetry.load_enrollment", return_value=enrollment),
            patch("lumen_argus_core.detect.detect_installed_clients", return_value=mock_report),
            patch("lumen_argus_core.setup.protection.protection_status", return_value={"enabled": True}),
            patch("lumen_argus_core.telemetry.urllib.request.urlopen", return_value=mock_resp) as mock_urlopen,
        ):
            send_heartbeat()
            import json

            payload = json.loads(mock_urlopen.call_args[0][0].data)
            self.assertEqual(len(payload["tools"]), 1)
            tool = payload["tools"][0]
            self.assertEqual(tool["client_id"], "claude")
            self.assertEqual(tool["display_name"], "Claude Code")
            self.assertEqual(tool["install_method"], "binary")
            self.assertEqual(tool["proxy_config_type"], "env_var")

    def test_heartbeat_empty_string_urls_fall_back_to_server(self):
        """Empty string proxy_url/dashboard_url should fall back to server."""
        from lumen_argus_core.telemetry import send_heartbeat

        enrollment = {
            "server": "https://argus.corp.io",
            "proxy_url": "",
            "dashboard_url": "",
            "agent_id": "agent_test123",
            "enrolled_at": "2026-04-02T10:30:00Z",
        }

        mock_report = unittest.mock.MagicMock()
        mock_report.clients = []
        mock_resp = self._mock_urlopen_response()

        with (
            patch("lumen_argus_core.telemetry.load_enrollment", return_value=enrollment),
            patch("lumen_argus_core.telemetry._relay_url_or", side_effect=lambda fb: fb),
            patch("lumen_argus_core.detect.detect_installed_clients", return_value=mock_report) as mock_detect,
            patch("lumen_argus_core.setup.protection.protection_status", return_value={"enabled": True}),
            patch("lumen_argus_core.telemetry.urllib.request.urlopen", return_value=mock_resp) as mock_urlopen,
        ):
            result = send_heartbeat()
            self.assertTrue(result)
            mock_detect.assert_called_once_with(proxy_url="https://argus.corp.io")
            req = mock_urlopen.call_args[0][0]
            self.assertEqual(
                req.full_url,
                "https://argus.corp.io/api/v1/enrollment/heartbeat",
            )

    def test_heartbeat_handles_http_error(self):
        from lumen_argus_core.telemetry import send_heartbeat

        enrollment = {
            "server": "https://argus.corp.io",
            "proxy_url": "https://argus.corp.io:8080",
            "dashboard_url": "https://argus.corp.io:8081",
            "agent_id": "agent_test123",
            "enrolled_at": "2026-04-02T10:30:00Z",
        }

        mock_report = unittest.mock.MagicMock()
        mock_report.clients = []

        import urllib.error

        with (
            patch("lumen_argus_core.telemetry.load_enrollment", return_value=enrollment),
            patch("lumen_argus_core.detect.detect_installed_clients", return_value=mock_report),
            patch("lumen_argus_core.setup.protection.protection_status", return_value={"enabled": False}),
            patch(
                "lumen_argus_core.telemetry.urllib.request.urlopen",
                side_effect=urllib.error.HTTPError(None, 500, "Server Error", {}, None),
            ),
        ):
            self.assertFalse(send_heartbeat())

    def test_heartbeat_sends_auth_header_when_token_present(self):
        """Heartbeat includes Authorization header when agent_token is in enrollment."""
        from lumen_argus_core.telemetry import send_heartbeat

        enrollment = {
            "server": "https://argus.corp.io",
            "proxy_url": "https://argus.corp.io:8080",
            "dashboard_url": "https://argus.corp.io:8081",
            "agent_id": "agent_test123",
            "enrolled_at": "2026-04-02T10:30:00Z",
            "agent_token": "la_agent_testtoken123456",
        }

        mock_report = unittest.mock.MagicMock()
        mock_report.clients = []
        mock_resp = self._mock_urlopen_response()

        with (
            patch("lumen_argus_core.telemetry.load_enrollment", return_value=enrollment),
            patch("lumen_argus_core.detect.detect_installed_clients", return_value=mock_report),
            patch("lumen_argus_core.setup.protection.protection_status", return_value={"enabled": True}),
            patch("lumen_argus_core.telemetry.urllib.request.urlopen", return_value=mock_resp) as mock_urlopen,
        ):
            send_heartbeat()
            req = mock_urlopen.call_args[0][0]
            self.assertEqual(req.get_header("Authorization"), "Bearer la_agent_testtoken123456")

    def test_heartbeat_no_auth_header_without_token(self):
        """Heartbeat omits Authorization header when no agent_token."""
        from lumen_argus_core.telemetry import send_heartbeat

        enrollment = {
            "server": "https://argus.corp.io",
            "proxy_url": "https://argus.corp.io:8080",
            "dashboard_url": "https://argus.corp.io:8081",
            "agent_id": "agent_test123",
            "enrolled_at": "2026-04-02T10:30:00Z",
        }

        mock_report = unittest.mock.MagicMock()
        mock_report.clients = []
        mock_resp = self._mock_urlopen_response()

        with (
            patch("lumen_argus_core.telemetry.load_enrollment", return_value=enrollment),
            patch("lumen_argus_core.detect.detect_installed_clients", return_value=mock_report),
            patch("lumen_argus_core.setup.protection.protection_status", return_value={"enabled": True}),
            patch("lumen_argus_core.telemetry.urllib.request.urlopen", return_value=mock_resp) as mock_urlopen,
        ):
            send_heartbeat()
            req = mock_urlopen.call_args[0][0]
            self.assertIsNone(req.get_header("Authorization"))

    def test_heartbeat_with_policy_change_updates_file(self):
        """Heartbeat success path calls fetch_policy + update_enrollment_policy."""
        from lumen_argus_core.telemetry import send_heartbeat

        enrollment = {
            "server": "https://argus.corp.io",
            "proxy_url": "https://argus.corp.io:8080",
            "dashboard_url": "https://argus.corp.io:8081",
            "agent_id": "agent_test123",
            "enrolled_at": "2026-04-02T10:30:00Z",
            "agent_token": "la_agent_token",
            "policy": {"fail_mode": "open"},
        }

        mock_report = unittest.mock.MagicMock()
        mock_report.clients = []
        mock_resp = self._mock_urlopen_response()

        with (
            patch("lumen_argus_core.telemetry.load_enrollment", return_value=enrollment),
            patch("lumen_argus_core.detect.detect_installed_clients", return_value=mock_report),
            patch("lumen_argus_core.setup.protection.protection_status", return_value={"enabled": True}),
            patch("lumen_argus_core.telemetry.urllib.request.urlopen", return_value=mock_resp),
            patch("lumen_argus_core.telemetry.fetch_policy", return_value={"fail_mode": "closed"}) as mock_fetch,
            patch("lumen_argus_core.telemetry.update_enrollment_policy", return_value=True) as mock_update,
        ):
            result = send_heartbeat()
        self.assertTrue(result)
        mock_fetch.assert_called_once()
        mock_update.assert_called_once_with({"fail_mode": "closed"})

    def test_heartbeat_policy_refresh_failure_does_not_fail_heartbeat(self):
        """fetch_policy raising must never flip heartbeat success to failure."""
        from lumen_argus_core.enrollment import EnrollmentError
        from lumen_argus_core.telemetry import send_heartbeat

        enrollment = {
            "server": "https://argus.corp.io",
            "proxy_url": "https://argus.corp.io:8080",
            "dashboard_url": "https://argus.corp.io:8081",
            "agent_id": "agent_test123",
            "enrolled_at": "2026-04-02T10:30:00Z",
            "agent_token": "la_agent_token",
            "policy": {},
        }

        mock_report = unittest.mock.MagicMock()
        mock_report.clients = []
        mock_resp = self._mock_urlopen_response()

        with (
            patch("lumen_argus_core.telemetry.load_enrollment", return_value=enrollment),
            patch("lumen_argus_core.detect.detect_installed_clients", return_value=mock_report),
            patch("lumen_argus_core.setup.protection.protection_status", return_value={"enabled": True}),
            patch("lumen_argus_core.telemetry.urllib.request.urlopen", return_value=mock_resp),
            patch("lumen_argus_core.telemetry.fetch_policy", side_effect=EnrollmentError("network down")),
            patch("lumen_argus_core.telemetry.update_enrollment_policy") as mock_update,
        ):
            self.assertTrue(send_heartbeat())
        mock_update.assert_not_called()

    def test_heartbeat_policy_refresh_runs_on_heartbeat_failure(self):
        """Refresh runs regardless of heartbeat outcome — policy propagates even if dashboard POST is flaky."""
        import urllib.error

        from lumen_argus_core.telemetry import send_heartbeat

        enrollment = {
            "server": "https://argus.corp.io",
            "proxy_url": "https://argus.corp.io:8080",
            "dashboard_url": "https://argus.corp.io:8081",
            "agent_id": "agent_test123",
            "enrolled_at": "2026-04-02T10:30:00Z",
            "agent_token": "la_agent_token",
            "policy": {},
        }

        mock_report = unittest.mock.MagicMock()
        mock_report.clients = []

        with (
            patch("lumen_argus_core.telemetry.load_enrollment", return_value=enrollment),
            patch("lumen_argus_core.detect.detect_installed_clients", return_value=mock_report),
            patch("lumen_argus_core.setup.protection.protection_status", return_value={"enabled": True}),
            patch(
                "lumen_argus_core.telemetry.urllib.request.urlopen",
                side_effect=urllib.error.HTTPError(None, 500, "Server Error", {}, None),
            ),
            patch("lumen_argus_core.telemetry.fetch_policy", return_value={"fail_mode": "closed"}) as mock_fetch,
            patch("lumen_argus_core.telemetry.update_enrollment_policy", return_value=True) as mock_update,
        ):
            self.assertFalse(send_heartbeat())
        mock_fetch.assert_called_once()
        mock_update.assert_called_once()

    def test_heartbeat_policy_change_log_lists_field_names_not_values(self):
        """Change log must contain field NAMES only — no policy values."""
        import logging as _logging

        from lumen_argus_core.telemetry import send_heartbeat

        enrollment = {
            "server": "https://argus.corp.io",
            "proxy_url": "https://argus.corp.io:8080",
            "dashboard_url": "https://argus.corp.io:8081",
            "agent_id": "agent_test123",
            "enrolled_at": "2026-04-02T10:30:00Z",
            "agent_token": "la_agent_token",
            "policy": {"fail_mode": "open", "secret_knob": "OLD_SENSITIVE_VALUE"},
        }

        mock_report = unittest.mock.MagicMock()
        mock_report.clients = []
        mock_resp = self._mock_urlopen_response()

        new_policy = {"fail_mode": "closed", "secret_knob": "NEW_SENSITIVE_VALUE"}

        with (
            patch("lumen_argus_core.telemetry.load_enrollment", return_value=enrollment),
            patch("lumen_argus_core.detect.detect_installed_clients", return_value=mock_report),
            patch("lumen_argus_core.setup.protection.protection_status", return_value={"enabled": True}),
            patch("lumen_argus_core.telemetry.urllib.request.urlopen", return_value=mock_resp),
            patch("lumen_argus_core.telemetry.fetch_policy", return_value=new_policy),
            patch("lumen_argus_core.telemetry.update_enrollment_policy", return_value=True),
            self.assertLogs("argus.telemetry", level=_logging.INFO) as caplog,
        ):
            send_heartbeat()

        joined = "\n".join(caplog.output)
        self.assertIn("fail_mode", joined)
        self.assertIn("secret_knob", joined)
        self.assertNotIn("OLD_SENSITIVE_VALUE", joined)
        self.assertNotIn("NEW_SENSITIVE_VALUE", joined)

    def test_heartbeat_refresh_runs_on_unexpected_exception(self):
        """SSLError / TimeoutError escaping urlopen must not skip refresh."""
        import ssl

        from lumen_argus_core.telemetry import send_heartbeat

        enrollment = {
            "server": "https://argus.corp.io",
            "proxy_url": "https://argus.corp.io:8080",
            "dashboard_url": "https://argus.corp.io:8081",
            "agent_id": "agent_test123",
            "enrolled_at": "2026-04-02T10:30:00Z",
            "agent_token": "la_agent_token",
            "policy": {},
        }

        mock_report = unittest.mock.MagicMock()
        mock_report.clients = []

        with (
            patch("lumen_argus_core.telemetry.load_enrollment", return_value=enrollment),
            patch("lumen_argus_core.detect.detect_installed_clients", return_value=mock_report),
            patch("lumen_argus_core.setup.protection.protection_status", return_value={"enabled": True}),
            patch(
                "lumen_argus_core.telemetry.urllib.request.urlopen",
                side_effect=ssl.SSLError("handshake failed"),
            ),
            patch("lumen_argus_core.telemetry.fetch_policy", return_value={"fail_mode": "closed"}) as mock_fetch,
            patch("lumen_argus_core.telemetry.update_enrollment_policy", return_value=True) as mock_update,
        ):
            self.assertFalse(send_heartbeat())
        mock_fetch.assert_called_once()
        mock_update.assert_called_once()

    def test_heartbeat_skips_refresh_without_agent_token(self):
        """Community-only deployments without bearer auth must not attempt refresh."""
        from lumen_argus_core.telemetry import send_heartbeat

        enrollment = {
            "server": "https://argus.corp.io",
            "proxy_url": "https://argus.corp.io:8080",
            "dashboard_url": "https://argus.corp.io:8081",
            "agent_id": "agent_test123",
            "enrolled_at": "2026-04-02T10:30:00Z",
            # no agent_token
        }

        mock_report = unittest.mock.MagicMock()
        mock_report.clients = []
        mock_resp = self._mock_urlopen_response()

        with (
            patch("lumen_argus_core.telemetry.load_enrollment", return_value=enrollment),
            patch("lumen_argus_core.detect.detect_installed_clients", return_value=mock_report),
            patch("lumen_argus_core.setup.protection.protection_status", return_value={"enabled": True}),
            patch("lumen_argus_core.telemetry.urllib.request.urlopen", return_value=mock_resp),
            patch("lumen_argus_core.telemetry.fetch_policy") as mock_fetch,
        ):
            self.assertTrue(send_heartbeat())
        mock_fetch.assert_not_called()

    def test_heartbeat_rotates_token_from_response(self):
        """Heartbeat updates enrollment.json when proxy returns new_token."""
        from lumen_argus_core.telemetry import send_heartbeat

        enrollment = {
            "server": "https://argus.corp.io",
            "proxy_url": "https://argus.corp.io:8080",
            "dashboard_url": "https://argus.corp.io:8081",
            "agent_id": "agent_test123",
            "enrolled_at": "2026-04-02T10:30:00Z",
            "agent_token": "la_agent_oldtoken",
        }

        mock_report = unittest.mock.MagicMock()
        mock_report.clients = []
        mock_resp = self._mock_urlopen_response(b'{"new_token": "la_agent_newtoken"}')

        with (
            patch("lumen_argus_core.telemetry.load_enrollment", return_value=enrollment),
            patch("lumen_argus_core.detect.detect_installed_clients", return_value=mock_report),
            patch("lumen_argus_core.setup.protection.protection_status", return_value={"enabled": True}),
            patch("lumen_argus_core.telemetry.urllib.request.urlopen", return_value=mock_resp),
            patch("lumen_argus_core.telemetry.update_agent_token") as mock_rotate,
        ):
            send_heartbeat()
            mock_rotate.assert_called_once_with("la_agent_newtoken")


class TestFetchPolicy(unittest.TestCase):
    """fetch_policy() contract: bearer required, HTTPS-or-loopback only, returns .policy."""

    @staticmethod
    def _mock_urlopen_response(body: bytes):
        resp = unittest.mock.MagicMock()
        resp.__enter__ = lambda s: resp
        resp.__exit__ = lambda s, *a: None
        resp.read.return_value = body
        return resp

    def test_fetch_policy_happy_path(self):
        body = b'{"policy": {"fail_mode": "closed", "auto_configure": true}}'
        with patch(
            "lumen_argus_core.enrollment.urllib.request.urlopen",
            return_value=self._mock_urlopen_response(body),
        ):
            result = fetch_policy("https://argus.corp.io", "la_agent_token123")
        self.assertEqual(result, {"fail_mode": "closed", "auto_configure": True})

    def test_fetch_policy_sends_bearer_header(self):
        body = b'{"policy": {}}'
        with patch(
            "lumen_argus_core.enrollment.urllib.request.urlopen",
            return_value=self._mock_urlopen_response(body),
        ) as mock_urlopen:
            fetch_policy("https://argus.corp.io", "la_agent_bearer")
        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.get_header("Authorization"), "Bearer la_agent_bearer")

    def test_fetch_policy_missing_token_raises(self):
        with self.assertRaises(EnrollmentError):
            fetch_policy("https://argus.corp.io", "")

    def test_fetch_policy_rejects_http_in_non_loopback(self):
        """Must not leak bearer token over cleartext HTTP to a remote host."""
        with self.assertRaises(EnrollmentError):
            fetch_policy("http://argus.corp.io", "la_agent_token")

    def test_fetch_policy_allows_loopback_http(self):
        """HTTP is fine against loopback — no network exposure."""
        body = b'{"policy": {}}'
        with patch(
            "lumen_argus_core.enrollment.urllib.request.urlopen",
            return_value=self._mock_urlopen_response(body),
        ):
            fetch_policy("http://127.0.0.1:8081", "la_agent_token")
        # no raise = pass

    def test_fetch_policy_http_error_raises(self):
        import urllib.error

        with patch(
            "lumen_argus_core.enrollment.urllib.request.urlopen",
            side_effect=urllib.error.HTTPError(None, 401, "Unauthorized", {}, None),
        ):
            with self.assertRaises(EnrollmentError):
                fetch_policy("https://argus.corp.io", "la_agent_token")

    def test_fetch_policy_invalid_json_raises(self):
        with patch(
            "lumen_argus_core.enrollment.urllib.request.urlopen",
            return_value=self._mock_urlopen_response(b"not json"),
        ):
            with self.assertRaises(EnrollmentError):
                fetch_policy("https://argus.corp.io", "la_agent_token")

    def test_fetch_policy_missing_policy_key_raises(self):
        """Server response without .policy key is malformed — reject to avoid wiping local policy."""
        with patch(
            "lumen_argus_core.enrollment.urllib.request.urlopen",
            return_value=self._mock_urlopen_response(b'{"organization": "Acme"}'),
        ):
            with self.assertRaises(EnrollmentError):
                fetch_policy("https://argus.corp.io", "la_agent_token")

    def test_fetch_policy_empty_policy_accepted(self):
        """Explicit empty policy dict is a valid admin state — accept it."""
        with patch(
            "lumen_argus_core.enrollment.urllib.request.urlopen",
            return_value=self._mock_urlopen_response(b'{"policy": {}}'),
        ):
            result = fetch_policy("https://argus.corp.io", "la_agent_token")
        self.assertEqual(result, {})

    def test_fetch_policy_401_maps_to_reenroll_message(self):
        """Revoked agent token should surface as an actionable message."""
        import urllib.error

        with patch(
            "lumen_argus_core.enrollment.urllib.request.urlopen",
            side_effect=urllib.error.HTTPError(None, 401, "Unauthorized", {}, None),
        ):
            with self.assertRaises(EnrollmentError) as cm:
                fetch_policy("https://argus.corp.io", "la_agent_token")
        self.assertIn("re-enrollment", str(cm.exception).lower())

    def test_fetch_policy_non_dict_policy_raises(self):
        """Policy value must be a JSON object — reject lists/strings."""
        with patch(
            "lumen_argus_core.enrollment.urllib.request.urlopen",
            return_value=self._mock_urlopen_response(b'{"policy": "not-an-object"}'),
        ):
            with self.assertRaises(EnrollmentError):
                fetch_policy("https://argus.corp.io", "la_agent_token")


class TestUpdateEnrollmentPolicy(unittest.TestCase):
    """update_enrollment_policy() contract: identity fields immutable, atomic, idempotent."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.enrollment_file = os.path.join(self.tmpdir, "enrollment.json")

        self.baseline = {
            "server": "https://argus.corp.io",
            "proxy_url": "https://argus.corp.io:8080",
            "dashboard_url": "https://argus.corp.io:8081",
            "organization": "Acme Corp",
            "policy": {"fail_mode": "open", "auto_configure": True},
            "enrolled_at": "2026-04-02T10:30:00Z",
            "agent_id": "agent_abc123",
            "machine_id": "mac_def456",
            "agent_token": "la_agent_originaltoken",
        }

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _seed(self):
        with (
            patch("lumen_argus_core.enrollment.ENROLLMENT_FILE", self.enrollment_file),
            patch("lumen_argus_core.enrollment._ARGUS_DIR", self.tmpdir),
        ):
            _save_enrollment(self.baseline)

    def test_not_enrolled_returns_false(self):
        with patch("lumen_argus_core.enrollment.ENROLLMENT_FILE", self.enrollment_file):
            self.assertFalse(update_enrollment_policy({"fail_mode": "closed"}))

    def test_noop_when_identical(self):
        self._seed()
        with (
            patch("lumen_argus_core.enrollment.ENROLLMENT_FILE", self.enrollment_file),
            patch("lumen_argus_core.enrollment._ARGUS_DIR", self.tmpdir),
        ):
            result = update_enrollment_policy({"fail_mode": "open", "auto_configure": True})
        self.assertFalse(result)

    def test_returns_true_when_changed(self):
        self._seed()
        with (
            patch("lumen_argus_core.enrollment.ENROLLMENT_FILE", self.enrollment_file),
            patch("lumen_argus_core.enrollment._ARGUS_DIR", self.tmpdir),
        ):
            result = update_enrollment_policy({"fail_mode": "closed", "auto_configure": False})
        self.assertTrue(result)
        import json as _json

        with open(self.enrollment_file) as f:
            loaded = _json.load(f)
        self.assertEqual(loaded["policy"]["fail_mode"], "closed")
        self.assertFalse(loaded["policy"]["auto_configure"])

    def test_preserves_identity_fields(self):
        """Every identity field must be byte-for-byte unchanged after refresh."""
        self._seed()
        with (
            patch("lumen_argus_core.enrollment.ENROLLMENT_FILE", self.enrollment_file),
            patch("lumen_argus_core.enrollment._ARGUS_DIR", self.tmpdir),
        ):
            update_enrollment_policy(
                {
                    "fail_mode": "closed",
                    "agent_id": "ATTACKER_CONTROLLED",
                    "agent_token": "la_agent_SWAPPED",
                    "organization": "Evil Corp",
                    "server": "https://attacker.example",
                }
            )
            loaded = load_enrollment()
        assert loaded is not None
        for field in _ENROLLMENT_IDENTITY_FIELDS:
            self.assertEqual(
                loaded[field],
                self.baseline[field],
                "identity field %s was mutated by update_enrollment_policy" % field,
            )
        # Policy slice *did* absorb every key — including ones named after
        # identity fields, which is fine because they live inside .policy now.
        self.assertEqual(loaded["policy"]["agent_id"], "ATTACKER_CONTROLLED")

    def test_atomic_on_crash(self):
        """A mid-write failure must not leave enrollment.json corrupt."""
        self._seed()
        with open(self.enrollment_file, "rb") as f:
            original_bytes = f.read()

        # Patch _save_enrollment to simulate a crash after tmp write but
        # before os.replace. The .tmp file exists, the real file is intact.
        tmp_path = self.enrollment_file + ".tmp"

        def boom(state):
            with open(tmp_path, "w") as f:
                f.write("{corrupted")
            raise RuntimeError("simulated crash during save")

        with (
            patch("lumen_argus_core.enrollment.ENROLLMENT_FILE", self.enrollment_file),
            patch("lumen_argus_core.enrollment._ARGUS_DIR", self.tmpdir),
            patch("lumen_argus_core.enrollment._save_enrollment", side_effect=boom),
            self.assertRaises(RuntimeError),
        ):
            update_enrollment_policy({"fail_mode": "closed"})

        # Real file is byte-identical to pre-crash state.
        with open(self.enrollment_file, "rb") as f:
            self.assertEqual(f.read(), original_bytes)


class TestPolicyDiffFields(unittest.TestCase):
    def test_empty_when_identical(self):
        self.assertEqual(policy_diff_fields({"a": 1}, {"a": 1}), [])

    def test_lists_only_changed_fields(self):
        self.assertEqual(
            policy_diff_fields({"a": 1, "b": 2}, {"a": 1, "b": 3}),
            ["b"],
        )

    def test_treats_missing_keys_as_changed(self):
        self.assertEqual(
            sorted(policy_diff_fields({"a": 1}, {"b": 2})),
            ["a", "b"],
        )


class TestEnrollCA(unittest.TestCase):
    """Test CA certificate handling during enrollment."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_enroll_saves_ca_cert(self):
        from lumen_argus_core.enrollment import enroll

        ca_pem = "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----"
        config_response = {
            "proxy_url": "https://argus.corp.io:8080",
            "dashboard_url": "https://argus.corp.io:8081",
            "organization": "Test Corp",
            "policy": {},
            "ca_cert": ca_pem,
        }
        ca_cert_path = os.path.join(self.tmpdir, "ca.pem")

        with (
            patch("lumen_argus_core.enrollment.fetch_enrollment_config", return_value=config_response),
            patch("lumen_argus_core.enrollment.register_agent", return_value={}),
            patch("lumen_argus_core.enrollment.ENROLLMENT_FILE", os.path.join(self.tmpdir, "enrollment.json")),
            patch("lumen_argus_core.enrollment._ARGUS_DIR", self.tmpdir),
            patch("lumen_argus_core.enrollment._CA_CERT_FILE", ca_cert_path),
        ):
            state = enroll("https://argus.corp.io")
            self.assertEqual(state["organization"], "Test Corp")
            # Verify CA cert was written
            self.assertTrue(os.path.isfile(ca_cert_path))
            with open(ca_cert_path) as f:
                self.assertEqual(f.read(), ca_pem)
            # Verify permissions
            mode = os.stat(ca_cert_path).st_mode & 0o777
            self.assertEqual(mode, 0o600)

    def test_enroll_without_ca_cert(self):
        from lumen_argus_core.enrollment import enroll

        config_response = {
            "proxy_url": "https://argus.corp.io:8080",
            "organization": "No Cert Corp",
            "policy": {},
        }
        ca_cert_path = os.path.join(self.tmpdir, "ca.pem")

        with (
            patch("lumen_argus_core.enrollment.fetch_enrollment_config", return_value=config_response),
            patch("lumen_argus_core.enrollment.register_agent", return_value={}),
            patch("lumen_argus_core.enrollment.ENROLLMENT_FILE", os.path.join(self.tmpdir, "enrollment.json")),
            patch("lumen_argus_core.enrollment._ARGUS_DIR", self.tmpdir),
            patch("lumen_argus_core.enrollment._CA_CERT_FILE", ca_cert_path),
        ):
            enroll("https://argus.corp.io")
            self.assertFalse(os.path.exists(ca_cert_path))


if __name__ == "__main__":
    unittest.main()
