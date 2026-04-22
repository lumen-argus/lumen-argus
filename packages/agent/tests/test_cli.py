"""Tests for the lumen-argus-agent CLI."""

import argparse
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import ClassVar
from unittest.mock import patch

from lumen_argus_agent.cli import _run_refresh_policy, _run_uninstall
from lumen_argus_agent.uninstall import UninstallResult

from lumen_argus_core.enrollment import EnrollmentError


class TestAgentCLI(unittest.TestCase):
    """Verify agent CLI commands work end-to-end."""

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "lumen_argus_agent", *args],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_version(self):
        result = self._run("--version")
        self.assertEqual(result.returncode, 0)
        self.assertIn("lumen-argus-agent", result.stdout)

    def test_help(self):
        result = self._run("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("detect", result.stdout)
        self.assertIn("setup", result.stdout)
        self.assertIn("watch", result.stdout)
        self.assertIn("protection", result.stdout)
        self.assertIn("clients", result.stdout)
        self.assertIn("uninstall", result.stdout)

    def test_uninstall_help_documents_flags(self):
        result = self._run("uninstall", "--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--keep-data", result.stdout)
        self.assertIn("--non-interactive", result.stdout)

    def test_no_command_shows_help(self):
        result = self._run()
        self.assertNotEqual(result.returncode, 0)

    def test_clients_json(self):
        result = self._run("clients", "--json")
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertIn("clients", data)
        self.assertGreaterEqual(len(data["clients"]), 27)

    def test_clients_text(self):
        result = self._run("clients")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Claude Code", result.stdout)
        self.assertIn("Gemini CLI", result.stdout)

    def test_detect_json(self):
        result = self._run("detect", "--json")
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertIn("platform", data)
        self.assertIn("clients", data)
        self.assertIn("total_detected", data)

    def test_detect_audit(self):
        result = self._run("detect", "--audit")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Audit", result.stdout)

    def test_protection_status(self):
        result = self._run("protection", "status")
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertIn("enabled", data)

    def test_watch_status(self):
        result = self._run("watch", "--status")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Platform", result.stdout)


class TestRunUninstallHandler(unittest.TestCase):
    """Unit tests for the ``_run_uninstall`` dispatch wrapper.

    The end-to-end CLI is already covered via subprocess in
    ``TestAgentCLI`` above.  These tests pin the contract of the thin
    wrapper itself: JSON on stdout, exit-code mapping from
    ``UninstallResult.ok``, and correct propagation of ``--keep-data``
    into the call.  Running them in-process keeps the round-trip fast
    and lets us assert on the exact orchestrator call, which a
    subprocess test cannot observe.
    """

    @staticmethod
    def _args(*, keep_data: bool = False) -> argparse.Namespace:
        return argparse.Namespace(keep_data=keep_data, non_interactive=False)

    def test_prints_json_and_exits_zero_when_result_is_ok(self):
        ok_result = UninstallResult(steps={"protection_disable": "ok"})
        buf = io.StringIO()
        with (
            patch("lumen_argus_agent.cli.sys.stdout", buf),
            patch("lumen_argus_agent.uninstall.uninstall_agent", return_value=ok_result) as fake,
        ):
            _run_uninstall(self._args())  # does not raise SystemExit

        fake.assert_called_once_with(keep_data=False)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["steps"], {"protection_disable": "ok"})
        self.assertEqual(payload["errors"], [])

    def test_exits_nonzero_when_result_has_errors(self):
        failed = UninstallResult(
            steps={"protection_disable": "failed"},
            errors=["protection_disable: boom"],
        )
        buf = io.StringIO()
        with (
            patch("lumen_argus_agent.cli.sys.stdout", buf),
            patch("lumen_argus_agent.uninstall.uninstall_agent", return_value=failed),
            self.assertRaises(SystemExit) as cm,
        ):
            _run_uninstall(self._args())
        self.assertEqual(cm.exception.code, 1)
        # The JSON still has to be on stdout before the exit — callers
        # (tray app) parse it even on the failure path.
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["errors"], ["protection_disable: boom"])

    def test_keep_data_flag_is_forwarded(self):
        ok = UninstallResult(steps={"protection_disable": "ok"})
        with (
            patch("lumen_argus_agent.cli.sys.stdout", io.StringIO()),
            patch("lumen_argus_agent.uninstall.uninstall_agent", return_value=ok) as fake,
        ):
            _run_uninstall(self._args(keep_data=True))
        fake.assert_called_once_with(keep_data=True)


class TestRefreshPolicyCLI(unittest.TestCase):
    """refresh-policy subcommand contract: exit codes + JSON shape."""

    _ENROLLED: ClassVar[dict] = {
        "server": "https://argus.corp.io",
        "proxy_url": "https://argus.corp.io:8080",
        "dashboard_url": "https://argus.corp.io:8081",
        "organization": "Acme",
        "policy": {"fail_mode": "open"},
        "enrolled_at": "2026-04-02T10:30:00Z",
        "agent_id": "agent_abc",
        "machine_id": "mac_abc",
        "agent_token": "la_agent_token",
    }

    @staticmethod
    def _args(*, json_flag: bool = False) -> argparse.Namespace:
        return argparse.Namespace(json=json_flag, non_interactive=False)

    def test_exit_code_2_when_not_enrolled(self):
        with (
            patch("lumen_argus_core.enrollment.load_enrollment", return_value=None),
            self.assertRaises(SystemExit) as cm,
        ):
            _run_refresh_policy(self._args())
        self.assertEqual(cm.exception.code, 2)

    def test_exit_code_1_on_network_error(self):
        with (
            patch("lumen_argus_core.enrollment.load_enrollment", return_value=self._ENROLLED),
            patch("lumen_argus_core.enrollment.fetch_policy", side_effect=EnrollmentError("boom")),
            self.assertRaises(SystemExit) as cm,
        ):
            _run_refresh_policy(self._args())
        self.assertEqual(cm.exception.code, 1)

    def test_exit_code_1_when_enrollment_lacks_token(self):
        state = dict(self._ENROLLED)
        state.pop("agent_token")
        with (
            patch("lumen_argus_core.enrollment.load_enrollment", return_value=state),
            self.assertRaises(SystemExit) as cm,
        ):
            _run_refresh_policy(self._args())
        self.assertEqual(cm.exception.code, 1)

    def test_success_exit_zero_and_text_output(self):
        buf = io.StringIO()
        with (
            patch("lumen_argus_core.enrollment.load_enrollment", return_value=self._ENROLLED),
            patch("lumen_argus_core.enrollment.fetch_policy", return_value={"fail_mode": "closed"}),
            patch("lumen_argus_core.enrollment.update_enrollment_policy", return_value=True),
            patch("lumen_argus_agent.cli.sys.stdout", buf),
        ):
            _run_refresh_policy(self._args())
        self.assertIn("Policy refreshed", buf.getvalue())

    def test_json_output_shape(self):
        buf = io.StringIO()
        with (
            patch("lumen_argus_core.enrollment.load_enrollment", return_value=self._ENROLLED),
            patch("lumen_argus_core.enrollment.fetch_policy", return_value={"fail_mode": "closed"}),
            patch("lumen_argus_core.enrollment.update_enrollment_policy", return_value=True),
            patch("lumen_argus_agent.cli.sys.stdout", buf),
        ):
            _run_refresh_policy(self._args(json_flag=True))
        payload = json.loads(buf.getvalue())
        self.assertIn("changed", payload)
        self.assertIn("policy_version", payload)
        self.assertTrue(payload["changed"])
        # policy_version mirrors enrolled_at — stable across no-op refreshes
        self.assertEqual(payload["policy_version"], self._ENROLLED["enrolled_at"])

    def test_json_output_when_unchanged(self):
        buf = io.StringIO()
        with (
            patch("lumen_argus_core.enrollment.load_enrollment", return_value=self._ENROLLED),
            patch("lumen_argus_core.enrollment.fetch_policy", return_value={"fail_mode": "open"}),
            patch("lumen_argus_core.enrollment.update_enrollment_policy", return_value=False),
            patch("lumen_argus_agent.cli.sys.stdout", buf),
        ):
            _run_refresh_policy(self._args(json_flag=True))
        payload = json.loads(buf.getvalue())
        self.assertFalse(payload["changed"])
        # Same anchor on no-op — downstream callers must see a stable version.
        self.assertEqual(payload["policy_version"], self._ENROLLED["enrolled_at"])


class TestRefreshPolicySubprocess(unittest.TestCase):
    """End-to-end subprocess tests for refresh-policy (not-enrolled case only)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = {**os.environ, "HOME": self.tmpdir, "USERPROFILE": self.tmpdir}
        return subprocess.run(
            [sys.executable, "-m", "lumen_argus_agent", *args],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )

    def test_refresh_policy_not_enrolled_exits_two(self):
        result = self._run("refresh-policy")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("Not enrolled", result.stderr)

    def test_refresh_policy_help_documents_exit_codes(self):
        result = self._run("refresh-policy", "--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Exit codes", result.stdout)
        self.assertIn("--json", result.stdout)


if __name__ == "__main__":
    unittest.main()
