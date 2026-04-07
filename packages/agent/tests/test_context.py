"""Tests for caller context resolution."""

import os
import platform
import unittest
from unittest.mock import patch

from lumen_argus_agent.context import (
    CallerContext,
    _get_process_cwd,
    _get_process_executable,
    _git_branch,
    _lsof_pid,
    _proc_net_pid,
    resolve_context,
    static_context,
)


class TestCallerContext(unittest.TestCase):
    """CallerContext dataclass defaults."""

    def test_defaults(self):
        ctx = CallerContext()
        self.assertEqual(ctx.working_directory, "")
        self.assertEqual(ctx.git_branch, "")
        self.assertEqual(ctx.os_platform, "")
        self.assertEqual(ctx.hostname, "")
        self.assertEqual(ctx.username, "")
        self.assertEqual(ctx.client_pid, 0)
        self.assertEqual(ctx.client_executable, "")


class TestStaticContext(unittest.TestCase):
    """Static (machine-level) context."""

    def test_returns_os_platform(self):
        ctx = static_context()
        self.assertEqual(ctx.os_platform, platform.system().lower())

    def test_returns_hostname(self):
        ctx = static_context()
        self.assertTrue(len(ctx.hostname) > 0)

    def test_returns_username(self):
        ctx = static_context()
        self.assertTrue(len(ctx.username) > 0)

    def test_working_directory_empty(self):
        """Static context has no working_directory — needs PID resolution."""
        ctx = static_context()
        self.assertEqual(ctx.working_directory, "")


class TestResolveContext(unittest.TestCase):
    """resolve_context() with mocked PID resolution."""

    @patch("lumen_argus_agent.context._source_port_to_pid", return_value=0)
    def test_no_pid_returns_static(self, _mock):
        ctx = resolve_context(8070, 54321)
        self.assertEqual(ctx.client_pid, 0)
        self.assertEqual(ctx.working_directory, "")
        # Machine-level fields still populated
        self.assertTrue(len(ctx.os_platform) > 0)

    @patch("lumen_argus_agent.context._get_process_executable", return_value="/usr/bin/claude")
    @patch("lumen_argus_agent.context._git_branch", return_value="main")
    @patch("lumen_argus_agent.context._get_process_cwd", return_value="/Users/dev/project-a")
    @patch("lumen_argus_agent.context._source_port_to_pid", return_value=12345)
    def test_pid_resolved_populates_all(self, _pid, _cwd, _branch, _exe):
        ctx = resolve_context(8070, 54321)
        self.assertEqual(ctx.client_pid, 12345)
        self.assertEqual(ctx.working_directory, "/Users/dev/project-a")
        self.assertEqual(ctx.git_branch, "main")
        self.assertEqual(ctx.client_executable, "/usr/bin/claude")

    @patch("lumen_argus_agent.context._get_process_executable", return_value="")
    @patch("lumen_argus_agent.context._git_branch", return_value="")
    @patch("lumen_argus_agent.context._get_process_cwd", return_value="")
    @patch("lumen_argus_agent.context._source_port_to_pid", return_value=99)
    def test_pid_resolved_but_cwd_fails(self, _pid, _cwd, _branch, _exe):
        ctx = resolve_context(8070, 54321)
        self.assertEqual(ctx.client_pid, 99)
        self.assertEqual(ctx.working_directory, "")
        self.assertEqual(ctx.git_branch, "")


class TestGitBranch(unittest.TestCase):
    """Git branch detection."""

    def test_empty_cwd(self):
        self.assertEqual(_git_branch(""), "")

    def test_current_directory(self):
        """Should return a branch for the current git repo."""
        cwd = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        branch = _git_branch(cwd)
        # We're in a git repo, so this should be non-empty
        self.assertTrue(len(branch) > 0, "expected branch in git repo at %s" % cwd)

    @patch("subprocess.run", side_effect=OSError("git not found"))
    def test_git_not_installed(self, _mock):
        self.assertEqual(_git_branch("/some/dir"), "")


class TestGetProcessCwd(unittest.TestCase):
    """Process cwd resolution."""

    def test_own_process(self):
        """Should be able to get our own process's cwd."""
        cwd = _get_process_cwd(os.getpid())
        # May or may not work depending on OS and permissions
        # On macOS with lsof, should work for own process
        if platform.system() in ("Darwin", "Linux"):
            self.assertTrue(len(cwd) > 0, "expected cwd for own process on %s" % platform.system())

    def test_nonexistent_pid(self):
        # macOS lsof may return "/" for invalid PIDs; accept "" or "/"
        cwd = _get_process_cwd(999999999)
        self.assertIn(cwd, ("", "/"))


class TestGetProcessExecutable(unittest.TestCase):
    """Process executable resolution."""

    def test_own_process(self):
        exe = _get_process_executable(os.getpid())
        # ps should return something for our own process
        self.assertTrue(len(exe) > 0)

    def test_nonexistent_pid(self):
        exe = _get_process_executable(999999999)
        self.assertEqual(exe, "")


class TestLsofPid(unittest.TestCase):
    """macOS lsof PID resolution."""

    @unittest.skipUnless(platform.system() == "Darwin", "macOS only")
    def test_no_connections_returns_zero(self):
        # Port 1 is unlikely to have connections
        self.assertEqual(_lsof_pid(1, 1), 0)

    @patch("subprocess.run", side_effect=OSError("lsof not found"))
    def test_lsof_not_available(self, _mock):
        self.assertEqual(_lsof_pid(8070, 54321), 0)


class TestProcNetPid(unittest.TestCase):
    """Linux /proc/net/tcp PID resolution."""

    @unittest.skipUnless(platform.system() == "Linux", "Linux only")
    def test_nonexistent_port(self):
        self.assertEqual(_proc_net_pid(1), 0)

    @unittest.skipIf(platform.system() == "Linux", "non-Linux")
    def test_non_linux_returns_zero(self):
        self.assertEqual(_proc_net_pid(54321), 0)


if __name__ == "__main__":
    unittest.main()
