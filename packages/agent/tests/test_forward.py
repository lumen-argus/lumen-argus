"""Tests for forward proxy orchestration."""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from lumen_argus_agent import forward


class TestForwardProxyConfig(unittest.TestCase):
    """Test ForwardProxyConfig defaults."""

    def test_defaults(self):
        config = forward.ForwardProxyConfig()
        self.assertEqual(config.bind, "127.0.0.1")
        self.assertEqual(config.port, 9090)
        self.assertEqual(config.upstream_proxy, "http://localhost:8080")
        self.assertEqual(config.agent_token, "")
        self.assertTrue(config.send_username)
        self.assertTrue(config.send_hostname)


class TestAliases(unittest.TestCase):
    """Test shell alias file management."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self._orig_aliases = forward._ALIASES_PATH
        self._orig_argus_dir = forward._ARGUS_DIR
        forward._ARGUS_DIR = self.tmpdir
        forward._ALIASES_PATH = os.path.join(self.tmpdir, "forward-proxy-aliases.sh")

    def tearDown(self):
        forward._ALIASES_PATH = self._orig_aliases
        forward._ARGUS_DIR = self._orig_argus_dir
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_write_aliases(self):
        path = forward.write_aliases(9090, "/tmp/ca-cert.pem")
        self.assertTrue(os.path.isfile(path))
        with open(path) as f:
            content = f.read()
        self.assertIn("alias copilot=", content)
        self.assertIn("HTTPS_PROXY=http://localhost:9090", content)
        self.assertIn("NODE_EXTRA_CA_CERTS=/tmp/ca-cert.pem", content)

    def test_write_aliases_custom_port(self):
        forward.write_aliases(9100, "/tmp/ca.pem")
        with open(forward._ALIASES_PATH) as f:
            content = f.read()
        self.assertIn("HTTPS_PROXY=http://localhost:9100", content)

    def test_clear_aliases(self):
        forward.write_aliases(9090, "/tmp/ca.pem")
        forward.clear_aliases()
        with open(forward._ALIASES_PATH) as f:
            content = f.read()
        self.assertIn("disabled", content)
        self.assertNotIn("alias copilot=", content)

    def test_get_aliases_path(self):
        path = forward.get_aliases_path()
        self.assertEqual(path, forward._ALIASES_PATH)


class TestForwardProxyState(unittest.TestCase):
    """Test forward proxy state file management."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self._orig_state = forward._FORWARD_STATE_PATH
        self._orig_argus_dir = forward._ARGUS_DIR
        forward._ARGUS_DIR = self.tmpdir
        forward._FORWARD_STATE_PATH = os.path.join(self.tmpdir, "forward-proxy.json")

    def tearDown(self):
        forward._FORWARD_STATE_PATH = self._orig_state
        forward._ARGUS_DIR = self._orig_argus_dir
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_no_state_returns_none(self):
        self.assertIsNone(forward.load_forward_proxy_state())

    def test_write_and_load_state(self):
        config = forward.ForwardProxyConfig(port=9090, upstream_proxy="http://localhost:8080")
        with mock.patch("lumen_argus_agent.ca.get_ca_cert_path", return_value="/tmp/ca.pem"):
            forward._write_state(config)

        state = forward.load_forward_proxy_state()
        self.assertIsNotNone(state)
        self.assertEqual(state["port"], 9090)
        self.assertEqual(state["upstream_proxy"], "http://localhost:8080")
        self.assertEqual(state["pid"], os.getpid())

    def test_stale_state_removed(self):
        """Dead PID should result in None and removal of state file."""
        import json

        state = {"port": 9090, "pid": 99999999, "upstream_proxy": "http://localhost:8080"}
        with open(forward._FORWARD_STATE_PATH, "w") as f:
            json.dump(state, f)

        result = forward.load_forward_proxy_state()
        self.assertIsNone(result)
        self.assertFalse(os.path.exists(forward._FORWARD_STATE_PATH))

    def test_remove_state(self):
        config = forward.ForwardProxyConfig()
        with mock.patch("lumen_argus_agent.ca.get_ca_cert_path", return_value="/tmp/ca.pem"):
            forward._write_state(config)
        self.assertTrue(os.path.isfile(forward._FORWARD_STATE_PATH))
        forward._remove_state()
        self.assertFalse(os.path.isfile(forward._FORWARD_STATE_PATH))

    def test_remove_state_nonexistent(self):
        # Should not raise
        forward._remove_state()


if __name__ == "__main__":
    unittest.main()
