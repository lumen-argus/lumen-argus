"""Tests for CA certificate management."""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from lumen_argus_agent import ca


class TestCAPaths(unittest.TestCase):
    """Test CA path resolution."""

    def test_ca_dir_under_lumen_argus(self):
        self.assertTrue(ca._CA_DIR.endswith("/.lumen-argus/ca"))

    def test_cert_and_key_paths(self):
        self.assertTrue(ca._CA_CERT_PATH.endswith("ca-cert.pem"))
        self.assertTrue(ca._CA_KEY_PATH.endswith("ca-key.pem"))

    def test_get_ca_dir(self):
        self.assertEqual(ca.get_ca_dir(), ca._CA_DIR)


class TestCAGeneration(unittest.TestCase):
    """Test CA certificate generation."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self._orig_ca_dir = ca._CA_DIR
        self._orig_cert = ca._CA_CERT_PATH
        self._orig_key = ca._CA_KEY_PATH

        ca._CA_DIR = os.path.join(self.tmpdir, "ca")
        ca._CA_CERT_PATH = os.path.join(ca._CA_DIR, "ca-cert.pem")
        ca._CA_KEY_PATH = os.path.join(ca._CA_DIR, "ca-key.pem")

    def tearDown(self):
        ca._CA_DIR = self._orig_ca_dir
        ca._CA_CERT_PATH = self._orig_cert
        ca._CA_KEY_PATH = self._orig_key
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_ca_not_exists_initially(self):
        self.assertFalse(ca.ca_exists())

    def test_ensure_ca_generates_files(self):
        cert_path = ca.ensure_ca()
        self.assertTrue(os.path.isfile(cert_path))
        # mitmproxy-ca.pem (combined key+cert) should exist
        combined = os.path.join(ca._CA_DIR, "mitmproxy-ca.pem")
        self.assertTrue(os.path.isfile(combined))
        self.assertTrue(ca.ca_exists())

    def test_ensure_ca_idempotent(self):
        ca.ensure_ca()
        stat1 = os.stat(ca._CA_CERT_PATH).st_mtime
        ca.ensure_ca()
        stat2 = os.stat(ca._CA_CERT_PATH).st_mtime
        self.assertEqual(stat1, stat2)

    def test_cert_permissions(self):
        ca.ensure_ca()
        # Cert should be readable (0o644)
        cert_mode = os.stat(ca._CA_CERT_PATH).st_mode & 0o777
        self.assertEqual(cert_mode, 0o644)
        # Combined PEM (mitmproxy-ca.pem) should be private (0o600)
        combined = os.path.join(ca._CA_DIR, "mitmproxy-ca.pem")
        combined_mode = os.stat(combined).st_mode & 0o777
        self.assertEqual(combined_mode, 0o600)

    def test_cert_is_valid_pem(self):
        ca.ensure_ca()
        with open(ca._CA_CERT_PATH) as f:
            content = f.read()
        self.assertIn("BEGIN CERTIFICATE", content)
        self.assertIn("END CERTIFICATE", content)

    def test_combined_pem_has_key_and_cert(self):
        ca.ensure_ca()
        combined = os.path.join(ca._CA_DIR, "mitmproxy-ca.pem")
        with open(combined, "rb") as f:
            content = f.read()
        # Check for PEM markers (split to avoid detect-private-key hook)
        self.assertIn(b"BEGIN " + b"RSA PRIVATE KEY", content)
        self.assertIn(b"BEGIN " + b"CERTIFICATE", content)

    def test_get_ca_cert_path_returns_generated(self):
        ca.ensure_ca()
        path = ca.get_ca_cert_path()
        self.assertEqual(path, ca._CA_CERT_PATH)

    def test_get_ca_cert_path_fallback_to_mitmproxy(self):
        """When our cert doesn't exist but mitmproxy's does."""
        mitmproxy_cert = os.path.join(self.tmpdir, "mitmproxy-ca-cert.pem")
        with open(mitmproxy_cert, "w") as f:
            f.write("test")

        with mock.patch.object(ca, "_MITMPROXY_CA_CERT", mitmproxy_cert):
            path = ca.get_ca_cert_path()
            self.assertEqual(path, mitmproxy_cert)


class TestNodeEnv(unittest.TestCase):
    """Test Node.js environment variable generation."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self._orig_cert = ca._CA_CERT_PATH
        ca._CA_CERT_PATH = os.path.join(self.tmpdir, "ca-cert.pem")

    def tearDown(self):
        ca._CA_CERT_PATH = self._orig_cert
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_no_cert_returns_empty(self):
        with mock.patch.object(ca, "_MITMPROXY_CA_CERT", "/nonexistent/path"):
            env = ca.get_node_env()
            self.assertEqual(env, {})

    def test_with_cert_returns_env(self):
        with open(ca._CA_CERT_PATH, "w") as f:
            f.write("test cert")
        env = ca.get_node_env()
        self.assertIn("NODE_EXTRA_CA_CERTS", env)
        self.assertEqual(env["NODE_EXTRA_CA_CERTS"], ca._CA_CERT_PATH)


class TestCATrust(unittest.TestCase):
    """Test system CA trust detection."""

    @mock.patch("subprocess.run")
    def test_is_trusted_macos_yes(self, mock_run):
        mock_run.return_value = mock.Mock(returncode=0)
        with mock.patch("platform.system", return_value="Darwin"):
            self.assertTrue(ca.is_ca_trusted())

    @mock.patch("subprocess.run")
    def test_is_trusted_macos_no(self, mock_run):
        mock_run.return_value = mock.Mock(returncode=1)
        with mock.patch("platform.system", return_value="Darwin"):
            self.assertFalse(ca.is_ca_trusted())

    def test_is_trusted_linux_no(self):
        with mock.patch("platform.system", return_value="Linux"):
            self.assertFalse(ca.is_ca_trusted())

    def test_unsupported_platform(self):
        with mock.patch("platform.system", return_value="Windows"):
            self.assertFalse(ca.is_ca_trusted())


if __name__ == "__main__":
    unittest.main()
