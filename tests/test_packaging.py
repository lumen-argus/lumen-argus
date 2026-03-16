"""Tests for package installation and CLI entry point."""

import subprocess
import sys
import unittest


class TestPackaging(unittest.TestCase):
    def test_version_command(self):
        result = subprocess.run(
            [sys.executable, "-m", "lumen_argus", "--version"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("lumen-argus", result.stdout)

    def test_help_command(self):
        result = subprocess.run(
            [sys.executable, "-m", "lumen_argus", "--help"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("serve", result.stdout)
        self.assertIn("scan", result.stdout)

    def test_serve_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "lumen_argus", "serve", "--help"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("--port", result.stdout)
        self.assertIn("--format", result.stdout)

    def test_scan_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "lumen_argus", "scan", "--help"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("files", result.stdout)


if __name__ == "__main__":
    unittest.main()
