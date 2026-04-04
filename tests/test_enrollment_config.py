"""Tests for enrollment config YAML parsing (defaults, custom values, minimum intervals)."""

import os
import tempfile
import unittest

from lumen_argus.config import load_config


class TestEnrollmentConfig(unittest.TestCase):
    """Test that enrollment config loads correctly from YAML."""

    def test_default_enrollment_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            with open(cfg_path, "w") as f:
                f.write("")
            config = load_config(config_path=cfg_path)
            self.assertEqual(config.enrollment.organization, "")
            self.assertEqual(config.enrollment.proxy_url, "")
            self.assertEqual(config.enrollment.policy.fail_mode, "open")
            self.assertTrue(config.enrollment.policy.auto_configure)
            self.assertTrue(config.enrollment.policy.allow_disable_protection)
            self.assertEqual(config.enrollment.policy.telemetry_interval_seconds, 300)
            self.assertEqual(config.enrollment.policy.watch_interval_seconds, 300)

    def test_enrollment_config_from_yaml(self):
        yaml_content = """
enrollment:
  organization: "Test Corp"
  proxy_url: "https://proxy.test.io:8080"
  policy:
    fail_mode: closed
    auto_configure: false
    allow_disable_protection: false
    telemetry_interval_seconds: 600
    watch_interval_seconds: 120
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            with open(cfg_path, "w") as f:
                f.write(yaml_content)
            config = load_config(config_path=cfg_path)
            self.assertEqual(config.enrollment.organization, "Test Corp")
            self.assertEqual(config.enrollment.proxy_url, "https://proxy.test.io:8080")
            self.assertEqual(config.enrollment.policy.fail_mode, "closed")
            self.assertFalse(config.enrollment.policy.auto_configure)
            self.assertFalse(config.enrollment.policy.allow_disable_protection)
            self.assertEqual(config.enrollment.policy.telemetry_interval_seconds, 600)
            self.assertEqual(config.enrollment.policy.watch_interval_seconds, 120)

    def test_enrollment_interval_minimum(self):
        yaml_content = """
enrollment:
  policy:
    telemetry_interval_seconds: 10
    watch_interval_seconds: 5
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            with open(cfg_path, "w") as f:
                f.write(yaml_content)
            config = load_config(config_path=cfg_path)
            self.assertEqual(config.enrollment.policy.telemetry_interval_seconds, 60, "minimum 60s enforced")
            self.assertEqual(config.enrollment.policy.watch_interval_seconds, 60, "minimum 60s enforced")


if __name__ == "__main__":
    unittest.main()
