"""Tests for session statistics."""

import unittest

from lumen_argus.models import Finding, ScanResult
from lumen_argus.stats import SessionStats


class TestSessionStats(unittest.TestCase):
    def test_empty_summary(self):
        stats = SessionStats()
        s = stats.summary()
        self.assertEqual(s["total_requests"], 0)
        self.assertEqual(s["avg_scan_ms"], 0)

    def test_record_pass(self):
        stats = SessionStats()
        stats.record("anthropic", 1000, ScanResult(action="pass", scan_duration_ms=5.0))
        s = stats.summary()
        self.assertEqual(s["total_requests"], 1)
        self.assertEqual(s["actions"]["pass"], 1)
        self.assertEqual(s["providers"]["anthropic"], 1)
        self.assertEqual(s["total_bytes_scanned"], 1000)

    def test_record_with_findings(self):
        stats = SessionStats()
        result = ScanResult(
            action="alert",
            scan_duration_ms=10.0,
            findings=[
                Finding(detector="secrets", type="aws_access_key", severity="critical",
                        location="msg[0]", value_preview="AKIA****", matched_value="x"),
                Finding(detector="pii", type="email", severity="warning",
                        location="msg[1]", value_preview="john****", matched_value="x"),
            ],
        )
        stats.record("anthropic", 5000, result)
        s = stats.summary()
        self.assertEqual(s["actions"]["alert"], 1)
        self.assertEqual(s["finding_types"]["aws_access_key"], 1)
        self.assertEqual(s["finding_types"]["email"], 1)

    def test_multiple_requests(self):
        stats = SessionStats()
        stats.record("anthropic", 1000, ScanResult(action="pass", scan_duration_ms=5.0))
        stats.record("openai", 2000, ScanResult(action="alert", scan_duration_ms=15.0))
        stats.record("anthropic", 3000, ScanResult(action="block", scan_duration_ms=8.0))

        s = stats.summary()
        self.assertEqual(s["total_requests"], 3)
        self.assertEqual(s["total_bytes_scanned"], 6000)
        self.assertEqual(s["providers"]["anthropic"], 2)
        self.assertEqual(s["providers"]["openai"], 1)
        self.assertEqual(s["actions"]["pass"], 1)
        self.assertEqual(s["actions"]["alert"], 1)
        self.assertEqual(s["actions"]["block"], 1)
        self.assertGreater(s["avg_scan_ms"], 0)
        self.assertGreater(s["p95_scan_ms"], 0)

    def test_scan_timing_stats(self):
        stats = SessionStats()
        for ms in [5.0, 10.0, 15.0, 20.0, 25.0]:
            stats.record("anthropic", 100, ScanResult(action="pass", scan_duration_ms=ms))

        s = stats.summary()
        self.assertAlmostEqual(s["avg_scan_ms"], 15.0)
        self.assertGreaterEqual(s["p95_scan_ms"], 20.0)


if __name__ == "__main__":
    unittest.main()
