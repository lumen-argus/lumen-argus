"""Tests for baseline file functionality."""

import json
import os
import tempfile
import unittest

from lumen_argus.baseline import (
    _finding_key,
    filter_baseline,
    load_baseline,
    save_baseline,
)
from lumen_argus.models import Finding


def _finding(detector="secrets", ftype="aws_key", matched="secret123", severity="critical"):
    return Finding(
        detector=detector,
        type=ftype,
        severity=severity,
        location="test",
        value_preview="****",
        matched_value=matched,
    )


class TestFindingKey(unittest.TestCase):
    def test_key_structure(self):
        f = _finding()
        key = _finding_key(f, "config.py")
        self.assertEqual(len(key), 4)
        self.assertEqual(key[0], "secrets")
        self.assertEqual(key[1], "aws_key")
        self.assertEqual(key[2], "config.py")
        self.assertEqual(len(key[3]), 64)  # full sha256 hex

    def test_same_finding_same_key(self):
        f1 = _finding(matched="abc")
        f2 = _finding(matched="abc")
        self.assertEqual(_finding_key(f1, "a.py"), _finding_key(f2, "a.py"))

    def test_different_value_different_key(self):
        f1 = _finding(matched="abc")
        f2 = _finding(matched="xyz")
        self.assertNotEqual(_finding_key(f1, "a.py"), _finding_key(f2, "a.py"))

    def test_different_file_different_key(self):
        f = _finding()
        self.assertNotEqual(_finding_key(f, "a.py"), _finding_key(f, "b.py"))

    def test_matched_value_not_in_key(self):
        f = _finding(matched="SUPER_SECRET")
        key = _finding_key(f, "test.py")
        for part in key:
            self.assertNotIn("SUPER_SECRET", str(part))


class TestLoadBaseline(unittest.TestCase):
    def test_nonexistent_file(self):
        result = load_baseline("/nonexistent/baseline.json")
        self.assertEqual(result, set())

    def test_valid_baseline(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                {
                    "version": "1",
                    "findings": [
                        {"detector": "secrets", "type": "aws_key", "file": "a.py", "value_hash": "abc123"},
                        {"detector": "pii", "type": "email", "file": "b.py", "value_hash": "def456"},
                    ],
                },
                f,
            )
            path = f.name
        try:
            result = load_baseline(path)
            self.assertEqual(len(result), 2)
            self.assertIn(("secrets", "aws_key", "a.py", "abc123"), result)
            self.assertIn(("pii", "email", "b.py", "def456"), result)
        finally:
            os.unlink(path)

    def test_invalid_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not json")
            path = f.name
        try:
            result = load_baseline(path)
            self.assertEqual(result, set())
        finally:
            os.unlink(path)


class TestSaveBaseline(unittest.TestCase):
    def test_save_and_load_roundtrip(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            findings = {
                "a.py": [_finding(matched="secret1")],
                "b.py": [_finding(ftype="email", matched="test@test.com")],
            }
            save_baseline(path, findings)

            # Load and verify
            with open(path) as f:
                data = json.load(f)
            self.assertEqual(data["version"], "1")
            self.assertEqual(data["count"], 2)
            self.assertEqual(len(data["findings"]), 2)

            # Verify no matched_value in output
            content = open(path).read()
            self.assertNotIn("secret1", content)
            self.assertNotIn("test@test.com", content)
        finally:
            os.unlink(path)

    def test_empty_findings(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            save_baseline(path, {})
            with open(path) as f:
                data = json.load(f)
            self.assertEqual(data["count"], 0)
        finally:
            os.unlink(path)


class TestFilterBaseline(unittest.TestCase):
    def test_known_finding_filtered(self):
        f = _finding(matched="known_secret")
        key = _finding_key(f, "config.py")
        baseline = {key}
        result = filter_baseline([f], "config.py", baseline)
        self.assertEqual(len(result), 0)

    def test_new_finding_kept(self):
        f = _finding(matched="new_secret")
        baseline = {("secrets", "aws_key", "config.py", "different_hash")}
        result = filter_baseline([f], "config.py", baseline)
        self.assertEqual(len(result), 1)

    def test_empty_baseline_keeps_all(self):
        f = _finding()
        result = filter_baseline([f], "config.py", set())
        self.assertEqual(len(result), 1)

    def test_mixed_findings(self):
        known = _finding(matched="known")
        new = _finding(matched="new")
        key = _finding_key(known, "a.py")
        baseline = {key}
        result = filter_baseline([known, new], "a.py", baseline)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].matched_value, "new")


if __name__ == "__main__":
    unittest.main()
