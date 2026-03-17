"""Tests for git diff scanning."""

import unittest

from lumen_argus.scanner import _parse_diff


class TestParseDiff(unittest.TestCase):
    def test_single_file_added_lines(self):
        diff = """\
diff --git a/config.py b/config.py
index abc123..def456 100644
--- a/config.py
+++ b/config.py
@@ -10,0 +11,2 @@
+API_KEY = "sk-secret-12345"
+DB_URL = "postgres://user:pass@host/db"
"""
        result = _parse_diff(diff)
        self.assertIn("config.py", result)
        self.assertIn("sk-secret-12345", result["config.py"])
        self.assertIn("postgres://user:pass@host/db", result["config.py"])

    def test_deleted_lines_ignored(self):
        diff = """\
diff --git a/old.py b/old.py
--- a/old.py
+++ b/old.py
@@ -5,2 +5,1 @@
-OLD_SECRET = "removed_secret"
+REPLACEMENT = "safe_value"
"""
        result = _parse_diff(diff)
        self.assertIn("old.py", result)
        self.assertNotIn("removed_secret", result["old.py"])
        self.assertIn("safe_value", result["old.py"])

    def test_multiple_files(self):
        diff = """\
diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1,0 +2 @@
+line_in_a
diff --git a/b.py b/b.py
--- a/b.py
+++ b/b.py
@@ -1,0 +2 @@
+line_in_b
"""
        result = _parse_diff(diff)
        self.assertEqual(len(result), 2)
        self.assertIn("a.py", result)
        self.assertIn("b.py", result)
        self.assertIn("line_in_a", result["a.py"])
        self.assertIn("line_in_b", result["b.py"])

    def test_empty_diff(self):
        result = _parse_diff("")
        self.assertEqual(result, {})

    def test_no_added_lines(self):
        diff = """\
diff --git a/file.py b/file.py
--- a/file.py
+++ b/file.py
@@ -5,2 +5,0 @@
-removed_line_1
-removed_line_2
"""
        result = _parse_diff(diff)
        self.assertEqual(result, {})

    def test_new_file(self):
        diff = """\
diff --git a/new.py b/new.py
new file mode 100644
--- /dev/null
+++ b/new.py
@@ -0,0 +1,3 @@
+#!/usr/bin/env python3
+SECRET = "my_secret"
+print("hello")
"""
        result = _parse_diff(diff)
        self.assertIn("new.py", result)
        self.assertIn("my_secret", result["new.py"])

    def test_path_with_directories(self):
        diff = """\
diff --git a/src/config/settings.py b/src/config/settings.py
--- a/src/config/settings.py
+++ b/src/config/settings.py
@@ -1,0 +2 @@
+TOKEN = "abc123"
"""
        result = _parse_diff(diff)
        self.assertIn("src/config/settings.py", result)

    def test_plus_plus_plus_header_not_treated_as_content(self):
        diff = """\
diff --git a/file.py b/file.py
--- a/file.py
+++ b/file.py
@@ -1,0 +2 @@
+real content
"""
        result = _parse_diff(diff)
        self.assertIn("file.py", result)
        self.assertNotIn("+++ b/file.py", result["file.py"])
        self.assertIn("real content", result["file.py"])


if __name__ == "__main__":
    unittest.main()
