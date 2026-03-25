"""Tests for the allowlist matcher."""

import unittest

from lumen_argus.allowlist import AllowlistMatcher


class TestAllowlistMatcher(unittest.TestCase):
    def test_exact_secret_match(self):
        al = AllowlistMatcher(secrets=["AKIAIOSFODNN7EXAMPLE"])
        self.assertTrue(al.is_allowed_secret("AKIAIOSFODNN7EXAMPLE"))
        self.assertFalse(al.is_allowed_secret("AKIAIOSFODNN7OTHER"))

    def test_glob_secret_match(self):
        al = AllowlistMatcher(secrets=["sk-ant-api03-example*"])
        self.assertTrue(al.is_allowed_secret("sk-ant-api03-example-key"))
        self.assertFalse(al.is_allowed_secret("sk-ant-api03-real-key"))

    def test_pii_domain_glob(self):
        al = AllowlistMatcher(pii=["*@example.com"])
        self.assertTrue(al.is_allowed_pii("test@example.com"))
        self.assertTrue(al.is_allowed_pii("admin@example.com"))
        self.assertFalse(al.is_allowed_pii("user@company.com"))

    def test_path_glob(self):
        al = AllowlistMatcher(paths=["test/**", "fixtures/**"])
        self.assertTrue(al.is_allowed_path("test/data/secrets.txt"))
        self.assertTrue(al.is_allowed_path("fixtures/sample.json"))
        self.assertFalse(al.is_allowed_path("src/main.py"))

    def test_empty_allowlist(self):
        al = AllowlistMatcher()
        self.assertFalse(al.is_allowed_secret("anything"))
        self.assertFalse(al.is_allowed_pii("anything"))
        self.assertFalse(al.is_allowed_path("anything"))

    def test_multiple_patterns(self):
        al = AllowlistMatcher(secrets=["sk_test_*", "AKIA*", "ghp_example*"])
        self.assertTrue(al.is_allowed_secret("sk_test_abc123"))
        self.assertTrue(al.is_allowed_secret("AKIAIOSFODNN7EXAMPLE"))
        self.assertTrue(al.is_allowed_secret("ghp_example_token"))
        self.assertFalse(al.is_allowed_secret("real_secret"))

    def test_special_regex_chars_escaped(self):
        """fnmatch.translate properly escapes regex metacharacters."""
        al = AllowlistMatcher(secrets=["sk.test+key"])
        # Dots and plus are literal in fnmatch (not regex wildcards)
        self.assertTrue(al.is_allowed_secret("sk.test+key"))
        self.assertFalse(al.is_allowed_secret("skXtestXkey"))

    def test_question_mark_glob(self):
        al = AllowlistMatcher(secrets=["key_?_test"])
        self.assertTrue(al.is_allowed_secret("key_A_test"))
        self.assertFalse(al.is_allowed_secret("key_AB_test"))

    def test_large_allowlist(self):
        """100+ patterns compile and match correctly."""
        patterns = ["pattern_%d_*" % i for i in range(150)]
        al = AllowlistMatcher(secrets=patterns)
        self.assertTrue(al.is_allowed_secret("pattern_0_value"))
        self.assertTrue(al.is_allowed_secret("pattern_149_value"))
        self.assertFalse(al.is_allowed_secret("pattern_150_value"))
        self.assertFalse(al.is_allowed_secret("unrelated"))

    def test_no_partial_match(self):
        """Pattern must match the full value, not a substring."""
        al = AllowlistMatcher(secrets=["abc"])
        self.assertTrue(al.is_allowed_secret("abc"))
        self.assertFalse(al.is_allowed_secret("abcdef"))
        self.assertFalse(al.is_allowed_secret("xabc"))


if __name__ == "__main__":
    unittest.main()
