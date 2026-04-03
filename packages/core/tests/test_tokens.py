"""Tests for token generation, validation, and hashing."""

import unittest

from lumen_argus_core.tokens import (
    extract_type,
    generate_token,
    hash_token,
    validate_format,
)


class TestGenerateToken(unittest.TestCase):
    """Test token generation."""

    def test_generates_agent_token(self):
        token = generate_token("agent")
        self.assertTrue(token.startswith("la_agent_"))

    def test_generates_enroll_token(self):
        token = generate_token("enroll")
        self.assertTrue(token.startswith("la_enroll_"))

    def test_generates_org_token(self):
        token = generate_token("org")
        self.assertTrue(token.startswith("la_org_"))

    def test_invalid_type_raises(self):
        with self.assertRaises(ValueError):
            generate_token("invalid")

    def test_token_length(self):
        token = generate_token("agent")
        # la_agent_ (9) + 30 random + 6 CRC = 45
        self.assertEqual(len(token), 9 + 30 + 6)

    def test_tokens_are_unique(self):
        tokens = {generate_token("agent") for _ in range(100)}
        self.assertEqual(len(tokens), 100)

    def test_token_is_ascii_safe(self):
        token = generate_token("agent")
        self.assertTrue(token.isascii())
        # No special chars that need URL encoding
        for c in token:
            self.assertTrue(c.isalnum() or c == "_", f"unexpected char: {c!r}")


class TestValidateFormat(unittest.TestCase):
    """Test offline token format validation."""

    def test_valid_token_passes(self):
        token = generate_token("agent")
        self.assertTrue(validate_format(token))

    def test_all_types_validate(self):
        for token_type in ("agent", "enroll", "org"):
            token = generate_token(token_type)
            self.assertTrue(validate_format(token), f"failed for type {token_type}")

    def test_empty_string_fails(self):
        self.assertFalse(validate_format(""))

    def test_wrong_prefix_fails(self):
        self.assertFalse(validate_format("la_bad_" + "a" * 36))

    def test_truncated_token_fails(self):
        token = generate_token("agent")
        self.assertFalse(validate_format(token[:-1]))

    def test_corrupted_crc_fails(self):
        token = generate_token("agent")
        # Flip the last character
        corrupted = token[:-1] + ("a" if token[-1] != "a" else "b")
        self.assertFalse(validate_format(corrupted))

    def test_corrupted_body_fails(self):
        token = generate_token("agent")
        # Flip a character in the random body
        prefix = "la_agent_"
        body = list(token[len(prefix) :])
        body[5] = "a" if body[5] != "a" else "b"
        corrupted = prefix + "".join(body)
        self.assertFalse(validate_format(corrupted))

    def test_non_base62_chars_fail(self):
        self.assertFalse(validate_format("la_agent_" + "!" * 36))

    def test_random_string_fails(self):
        self.assertFalse(validate_format("not-a-token-at-all"))


class TestHashToken(unittest.TestCase):
    """Test token hashing."""

    def test_returns_64_hex_chars(self):
        token = generate_token("agent")
        h = hash_token(token)
        self.assertEqual(len(h), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in h))

    def test_deterministic(self):
        token = generate_token("agent")
        self.assertEqual(hash_token(token), hash_token(token))

    def test_different_tokens_different_hashes(self):
        t1 = generate_token("agent")
        t2 = generate_token("agent")
        self.assertNotEqual(hash_token(t1), hash_token(t2))


class TestExtractType(unittest.TestCase):
    """Test token type extraction."""

    def test_agent_type(self):
        self.assertEqual(extract_type(generate_token("agent")), "agent")

    def test_enroll_type(self):
        self.assertEqual(extract_type(generate_token("enroll")), "enroll")

    def test_org_type(self):
        self.assertEqual(extract_type(generate_token("org")), "org")

    def test_unknown_returns_none(self):
        self.assertIsNone(extract_type("not_a_token"))

    def test_empty_returns_none(self):
        self.assertIsNone(extract_type(""))
