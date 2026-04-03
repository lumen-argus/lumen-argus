"""Token utilities — generation, validation, and hashing.

GitHub-style prefixed tokens with CRC32 checksum for offline validation.
Stdlib only: secrets, hashlib, zlib. No external dependencies.

Token format: la_<type>_<30 Base62 random><6 Base62 CRC32>
- Prefix enables secret scanning (detect `la_agent_` in leaked code)
- CRC32 suffix enables offline format validation before any DB query
- Base62 (a-zA-Z0-9) is terminal-safe, no escaping needed
- 30 Base62 chars = 178 bits entropy (>> 128 bits NIST minimum)

Token types:
- la_agent_   — per-agent bearer token (persistent, rotatable)
- la_enroll_  — one-time enrollment token (time-limited, single/multi-use)
- la_org_     — organization API key for SaaS (persistent, rotatable)

Server-side storage: BLAKE2b-256 hash (64 hex chars). Fast cryptographic
hash — not bcrypt (tokens are already high-entropy, brute-force infeasible).
"""

from __future__ import annotations

import hashlib
import secrets
import string
import zlib

_BASE62 = string.ascii_letters + string.digits  # a-zA-Z0-9
_BASE62_SET = frozenset(_BASE62)  # O(1) membership check for validation
_TOKEN_LENGTH = 30  # 30 Base62 chars = 178 bits entropy
_CRC_LENGTH = 6  # 6 Base62 chars for CRC32 checksum

VALID_PREFIXES = frozenset({"la_agent_", "la_enroll_", "la_org_"})


def _base62_encode(n: int, length: int) -> str:
    """Encode a non-negative integer as a fixed-length Base62 string."""
    chars = []
    for _ in range(length):
        n, remainder = divmod(n, 62)
        chars.append(_BASE62[remainder])
    return "".join(reversed(chars))


def _base62_random(length: int) -> str:
    """Generate a cryptographically random Base62 string."""
    return "".join(secrets.choice(_BASE62) for _ in range(length))


def _compute_crc(prefix: str, random_part: str) -> str:
    """Compute CRC32 checksum of prefix+random as 6-char Base62."""
    raw = (prefix + random_part).encode()
    crc = zlib.crc32(raw) & 0xFFFFFFFF
    return _base62_encode(crc, _CRC_LENGTH)


def generate_token(token_type: str = "agent") -> str:
    """Generate a new token with prefix, random body, and CRC32 checksum.

    Args:
        token_type: One of 'agent', 'enroll', 'org'.

    Returns:
        Token string like 'la_agent_AbCd1234XxYyZzNnMmK7mP2q...'

    Raises:
        ValueError: If token_type is not recognized.
    """
    prefix = f"la_{token_type}_"
    if prefix not in VALID_PREFIXES:
        raise ValueError(f"invalid token type: {token_type!r} (expected: agent, enroll, org)")
    random_part = _base62_random(_TOKEN_LENGTH)
    crc = _compute_crc(prefix, random_part)
    return f"{prefix}{random_part}{crc}"


def validate_format(token: str) -> bool:
    """Validate token format and CRC32 checksum without any DB query.

    Returns True if the token has a valid prefix, correct length,
    Base62 characters, and matching CRC32 checksum. Does NOT verify
    the token exists in the database — use this for early rejection
    of malformed tokens before hitting the DB.
    """
    # Find prefix
    prefix = ""
    for p in VALID_PREFIXES:
        if token.startswith(p):
            prefix = p
            break
    if not prefix:
        return False

    body = token[len(prefix) :]
    expected_length = _TOKEN_LENGTH + _CRC_LENGTH
    if len(body) != expected_length:
        return False

    if not set(body).issubset(_BASE62_SET):
        return False

    # Verify CRC32
    random_part = body[:_TOKEN_LENGTH]
    crc_part = body[_TOKEN_LENGTH:]
    expected_crc = _compute_crc(prefix, random_part)
    return crc_part == expected_crc


def hash_token(token: str) -> str:
    """Hash a token for server-side storage using BLAKE2b-256.

    Returns 64 hex chars. This is the value stored in the database.
    The raw token is never stored — only the hash.

    BLAKE2b is used (not bcrypt/argon2) because tokens are already
    high-entropy (178 bits) — password-style slow hashing is unnecessary
    and would add latency to every authenticated request.
    """
    return hashlib.blake2b(token.encode(), digest_size=32).hexdigest()


def extract_type(token: str) -> str | None:
    """Extract the token type from the prefix.

    Returns 'agent', 'enroll', or 'org'. Returns None if the
    prefix is not recognized.
    """
    for p in VALID_PREFIXES:
        if token.startswith(p):
            # la_agent_ → agent, la_enroll_ → enroll, la_org_ → org
            return p[3:-1]
    return None
