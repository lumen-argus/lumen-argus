"""Allowlist matching — skip known-safe values from detection."""

from __future__ import annotations

import fnmatch
import re
from typing import List, Optional


def _compile_patterns(patterns: List[str]) -> Optional[re.Pattern[str]]:
    """Compile glob patterns into a single regex for O(1) matching.

    Returns compiled regex or None if no patterns.
    Uses fnmatch.translate() to convert each glob to regex,
    then joins with alternation for a single-pass match.
    """
    if not patterns:
        return None
    parts = [fnmatch.translate(p) for p in patterns]
    combined = "|".join(parts)
    return re.compile(combined)


class AllowlistMatcher:
    """Checks values against configured allowlists.

    Patterns are pre-compiled into a single regex at construction time
    for O(1) matching instead of O(N) per-pattern fnmatch calls.
    """

    def __init__(
        self,
        secrets: Optional[List[str]] = None,
        pii: Optional[List[str]] = None,
        paths: Optional[List[str]] = None,
    ):
        self._secrets_re = _compile_patterns(secrets or [])
        self._pii_re = _compile_patterns(pii or [])
        self._paths_re = _compile_patterns(paths or [])

    def is_allowed_secret(self, value: str) -> bool:
        """Check if a secret value is in the allowlist."""
        if self._secrets_re is None:
            return False
        return self._secrets_re.match(value) is not None

    def is_allowed_pii(self, value: str) -> bool:
        """Check if a PII value is in the allowlist."""
        if self._pii_re is None:
            return False
        return self._pii_re.match(value) is not None

    def is_allowed_path(self, path: str) -> bool:
        """Check if a file path is in the path allowlist."""
        if self._paths_re is None:
            return False
        return self._paths_re.match(path) is not None
