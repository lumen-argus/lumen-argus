"""Custom regex detector: user-defined patterns from config."""

from typing import Any

from lumen_argus.allowlist import AllowlistMatcher
from lumen_argus.detectors import BaseDetector
from lumen_argus.detectors.secrets import _build_merged_text, _find_field, _mask_value
from lumen_argus.models import Finding, ScanField


class CustomDetector(BaseDetector):
    """Detects matches for user-defined regex patterns from config.

    Patterns are compiled at config load time and stored in
    CustomRuleConfig objects. This detector uses the same merged-text
    batch scanning approach as SecretsDetector for performance.
    """

    def __init__(self, rules: Any = None) -> None:
        """
        Args:
            rules: List of CustomRuleConfig with compiled regex patterns.
        """
        self._rules: list[Any] = rules or []

    def update_rules(self, rules: Any) -> None:
        """Replace rules — called on SIGHUP config reload."""
        self._rules = rules or []

    def scan(
        self,
        fields: list[ScanField],
        allowlist: AllowlistMatcher,
    ) -> list[Finding]:
        if not fields or not self._rules:
            return []

        merged, boundaries = _build_merged_text(fields)
        findings = []

        for rule in self._rules:
            if not rule.compiled:
                continue
            for match in rule.compiled.finditer(merged):
                value = match.group(1) if match.lastindex else match.group(0)
                if not value:
                    continue
                if allowlist and allowlist.is_allowed_secret(value):
                    continue
                field_idx = _find_field(match.start(), boundaries)
                findings.append(
                    Finding(
                        detector=rule.detector,
                        type=rule.name,
                        severity=rule.severity,
                        location=fields[field_idx].path,
                        value_preview=_mask_value(value),
                        matched_value=value,
                        action=rule.action,  # empty = PolicyEngine uses default
                    )
                )

        return findings
