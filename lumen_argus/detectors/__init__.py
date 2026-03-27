"""Detection engine base class and exports."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lumen_argus.allowlist import AllowlistMatcher
    from lumen_argus.models import Finding, ScanField


class BaseDetector(ABC):
    """Abstract base for all detectors."""

    @abstractmethod
    def scan(
        self,
        fields: "list[ScanField]",
        allowlist: "AllowlistMatcher",
    ) -> "list[Finding]":
        """Scan extracted fields and return findings."""
        ...
