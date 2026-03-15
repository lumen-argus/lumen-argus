"""Session statistics: thread-safe counters for requests, findings, and timing."""

import threading
from typing import Dict, List

from lumen_argus.models import ScanResult


class SessionStats:
    """Thread-safe session statistics collector."""

    def __init__(self):
        self._lock = threading.Lock()
        self.total_requests = 0
        self.total_bytes_scanned = 0
        self.actions = {"pass": 0, "log": 0, "alert": 0, "block": 0}  # type: Dict[str, int]
        self.providers = {}  # type: Dict[str, int]
        self.finding_types = {}  # type: Dict[str, int]
        self.scan_times_ms = []  # type: List[float]

    def record(
        self,
        provider: str,
        body_size: int,
        result: ScanResult,
    ) -> None:
        """Record a completed request."""
        with self._lock:
            self.total_requests += 1
            self.total_bytes_scanned += body_size

            action = result.action
            if action in self.actions:
                self.actions[action] += 1
            else:
                self.actions[action] = 1

            self.providers[provider] = self.providers.get(provider, 0) + 1

            for f in result.findings:
                self.finding_types[f.type] = self.finding_types.get(f.type, 0) + 1

            if result.scan_duration_ms > 0:
                self.scan_times_ms.append(result.scan_duration_ms)

    def summary(self) -> dict:
        """Return a snapshot of current stats."""
        with self._lock:
            avg_scan = 0.0
            p95_scan = 0.0
            if self.scan_times_ms:
                avg_scan = sum(self.scan_times_ms) / len(self.scan_times_ms)
                sorted_times = sorted(self.scan_times_ms)
                p95_idx = int(len(sorted_times) * 0.95)
                p95_scan = sorted_times[min(p95_idx, len(sorted_times) - 1)]

            return {
                "total_requests": self.total_requests,
                "total_bytes_scanned": self.total_bytes_scanned,
                "actions": dict(self.actions),
                "providers": dict(self.providers),
                "finding_types": dict(self.finding_types),
                "avg_scan_ms": round(avg_scan, 1),
                "p95_scan_ms": round(p95_scan, 1),
            }
