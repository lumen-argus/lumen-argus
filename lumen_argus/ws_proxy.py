"""WebSocket frame scanning — bidirectional text frame analysis.

WebSocketScanner scans text frames for secrets, PII, and injection patterns.
Used by async_proxy.py which handles the WebSocket relay on the same port
(ws://localhost:8080/ws?url=ws://target).

Binary frames pass through without scanning.
"""

import logging
from typing import List

from lumen_argus.models import Finding, ScanField
from lumen_argus.text_utils import sanitize_text

log = logging.getLogger("argus.ws")


class WebSocketScanner:
    """Scans WebSocket text frames for sensitive data.

    Reuses existing detectors for secret/PII detection.
    Reuses response scanner for injection detection on inbound frames.
    """

    def __init__(
        self,
        detectors: list = None,
        allowlist=None,
        response_scanner=None,
        scan_outbound: bool = True,
        scan_inbound: bool = True,
        max_frame_size: int = 1_048_576,
    ):
        self._detectors = detectors or []
        self._allowlist = allowlist
        self._response_scanner = response_scanner
        self._scan_outbound = scan_outbound
        self._scan_inbound = scan_inbound
        self._max_frame_size = max_frame_size

    def scan_outbound_frame(self, text: str) -> List[Finding]:
        """Scan an outbound text frame (client -> server)."""
        if not self._scan_outbound or not text:
            return []
        return self._scan_text(text, "ws.outbound")

    def scan_inbound_frame(self, text: str) -> List[Finding]:
        """Scan an inbound text frame (server -> client)."""
        if not self._scan_inbound or not text:
            return []

        findings = self._scan_text(text, "ws.inbound")

        # Injection detection on inbound frames
        if self._response_scanner:
            try:
                inj_findings = self._response_scanner._scan_injection_patterns(text)
                for f in inj_findings:
                    f.location = "ws.inbound"
                findings.extend(inj_findings)
            except Exception as e:
                log.warning("ws injection scan failed: %s", e)

        return findings

    def _scan_text(self, text: str, location_prefix: str) -> List[Finding]:
        """Scan text with all detectors."""
        if len(text) > self._max_frame_size:
            log.debug("ws frame truncated: %d -> %d", len(text), self._max_frame_size)
            text = text[: self._max_frame_size]

        text = sanitize_text(text)
        fields = [ScanField(path=location_prefix, text=text)]

        findings = []
        for detector in self._detectors:
            try:
                det_findings = detector.scan(fields, self._allowlist)
                for f in det_findings:
                    f.location = "%s.%s" % (location_prefix, f.location)
                findings.extend(det_findings)
            except Exception as e:
                log.warning("ws detector %s failed: %s", detector.__class__.__name__, e)

        return findings
