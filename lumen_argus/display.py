"""Terminal display: CLI output with ANSI colors or JSON lines."""

from __future__ import annotations

import json
import sys
import threading
from typing import Any, Optional

from lumen_argus.models import ScanResult


class TerminalDisplay:
    """Handles all terminal output with optional ANSI color support."""

    def __init__(self, no_color: bool = False):
        self._use_color = sys.stdout.isatty() and not no_color
        self._lock = threading.Lock()

    def _c(self, code: str, text: str) -> str:
        """Apply ANSI color code if colors are enabled."""
        if not self._use_color:
            return text
        return "\033[%sm%s\033[0m" % (code, text)

    def _green(self, text: str) -> str:
        return self._c("32", text)

    def _yellow(self, text: str) -> str:
        return self._c("33", text)

    def _red(self, text: str) -> str:
        return self._c("31", text)

    def _cyan(self, text: str) -> str:
        return self._c("36", text)

    def _dim(self, text: str) -> str:
        return self._c("2", text)

    def _bold(self, text: str) -> str:
        return self._c("1", text)

    def show_banner(self, port: int, bind: str = "127.0.0.1") -> None:
        """Display startup banner."""
        with self._lock:
            print()
            print(
                "  %s — listening on %s"
                % (
                    self._bold("lumen-argus"),
                    self._cyan("http://%s:%d" % (bind, port)),
                )
            )
            print()

    def show_request(
        self,
        request_id: int,
        method: str,
        path: str,
        model: str,
        req_size: int,
        resp_size: int,
        duration_ms: float,
        result: ScanResult,
    ) -> None:
        """Display a single request line in the terminal."""
        # Format sizes
        req_str = self._format_size(req_size)
        resp_str = self._format_size(resp_size)
        size_str = "%s->%s" % (req_str, resp_str)

        # Format duration
        if duration_ms >= 1000:
            dur_str = "%.1fs" % (duration_ms / 1000)
        else:
            dur_str = "%dms" % int(duration_ms)

        # Shorten model name for display
        short_model = self._shorten_model(model)

        # Format action/result
        action = result.action.upper()
        if action == "PASS":
            action_str = self._green("PASS")
            detail = ""
        elif action == "ALERT":
            action_str = self._yellow("ALERT")
            detail = self._format_findings_summary(result)
        elif action == "BLOCK":
            action_str = self._red("BLOCK")
            detail = self._format_findings_summary(result)
        elif action == "LOG":
            action_str = self._dim("LOG")
            detail = self._format_findings_summary(result)
        else:
            action_str = action
            detail = ""

        line = "  #%-3d %-4s %-20s %-12s %10s  %6s  %s" % (
            request_id,
            method,
            path[:20],
            short_model,
            size_str,
            dur_str,
            action_str,
        )
        if detail:
            line += "  " + detail

        with self._lock:
            print(line)

    def show_error(self, request_id: int, error: str) -> None:
        """Display a proxy error."""
        with self._lock:
            print(
                "  %s Request #%d: %s"
                % (
                    self._red("[ERROR]"),
                    request_id,
                    error,
                )
            )

    def show_shutdown(self, stats: Optional[dict[str, Any]] = None) -> None:
        """Display shutdown summary with optional session statistics."""
        with self._lock:
            print()
            if not stats or stats.get("total_requests", 0) == 0:
                print("  %s" % self._dim("shutdown"))
                return

            total = stats["total_requests"]
            actions = stats.get("actions", {})
            blocked = actions.get("block", 0)
            alerted = actions.get("alert", 0)
            avg_scan = stats.get("avg_scan_ms", 0)

            print(
                "  %s — %d requests | %d blocked | %d alerts | avg scan %.1fms"
                % (
                    self._dim("shutdown"),
                    total,
                    blocked,
                    alerted,
                    avg_scan,
                )
            )

            # Finding type summary
            finding_types = stats.get("finding_types", {})
            if finding_types:
                parts = []
                for ftype, count in sorted(finding_types.items(), key=lambda x: -x[1]):
                    if count > 1:
                        parts.append("%s\u00d7%d" % (ftype, count))
                    else:
                        parts.append(ftype)
                print(
                    "  %s %s"
                    % (
                        self._dim("findings:"),
                        ", ".join(parts),
                    )
                )

    def _format_size(self, size_bytes: int) -> str:
        """Format byte size as human-readable (e.g. 88.3k)."""
        if size_bytes >= 1_000_000:
            return "%.1fM" % (size_bytes / 1_000_000)
        if size_bytes >= 1_000:
            return "%.1fk" % (size_bytes / 1_000)
        return "%dB" % size_bytes

    def _shorten_model(self, model: str) -> str:
        """Shorten model ID for display."""
        if not model:
            return "unknown"
        # Strip common prefixes
        for prefix in ("claude-", "gpt-", "gemini-"):
            if model.startswith(prefix):
                model = model[len(prefix) :]
                break
        # Truncate long model strings
        if len(model) > 12:
            model = model[:12]
        return model

    def _format_findings_summary(self, result: ScanResult) -> str:
        """Create a compact summary of findings, e.g. 'aws_access_key (messages[4])'."""
        if not result.findings:
            return ""

        parts = []
        for f in result.findings:
            if f.count > 1:
                parts.append("%s\u00d7%d" % (f.type, f.count))
            else:
                parts.append("%s (%s)" % (f.type, f.location))

        return ", ".join(parts)


class JsonDisplay:
    """JSON lines output for machine-readable / CI use."""

    def __init__(self) -> None:
        self._lock = threading.Lock()

    def show_banner(self, port: int, bind: str = "127.0.0.1") -> None:
        self._emit({"event": "start", "bind": bind, "port": port})

    def show_request(
        self,
        request_id: int,
        method: str,
        path: str,
        model: str,
        req_size: int,
        resp_size: int,
        duration_ms: float,
        result: ScanResult,
    ) -> None:
        findings = []
        for f in result.findings:
            entry: dict[str, Any] = {
                "detector": f.detector,
                "type": f.type,
                "severity": f.severity,
                "location": f.location,
                "action": f.action,
            }
            if f.count > 1:
                entry["count"] = f.count
            findings.append(entry)

        self._emit(
            {
                "event": "request",
                "request_id": request_id,
                "method": method,
                "path": path,
                "model": model,
                "req_bytes": req_size,
                "resp_bytes": resp_size,
                "duration_ms": round(duration_ms, 1),
                "action": result.action,
                "findings": findings,
                "scan_ms": round(result.scan_duration_ms, 1),
            }
        )

    def show_error(self, request_id: int, error: str) -> None:
        self._emit({"event": "error", "request_id": request_id, "error": error})

    def show_shutdown(self, stats: Optional[dict[str, Any]] = None) -> None:
        self._emit({"event": "shutdown", "stats": stats or {}})

    def _emit(self, data: dict[str, Any]) -> None:
        line = json.dumps(data, separators=(",", ":"))
        with self._lock:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
