"""Basic webhook notifier — sends findings as JSON POST."""

import json
import logging
from typing import Any
from urllib.request import Request, urlopen

from lumen_argus.models import SEVERITY_ORDER

log = logging.getLogger("argus.notifiers.webhook")

WEBHOOK_CHANNEL_TYPE = {
    "webhook": {
        "label": "Webhook",
        "description": "Send findings to any HTTP endpoint as JSON",
        "fields": {
            "url": {
                "label": "Webhook URL",
                "type": "url",
                "required": True,
                "placeholder": "https://your-endpoint.com/webhook",
            },
            "headers": {
                "label": "Custom Headers (JSON)",
                "type": "text",
                "required": False,
                "placeholder": '{"Authorization": "Bearer ..."}',
                "hint": "Optional JSON object of custom HTTP headers",
            },
        },
    },
}


def build_notifier(channel: dict[str, Any]) -> "WebhookNotifier | None":
    """Build a WebhookNotifier from a channel dict. Returns None if type unknown."""
    if channel.get("type") != "webhook":
        return None
    ch_config = channel.get("config") or {}
    if isinstance(ch_config, str):
        try:
            ch_config = json.loads(ch_config)
        except Exception:
            ch_config = {}
    url = ch_config.get("url", "")
    if not url:
        return None
    headers = ch_config.get("headers")
    if isinstance(headers, str):
        try:
            headers = json.loads(headers)
        except Exception:
            headers = {}
    return WebhookNotifier(
        url=url,
        headers=headers or {},
        min_severity=ch_config.get("min_severity", "critical"),
    )


class WebhookNotifier:
    """Sends findings to an HTTP endpoint as JSON POST.

    Filters by min_severity before sending. Raises on failure
    (caller handles retry/logging).
    """

    def __init__(self, url: str, headers: dict[str, str] | None = None, min_severity: str = "critical") -> None:
        self.url = url
        self.headers = headers or {}
        self.min_severity = min_severity

    def notify(self, findings: list[Any], provider: str = "", model: str = "", **kwargs: Any) -> None:
        """Send findings to the webhook endpoint.

        Args:
            findings: List of Finding objects to send.
            provider: API provider name (e.g. "anthropic").
            model: Model name if available.
            **kwargs: Forward compatibility (e.g. session_id).
        """
        min_level = SEVERITY_ORDER.get(self.min_severity, 0)
        filtered = [f for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= min_level]
        if not filtered:
            return

        payload = json.dumps(
            {
                "findings": [
                    {
                        "detector": f.detector,
                        "type": f.type,
                        "severity": f.severity,
                        "action": f.action,
                        "value_preview": f.value_preview,
                    }
                    for f in filtered
                ],
                "count": len(filtered),
                "provider": provider,
                "model": model,
            }
        ).encode("utf-8")

        headers = {"Content-Type": "application/json"}
        headers.update(self.headers)
        req = Request(self.url, data=payload, headers=headers, method="POST")
        urlopen(req, timeout=10)
