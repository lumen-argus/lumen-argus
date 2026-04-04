"""Config overrides repository — extracted from AnalyticsStore."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from lumen_argus.analytics.base import BaseRepository
from lumen_argus.models import ACTION_SET

if TYPE_CHECKING:
    from lumen_argus.analytics.adapter import DatabaseAdapter

log = logging.getLogger("argus.analytics")

# Community-editable config keys with validation rules
_VALID_CONFIG_KEYS = {
    "proxy.timeout",
    "proxy.retries",
    "default_action",
    "detectors.secrets.enabled",
    "detectors.pii.enabled",
    "detectors.proprietary.enabled",
    "detectors.secrets.action",
    "detectors.pii.action",
    "detectors.proprietary.action",
    "pipeline.stages.outbound_dlp.enabled",
    "pipeline.stages.encoding_decode.enabled",
    "pipeline.stages.encoding_decode.base64",
    "pipeline.stages.encoding_decode.hex",
    "pipeline.stages.encoding_decode.url",
    "pipeline.stages.encoding_decode.unicode",
    "pipeline.stages.encoding_decode.max_depth",
    "pipeline.stages.encoding_decode.min_decoded_length",
    "pipeline.stages.encoding_decode.max_decoded_length",
    "pipeline.stages.response_secrets.enabled",
    "pipeline.stages.response_injection.enabled",
    "pipeline.stages.mcp_arguments.enabled",
    "pipeline.stages.mcp_responses.enabled",
    "pipeline.stages.websocket_outbound.enabled",
    "pipeline.stages.websocket_inbound.enabled",
    "pipeline.parallel_batching",
    "proxy.port",
    "proxy.bind",
    "proxy.mode",
}

_VALID_ACTIONS = ACTION_SET


def _validate_int_range(value: str, name: str, lo: int, hi: int) -> None:
    """Validate that *value* is an integer in [lo, hi]."""
    try:
        v = int(value)
    except (ValueError, TypeError):
        raise ValueError("%s must be an integer (%d-%d)" % (name, lo, hi))
    if v < lo or v > hi:
        raise ValueError("%s must be %d-%d" % (name, lo, hi))


def _validate_boolean(value: str, label: str) -> str:
    """Validate and normalize a boolean string."""
    if value.lower() not in ("true", "false"):
        raise ValueError("%s must be true or false" % label)
    return value.lower()


def _validate_action(value: str) -> None:
    """Validate that *value* is a recognized action."""
    if value not in _VALID_ACTIONS:
        raise ValueError("action must be one of: %s" % ", ".join(sorted(_VALID_ACTIONS)))


def _validate_bind(value: str) -> str:
    """Validate and normalize a bind address."""
    import ipaddress

    addr = value.strip()
    if addr not in ("localhost",):
        try:
            ipaddress.ip_address(addr)
        except ValueError:
            raise ValueError("bind must be a valid IP address or 'localhost'")
    return addr


def _validate_mode(value: str) -> None:
    """Validate proxy mode."""
    if value not in ("active", "passthrough"):
        raise ValueError("mode must be 'active' or 'passthrough'")


# Lookup table: key → (validator_fn, returns_new_value)
# Validators that return a str replace the stored value; None means no replacement.
_INT_RANGE_KEYS: dict[str, tuple[str, int, int]] = {
    "proxy.timeout": ("timeout", 1, 300),
    "proxy.port": ("port", 1, 65535),
    "proxy.retries": ("retries", 0, 10),
    "pipeline.stages.encoding_decode.max_depth": ("max_depth", 1, 5),
    "pipeline.stages.encoding_decode.min_decoded_length": ("min_decoded_length", 1, 100),
    "pipeline.stages.encoding_decode.max_decoded_length": ("max_decoded_length", 100, 1_000_000),
}

_ACTION_KEYS = {
    "default_action",
    "detectors.secrets.action",
    "detectors.pii.action",
    "detectors.proprietary.action",
}

_BOOLEAN_SUFFIXES = (".enabled", ".base64", ".hex", ".url", ".unicode")


class ConfigOverridesRepository(BaseRepository):
    """Repository for config override CRUD operations."""

    def __init__(self, adapter: DatabaseAdapter) -> None:
        super().__init__(adapter)

    def get_all(self, namespace_id: int = 1) -> dict[str, Any]:
        """Return all config overrides as a dict."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT key, value FROM config_overrides WHERE namespace_id = ?",
                (namespace_id,),
            ).fetchall()
        overrides = {row["key"]: row["value"] for row in rows}
        log.debug("loaded %d config override(s) from DB", len(overrides))
        return overrides

    def set(self, key: str, value: Any, namespace_id: int = 1) -> None:
        """Set a config override. Validates key and value."""
        if key not in _VALID_CONFIG_KEYS:
            raise ValueError("Invalid config key: %s" % key)

        value = str(value)

        if key in _INT_RANGE_KEYS:
            name, lo, hi = _INT_RANGE_KEYS[key]
            _validate_int_range(value, name, lo, hi)
        elif key == "proxy.bind":
            value = _validate_bind(value)
        elif key == "proxy.mode":
            _validate_mode(value)
        elif key in _ACTION_KEYS:
            _validate_action(value)
        elif key == "pipeline.parallel_batching":
            value = _validate_boolean(value, "parallel_batching")
        elif key.endswith(_BOOLEAN_SUFFIXES):
            value = _validate_boolean(value, key)

        now = self._now()
        with self._adapter.write_lock():
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO config_overrides "
                    "(namespace_id, key, value, updated_at) VALUES (?, ?, ?, ?)",
                    (namespace_id, key, value, now),
                )
        log.debug("config override stored: %s = %s", key, value)

    def delete(self, key: str, namespace_id: int = 1) -> bool:
        """Delete a config override (revert to YAML default)."""
        with self._adapter.write_lock():
            with self._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM config_overrides WHERE key = ? AND namespace_id = ?",
                    (key, namespace_id),
                )
                deleted = cursor.rowcount > 0
        if deleted:
            log.info("config override deleted: %s (reverted to YAML default)", key)
        return deleted
