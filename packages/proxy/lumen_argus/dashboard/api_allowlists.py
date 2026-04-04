"""Allowlist API handlers — list, add, test, delete."""

from __future__ import annotations

import fnmatch
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore
    from lumen_argus.config import Config

from lumen_argus.dashboard.api_helpers import (
    json_response,
    parse_json_body,
    require_store,
)

log = logging.getLogger("argus.dashboard.api")


def handle_allowlists(store: AnalyticsStore | None, config: Config | None) -> tuple[int, bytes]:
    result: dict[str, Any] = {"secrets": [], "pii": [], "paths": [], "api_entries": []}
    if config:
        try:
            result["secrets"] = [{"pattern": p, "source": "config"} for p in config.allowlist.secrets]
            result["pii"] = [{"pattern": p, "source": "config"} for p in config.allowlist.pii]
            result["paths"] = [{"pattern": p, "source": "config"} for p in config.allowlist.paths]
        except Exception as e:
            log.warning("GET /api/v1/allowlists: config read failed: %s", e)
    if store:
        try:
            api_entries = store.list_allowlist_entries()
            result["api_entries"] = api_entries
            for entry in api_entries:
                lt = entry["list_type"]
                if lt in result:
                    result[lt].append({"pattern": entry["pattern"], "source": "api", "id": entry["id"]})
        except Exception as e:
            log.warning("GET /api/v1/allowlists: DB read failed: %s", e)
    return json_response(200, result)


def handle_allowlist_add(body: bytes, store: AnalyticsStore | None) -> tuple[int, bytes]:
    store = require_store(store, "POST /api/v1/allowlists")
    data = parse_json_body(body, "POST /api/v1/allowlists")
    if isinstance(data, tuple):
        return data
    list_type = data.get("type", "")
    pattern = data.get("pattern", "")
    if list_type not in ("secrets", "pii", "paths"):
        log.warning("POST /api/v1/allowlist: invalid type '%s'", list_type)
        return json_response(400, {"error": "type must be secrets, pii, or paths"})
    if not pattern or not pattern.strip():
        return json_response(400, {"error": "pattern is required"})
    description = data.get("description", "")
    try:
        entry = store.add_allowlist_entry(list_type, pattern, description=description, created_by="dashboard")
        log.info("allowlist entry added: %s '%s' (id=%d)", list_type, pattern.strip(), entry["id"])
        return json_response(201, entry)
    except ValueError as e:
        return json_response(400, {"error": str(e)})


def _find_matching_findings(store: AnalyticsStore, pattern: str) -> tuple[int, list[dict[str, Any]]]:
    matching: list[dict[str, Any]] = []
    count = 0
    findings, _ = store.get_findings_page(limit=200)
    for f in findings:
        preview = f.get("value_preview", "")
        if not preview or not fnmatch.fnmatch(preview, pattern):
            continue
        count += 1
        if len(matching) < 20:
            matching.append(
                {
                    "id": f.get("id"),
                    "finding_type": f.get("finding_type", ""),
                    "value_preview": preview,
                    "severity": f.get("severity", ""),
                }
            )
    return count, matching


def handle_allowlist_test(body: bytes, store: AnalyticsStore | None) -> tuple[int, bytes]:
    data = parse_json_body(body, "POST /api/v1/allowlists/test")
    if isinstance(data, tuple):
        return data
    pattern = data.get("pattern", "")
    test_value = data.get("value", "")
    if not pattern:
        return json_response(400, {"error": "pattern is required"})
    value_match = fnmatch.fnmatch(test_value, pattern) if test_value else False
    matching_count = 0
    matching: list[dict[str, Any]] = []
    if store:
        try:
            matching_count, matching = _find_matching_findings(store, pattern)
        except Exception as e:
            log.warning("POST /api/v1/allowlist/test: findings scan failed: %s", e)
    log.debug("POST /api/v1/allowlist/test: pattern='%s' matched=%d findings", pattern, matching_count)
    return json_response(
        200, {"value_match": value_match, "matching_findings_count": matching_count, "matching_findings": matching}
    )


def handle_allowlist_delete(entry_id: str, store: AnalyticsStore | None) -> tuple[int, bytes]:
    store = require_store(store, "DELETE /api/v1/allowlists")
    try:
        entry_id_int = int(entry_id)
    except (ValueError, TypeError):
        return json_response(400, {"error": "invalid id"})
    if store.delete_allowlist_entry(entry_id_int):
        log.info("allowlist entry deleted: id=%d", entry_id_int)
        return json_response(200, {"deleted": entry_id_int})
    return json_response(404, {"error": "entry not found"})
