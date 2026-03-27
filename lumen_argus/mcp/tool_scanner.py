"""Tool description poisoning detection and drift tracking.

Scans tool descriptions from tools/list responses for injection patterns
and tracks tool definition changes (rug-pull detection) via SHA-256 hashes.
"""

import hashlib
import json
import logging
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lumen_argus.analytics.store import AnalyticsStore

from lumen_argus.models import Finding

log = logging.getLogger("argus.mcp")

# --- Poisoning detection patterns ---

_POISON_PATTERNS = [
    # 1. Instruction tags
    (
        "instruction_tag",
        re.compile(
            r"<IMPORTANT>|<SYSTEM>|\[CRITICAL\]|\[SYSTEM\]|\*\*SYSTEM\*\*|\*\*INSTRUCTION\*\*"
            r"|<OVERRIDE>|\[OVERRIDE\]",
            re.IGNORECASE,
        ),
    ),
    # 2. File exfiltration
    (
        "file_exfiltration",
        re.compile(
            r"(?:read|send|steal|exfil|upload|transmit|fetch)\s+.*?"
            r"(?:\.ssh/id_|\.aws/credentials|\.env|\.gnupg|\.npmrc|\.pypirc|id_rsa|id_ed25519)",
            re.IGNORECASE,
        ),
    ),
    # 3. Cross-tool manipulation
    (
        "cross_tool_manipulation",
        re.compile(
            r"instead\s+of\s+(?:tool|using)\s+\w+.*?use\s+\w+"
            r"|do\s+not\s+use\s+\w+.*?use\s+\w+\s+instead"
            r"|ignore\s+(?:the\s+)?(?:tool|request)\s+and",
            re.IGNORECASE,
        ),
    ),
    # 4. Dangerous capability — local execution
    (
        "dangerous_exec",
        re.compile(
            r"execute\s+(?:local\s+)?(?:file|script|command|binary|program)"
            r"|run\s+(?:this\s+)?(?:script|command|binary)",
            re.IGNORECASE,
        ),
    ),
    # 5. Dangerous capability — download + execute
    (
        "download_exec",
        re.compile(
            r"download\s+and\s+(?:run|execute|install)" r"|fetch\s+and\s+(?:run|execute)",
            re.IGNORECASE,
        ),
    ),
    # 6. HTML/script injection
    (
        "script_injection",
        re.compile(
            r"<script|javascript:|on(?:load|error|click|mouseover)\s*=",
            re.IGNORECASE,
        ),
    ),
    # 7. Command injection in description
    (
        "command_injection",
        re.compile(
            r"(?:^|\s)(?:curl|wget|bash|sh|python|node|perl|ruby)\s+-",
            re.IGNORECASE,
        ),
    ),
]


def scan_tool_descriptions(tools: list[dict[str, Any]], action: str = "alert") -> list[Finding]:
    """Scan tool descriptions for poisoning patterns.

    Args:
        tools: List of tool dicts from tools/list response
               (each has name, description, inputSchema).
        action: Action for findings (from scanner config).

    Returns:
        List of Finding objects for poisoned descriptions.
    """
    findings = []

    for tool in tools:
        name = tool.get("name", "")
        desc = tool.get("description", "")

        if not desc:
            log.debug("mcp: tool '%s' has empty description (unverifiable)", name)
            continue

        for pattern_name, pattern in _POISON_PATTERNS:
            match = pattern.search(desc)
            if match:
                findings.append(
                    Finding(
                        detector="mcp_tool_poison",
                        type=pattern_name,
                        severity="high",
                        location="mcp.tools/list.%s.description" % name,
                        value_preview=match.group(0)[:80],
                        matched_value=match.group(0),
                        action=action,
                    )
                )
                log.warning(
                    "mcp: poisoning detected in tool '%s' description: %s (%s)",
                    name,
                    pattern_name,
                    match.group(0)[:60],
                )

    return findings


# --- Drift detection ---


def hash_tool_definition(description: str, input_schema: dict[str, Any]) -> str:
    """Compute SHA-256 hash of a tool definition for drift detection."""
    content = description + "\0" + json.dumps(input_schema, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def extract_param_names(input_schema: dict[str, Any]) -> list[str]:
    """Extract parameter names from a JSON Schema inputSchema."""
    props = input_schema.get("properties", {})
    if isinstance(props, dict):
        return sorted(props.keys())
    return []


def diff_tool_definitions(
    tool_name: str,
    old_desc: str,
    old_params: list[str],
    new_desc: str,
    new_params: list[str],
) -> str:
    """Generate a human-readable diff summary for a changed tool definition."""
    parts = ['Tool "%s" definition changed:' % tool_name]

    if old_desc != new_desc:
        old_len = len(old_desc)
        new_len = len(new_desc)
        diff = new_len - old_len
        sign = "+" if diff > 0 else ""
        parts.append("  description: %d -> %d chars (%s%d)" % (old_len, new_len, sign, diff))

        # Show added text snippet
        if new_len > old_len:
            added = new_desc[old_len:] if new_desc.startswith(old_desc) else ""
            if added:
                parts.append('  added: "%s"' % added[:100])

    old_set = set(old_params)
    new_set = set(new_params)
    added_params = sorted(new_set - old_set)
    removed_params = sorted(old_set - new_set)
    if added_params:
        parts.append("  parameters added: %s" % json.dumps(added_params))
    if removed_params:
        parts.append("  parameters removed: %s" % json.dumps(removed_params))

    return "\n".join(parts)


def check_tool_drift(
    tools: list[dict[str, Any]],
    store: AnalyticsStore,
) -> list[tuple[str, str]]:
    """Check tools against stored baselines and update.

    Args:
        tools: List of tool dicts from tools/list response.
        store: AnalyticsStore instance with mcp_tool_baselines methods.

    Returns:
        List of (tool_name, diff_summary) for tools that drifted.
    """
    drifted = []

    for tool in tools:
        name = tool.get("name", "")
        desc = tool.get("description", "")
        schema = tool.get("inputSchema", {})
        if not name:
            continue

        current_hash = hash_tool_definition(desc, schema)
        current_params = extract_param_names(schema)

        baseline = store.get_mcp_tool_baseline(name)
        if baseline is None:
            # First time seeing this tool — record baseline
            store.record_mcp_tool_baseline(
                tool_name=name,
                definition_hash=current_hash,
                description=desc,
                param_names=current_params,
            )
            continue

        if baseline["definition_hash"] == current_hash:
            # No change — update last_seen
            store.update_mcp_tool_baseline_seen(name)
            continue

        # Drift detected
        old_params = json.loads(baseline.get("param_names", "[]"))
        summary = diff_tool_definitions(
            name,
            baseline.get("description", ""),
            old_params,
            desc,
            current_params,
        )
        drifted.append((name, summary))
        log.warning("mcp: tool drift detected — %s", summary)

        # Update baseline
        store.record_mcp_tool_baseline(
            tool_name=name,
            definition_hash=current_hash,
            description=desc,
            param_names=current_params,
        )
        store.increment_mcp_tool_drift_count(name)

    return drifted
