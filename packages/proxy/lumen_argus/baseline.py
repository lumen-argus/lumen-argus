"""Baseline file: record known findings to suppress on future scans.

A baseline stores fingerprints of known findings so they can be filtered
out during scanning. This enables adopting lumen-argus on existing
codebases with legacy secrets that can't be immediately fixed.

The baseline never stores actual secret values — only detector type,
finding type, file path, and a hash of the matched line content.
"""

import hashlib
import json
import os
import sys
from datetime import datetime, timezone

from lumen_argus.models import Finding


def _finding_key(finding: Finding, filepath: str) -> tuple[str, str, str, str]:
    """Create a baseline key for a finding.

    Uses a hash of matched_value instead of the value itself — the
    baseline file must never contain secrets.
    """
    value_hash = hashlib.sha256(finding.matched_value.encode("utf-8")).hexdigest()
    return (finding.detector, finding.type, filepath, value_hash)


def load_baseline(path: str) -> set[tuple[str, str, str, str]]:
    """Load baseline from JSON file. Returns set of finding keys."""
    path = os.path.expanduser(path)
    if not os.path.exists(path):
        return set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        keys = set()
        for entry in data.get("findings", []):
            keys.add(
                (
                    entry.get("detector", ""),
                    entry.get("type", ""),
                    entry.get("file", ""),
                    entry.get("value_hash", ""),
                )
            )
        return keys
    except (json.JSONDecodeError, OSError) as e:
        print("lumen-argus: failed to load baseline %s: %s" % (path, e), file=sys.stderr)
        return set()


def save_baseline(path: str, findings_by_file: dict[str, list[Finding]]) -> None:
    """Save findings as a baseline JSON file."""
    path = os.path.expanduser(path)
    entries = []
    for filepath, findings in sorted(findings_by_file.items()):
        for f in findings:
            key = _finding_key(f, filepath)
            entries.append(
                {
                    "detector": key[0],
                    "type": key[1],
                    "file": key[2],
                    "value_hash": key[3],
                }
            )

    data = {
        "version": "1",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "count": len(entries),
        "findings": entries,
    }

    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
        print("lumen-argus: baseline saved to %s (%d findings)" % (path, len(entries)), file=sys.stderr)
    except OSError as e:
        print("lumen-argus: failed to save baseline: %s" % e, file=sys.stderr)


def filter_baseline(findings: list[Finding], filepath: str, baseline: set[tuple[str, str, str, str]]) -> list[Finding]:
    """Remove findings that are in the baseline."""
    if not baseline:
        return findings
    return [f for f in findings if _finding_key(f, filepath) not in baseline]
