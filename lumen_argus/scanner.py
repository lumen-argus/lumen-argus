"""Offline file scanner — reuses the detection pipeline without the proxy.

Used by the `lumen-argus scan` subcommand and as a git pre-commit hook.
"""

import json
import sys
from dataclasses import replace
from typing import List

from lumen_argus.allowlist import AllowlistMatcher
from lumen_argus.config import load_config
from lumen_argus.detectors.pii import PIIDetector
from lumen_argus.detectors.proprietary import ProprietaryDetector
from lumen_argus.detectors.secrets import SecretsDetector
from lumen_argus.models import Finding, ScanField


def _deduplicate(findings: List[Finding]) -> List[Finding]:
    """Collapse duplicate findings. Creates new objects to avoid mutation."""
    seen = {}  # type: dict[tuple, int]
    first = {}  # type: dict[tuple, Finding]
    for f in findings:
        key = (f.detector, f.type, f.matched_value)
        if key in seen:
            seen[key] += 1
        else:
            seen[key] = 1
            first[key] = f
    return [replace(first[k], count=c) for k, c in seen.items()]


def _build_detectors(config):
    """Build detector list from config."""
    return [
        SecretsDetector(entropy_threshold=config.entropy_threshold),
        PIIDetector(),
        ProprietaryDetector(),
    ]


def _build_allowlist(config):
    """Build allowlist from config."""
    return AllowlistMatcher(
        secrets=config.allowlist.secrets,
        pii=config.allowlist.pii,
        paths=config.allowlist.paths,
    )


def scan_text(
    text: str,
    config_path: str = None,
    output_format: str = "text",
) -> int:
    """Scan text for secrets/PII/proprietary content.

    Returns:
        Exit code: 0 = clean, 1 = findings detected.
    """
    config = load_config(config_path=config_path)
    allowlist = _build_allowlist(config)
    detectors = _build_detectors(config)

    fields = [ScanField(path="stdin", text=text)]
    all_findings = []  # type: List[Finding]
    for det in detectors:
        all_findings.extend(det.scan(fields, allowlist))

    findings = _deduplicate(all_findings)

    if not findings:
        if output_format == "json":
            print(json.dumps({"status": "clean", "findings": []}))
        return 0

    if output_format == "json":
        print(json.dumps({
            "status": "findings",
            "count": len(findings),
            "findings": [
                {
                    "detector": f.detector,
                    "type": f.type,
                    "severity": f.severity,
                    "location": f.location,
                    "count": f.count,
                }
                for f in findings
            ],
        }))
    else:
        print("lumen-argus: %d finding(s) detected" % len(findings), file=sys.stderr)
        for f in findings:
            count_str = " (\u00d7%d)" % f.count if f.count > 1 else ""
            print(
                "  [%s] %s: %s%s" % (f.severity.upper(), f.detector, f.type, count_str),
                file=sys.stderr,
            )

    return 1


def scan_files(files: List[str], config_path: str = None, output_format: str = "text") -> int:
    """Scan one or more files. Returns 0 if clean, 1 if findings detected."""
    config = load_config(config_path=config_path)
    allowlist = _build_allowlist(config)
    detectors = _build_detectors(config)
    exit_code = 0

    for filepath in files:
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except (OSError, IOError) as e:
            print("lumen-argus: cannot read %s: %s" % (filepath, e), file=sys.stderr)
            continue

        if allowlist.is_allowed_path(filepath):
            continue

        fields = [ScanField(path=filepath, text=text, source_filename=filepath)]
        all_findings = []  # type: List[Finding]
        for det in detectors:
            all_findings.extend(det.scan(fields, allowlist))

        findings = _deduplicate(all_findings)

        if findings:
            exit_code = 1
            if output_format == "json":
                print(json.dumps({
                    "file": filepath,
                    "count": len(findings),
                    "findings": [
                        {
                            "detector": f.detector,
                            "type": f.type,
                            "severity": f.severity,
                            "count": f.count,
                        }
                        for f in findings
                    ],
                }))
            else:
                print("lumen-argus: %s — %d finding(s)" % (filepath, len(findings)), file=sys.stderr)
                for f in findings:
                    count_str = " (\u00d7%d)" % f.count if f.count > 1 else ""
                    print(
                        "  [%s] %s: %s%s" % (f.severity.upper(), f.detector, f.type, count_str),
                        file=sys.stderr,
                    )

    return exit_code
