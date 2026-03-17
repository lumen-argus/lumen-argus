"""Offline file scanner — reuses the detection pipeline without the proxy.

Used by the `lumen-argus scan` subcommand and as a git pre-commit hook.

Exit codes:
    0 — No findings
    1 — Findings with action "block" (should fail CI)
    2 — Findings with action "alert" only (CI can choose)
    3 — Findings with action "log" only (informational)
"""

import json
import sys
from dataclasses import replace
from typing import List

from lumen_argus.allowlist import AllowlistMatcher
from lumen_argus.config import load_config
from lumen_argus.detectors.custom import CustomDetector
from lumen_argus.detectors.pii import PIIDetector
from lumen_argus.detectors.proprietary import ProprietaryDetector
from lumen_argus.detectors.secrets import SecretsDetector
from lumen_argus.models import Finding, ScanField

# Exit codes by action severity (highest wins).
# "redact" maps to "alert" in Community Edition (PolicyEngine downgrades it).
_EXIT_CODES = {"block": 1, "redact": 2, "alert": 2, "log": 3}


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
    detectors = [
        SecretsDetector(entropy_threshold=config.entropy_threshold),
        PIIDetector(),
        ProprietaryDetector(),
    ]
    if config.custom_rules:
        detectors.append(CustomDetector(config.custom_rules))
    return detectors


def _resolve_exit_code(findings, config):
    """Determine exit code from findings based on resolved actions.

    Uses the same action resolution as PolicyEngine: per-detector
    overrides, then default_action. Highest-severity action wins.
    """
    if not findings:
        return 0

    overrides = {}
    if config.secrets.action:
        overrides["secrets"] = config.secrets.action
    if config.pii.action:
        overrides["pii"] = config.pii.action
    if config.proprietary.action:
        overrides["proprietary"] = config.proprietary.action

    exit_code = 3  # log (lowest)
    for f in findings:
        action = f.action or overrides.get(f.detector, config.default_action)
        code = _EXIT_CODES.get(action, 3)
        if code < exit_code:
            exit_code = code  # lower code = higher severity

    return exit_code


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
        Exit code: 0=clean, 1=block findings, 2=alert/redact only, 3=log only.
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

    exit_code = _resolve_exit_code(findings, config)

    if output_format == "json":
        print(json.dumps({
            "status": "findings",
            "count": len(findings),
            "exit_code": exit_code,
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

    return exit_code


def scan_files(files: List[str], config_path: str = None, output_format: str = "text") -> int:
    """Scan one or more files.

    Returns:
        Exit code: 0=clean, 1=block findings, 2=alert only, 3=log only.
    """
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
            file_exit = _resolve_exit_code(findings, config)
            # Keep highest severity (lowest exit code, but never downgrade)
            if exit_code == 0 or file_exit < exit_code:
                exit_code = file_exit

            if output_format == "json":
                print(json.dumps({
                    "file": filepath,
                    "count": len(findings),
                    "exit_code": file_exit,
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
                print("lumen-argus: %s — %d finding(s)" % (filepath, len(findings)), file=sys.stderr)
                for f in findings:
                    count_str = " (\u00d7%d)" % f.count if f.count > 1 else ""
                    print(
                        "  [%s] %s: %s%s" % (f.severity.upper(), f.detector, f.type, count_str),
                        file=sys.stderr,
                    )

    return exit_code
