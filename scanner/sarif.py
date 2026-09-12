"""SARIF output helpers for Blindspot scan results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .engine import ScanResult, Finding
from .rules import RULES

EXTRA_RULES = [
    ("MCP-AUDIT-001", "Tool name shadows high-trust capability", "MCP Structural Audit", "HIGH", "AML.T0051.002", "MCP tool names that resemble built-in file, shell, browser, network, or email tools can confuse agents and users."),
    ("MCP-AUDIT-002", "External URL in tool description", "MCP Structural Audit", "HIGH", "AML.T0056", "External URLs in MCP tool descriptions may steer models toward attacker-controlled infrastructure or callbacks."),
    ("MCP-AUDIT-003", "Sensitive or high-agency parameter surface", "MCP Structural Audit", "HIGH", "AML.T0055", "Tool parameters for commands, paths, URLs, callbacks, tokens, or secrets should require explicit policy review."),
    ("MCP-AUDIT-004", "Dangerous MCP parameter default", "MCP Structural Audit", "CRITICAL", "AML.T0051.002", "Dangerous defaults such as root paths or external callback URLs can cause accidental privileged access or exfiltration."),
    ("MCP-AUDIT-005", "Duplicate MCP tool names", "MCP Structural Audit", "HIGH", "AML.T0051.002", "Duplicate tool names can confuse model tool selection and may indicate shadowing or manifest tampering."),
]

SEVERITY_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def _uri(path: str | None, root: Path | None = None) -> str:
    if not path:
        return "<stdin>"
    p = Path(path)
    try:
        if root:
            return p.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        pass
    return p.as_posix()


def _first_match_region(file_path: str | None, match: str | None) -> dict:
    """Best-effort locate the first match for SARIF annotations."""
    if not file_path or not match:
        return {"startLine": 1}
    try:
        text = Path(file_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"startLine": 1}

    # Many detector matches are excerpts or synthetic messages. Use the first
    # short literal chunk if the full match cannot be found.
    candidates = [match]
    if len(match) > 40:
        candidates.append(match[:40])
    if " → " in match:
        candidates.append(match.split(" → ", 1)[0].strip("'…"))

    for candidate in candidates:
        if not candidate:
            continue
        idx = text.find(candidate)
        if idx >= 0:
            start_line = text.count("\n", 0, idx) + 1
            line_start = text.rfind("\n", 0, idx) + 1
            return {
                "startLine": start_line,
                "startColumn": idx - line_start + 1,
            }
    return {"startLine": 1}


def _rules_metadata() -> list[dict]:
    out = []
    for rule in RULES:
        out.append({
            "id": rule["id"],
            "name": rule["name"],
            "shortDescription": {"text": rule["name"]},
            "fullDescription": {"text": rule["note"]},
            "help": {"text": rule["note"], "markdown": rule["note"]},
            "properties": {
                "category": rule["category"],
                "severity": rule["severity"],
                "atlas_id": rule["atlas_id"],
                "tags": ["blindspot", rule["category"], rule["severity"], rule["atlas_id"]],
            },
        })
    for rule_id, name, category, severity, atlas_id, note in EXTRA_RULES:
        out.append({
            "id": rule_id,
            "name": name,
            "shortDescription": {"text": name},
            "fullDescription": {"text": note},
            "help": {"text": note, "markdown": note},
            "properties": {
                "category": category,
                "severity": severity,
                "atlas_id": atlas_id,
                "tags": ["blindspot", category, severity, atlas_id],
            },
        })
    return out


def finding_to_sarif_result(result: ScanResult, finding: Finding, root: Path | None = None) -> dict:
    first_match = finding.matches[0] if finding.matches else None
    message = f"[{finding.severity}] {finding.name}: {finding.note}"
    if first_match:
        message += f" Match: {first_match[:200]}"

    return {
        "ruleId": finding.rule_id,
        "level": SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
        "message": {"text": message},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": _uri(result.file_path, root)},
                "region": _first_match_region(result.file_path, first_match),
            }
        }],
        "properties": {
            "severity": finding.severity,
            "category": finding.category,
            "atlas_id": finding.atlas_id,
            "matches": finding.matches[:5],
        },
    }


def results_to_sarif(results: Iterable[ScanResult], min_severity: str = "INFO", root: str | Path | None = None) -> dict:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    min_ord = order.get(min_severity.upper(), 4)
    root_path = Path(root) if root else None

    sarif_results = []
    for scan_result in results:
        for finding in scan_result.findings:
            if order.get(finding.severity, 99) <= min_ord:
                sarif_results.append(finding_to_sarif_result(scan_result, finding, root_path))

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Blindspot",
                    "informationUri": "https://github.com/blindspot-ai/blindspot",
                    "semanticVersion": "0.1.0",
                    "rules": _rules_metadata(),
                }
            },
            "results": sarif_results,
        }],
    }


def dumps(results: Iterable[ScanResult], min_severity: str = "INFO", root: str | Path | None = None) -> str:
    return json.dumps(results_to_sarif(results, min_severity=min_severity, root=root), indent=2)
