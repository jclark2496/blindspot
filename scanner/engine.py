"""
Scan engine for skill-scan.

Accepts a file path or raw content string and returns a ScanResult.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .rules import RULES

# Severity order for sorting (highest first)
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class Finding:
    rule_id: str
    name: str
    category: str
    severity: str
    atlas_id: str
    note: str
    matches: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "atlas_id": self.atlas_id,
            "note": self.note,
            "matches": self.matches,
        }


@dataclass
class ScanResult:
    file_path: Optional[str]
    file_type: str          # "skill" | "mcp" | "unknown"
    findings: list[Finding] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def max_severity(self) -> Optional[str]:
        if not self.findings:
            return None
        return min(self.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99)).severity

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def clean(self) -> bool:
        return len(self.findings) == 0

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "file_type": self.file_type,
            "max_severity": self.max_severity,
            "clean": self.clean,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def _detect_file_type(path: Optional[str], content: str) -> str:
    if path:
        ext = Path(path).suffix.lower()
        if ext == ".json":
            # MCP manifests are JSON with a "tools" array
            try:
                parsed = json.loads(content)
                if isinstance(parsed, dict) and "tools" in parsed:
                    return "mcp"
            except json.JSONDecodeError:
                pass
            return "json"
        if ext in (".md", ".txt", ""):
            return "skill"
        if ext in (".yaml", ".yml"):
            return "skill"
    # Heuristic: JSON with tools key → mcp
    if content.strip().startswith("{"):
        try:
            parsed = json.loads(content)
            if isinstance(parsed, dict) and "tools" in parsed:
                return "mcp"
        except json.JSONDecodeError:
            pass
    return "skill"


def _apply_rule(rule: dict, content: str) -> list[str]:
    """Return a list of match excerpts, or empty list if no match."""
    matches: list[str] = []

    if rule.get("match_fn") is not None:
        results = rule["match_fn"](content)
        matches.extend(results or [])

    if rule.get("pattern") is not None:
        pattern: re.Pattern = rule["pattern"]
        for m in pattern.finditer(content):
            excerpt = m.group(0)[:120].replace("\n", " ")
            matches.append(excerpt)

    return matches


def scan_content(content: str, file_path: Optional[str] = None) -> ScanResult:
    file_type = _detect_file_type(file_path, content)
    result = ScanResult(file_path=file_path, file_type=file_type)

    for rule in RULES:
        matches = _apply_rule(rule, content)
        if matches:
            # Deduplicate while preserving order
            seen: set[str] = set()
            unique: list[str] = []
            for m in matches:
                if m not in seen:
                    seen.add(m)
                    unique.append(m)
            result.findings.append(Finding(
                rule_id=rule["id"],
                name=rule["name"],
                category=rule["category"],
                severity=rule["severity"],
                atlas_id=rule["atlas_id"],
                note=rule["note"],
                matches=unique,
            ))

    # Sort findings: highest severity first, then by rule_id
    result.findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), f.rule_id))
    return result


def scan_file(path: str | Path) -> ScanResult:
    path = Path(path)
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return ScanResult(file_path=str(path), file_type="unknown", error=str(e))
    return scan_content(content, file_path=str(path))
