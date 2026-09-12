"""Lightweight Blindspot policy loading and finding suppression."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from .engine import ScanResult


@dataclass
class Suppression:
    rule: str = "*"
    path: str = "*"
    reason: str = ""


@dataclass
class Policy:
    min_severity: str | None = None
    fail_on_findings: bool | None = None
    suppressions: list[Suppression] = field(default_factory=list)


def find_policy(start: Path) -> Path | None:
    """Find .blindspot.yml/.yaml/.json at start or nearest parent."""
    cur = start if start.is_dir() else start.parent
    for parent in [cur, *cur.parents]:
        for name in (".blindspot.yml", ".blindspot.yaml", ".blindspot.json"):
            candidate = parent / name
            if candidate.exists():
                return candidate
    return None


def _parse_scalar(value: str) -> Any:
    value = value.strip().strip('"').strip("'")
    if value.lower() in {"true", "yes", "on"}:
        return True
    if value.lower() in {"false", "no", "off"}:
        return False
    if value.lower() in {"null", "none"}:
        return None
    return value


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    """Parse the small .blindspot.yml shape without adding a PyYAML dependency.

    Supported shape:
      min_severity: HIGH
      fail_on_findings: true
      suppressions:
        - rule: HC-004
          path: docs/examples/*.md
          reason: Intentional training sample
    """
    data: dict[str, Any] = {}
    current_list: str | None = None
    current_item: dict[str, Any] | None = None

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        if not raw.startswith(" ") and stripped.endswith(":"):
            key = stripped[:-1]
            data[key] = []
            current_list = key
            current_item = None
            continue
        if not raw.startswith(" ") and ":" in stripped:
            key, value = stripped.split(":", 1)
            data[key.strip()] = _parse_scalar(value)
            current_list = None
            current_item = None
            continue
        if current_list and stripped.startswith("- "):
            current_item = {}
            data[current_list].append(current_item)
            rest = stripped[2:]
            if ":" in rest:
                key, value = rest.split(":", 1)
                current_item[key.strip()] = _parse_scalar(value)
            continue
        if current_item is not None and ":" in stripped:
            key, value = stripped.split(":", 1)
            current_item[key.strip()] = _parse_scalar(value)
    return data


def load_policy(path: Path | None) -> Policy:
    if not path:
        return Policy()
    raw = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        data = json.loads(raw)
    else:
        data = _parse_simple_yaml(raw)

    suppressions = []
    for item in data.get("suppressions", []) or []:
        suppressions.append(Suppression(
            rule=str(item.get("rule", "*")),
            path=str(item.get("path", "*")),
            reason=str(item.get("reason", "")),
        ))
    return Policy(
        min_severity=str(data["min_severity"]).upper() if data.get("min_severity") else None,
        fail_on_findings=bool(data["fail_on_findings"]) if "fail_on_findings" in data else None,
        suppressions=suppressions,
    )


def _matches_suppression(file_path: str | None, rule_id: str, suppression: Suppression, root: Path | None) -> bool:
    path = file_path or "<stdin>"
    candidates = [path, Path(path).name]
    if root and file_path:
        try:
            candidates.append(Path(file_path).resolve().relative_to(root.resolve()).as_posix())
        except Exception:
            pass
    return fnmatch(rule_id, suppression.rule) and any(fnmatch(c, suppression.path) for c in candidates)


def apply_policy(results: list[ScanResult], policy: Policy, root: Path | None = None) -> int:
    """Remove suppressed findings in-place. Return number suppressed."""
    if not policy.suppressions:
        return 0
    suppressed = 0
    for result in results:
        kept = []
        for finding in result.findings:
            if any(_matches_suppression(result.file_path, finding.rule_id, s, root) for s in policy.suppressions):
                suppressed += 1
            else:
                kept.append(finding)
        result.findings = kept
    return suppressed
