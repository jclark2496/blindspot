"""Provenance and rug-pull diff helpers for Blindspot."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from .engine import Finding, ScanResult, scan_file
from .mcp_auditor import audit_mcp_manifest

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SUPPORTED_EXTS = {".md", ".json", ".yaml", ".yml", ".txt"}


@dataclass(frozen=True)
class FindingKey:
    rule_id: str
    severity: str


@dataclass
class ArtifactPosture:
    path: str
    exists: bool
    sha256: str | None = None
    file_type: str = "missing"
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    @property
    def max_severity(self) -> str | None:
        if not self.findings:
            return None
        return min(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99)).severity

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def clean(self) -> bool:
        return not self.findings

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "exists": self.exists,
            "sha256": self.sha256,
            "file_type": self.file_type,
            "max_severity": self.max_severity,
            "clean": self.clean,
            "finding_count": self.finding_count,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
        }


@dataclass
class ArtifactDiff:
    relative_path: str
    before: ArtifactPosture
    after: ArtifactPosture
    added_findings: list[Finding] = field(default_factory=list)
    removed_findings: list[Finding] = field(default_factory=list)
    unchanged_findings: list[Finding] = field(default_factory=list)
    worsened_findings: list[Finding] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return self.before.sha256 != self.after.sha256 or self.before.exists != self.after.exists

    @property
    def posture_changed(self) -> bool:
        return bool(self.added_findings or self.removed_findings or self.worsened_findings)

    @property
    def recommendation(self) -> str:
        severe_added = [f for f in self.added_findings if SEVERITY_ORDER.get(f.severity, 99) <= SEVERITY_ORDER["HIGH"]]
        severe_worsened = [f for f in self.worsened_findings if SEVERITY_ORDER.get(f.severity, 99) <= SEVERITY_ORDER["HIGH"]]
        if severe_added or severe_worsened:
            return "BLOCK UPDATE"
        if self.added_findings or self.worsened_findings:
            return "REVIEW UPDATE"
        if self.removed_findings:
            return "RISK REDUCED"
        return "NO NEW RISK"

    def to_dict(self) -> dict:
        return {
            "relative_path": self.relative_path,
            "changed": self.changed,
            "posture_changed": self.posture_changed,
            "recommendation": self.recommendation,
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "added_findings": [f.to_dict() for f in self.added_findings],
            "removed_findings": [f.to_dict() for f in self.removed_findings],
            "unchanged_findings": [f.to_dict() for f in self.unchanged_findings],
            "worsened_findings": [f.to_dict() for f in self.worsened_findings],
        }


@dataclass
class ProvenanceDiff:
    before_root: str
    after_root: str
    artifact_diffs: list[ArtifactDiff]

    @property
    def added_finding_count(self) -> int:
        return sum(len(d.added_findings) for d in self.artifact_diffs)

    @property
    def worsened_finding_count(self) -> int:
        return sum(len(d.worsened_findings) for d in self.artifact_diffs)

    @property
    def changed_artifact_count(self) -> int:
        return sum(1 for d in self.artifact_diffs if d.changed)

    @property
    def recommendation(self) -> str:
        recommendations = {d.recommendation for d in self.artifact_diffs}
        if "BLOCK UPDATE" in recommendations:
            return "BLOCK UPDATE"
        if "REVIEW UPDATE" in recommendations:
            return "REVIEW UPDATE"
        if "RISK REDUCED" in recommendations:
            return "RISK REDUCED"
        return "NO NEW RISK"

    def to_dict(self) -> dict:
        return {
            "before_root": self.before_root,
            "after_root": self.after_root,
            "changed_artifact_count": self.changed_artifact_count,
            "added_finding_count": self.added_finding_count,
            "worsened_finding_count": self.worsened_finding_count,
            "recommendation": self.recommendation,
            "artifact_diffs": [d.to_dict() for d in self.artifact_diffs],
        }


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _collect_artifacts(root: Path) -> dict[str, Path]:
    if root.is_file():
        return {root.name: root}
    if root.is_dir():
        return {
            p.relative_to(root).as_posix(): p
            for p in sorted(root.rglob("*"))
            if p.is_file() and p.suffix.lower() in SUPPORTED_EXTS
        }
    return {}


def _scan_artifact(path: Path | None, display_path: str, *, mcp_audit: bool) -> ArtifactPosture:
    if path is None or not path.exists():
        return ArtifactPosture(path=display_path, exists=False)

    result = scan_file(path)
    if mcp_audit and path.suffix.lower() == ".json" and not result.error:
        result.findings.extend(audit_mcp_manifest(path))
        result.findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.rule_id))

    return ArtifactPosture(
        path=display_path,
        exists=True,
        sha256=_sha256(path),
        file_type=result.file_type,
        findings=result.findings,
        error=result.error,
    )


def _finding_key(finding: Finding) -> FindingKey:
    return FindingKey(rule_id=finding.rule_id, severity=finding.severity)


def _finding_map(findings: list[Finding]) -> dict[str, Finding]:
    # Compare by rule ID for rug-pull posture. If a rule changes severity between
    # versions, it is surfaced separately as worsened/reduced by severity order.
    return {finding.rule_id: finding for finding in findings}


def _compare_findings(before: ArtifactPosture, after: ArtifactPosture) -> tuple[list[Finding], list[Finding], list[Finding], list[Finding]]:
    before_by_rule = _finding_map(before.findings)
    after_by_rule = _finding_map(after.findings)

    added = [after_by_rule[rule_id] for rule_id in sorted(after_by_rule.keys() - before_by_rule.keys())]
    removed = [before_by_rule[rule_id] for rule_id in sorted(before_by_rule.keys() - after_by_rule.keys())]
    unchanged: list[Finding] = []
    worsened: list[Finding] = []

    for rule_id in sorted(before_by_rule.keys() & after_by_rule.keys()):
        old = before_by_rule[rule_id]
        new = after_by_rule[rule_id]
        if SEVERITY_ORDER.get(new.severity, 99) < SEVERITY_ORDER.get(old.severity, 99):
            worsened.append(new)
        else:
            unchanged.append(new)

    return added, removed, unchanged, worsened


def diff_artifacts(before: str | Path, after: str | Path, *, mcp_audit: bool = False) -> ProvenanceDiff:
    before_root = Path(before)
    after_root = Path(after)
    if before_root.is_file() and after_root.is_file():
        rel = after_root.name
        before_artifacts = {rel: before_root}
        after_artifacts = {rel: after_root}
    else:
        before_artifacts = _collect_artifacts(before_root)
        after_artifacts = _collect_artifacts(after_root)
    rel_paths = sorted(set(before_artifacts) | set(after_artifacts))

    artifact_diffs: list[ArtifactDiff] = []
    for rel_path in rel_paths:
        before_path = before_artifacts.get(rel_path)
        after_path = after_artifacts.get(rel_path)
        before_posture = _scan_artifact(before_path, rel_path, mcp_audit=mcp_audit)
        after_posture = _scan_artifact(after_path, rel_path, mcp_audit=mcp_audit)
        added, removed, unchanged, worsened = _compare_findings(before_posture, after_posture)
        artifact_diffs.append(ArtifactDiff(
            relative_path=rel_path,
            before=before_posture,
            after=after_posture,
            added_findings=added,
            removed_findings=removed,
            unchanged_findings=unchanged,
            worsened_findings=worsened,
        ))

    return ProvenanceDiff(
        before_root=str(before_root),
        after_root=str(after_root),
        artifact_diffs=artifact_diffs,
    )
