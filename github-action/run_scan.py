#!/usr/bin/env python3
"""
Blindspot Action runner.
Supports normal scan mode and provenance/rug-pull diff mode, emits GitHub
annotations/summaries, and sets composite action outputs.
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from scanner.engine import Finding, ScanResult, scan_file
from scanner.mcp_auditor import audit_mcp_manifest
from scanner.policy import apply_policy, find_policy, load_policy
from scanner.provenance import ArtifactDiff, ProvenanceDiff, diff_artifacts
from scanner.sarif import dumps as sarif_dumps

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
SUPPORTED_EXTS = {".md", ".json", ".yaml", ".yml", ".txt"}


def collect_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path] if path.suffix.lower() in SUPPORTED_EXTS else []
    return sorted(f for f in path.rglob("*") if f.suffix.lower() in SUPPORTED_EXTS)


def set_output(name: str, value: str) -> None:
    """Write to GITHUB_OUTPUT for use in subsequent steps."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"{name}={value}\n")


def emit_annotation(level: str, file: str, message: str) -> None:
    """Emit a GitHub Actions workflow annotation."""
    safe_msg = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::{level} file={file}::{safe_msg}")


def finding_at_threshold(finding: Finding, min_severity: str) -> bool:
    return SEVERITY_ORDER.get(finding.severity, 9) <= SEVERITY_ORDER.get(min_severity, 4)


def filtered_scan_findings(results: list[ScanResult], min_severity: str) -> list[tuple[ScanResult, Finding]]:
    return [
        (r, f) for r in results
        for f in r.findings
        if finding_at_threshold(f, min_severity)
    ]


def filtered_diff_findings(diff: ProvenanceDiff, min_severity: str) -> list[tuple[ArtifactDiff, Finding, str]]:
    findings: list[tuple[ArtifactDiff, Finding, str]] = []
    for artifact in diff.artifact_diffs:
        for finding in artifact.added_findings:
            if finding_at_threshold(finding, min_severity):
                findings.append((artifact, finding, "new"))
        for finding in artifact.worsened_findings:
            if finding_at_threshold(finding, min_severity):
                findings.append((artifact, finding, "worsened"))
    return findings


def count_severities(findings: list[Finding]) -> tuple[int, int, int]:
    critical = sum(1 for f in findings if f.severity == "CRITICAL")
    high = sum(1 for f in findings if f.severity == "HIGH")
    return len(findings), critical, high


def write_scan_summary(results: list, min_severity: str) -> None:
    """Write a rich markdown scan summary to the GitHub Actions job summary."""
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return

    all_findings = filtered_scan_findings(results, min_severity)
    findings_only = [f for _, f in all_findings]
    total_findings, critical, _high = count_severities(findings_only)
    flagged = sum(
        1 for r in results
        if any(finding_at_threshold(f, min_severity) for f in r.findings)
    )

    lines = ["# Blindspot Scan Results\n"]

    if total_findings == 0:
        lines.append("## ✅ No findings detected\n")
        lines.append(f"Scanned {len(results)} file(s) — all clear at `{min_severity}` severity and above.\n")
    else:
        lines.append(f"## ⚠️ {total_findings} finding(s) detected\n")
        lines.append("| | |\n|---|---|\n")
        lines.append(f"| Files scanned | {len(results)} |\n")
        lines.append(f"| Files flagged | {flagged} |\n")
        lines.append(f"| Critical findings | {critical} |\n")
        lines.append(f"| Total findings | {total_findings} |\n\n")

        for r in results:
            filtered = [f for f in r.findings if finding_at_threshold(f, min_severity)]
            if not filtered:
                continue

            lines.append(f"### `{r.file_path}`\n")
            lines.append("| Severity | Rule | Name | Category |\n")
            lines.append("|---|---|---|---|\n")
            for f in filtered:
                emoji = SEVERITY_EMOJI.get(f.severity, "")
                lines.append(f"| {emoji} {f.severity} | `{f.rule_id}` | {f.name} | {f.category} |\n")
                if f.matches:
                    match_text = f.matches[0][:120].replace("|", "\\|")
                    lines.append(f"\n> ↳ `{match_text}`\n\n")
                lines.append(f"> {f.note}\n\n")

    lines.append("\n---\n")
    lines.append("*Powered by [Blindspot](https://github.com/jclark2496/blindspot) — AI Security Scanner*\n")

    with open(summary_file, "w") as f:
        f.writelines(lines)


def write_diff_summary(diff: ProvenanceDiff, min_severity: str) -> None:
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return

    diff_findings = filtered_diff_findings(diff, min_severity)
    findings_only = [finding for _artifact, finding, _kind in diff_findings]
    total_findings, critical, high = count_severities(findings_only)

    lines = ["# Blindspot Provenance Diff\n"]
    lines.append("| | |\n|---|---|\n")
    lines.append(f"| Before | `{diff.before_root}` |\n")
    lines.append(f"| After | `{diff.after_root}` |\n")
    lines.append(f"| Changed artifacts | {diff.changed_artifact_count} |\n")
    lines.append(f"| Recommendation | **{diff.recommendation}** |\n")
    lines.append(f"| New/worsened findings | {total_findings} |\n")
    lines.append(f"| Critical | {critical} |\n")
    lines.append(f"| High | {high} |\n\n")

    if total_findings == 0:
        lines.append(f"## ✅ No new or worsened findings at `{min_severity}` severity and above\n")
    else:
        lines.append(f"## ⚠️ {total_findings} new/worsened finding(s)\n")
        for artifact in diff.artifact_diffs:
            added = [f for f in artifact.added_findings if finding_at_threshold(f, min_severity)]
            worsened = [f for f in artifact.worsened_findings if finding_at_threshold(f, min_severity)]
            if not added and not worsened:
                continue
            before_sev = artifact.before.max_severity or "CLEAN"
            after_sev = artifact.after.max_severity or "CLEAN"
            lines.append(f"### `{artifact.relative_path}` — {before_sev} → {after_sev}\n")
            lines.append("| Change | Severity | Rule | Name |\n")
            lines.append("|---|---|---|---|\n")
            for kind, items in (("New", added), ("Worsened", worsened)):
                for f in items:
                    emoji = SEVERITY_EMOJI.get(f.severity, "")
                    lines.append(f"| {kind} | {emoji} {f.severity} | `{f.rule_id}` | {f.name} |\n")
            lines.append("\n")

    lines.append("\n---\n")
    lines.append("*Powered by [Blindspot](https://github.com/jclark2496/blindspot) — AI Security Scanner*\n")
    with open(summary_file, "w") as f:
        f.writelines(lines)


def filtered_diff_dict(diff: ProvenanceDiff, min_severity: str) -> dict:
    payload = diff.to_dict()
    min_ord = SEVERITY_ORDER.get(min_severity, 4)
    for artifact in payload["artifact_diffs"]:
        for key in ("added_findings", "removed_findings", "unchanged_findings", "worsened_findings"):
            artifact[key] = [
                finding for finding in artifact[key]
                if SEVERITY_ORDER.get(finding["severity"], 9) <= min_ord
            ]
    payload["added_finding_count"] = sum(len(item["added_findings"]) for item in payload["artifact_diffs"])
    payload["worsened_finding_count"] = sum(len(item["worsened_findings"]) for item in payload["artifact_diffs"])
    return payload


def run_scan(args: argparse.Namespace) -> int:
    min_severity = args.min_severity.upper()
    fail_on_findings = args.fail_on_findings.lower() == "true"
    emit_annotations = args.annotations.lower() == "true"
    target = Path(args.path)
    policy_path = Path(args.policy) if args.policy else find_policy(target)
    policy = load_policy(policy_path)
    if policy.min_severity:
        min_severity = policy.min_severity
    if policy.fail_on_findings is not None:
        fail_on_findings = policy.fail_on_findings

    files = collect_files(target)

    if not files:
        print(f"Blindspot: no supported files found at '{target}'")
        set_output("finding-count", "0")
        set_output("critical-count", "0")
        set_output("high-count", "0")
        set_output("added-finding-count", "0")
        set_output("worsened-finding-count", "0")
        set_output("recommendation", "NO NEW RISK")
        set_output("result", "clean")
        return 0

    results = [scan_file(f) for f in files]
    if args.mcp_audit.lower() == "true":
        for result in results:
            if result.file_path and Path(result.file_path).suffix.lower() == ".json":
                result.findings.extend(audit_mcp_manifest(result.file_path))
                result.findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.rule_id))
    suppressed_count = apply_policy(results, policy, root=Path.cwd())

    if args.sarif_file:
        Path(args.sarif_file).write_text(sarif_dumps(results, min_severity, root=Path.cwd()), encoding="utf-8")
        set_output("sarif-file", args.sarif_file)

    if args.output_format == "sarif":
        print(sarif_dumps(results, min_severity, root=Path.cwd()))

    all_findings = filtered_scan_findings(results, min_severity)
    findings_only = [f for _, f in all_findings]
    total_count, critical_count, high_count = count_severities(findings_only)

    if args.output_format == "table":
        print("\nBlindspot — AI Security Scanner")
        print(f"{'─' * 60}")
        print(f"Scanned {len(results)} file(s)  ·  min severity: {min_severity}\n")

        for r in results:
            filtered = [f for f in r.findings if finding_at_threshold(f, min_severity)]
            status = "✓ CLEAN" if not filtered else f"✖ {filtered[0].severity}"
            print(f"  {status:<12}  {r.file_path}")
            for f in filtered:
                print(f"              [{f.rule_id}] {f.name}")
                if f.matches:
                    print(f"              ↳ {f.matches[0][:90]}")

        print(f"\n{'─' * 60}")
        if total_count == 0:
            print(f"  ✅  All clear. {len(results)} file(s) scanned, 0 findings.")
        else:
            print(f"  ⚠️   {total_count} finding(s) — {critical_count} CRITICAL, {high_count} HIGH")
        if suppressed_count:
            print(f"  Policy suppressed {suppressed_count} finding(s)")

    if args.output_format == "json":
        out = [r.to_dict() for r in results]
        print(json.dumps(out, indent=2))

    if emit_annotations:
        for r, f in all_findings:
            level = "error" if f.severity == "CRITICAL" else "warning"
            msg = f"[{f.rule_id}] {f.name}: {f.note}"
            if f.matches:
                msg += f" | Match: {f.matches[0][:100]}"
            emit_annotation(level, str(r.file_path), msg)

    write_scan_summary(results, min_severity)

    set_output("finding-count", str(total_count))
    set_output("critical-count", str(critical_count))
    set_output("high-count", str(high_count))
    set_output("added-finding-count", "0")
    set_output("worsened-finding-count", "0")
    set_output("recommendation", "findings" if total_count > 0 else "NO NEW RISK")
    set_output("result", "findings" if total_count > 0 else "clean")

    if fail_on_findings and total_count > 0:
        return 2
    return 0


def run_diff(args: argparse.Namespace) -> int:
    min_severity = args.min_severity.upper()
    fail_on_findings = args.fail_on_findings.lower() == "true"
    emit_annotations = args.annotations.lower() == "true"

    if not args.before_path or not args.after_path:
        print("Blindspot: diff mode requires --before-path and --after-path", file=sys.stderr)
        return 1
    if args.output_format == "sarif":
        print("Blindspot: diff mode currently supports table or json output; SARIF is scan-mode only.", file=sys.stderr)
        return 1

    diff = diff_artifacts(args.before_path, args.after_path, mcp_audit=args.mcp_audit.lower() == "true")
    diff_findings = filtered_diff_findings(diff, min_severity)
    findings_only = [finding for _artifact, finding, _kind in diff_findings]
    total_count, critical_count, high_count = count_severities(findings_only)
    added_count = sum(1 for _artifact, _finding, kind in diff_findings if kind == "new")
    worsened_count = sum(1 for _artifact, _finding, kind in diff_findings if kind == "worsened")

    if args.output_format == "json":
        print(json.dumps(filtered_diff_dict(diff, min_severity), indent=2))
    else:
        print("\nBlindspot — Provenance Diff")
        print(f"{'─' * 60}")
        print(f"Before: {args.before_path}")
        print(f"After:  {args.after_path}")
        print(f"Recommendation: {diff.recommendation}")
        print(f"Changed artifacts: {diff.changed_artifact_count}\n")
        for artifact in diff.artifact_diffs:
            added = [f for f in artifact.added_findings if finding_at_threshold(f, min_severity)]
            worsened = [f for f in artifact.worsened_findings if finding_at_threshold(f, min_severity)]
            if not artifact.changed and not added and not worsened:
                continue
            before_sev = artifact.before.max_severity or "CLEAN"
            after_sev = artifact.after.max_severity or "CLEAN"
            print(f"  {artifact.relative_path}: {before_sev} → {after_sev}")
            for kind, items in (("NEW", added), ("WORSE", worsened)):
                for f in items:
                    print(f"              [{kind}] {f.severity} {f.rule_id} — {f.name}")
        print(f"\n{'─' * 60}")
        if total_count == 0:
            print("  ✅  No new or worsened findings at threshold.")
        else:
            print(f"  ⚠️   {total_count} new/worsened finding(s) — {critical_count} CRITICAL, {high_count} HIGH")

    if emit_annotations:
        for artifact, f, kind in diff_findings:
            level = "error" if f.severity == "CRITICAL" else "warning"
            msg = f"{kind.upper()} [{f.rule_id}] {f.name}: {f.note}"
            if f.matches:
                msg += f" | Match: {f.matches[0][:100]}"
            emit_annotation(level, artifact.relative_path, msg)

    write_diff_summary(diff, min_severity)

    set_output("finding-count", str(total_count))
    set_output("critical-count", str(critical_count))
    set_output("high-count", str(high_count))
    set_output("added-finding-count", str(added_count))
    set_output("worsened-finding-count", str(worsened_count))
    set_output("recommendation", diff.recommendation)
    set_output("result", "findings" if total_count > 0 else "clean")

    if fail_on_findings and total_count > 0:
        return 2
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="scan", choices=["scan", "diff"])
    parser.add_argument("--path", default=".")
    parser.add_argument("--before-path", default="")
    parser.add_argument("--after-path", default="")
    parser.add_argument("--min-severity", default="HIGH")
    parser.add_argument("--fail-on-findings", default="true")
    parser.add_argument("--output-format", default="table", choices=["table", "json", "sarif"])
    parser.add_argument("--annotations", default="true")
    parser.add_argument("--sarif-file", default="blindspot.sarif")
    parser.add_argument("--policy", default="")
    parser.add_argument("--mcp-audit", default="false")
    args = parser.parse_args()

    if args.mode == "diff":
        return run_diff(args)
    return run_scan(args)


if __name__ == "__main__":
    sys.exit(main())
