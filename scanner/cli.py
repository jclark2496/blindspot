"""
skill-scan CLI — static scanner for AI skill files and MCP manifests.

Usage:
  skill-scan <file_or_dir> [options]

Options:
  --json          Output findings as JSON (for CI / machine consumption)
  --min-severity  Only report findings at this severity or above
                  (CRITICAL | HIGH | MEDIUM | LOW | INFO)  [default: INFO]
  --exit-code     Exit non-zero if any findings at --min-severity or above
                  (default: always exit 0 unless scan errors)
  --no-color      Disable ANSI color output
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running as `python -m scanner.cli` or directly
sys.path.insert(0, str(Path(__file__).parent.parent))
from scanner.engine import scan_file, ScanResult, Finding
from scanner.mcp_auditor import audit_mcp_manifest
from scanner.policy import apply_policy, find_policy, load_policy
from scanner.provenance import diff_artifacts, ProvenanceDiff
from scanner.sarif import dumps as sarif_dumps

# ── Terminal colors ──────────────────────────────────────────────────────────

_USE_COLOR = True

_SEV_COLOR = {
    "CRITICAL": "\033[91m",   # bright red
    "HIGH":     "\033[93m",   # bright yellow
    "MEDIUM":   "\033[94m",   # bright blue
    "LOW":      "\033[96m",   # cyan
    "INFO":     "\033[37m",   # grey
}
_GREEN  = "\033[92m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"
_RESET  = "\033[0m"

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

_SEV_ICON = {
    "CRITICAL": "✖",
    "HIGH":     "⚠",
    "MEDIUM":   "▲",
    "LOW":      "ℹ",
    "INFO":     "·",
}


def _c(text: str, code: str) -> str:
    if not _USE_COLOR:
        return text
    return f"{code}{text}{_RESET}"


def _sev(s: str) -> str:
    color = _SEV_COLOR.get(s, "")
    icon  = _SEV_ICON.get(s, "?")
    return _c(f"{icon} {s:<8}", color)


# ── Supported extensions ─────────────────────────────────────────────────────

_SUPPORTED_EXTS = {".md", ".json", ".yaml", ".yml", ".txt"}


def _collect_files(targets: list[Path]) -> list[Path]:
    files: list[Path] = []
    for t in targets:
        if t.is_dir():
            for ext in _SUPPORTED_EXTS:
                files.extend(t.rglob(f"*{ext}"))
        elif t.is_file():
            files.append(t)
        else:
            print(_c(f"  warning: path not found: {t}", _DIM), file=sys.stderr)
    return sorted(set(files))


# ── Renderers ────────────────────────────────────────────────────────────────

def _render_human(results: list[ScanResult], min_severity: str) -> None:
    min_ord = _SEVERITY_ORDER.get(min_severity, 4)
    any_findings = False

    for result in results:
        filtered = [f for f in result.findings
                    if _SEVERITY_ORDER.get(f.severity, 99) <= min_ord]

        if result.error:
            print(f"\n  {_c('ERROR', _SEV_COLOR['CRITICAL'])}  {result.file_path}")
            print(f"    {result.error}")
            continue

        rel = result.file_path or "<stdin>"
        if not filtered:
            print(f"  {_c('✓ NO INDICATORS', _GREEN)}  {_c(rel, _DIM)}")
            continue

        any_findings = True
        max_sev = filtered[0].severity  # already sorted
        print(f"\n  {_sev(max_sev)}  {_c(rel, _BOLD)}")
        print(f"  {_c('─' * 66, _DIM)}")

        for finding in filtered:
            print(f"  {_sev(finding.severity)}  "
                  f"[{_c(finding.rule_id, _DIM)}] {finding.name}")
            print(f"    {_c('atlas:', _DIM)} {finding.atlas_id}")
            print(f"    {_c('note:', _DIM)}  {finding.note}")
            if finding.matches:
                for m in finding.matches[:3]:
                    truncated = m[:100] + ("…" if len(m) > 100 else "")
                    print(f"    {_c('↳', _DIM)} {truncated}")
            print()

    if not any_findings:
        pass  # individual CLEAN lines already printed


def _render_summary(results: list[ScanResult], min_severity: str) -> tuple[int, int]:
    """Return (files_with_findings, total_findings)."""
    min_ord = _SEVERITY_ORDER.get(min_severity, 4)
    files_flagged = 0
    total_findings = 0
    for r in results:
        count = sum(1 for f in r.findings if _SEVERITY_ORDER.get(f.severity, 99) <= min_ord)
        if count:
            files_flagged += 1
            total_findings += count
    return files_flagged, total_findings


def _render_json(results: list[ScanResult], min_severity: str) -> None:
    min_ord = _SEVERITY_ORDER.get(min_severity, 4)
    output = []
    for r in results:
        d = r.to_dict()
        d["findings"] = [f for f in d["findings"]
                         if _SEVERITY_ORDER.get(f["severity"], 99) <= min_ord]
        d["finding_count"] = len(d["findings"])
        d["max_severity"] = d["findings"][0]["severity"] if d["findings"] else None
        d["clean"] = len(d["findings"]) == 0
        output.append(d)
    print(json.dumps(output, indent=2))


def _finding_at_threshold(finding: Finding, min_severity: str) -> bool:
    return _SEVERITY_ORDER.get(finding.severity, 99) <= _SEVERITY_ORDER.get(min_severity, 99)


def _diff_has_new_risk(diff: ProvenanceDiff, min_severity: str) -> bool:
    for artifact in diff.artifact_diffs:
        if any(_finding_at_threshold(f, min_severity) for f in artifact.added_findings):
            return True
        if any(_finding_at_threshold(f, min_severity) for f in artifact.worsened_findings):
            return True
    return False


def _filtered_diff_dict(diff: ProvenanceDiff, min_severity: str) -> dict:
    payload = diff.to_dict()
    min_ord = _SEVERITY_ORDER.get(min_severity, 99)
    for artifact in payload["artifact_diffs"]:
        for key in ("added_findings", "removed_findings", "unchanged_findings", "worsened_findings"):
            artifact[key] = [
                finding for finding in artifact[key]
                if _SEVERITY_ORDER.get(finding["severity"], 99) <= min_ord
            ]
    payload["added_finding_count"] = sum(len(item["added_findings"]) for item in payload["artifact_diffs"])
    payload["worsened_finding_count"] = sum(len(item["worsened_findings"]) for item in payload["artifact_diffs"])
    return payload


def _render_diff_human(diff: ProvenanceDiff, min_severity: str) -> None:
    print()
    print(_c("  Blindspot provenance diff", _BOLD))
    print(_c("  " + "─" * 50, _DIM))
    print(f"  before: {_c(diff.before_root, _DIM)}")
    print(f"  after:  {_c(diff.after_root, _DIM)}")
    recommendation_color = _SEV_COLOR["CRITICAL"] if diff.recommendation == "BLOCK UPDATE" else _BOLD
    print(f"  recommendation: {_c(diff.recommendation, recommendation_color)}")
    print()

    shown = 0
    for artifact in diff.artifact_diffs:
        added = [f for f in artifact.added_findings if _finding_at_threshold(f, min_severity)]
        worsened = [f for f in artifact.worsened_findings if _finding_at_threshold(f, min_severity)]
        removed = [f for f in artifact.removed_findings if _finding_at_threshold(f, min_severity)]
        if not artifact.changed and not added and not worsened and not removed:
            continue
        shown += 1
        before_sev = artifact.before.max_severity or "CLEAN"
        after_sev = artifact.after.max_severity or "CLEAN"
        print(f"  {_c(artifact.relative_path, _BOLD)}")
        print(f"    posture: {before_sev} → {after_sev}")
        print(f"    hashes:  {(artifact.before.sha256 or 'missing')[:12]} → {(artifact.after.sha256 or 'missing')[:12]}")
        if added:
            print("    new findings:")
            for finding in added:
                print(f"      {_sev(finding.severity)} [{finding.rule_id}] {finding.name}")
        if worsened:
            print("    worsened findings:")
            for finding in worsened:
                print(f"      {_sev(finding.severity)} [{finding.rule_id}] {finding.name}")
        if removed:
            print("    removed findings:")
            for finding in removed:
                print(f"      {_sev(finding.severity)} [{finding.rule_id}] {finding.name}")
        if not added and not worsened and not removed:
            print("    content changed, but no finding posture change at this threshold")
        print()

    if shown == 0:
        print(f"  {_c('No artifact changes or new risk at this threshold.', _GREEN)}\n")


def _main_diff(argv: list[str]) -> int:
    global _USE_COLOR

    parser = argparse.ArgumentParser(
        prog="skill-scan diff",
        description="Compare two AI artifact versions for rug-pull risk.",
    )
    parser.add_argument("before", help="Previous artifact file or directory")
    parser.add_argument("after", help="New artifact file or directory")
    parser.add_argument("--format", choices=["table", "json"], default="table",
                        help="Output format: table or json (default: table)")
    parser.add_argument("--json", action="store_true",
                        help="Output provenance diff as JSON (alias for --format json)")
    parser.add_argument("--mcp-audit", action="store_true",
                        help="Add MCP structural audit findings for JSON manifests with a tools array")
    parser.add_argument("--min-severity", metavar="LEVEL", default="INFO",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Minimum severity to report (default: INFO)")
    parser.add_argument("--exit-code", action="store_true",
                        help="Exit 2 when new or worsened findings meet --min-severity")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI color output")
    args = parser.parse_args(argv)

    output_format = "json" if args.json else args.format
    if args.no_color or output_format == "json":
        _USE_COLOR = False

    diff = diff_artifacts(args.before, args.after, mcp_audit=args.mcp_audit)
    if output_format == "json":
        print(json.dumps(_filtered_diff_dict(diff, args.min_severity), indent=2))
    else:
        _render_diff_human(diff, args.min_severity)

    if args.exit_code and _diff_has_new_risk(diff, args.min_severity):
        return 2
    return 0


# ── Main ─────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    global _USE_COLOR

    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "diff":
        return _main_diff(argv[1:])

    parser = argparse.ArgumentParser(
        prog="skill-scan",
        description="Static security scanner for AI skill files and MCP manifests.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("targets", nargs="+", metavar="PATH",
                        help="File(s) or directory/ies to scan")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON (alias for --format json)")
    parser.add_argument("--format", choices=["table", "json", "sarif"], default="table",
                        help="Output format: table, json, or sarif (default: table)")
    parser.add_argument("--sarif-file", metavar="PATH",
                        help="Also write SARIF results to PATH")
    parser.add_argument("--policy", metavar="PATH",
                        help="Path to .blindspot.yml/.json policy file. If omitted, searches parent directories.")
    parser.add_argument("--no-policy", action="store_true",
                        help="Disable automatic .blindspot.yml policy discovery")
    parser.add_argument("--mcp-audit", action="store_true",
                        help="Add MCP structural audit findings for JSON manifests with a tools array")
    parser.add_argument("--min-severity", metavar="LEVEL", default="INFO",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Minimum severity to report (default: INFO; policy can override)")
    parser.add_argument("--exit-code", action="store_true",
                        help="Exit non-zero when findings meet --min-severity threshold")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI color output")

    args = parser.parse_args(argv)

    output_format = "json" if args.json else args.format

    if args.no_color or output_format in {"json", "sarif"}:
        _USE_COLOR = False

    target_paths = [Path(t) for t in args.targets]
    policy_path = None
    if args.policy:
        policy_path = Path(args.policy)
    elif not args.no_policy and target_paths:
        policy_path = find_policy(target_paths[0])
    policy = load_policy(policy_path)
    min_severity = policy.min_severity or args.min_severity

    files = _collect_files(target_paths)
    if not files:
        print("skill-scan: no supported files found.", file=sys.stderr)
        return 1

    results = [scan_file(f) for f in files]
    if args.mcp_audit:
        for result in results:
            if result.file_path and Path(result.file_path).suffix.lower() == ".json":
                result.findings.extend(audit_mcp_manifest(result.file_path))
                result.findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), f.rule_id))
    suppressed_count = apply_policy(results, policy, root=Path.cwd())

    if args.sarif_file:
        Path(args.sarif_file).write_text(sarif_dumps(results, min_severity, root=Path.cwd()), encoding="utf-8")

    if output_format == "sarif":
        print(sarif_dumps(results, min_severity, root=Path.cwd()))
        files_flagged, _ = _render_summary(results, min_severity)
        should_fail = policy.fail_on_findings if policy.fail_on_findings is not None else args.exit_code
        if should_fail and files_flagged > 0:
            return 2
        return 0

    if output_format == "json":
        _render_json(results, min_severity)
        files_flagged, _ = _render_summary(results, min_severity)
        should_fail = policy.fail_on_findings if policy.fail_on_findings is not None else args.exit_code
        if should_fail and files_flagged > 0:
            return 2  # distinct from usage errors (1)
        return 0

    # Human output
    print()
    print(_c("  skill-scan", _BOLD) + _c(" — AI skill & MCP security scanner", _DIM))
    print(_c("  " + "─" * 50, _DIM))
    print()

    _render_human(results, min_severity)
    if suppressed_count:
        print(_c(f"  policy: suppressed {suppressed_count} finding(s)", _DIM))

    files_flagged, total_findings = _render_summary(results, min_severity)
    total_files = len(results)
    clean_files = total_files - files_flagged

    print(_c("  " + "─" * 50, _DIM))
    if files_flagged == 0:
        print(f"  {_c('No known static indicators detected.', _GREEN)} "
              f"{total_files} file{'s' if total_files != 1 else ''} scanned against the current rule set. "
              f"This is static pattern analysis, not a guarantee of safety.\n")
    else:
        sev_label = _c(f"{total_findings} finding{'s' if total_findings != 1 else ''}", _SEV_COLOR["CRITICAL"])
        print(f"  {sev_label} across {files_flagged} file{'s' if files_flagged != 1 else ''}. "
              f"{clean_files} clean.\n")

    should_fail = policy.fail_on_findings if policy.fail_on_findings is not None else args.exit_code
    if should_fail and files_flagged > 0:
        return 2  # distinct from usage errors (1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
