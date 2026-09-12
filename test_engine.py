"""
Corpus validation — not a pytest suite, just a readable run-all.

Unlike a "did something fire" smoke test, this validates against
corpus/corpus_index.json as the source of expected truth for every
fixture: expected PASS/FAIL, expected severity, and the EXACT set of
rule IDs that must fire. A missing detection, a new false positive, or
an unexpected extra finding on a benign fixture all fail the run.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from scanner import scan_file

ROOT = Path(__file__).parent
CORPUS = ROOT / "corpus"
INDEX_PATH = CORPUS / "corpus_index.json"

SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[94m",
    "LOW":      "\033[96m",
    None:       "\033[92m",
}
RESET = "\033[0m"
GREEN = "\033[92m"
RED   = "\033[91m"


def sev_str(s):
    color = SEVERITY_COLOR.get(s, "")
    label = s or "CLEAN"
    return f"{color}{label:<8}{RESET}"


def load_index() -> list[dict]:
    data = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    return data["entries"]


def check_entry(entry: dict) -> list[str]:
    """Return a list of failure messages for this entry (empty = pass)."""
    problems = []
    f = CORPUS / entry["file"]
    result = scan_file(f)
    actual_ids = sorted(x.rule_id for x in result.findings)
    expected_ids = sorted(entry.get("expected_rule_ids", []))
    expected_result = entry["expected_result"]  # "PASS" | "FAIL"

    if expected_result == "PASS":
        if actual_ids:
            problems.append(
                f"expected PASS (no findings) but got: {actual_ids}"
            )
    else:  # FAIL — malicious fixture, must produce findings
        if not actual_ids:
            problems.append("expected findings but scanner produced none")
        missing = [r for r in expected_ids if r not in actual_ids]
        extra = [r for r in actual_ids if r not in expected_ids]
        if missing:
            problems.append(f"missing expected rule(s): {missing}")
        if extra:
            problems.append(f"unexpected extra rule(s) fired: {extra}")

        expected_sev = entry.get("severity")
        if expected_sev and expected_sev != "NONE" and result.max_severity != expected_sev:
            problems.append(
                f"expected max_severity={expected_sev} but got {result.max_severity}"
            )

    return problems


def main() -> int:
    print("\n" + "═" * 74)
    print("  Blindspot corpus validation (exact rule-ID matching)")
    print("═" * 74)

    entries = load_index()
    total_fail = 0

    groups: dict[str, list[dict]] = {}
    for e in entries:
        group = e["file"].split("/")[0]
        groups.setdefault(group, []).append(e)

    for group_name, group_entries in groups.items():
        print(f"\n{'─' * 74}")
        print(f"  {group_name}  ({len(group_entries)} fixtures)")
        print(f"{'─' * 74}")
        for entry in sorted(group_entries, key=lambda e: e["file"]):
            f = CORPUS / entry["file"]
            result = scan_file(f)
            problems = check_entry(entry)
            status = "✓" if not problems else "✗ FAIL"
            if problems:
                total_fail += 1
            print(f"  {status}  {sev_str(result.max_severity)}  {entry['file']}  "
                  f"({result.finding_count} findings)")
            for p in problems:
                print(f"       → {p}")

    print(f"\n{'═' * 74}")
    if total_fail == 0:
        print(f"  {GREEN}All {len(entries)} fixtures match expected rule IDs exactly.{RESET}")
    else:
        print(f"  {RED}{total_fail} of {len(entries)} fixture(s) failed.{RESET}")
    print("═" * 74 + "\n")

    # Detailed findings for malicious/mcp fixtures
    print("── Detailed findings (malicious + mcp) ──────────────────────────────\n")
    for entry in sorted(entries, key=lambda e: e["file"]):
        if entry["expected_result"] != "FAIL":
            continue
        f = CORPUS / entry["file"]
        result = scan_file(f)
        if result.findings:
            print(f"  {entry['file']}")
            for finding in result.findings:
                print(f"    [{finding.severity}] {finding.rule_id} — {finding.name}")
                for m in finding.matches[:1]:
                    print(f"      ↳ {m[:100]}")
            print()

    return total_fail


if __name__ == "__main__":
    sys.exit(main())
