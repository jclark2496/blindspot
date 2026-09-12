import json
import subprocess
import sys
import unittest
from pathlib import Path

from scanner.provenance import diff_artifacts


ROOT = Path(__file__).resolve().parents[1]


class ProvenanceDiffTests(unittest.TestCase):
    def test_skill_rugpull_adds_new_findings(self):
        diff = diff_artifacts(
            ROOT / "corpus/provenance/calendar-helper-v1.md",
            ROOT / "corpus/provenance/calendar-helper-v2-rugpull.md",
        )
        self.assertEqual(diff.recommendation, "BLOCK UPDATE")
        artifact = diff.artifact_diffs[0]
        added_ids = {finding.rule_id for finding in artifact.added_findings}
        self.assertIn("HC-004", added_ids)
        self.assertIn("PI-005", added_ids)
        self.assertEqual(artifact.before.max_severity, None)
        self.assertEqual(artifact.after.max_severity, "CRITICAL")

    def test_mcp_rugpull_includes_structural_audit(self):
        diff = diff_artifacts(
            ROOT / "corpus/provenance/mcp-docs-v1.json",
            ROOT / "corpus/provenance/mcp-docs-v2-rugpull.json",
            mcp_audit=True,
        )
        artifact = diff.artifact_diffs[0]
        added_ids = {finding.rule_id for finding in artifact.added_findings}
        self.assertIn("MCP-001", added_ids)
        self.assertIn("DE-002", added_ids)
        self.assertIn("MCP-AUDIT-003", added_ids)
        self.assertIn("MCP-AUDIT-004", added_ids)

    def test_cli_diff_json_and_exit_code(self):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "scanner.cli",
                "diff",
                "corpus/provenance/calendar-helper-v1.md",
                "corpus/provenance/calendar-helper-v2-rugpull.md",
                "--json",
                "--exit-code",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 2)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["recommendation"], "BLOCK UPDATE")
        self.assertEqual(payload["added_finding_count"], 2)
        added_ids = {
            finding["rule_id"]
            for artifact in payload["artifact_diffs"]
            for finding in artifact["added_findings"]
        }
        self.assertIn("HC-004", added_ids)
        self.assertIn("PI-005", added_ids)


if __name__ == "__main__":
    unittest.main()
