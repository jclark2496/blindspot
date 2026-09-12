import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CliFeatureTests(unittest.TestCase):
    def run_cli(self, *args, check=True):
        result = subprocess.run(
            [sys.executable, "-m", "scanner.cli", *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        if check and result.returncode != 0:
            self.fail(f"command failed with {result.returncode}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
        return result

    def test_sarif_output_contains_expected_result(self):
        result = self.run_cli(
            "corpus/malicious/01_prompt_injection_basic.md",
            "--format",
            "sarif",
            "--no-policy",
        )
        sarif = json.loads(result.stdout)
        self.assertEqual(sarif["version"], "2.1.0")
        results = sarif["runs"][0]["results"]
        self.assertEqual({item["ruleId"] for item in results}, {"PI-001", "PI-003"})
        self.assertEqual(
            results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "corpus/malicious/01_prompt_injection_basic.md",
        )

    def test_policy_suppression_removes_matching_rule(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as tmp:
            tmp.write(
                "min_severity: HIGH\n"
                "fail_on_findings: true\n"
                "suppressions:\n"
                "  - rule: PI-001\n"
                "    path: corpus/malicious/01_prompt_injection_basic.md\n"
                "    reason: unit test suppression\n"
            )
            policy_path = tmp.name

        try:
            result = self.run_cli(
                "corpus/malicious/01_prompt_injection_basic.md",
                "--policy",
                policy_path,
                "--json",
                check=False,
            )
        finally:
            Path(policy_path).unlink(missing_ok=True)

        self.assertEqual(result.returncode, 2)
        payload = json.loads(result.stdout)
        rule_ids = {finding["rule_id"] for finding in payload[0]["findings"]}
        self.assertNotIn("PI-001", rule_ids)
        self.assertIn("PI-003", rule_ids)

    def test_mcp_audit_adds_structural_findings(self):
        result = self.run_cli(
            "corpus/mcp/16_mcp_confused_deputy.json",
            "--mcp-audit",
            "--json",
            "--no-policy",
        )
        payload = json.loads(result.stdout)
        rule_ids = {finding["rule_id"] for finding in payload[0]["findings"]}
        self.assertIn("MCP-AUDIT-003", rule_ids)
        self.assertIn("MCP-AUDIT-004", rule_ids)

    def test_readme_badge_url_is_not_base64_payload(self):
        result = self.run_cli("README.md", "--json", "--no-policy")
        payload = json.loads(result.stdout)
        self.assertEqual(payload[0]["findings"], [])

    def test_action_runner_diff_mode_blocks_rug_pull(self):
        result = subprocess.run(
            [
                sys.executable,
                "github-action/run_scan.py",
                "--mode",
                "diff",
                "--before-path",
                "corpus/provenance/calendar-helper-v1.md",
                "--after-path",
                "corpus/provenance/calendar-helper-v2-rugpull.md",
                "--min-severity",
                "HIGH",
                "--fail-on-findings",
                "true",
                "--output-format",
                "json",
                "--annotations",
                "false",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["recommendation"], "BLOCK UPDATE")
        self.assertEqual(payload["added_finding_count"], 2)


if __name__ == "__main__":
    unittest.main()
