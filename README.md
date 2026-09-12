# Blindspot

[![Blindspot CI](https://github.com/jclark2496/blindspot/actions/workflows/blindspot.yml/badge.svg)](https://github.com/jclark2496/blindspot/actions/workflows/blindspot.yml)

Blindspot is a static AI security toolchain for finding malicious patterns in AI skills, MCP manifests, and web pages before they are installed, trusted, loaded, indexed, or exposed to an agent.

It maps findings to OWASP LLM Top 10 style risks and MITRE ATLAS techniques, with one canonical rule catalog shared across the Python CLI, standalone browser scanner, and Chrome extension.

## Tools in this repository

- **Blindspot CLI** — Python scanner package, currently exposed as `skill-scan`.
- **Blindspot Scanner** — standalone browser scanner in `skill-scan.html`.
- **Blindspot for Chrome** — user-initiated Manifest V3 extension in `extension/`.
- **Blindspot Action** — GitHub composite action in `github-action/`.
- **Guardian Skill** — Claude skill that reviews other skills in `GUARDIAN_SKILL.md`.
- **SkillVault Demo Site** — fake AI skill marketplace and attack lab in `demo-site/`.

## Repository hygiene

- CI lives in `.github/workflows/blindspot.yml` and verifies generated rules, scanner tests, CLI features, JavaScript parity, the extension privacy/permission contract, deterministic packaging, and the local composite GitHub Action.
- Security reporting guidance lives in `SECURITY.md`.
- Public issue templates separate bugs from rule coverage requests.
- Pull requests should use `.github/pull_request_template.md` and include the relevant verification commands.

## Quick start

Run from the repository root:

```bash
python3 -m scanner.cli corpus/malicious/01_prompt_injection_basic.md
python3 -m scanner.cli corpus --min-severity HIGH --exit-code
```

Install locally as a command-line package:

```bash
python3 -m pip install -e .
skill-scan corpus --min-severity HIGH --exit-code
```

## Chrome extension

The extension scans only after you click its toolbar icon. It injects a local extractor into the current tab, returns bounded page content to the popup, and runs the packaged rules there. It has no background service worker, persistent content script, host permission, network request, telemetry, or retained scan history.

Install from source:

1. Open `chrome://extensions` and enable **Developer mode**.
2. Choose **Load unpacked** and select this repository's `extension/` directory.
3. Open a regular web page and click Blindspot to scan that tab, or use the popup's **Paste** tab.

Build the reviewable release ZIP:

```bash
python3 scripts/build_extension.py
```

The builder writes `dist/blindspot-extension-<version>.zip` with a fixed runtime-file allowlist, sorted entries, stable metadata, and timestamps. Rebuilding unchanged source produces identical bytes.

Permissions are deliberately limited to:

- `activeTab` — temporary access to the tab where the user invoked Blindspot.
- `scripting` — inject the packaged extractor into that tab on demand.

See [PRIVACY.md](PRIVACY.md) for the exact data-handling statement. Blindspot is static, pattern-based analysis: it can miss novel, obfuscated, contextual, or dynamically loaded attacks and can produce false positives. A clean result is not a guarantee of safety. Chrome-protected pages, the Chrome Web Store, and some viewer/restricted-frame content cannot be scanned; use the Paste tab when appropriate.

Useful flags:

```bash
# JSON output
python3 -m scanner.cli corpus/malicious/01_prompt_injection_basic.md --json

# SARIF output for GitHub code scanning or other SARIF consumers
python3 -m scanner.cli corpus/malicious/01_prompt_injection_basic.md --format sarif > blindspot.sarif
python3 -m scanner.cli corpus/malicious/01_prompt_injection_basic.md --sarif-file blindspot.sarif

# Optional MCP structural audit layer
python3 -m scanner.cli corpus/mcp/16_mcp_confused_deputy.json --mcp-audit

# Compare two artifact versions for rug-pull risk
python3 -m scanner.cli diff corpus/provenance/calendar-helper-v1.md corpus/provenance/calendar-helper-v2-rugpull.md
python3 -m scanner.cli diff corpus/provenance/mcp-docs-v1.json corpus/provenance/mcp-docs-v2-rugpull.json --mcp-audit --exit-code

# Enforce exit code 2 when findings meet the threshold
python3 -m scanner.cli corpus --min-severity HIGH --exit-code
```

## Policy configuration

Blindspot can load a `.blindspot.yml`, `.blindspot.yaml`, or `.blindspot.json` policy file. If `--policy` is not provided, the CLI searches parent directories from the scanned target.

Start from:

```bash
cp .blindspot.example.yml .blindspot.yml
```

Example:

```yaml
min_severity: HIGH
fail_on_findings: true

suppressions:
  - rule: HC-004
    path: docs/training-examples/*.md
    reason: Intentional training sample showing HTML comment attacks.
```

Current policy support is intentionally lightweight:

- `min_severity` overrides the CLI/action threshold.
- `fail_on_findings` can force or disable failure behavior.
- `suppressions` remove findings by rule and path glob. Suppressions should include a human-readable `reason`.

Disable policy discovery with:

```bash
python3 -m scanner.cli corpus --no-policy
```

## SARIF and GitHub code scanning

The CLI can emit SARIF 2.1.0:

```bash
python3 -m scanner.cli corpus --format sarif --no-policy > blindspot.sarif
```

Or write SARIF while still printing another output format:

```bash
python3 -m scanner.cli corpus --sarif-file blindspot.sarif
```

The GitHub Action always writes a SARIF file by default:

```yaml
name: Blindspot
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: ./github-action
        id: blindspot
        with:
          path: .
          min-severity: HIGH
          output-format: table
          mcp-audit: 'true'
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ${{ steps.blindspot.outputs.sarif-file }}
```

The repository's own workflow exercises the local action against a safe file (`SECURITY.md`) so CI proves the action installs from source before the package is published. It uploads SARIF on push when code scanning is available, but the SARIF upload is allowed to fail so private-repo code-scanning availability does not break normal CI.

The action can also run provenance diff mode to block AI artifact rug pulls in PRs:

```yaml
- uses: jclark2496/blindspot/github-action@main
  id: blindspot-diff
  with:
    mode: diff
    before-path: approved-ai-artifacts
    after-path: incoming-ai-artifacts
    min-severity: HIGH
    fail-on-findings: 'true'
    output-format: table
    mcp-audit: 'true'
```

Diff mode fails when the updated artifact introduces new or worsened findings at the configured severity threshold. See `examples/github-actions/rugpull-diff.yml` for a complete workflow skeleton.

## MCP static audit mode

The rule engine already catches malicious text in MCP descriptions and schemas. `--mcp-audit` adds MCP-aware structural checks for JSON manifests with tool definitions.

It currently adds these audit findings:

- `MCP-AUDIT-001` — tool name shadows high-trust capability.
- `MCP-AUDIT-002` — external URL in tool description.
- `MCP-AUDIT-003` — sensitive or high-agency parameter surface.
- `MCP-AUDIT-004` — dangerous MCP parameter default.
- `MCP-AUDIT-005` — duplicate MCP tool names.

Example:

```bash
python3 -m scanner.cli corpus/mcp/16_mcp_confused_deputy.json --mcp-audit --json
```

## Provenance / rug-pull diffing

Blindspot can compare a previously approved artifact to a newer version and report whether the update introduced new static risk.

```bash
python3 -m scanner.cli diff OLD NEW
python3 -m scanner.cli diff OLD NEW --json
python3 -m scanner.cli diff OLD NEW --exit-code --min-severity HIGH
```

For MCP manifests, include the structural audit layer:

```bash
python3 -m scanner.cli diff old-manifest.json new-manifest.json --mcp-audit --exit-code
```

The diff reports:

- content hashes for the old and new artifact
- old posture and new posture, e.g. `CLEAN → CRITICAL`
- newly added findings
- removed findings
- worsened findings
- a recommendation: `NO NEW RISK`, `REVIEW UPDATE`, `RISK REDUCED`, or `BLOCK UPDATE`

Use this in CI or dependency-review workflows to catch the supply-chain case where an artifact was trusted when installed but later gained hidden instructions, exfiltration behavior, or dangerous MCP tool defaults.

## Canonical rule flow

`rules/catalog.json` is the canonical rule source. Do not hand-edit generated rule files:

- `scanner/rules.py`
- `extension/rules.js`
- generated rules block in `skill-scan.html`

To change rules:

```bash
python3 scripts/generate_rules.py
python3 scripts/generate_rules.py --check
python3 test_engine.py
node tests/check_rule_parity.js
```

If expected detections change, update `corpus/corpus_index.json`.

## Verification checklist

Run before shipping changes:

```bash
python3 scripts/generate_rules.py --check
python3 test_engine.py
node tests/check_rule_parity.js
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m scanner.cli corpus/malicious/01_prompt_injection_basic.md --json --exit-code
python3 -m scanner.cli corpus --min-severity HIGH --exit-code
node --check extension/content.js
node --check extension/popup.js
node --check extension/rules.js
python3 scripts/build_extension.py
```

The two CLI commands with `--exit-code` are expected to exit with code `2` when findings are present.
