# Security Policy

Blindspot is a security tool, so reports about bypasses, unsafe defaults, or vulnerabilities are welcome.

## Supported versions

This project is currently pre-1.0. Security fixes target the `main` branch.

## Reporting a vulnerability

Please do **not** open public issues for vulnerabilities that could expose users or organizations to active abuse before a fix is available.

For now, report privately by emailing the maintainer or opening a private GitHub security advisory if available for this repository.

Include as much of the following as you can safely share:

- Affected Blindspot component: CLI, rule catalog, browser scanner, Chrome extension, GitHub Action, demo site, or docs.
- Exact version or commit SHA.
- Reproduction steps.
- Sample artifact that triggers the problem, with secrets removed.
- Expected result and actual result.
- Whether the issue causes a false negative, false positive, crash, policy bypass, credential exposure, or unsafe installation guidance.

## Sensitive samples

Do not send real credentials, private keys, production prompts, confidential model artifacts, or private customer data. If a sample requires sensitive content to reproduce, redact it and describe the omitted portion.

## Scope

In scope:

- Scanner false negatives for malicious AI artifacts.
- Scanner crashes on malformed AI artifacts.
- Policy suppression bypasses.
- SARIF/reporting output that misrepresents severity or location.
- GitHub Action behavior that leaks data or silently passes on findings.
- Chrome extension behavior that leaks page contents outside the local browser context.

Out of scope:

- Attacks against GitHub, browser vendors, or third-party MCP hosts.
- Generic LLM jailbreaks that do not involve Blindspot artifacts, rules, or integrations.
- Demo-site payloads that are intentionally malicious and documented as examples.

## Disclosure

The maintainer will acknowledge reasonable reports, investigate impact, and coordinate a fix or mitigation. Because this is a pre-1.0 project, timelines may vary, but high-impact issues will be prioritized.
