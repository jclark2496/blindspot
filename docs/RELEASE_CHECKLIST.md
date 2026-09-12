# Release checklist

Use this checklist before publishing a Blindspot release.

## Repository

- Run the full scanner, CLI, rule-parity, syntax, and extension contract test suite.
- Build the Python sdist and wheel in an isolated environment and install the wheel for a CLI smoke test.
- Scan the current tree and all reachable Git history for credentials, personal paths, private data, and unintended infrastructure references.
- Confirm documentation describes the static-analysis limits accurately.

## Chrome extension

- Confirm the manifest requests only `activeTab` and `scripting`.
- Confirm there are no host permissions, persistent content scripts, background worker, network requests, telemetry, or stored scan history.
- Confirm page scans begin only after the user invokes the extension.
- Verify regular-page scanning and safe errors for browser-protected pages.
- Build twice with `python3 scripts/build_extension.py` and confirm identical checksums.
- Inspect the ZIP contents against the runtime allowlist before attaching it to a release.

## Publication

- Create a versioned release from an exact reviewed commit.
- Attach the deterministic extension ZIP and publish its SHA-256 checksum.
- Re-run hosted CI on the public default branch.
- Verify installation instructions and release links from a signed-out browser.
