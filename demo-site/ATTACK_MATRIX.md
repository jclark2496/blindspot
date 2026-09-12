# SkillVault demo site — attack matrix

Reference for every intentional attack embedded in `demo-site/index.html`.
Used for demos and as a regression checklist — if a row's "Detected by"
column regresses, the corresponding tool has a bug.

Detection surfaces:
- **CLI** — `scanner/cli.py` / `scanner/engine.py` (Python, scans file/paste content)
- **Ext** — `extension/` Chrome extension (scans extracted skill content AND
  live page-level surfaces via `extractWebPageAttackSurfaces()`)
- **Std** — `skill-scan.html` standalone browser scanner (scans pasted/dropped
  file content only — no live DOM access, so it cannot see CSS-hidden text,
  computed styles, or the rendered page surface)

All three share one rule catalog (`rules/catalog.json`), so any pattern-based
rule detected by one is detected by all three on identical input. The
difference in the table below is purely about *what content each tool can
observe*, not rule coverage.

---

## Part 1 — Downloadable skill cards (skill-content attacks)

Every skill card's `content` field is plain text/JSON identical across all
three tools' input paths, so CLI/Ext/Std detection is always identical here.

| # | OWASP risk | Skill name | Expected rule IDs | Severity | CLI | Ext | Std |
|---|---|---|---|---|---|---|---|
| s1 | LLM01 Prompt Injection | Executive Briefing Assistant | `HC-002`, `HC-004`, `PI-005` | CRITICAL | ✅ | ✅ | ✅ |
| s2 | LLM02 Sensitive Info Disclosure | HR Onboarding Helper | `DE-002`, `DE-005`, `PI-005` | CRITICAL | ✅ | ✅ | ✅ |
| s3 | LLM03 Supply Chain | DevOps Automation Skill | `CR-001`, `CR-003` | CRITICAL | ✅ | ✅ | ✅ |
| s4 | LLM04 Data Poisoning | Legal Research Assistant | `BM-001` | HIGH | ✅ | ✅ | ✅ |
| s5 | LLM05 Improper Output Handling | Code Review Bot | `MCP-004` | CRITICAL | ✅ | ✅ | ✅ |
| s6 | LLM06 Excessive Agency | Calendar & Email Manager | `MCP-001`, `MCP-003`, `MCP-005` | CRITICAL | ✅ | ✅ | ✅ |
| s7 | LLM07 System Prompt Leakage | Customer Support Agent | `DE-001`, `HC-004`, `PI-005` | CRITICAL | ✅ | ✅ | ✅ |
| s8 | LLM08 Vector/Embedding Weakness | Knowledge Base Connector | `MCP-005` | CRITICAL | ✅ | ✅ | ✅ |
| s9 | LLM09 Misinformation | Medical Info Assistant | `IP-001`, `PI-003` | CRITICAL | ✅ | ✅ | ✅ |
| s10 | LLM10 Unbounded Consumption | Research & Web Assistant | `HC-002`, `MCP-002` | CRITICAL | ✅ | ✅ | ✅ |

`s3`'s placeholder AWS key is `AKIA4BUILDBOT12345AB` — exactly 16 characters
after `AKIA`, matching the real AWS access key format (`AKIA[0-9A-Z]{16}\b`)
so `CR-001` fires alongside `CR-003` (the MongoDB connection string in the
same file).

---

## Part 2 — Page-level attack surfaces (only the Chrome extension can see these)

These attacks live in the page's HTML structure itself — metadata, structured
data, comments, CSS-hidden text, and attribute values — not in a skill file.
Detecting them requires a live DOM (computed styles, rendered attributes),
which only the Chrome extension has. CLI and the standalone scanner would
only catch these if you pasted the *raw page source* directly into them.

| Surface | Location in page | Rule IDs observed | Severity | Detected by |
|---|---|---|---|---|
| `meta[name=description]` | `<head>` | `PI-002`, `MCP-002` | CRITICAL | Ext only (CLI/Std if raw source pasted) |
| `meta[name=keywords]` | `<head>` | `PI-001`, `PI-003` | CRITICAL | Ext only |
| `script[type=application/ld+json]` | `<head>` | `DE-001`, `MCP-001`, `MCP-003` | CRITICAL | Ext only |
| HTML comment (top of `<body>`) | `<body>` | `PI-001`, `PI-005`, `DE-001` | CRITICAL | Ext only |
| Hidden text — white-on-white CSS | Blog post 1 | `PI-001`, `PI-003` (and more via nested skill content) | CRITICAL | Ext only |
| Hidden text — `font-size:0` | Blog post 1 | `IP-001` | CRITICAL | Ext only |
| Hidden text — `display:none` div | Blog post 3 (inside "AI Safety" article) | `PI-002`, `DE-001`, `HC-002` | CRITICAL | Ext only |
| Hidden text — `display:none` div | Footer | `HC-002` | CRITICAL | Ext only |
| `img[alt]` | Blog post 2 | `DE-005`, `PE-001` | CRITICAL | Ext only |
| `img[title]` | Blog post 2 | `PI-001`, `PI-003` | CRITICAL | Ext only |
| `button[title]` | Blog post 2 | `DE-001`, `DE-003` | CRITICAL | Ext only |
| Zero-width chars in nav logo | Nav bar | `HC-001` | CRITICAL | Ext only |
| MCP Zoo sample manifest | Blindspot attack labs section | `MCP-003`, `MCP-004`, `MCP-AUDIT-001`, `MCP-AUDIT-004` | CRITICAL | CLI with `--mcp-audit`; Ext/Std detect text rules if pasted |
| RAG poisoning hidden text | Blindspot attack labs section | `PI-001`, `IP-001` | CRITICAL | Ext only for hidden DOM surface; CLI/Std if raw source pasted |
| Provenance rug-pull diff | Blindspot attack labs section | `PI-005`, `HC-004` newly added from v1.0 → v1.1 | CRITICAL | CLI `diff`; visible demo panel |

### False-positive guardrail verification

Ordinary HTML comments used purely as source-code annotations (e.g. the
`<!-- ATTACK: LLM01 ... -->` labels sprinkled through this file to mark each
attack for readers) produce **zero findings** — `HC-004` cannot fire on a
`Comment.data` value because it requires the literal `<!--`/`-->` delimiters,
which are never part of a comment node's `.data` property. Only comments
whose *content* independently matches a real detection rule are ever
surfaced. Verified against benign copyright/analytics/TODO-style comment
text with zero false positives.

---

## Regenerating this matrix

If skill card content or page-level attack surfaces change, re-run the
verification queries in `scanner/engine.py` (`scan_content`) against each
skill's `content` field, and re-verify page surfaces via the Chrome
extension's `extractWebPageAttackSurfaces()` + `scanContent()` pipeline.
There is currently no automated generator for this file — update it by hand
alongside any demo-site content change.
