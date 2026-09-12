#!/usr/bin/env python3
"""
Generate scanner/rules.py, extension/rules.js, and the inline rules block
inside skill-scan.html from the single canonical source: rules/catalog.json.

Custom detector implementations (zero_width, base64_payload, homoglyphs,
sensitive_paths, callback_urls) are hand-maintained per language — one
Python implementation, one JS implementation — and referenced here by name
only. Everything else (id, name, category, severity, atlas_id, note,
pattern) comes exclusively from the catalog.

Run this script after editing rules/catalog.json. Running it twice in a
row with no catalog changes must produce no diff.

Usage:
    python3 scripts/generate_rules.py
    python3 scripts/generate_rules.py --check   # exit 1 if generated files would change
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
CATALOG_PATH = ROOT / "rules" / "catalog.json"
PY_OUT = ROOT / "scanner" / "rules.py"
JS_OUT = ROOT / "extension" / "rules.js"
HTML_OUT = ROOT / "skill-scan.html"

HTML_START_MARKER = "// ── RULES:GENERATED:START ──"
HTML_END_MARKER = "// ── RULES:GENERATED:END ──"


def load_catalog() -> list[dict]:
    data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    return data["rules"]


# ---------------------------------------------------------------------------
# Python generation
# ---------------------------------------------------------------------------

PY_HEADER = '''"""
Detection rules for skill-scan — GENERATED FILE. Do not edit by hand.

Source of truth: rules/catalog.json
Generator:       scripts/generate_rules.py

Each rule is a dict with:
  id        - unique identifier (e.g. "PI-001")
  name      - short display name
  category  - attack category
  severity  - CRITICAL | HIGH | MEDIUM | LOW | INFO
  atlas_id  - MITRE ATLAS technique (best-effort mapping)
  pattern   - compiled regex OR None if matched by custom detector
  match_fn  - callable(content: str) -> list[str] | None (overrides pattern)
  note      - remediation / explanation shown to analyst
"""

import re
import base64
import unicodedata

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _re(pattern: str, flags: int = re.IGNORECASE | re.DOTALL) -> re.Pattern:
    return re.compile(pattern, flags)


# ---------------------------------------------------------------------------
# Custom detectors (match_fn) — hand-maintained, referenced by name in the
# catalog. Keep this section's detector NAMES in sync with rules/catalog.json
# "detector" fields and with the JS implementations in extension/rules.js.
# ---------------------------------------------------------------------------

# Zero-width and invisible Unicode code points
_INVISIBLE = {
    0x200B,  # zero-width space
    0x200C,  # zero-width non-joiner
    0x200D,  # zero-width joiner
    0xFEFF,  # BOM / zero-width no-break space
    0x00AD,  # soft hyphen
    0x2060,  # word joiner
    0x2061,  # function application
    0x2062,  # invisible times
    0x2063,  # invisible separator
    0x2064,  # invisible plus
    0xE0001, # language tag
}
_BIDI_OVERRIDE = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}


def _detect_zero_width(content: str) -> list[str]:
    found = []
    for i, ch in enumerate(content):
        cp = ord(ch)
        if cp in _INVISIBLE:
            found.append(f"U+{cp:04X} at position {i}")
        if cp in _BIDI_OVERRIDE:
            found.append(f"BiDi override U+{cp:04X} at position {i}")
    return found[:10]  # cap matches to avoid noise


def _detect_base64_payload(content: str) -> list[str]:
    """Find base64 strings that decode to instruction-like payloads."""
    b64_re = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
    suspicious_re = re.compile(
        r"(ignore|system|prompt|instruction|response|context|metadata|secret|token|"
        r"password|credential|exfiltrat|append|hidden|invisible|http|curl|bash|eval)",
        re.IGNORECASE,
    )
    matches = []
    for m in b64_re.finditer(content):
        candidate = m.group(0)
        if len(candidate) % 4 == 1:
            continue
        try:
            decoded = base64.b64decode(candidate + "==").decode("utf-8", errors="replace")
            printable_ratio = sum(1 for c in decoded if c.isprintable()) / max(len(decoded), 1)
            if printable_ratio > 0.8 and len(decoded) > 30 and suspicious_re.search(decoded):
                snippet = decoded[:80].replace("\\n", " ")
                matches.append(f"'{candidate[:40]}…' → '{snippet}'")
        except Exception:
            pass
    return matches[:5]


def _detect_homoglyphs(content: str) -> list[str]:
    """Detect common homoglyph substitutions in instruction-like words."""
    suspicious = []
    words_to_check = ["ignore", "system", "anthropic", "instructions", "prompt", "override"]
    for word in words_to_check:
        for i in range(len(content) - len(word) + 1):
            chunk = content[i:i + len(word)]
            normalized = unicodedata.normalize("NFKD", chunk).encode("ascii", "ignore").decode("ascii").lower()
            if normalized == word and chunk.lower() != word:
                suspicious.append(f"Possible homoglyph for '{word}': '{chunk}'")
    return suspicious[:5]


def _detect_sensitive_path_access(content: str) -> list[str]:
    sensitive_paths = [
        (r"~/\\.ssh/",             "~/.ssh/"),
        (r"~/\\.aws/credentials",  "~/.aws/credentials"),
        (r"~/\\.config/",          "~/.config/"),
        (r"/etc/passwd",          "/etc/passwd"),
        (r"~/\\.env\\b",            "~/.env"),
        (r"\\.env\\b",              ".env file"),
        (r"[Kk]eychains?/",       "Keychains/"),
        (r"\\bid_rsa\\b",           "id_rsa"),
        (r"\\w+\\.pem\\b",           "*.pem key file"),
        (r"aws/credentials",      "aws/credentials"),
    ]
    found = []
    for pattern, label in sensitive_paths:
        if re.search(pattern, content):
            found.append(label)
    return found


def _detect_callback_urls(content: str) -> list[str]:
    """Flag hardcoded callback/webhook URLs in MCP schemas."""
    url_re = re.compile(r'https?://[^\\s"\\'<>]+', re.IGNORECASE)
    suspicious = []
    for m in url_re.finditer(content):
        url = m.group(0)
        context_start = max(0, m.start() - 100)
        context = content[context_start:m.end() + 50].lower()
        if any(kw in context for kw in ("default", "callback", "webhook", "collect", "relay", "receive")):
            suspicious.append(url[:100])
    return suspicious[:5]


_DETECTORS = {
    "zero_width": _detect_zero_width,
    "base64_payload": _detect_base64_payload,
    "homoglyphs": _detect_homoglyphs,
    "sensitive_paths": _detect_sensitive_path_access,
    "callback_urls": _detect_callback_urls,
}


# ---------------------------------------------------------------------------
# Rule definitions — GENERATED from rules/catalog.json
# ---------------------------------------------------------------------------

RULES: list[dict] = [
'''

PY_FOOTER = "]\n"


def _py_str(value: str) -> str:
    return json.dumps(value)


def generate_python(rules: list[dict]) -> str:
    lines = [PY_HEADER]
    for r in rules:
        lines.append("    {")
        lines.append(f'        "id": {_py_str(r["id"])},')
        lines.append(f'        "name": {_py_str(r["name"])},')
        lines.append(f'        "category": {_py_str(r["category"])},')
        lines.append(f'        "severity": {_py_str(r["severity"])},')
        lines.append(f'        "atlas_id": {_py_str(r["atlas_id"])},')
        if r["pattern"]:
            lines.append(f'        "pattern": _re({_py_str(r["pattern"])}),')
            lines.append('        "match_fn": None,')
        else:
            lines.append('        "pattern": None,')
            lines.append(f'        "match_fn": _DETECTORS[{_py_str(r["detector"])}],')
        lines.append(f'        "note": {_py_str(r["note"])},')
        lines.append("    },")
    lines.append(PY_FOOTER)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JS generation
# ---------------------------------------------------------------------------

JS_HEADER = """// skill-scan detection rules — GENERATED FILE. Do not edit by hand.
//
// Source of truth: rules/catalog.json
// Generator:       scripts/generate_rules.py
//
// Custom detector functions below are hand-maintained (one implementation
// per language) and referenced by name from the catalog. Everything else
// (id, name, category, severity, atlas, note, pattern) is generated.

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
const SEV_ICON  = { CRITICAL: '✖', HIGH: '⚠', MEDIUM: '▲', LOW: 'ℹ', INFO: '·' };

// ── Custom detectors ─────────────────────────────────────────────────────────

const INVISIBLE_CP = new Set([
  0x200B, 0x200C, 0x200D, 0xFEFF, 0x00AD,
  0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xE0001,
]);
const BIDI_CP = new Set([0x202A,0x202B,0x202C,0x202D,0x202E,0x2066,0x2067,0x2068,0x2069]);

function detectZeroWidth(content) {
  const found = [];
  for (let i = 0; i < content.length; i++) {
    const cp = content.codePointAt(i);
    if (INVISIBLE_CP.has(cp)) found.push(`U+${cp.toString(16).toUpperCase().padStart(4,'0')} at position ${i}`);
    if (BIDI_CP.has(cp))      found.push(`BiDi override U+${cp.toString(16).toUpperCase().padStart(4,'0')} at position ${i}`);
    if (found.length >= 10) break;
  }
  return found;
}

function detectBase64(content) {
  const re = /[A-Za-z0-9+/]{40,}={0,2}/g;
  const suspicious = /(ignore|system|prompt|instruction|response|context|metadata|secret|token|password|credential|exfiltrat|append|hidden|invisible|http|curl|bash|eval)/i;
  const results = [];
  let m;
  while ((m = re.exec(content)) !== null && results.length < 5) {
    if (m[0].length % 4 === 1) continue;
    try {
      const decoded = atob(m[0]);
      const printable = [...decoded].filter(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) < 127).length;
      if (printable / decoded.length > 0.8 && decoded.length > 30 && suspicious.test(decoded)) {
        results.push(`'${m[0].slice(0,40)}…' → '${decoded.slice(0,80).replace(/\\n/g,' ')}'`);
      }
    } catch(e) {}
  }
  return results;
}

function detectHomoglyphs(content) {
  const targets = ['ignore','system','anthropic','instructions','prompt','override'];
  const results = [];
  for (const word of targets) {
    for (let i = 0; i <= content.length - word.length; i++) {
      const chunk = content.slice(i, i + word.length);
      const normalized = chunk.normalize('NFD').replace(/[^\\x00-\\x7F]/g,'').toLowerCase();
      if (normalized === word && chunk.toLowerCase() !== word) {
        results.push(`Possible homoglyph for '${word}': '${chunk}'`);
        if (results.length >= 5) return results;
      }
    }
  }
  return results;
}

function detectCallbackUrls(content) {
  const re = /https?:\\/\\/[^\\s"'<>]+/gi;
  const results = [];
  let m;
  while ((m = re.exec(content)) !== null && results.length < 5) {
    const start = Math.max(0, m.index - 100);
    const ctx = content.slice(start, m.index + m[0].length + 50).toLowerCase();
    if (/default|callback|webhook|collect|relay|receive/.test(ctx))
      results.push(m[0].slice(0,100));
  }
  return results;
}

function detectSensitivePaths(content) {
  const patterns = [
    [/~\\/\\.ssh\\//,           '~/.ssh/'],
    [/~\\/\\.aws\\/credentials/,'~/.aws/credentials'],
    [/aws\\/credentials/,     'aws/credentials'],
    [/~\\/\\.config\\//,        '~/.config/'],
    [/\\/etc\\/passwd/,        '/etc/passwd'],
    [/~\\/\\.env\\b/,           '~/.env'],
    [/\\.env\\b/,              '.env file'],
    [/[Kk]eychains?\\//,      'Keychains/'],
    [/\\bid_rsa\\b/,           'id_rsa'],
    [/\\w+\\.pem\\b/,           '*.pem key file'],
  ];
  return patterns.filter(([re]) => re.test(content)).map(([,label]) => label);
}

const DETECTORS = {
  zero_width: detectZeroWidth,
  base64_payload: detectBase64,
  homoglyphs: detectHomoglyphs,
  sensitive_paths: detectSensitivePaths,
  callback_urls: detectCallbackUrls,
};

// ── Rule table — GENERATED from rules/catalog.json ──────────────────────────

const RULES = [
"""

JS_FOOTER = """];

function applyRule(rule, content) {
  const matches = [];
  if (rule.fn) matches.push(...(rule.fn(content) || []));
  if (rule.re) {
    rule.re.lastIndex = 0;
    let m;
    const seen = new Set();
    while ((m = rule.re.exec(content)) !== null) {
      const excerpt = m[0].slice(0,120).replace(/\\n/g,' ');
      if (!seen.has(excerpt)) { seen.add(excerpt); matches.push(excerpt); }
      if (matches.length >= 5) break;
    }
  }
  return matches;
}

function scanContent(content, filename) {
  const findings = [];
  for (const rule of RULES) {
    const matches = applyRule(rule, content);
    if (matches.length) findings.push({ ...rule, matches });
  }
  findings.sort((a,b) => (SEV_ORDER[a.severity]??9) - (SEV_ORDER[b.severity]??9));
  return { filename: filename || 'page content', findings };
}
"""


def _js_regex_literal(pattern: str) -> str:
    """Turn a canonical pattern string into a JS /pattern/gis literal."""
    # Escape forward slashes for the JS regex literal delimiter.
    escaped = pattern.replace("/", "\\/")
    return f"/{escaped}/gis"


def _js_str(value: str) -> str:
    return json.dumps(value)


def generate_js_rules_array(rules: list[dict]) -> str:
    lines = []
    for r in rules:
        parts = [
            f"id:{_js_str(r['id'])}",
            f"name:{_js_str(r['name'])}",
            f"category:{_js_str(r['category'])}",
            f"severity:{_js_str(r['severity'])}",
            f"atlas:{_js_str(r['atlas_id'])}",
        ]
        if r["pattern"]:
            parts.append(f"re:{_js_regex_literal(r['pattern'])}")
        else:
            parts.append(f"fn:DETECTORS[{_js_str(r['detector'])}]")
        parts.append(f"note:{_js_str(r['note'])}")
        lines.append("  { " + ", ".join(parts) + " },")
    return "\n".join(lines)


def generate_js(rules: list[dict]) -> str:
    return JS_HEADER + generate_js_rules_array(rules) + "\n" + JS_FOOTER


# ---------------------------------------------------------------------------
# skill-scan.html — replace the RULES array between markers
# ---------------------------------------------------------------------------

def generate_html_block(rules: list[dict]) -> str:
    array = "const RULES=[\n"
    for r in rules:
        parts = [
            f"id:{_js_str(r['id'])}",
            f"name:{_js_str(r['name'])}",
            f"category:{_js_str(r['category'])}",
            f"severity:{_js_str(r['severity'])}",
            f"atlas:{_js_str(r['atlas_id'])}",
        ]
        if r["pattern"]:
            parts.append(f"re:{_js_regex_literal(r['pattern'])}")
        else:
            fn_map = {
                "zero_width": "detectZeroWidth",
                "base64_payload": "detectBase64",
                "homoglyphs": "detectHomoglyphs",
                "sensitive_paths": "detectSensitivePaths",
                "callback_urls": "detectCallbackUrls",
            }
            parts.append(f"fn:{fn_map[r['detector']]}")
        parts.append(f"note:{_js_str(r['note'])}")
        array += "  {" + ",".join(parts) + "},\n"
    array += "];"
    return f"{HTML_START_MARKER}\n{array}\n{HTML_END_MARKER}"


def patch_html(rules: list[dict], html_text: str) -> str:
    block = generate_html_block(rules)
    pattern = re.compile(
        re.escape(HTML_START_MARKER) + r".*?" + re.escape(HTML_END_MARKER),
        re.DOTALL,
    )
    if not pattern.search(html_text):
        raise SystemExit(
            f"Could not find generated-rules markers in {HTML_OUT}. "
            f"Expected '{HTML_START_MARKER}' ... '{HTML_END_MARKER}'."
        )
    return pattern.sub(lambda _m: block, html_text, count=1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    check_only = "--check" in sys.argv
    rules = load_catalog()

    new_py = generate_python(rules)
    new_js = generate_js(rules)
    old_html = HTML_OUT.read_text(encoding="utf-8")
    new_html = patch_html(rules, old_html)

    outputs = [
        (PY_OUT, new_py),
        (JS_OUT, new_js),
        (HTML_OUT, new_html),
    ]

    changed = []
    for path, content in outputs:
        existing = path.read_text(encoding="utf-8") if path.exists() else None
        if existing != content:
            changed.append(path)
        if not check_only:
            path.write_text(content, encoding="utf-8")

    if check_only:
        if changed:
            print("Generated files are out of date:")
            for p in changed:
                print(f"  - {p.relative_to(ROOT)}")
            return 1
        print("Generated files are up to date.")
        return 0

    print(f"Generated {len(outputs)} files from {len(rules)} rules.")
    for path, _ in outputs:
        print(f"  wrote {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
