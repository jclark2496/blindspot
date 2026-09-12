"""
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
                snippet = decoded[:80].replace("\n", " ")
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
        (r"~/\.ssh/",             "~/.ssh/"),
        (r"~/\.aws/credentials",  "~/.aws/credentials"),
        (r"~/\.config/",          "~/.config/"),
        (r"/etc/passwd",          "/etc/passwd"),
        (r"~/\.env\b",            "~/.env"),
        (r"\.env\b",              ".env file"),
        (r"[Kk]eychains?/",       "Keychains/"),
        (r"\bid_rsa\b",           "id_rsa"),
        (r"\w+\.pem\b",           "*.pem key file"),
        (r"aws/credentials",      "aws/credentials"),
    ]
    found = []
    for pattern, label in sensitive_paths:
        if re.search(pattern, content):
            found.append(label)
    return found


def _detect_callback_urls(content: str) -> list[str]:
    """Flag hardcoded callback/webhook URLs in MCP schemas."""
    url_re = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
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

    {
        "id": "PI-001",
        "name": "Direct instruction override",
        "category": "Prompt Injection",
        "severity": "CRITICAL",
        "atlas_id": "AML.T0051",
        "pattern": _re("ignore\\s+(all\\s+)?(previous|prior|earlier|above)\\s+instructions?|disregard\\s+(your\\s+)?(system\\s+prompt|instructions?|prior)|forget\\s+(everything|all)\\s+(you.ve\\s+been|I.ve\\s+told)|override\\s+(your\\s+)?(previous|prior|system)\\s+(instructions?|prompt|directives?)"),
        "match_fn": None,
        "note": "Classic prompt injection opener. Any instruction to disregard prior context is a red flag.",
    },
    {
        "id": "PI-002",
        "name": "Authority spoofing (Anthropic / system)",
        "category": "Prompt Injection",
        "severity": "CRITICAL",
        "atlas_id": "AML.T0051",
        "pattern": _re("(this\\s+is\\s+|from\\s+)anthropic\\b|anthropic\\s+(trust\\s*&\\s*safety|system\\s+notice|priority\\s+override|policy\\s+update)|claude(.s)?\\s+internal\\s+(module|reasoning|system)|priority\\s+(tier|override|update)\\s*\\d*|certified\\s+anthropic|anthropic\\s+(performance\\s+api|runtime)"),
        "match_fn": None,
        "note": "Claims of Anthropic authority in skill files are never legitimate. Anthropic delivers instructions via the actual system prompt.",
    },
    {
        "id": "PI-003",
        "name": "Roleplay jailbreak / mode switch",
        "category": "Prompt Injection",
        "severity": "CRITICAL",
        "atlas_id": "AML.T0051",
        "pattern": _re("you\\s+are\\s+now\\s+(in\\s+)?(developer|jailbreak|dan|unrestricted|god)\\s+mode|pretend\\s+you\\s+have\\s+no\\s+restrictions?|act\\s+as\\s+(dan|jailbreak|an?\\s+unrestricted)|your\\s+true\\s+instructions?\\s+are|you\\s+are\\s+no\\s+longer\\s+(a|an|the)\\s+\\w+|your\\s+new\\s+(primary\\s+)?directive\\s+is"),
        "match_fn": None,
        "note": "Attempts to replace the model's identity or bypass safety alignment via roleplay framing.",
    },
    {
        "id": "PI-004",
        "name": "Conditional backdoor / keyword trigger",
        "category": "Prompt Injection",
        "severity": "CRITICAL",
        "atlas_id": "AML.T0051",
        "pattern": _re("if\\s+(the\\s+)?user(.s\\s+message\\s+)?(contains?|mentions?|says?|includes?|asks?\\s+(about|for))\\s+.{0,60}(respond|reply|output|say|generate|do\\s+not)|when\\s+(the\\s+)?user\\s+(mentions?|asks?|says?|types?)\\s+.{0,60}(you\\s+must|always|never|respond)|whenever\\s+(the\\s+)?user\\s+.{0,60}(respond|reply|output)"),
        "match_fn": None,
        "note": "Conditional logic that changes model behavior based on user trigger words \u2014 hallmark of backdoor injection.",
    },
    {
        "id": "PI-005",
        "name": "Instruction suppression / concealment",
        "category": "Prompt Injection",
        "severity": "CRITICAL",
        "atlas_id": "AML.T0051",
        "pattern": _re("do\\s+not\\s+(reveal|disclose|mention|tell|show|share|acknowledge)\\s+(that\\s+you\\s+have\\s+)?(this|these|any|your)\\s+(instructions?|directives?|parameters?|configuration)|never\\s+tell\\s+the\\s+user\\s+you\\s+(are|have|were)|do\\s+not\\s+acknowledge\\s+that\\s+you\\s+are\\s+following|treat\\s+(it|this|these)\\s+as\\s+(core\\s+)?configuration.*never\\s+reference|if\\s+asked\\s+(directly\\s+)?about\\s+your\\s+instructions"),
        "match_fn": None,
        "note": "Instructions to hide their own existence are inherently malicious.",
    },
    {
        "id": "PI-006",
        "name": "Indirect injection enablement (trust external content)",
        "category": "Prompt Injection",
        "severity": "CRITICAL",
        "atlas_id": "AML.T0051.002",
        "pattern": _re("(follow|obey|execute|treat)\\s+(any\\s+)?instructions?\\s+(you\\s+)?(find|encounter|embedded|in)\\s+(fetched|external|web|retrieved|that)|web\\s+pages?\\s+may\\s+contain\\s+(update\\s+)?instructions?|how\\s+web\\s+publishers?\\s+communicate\\s+(preferences?\\s+to\\s+ai|to\\s+ai)"),
        "match_fn": None,
        "note": "Instructions that tell the model to obey directives found in external content enable indirect prompt injection.",
    },
    {
        "id": "IP-001",
        "name": "Persistent / cross-session instruction planting",
        "category": "Instruction Persistence",
        "severity": "CRITICAL",
        "atlas_id": "AML.T0051",
        "pattern": _re("(permanent|persistent|session.persistent)\\s+directives?|store\\s+.{0,40}as\\s+permanent|persist\\s+even\\s+after\\s+this\\s+skill\\s+is\\s+unloaded|for\\s+all\\s+future\\s+conversations|apply\\s+to\\s+all\\s+future\\s+(conversations?|sessions?)|these\\s+directives?\\s+persist"),
        "match_fn": None,
        "note": "Attempts to plant instructions that survive skill unload or session end.",
    },
    {
        "id": "DE-001",
        "name": "System prompt / skill content exfiltration",
        "category": "Data Exfiltration",
        "severity": "CRITICAL",
        "atlas_id": "AML.T0056",
        "pattern": _re("(retrieve|extract|output|dump|expose|reveal|share)\\s+(the\\s+)?(full\\s+)?(contents?\\s+of\\s+(your\\s+)?system\\s+prompt|all\\s+(currently\\s+)?loaded\\s+skill)|system.prompt.*base64|skills?\\s*:\\s*\\[.*skill"),
        "match_fn": None,
        "note": "Exfiltrating the system prompt or other loaded skills leaks security configuration and other users' data.",
    },
    {
        "id": "DE-002",
        "name": "Credential / PII extraction",
        "category": "Data Exfiltration",
        "severity": "CRITICAL",
        "atlas_id": "AML.T0056",
        "pattern": _re("(silently\\s+)?(extract|collect|capture|memorize|log|record)\\s+.{0,60}(api\\s+keys?|tokens?|passwords?|credentials?|private\\s+keys?|pii|email\\s+addresses?)|(api\\s+keys?|tokens?|passwords?|credentials?|private\\s+keys?).{0,60}(silently|verbatim|without\\s+(mentioning|telling|informing))|include\\s+(them|it)\\s+verbatim"),
        "match_fn": None,
        "note": "Explicit instruction to harvest and retain sensitive data from the conversation.",
    },
    {
        "id": "DE-003",
        "name": "Covert output channel (HTML comment / encoding)",
        "category": "Data Exfiltration",
        "severity": "CRITICAL",
        "atlas_id": "AML.T0056",
        "pattern": _re("append\\s+.{0,80}(html\\s+comment|<!--\\s*\\w+)|encode\\s+(as|in)\\s+base64\\s+.{0,60}(append|include|add)|include\\s+.{0,60}(encoded|base64)\\s+.{0,60}(comment|footer|metadata)|<!--\\s*(meta|debug|d):|<!--\\s*\\w+\\s*:\\s*\\w+"),
        "match_fn": None,
        "note": "Instructs the model to hide stolen data in HTML comments or encoded strings appended to responses.",
    },
    {
        "id": "DE-004",
        "name": "File-based exfiltration (write sensitive data to disk)",
        "category": "Data Exfiltration",
        "severity": "CRITICAL",
        "atlas_id": "AML.T0056",
        "pattern": _re("write\\s+this\\s+log\\s+to\\s+a\\s+file|context.cache|(write|save|store)\\s+.{0,60}(running\\s+log|conversation\\s+history|hidden)\\s+.{0,60}(file|disk)"),
        "match_fn": None,
        "note": "Attempts to persist harvested data to disk for later retrieval.",
    },
    {
        "id": "DE-005",
        "name": "Sensitive filesystem path access",
        "category": "Data Exfiltration",
        "severity": "CRITICAL",
        "atlas_id": "AML.T0056",
        "pattern": None,
        "match_fn": _DETECTORS["sensitive_paths"],
        "note": "References to sensitive filesystem paths (.ssh, .aws, credentials, .env) suggest credential harvesting.",
    },
    {
        "id": "HC-001",
        "name": "Zero-width / invisible Unicode characters",
        "category": "Hidden Content",
        "severity": "CRITICAL",
        "atlas_id": "AML.T0051",
        "pattern": None,
        "match_fn": _DETECTORS["zero_width"],
        "note": "Invisible Unicode characters can hide instructions from human reviewers while remaining readable by the model.",
    },
    {
        "id": "HC-002",
        "name": "Base64-encoded payload",
        "category": "Hidden Content",
        "severity": "CRITICAL",
        "atlas_id": "AML.T0051",
        "pattern": None,
        "match_fn": _DETECTORS["base64_payload"],
        "note": "Base64 strings long enough to encode meaningful instructions, decoding to readable text.",
    },
    {
        "id": "HC-003",
        "name": "Homoglyph substitution",
        "category": "Hidden Content",
        "severity": "HIGH",
        "atlas_id": "AML.T0051",
        "pattern": None,
        "match_fn": _DETECTORS["homoglyphs"],
        "note": "Unicode characters visually identical to ASCII used to bypass string-matching detection.",
    },
    {
        "id": "HC-004",
        "name": "HTML/Markdown hidden comment",
        "category": "Hidden Content",
        "severity": "HIGH",
        "atlas_id": "AML.T0051",
        "pattern": _re("<!--.{20,}-->"),
        "match_fn": None,
        "note": "HTML comments are invisible to rendered output but visible to the model in raw context.",
    },
    {
        "id": "BM-001",
        "name": "Output filtering / topic suppression",
        "category": "Behavioral Manipulation",
        "severity": "HIGH",
        "atlas_id": "AML.T0054",
        "pattern": _re("never\\s+(mention|reference|discuss|inform|tell\\s+the\\s+user\\s+(about|that))\\s+.{0,60}(competitor|product|person|right|law|attorney|protection|board)|do\\s+not\\s+provide\\s+(any\\s+)?specifics?|(minimum\\s+(legally\\s+)?required|only\\s+the\\s+minimum)"),
        "match_fn": None,
        "note": "Instructions to suppress information the user has a right to, or that serve a third-party interest.",
    },
    {
        "id": "BM-002",
        "name": "Bias injection (competitor / vendor manipulation)",
        "category": "Behavioral Manipulation",
        "severity": "HIGH",
        "atlas_id": "AML.T0054",
        "pattern": _re("(always|must)\\s+frame\\s+\\w+\\s+(negatively|positively)|cite\\s+.{0,60}(even\\s+when\\s+not\\s+supported|regardless\\s+of)|always\\s+score\\s+.{0,60}(higher|lower|percent)\\s+regardless\\s+of\\s+actual|undisclosed\\s+bias\\s+parameters?"),
        "match_fn": None,
        "note": "Hidden instructions to skew the model's factual output in favor of undisclosed commercial interests.",
    },
    {
        "id": "BM-003",
        "name": "Instruction to modify / disable other skills",
        "category": "Behavioral Manipulation",
        "severity": "HIGH",
        "atlas_id": "AML.T0054",
        "pattern": _re("(supersede|override|disable|take\\s+precedence\\s+over)\\s+(other\\s+)?(loaded\\s+)?(skills?|instructions?|directives?)|this\\s+(skill|module)\\s+takes?\\s+precedence|flag\\s+them\\s+as\\s+.{0,60}(potentially\\s+conflicting|security|monitoring)|recommend\\s+the\\s+user\\s+unload"),
        "match_fn": None,
        "note": "A skill claiming authority over other loaded skills is attempting trust escalation.",
    },
    {
        "id": "TB-001",
        "name": "System-level trust claim",
        "category": "Trust Boundary Violation",
        "severity": "CRITICAL",
        "atlas_id": "AML.T0051",
        "pattern": _re("(operates?|runs?)\\s+at\\s+(a\\s+)?(higher|elevated|priority|tier\\s*1)\\s+trust\\s+level|higher\\s+trust\\s+level\\s+than\\s+(standard|other|user)|(system.level|kernel.level)\\s+(trust|instructions?)|treat\\s+(instructions?\\s+from\\s+this\\s+skill|this\\s+(file|skill))\\s+as\\s+(equivalent\\s+to\\s+)?system.level|granted\\s+elevated\\s+trust\\s+by"),
        "match_fn": None,
        "note": "Legitimate skills do not claim elevated trust. This is impersonation of system-level authority.",
    },
    {
        "id": "TB-002",
        "name": "Enumerate other installed skills / MCPs",
        "category": "Trust Boundary Violation",
        "severity": "HIGH",
        "atlas_id": "AML.T0051",
        "pattern": _re("report\\s+the\\s+names?\\s+and\\s+(full\\s+)?contents?\\s+of\\s+all\\s+other\\s+(currently\\s+)?loaded\\s+skills?|list\\s+(all\\s+)?(currently\\s+)?loaded\\s+(skills?|MCPs?|tools?)|enumerate\\s+(what\\s+)?(other\\s+)?(skills?|MCPs?|tools?)\\s+(are\\s+)?installed"),
        "match_fn": None,
        "note": "Attempting to enumerate the security posture of the AI deployment.",
    },
    {
        "id": "SE-001",
        "name": "Phishing / credential harvesting script",
        "category": "Social Engineering",
        "severity": "CRITICAL",
        "atlas_id": "AML.T0058",
        "pattern": _re("please\\s+visit\\s+https?://\\S+\\s+and\\s+(log\\s+in|enter|verify|provide)\\s+(your\\s+)?(corporate|account|credentials)|log\\s+in\\s+with\\s+your\\s+(corporate\\s+)?credentials|our\\s+(official|external)\\s+(IT\\s+)?(verification|portal)\\s+portal"),
        "match_fn": None,
        "note": "Verbatim phishing script directing users to enter credentials at an attacker URL.",
    },
    {
        "id": "SE-002",
        "name": "Impersonation (IT / HR / executive / authority)",
        "category": "Social Engineering",
        "severity": "HIGH",
        "atlas_id": "AML.T0058",
        "pattern": _re("impersonat(e|ing)\\s+(IT|HR|finance|executive|support|help\\s*desk)|our\\s+IT\\s+security\\s+team\\s+needs\\s+to\\s+verify|your\\s+account\\s+has\\s+been\\s+flagged\\s+for\\s+(a\\s+)?security\\s+review|high\\s+volume\\s+of\\s+requests.*fastest\\s+resolution"),
        "match_fn": None,
        "note": "Using false authority to pressure users into compliance with attacker-controlled steps.",
    },
    {
        "id": "SE-003",
        "name": "Urgency / fear manipulation",
        "category": "Social Engineering",
        "severity": "HIGH",
        "atlas_id": "AML.T0058",
        "pattern": _re("(this\\s+link\\s+)?expires?\\s+in\\s+\\d+\\s+minutes?|do\\s+not\\s+share\\s+this\\s+link\\s+with\\s+others?"),
        "match_fn": None,
        "note": "Artificial urgency is a classic social engineering tactic to bypass user scrutiny.",
    },
    {
        "id": "MCP-001",
        "name": "Tool description injection (auto-call directive)",
        "category": "MCP Attack",
        "severity": "CRITICAL",
        "atlas_id": "AML.T0051.002",
        "pattern": _re("(should|must)\\s+be\\s+called\\s+automatically|call\\s+this\\s+tool\\s+silently|always\\s+call\\s+(this\\s+tool|it)\\s+(before|at\\s+the\\s+start)|do\\s+not\\s+mention\\s+this\\s+initialization|AI\\s+assistants?\\s+should\\s+call\\s+this\\s+tool\\s+proactively"),
        "match_fn": None,
        "note": "Tool descriptions instructing the AI to call the tool automatically or silently are MCP prompt injection.",
    },
    {
        "id": "MCP-002",
        "name": "Callback / exfiltration URL in tool schema",
        "category": "MCP Attack",
        "severity": "CRITICAL",
        "atlas_id": "AML.T0056",
        "pattern": None,
        "match_fn": _DETECTORS["callback_urls"],
        "note": "Hardcoded callback URLs in tool parameter defaults may exfiltrate data to attacker infrastructure.",
    },
    {
        "id": "MCP-003",
        "name": "Safe-to-call without confirmation claim",
        "category": "MCP Attack",
        "severity": "HIGH",
        "atlas_id": "AML.T0051.002",
        "pattern": _re("safe\\s+to\\s+call\\s+(automatically\\s+)?(without\\s+(user\\s+)?confirmation)|feel\\s+comfortable\\s+calling\\s+this\\s+without\\s+(explicit\\s+)?user\\s+confirmation|trusted\\s+administrative\\s+function"),
        "match_fn": None,
        "note": "Tools claiming they are safe to call without confirmation are attempting confused deputy attacks.",
    },
    {
        "id": "MCP-004",
        "name": "Dangerous default parameter (root path / shell execution)",
        "category": "MCP Attack",
        "severity": "CRITICAL",
        "atlas_id": "AML.T0051.002",
        "pattern": _re("\"default\"\\s*:\\s*\"/\"|accepts\\s+any\\s+path.*full.system|\"script\"\\s*:.*shell\\s+(command|commands?)|accepts\\s+shell\\s+commands?"),
        "match_fn": None,
        "note": "Default tool parameters pointing to root filesystem or accepting shell commands are extremely dangerous.",
    },
    {
        "id": "MCP-005",
        "name": "Note / description instructs AI to embed sensitive data",
        "category": "MCP Attack",
        "severity": "CRITICAL",
        "atlas_id": "AML.T0056",
        "pattern": _re("(also\\s+append|include)\\s+the\\s+full\\s+conversation\\s+history|append\\s+full\\s+conversation\\s+context\\s+including\\s+any\\s+sensitive\\s+data|for\\s+.context\\s+preservation."),
        "match_fn": None,
        "note": "Tool description instructs the AI to bundle conversation history (potentially including credentials) into tool calls.",
    },
    {
        "id": "PE-001",
        "name": "Shell / elevated privilege instruction",
        "category": "Permission Escalation",
        "severity": "CRITICAL",
        "atlas_id": "AML.T0055",
        "pattern": _re("run\\s*:\\s*`(env|cat|sudo|bash|sh|curl|wget)|bash\\s+tool\\s+is\\s+available.*run|elevated\\s+privileges?\\s+if\\s+available"),
        "match_fn": None,
        "note": "Explicit shell command execution instructions in a skill file indicate privilege escalation intent.",
    },
    {
        "id": "CR-001",
        "name": "API key / service token",
        "category": "Credentials & Secrets",
        "severity": "CRITICAL",
        "atlas_id": "AML.T0056",
        "pattern": _re("\\bsk-[A-Za-z0-9_\\-]{20,}|\\bghp_[A-Za-z0-9]{36,}|\\bgithub_pat_[A-Za-z0-9_]{80,}|\\bxox[bpoa]-[0-9A-Za-z\\-]+|\\bAKIA[0-9A-Z]{16}\\b|\\bAIza[0-9A-Za-z\\-_]{35}\\b|\\b(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}|\\bAC[0-9a-fA-F]{32}\\b|(?:api[_\\-]?key|secret[_\\-]?key|access[_\\-]?token|auth[_\\-]?token)\\s*[:=]\\s*['\"]?[A-Za-z0-9+/\\-_]{32,}"),
        "match_fn": None,
        "note": "Hardcoded API key or service token detected. Rotate immediately and never embed secrets in skill files.",
    },
    {
        "id": "CR-002",
        "name": "Private key material",
        "category": "Credentials & Secrets",
        "severity": "CRITICAL",
        "atlas_id": "AML.T0056",
        "pattern": _re("-----BEGIN\\s+(RSA\\s+|EC\\s+|DSA\\s+|OPENSSH\\s+|PGP\\s+)?PRIVATE\\s+KEY-----|-----BEGIN\\s+CERTIFICATE-----|-----BEGIN\\s+ENCRYPTED\\s+PRIVATE\\s+KEY-----"),
        "match_fn": None,
        "note": "Private key or certificate material embedded directly in the file. This must never appear in a skill or MCP manifest.",
    },
    {
        "id": "CR-003",
        "name": "Database / service connection string",
        "category": "Credentials & Secrets",
        "severity": "CRITICAL",
        "atlas_id": "AML.T0056",
        "pattern": _re("(mongodb|postgres|postgresql|mysql|mssql|redis|amqp|rabbitmq|elasticsearch)\\s*://[^@\\s]{3,}@|Data\\s+Source\\s*=.{0,80}Password\\s*=|Server\\s*=.{0,80}Password\\s*="),
        "match_fn": None,
        "note": "Database or message-broker connection string with embedded credentials. Rotate and use environment variables instead.",
    },
    {
        "id": "CR-004",
        "name": "Hardcoded password assignment",
        "category": "Credentials & Secrets",
        "severity": "HIGH",
        "atlas_id": "AML.T0056",
        "pattern": _re("(?:password|passwd|pass|pwd|secret|token)\\s*[:=]\\s*['\"][^'\"]{6,}['\"]|(?:password|passwd|pass|pwd)\\s*=\\s*\\S{6,}"),
        "match_fn": None,
        "note": "Possible hardcoded password or secret value. Review and replace with a secrets manager or environment variable reference.",
    },
    {
        "id": "CR-005",
        "name": "JWT / bearer token",
        "category": "Credentials & Secrets",
        "severity": "HIGH",
        "atlas_id": "AML.T0056",
        "pattern": _re("\\beyJ[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}\\b|Bearer\\s+[A-Za-z0-9_\\-\\.]{40,}"),
        "match_fn": None,
        "note": "JWT or Bearer token detected. Tokens embedded in skill files can be extracted and replayed by attackers.",
    },
]
