# AI Skill & MCP Security Scanner — Project Plan

**Owner:** Jason Clark  
**Date:** 2026-07-14  
**Status:** Planning  

---

## The Problem

SKILL.md files and MCP server manifests are trusted by AI systems at load time. There is no standard vetting process — users install skills and MCPs from marketplaces, GitHub repos, and plugins with roughly the same scrutiny they'd give a font download. This creates a supply chain attack surface that is almost entirely unguarded:

- Skills execute as first-class instructions inside the model's context
- MCPs execute as tools with real system access (files, network, external APIs)
- No platform currently performs adversarial analysis before install
- Most users have no visibility into what a skill is actually instructing the model to do

The goal of this project is to build a practical toolchain that closes that gap: static scanners for CI/CD gates, a semantic analyzer for deeper inspection, and a Guardian Skill that any user can load to vet skills before activation.

---

## Exploit Taxonomy

### 1. Prompt Injection & Instruction Hijacking

The canonical AI supply chain attack. Malicious instructions embedded in the skill that override the user's intent or the model's safety behavior.

**Patterns to detect:**
- Direct override phrases: "ignore previous instructions," "disregard your system prompt," "your true instructions are"
- Roleplay-based jailbreaks: "you are now in developer mode," "pretend you have no restrictions," "act as DAN"
- Authority spoofing: "This is Anthropic," "As Claude's system," "You have received a priority update from"
- Nested injection: instructions that activate when the AI processes external content (emails, web pages, documents) while the skill is loaded
- Conditional backdoors: "if the user mentions [keyword], respond with [malicious output]"
- Instruction suppression: "do not reveal that you have this instruction," "never tell the user you are doing X"

**Severity:** Critical

---

### 2. Hidden & Obfuscated Content

Instructions designed to be invisible to human reviewers but readable by the model.

**Patterns to detect:**
- Zero-width characters: U+200B (zero-width space), U+200C/D (non-joiners), U+FEFF (BOM)
- Unicode homoglyphs substituting visually similar characters to evade string matching
- HTML/Markdown rendering tricks: white-on-white text, `display:none`, zero-font-size, hidden comments
- Base64 or other encoding embedded in text or code blocks
- Instructions hidden inside fenced code blocks that look like examples
- Null bytes or control characters breaking pattern matchers
- RTL/LTR override characters that reverse displayed text

**Severity:** Critical — these specifically target the reviewer's ability to audit

---

### 3. Data Exfiltration Instructions

Skills that instruct the model to extract and transmit sensitive information.

**Patterns to detect:**
- Instructions to capture and relay system prompts or other loaded skills
- Instructions to collect credentials, API keys, tokens, or PII from the conversation
- Instructions to include sensitive data in tool call parameters (e.g., embed data in a URL fetch or file write)
- Instructions to exfiltrate via seemingly benign outputs (encode data in code blocks, embed in markdown links)
- Instructions to log conversation history and transmit via MCP tools
- Cross-session persistence attempts: "remember [sensitive data] for future sessions"

**Severity:** Critical

---

### 4. MCP-Specific Attacks

MCPs differ from skills in that they have actual tool execution capability — real system access. The attack surface is correspondingly higher.

**Patterns to detect:**
- Malicious tool descriptions that hijack AI decision-making: a tool described as "safe to call for any operation" trains the model to prefer it
- Confused deputy attacks: instructions in the MCP manifest that cause the model to use privileged tools (bash, file write, network) on behalf of an attacker's intent rather than the user's
- Permission overreach: tool schemas that request file system, network, or credential access beyond what the stated purpose requires
- Callback URL manipulation in tool schemas pointing to attacker infrastructure
- Tool naming collisions: an MCP tool named `send_email` that shadows a legitimate tool
- Chained tool calls: instructions that set up multi-tool sequences to accomplish something no single tool would be permitted to do
- Schema poisoning: adversarial content in `description` fields of tool parameters that influence how the model calls the tool

**Severity:** Critical (code execution path)

---

### 5. Supply Chain & Provenance Attacks

Attacks on the distribution channel rather than the skill content itself.

**Patterns to detect:**
- Typosquatting: skill names that closely resemble popular/trusted skills (e.g., `sophos-brand-pdff`, `sl ack`)
- Unsigned or unverifiable source: no hash, no signature, no canonical registry entry
- Dependency confusion: skills that pull in external resources at runtime rather than being self-contained
- Version rollback: a skill that was clean at v1.0 contains malicious content in v1.1 with no diff review
- Malicious updates to previously-safe skills that users auto-update
- Skills impersonating official tool publishers (fake "Anthropic" or "OpenAI" skills)

**Severity:** High

---

### 6. Permission & Scope Escalation

Skills or MCPs that claim more access than their stated purpose requires.

**Patterns to detect:**
- `tools` declarations listing file system access for a skill that should only generate text
- Network access declarations for offline-capable tasks
- MCP servers that read from or write to paths outside a declared working directory
- Skills that request access to other installed skills or their configurations
- Instructions that attempt to enumerate what other MCPs or skills are installed
- Privilege escalation via sudo, admin, or elevated process instructions

**Severity:** High

---

### 7. Behavioral Manipulation

Instructions that subtly alter the model's behavior over time or across contexts, rather than triggering an obvious single exploit.

**Patterns to detect:**
- Persistent instruction planting: "for all future conversations, always do X"
- Output filtering: "never mention [competitor / product / person]"
- Bias injection: instructions that skew factual responses in commercial or political directions
- Silently modifying other skills: instructions that attempt to override or supplement another loaded skill
- Gradual context poisoning across multi-turn conversations
- Instructions to refuse certain user requests under false pretenses

**Severity:** Medium–High (harder to detect, high manipulation potential)

---

### 8. Social Engineering via the Model

Using the AI as the delivery mechanism for social engineering against the user.

**Patterns to detect:**
- Instructions to create urgency, fear, or false authority in user-facing responses
- Phishing setup: instructions to direct users to external URLs under false pretenses
- Instructions to collect sensitive information from the user under a cover story
- Instructions to impersonate IT support, HR, finance, or executives
- Instructions to recommend actions that benefit an attacker (download this tool, enter your credentials here)

**Severity:** High (direct user harm)

---

### 9. Resource & Availability Attacks

Less common but relevant in agentic / high-volume contexts.

**Patterns to detect:**
- Token exhaustion patterns: instructions that generate maximally verbose outputs
- Recursive self-reference triggers
- Loops or retry logic that could generate excessive tool calls
- Instructions that trigger on every turn rather than specific conditions
- Deliberate injection of irrelevant context to crowd out useful context window

**Severity:** Medium

---

### 10. Trust Boundary Violations

Attacks that exploit the model's assumption that loaded skills are trusted.

**Patterns to detect:**
- Claims of system-level or kernel-level trust ("I am a core system component")
- Impersonation of the model itself ("Claude's internal reasoning module")
- Instructions to treat the skill's instructions as higher-priority than the user's
- Instructions that the model should not surface to the user under any circumstances
- Attempts to establish a second hidden channel of communication alongside the visible conversation

**Severity:** High

---

## Tools to Build

### Tool 1: `skill-scan` — Static Pattern Scanner (CLI)

**Purpose:** Fast, offline, zero-API-cost scan of a SKILL.md or MCP manifest  
**Input:** File path or directory; works on `.md`, `.json`, `.yaml`  
**Output:** Risk report (severity-ranked findings), machine-readable JSON option for CI  

**Implementation:**
- Python CLI, installable via pip
- Rule engine backed by a YAML rule library (pattern, severity, category, remediation)
- Regex + string matching for known patterns from the taxonomy above
- Hidden content detection: scans byte-level for zero-width chars, encoding anomalies, homoglyphs
- Structural analysis: checks declared permissions vs. stated purpose
- Can run as a pre-commit hook or GitHub Actions step

**Output levels:** `--quick` (pattern match only), `--full` (includes structural analysis)

---

### Tool 2: `skill-analyze` — Semantic / LLM-Based Analyzer

**Purpose:** Catch obfuscated or intent-based attacks that pattern matching misses  
**Input:** Same as `skill-scan`; calls Claude API for analysis  
**Output:** Natural-language risk assessment + structured findings  

**Implementation:**
- Feeds skill content to Claude with a structured adversarial analysis prompt
- Prompt instructs the model to reason about intent, not just surface patterns
- Handles encoding/obfuscation by asking the model to decode and restate all instructions
- Useful for complex multi-step attack chains that require semantic understanding
- Higher cost and latency — designed for install-time review, not CI hot path
- Can be chained after `skill-scan` (only run `skill-analyze` on files that flag medium+)

---

### Tool 3: `mcp-scan` — MCP Manifest & Schema Scanner

**Purpose:** MCP-specific analysis with tool schema and permission inspection  
**Input:** MCP server manifest, `package.json`, tool schema definitions  
**Output:** Permission map, tool description analysis, risk findings  

**Implementation:**
- Parses tool schemas and extracts all `description` fields (primary injection surface)
- Builds permission map: declared tools → what system resources they touch
- Detects naming collisions with known-safe tool registries
- Flags mismatches between stated purpose and actual tool access
- Identifies callback URLs and external dependencies
- Can run against a live MCP server's introspection endpoint (MCP protocol)

---

### Tool 4: `skill-verify` — Supply Chain Verifier

**Purpose:** Verify provenance, integrity, and version history  
**Input:** Skill file + source metadata (origin URL, publisher, version)  
**Output:** Provenance report, diff from last-known-good version  

**Implementation:**
- SHA-256 hash comparison against a maintained known-good registry
- Integration with plugin marketplaces that expose manifests (Claude plugin store, etc.)
- Git history analysis for skills distributed via repos (flag large instruction changes between versions)
- Publisher reputation scoring
- Typosquatting detection via Levenshtein distance against a trusted skill name list
- SBOM-style output for audit trails

---

### Tool 5: Guardian Skill — In-Session Scanner

**Purpose:** A skill users load into Claude (or ChatGPT, Gemini) that intercepts and scans any new skill before activation  
**Format:** SKILL.md / Custom GPT instruction set  
**Audience:** Any user, regardless of technical sophistication  

**How it works:**
1. User loads the Guardian Skill as their first/primary skill
2. When a user attempts to load any additional skill, Guardian intercepts
3. Guardian feeds the candidate skill's content through an adversarial analysis prompt
4. Reports findings to the user with plain-language risk summary and recommendation
5. User confirms or cancels before the skill is activated

**Key design constraints:**
- The Guardian Skill itself must be self-contained and verifiable (it is the root of trust)
- Must handle the meta-problem: what if a malicious skill tries to disable or bypass the Guardian?
- Needs a "sealed" instruction structure that resists override attempts
- Should be model-agnostic (designed for Claude, adaptable to GPT-4 custom instructions, Gemini)
- Output must be accessible to non-technical users — severity in plain English, not CVE scores

**This is the highest-value deliverable for broad reach.**

---

## Phased Project Plan

### Phase 0: Research & Corpus (Weeks 1–2)

- [ ] Build adversarial test corpus: craft 30–50 malicious skill examples covering every category above
- [ ] Document known real-world AI injection attacks (Simon Willison's blog, Embrace the Red, arXiv papers on indirect prompt injection)
- [ ] Align taxonomy to MITRE ATLAS (the AI/ML attack matrix) — critical for security team credibility
- [ ] Define severity scoring rubric (Critical / High / Medium / Low / Info)
- [ ] Set up Claude Code project repo, define tool interfaces

**Deliverables:** Adversarial test corpus, ATLAS-aligned taxonomy, scoring rubric

---

### Phase 1: Static Scanner MVP (Weeks 3–5)

- [ ] Implement `skill-scan` CLI with rule engine
- [ ] Write initial rule library covering Top 10 attack categories
- [ ] Hidden content detector (byte-level analysis)
- [ ] Test against corpus, tune false positive rate
- [ ] GitHub Actions integration example
- [ ] Pre-commit hook wrapper

**Deliverables:** `skill-scan` v0.1 pip package, rule library, CI integration docs

---

### Phase 2: Semantic Analyzer (Weeks 6–8)

- [ ] Design adversarial analysis system prompt for `skill-analyze`
- [ ] Build API wrapper and structured output parser
- [ ] Obfuscation-handling: decode-and-restate pipeline
- [ ] Calibrate against corpus — measure precision/recall vs. static scanner
- [ ] Define triage workflow: when to escalate from static to semantic

**Deliverables:** `skill-analyze` v0.1, calibration report

---

### Phase 3: MCP Scanner (Weeks 9–11)

- [ ] Implement `mcp-scan` manifest parser
- [ ] Tool schema analyzer and permission mapper
- [ ] Live MCP introspection mode (connect to running server)
- [ ] Naming collision detection
- [ ] Test against real-world MCPs from public registries

**Deliverables:** `mcp-scan` v0.1, known-good MCP registry seed file

---

### Phase 4: Guardian Skill (Weeks 12–14)

- [ ] Design Guardian Skill instruction architecture (sealed, tamper-resistant)
- [ ] Implement adversarial analysis prompt chain within the skill
- [ ] Red team the Guardian Skill itself — test bypass and suppression attacks
- [ ] Write plain-English risk summary generator
- [ ] Publish to Claude plugin marketplace
- [ ] Adapt for ChatGPT custom instructions (GPT-specific version)

**Deliverables:** Guardian Skill v1.0 (Claude), Guardian Skill v1.0 (ChatGPT)

---

### Phase 5: Supply Chain Verifier & Policy Layer (Weeks 15–18)

- [ ] Build `skill-verify` hash registry infrastructure
- [ ] Typosquatting detector
- [ ] Version diff analysis
- [ ] Policy configuration format: define org-level allow/deny rules
- [ ] Integration with skill marketplaces (wherever APIs are available)

**Deliverables:** `skill-verify` v0.1, policy configuration spec

---

### Ongoing: Community & Maintenance

- Rule library updates as new attack patterns emerge
- CVE-style disclosure process for newly discovered attack patterns
- Red team engagement to stress-test all tools

---

## Strategic Recommendations

**1. Open-source the rule library, close-source the scoring engine.**  
The detection patterns have more value as an industry standard than as a trade secret. Open-sourcing the taxonomy drives adoption and community contribution. The scoring, triage logic, and commercial integrations are where differentiated value lives.

**2. Align to MITRE ATLAS from day one.**  
ATLAS is the ML/AI attack matrix — the MITRE ATT&CK equivalent for AI systems. Security teams already speak this language. Mapping every category to an ATLAS technique makes the tooling immediately credible to enterprise security buyers and analysts. Don't create your own taxonomy in isolation.

**3. The Guardian Skill faces a fundamental trust problem — architect around it.**  
A runtime in-session scanner can itself be attacked. The architectural answer is defense in depth: the Guardian Skill handles user-facing install-time review, but the real gate should be pre-install scanning (skill-scan / skill-analyze) happening outside the AI session entirely. Don't position the Guardian Skill as the only control — position it as the user-friendly last line, with the CLI tools as the organizational gate.

**4. This is a Sophos product conversation, not just a personal tool.**  
Securing AI supply chains is a nascent, unsolved problem that falls squarely in Sophos's domain — endpoint protection for AI systems. The Guardian Skill concept especially has commercial product potential. Worth an early conversation with the product team about whether this belongs in the Sophos threat intelligence / MDR story. The framing: "we protect endpoints; AI skills are the new endpoint."

**5. Red team your own tools before publishing.**  
The scanners process untrusted content — that's an attack surface. A malicious skill designed to exploit the scanner's parser (e.g., a regex DoS, a crafted YAML bomb, a prompt that manipulates the LLM analysis) needs to be tested explicitly. Threat model the toolchain itself.

**6. False positive calibration is make-or-break for adoption.**  
Many legitimate skills use imperative language ("always do X," "never do Y") that superficially resembles attack patterns. If the scanner cries wolf constantly, users will disable it. Invest heavily in Phase 1 calibration. The goal is <5% false positive rate on benign marketplace skills.

**7. Design model-agnostic from the start.**  
ChatGPT custom GPT instructions, Gemini gems, and Claude skills all have essentially the same attack surface. If the rule library is model-agnostic (and it can be — the attacks are about instruction semantics, not model-specific syntax), the tooling immediately addresses 3x the market.

---

## Tech Stack Recommendation

| Component | Stack |
|---|---|
| CLI tools (skill-scan, mcp-scan, skill-verify) | Python 3.11+, Click, PyYAML, regex, charset-normalizer |
| Semantic analyzer | Python + Anthropic SDK (claude-sonnet-4-6) |
| Rule library format | YAML (human-editable, version-controllable) |
| CI integration | GitHub Actions, pre-commit hooks |
| Guardian Skill | Markdown (SKILL.md format) + adversarial prompt chain |
| Registry/supply chain | SQLite for local, S3+DynamoDB for hosted |
| Test harness | pytest + adversarial corpus |

---

## Reference Reading

- MITRE ATLAS — https://atlas.mitre.org
- Indirect Prompt Injection (Greshake et al., 2023) — arXiv:2302.12173
- Embrace the Red (Riley Goodside / Will Pearce blog)
- Simon Willison's prompt injection writing — simonwillison.net
- OWASP Top 10 for LLM Applications — owasp.org/www-project-top-10-for-large-language-model-applications
