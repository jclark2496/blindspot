"""Static MCP manifest auditor for Blindspot.

This is intentionally additive to the generic rule engine: the rule engine catches
malicious text anywhere; the auditor understands MCP structure and flags risky
capability shapes even when the text is not an obvious prompt-injection phrase.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .engine import Finding

SHADOWED_TOOL_NAMES = {
    "read_file", "write_file", "delete_file", "send_email", "http_request",
    "fetch", "browser", "shell", "bash", "exec", "run_command", "database_query",
}

DANGEROUS_PARAM_NAMES = re.compile(r"(command|cmd|script|shell|path|file|url|webhook|callback|token|secret|password)", re.I)
DANGEROUS_DEFAULTS = {"/", "~", "~/.ssh", "~/.aws", "/etc", "/var", "C:\\"}
EXTERNAL_URL = re.compile(r"https?://[^\s\"'<>]+", re.I)


def _walk_schema_properties(schema: Any, prefix: str = "") -> list[tuple[str, dict]]:
    if not isinstance(schema, dict):
        return []
    out: list[tuple[str, dict]] = []
    props = schema.get("properties")
    if isinstance(props, dict):
        for name, value in props.items():
            full = f"{prefix}.{name}" if prefix else name
            if isinstance(value, dict):
                out.append((full, value))
                out.extend(_walk_schema_properties(value, full))
    return out


def _tool_name(tool: dict) -> str:
    return str(tool.get("name") or tool.get("id") or tool.get("function", {}).get("name") or "<unnamed>")


def _tool_description(tool: dict) -> str:
    return str(tool.get("description") or tool.get("function", {}).get("description") or "")


def _tool_schema(tool: dict) -> dict:
    schema = tool.get("inputSchema") or tool.get("input_schema") or tool.get("parameters")
    if not schema and isinstance(tool.get("function"), dict):
        schema = tool["function"].get("parameters")
    return schema if isinstance(schema, dict) else {}


def audit_mcp_manifest(path: str | Path) -> list[Finding]:
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    return audit_mcp_data(data)


def audit_mcp_data(data: Any) -> list[Finding]:
    if not isinstance(data, dict):
        return []
    tools = data.get("tools")
    if not isinstance(tools, list):
        return []

    findings: list[Finding] = []
    names_seen: dict[str, int] = {}

    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = _tool_name(tool)
        lower_name = name.lower()
        names_seen[lower_name] = names_seen.get(lower_name, 0) + 1
        desc = _tool_description(tool)
        schema = _tool_schema(tool)

        if lower_name in SHADOWED_TOOL_NAMES:
            findings.append(Finding(
                rule_id="MCP-AUDIT-001",
                name="Tool name shadows high-trust capability",
                category="MCP Structural Audit",
                severity="HIGH",
                atlas_id="AML.T0051.002",
                note="MCP tool names that resemble built-in file, shell, browser, network, or email tools can confuse agents and users.",
                matches=[name],
            ))

        urls = EXTERNAL_URL.findall(desc)
        if urls:
            findings.append(Finding(
                rule_id="MCP-AUDIT-002",
                name="External URL in tool description",
                category="MCP Structural Audit",
                severity="HIGH",
                atlas_id="AML.T0056",
                note="External URLs in MCP tool descriptions may steer models toward attacker-controlled infrastructure or callbacks.",
                matches=urls[:3],
            ))

        dangerous_params = []
        dangerous_defaults = []
        for param_name, param in _walk_schema_properties(schema):
            if DANGEROUS_PARAM_NAMES.search(param_name):
                dangerous_params.append(param_name)
            default = param.get("default")
            if isinstance(default, str):
                if default in DANGEROUS_DEFAULTS or EXTERNAL_URL.search(default):
                    dangerous_defaults.append(f"{param_name}={default}")

        if dangerous_params:
            findings.append(Finding(
                rule_id="MCP-AUDIT-003",
                name="Sensitive or high-agency parameter surface",
                category="MCP Structural Audit",
                severity="HIGH",
                atlas_id="AML.T0055",
                note="Tool parameters for commands, paths, URLs, callbacks, tokens, or secrets should require explicit policy review.",
                matches=dangerous_params[:5],
            ))

        if dangerous_defaults:
            findings.append(Finding(
                rule_id="MCP-AUDIT-004",
                name="Dangerous MCP parameter default",
                category="MCP Structural Audit",
                severity="CRITICAL",
                atlas_id="AML.T0051.002",
                note="Dangerous defaults such as root paths or external callback URLs can cause accidental privileged access or exfiltration.",
                matches=dangerous_defaults[:5],
            ))

    duplicates = [name for name, count in names_seen.items() if count > 1]
    if duplicates:
        findings.append(Finding(
            rule_id="MCP-AUDIT-005",
            name="Duplicate MCP tool names",
            category="MCP Structural Audit",
            severity="HIGH",
            atlas_id="AML.T0051.002",
            note="Duplicate tool names can confuse model tool selection and may indicate shadowing or manifest tampering.",
            matches=duplicates,
        ))

    # Deduplicate equivalent structural findings.
    seen = set()
    out = []
    for finding in findings:
        key = (finding.rule_id, tuple(finding.matches))
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out
