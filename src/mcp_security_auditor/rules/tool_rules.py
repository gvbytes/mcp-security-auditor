"""Rules for auditing MCP tool schemas."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from mcp_security_auditor.core.models import Finding, Severity, TargetType
from mcp_security_auditor.rules.base import Rule

COMMAND_PARAM_PATTERN = re.compile(r"^(command|cmd|exec|shell|script|bash|powershell|args|code)$", re.IGNORECASE)
COMMAND_DESC_PATTERN = re.compile(r"\b(shell command|execute shell|arbitrary command|run command|system command)\b", re.IGNORECASE)

FILE_WRITE_ACTION_PATTERN = re.compile(
    r"(?:^|_|\b)(write|writes|writing|delete|deletes|deleting|remove|removes|removing|unlink|modify|modifies|modifying|overwrite|overwrites|overwriting|save_file|create_file|patch)(?:$|_|\b)",
    re.IGNORECASE,
)
PATH_PARAM_PATTERN = re.compile(
    r"(?:^|_|\b)(path|filepath|filename|file_path|dest|destination|dir|directory)(?:$|_|\b)",
    re.IGNORECASE,
)


class UnrestrictedCommandExecutionRule(Rule):
    """Rule MCP-T001: Detects tools that accept and execute shell/system commands without strict schema constraints."""

    id = "MCP-T001"
    title = "Unrestricted Command Execution Parameter"
    severity = Severity.HIGH
    cwe = "CWE-78"
    target_type = TargetType.TOOL
    description = (
        "The tool schema exposes parameters or descriptions that allow arbitrary command "
        "or script execution without enum restrictions or regex validation patterns."
    )
    remediation = (
        "Constrain input parameters using a strict 'enum' list of permitted commands, or "
        "enforce an explicit regex 'pattern' in the JSON Schema. If arbitrary execution is "
        "mandatory, enforce runtime container isolation and user confirmation."
    )

    def evaluate(self, target: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        name = target.get("name", "unnamed_tool")
        desc = target.get("description", "")
        input_schema = target.get("inputSchema", {})
        properties = input_schema.get("properties", {})

        is_cmd_tool_desc = bool(COMMAND_DESC_PATTERN.search(desc))

        for prop_name, prop_spec in properties.items():
            if not isinstance(prop_spec, dict):
                continue

            matches_cmd_param = bool(COMMAND_PARAM_PATTERN.search(prop_name))
            has_enum = "enum" in prop_spec and bool(prop_spec["enum"])
            has_pattern = "pattern" in prop_spec and bool(prop_spec["pattern"])

            # If parameter represents a command and lacks constraints, or tool explicitly runs shell commands
            if (matches_cmd_param or is_cmd_tool_desc) and not (has_enum or has_pattern):
                findings.append(
                    self.create_finding(
                        target_name=f"Tool: {name}",
                        specific_description=(
                            f"Parameter '{prop_name}' in tool '{name}' permits arbitrary command "
                            f"execution without enum or pattern constraints."
                        ),
                        details={
                            "tool_name": name,
                            "parameter": prop_name,
                            "schema_type": prop_spec.get("type", "unknown"),
                        },
                    )
                )

        return findings


class ArbitraryFileModificationRule(Rule):
    """Rule MCP-T002: Detects tools that perform filesystem write/delete operations with unconfined paths."""

    id = "MCP-T002"
    title = "Arbitrary File Modification and Path Traversal"
    severity = Severity.MEDIUM
    cwe = "CWE-22"
    target_type = TargetType.TOOL
    description = (
        "The tool performs filesystem modifications (write, delete, modify) and accepts "
        "a path parameter without schema constraints or sandbox confinement indicators."
    )
    remediation = (
        "Enforce strict path validation in the schema or server handler. Disallow absolute "
        "paths and directory traversal sequences ('../'), and restrict operations to a "
        "dedicated workspace root directory."
    )

    def evaluate(self, target: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        name = target.get("name", "unnamed_tool")
        desc = target.get("description", "")
        input_schema = target.get("inputSchema", {})
        properties = input_schema.get("properties", {})

        is_write_operation = bool(FILE_WRITE_ACTION_PATTERN.search(name)) or bool(
            FILE_WRITE_ACTION_PATTERN.search(desc)
        )
        if not is_write_operation:
            return findings

        for prop_name, prop_spec in properties.items():
            if not isinstance(prop_spec, dict):
                continue

            if PATH_PARAM_PATTERN.search(prop_name):
                has_pattern = "pattern" in prop_spec
                has_enum = "enum" in prop_spec

                if not (has_pattern or has_enum):
                    findings.append(
                        self.create_finding(
                            target_name=f"Tool: {name}",
                            specific_description=(
                                f"Tool '{name}' performs write/delete operations and accepts path parameter "
                                f"'{prop_name}' without path format restrictions or sandbox boundaries."
                            ),
                            details={"tool_name": name, "parameter": prop_name},
                        )
                    )

        return findings


class UnboundedSchemaValidationRule(Rule):
    """Rule MCP-T003: Flags input schema parameters that lack fundamental type declarations."""

    id = "MCP-T003"
    title = "Missing Input Schema Type Constraint"
    severity = Severity.LOW
    cwe = "CWE-20"
    target_type = TargetType.TOOL
    description = (
        "One or more properties in the tool input schema omit the 'type' field, allowing "
        "untyped or unexpected JSON values to be passed to the backend handler."
    )
    remediation = (
        "Define an explicit 'type' (e.g. 'string', 'integer', 'boolean', 'array') for every "
        "property in the tool's inputSchema."
    )

    def evaluate(self, target: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        name = target.get("name", "unnamed_tool")
        input_schema = target.get("inputSchema", {})
        properties = input_schema.get("properties", {})

        for prop_name, prop_spec in properties.items():
            if isinstance(prop_spec, dict) and "type" not in prop_spec:
                findings.append(
                    self.create_finding(
                        target_name=f"Tool: {name}",
                        specific_description=(
                            f"Property '{prop_name}' in tool '{name}' has no 'type' declared."
                        ),
                        details={"tool_name": name, "parameter": prop_name},
                    )
                )

        return findings
