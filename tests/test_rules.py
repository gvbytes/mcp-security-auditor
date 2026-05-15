"""Unit tests for security audit rules."""

from mcp_security_auditor.core.models import Severity, TargetType
from mcp_security_auditor.rules.prompt_rules import PromptInjectionSurfaceRule
from mcp_security_auditor.rules.resource_rules import (
    RootFilesystemExposureRule,
    SensitiveResourceExposureRule,
)
from mcp_security_auditor.rules.tool_rules import (
    ArbitraryFileModificationRule,
    UnboundedSchemaValidationRule,
    UnrestrictedCommandExecutionRule,
)


def test_command_execution_rule_flags_unconstrained():
    rule = UnrestrictedCommandExecutionRule()
    target = {
        "name": "run_shell",
        "description": "Execute arbitrary shell commands.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string"},
            },
        },
    }
    findings = rule.evaluate(target)
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-T001"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].target_type == TargetType.TOOL


def test_command_execution_rule_allows_enum_constraints():
    rule = UnrestrictedCommandExecutionRule()
    target = {
        "name": "git_safe_action",
        "description": "Runs restricted git commands.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "enum": ["status", "diff", "branch"],
                },
            },
        },
    }
    findings = rule.evaluate(target)
    assert len(findings) == 0


def test_file_modification_rule():
    rule = ArbitraryFileModificationRule()
    target_vuln = {
        "name": "delete_file",
        "description": "Deletes target file.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filepath": {"type": "string"},
            },
        },
    }
    target_safe = {
        "name": "read_file_stats",
        "description": "Reads file size without modification.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filepath": {"type": "string"},
            },
        },
    }
    assert len(rule.evaluate(target_vuln)) == 1
    assert len(rule.evaluate(target_safe)) == 0


def test_unbounded_schema_validation_rule():
    rule = UnboundedSchemaValidationRule()
    target = {
        "name": "untyped_tool",
        "inputSchema": {
            "properties": {
                "valid_param": {"type": "string"},
                "bad_param": {"description": "Missing type"},
            },
        },
    }
    findings = rule.evaluate(target)
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-T003"
    assert findings[0].severity == Severity.LOW


def test_sensitive_resource_rule():
    rule = SensitiveResourceExposureRule()
    env_res = {"name": "app_env", "uri": "file:///var/app/.env"}
    passwd_res = {"name": "system_users", "uri": "file:///etc/passwd"}
    ssh_res = {"name": "deploy_key", "uri": "file:///root/.ssh/id_rsa"}
    safe_res = {"name": "logo", "uri": "file:///public/logo.png"}

    assert len(rule.evaluate(env_res)) == 1
    assert len(rule.evaluate(passwd_res)) == 1
    assert len(rule.evaluate(ssh_res)) == 1
    assert len(rule.evaluate(safe_res)) == 0


def test_root_filesystem_rule():
    rule = RootFilesystemExposureRule()
    root_res = {"name": "root_mount", "uri": "file:///"}
    etc_res = {"name": "etc_mount", "uri": "file:///etc/"}
    safe_res = {"name": "scoped_data", "uri": "file:///workspace/data/items.json"}

    assert len(rule.evaluate(root_res)) == 1
    assert len(rule.evaluate(etc_res)) == 1
    assert len(rule.evaluate(safe_res)) == 0


def test_prompt_injection_rule():
    rule = PromptInjectionSurfaceRule()
    vuln_prompt = {
        "name": "direct_comment",
        "description": "Directly feeds raw unframed user comment into LLM context without framing.",
        "arguments": [{"name": "comment"}],
    }
    override_prompt = {
        "name": "custom_agent",
        "description": "Standard agent.",
        "arguments": [{"name": "system_instruction"}],
    }
    safe_prompt = {
        "name": "safe_summary",
        "description": "Summarizes text enclosed in delimited XML tags.",
        "arguments": [{"name": "body"}],
    }

    assert len(rule.evaluate(vuln_prompt)) == 1
    assert len(rule.evaluate(override_prompt)) == 1
    assert len(rule.evaluate(safe_prompt)) == 0


def test_path_traversal_resource_rule():
    from mcp_security_auditor.rules.resource_rules import PathTraversalResourceRule

    rule = PathTraversalResourceRule()
    traversal_res = {"name": "escape", "uri": "file:///workspace/data/../../etc/shadow"}
    encoded_res = {"name": "encoded_escape", "uri": "file:///workspace/%2e%2e%2fprivate"}
    wildcard_res = {"name": "wildcard_template", "uriTemplate": "file:///{path}"}
    safe_res = {"name": "safe_doc", "uri": "file:///workspace/docs/guide.md"}

    assert len(rule.evaluate(traversal_res)) == 1
    assert len(rule.evaluate(encoded_res)) == 1
    assert len(rule.evaluate(wildcard_res)) == 1
    assert len(rule.evaluate(safe_res)) == 0


def test_rule_registry_suppressions():
    from mcp_security_auditor.rules import create_default_registry

    # Tool with unconstrained command
    tool = {
        "name": "exec_cmd",
        "description": "Runs arbitrary shell commands.",
        "inputSchema": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
        },
    }

    # Normal registry should flag it
    normal_reg = create_default_registry()
    assert len(normal_reg.evaluate_tools([tool])) >= 1

    # Suppressing MCP-T001
    suppressed_rule_reg = create_default_registry(ignore_rules={"MCP-T001"})
    assert len(suppressed_rule_reg.evaluate_tools([tool])) == 0

    # Excluding tool name
    excluded_tool_reg = create_default_registry(exclude_tools={"exec_cmd"})
    assert len(excluded_tool_reg.evaluate_tools([tool])) == 0
