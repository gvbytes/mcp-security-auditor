"""Unit tests for report formatters."""

import json
from mcp_security_auditor.core.models import (
    AuditReport,
    Finding,
    ServerMetadata,
    Severity,
    TargetType,
)
from mcp_security_auditor.formatters import ConsoleFormatter, JsonFormatter, SarifFormatter


def _create_sample_report() -> AuditReport:
    server_meta = ServerMetadata(
        name="TestServer",
        version="1.2.3",
        protocol_version="2024-11-05",
    )
    finding = Finding(
        rule_id="MCP-T001",
        title="Unrestricted Command Execution Parameter",
        severity=Severity.HIGH,
        target_type=TargetType.TOOL,
        target_name="Tool: execute_shell",
        description="Parameter 'command' permits arbitrary command execution.",
        remediation="Use an enum constraint.",
        cwe="CWE-78",
    )
    return AuditReport(
        server_info=server_meta,
        findings=[finding],
        tools_count=3,
        resources_count=2,
        prompts_count=1,
        duration_seconds=0.42,
    )


def test_console_formatter():
    report = _create_sample_report()
    formatter = ConsoleFormatter(use_color=False)
    output = formatter.format(report)

    assert "MCP SECURITY AUDIT REPORT" in output
    assert "TestServer (v1.2.3)" in output
    assert "MCP-T001" in output
    assert "CWE-78" in output
    assert "SUMMARY BY SEVERITY" in output


def test_json_formatter():
    report = _create_sample_report()
    formatter = JsonFormatter()
    output = formatter.format(report)

    parsed = json.loads(output)
    assert parsed["server_info"]["name"] == "TestServer"
    assert parsed["summary"]["total_findings"] == 1
    assert parsed["summary"]["high"] == 1
    assert len(parsed["findings"]) == 1
    assert parsed["findings"][0]["rule_id"] == "MCP-T001"


def test_sarif_formatter():
    report = _create_sample_report()
    formatter = SarifFormatter()
    output = formatter.format(report)

    sarif = json.loads(output)
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1

    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "mcp-security-auditor"
    assert len(driver["rules"]) == 1
    assert driver["rules"][0]["id"] == "MCP-T001"

    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "MCP-T001"
    assert results[0]["level"] == "error"
