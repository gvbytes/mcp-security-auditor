"""Integration tests for MCPClient and MCPSecurityAuditor."""

import sys
from pathlib import Path
import pytest

from mcp_security_auditor.core.auditor import MCPSecurityAuditor
from mcp_security_auditor.core.client import MCPClient, MCPClientError
from mcp_security_auditor.core.models import Severity

MOCK_SERVER_SCRIPT = str(Path(__file__).resolve().parent / "mock_server.py")
CMD = f"{sys.executable} {MOCK_SERVER_SCRIPT}"


@pytest.mark.asyncio
async def test_mcp_client_handshake_and_lists():
    client = MCPClient(CMD)
    await client.connect()
    try:
        server_info = await client.initialize()
        assert server_info.name == "VulnerableMockMCPServer"
        assert server_info.version == "1.0.0"

        tools = await client.list_tools()
        assert len(tools) == 3
        tool_names = [t["name"] for t in tools]
        assert "execute_shell" in tool_names
        assert "add_integers" in tool_names

        resources = await client.list_resources()
        assert len(resources) == 3

        prompts = await client.list_prompts()
        assert len(prompts) == 2
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_mcp_security_auditor_end_to_end():
    auditor = MCPSecurityAuditor(CMD)
    report = await auditor.audit()

    assert report.server_info.name == "VulnerableMockMCPServer"
    assert report.tools_count == 3
    assert report.resources_count == 3
    assert report.prompts_count == 2
    assert report.has_findings

    # Check that high-risk findings exist
    high_findings = [f for f in report.findings if f.severity == Severity.HIGH]
    assert len(high_findings) >= 2  # Shell command tool + sensitive resource

    rule_ids = {f.rule_id for f in report.findings}
    assert "MCP-T001" in rule_ids
    assert "MCP-R001" in rule_ids


@pytest.mark.asyncio
async def test_mcp_client_invalid_command():
    client = MCPClient("non_existent_binary_xyz_12345")
    with pytest.raises(MCPClientError):
        await client.connect()


def test_extract_servers_from_config(tmp_path):
    import json
    from mcp_security_auditor.cli import extract_servers_from_config

    cfg_file = tmp_path / "test_mcp_cfg.json"
    cfg_data = {
        "mcpServers": {
            "mock": {
                "command": "python3",
                "args": ["mock_server.py", "--flag"],
            }
        }
    }
    cfg_file.write_text(json.dumps(cfg_data))

    servers = extract_servers_from_config(cfg_file)
    assert "mock" in servers
    assert "mock_server.py" in servers["mock"]
