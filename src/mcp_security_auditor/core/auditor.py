"""Auditor engine orchestrating client communication and rule evaluation."""

from __future__ import annotations

import time
from typing import Optional

from mcp_security_auditor.core.client import MCPClient
from mcp_security_auditor.core.models import AuditReport, ServerMetadata
from mcp_security_auditor.rules import create_default_registry
from mcp_security_auditor.rules.base import RuleRegistry


class MCPSecurityAuditor:
    """Orchestrates communication with an MCP server and executes security audit rules."""

    def __init__(
        self,
        command: str,
        timeout: float = 10.0,
        registry: Optional[RuleRegistry] = None,
    ) -> None:
        self.command = command
        self.timeout = timeout
        self.registry = registry or create_default_registry()

    async def audit(self) -> AuditReport:
        """Run a full security audit against the configured MCP server."""
        start_time = time.perf_counter()
        client = MCPClient(self.command, timeout=self.timeout)

        server_info = ServerMetadata()
        tools_count = 0
        resources_count = 0
        prompts_count = 0
        findings = []

        try:
            await client.connect()
            server_info = await client.initialize()

            # Audit tools
            tools = await client.list_tools()
            tools_count = len(tools)
            findings.extend(self.registry.evaluate_tools(tools))

            # Audit resources and resource templates
            resources = await client.list_resources()
            resource_templates = await client.list_resource_templates()
            all_resources = resources + resource_templates
            resources_count = len(all_resources)
            findings.extend(self.registry.evaluate_resources(all_resources))

            # Audit prompts
            prompts = await client.list_prompts()
            prompts_count = len(prompts)
            findings.extend(self.registry.evaluate_prompts(prompts))

        finally:
            await client.close()

        duration = time.perf_counter() - start_time
        return AuditReport(
            server_info=server_info,
            findings=findings,
            tools_count=tools_count,
            resources_count=resources_count,
            prompts_count=prompts_count,
            duration_seconds=duration,
        )
