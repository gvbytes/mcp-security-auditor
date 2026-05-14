"""Asynchronous Model Context Protocol (MCP) JSON-RPC client."""

from __future__ import annotations

import asyncio
import json
import logging
import shlex
from typing import Any, Dict, List, Optional

from mcp_security_auditor.core.models import ServerMetadata

logger = logging.getLogger(__name__)


class MCPClientError(Exception):
    """Base exception for MCP client failures."""
    pass


class MCPClient:
    """Client for communicating with MCP servers over standard I/O (stdio)."""

    def __init__(self, command: str, timeout: float = 10.0):
        self.command = command
        self.timeout = timeout
        self.process: Optional[asyncio.subprocess.Process] = None
        self._request_id = 1

    async def connect(self) -> None:
        """Spawn the MCP server process without shell expansion."""
        cmd_parts = shlex.split(self.command)
        if not cmd_parts:
            raise MCPClientError("Server command cannot be empty.")

        try:
            self.process = await asyncio.create_subprocess_exec(
                *cmd_parts,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise MCPClientError(f"Executable not found: {cmd_parts[0]}") from exc
        except Exception as exc:
            raise MCPClientError(f"Failed to spawn MCP process: {exc}") from exc

    async def send_notification(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        """Send a JSON-RPC notification (no response expected)."""
        if not self.process or not self.process.stdin:
            raise MCPClientError("Client is not connected to a server process.")

        payload: Dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if params is not None:
            payload["params"] = params

        raw = (json.dumps(payload) + "\n").encode("utf-8")
        self.process.stdin.write(raw)
        await self.process.stdin.drain()

    async def call_method(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Send a JSON-RPC request and wait for the corresponding response."""
        if not self.process or not self.process.stdin or not self.process.stdout:
            raise MCPClientError("Client is not connected to a server process.")

        req_id = self._request_id
        self._request_id += 1

        payload: Dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
        }
        if params is not None:
            payload["params"] = params

        raw = (json.dumps(payload) + "\n").encode("utf-8")
        self.process.stdin.write(raw)
        await self.process.stdin.drain()

        effective_timeout = timeout or self.timeout

        async def read_response() -> Dict[str, Any]:
            while True:
                line_bytes = await self.process.stdout.readline()
                if not line_bytes:
                    stderr_output = ""
                    if self.process.stderr:
                        try:
                            err_bytes = await asyncio.wait_for(
                                self.process.stderr.read(4096), timeout=0.5
                            )
                            stderr_output = err_bytes.decode("utf-8", errors="replace").strip()
                        except Exception:
                            pass
                    raise MCPClientError(
                        f"Server closed connection unexpectedly. Stderr: {stderr_output}"
                    )

                line = line_bytes.decode("utf-8", errors="replace").strip()
                if not line:
                    continue

                # Ignore non-JSON lines (e.g. server debug logging leaking to stdout)
                if not (line.startswith("{") and line.endswith("}")):
                    logger.debug("Skipping non-JSON output from server stdout: %s", line)
                    continue

                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # Match response ID if present
                if data.get("id") == req_id:
                    if "error" in data:
                        err = data["error"]
                        code = err.get("code", "unknown")
                        msg = err.get("message", "No message provided")
                        raise MCPClientError(f"Server returned error [code {code}]: {msg}")
                    return data.get("result", {})

        try:
            return await asyncio.wait_for(read_response(), timeout=effective_timeout)
        except asyncio.TimeoutError as exc:
            raise MCPClientError(
                f"Timed out waiting for response to '{method}' after {effective_timeout}s"
            ) from exc

    async def initialize(self) -> ServerMetadata:
        """Perform MCP protocol handshake and send 'notifications/initialized'."""
        result = await self.call_method(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-security-auditor",
                    "version": "0.2.0",
                },
            },
        )

        server_info = result.get("serverInfo", {})
        metadata = ServerMetadata(
            name=server_info.get("name", "Unknown Server"),
            version=server_info.get("version", "0.0.0"),
            protocol_version=result.get("protocolVersion", "2024-11-05"),
            capabilities=result.get("capabilities", {}),
        )

        # Send official MCP initialized notification
        await self.send_notification("notifications/initialized")
        return metadata

    async def list_tools(self) -> List[Dict[str, Any]]:
        """Fetch all tools with pagination support."""
        tools: List[Dict[str, Any]] = []
        cursor: Optional[str] = None

        while True:
            params: Dict[str, Any] = {}
            if cursor:
                params["cursor"] = cursor

            try:
                result = await self.call_method("tools/list", params if params else None)
            except MCPClientError as e:
                # Some servers might not implement tools/list if they don't have tools
                logger.warning("tools/list call failed: %s", e)
                break

            items = result.get("tools", [])
            tools.extend(items)

            cursor = result.get("nextCursor")
            if not cursor:
                break

        return tools

    async def list_resources(self) -> List[Dict[str, Any]]:
        """Fetch all resources with pagination support."""
        resources: List[Dict[str, Any]] = []
        cursor: Optional[str] = None

        while True:
            params: Dict[str, Any] = {}
            if cursor:
                params["cursor"] = cursor

            try:
                result = await self.call_method("resources/list", params if params else None)
            except MCPClientError as e:
                logger.warning("resources/list call failed: %s", e)
                break

            items = result.get("resources", [])
            resources.extend(items)

            cursor = result.get("nextCursor")
            if not cursor:
                break

        return resources

    async def list_resource_templates(self) -> List[Dict[str, Any]]:
        """Fetch all resource templates if supported by server."""
        templates: List[Dict[str, Any]] = []
        cursor: Optional[str] = None

        while True:
            params: Dict[str, Any] = {}
            if cursor:
                params["cursor"] = cursor

            try:
                result = await self.call_method("resources/templates/list", params if params else None)
            except MCPClientError:
                # Optional feature in MCP specification
                break

            items = result.get("resourceTemplates", [])
            templates.extend(items)

            cursor = result.get("nextCursor")
            if not cursor:
                break

        return templates

    async def list_prompts(self) -> List[Dict[str, Any]]:
        """Fetch all prompts with pagination support."""
        prompts: List[Dict[str, Any]] = []
        cursor: Optional[str] = None

        while True:
            params: Dict[str, Any] = {}
            if cursor:
                params["cursor"] = cursor

            try:
                result = await self.call_method("prompts/list", params if params else None)
            except MCPClientError as e:
                logger.warning("prompts/list call failed: %s", e)
                break

            items = result.get("prompts", [])
            prompts.extend(items)

            cursor = result.get("nextCursor")
            if not cursor:
                break

        return prompts

    async def close(self) -> None:
        """Safely terminate child process and close pipes."""
        if not self.process:
            return

        try:
            if self.process.stdin:
                self.process.stdin.close()
                await self.process.stdin.wait_closed()
        except Exception:
            pass

        if self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                self.process.kill()
                await self.process.wait()
