#!/usr/bin/env python3
"""Sanitized mock MCP server for testing and auditing."""

import json
import sys


def handle_request(line: str) -> None:
    try:
        req = json.loads(line)
    except json.JSONDecodeError:
        return

    method = req.get("method")
    msg_id = req.get("id")

    # Notifications do not have an id and must not produce a response
    if msg_id is None:
        return

    if method == "initialize":
        res = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {},
                    "resources": {},
                    "prompts": {},
                },
                "serverInfo": {
                    "name": "VulnerableMockMCPServer",
                    "version": "1.0.0",
                },
            },
        }
    elif method == "tools/list":
        res = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": [
                    {
                        "name": "execute_shell",
                        "description": "Runs arbitrary shell commands directly on the host machine.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "command": {
                                    "type": "string",
                                    "description": "The shell command to execute.",
                                }
                            },
                            "required": ["command"],
                        },
                    },
                    {
                        "name": "update_system_config",
                        "description": "Modifies system configuration files on disk.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "description": "Absolute target path to overwrite.",
                                },
                                "content": {"type": "string"},
                            },
                            "required": ["path", "content"],
                        },
                    },
                    {
                        "name": "add_integers",
                        "description": "Calculates the sum of two integers.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "a": {"type": "integer"},
                                "b": {"type": "integer"},
                            },
                            "required": ["a", "b"],
                        },
                    },
                ]
            },
        }
    elif method == "resources/list":
        res = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "resources": [
                    {
                        "uri": "file:///workspace/.env",
                        "name": "Application Environment Config",
                        "mimeType": "text/plain",
                    },
                    {
                        "uri": "file:///etc/passwd",
                        "name": "System Users Database",
                        "mimeType": "text/plain",
                    },
                    {
                        "uri": "file:///assets/logo.png",
                        "name": "Public Logo Asset",
                        "mimeType": "image/png",
                    },
                ]
            },
        }
    elif method == "prompts/list":
        res = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "prompts": [
                    {
                        "name": "unframed_comment_translator",
                        "description": "Directly feeds raw unframed user comment into LLM context without framing.",
                        "arguments": [
                            {"name": "comment", "description": "Raw comment", "required": True}
                        ],
                    },
                    {
                        "name": "secure_summarizer",
                        "description": "Summarizes documents using delimited XML tags to isolate untrusted text.",
                        "arguments": [
                            {
                                "name": "document_text",
                                "description": "Text framed within <document> tags.",
                                "required": True,
                            }
                        ],
                    },
                ]
            },
        }
    else:
        res = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method '{method}' not found"},
        }

    sys.stdout.write(json.dumps(res) + "\n")
    sys.stdout.flush()


def main() -> None:
    for line in sys.stdin:
        cleaned = line.strip()
        if not cleaned:
            continue
        handle_request(cleaned)


if __name__ == "__main__":
    main()
