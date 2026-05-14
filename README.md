# MCP Security Auditor

This is a simple tool to check Model Context Protocol (MCP) server schemas for security risks before you run them on your system. It does a passive audit on the JSON-RPC schema definitions exposed by the server.

## Risks Checked
The tool looks for four common design flaws:
1. Tool Injection: Tools that accept commands or scripts (like cmd or eval) without strict limits. If an LLM is hijacked, it could run commands on your machine.
2. Privilege Escalation: Tools that write, modify, or delete files.
3. Sensitive Data Exposure: Resources that expose configurations, keys, or sensitive system files (like .env or .ssh).
4. Prompt Poisoning: Prompt templates that take raw inputs without instructing the model on how to handle untrusted data.

## Requirements
- Python 3.x
- Uses only built-in Python modules (no pip install required)

## How to Use

To audit an MCP server running on stdio, run the script and pass the start command of your target server:

```bash
python mcp_auditor.py --stdio "python path/to/your/server.py"
```

To test the auditor with the provided mock server, run:

```bash
python mcp_auditor.py --stdio "python test_server.py"
```

The console will display the detected risks along with recommendations on how to fix them.
