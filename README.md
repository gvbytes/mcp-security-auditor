# MCP Security Auditor

When you configure a Model Context Protocol (MCP) server in tools like Claude Desktop, Cursor, or an autonomous AI agent, you give an LLM direct access to local tools and system resources. Because these processes run under your user account, an insecure server schema combined with prompt injection can easily lead to remote command execution, credential theft, or unauthorized file modification.

**MCP Security Auditor** is a static and dynamic analysis tool that checks MCP servers for these security risks before you deploy or connect them. It performs protocol handshakes, evaluates JSON schemas and URI registrations, and flags vulnerabilities in **Console**, **JSON**, or **SARIF v2.1.0** format for your CI/CD pipeline.

---

## What It Checks

| Rule ID | Finding | Severity | CWE | Why It Matters |
| :--- | :--- | :--- | :--- | :--- |
| **`MCP-T001`** | Unrestricted Command Execution | **HIGH** | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | Tool exposes shell or script execution parameters without `enum` or regex `pattern` restrictions, allowing arbitrary command execution if hijacked. |
| **`MCP-T002`** | Arbitrary File Modification | **MEDIUM** | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | Tool performs file writes, updates, or deletions with unconfined path parameters that can escape workspace roots. |
| **`MCP-T003`** | Missing Schema Validation | **LOW** | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) | Tool parameters omit basic JSON Schema `type` declarations, allowing unexpected inputs into backend handlers. |
| **`MCP-R001`** | Sensitive File / Secret Exposure | **HIGH** | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | Server exposes `.env` files, SSH private keys, cloud tokens, database credentials, or `/etc/passwd` as resources. |
| **`MCP-R002`** | Root Filesystem Exposure | **MEDIUM** | [CWE-552](https://cwe.mitre.org/data/definitions/552.html) | Server registers root filesystem URIs (`file:///`), giving the LLM full read access across the host operating system. |
| **`MCP-R003`** | Path Traversal in Resource URIs | **HIGH** | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | Resource URIs or URI templates contain directory traversal sequences (`../`) or unrestricted wildcards (`file:///{path}`). |
| **`MCP-P001`** | Unframed Prompt Injection Surface | **MEDIUM** | [CWE-77](https://cwe.mitre.org/data/definitions/77.html) | Prompt template feeds raw untrusted user input into model context without delimiter boundaries or safety instructions. |

---

## Installation

### Using pip
```bash
git clone https://github.com/gvbytes/mcp-security-auditor.git
cd mcp-security-auditor
pip install .
```

### For Development
```bash
pip install -e ".[dev]"
```

---

## Usage Examples

### 1. Audit a Single Server Running Over stdio
Point the auditor to the start command of your MCP server:

```bash
mcp-security-auditor --stdio "python path/to/server.py"
```

### 2. Audit All Local Claude Desktop Servers in One Command
If you use Claude Desktop, the `--claude` flag automatically finds your configuration file and audits all registered MCP servers:

```bash
mcp-security-auditor --claude
```

### 3. Audit Servers from a Custom Config File
You can also point the auditor directly to any Claude Desktop or Cursor configuration file:

```bash
mcp-security-auditor --config ~/.config/Claude/claude_desktop_config.json
```

### 4. CI/CD Gating with Exit Codes
By default, the auditor exits with code `1` if any **HIGH** or **CRITICAL** vulnerability is detected, and `0` otherwise. You can adjust this threshold for your automated builds:

```bash
# Fail only on CRITICAL findings
mcp-security-auditor --stdio "node dist/index.js" --fail-on critical

# Informational run (always exits with code 0)
mcp-security-auditor --stdio "node dist/index.js" --fail-on none
```

### 5. Suppressing Rules and Excluding Tools
If you have an intentional administrative tool or want to ignore specific rules, pass them on the command line:

```bash
mcp-security-auditor --stdio "python server.py" \
  --ignore-rules MCP-T003,MCP-P001 \
  --exclude-tools legitimate_exec_tool
```

You can also create a `.mcpauditor.json` file in your repository root to persist these settings:

```json
{
  "fail_on": "high",
  "ignore_rules": ["MCP-T003"],
  "exclude_tools": ["admin_shell"]
}
```

---

## Export Formats

### JSON
```bash
mcp-security-auditor --stdio "python server.py" --format json -o report.json
```

### SARIF (GitHub Code Scanning)
Generate SARIF v2.1.0 output to upload findings directly into GitHub's Security tab:

```bash
mcp-security-auditor --stdio "python server.py" --format sarif -o results.sarif
```

#### GitHub Actions Workflow Example

```yaml
name: Security Scan MCP Servers

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install dependencies
        run: |
          pip install mcp-security-auditor
          pip install -r requirements.txt

      - name: Run MCP Security Auditor
        run: |
          mcp-security-auditor \
            --stdio "python server.py" \
            --format sarif \
            --output results.sarif \
            --fail-on high

      - name: Upload SARIF to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

---

## How It Works Under the Hood

1. **Protocol Handshake:** Spawns the MCP server child process safely without shell expansion (`shlex.split`), completes the `initialize` handshake, and issues the `notifications/initialized` notification per the MCP spec.
2. **Schema and Resource Inspection:** Queries `tools/list`, `resources/list`, `resources/templates/list`, and `prompts/list`, automatically handling pagination cursors.
3. **AST & Constraint Analysis:** Analyzes input schemas against known attack vectors. Unlike naive keyword matching, it checks whether parameters are constrained by strict JSON Schema `enum` arrays or regex `pattern` rules before flagging an issue.
4. **Structured Output:** Aggregates findings with Common Weakness Enumeration (CWE) mappings, plain-text remediation advice, and reproducible metadata.

---

## Running Tests

To run the automated test suite locally:

```bash
pytest -v
```

---

## License

This project is licensed under the [MIT License](LICENSE).
