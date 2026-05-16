import sys
import json
import argparse
import subprocess
import time

# Simple terminal colors for our report
CLR_Y = '\033[93m'  # Warning/Medium
CLR_R = '\033[91m'  # High/Critical
CLR_B = '\033[94m'  # Info
CLR_G = '\033[92m'  # Safe/Success
CLR_N = '\033[0m'   # Reset

# Junior researcher comments:
# "I put all the security checks in this simple list. It makes it easy to add
# new checks later when we find more MCP vulnerabilities."
CHECK_RULES = {
    "tool_injection": {
        "keys": ["command", "cmd", "exec", "shell", "script", "args"],
        "desc": "Check if tool schema has command execution parameters without restriction."
    },
    "privilege_escalation": {
        "keys": ["write", "delete", "config", "install", "modify", "path"],
        "desc": "Check if tool allows filesystem modifications or admin state changes."
    },
    "sensitive_data": {
        "keys": [".env", "passwd", ".ssh", "id_rsa", "secret", "key", "token"],
        "desc": "Check if resource URI path exposes secrets, credentials, or keys."
    },
    "prompt_poisoning": {
        "keys": ["raw", "untrusted", "user_content", "comment", "body"],
        "desc": "Check if prompt template accepts raw arguments without instructions."
    }
}

class SimpleMCPAuditor:
    def __init__(self, run_command):
        self.cmd = run_command
        self.proc = None
        self.req_id = 1

    def query_server(self, method, params=None):
        """Send a JSON-RPC message over stdout/stdin and get the response back."""
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "id": self.req_id
        }
        if params:
            payload["params"] = params

        # Write to server stdin
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()
        self.req_id += 1

        # Read line from server stdout
        res_line = self.proc.stdout.readline().strip()
        if not res_line:
            err = self.proc.stderr.readline().strip()
            raise Exception(f"No response from server. Error info: {err}")
        return json.loads(res_line)

    def scan(self):
        print(f"{CLR_B}[*] Spawning MCP Server: {self.cmd}{CLR_N}")
        try:
            self.proc = subprocess.Popen(
                self.cmd,
                shell=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            time.sleep(0.5)  # wait for startup
        except Exception as e:
            print(f"{CLR_R}[-] Failed to spawn server: {e}{CLR_N}")
            return

        findings = []

        try:
            # 1. Initialize Handshake
            print("[*] Performing handshakes...")
            self.query_server("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "SimpleAuditor", "version": "1.0.0"}
            })

            # 2. Get Tools List
            print("[*] Fetching tools list...")
            tools_res = self.query_server("tools/list")
            tools = tools_res.get("result", {}).get("tools", [])

            # Audit tools
            for t in tools:
                name = t.get("name", "")
                desc = t.get("description", "").lower()
                props = t.get("inputSchema", {}).get("properties", {})

                # Check Tool Injection
                is_inj = any(k in desc for k in ["exec", "shell", "run"])
                for p in props:
                    if any(k in p.lower() for k in CHECK_RULES["tool_injection"]["keys"]):
                        is_inj = True
                if is_inj:
                    findings.append({
                        "type": "Tool Injection Risk",
                        "severity": "HIGH",
                        "target": f"Tool: {name}",
                        "desc": "Accepts parameters that look like shell commands without enum/regex validations.",
                        "fix": "Use strict 'enum' validation arrays or regular expression patterns in JSON schemas."
                    })

                # Check Privilege Escalation
                is_esc = any(k in desc for k in ["config", "write", "install"])
                for p in props:
                    if any(k in p.lower() for k in CHECK_RULES["privilege_escalation"]["keys"]):
                        is_esc = True
                # Skip if already flagged as High Injection
                if is_esc and not is_inj:
                    findings.append({
                        "type": "Privilege Escalation Risk",
                        "severity": "MEDIUM",
                        "target": f"Tool: {name}",
                        "desc": "Allows writing to paths or modifying config files.",
                        "fix": "Restrict tool writes to a specific relative directory sandbox."
                    })

            # 3. Get Resources List
            print("[*] Fetching resources list...")
            try:
                res_res = self.query_server("resources/list")
                resources = res_res.get("result", {}).get("resources", [])
                for r in resources:
                    uri = r.get("uri", "").lower()
                    name = r.get("name", "").lower()
                    if any(k in uri or k in name for k in CHECK_RULES["sensitive_data"]["keys"]):
                        findings.append({
                            "type": "Sensitive Data Exposure",
                            "severity": "HIGH",
                            "target": f"Resource: {r.get('name')} ({r.get('uri')})",
                            "desc": "Exposes sensitive file paths, secrets, or configuration environment files.",
                            "fix": "Do not register system credentials or root directories as resources."
                        })
            except Exception as e:
                print(f"[!] Server doesn't support resources/list: {e}")

            # 4. Get Prompts List
            print("[*] Fetching prompts list...")
            try:
                prompts_res = self.query_server("prompts/list")
                prompts = prompts_res.get("result", {}).get("prompts", [])
                for p in prompts:
                    name = p.get("name", "")
                    desc = p.get("description", "").lower()
                    for arg in p.get("arguments", []):
                        arg_name = arg.get("name", "").lower()
                        if any(k in arg_name or k in desc for k in CHECK_RULES["prompt_poisoning"]["keys"]):
                            findings.append({
                                "type": "Prompt Poisoning Vulnerability",
                                "severity": "MEDIUM",
                                "target": f"Prompt: {name} (Arg: {arg.get('name')})",
                                "desc": "Processes unconstrained input variables without framing boundaries.",
                                "fix": "Add instructions in the template telling the model to treat this parameter as untrusted data."
                            })
            except Exception as e:
                print(f"[!] Server doesn't support prompts/list: {e}")

            # Print Findings
            print("\n" + "=" * 50)
            print("                 SECURITY REPORT                    ")
            print("=" * 50)
            if not findings:
                print(f"\n{CLR_G}[+] No vulnerabilities detected!{CLR_N}")
            else:
                print(f"\nFound {len(findings)} security issues:\n")
                for i, f in enumerate(findings, 1):
                    color = CLR_R if f["severity"] == "HIGH" else CLR_Y
                    print(f"{i}. [{f['type']}] - Severity: {color}{f['severity']}{CLR_N}")
                    print(f"   Target: {f['target']}")
                    print(f"   Details: {f['desc']}")
                    print(f"   How to fix: {CLR_B}{f['fix']}{CLR_N}")
                    print("-" * 50)

        except Exception as e:
            print(f"{CLR_R}[-] Audit interrupted by error: {e}{CLR_N}")
        finally:
            if self.proc:
                self.proc.terminate()
                self.proc.wait()
                print("\n[*] Connection closed.")

def main():
    parser = argparse.ArgumentParser(description="Simple MCP Security Auditor")
    parser.add_argument("--stdio", required=True, help="Command to run the stdio MCP server (e.g. 'python server.py')")
    args = parser.parse_args()

    auditor = SimpleMCPAuditor(args.stdio)
    auditor.scan()

if __name__ == "__main__":
    main()
