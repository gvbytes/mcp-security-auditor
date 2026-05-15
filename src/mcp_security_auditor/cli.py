"""Command-line interface for the MCP Security Auditor."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import platform
import shlex
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from mcp_security_auditor.core.auditor import MCPSecurityAuditor
from mcp_security_auditor.core.models import AuditReport, Finding, ServerMetadata, Severity
from mcp_security_auditor.formatters import ConsoleFormatter, JsonFormatter, SarifFormatter
from mcp_security_auditor.rules import create_default_registry

logger = logging.getLogger(__name__)


def find_claude_desktop_config() -> Optional[Path]:
    """Locate the Claude Desktop configuration file based on the operating system."""
    system = platform.system()
    home = Path.home()

    if system == "Darwin":
        candidate = home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    elif system == "Windows":
        appdata = os.environ.get("APPDATA")
        candidate = Path(appdata) / "Claude" / "claude_desktop_config.json" if appdata else None
    else:  # Linux / Unix
        candidate = home / ".config" / "Claude" / "claude_desktop_config.json"

    if candidate and candidate.is_file():
        return candidate
    return None


def load_local_config() -> Dict[str, Any]:
    """Load default settings from .mcpauditor.json in the current working directory if present."""
    local_cfg = Path(".mcpauditor.json")
    if local_cfg.is_file():
        try:
            with open(local_cfg, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning("Failed to parse .mcpauditor.json: %s", e)
    return {}


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    local_defaults = load_local_config()

    parser = argparse.ArgumentParser(
        prog="mcp-security-auditor",
        description="Static and dynamic security auditor for Model Context Protocol (MCP) servers.",
    )

    target_group = parser.add_mutually_exclusive_group(required=False)
    target_group.add_argument(
        "--stdio",
        help="Command to launch the MCP server over standard I/O (e.g. 'python my_server.py').",
    )
    target_group.add_argument(
        "--config",
        "-c",
        help="Path to an MCP configuration file (e.g. claude_desktop_config.json) to audit all servers.",
    )
    target_group.add_argument(
        "--claude",
        action="store_true",
        help="Automatically locate and audit all MCP servers defined in local Claude Desktop config.",
    )

    parser.add_argument(
        "--format",
        choices=["console", "json", "sarif"],
        default=local_defaults.get("format", "console"),
        help="Output report format (default: console).",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Path to write the report to. If omitted, prints to standard output.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default=local_defaults.get("fail_on", "high"),
        help="Exit with code 1 if findings reach or exceed this severity (default: high).",
    )
    parser.add_argument(
        "--ignore-rules",
        default=",".join(local_defaults.get("ignore_rules", [])),
        help="Comma-separated list of rule IDs to suppress (e.g. 'MCP-T003,MCP-P001').",
    )
    parser.add_argument(
        "--exclude-tools",
        default=",".join(local_defaults.get("exclude_tools", [])),
        help="Comma-separated list of tool names to exclude from audit.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Timeout in seconds for MCP RPC requests (default: 10.0).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output in console format.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable detailed debug logging.",
    )

    parsed = parser.parse_args(args)

    if not (parsed.stdio or parsed.config or parsed.claude):
        parser.error("You must specify either --stdio, --config, or --claude.")

    return parsed


async def audit_single_server(
    command: str,
    server_name: str,
    timeout: float,
    ignore_rules: Set[str],
    exclude_tools: Set[str],
) -> AuditReport:
    """Run security audit against a single MCP server command."""
    registry = create_default_registry(ignore_rules=ignore_rules, exclude_tools=exclude_tools)
    auditor = MCPSecurityAuditor(command=command, timeout=timeout, registry=registry)
    report = await auditor.audit()

    # Prepend server name to target names if analyzing multiple servers
    if server_name:
        for finding in report.findings:
            finding.target_name = f"[{server_name}] {finding.target_name}"

    return report


def extract_servers_from_config(config_path: Path) -> Dict[str, str]:
    """Parse MCP configuration JSON (e.g. Claude Desktop config) and return server commands."""
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        raise ValueError(f"Could not read config file '{config_path}': {e}") from e

    servers_dict = data.get("mcpServers", {})
    if not servers_dict:
        raise ValueError(f"No 'mcpServers' definition found in '{config_path}'.")

    commands: Dict[str, str] = {}
    for name, srv in servers_dict.items():
        cmd = srv.get("command", "")
        args = srv.get("args", [])
        if not cmd:
            continue
        full_parts = [cmd] + [str(a) for a in args]
        commands[name] = shlex.join(full_parts)

    return commands


async def run_audit(args: argparse.Namespace) -> int:
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="[%(levelname)s] %(name)s: %(message)s",
    )

    ignore_rules = {r.strip().upper() for r in args.ignore_rules.split(",") if r.strip()}
    exclude_tools = {t.strip().lower() for t in args.exclude_tools.split(",") if t.strip()}

    server_targets: Dict[str, str] = {}

    if args.claude:
        claude_cfg = find_claude_desktop_config()
        if not claude_cfg:
            sys.stderr.write("Could not automatically locate Claude Desktop config file.\n")
            return 2
        try:
            server_targets = extract_servers_from_config(claude_cfg)
        except Exception as e:
            sys.stderr.write(f"{e}\n")
            return 2
    elif args.config:
        cfg_path = Path(args.config)
        try:
            server_targets = extract_servers_from_config(cfg_path)
        except Exception as e:
            sys.stderr.write(f"{e}\n")
            return 2
    else:
        server_targets = {"": args.stdio}

    all_findings: List[Finding] = []
    total_tools = 0
    total_resources = 0
    total_prompts = 0
    total_duration = 0.0
    primary_server_meta = ServerMetadata(name="Aggregated Audit", version="1.0.0")

    is_multi = len(server_targets) > 1

    for srv_name, cmd in server_targets.items():
        if args.verbose or is_multi:
            target_label = f"server '{srv_name}'" if srv_name else "stdio target"
            logger.info("Auditing %s: %s", target_label, cmd)

        try:
            sub_report = await audit_single_server(
                command=cmd,
                server_name=srv_name if is_multi else "",
                timeout=args.timeout,
                ignore_rules=ignore_rules,
                exclude_tools=exclude_tools,
            )
            all_findings.extend(sub_report.findings)
            total_tools += sub_report.tools_count
            total_resources += sub_report.resources_count
            total_prompts += sub_report.prompts_count
            total_duration += sub_report.duration_seconds

            if not is_multi:
                primary_server_meta = sub_report.server_info
        except Exception as exc:
            sys.stderr.write(f"Error auditing server '{srv_name or cmd}': {exc}\n")
            return 2

    if is_multi:
        primary_server_meta = ServerMetadata(
            name=f"MCP Multi-Server ({len(server_targets)} servers)",
            version="1.0.0",
        )

    final_report = AuditReport(
        server_info=primary_server_meta,
        findings=all_findings,
        tools_count=total_tools,
        resources_count=total_resources,
        prompts_count=total_prompts,
        duration_seconds=total_duration,
    )

    # Format output
    if args.format == "json":
        formatter = JsonFormatter()
    elif args.format == "sarif":
        formatter = SarifFormatter()
    else:
        formatter = ConsoleFormatter(use_color=not args.no_color)

    output_str = formatter.format(final_report)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_str + "\n")
        except OSError as e:
            sys.stderr.write(f"Failed to write report to {args.output}: {e}\n")
            return 2
    else:
        print(output_str)

    # Evaluate failure threshold
    if args.fail_on != "none":
        threshold_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }
        threshold = threshold_map[args.fail_on]
        max_sev = final_report.max_severity()
        if max_sev and max_sev >= threshold:
            return 1

    return 0


def main(args: Optional[list[str]] = None) -> int:
    parsed_args = parse_args(args)
    return asyncio.run(run_audit(parsed_args))


if __name__ == "__main__":
    sys.exit(main())
