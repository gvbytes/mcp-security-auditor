"""Console formatter for terminal display without extraneous emojis."""

from __future__ import annotations

import sys
from mcp_security_auditor.core.models import AuditReport, Finding, Severity
from mcp_security_auditor.formatters.base import BaseFormatter


class ConsoleFormatter(BaseFormatter):
    """Formats audit reports into clean, human-readable terminal output."""

    def __init__(self, use_color: bool = True) -> None:
        self.use_color = use_color and sys.stdout.isatty()

    def _color(self, text: str, code: str) -> str:
        if not self.use_color:
            return text
        return f"\033[{code}m{text}\033[0m"

    def _severity_tag(self, severity: Severity) -> str:
        color_map = {
            Severity.CRITICAL: "1;95",  # Bold Magenta
            Severity.HIGH: "1;91",      # Bold Red
            Severity.MEDIUM: "1;93",    # Bold Yellow
            Severity.LOW: "1;94",       # Bold Blue
            Severity.INFO: "1;90",      # Bold Gray
        }
        code = color_map.get(severity, "0")
        return self._color(f"[{severity.value}]", code)

    def format(self, report: AuditReport) -> str:
        lines: list[str] = []
        sep = "=" * 64

        lines.append(sep)
        lines.append("                  MCP SECURITY AUDIT REPORT                 ")
        lines.append(sep)

        server = report.server_info
        lines.append(f"Target Server : {server.name} (v{server.version})")
        lines.append(f"Protocol      : {server.protocol_version}")
        lines.append(
            f"Audited Scope : {report.tools_count} tools, {report.resources_count} resources, "
            f"{report.prompts_count} prompts ({report.duration_seconds:.2f}s)"
        )
        lines.append("-" * 64)

        if not report.has_findings:
            lines.append(self._color("Status: PASSED. No security vulnerabilities detected.", "92"))
            lines.append(sep)
            return "\n".join(lines)

        lines.append(
            f"Status: FAILED. Detected {len(report.findings)} security issue(s):\n"
        )

        for idx, finding in enumerate(report.findings, start=1):
            tag = self._severity_tag(finding.severity)
            lines.append(f"{idx}. {tag} {finding.rule_id}: {finding.title}")
            lines.append(f"   Target : {finding.target_name}")
            lines.append(f"   CWE    : {finding.cwe}")
            lines.append(f"   Issue  : {finding.description}")
            lines.append(f"   Fix    : {self._color(finding.remediation, '36')}")
            if finding.details:
                detail_str = ", ".join(f"{k}={v}" for k, v in finding.details.items())
                lines.append(f"   Meta   : {detail_str}")
            lines.append("")

        lines.append("-" * 64)
        lines.append("SUMMARY BY SEVERITY:")
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = report.count_by_severity(sev)
            if count > 0:
                lines.append(f"  {self._severity_tag(sev):<20}: {count}")
        lines.append(sep)

        return "\n".join(lines)
