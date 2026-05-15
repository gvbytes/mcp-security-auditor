"""JSON formatter for machine-readable audit reports."""

import json
from mcp_security_auditor.core.models import AuditReport
from mcp_security_auditor.formatters.base import BaseFormatter


class JsonFormatter(BaseFormatter):
    """Formats audit reports into formatted JSON."""

    def __init__(self, indent: int = 2) -> None:
        self.indent = indent

    def format(self, report: AuditReport) -> str:
        return json.dumps(report.to_dict(), indent=self.indent)
