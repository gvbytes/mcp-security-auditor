"""SARIF v2.1.0 formatter for CI/CD and GitHub Advanced Security integration."""

from __future__ import annotations

import json
from typing import Any, Dict, List

from mcp_security_auditor.core.models import AuditReport, Severity
from mcp_security_auditor.formatters.base import BaseFormatter


class SarifFormatter(BaseFormatter):
    """Formats audit reports into OASIS SARIF v2.1.0 JSON format."""

    def __init__(self, indent: int = 2) -> None:
        self.indent = indent

    def _severity_to_level(self, severity: Severity) -> str:
        if severity in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if severity == Severity.MEDIUM:
            return "warning"
        return "note"

    def format(self, report: AuditReport) -> str:
        rules_map: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []

        for finding in report.findings:
            if finding.rule_id not in rules_map:
                rules_map[finding.rule_id] = {
                    "id": finding.rule_id,
                    "name": finding.title.replace(" ", ""),
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "help": {
                        "text": f"{finding.description}\n\nRemediation: {finding.remediation}",
                        "markdown": f"**{finding.title}**\n\n{finding.description}\n\n### Remediation\n{finding.remediation}",
                    },
                    "properties": {
                        "tags": ["security", "mcp", finding.target_type.value],
                        "precision": "high",
                        "security-severity": "8.0" if finding.severity == Severity.HIGH else "5.0",
                    },
                }

            result_entry: Dict[str, Any] = {
                "ruleId": finding.rule_id,
                "level": self._severity_to_level(finding.severity),
                "message": {"text": f"{finding.title} - {finding.description}"},
                "locations": [
                    {
                        "logicalLocations": [
                            {
                                "name": finding.target_name,
                                "kind": finding.target_type.value,
                            }
                        ]
                    }
                ],
            }
            results.append(result_entry)

        sarif_doc: Dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "mcp-security-auditor",
                            "version": "0.2.0",
                            "informationUri": "https://github.com/gvbytes/mcp-security-auditor",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

        return json.dumps(sarif_doc, indent=self.indent)
