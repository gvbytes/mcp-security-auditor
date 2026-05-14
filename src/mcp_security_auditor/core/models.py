"""Core data models for MCP Security Auditor."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        order = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return order[self]

    def __ge__(self, other: Any) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: Any) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: Any) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


class TargetType(str, Enum):
    TOOL = "tool"
    RESOURCE = "resource"
    PROMPT = "prompt"
    SERVER = "server"


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    target_type: TargetType
    target_name: str
    description: str
    remediation: str
    cwe: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "target_type": self.target_type.value,
            "target_name": self.target_name,
            "description": self.description,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "details": self.details,
        }


@dataclass
class ServerMetadata:
    name: str = "Unknown"
    version: str = "0.0.0"
    protocol_version: str = "2024-11-05"
    capabilities: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "protocol_version": self.protocol_version,
            "capabilities": self.capabilities,
        }


@dataclass
class AuditReport:
    server_info: ServerMetadata
    findings: List[Finding] = field(default_factory=list)
    tools_count: int = 0
    resources_count: int = 0
    prompts_count: int = 0
    duration_seconds: float = 0.0

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    def count_by_severity(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity == severity)

    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: f.severity.rank).severity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "server_info": self.server_info.to_dict(),
            "summary": {
                "total_findings": len(self.findings),
                "critical": self.count_by_severity(Severity.CRITICAL),
                "high": self.count_by_severity(Severity.HIGH),
                "medium": self.count_by_severity(Severity.MEDIUM),
                "low": self.count_by_severity(Severity.LOW),
                "info": self.count_by_severity(Severity.INFO),
                "tools_audited": self.tools_count,
                "resources_audited": self.resources_count,
                "prompts_audited": self.prompts_count,
                "duration_seconds": round(self.duration_seconds, 3),
            },
            "findings": [f.to_dict() for f in self.findings],
        }
