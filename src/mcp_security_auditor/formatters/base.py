"""Base interface for audit report formatters."""

from abc import ABC, abstractmethod
from mcp_security_auditor.core.models import AuditReport


class BaseFormatter(ABC):
    """Abstract base class for formatting audit reports."""

    @abstractmethod
    def format(self, report: AuditReport) -> str:
        """Format the report into a string representation."""
        pass
