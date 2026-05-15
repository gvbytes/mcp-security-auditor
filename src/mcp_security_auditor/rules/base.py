"""Base classes and registry for security audit rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set

from mcp_security_auditor.core.models import Finding, Severity, TargetType


class Rule(ABC):
    """Abstract base class for an MCP security rule."""

    id: str
    title: str
    severity: Severity
    cwe: str
    target_type: TargetType
    description: str
    remediation: str

    @abstractmethod
    def evaluate(self, target: Dict[str, Any]) -> List[Finding]:
        """Evaluate a target item (tool, resource, prompt) and return findings."""
        pass

    def create_finding(
        self,
        target_name: str,
        specific_description: str,
        details: Dict[str, Any] | None = None,
        override_severity: Severity | None = None,
    ) -> Finding:
        """Helper to create a finding instance populated with rule metadata."""
        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=override_severity or self.severity,
            target_type=self.target_type,
            target_name=target_name,
            description=specific_description,
            remediation=self.remediation,
            cwe=self.cwe,
            details=details or {},
        )


class RuleRegistry:
    """Registry managing rules grouped by target type with support for suppressions."""

    def __init__(
        self,
        ignore_rules: Optional[Set[str]] = None,
        exclude_tools: Optional[Set[str]] = None,
    ) -> None:
        self.tool_rules: List[Rule] = []
        self.resource_rules: List[Rule] = []
        self.prompt_rules: List[Rule] = []
        self.ignore_rules = {r.strip().upper() for r in ignore_rules} if ignore_rules else set()
        self.exclude_tools = {t.strip().lower() for t in exclude_tools} if exclude_tools else set()

    def register_tool_rule(self, rule: Rule) -> None:
        self.tool_rules.append(rule)

    def register_resource_rule(self, rule: Rule) -> None:
        self.resource_rules.append(rule)

    def register_prompt_rule(self, rule: Rule) -> None:
        self.prompt_rules.append(rule)

    def evaluate_tools(self, tools: List[Dict[str, Any]]) -> List[Finding]:
        findings: List[Finding] = []
        for tool in tools:
            name = tool.get("name", "").lower()
            if name in self.exclude_tools:
                continue
            for rule in self.tool_rules:
                if rule.id.upper() in self.ignore_rules:
                    continue
                findings.extend(rule.evaluate(tool))
        return findings

    def evaluate_resources(self, resources: List[Dict[str, Any]]) -> List[Finding]:
        findings: List[Finding] = []
        for resource in resources:
            for rule in self.resource_rules:
                if rule.id.upper() in self.ignore_rules:
                    continue
                findings.extend(rule.evaluate(resource))
        return findings

    def evaluate_prompts(self, prompts: List[Dict[str, Any]]) -> List[Finding]:
        findings: List[Finding] = []
        for prompt in prompts:
            for rule in self.prompt_rules:
                if rule.id.upper() in self.ignore_rules:
                    continue
                findings.extend(rule.evaluate(prompt))
        return findings
