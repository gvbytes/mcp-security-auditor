"""Rules for auditing MCP prompt templates."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from mcp_security_auditor.core.models import Finding, Severity, TargetType
from mcp_security_auditor.rules.base import Rule

RAW_INJECTION_INDICATORS = re.compile(
    r"\b(directly feeds raw|unframed|without framing|unvalidated input|execute user prompt|raw user input into context)\b",
    re.IGNORECASE,
)
FRAMING_SAFEGUARDS = re.compile(
    r"\b(untrusted|sanitize|delimited|xml tags|framed|isolate|safe boundary)\b",
    re.IGNORECASE,
)
HIGH_RISK_ARG_NAMES = re.compile(
    r"^(prompt_override|system_instruction|raw_prompt|exec_code)$",
    re.IGNORECASE,
)


class PromptInjectionSurfaceRule(Rule):
    """Rule MCP-P001: Flags prompt templates with unframed inputs or override arguments."""

    id = "MCP-P001"
    title = "Unframed Prompt Injection Surface"
    severity = Severity.MEDIUM
    cwe = "CWE-77"
    target_type = TargetType.PROMPT
    description = (
        "The prompt template accepts raw or unconstrained user variables without framing "
        "boundaries or explicit instructions instructing the LLM on handling untrusted text."
    )
    remediation = (
        "Wrap user-provided template arguments inside clear semantic delimiters (e.g. XML tags "
        "like <user_input>) and add explicit system instructions directing the model never "
        "to execute directives contained inside untrusted input delimiters."
    )

    def evaluate(self, target: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        name = target.get("name", "unnamed_prompt")
        desc = target.get("description", "")
        arguments = target.get("arguments", [])

        # If prompt explicitly mentions it feeds raw unframed data without safeguards
        if RAW_INJECTION_INDICATORS.search(desc) and not FRAMING_SAFEGUARDS.search(desc):
            findings.append(
                self.create_finding(
                    target_name=f"Prompt: {name}",
                    specific_description=(
                        f"Prompt '{name}' documentation explicitly indicates that untrusted input "
                        f"is injected into the context without framing delimiters."
                    ),
                    details={"prompt_name": name, "reason": "unframed_description"},
                )
            )

        for arg in arguments:
            if not isinstance(arg, dict):
                continue
            arg_name = arg.get("name", "")
            arg_desc = arg.get("description", "")

            # If an argument is meant to override system instructions or supply raw code
            if HIGH_RISK_ARG_NAMES.match(arg_name):
                findings.append(
                    self.create_finding(
                        target_name=f"Prompt: {name} (Arg: {arg_name})",
                        specific_description=(
                            f"Prompt argument '{arg_name}' allows overriding system directives "
                            f"or injecting raw executable context."
                        ),
                        details={"prompt_name": name, "argument": arg_name},
                        override_severity=Severity.HIGH,
                    )
                )

        return findings
