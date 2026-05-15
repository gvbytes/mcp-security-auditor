"""Rules initialization and default registry factory."""

from typing import Optional, Set

from mcp_security_auditor.rules.base import RuleRegistry
from mcp_security_auditor.rules.prompt_rules import PromptInjectionSurfaceRule
from mcp_security_auditor.rules.resource_rules import (
    PathTraversalResourceRule,
    RootFilesystemExposureRule,
    SensitiveResourceExposureRule,
)
from mcp_security_auditor.rules.tool_rules import (
    ArbitraryFileModificationRule,
    UnboundedSchemaValidationRule,
    UnrestrictedCommandExecutionRule,
)


def create_default_registry(
    ignore_rules: Optional[Set[str]] = None,
    exclude_tools: Optional[Set[str]] = None,
) -> RuleRegistry:
    """Create a RuleRegistry populated with standard MCP security rules."""
    registry = RuleRegistry(ignore_rules=ignore_rules, exclude_tools=exclude_tools)

    # Tool rules
    registry.register_tool_rule(UnrestrictedCommandExecutionRule())
    registry.register_tool_rule(ArbitraryFileModificationRule())
    registry.register_tool_rule(UnboundedSchemaValidationRule())

    # Resource rules
    registry.register_resource_rule(SensitiveResourceExposureRule())
    registry.register_resource_rule(RootFilesystemExposureRule())
    registry.register_resource_rule(PathTraversalResourceRule())

    # Prompt rules
    registry.register_prompt_rule(PromptInjectionSurfaceRule())

    return registry
