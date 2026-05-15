"""Rules for auditing MCP resource definitions."""

from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import unquote, urlparse

from mcp_security_auditor.core.models import Finding, Severity, TargetType
from mcp_security_auditor.rules.base import Rule

SENSITIVE_PATTERNS = [
    (re.compile(r"(^|/)(\.env(\..+)?|\.git(/.*)?|\.aws(/.*)?|\.kube(/.*)?|\.npmrc|\.pypirc)$", re.IGNORECASE), "Environment or configuration secret"),
    (re.compile(r"(^|/)(passwd|shadow|master\.passwd|htpasswd)$", re.IGNORECASE), "System credential or user database"),
    (re.compile(r"(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519|.*\.pem|.*\.key|.*\.pfx|.*\.pkcs12)$", re.IGNORECASE), "Cryptographic private key or certificate"),
    (re.compile(r"(credentials\.json|client_secrets\.json|service_account.*\.json)$", re.IGNORECASE), "API or service account credential"),
]

ROOT_FILESYSTEM_PATTERNS = [
    re.compile(r"^file:///(etc|root|var|private|proc|sys)(/.*)?$", re.IGNORECASE),
    re.compile(r"^file:///?$", re.IGNORECASE),
    re.compile(r"^file:///[a-zA-Z]:/?$", re.IGNORECASE),
]


class SensitiveResourceExposureRule(Rule):
    """Rule MCP-R001: Flags resources that point to known credential, key, or configuration files."""

    id = "MCP-R001"
    title = "Sensitive Credential or Configuration File Exposure"
    severity = Severity.HIGH
    cwe = "CWE-200"
    target_type = TargetType.RESOURCE
    description = (
        "The server registers a resource pointing to sensitive credentials, system accounts, "
        "cryptographic keys, or environment secrets."
    )
    remediation = (
        "Remove sensitive files from registered resources. Only expose application-specific "
        "assets from an isolated, designated public directory."
    )

    def evaluate(self, target: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        name = target.get("name", "unnamed_resource")
        uri = target.get("uri", "")

        decoded_uri = unquote(uri)
        path = urlparse(decoded_uri).path or decoded_uri

        for pattern, label in SENSITIVE_PATTERNS:
            if pattern.search(path) or pattern.search(name):
                findings.append(
                    self.create_finding(
                        target_name=f"Resource: {name}",
                        specific_description=(
                            f"Resource '{name}' ({uri}) references a sensitive path: {label}."
                        ),
                        details={"resource_name": name, "uri": uri, "category": label},
                    )
                )
                break

        return findings


class RootFilesystemExposureRule(Rule):
    """Rule MCP-R002: Flags resources mapped directly to the root filesystem or sensitive OS trees."""

    id = "MCP-R002"
    title = "Root or System Filesystem Resource Exposure"
    severity = Severity.MEDIUM
    cwe = "CWE-552"
    target_type = TargetType.RESOURCE
    description = (
        "The server exposes the root filesystem ('file:///') or core operating system "
        "directories, granting broad read access across the host machine."
    )
    remediation = (
        "Constrain resource roots to explicit workspace subdirectories. Avoid mounting "
        "the root drive or system directories."
    )

    def evaluate(self, target: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        name = target.get("name", "unnamed_resource")
        uri = target.get("uri", "")

        decoded_uri = unquote(uri)

        for pattern in ROOT_FILESYSTEM_PATTERNS:
            if pattern.search(decoded_uri):
                findings.append(
                    self.create_finding(
                        target_name=f"Resource: {name}",
                        specific_description=(
                            f"Resource '{name}' exposes a broad system or root path: '{uri}'."
                        ),
                        details={"resource_name": name, "uri": uri},
                    )
                )
                break

        return findings


class PathTraversalResourceRule(Rule):
    """Rule MCP-R003: Detects path traversal sequences in resource URIs or unconstrained URI templates."""

    id = "MCP-R003"
    title = "Path Traversal Sequence in Resource URI"
    severity = Severity.HIGH
    cwe = "CWE-22"
    target_type = TargetType.RESOURCE
    description = (
        "The resource URI or URI template contains path traversal sequences ('../', '..\\') "
        "or unconstrained path wildcards that can escape the application sandbox."
    )
    remediation = (
        "Normalize and sanitize resource URIs. Disallow relative traversal sequences "
        "and validate all URI template variables against a strict allowlist."
    )

    def evaluate(self, target: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        name = target.get("name", "unnamed_resource")
        uri = target.get("uri", "") or target.get("uriTemplate", "")

        decoded_uri = unquote(uri)

        traversal_pattern = re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.$)", re.IGNORECASE)
        unconstrained_template = re.compile(r"^file:///(?:\{[^\}]+\}|\*[^\/]*)$", re.IGNORECASE)

        if traversal_pattern.search(decoded_uri) or unconstrained_template.search(decoded_uri):
            findings.append(
                self.create_finding(
                    target_name=f"Resource: {name}",
                    specific_description=(
                        f"Resource '{name}' contains directory traversal sequences or unconstrained "
                        f"root wildcards in its URI: '{uri}'."
                    ),
                    details={"resource_name": name, "uri": uri},
                )
            )

        return findings
