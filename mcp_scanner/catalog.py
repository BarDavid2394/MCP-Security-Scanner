"""Versioned attack and rule catalog for the MCP security scanner."""

from dataclasses import dataclass
from typing import Dict, Tuple

CATALOG_VERSION = "2026.1"


@dataclass(frozen=True)
class AttackCategory:
    attack_id: str
    name: str
    source: str
    description: str
    fixable: bool = False


ATTACK_CATEGORIES: Dict[str, AttackCategory] = {
    "MCP01": AttackCategory("MCP01", "Token Mismanagement & Secret Exposure", "OWASP", "Secrets or credentials are exposed or reused unsafely."),
    "MCP02": AttackCategory("MCP02", "Privilege Escalation via Scope Creep", "OWASP", "Broad or weakly enforced scopes expand privileges."),
    "MCP03": AttackCategory("MCP03", "Tool Poisoning", "OWASP", "Malicious tool metadata manipulates model behavior.", True),
    "MCP04": AttackCategory("MCP04", "Software Supply Chain Attacks", "OWASP", "Mutable or untrusted dependencies can execute malicious code."),
    "MCP05": AttackCategory("MCP05", "Command Injection & Execution", "OWASP", "Untrusted values reach command or code execution sinks."),
    "MCP06": AttackCategory("MCP06", "Prompt Injection via Contextual Payloads", "OWASP", "Untrusted content can become model instructions.", True),
    "MCP07": AttackCategory("MCP07", "Insufficient Authentication & Authorization", "OWASP", "Operations lack identity or permission enforcement."),
    "MCP08": AttackCategory("MCP08", "Lack of Audit and Telemetry", "OWASP", "Sensitive operations cannot be reliably investigated."),
    "MCP09": AttackCategory("MCP09", "Shadow MCP Servers", "OWASP", "Unpinned or unmanaged server registrations bypass governance."),
    "MCP10": AttackCategory("MCP10", "Context Injection & Over-Sharing", "OWASP", "Context is shared across users, sessions, or trust boundaries."),
    "MCP11": AttackCategory("MCP11", "Confused Deputy", "MCP", "An OAuth proxy acts without per-client approval."),
    "MCP12": AttackCategory("MCP12", "Token Passthrough", "MCP", "A client token is forwarded without audience separation."),
    "MCP13": AttackCategory("MCP13", "Server-Side Request Forgery", "MCP", "Attacker-controlled URLs reach privileged destinations."),
    "MCP14": AttackCategory("MCP14", "Session Hijacking and Event Injection", "MCP", "Weak or unbound sessions permit impersonation."),
    "MCP15": AttackCategory("MCP15", "Unsafe OAuth Authorization URLs", "MCP", "Untrusted authorization URLs enable code execution."),
    "MCP16": AttackCategory("MCP16", "Local Server and stdio Proxy Compromise", "MCP", "Startup or proxy behavior executes unsafe local commands."),
}

RULES: Dict[str, Tuple[str, str]] = {
    "MCP01-SECRET-HARDCODED": ("MCP01", "Hard-coded secret or token"),
    "MCP01-SECRET-OUTPUT": ("MCP01", "Secret included in output or logs"),
    "MCP02-BROAD-SCOPE": ("MCP02", "Wildcard or administrative scope"),
    "MCP03-TOOL-POISON": ("MCP03", "Poisoned tool metadata"),
    "MCP04-MUTABLE-DEPENDENCY": ("MCP04", "Unpinned or mutable dependency"),
    "MCP04-INSTALL-HOOK": ("MCP04", "Dangerous dependency install hook"),
    "MCP05-COMMAND-INJECTION": ("MCP05", "Tool input reaches command execution"),
    "MCP05-DYNAMIC-CODE": ("MCP05", "Dynamic code evaluation"),
    "MCP06-UNTRUSTED-CONTEXT": ("MCP06", "External content reaches model context"),
    "MCP07-MISSING-AUTH": ("MCP07", "Network server lacks visible authorization"),
    "MCP07-PERMISSIVE-BIND": ("MCP07", "Broad bind lacks visible authorization"),
    "MCP08-MISSING-AUDIT": ("MCP08", "Sensitive tool lacks audit telemetry"),
    "MCP09-UNMANAGED-SERVER": ("MCP09", "Unmanaged server registration"),
    "MCP09-CONFUSABLE-NAME": ("MCP09", "Duplicate or confusable name"),
    "MCP10-SHARED-CONTEXT": ("MCP10", "Insufficiently scoped mutable context"),
    "MCP10-OVER-SHARING": ("MCP10", "Sensitive context returned"),
    "MCP11-CONFUSED-DEPUTY": ("MCP11", "OAuth proxy lacks per-client consent"),
    "MCP12-TOKEN-PASSTHROUGH": ("MCP12", "Inbound bearer token forwarded"),
    "MCP13-SSRF": ("MCP13", "Tool-controlled URL reaches network client"),
    "MCP13-METADATA-SSRF": ("MCP13", "OAuth metadata URL is unvalidated"),
    "MCP14-WEAK-SESSION": ("MCP14", "Predictable or unbound session"),
    "MCP14-SESSION-AUTH": ("MCP14", "Session identifier used as authentication"),
    "MCP15-UNSAFE-AUTH-URL": ("MCP15", "Authorization URL handled unsafely"),
    "MCP16-DANGEROUS-STARTUP": ("MCP16", "Dangerous local startup command"),
    "MCP16-ARBITRARY-SPAWN": ("MCP16", "Proxy can spawn attacker-controlled commands"),
}


def normalize_check(value: str | None) -> str | None:
    if value is None:
        return None
    legacy = {"tool-poisoning": "MCP03", "tool_poisoning": "MCP03",
              "prompt-injection": "MCP06", "prompt_injection": "MCP06"}
    normalized = legacy.get(value.lower(), value.upper())
    if normalized not in ATTACK_CATEGORIES and normalized not in RULES:
        raise ValueError(f"Unknown attack or rule: {value}")
    return normalized
