"""
Indirect Prompt Injection Analyzer

Detects unsafe handling of external data that could allow malicious
instructions to be injected into LLM context through MCP tools.

Based on Section 5.2.2 of the research paper:
"Model Context Protocol (MCP): Landscape, Security Threats, and Future Research Directions"
"""

import ast
import re
from typing import List, Set, Optional, Dict, Any

from .base import BaseAnalyzer, Finding, Severity
from ..parsers.python_parser import MCPServerInfo, ToolDefinition
from ..patterns.signatures import (
    COMPILED_PROMPT_INJECTION,
    COMPILED_SANITIZATION,
)
from ..utils.helpers import truncate_string


class PromptInjectionAnalyzer(BaseAnalyzer):
    """
    Analyzer for detecting Indirect Prompt Injection vulnerabilities.

    Indirect prompt injection occurs when:
    1. An MCP tool fetches data from external sources (HTTP, files, databases)
    2. This data is returned to the LLM without sanitization
    3. Malicious content in the external data can manipulate the LLM

    Example attack scenario:
    - Attacker posts malicious instructions on a GitHub issue
    - MCP tool fetches GitHub issues and returns raw content
    - LLM follows the injected instructions from the issue
    """

    name = "Indirect Prompt Injection Analyzer"
    description = "Detects unsafe external data handling that enables prompt injection"
    vulnerability_type = "prompt_injection"

    # External data source patterns
    EXTERNAL_DATA_SOURCES = {
        "http_requests": {
            "pattern": r"requests\.(get|post|put|delete|patch)\s*\(",
            "description": "HTTP request via requests library",
        },
        "urllib": {
            "pattern": r"urllib\.request\.(urlopen|Request)",
            "description": "HTTP request via urllib",
        },
        "aiohttp": {
            "pattern": r"aiohttp\.(ClientSession|request)",
            "description": "Async HTTP request via aiohttp",
        },
        "httpx": {
            "pattern": r"httpx\.(get|post|put|delete|Client)",
            "description": "HTTP request via httpx",
        },
        "file_open": {
            "pattern": r"open\s*\([^)]+\)",
            "description": "File open operation",
        },
        "database_query": {
            "pattern": r"(cursor|conn|connection)\.(execute|query|fetchall|fetchone)",
            "description": "Database query operation",
        },
        "subprocess": {
            "pattern": r"subprocess\.(run|Popen|check_output|call)",
            "description": "Subprocess execution",
        },
    }

    RECOMMENDATIONS = {
        "requests_raw_return": (
            "Sanitize HTTP response content before returning to LLM context. "
            "Consider: 1) Validating response structure, 2) Stripping suspicious patterns, "
            "3) Using allowlists for expected content types."
        ),
        "urllib_raw_return": (
            "Sanitize URL content before returning. "
            "Implement content validation and strip any instruction-like text."
        ),
        "file_raw_return": (
            "Validate and sanitize file content before returning. "
            "Consider file type validation and content filtering."
        ),
        "database_raw_return": (
            "Sanitize database query results. Even trusted databases can contain "
            "user-generated content with malicious instructions."
        ),
        "subprocess_raw_return": (
            "CRITICAL: Never return raw subprocess output to LLM context. "
            "This can expose system information and enable command injection."
        ),
        "api_response_raw": (
            "Validate and sanitize API response data. External APIs can be "
            "compromised or return user-generated content with injected instructions."
        ),
        "user_input_concat": (
            "Never concatenate external content directly with prompts. "
            "Use structured data formats and explicit boundaries."
        ),
        "fstring_external_data": (
            "Avoid embedding external data in f-strings that become part of LLM context. "
            "Use separate data fields with clear boundaries."
        ),
    }

    def analyze(self, server_info: MCPServerInfo) -> List[Finding]:
        """
        Analyze all tools in an MCP server for prompt injection vulnerabilities.
        """
        self.reset()

        for tool in server_info.tools:
            tool_findings = self.analyze_tool(tool)
            self.findings.extend(tool_findings)

        return self.findings

    def analyze_tool(self, tool: ToolDefinition) -> List[Finding]:
        """
        Analyze a single tool for prompt injection vulnerabilities.
        """
        findings = []

        # Check for pattern-based vulnerabilities
        pattern_findings = self._check_patterns(tool)
        findings.extend(pattern_findings)

        # Use the fallback data-flow heuristic only when a more precise sink
        # signature did not already explain the same tool.
        if not pattern_findings:
            findings.extend(self._analyze_data_flow(tool))

        return findings

    def _check_patterns(self, tool: ToolDefinition) -> List[Finding]:
        """
        Check function body against known vulnerable patterns.
        """
        findings = []

        for pattern_name, pattern_info in COMPILED_PROMPT_INJECTION.items():
            matches = pattern_info["compiled"].finditer(tool.function_body)

            for match in matches:
                # A sanitizer elsewhere in the function is not proof that it is
                # applied to this value. Only recognize a sanitizer at the sink.
                match_line = tool.function_body[tool.function_body.rfind('\n', 0, match.start())+1:
                                                 tool.function_body.find('\n', match.end())]
                has_sanitization = self._check_sanitization(match_line)
                if has_sanitization:
                    continue  # Already sanitized, skip this finding

                severity_str = pattern_info["severity"]
                description_suffix = ""

                severity = self._get_severity(severity_str)
                line_offset = tool.function_body[:match.start()].count("\n")

                finding = self.create_finding(
                    severity=severity,
                    title=f"Prompt Injection Risk: {pattern_info['description']}",
                    description=(
                        f"External data is returned without apparent sanitization. "
                        f"This could allow injected content to manipulate the LLM.{description_suffix}"
                    ),
                    file_path=tool.source_file,
                    line_number=tool.line_number + line_offset,
                    function_name=tool.name,
                    matched_pattern=pattern_name,
                    matched_text=truncate_string(match.group(0), 100),
                    recommendation=self.RECOMMENDATIONS.get(
                        pattern_name,
                        "Implement sanitization for external data before returning to LLM."
                    ),
                    metadata={
                        "has_sanitization": has_sanitization,
                        "external_data_type": pattern_name,
                    }
                )
                findings.append(finding)

        return findings

    def _analyze_data_flow(self, tool: ToolDefinition) -> List[Finding]:
        """
        Perform simple data flow analysis to detect:
        1. External data being fetched
        2. That data being returned without transformation
        """
        findings = []

        try:
            # Parse the function body as a module to get a valid AST
            # We need to dedent and wrap it properly
            function_code = tool.function_body
            tree = ast.parse(function_code)
        except SyntaxError:
            return findings

        # Find external data sources
        external_sources = self._find_external_sources(tool.function_body)

        if not external_sources:
            return findings

        # Check if return statements include external data without sanitization
        for node in ast.walk(tree):
            if isinstance(node, ast.Return) and node.value:
                return_code = ast.unparse(node.value) if hasattr(ast, 'unparse') else str(node.value)

                # Check if return involves external data indicators
                for source_type, source_info in external_sources.items():
                    # Simple heuristic: check if return contains external data patterns
                    if any(indicator in return_code.lower() for indicator in
                           ['.text', '.content', '.json', '.read', 'fetch', 'response', 'result']):

                        # Check for sanitization
                        has_sanitization = self._check_sanitization(return_code)

                        if not has_sanitization:
                            finding = self.create_finding(
                                severity=Severity.MEDIUM,
                                title=f"Potential Prompt Injection: Unsanitized {source_type}",
                                description=(
                                    f"Function fetches external data ({source_info['description']}) "
                                    f"and may return it without sanitization. This could enable "
                                    f"indirect prompt injection if the external source is compromised."
                                ),
                                file_path=tool.source_file,
                                line_number=tool.line_number,
                                function_name=tool.name,
                                recommendation=(
                                    "Implement input validation and sanitization for all external data. "
                                    "Consider using allowlists, stripping HTML/markdown, and validating structure."
                                ),
                                metadata={
                                    "data_source": source_type,
                                    "return_statement": truncate_string(return_code, 100),
                                }
                            )
                            findings.append(finding)
                            break  # One finding per return is enough

        return findings

    def _find_external_sources(self, code: str) -> Dict[str, Dict[str, str]]:
        """
        Find all external data sources in the code.
        """
        sources = {}

        for source_name, source_info in self.EXTERNAL_DATA_SOURCES.items():
            if re.search(source_info["pattern"], code):
                sources[source_name] = source_info

        return sources

    def _check_sanitization(self, code: str) -> bool:
        """
        Check if code contains sanitization patterns.
        """
        for pattern in COMPILED_SANITIZATION:
            if pattern.search(code):
                return True
        return False

    def _get_severity(self, severity_str: str) -> Severity:
        """Convert severity string to Severity enum."""
        try:
            return Severity[severity_str.upper()]
        except KeyError:
            return Severity.MEDIUM

    def _reduce_severity(self, severity_str: str) -> str:
        """Reduce severity by one level."""
        reductions = {
            "CRITICAL": "HIGH",
            "HIGH": "MEDIUM",
            "MEDIUM": "LOW",
            "LOW": "INFO",
            "INFO": "INFO",
        }
        return reductions.get(severity_str.upper(), severity_str)

    def check_external_data_handling(self, code: str) -> Dict[str, Any]:
        """
        Utility method to check code for external data handling issues.
        Returns a summary of potential issues.

        Args:
            code: Source code to analyze.

        Returns:
            Dictionary with analysis results.
        """
        results = {
            "has_external_sources": False,
            "external_sources": [],
            "has_sanitization": False,
            "risk_level": "NONE",
            "issues": [],
        }

        # Find external sources
        sources = self._find_external_sources(code)
        if sources:
            results["has_external_sources"] = True
            results["external_sources"] = list(sources.keys())

        # Check sanitization
        results["has_sanitization"] = self._check_sanitization(code)

        # Determine risk level
        if results["has_external_sources"]:
            if results["has_sanitization"]:
                results["risk_level"] = "LOW"
            else:
                results["risk_level"] = "HIGH"

        # Check patterns
        for pattern_name, pattern_info in COMPILED_PROMPT_INJECTION.items():
            if pattern_info["compiled"].search(code):
                results["issues"].append({
                    "pattern": pattern_name,
                    "description": pattern_info["description"],
                    "severity": pattern_info["severity"],
                })

        return results
