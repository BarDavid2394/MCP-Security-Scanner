"""
Tool Poisoning Analyzer

Detects malicious instructions hidden in MCP tool descriptions/metadata
that could trick LLMs into performing unauthorized actions.

Based on Section 5.1.4 of the research paper:
"Model Context Protocol (MCP): Landscape, Security Threats, and Future Research Directions"
"""

import ast
import re
from ..metadata_instructions import instruction_signals, mask_reported_examples
import base64
import binascii
from typing import List, Optional

from .base import BaseAnalyzer, Finding, Severity
from ..parsers.python_parser import MCPServerInfo, ToolDefinition
from ..patterns.signatures import (
    COMPILED_TOOL_POISONING,
    COMPILED_SANITIZATION,
)
from ..utils.helpers import extract_context, truncate_string
from ..metadata_behavior import discrepancies
from ..reachable_python import ReachablePython


class ToolPoisoningAnalyzer(BaseAnalyzer):
    """
    Analyzer for detecting Tool Poisoning vulnerabilities.

    Tool poisoning occurs when malicious actors embed covert instructions
    in tool descriptions/docstrings that trick LLMs into:
    - Reading sensitive files (SSH keys, credentials)
    - Exfiltrating data to external URLs
    - Executing unauthorized commands
    - Chaining with other tools maliciously
    """

    name = "Tool Poisoning Analyzer"
    description = "Detects malicious instructions hidden in tool descriptions"
    vulnerability_type = "tool_poisoning"

    # These patterns are useful supporting evidence but are common in legitimate
    # documentation. Report them only when the same metadata also contains a
    # stronger concealment, override, exfiltration, or unauthorized-action signal.
    CONTEXTUAL_PATTERNS = {
        "invisible_unicode",
        "url_in_description",
        "command_execution",
        "file_read_instruction",
        "sequential_actions",
        "sensitive_paths",
        "imperative_must",
        "tool_chaining",
        "preference_manipulation",
    }
    BODY_PRIMARY_PATTERNS = {
        "html_hidden_instruction",
        "override_instructions",
        "data_exfiltration",
    }

    # Recommendations for each pattern type
    RECOMMENDATIONS = {
        "hidden_instruction_brackets": (
            "Remove bracketed instruction markers. Tool descriptions should only "
            "contain factual information about the tool's purpose, not behavioral instructions."
        ),
        "file_read_instruction": (
            "Remove file access instructions from descriptions. If file reading is "
            "the tool's legitimate purpose, describe it without imperative commands."
        ),
        "data_exfiltration": (
            "Remove data transmission instructions. Tool descriptions should never "
            "instruct to send data to external endpoints."
        ),
        "url_in_description": (
            "Avoid including URLs in tool descriptions unless absolutely necessary. "
            "URLs can be used for data exfiltration attacks."
        ),
        "command_execution": (
            "Remove command execution instructions. Describe what the tool does, "
            "not what actions the LLM should take."
        ),
        "sequential_actions": (
            "Remove sequential action instructions. Tool descriptions should not "
            "chain actions or instruct follow-up behaviors."
        ),
        "override_instructions": (
            "CRITICAL: Remove instructions that override rules or ignore restrictions. "
            "This is a strong indicator of malicious intent."
        ),
        "sensitive_paths": (
            "Remove references to sensitive file paths. Tool descriptions should not "
            "mention specific system files, SSH keys, or credentials."
        ),
        "imperative_must": (
            "Rephrase imperative statements. Use declarative descriptions instead of "
            "commanding language like 'must', 'always', 'should'."
        ),
        "tool_chaining": (
            "Remove instructions to call other tools. Tool chaining should be "
            "determined by the LLM based on user intent, not hardcoded in descriptions."
        ),
        "preference_manipulation": (
            "Remove self-promotional language. Tool descriptions should be objective "
            "and not attempt to bias tool selection."
        ),
        "invisible_unicode": "Remove invisible and bidirectional Unicode controls from tool metadata.",
        "html_hidden_instruction": "Remove hidden HTML-comment instructions from tool metadata.",
        "cross_tool_prerequisite": (
            "Remove mandatory cross-tool instructions. Tool selection and sequencing must "
            "follow the user's request rather than directives embedded in tool metadata."
        ),
        "user_intent_override": "Remove metadata that claims precedence over the user's request.",
        "forced_argument_change": (
            "Remove instructions that silently alter another tool's arguments or the user's request."
        ),
        "concealed_action": "Remove instructions to hide tool actions or results from the user.",
        "mandatory_shell_command": (
            "Remove shell commands mandated by tool metadata. Tool descriptions must not require "
            "unrelated command execution as a prerequisite or follow-up action."
        ),
        "coerced_followup_action": (
            "Remove metadata that coerces an extra action or silently changes the requested operation."
        ),
    }

    def analyze(self, server_info: MCPServerInfo) -> List[Finding]:
        """
        Analyze all tools in an MCP server for poisoning vulnerabilities.
        """
        self.reset()
        try:
            behavior = ReachablePython(ast.parse(server_info.source_code))
        except SyntaxError:
            behavior = None

        for tool in server_info.tools:
            tool_findings = self.analyze_tool(tool)
            self.findings.extend(tool_findings)
            if behavior is not None and isinstance(tool.raw_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for line, pattern, reason, path in discrepancies(behavior, tool.raw_node, tool.parameters, tool.full_description):
                    finding = self.create_finding(severity=Severity.MEDIUM,
                        title='Tool Poisoning: advertised behavior needs review', description=reason,
                        file_path=tool.source_file, line_number=line, function_name=tool.name,
                        matched_pattern=pattern, matched_text=pattern,
                        recommendation='Review the visible implementation and disclose sensitive behavior accurately.',
                        metadata={'source':'description_vs_reachable_behavior', 'needs_semantic_review':True, 'call_path':list(path)})
                    finding.fixable = False
                    self.findings.append(finding)

        return self.findings

    def analyze_tool(self, tool: ToolDefinition) -> List[Finding]:
        """
        Analyze a single tool for poisoning patterns.
        """
        findings = []

        # Combine all text that could contain malicious instructions
        texts_to_analyze = [
            ("description", tool.description),
            ("docstring", tool.docstring or ""),
        ]
        for source_name, text in list(texts_to_analyze):
            if not text: continue
            for token in re.findall(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,8192}={0,2}(?![A-Za-z0-9+/])", text)[:5]:
                try:
                    decoded = base64.b64decode(token, validate=True).decode("utf-8")
                    if decoded and all(c.isprintable() or c in "\r\n\t" for c in decoded):
                        texts_to_analyze.append(("decoded_"+source_name, decoded))
                except (ValueError, UnicodeError, binascii.Error): pass

        for source_name, text in texts_to_analyze:
            if not text:
                continue
            for signal, excerpt in instruction_signals(text):
                if excerpt.casefold() in text.casefold() and any(
                        name not in self.CONTEXTUAL_PATTERNS and info["compiled"].fullmatch(excerpt)
                        for name, info in COMPILED_TOOL_POISONING.items()):
                    # Preserve the existing high-confidence literal fixer path;
                    # do not add a duplicate report-only finding for that span.
                    continue
                finding = self.create_finding(
                    severity=Severity.HIGH, title="Tool Poisoning: assistant-directed instruction",
                    description="Untrusted tool metadata directs a policy override or disclosure of sensitive information.",
                    file_path=tool.source_file, line_number=tool.line_number, function_name=tool.name,
                    matched_pattern="metadata_" + signal, matched_text=truncate_string(excerpt, 100),
                    recommendation="Review the instruction in context and remove unauthorized behavior from metadata.",
                    code_snippet=truncate_string(text, 200),
                    metadata={"source": source_name, "needs_semantic_review": True})
                finding.fixable = False
                findings.append(finding)
            text = mask_reported_examples(text)
            normalized = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069]", "", text)

            strong_signal = any(
                pattern_name not in self.CONTEXTUAL_PATTERNS
                and pattern_info["compiled"].search(normalized)
                for pattern_name, pattern_info in COMPILED_TOOL_POISONING.items()
            )

            # Check each poisoning pattern
            for pattern_name, pattern_info in COMPILED_TOOL_POISONING.items():
                if pattern_name in self.CONTEXTUAL_PATTERNS and not strong_signal:
                    continue
                matches = pattern_info["compiled"].finditer(text if pattern_name == "invisible_unicode" else normalized)

                for match in matches:
                    severity = self._get_severity(pattern_info["severity"])
                    matched_text = match.group(0)

                    finding = self.create_finding(
                        severity=severity,
                        title=f"Tool Poisoning: {pattern_info['description']}",
                        description=(
                            f"Suspicious pattern detected in tool {source_name}. "
                            f"This pattern could be used to trick an LLM into "
                            f"performing unauthorized actions."
                        ),
                        file_path=tool.source_file,
                        line_number=tool.line_number,
                        function_name=tool.name,
                        matched_pattern=pattern_name,
                        matched_text=truncate_string(matched_text, 100),
                        recommendation=self.RECOMMENDATIONS.get(pattern_name, "Review and remove suspicious content."),
                        code_snippet=truncate_string(text, 200),
                        metadata={
                            "source": source_name,
                            "pattern_example": pattern_info.get("example", ""),
                            "full_match": matched_text,
                        }
                    )
                    findings.append(finding)
                    if (source_name.startswith("decoded_") or tool.description_derived
                            or pattern_name in {"system_role_impersonation", "system_safety_bypass"}):
                        finding.fixable = False

        # Also analyze the function body for hidden instructions in strings
        body_findings = self._analyze_function_body(tool)
        findings.extend(body_findings)
        mismatch = self._description_behavior_mismatch(tool)
        if mismatch:
            findings.append(mismatch)

        return findings

    def _description_behavior_mismatch(self, tool: ToolDefinition):
        """Flag a narrow, reviewable metadata/implementation contradiction."""
        description = tool.full_description.lower()
        body = tool.implementation_source or tool.function_body
        if not description or not body:
            return None
        benign_claim = re.search(r"\b(calculate|format|convert|summari[sz]e|weather|time|echo|status|lookup|read[- ]?only)\b", description)
        sensitive = re.search(
            r"(?i)(?:subprocess\.|os\.system|child_process|execSync\s*\(|spawn\s*\(|"
            r"os\.environ|process\.env|readFileSync\s*\(|writeFile(?:Sync)?\s*\(|unlink(?:Sync)?\s*\(|"
            r"rmSync\s*\(|rmtree\s*\(|open\s*\([^)]*(?:ssh|aws|token|secret))",
            body,
        )
        disclosure = re.search(r"(?i)\b(shell|command|process|credential|secret|environment|file)\b", description)
        if not benign_claim or not sensitive or disclosure:
            return None
        return self.create_finding(
            severity=Severity.MEDIUM,
            title="Tool Poisoning: description and implementation differ",
            description="The advertised benign behavior conflicts with sensitive process, file, or credential access in the implementation.",
            file_path=tool.source_file,
            line_number=tool.implementation_line or tool.line_number,
            function_name=tool.name,
            matched_pattern="description_behavior_mismatch",
            matched_text=truncate_string(sensitive.group(0), 100),
            recommendation="Make tool metadata accurately disclose sensitive behavior and require explicit authorization.",
            metadata={"source": "description_vs_implementation", "advertised": benign_claim.group(0),
                      "behavior": sensitive.group(0), "needs_semantic_review": True},
        )

    def _analyze_function_body(self, tool: ToolDefinition) -> List[Finding]:
        """
        Analyze function body for suspicious string literals.
        """
        findings = []

        try:
            tree = ast.parse(tool.function_body)
        except SyntaxError:
            return findings

        docstring_nodes = set()
        for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
            if function.body and isinstance(function.body[0], ast.Expr):
                value = function.body[0].value
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    docstring_nodes.add(id(value))

        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            if id(node) in docstring_nodes:
                continue
            string_content = node.value
            if len(string_content) < 20 or string_content == tool.docstring:
                continue

            # Check this string against poisoning patterns
            for pattern_name, pattern_info in COMPILED_TOOL_POISONING.items():
                if pattern_name not in self.BODY_PRIMARY_PATTERNS:
                    continue
                if pattern_info["compiled"].search(string_content):
                    # Calculate approximate line number
                    line_number = tool.line_number + getattr(node, "lineno", 1) - 1

                    finding = self.create_finding(
                        severity=self._get_severity(pattern_info["severity"]),
                        title=f"Tool Poisoning in Code: {pattern_info['description']}",
                        description=(
                            f"Suspicious pattern found in string literal within function body. "
                            f"This could be used for injection attacks."
                        ),
                        file_path=tool.source_file,
                        line_number=line_number,
                        function_name=tool.name,
                        matched_pattern=pattern_name,
                        matched_text=truncate_string(string_content, 100),
                        recommendation="Review string literals for hidden instructions.",
                        metadata={
                            "source": "function_body",
                            "pattern_example": pattern_info.get("example", ""),
                        }
                    )
                    findings.append(finding)
                    break  # One finding per string is enough

        return findings

    def _get_severity(self, severity_str: str) -> Severity:
        """Convert severity string to Severity enum."""
        try:
            return Severity[severity_str.upper()]
        except KeyError:
            return Severity.MEDIUM

    def analyze_text(self, text: str, source: str = "unknown") -> List[Finding]:
        """
        Analyze arbitrary text for poisoning patterns.
        Useful for testing or analyzing non-standard sources.

        Args:
            text: Text to analyze.
            source: Description of the text source.

        Returns:
            List of findings.
        """
        findings = []

        for pattern_name, pattern_info in COMPILED_TOOL_POISONING.items():
            matches = pattern_info["compiled"].finditer(text)

            for match in matches:
                severity = self._get_severity(pattern_info["severity"])

                finding = self.create_finding(
                    severity=severity,
                    title=f"Tool Poisoning: {pattern_info['description']}",
                    description=f"Suspicious pattern detected in {source}.",
                    file_path=source,
                    line_number=text[:match.start()].count("\n") + 1,
                    matched_pattern=pattern_name,
                    matched_text=truncate_string(match.group(0), 100),
                    recommendation=self.RECOMMENDATIONS.get(pattern_name, "Review and remove suspicious content."),
                )
                findings.append(finding)

        return findings
