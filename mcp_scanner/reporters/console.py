"""
Console Reporter - Pretty prints findings to terminal.
"""

from typing import List, Dict, Any
from ..analyzers.base import Finding, Severity
from .colors import SEVERITY_COLORS


class ConsoleReporter:
    """
    Reports security findings to the console with colored output.
    """

    # ANSI color codes
    COLORS = {
        **{level: colors[0] for level, colors in SEVERITY_COLORS.items()},
        "RESET": "\033[0m",
        "BOLD": "\033[1m",
        "DIM": "\033[2m",
    }

    # Severity symbols
    SYMBOLS = {
        "CRITICAL": "[!!!]",
        "HIGH": "[!!]",
        "MEDIUM": "[!]",
        "LOW": "[*]",
        "INFO": "[i]",
    }

    def __init__(self, use_colors: bool = True, verbose: bool = False):
        """
        Initialize console reporter.

        Args:
            use_colors: Whether to use ANSI color codes.
            verbose: Whether to show detailed output.
        """
        self.use_colors = use_colors
        self.verbose = verbose

    def _color(self, text: str, color_name: str) -> str:
        """Apply color to text if colors are enabled."""
        if not self.use_colors:
            return text
        color = self.COLORS.get(color_name, "")
        reset = self.COLORS["RESET"]
        return f"{color}{text}{reset}"

    def _severity_color(self, severity: Severity) -> str:
        """Get color name for severity level."""
        return severity.value

    def report(self, findings: List[Finding], scan_info: Dict[str, Any] = None):
        """
        Print findings to console.

        Args:
            findings: List of security findings.
            scan_info: Optional scan metadata (files scanned, time, etc.)
        """
        self._print_header()

        if scan_info:
            self._print_scan_info(scan_info)

        if not findings:
            print(self._color("\n  No vulnerabilities found.", "GREEN"))
            print()
            return

        # Group findings by severity
        by_severity = self._group_by_severity(findings)

        # Print findings by severity (critical first)
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            if severity in by_severity:
                for finding in by_severity[severity]:
                    self._print_finding(finding)

        # Print summary
        self._print_summary(findings)

    def _print_header(self):
        """Print scanner header."""
        header = """
================================================================
          MCP Security Scanner v2.0
    OWASP MCP Top 10 + MCP Security Best Practices
================================================================
"""
        print(self._color(header, "BOLD"))

    def _print_scan_info(self, scan_info: Dict[str, Any]):
        """Print scan metadata."""
        print(self._color("Scan Information:", "BOLD"))
        if "files_scanned" in scan_info:
            print(f"  Files scanned: {scan_info['files_scanned']}")
        if "tools_analyzed" in scan_info:
            print(f"  Tools analyzed: {scan_info['tools_analyzed']}")
        if "target" in scan_info:
            print(f"  Target: {scan_info['target']}")
        print()

    def _print_finding(self, finding: Finding):
        """Print a single finding."""
        severity = finding.severity.value
        symbol = self.SYMBOLS.get(severity, "[?]")
        color = self._severity_color(finding.severity)

        # Header line
        header = f"{symbol} {severity}: {finding.title}"
        print(self._color(header, color))

        # Location
        location = f"    Location: {finding.file_path}:{finding.line_number}"
        if finding.function_name:
            location += f" (function: {finding.function_name})"
        print(self._color(location, "DIM"))

        # Description
        print(f"    Issue: {finding.description}")

        # Matched text (if available)
        if finding.matched_text:
            print(f"    Match: \"{finding.matched_text}\"")

        # Recommendation
        if finding.recommendation:
            print(self._color(f"    Fix: {finding.recommendation}", "DIM"))

        review = finding.metadata.get("llm_review")
        if review:
            print(f"    Semantic review: {review.get('verdict')} ({review.get('confidence', 0):.0%})")
            print(self._color(f"    Review reason: {review.get('reason', '')}", "DIM"))

        evidence = finding.metadata.get("evidence")
        if isinstance(evidence, dict):
            source, sink = evidence.get("source"), evidence.get("sink")
            if source or sink:
                print(f"    Flow: {source or '?'} -> {sink or '?'}")
            path = evidence.get("path") or []
            if path:
                print(self._color("    Path: " + " -> ".join(map(str, path)), "DIM"))
            protections = evidence.get("protections") or []
            missing = evidence.get("missing_protections") or []
            if protections:
                print(self._color("    Protections: " + ", ".join(map(str, protections)), "DIM"))
            if missing:
                print(self._color("    Missing: " + ", ".join(map(str, missing)), "DIM"))

        # Code snippet (if verbose)
        if self.verbose and finding.code_snippet:
            print(self._color("    Code:", "DIM"))
            for line in finding.code_snippet.split("\n")[:5]:
                print(self._color(f"      {line}", "DIM"))

        print()

    def _print_summary(self, findings: List[Finding]):
        """Print summary of findings."""
        summary = self._calculate_summary(findings)

        print(self._color("-" * 60, "DIM"))
        print(self._color("Summary:", "BOLD"))

        total = sum(summary.values())
        print(f"  Total findings: {total}")
        fixable = sum(1 for finding in findings if finding.fixable)
        print(f"  Potentially fixable (MCP03/MCP06): {fixable}")

        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = summary.get(severity.value, 0)
            if count > 0:
                color = self._severity_color(severity)
                print(self._color(f"    {severity.value}: {count}", color))

        # Risk assessment
        if summary.get("CRITICAL", 0) > 0:
            risk = "CRITICAL - Immediate action required!"
            risk_color = "CRITICAL"
        elif summary.get("HIGH", 0) > 0:
            risk = "HIGH - Review and fix recommended"
            risk_color = "HIGH"
        elif summary.get("MEDIUM", 0) > 0:
            risk = "MEDIUM - Consider addressing these issues"
            risk_color = "MEDIUM"
        else:
            risk = "LOW - Minor issues found"
            risk_color = "LOW"

        print()
        print(self._color(f"  Risk Level: {risk}", risk_color))
        print()

    def _group_by_severity(self, findings: List[Finding]) -> Dict[Severity, List[Finding]]:
        """Group findings by severity level."""
        grouped = {}
        for finding in findings:
            severity = finding.severity
            if severity not in grouped:
                grouped[severity] = []
            grouped[severity].append(finding)
        return grouped

    def _calculate_summary(self, findings: List[Finding]) -> Dict[str, int]:
        """Calculate summary statistics."""
        summary = {}
        for finding in findings:
            severity = finding.severity.value
            summary[severity] = summary.get(severity, 0) + 1
        return summary
