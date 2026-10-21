"""
JSON Reporter - Outputs findings in JSON format.
"""

import json
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path

from ..analyzers.base import Finding
from ..catalog import CATALOG_VERSION


class JsonReporter:
    """
    Reports security findings in JSON format.
    Suitable for CI/CD integration and programmatic processing.
    """

    def __init__(self, pretty: bool = True):
        """
        Initialize JSON reporter.

        Args:
            pretty: Whether to pretty-print JSON output.
        """
        self.pretty = pretty

    def report(
        self,
        findings: List[Finding],
        scan_info: Dict[str, Any] = None,
        output_file: str = None
    ) -> str:
        """
        Generate JSON report.

        Args:
            findings: List of security findings.
            scan_info: Optional scan metadata.
            output_file: Optional file path to write report.

        Returns:
            JSON string of the report.
        """
        report_data = self._build_report(findings, scan_info)

        if self.pretty:
            json_str = json.dumps(report_data, indent=2, default=str)
        else:
            json_str = json.dumps(report_data, default=str)

        if output_file:
            Path(output_file).write_text(json_str, encoding="utf-8")

        return json_str

    def _build_report(
        self,
        findings: List[Finding],
        scan_info: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Build the report data structure."""
        report = {
            "scanner": "MCP Security Scanner",
            "version": "2.0.0",
            "catalog_version": CATALOG_VERSION,
            "timestamp": datetime.now().isoformat(),
            "scan_info": scan_info or {},
            "summary": self._calculate_summary(findings),
            "findings": [f.to_dict() for f in findings],
        }
        return report

    def _calculate_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        """Calculate summary statistics."""
        summary = {
            "total": len(findings),
            "by_severity": {},
            "by_type": {},
            "by_attack": {},
            "by_rule": {},
            "by_confidence": {},
            "fixable": 0,
            "risk_score": 0,
        }

        for finding in findings:
            # Count by severity
            severity = finding.severity.value
            summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1

            # Count by vulnerability type
            vuln_type = finding.vulnerability_type
            summary["by_type"][vuln_type] = summary["by_type"].get(vuln_type, 0) + 1

            if finding.attack_id:
                summary["by_attack"][finding.attack_id] = summary["by_attack"].get(finding.attack_id, 0) + 1
            if finding.rule_id:
                summary["by_rule"][finding.rule_id] = summary["by_rule"].get(finding.rule_id, 0) + 1
            summary["by_confidence"][finding.confidence] = summary["by_confidence"].get(finding.confidence, 0) + 1
            if finding.fixable:
                summary["fixable"] += 1

            # Calculate risk score
            summary["risk_score"] += finding.severity.score

        # Determine overall risk level
        if summary["by_severity"].get("CRITICAL", 0) > 0:
            summary["risk_level"] = "CRITICAL"
        elif summary["by_severity"].get("HIGH", 0) > 0:
            summary["risk_level"] = "HIGH"
        elif summary["by_severity"].get("MEDIUM", 0) > 0:
            summary["risk_level"] = "MEDIUM"
        elif summary["by_severity"].get("LOW", 0) > 0:
            summary["risk_level"] = "LOW"
        else:
            summary["risk_level"] = "NONE"

        return summary


def findings_to_sarif(findings: List[Finding], tool_name: str = "mcp-scanner") -> Dict[str, Any]:
    """
    Convert findings to SARIF format for GitHub Advanced Security integration.

    Args:
        findings: List of security findings.
        tool_name: Name of the scanning tool.

    Returns:
        SARIF-formatted dictionary.
    """
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": "2.0.0",
                    "informationUri": "https://github.com/mcp-security/mcp-scanner",
                    "rules": _get_sarif_rules(findings),
                }
            },
            "results": [_finding_to_sarif_result(f) for f in findings],
        }]
    }
    return sarif


def _get_sarif_rules(findings: List[Finding]) -> List[Dict[str, Any]]:
    """Extract unique rules from findings."""
    rules = {}
    for finding in findings:
        rule_id = finding.matched_pattern or finding.vulnerability_type
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.description[:100]},
                "fullDescription": {"text": finding.description},
                "help": {"text": finding.recommendation or "No recommendation available"},
                "defaultConfiguration": {
                    "level": _severity_to_sarif_level(finding.severity.value)
                }
            }
    return list(rules.values())


def _finding_to_sarif_result(finding: Finding) -> Dict[str, Any]:
    """Convert a finding to SARIF result format."""
    return {
        "ruleId": finding.matched_pattern or finding.vulnerability_type,
        "level": _severity_to_sarif_level(finding.severity.value),
        "message": {"text": finding.description},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": finding.file_path},
                "region": {"startLine": finding.line_number}
            }
        }],
    }


def _severity_to_sarif_level(severity: str) -> str:
    """Convert severity to SARIF level."""
    mapping = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }
    return mapping.get(severity, "warning")
