"""
MCP Security Fixer - Auto-remediation for detected vulnerabilities.

Workflow:
1. Scan target for vulnerabilities
2. Apply automated fixes
3. Optionally verify fixes with rescan
"""

import shutil
from pathlib import Path
from datetime import datetime
from typing import List, Optional
from dataclasses import dataclass, field

from .scanner import MCPScanner, ScanResult
from .defenses.transforms import CodeTransformer, TransformResult
from .utils.helpers import get_python_files


@dataclass
class FixResult:
    """Result of fixing a single file."""
    filepath: str
    original_issues: int
    fixes_applied: int
    changes: List[str] = field(default_factory=list)
    backup_path: Optional[str] = None
    success: bool = True
    error: Optional[str] = None


@dataclass
class FixReport:
    """Complete report of fix operation."""
    target: str
    files_scanned: int
    files_fixed: int
    total_issues_before: int
    total_issues_after: int
    total_fixes_applied: int
    other_issues_before: int = 0
    other_issues_after: int = 0
    file_results: List[FixResult] = field(default_factory=list)
    verification_passed: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    @property
    def all_fixed(self) -> bool:
        return self.total_issues_after == 0


class MCPFixer:
    """
    Auto-fixer for MCP security vulnerabilities.

    Usage:
        fixer = MCPFixer()
        report = fixer.fix("server.py", verify=True)
    """

    def __init__(
        self,
        create_backup: bool = True,
        dry_run: bool = False,
        verbose: bool = False,
        categories=None,
    ):
        """
        Initialize the fixer.

        Args:
            create_backup: Create .bak backup before modifying files
            dry_run: Preview changes without writing to files
            verbose: Enable verbose output
            categories: Non-empty selection of MCP03/MCP06 (default: both).
        """
        self.create_backup = create_backup
        self.dry_run = dry_run
        self.verbose = verbose
        self.categories = frozenset({"MCP03", "MCP06"} if categories is None else categories)
        if not self.categories or not self.categories <= {"MCP03", "MCP06"}:
            raise ValueError("Automatic fixes support only MCP03 and MCP06")
        self.scanner = MCPScanner()
        self.transformer = CodeTransformer()

    def fix(self, target: str, verify: bool = False) -> FixReport:
        """
        Fix vulnerabilities in target file or directory.

        Args:
            target: Path to file or directory
            verify: Run verification scan after fixing

        Returns:
            FixReport with complete results
        """
        target_path = Path(target)

        if target_path.is_file():
            return self._fix_file_workflow(target_path, verify)
        elif target_path.is_dir():
            return self._fix_directory_workflow(target_path, verify)
        else:
            report = FixReport(
                target=str(target),
                files_scanned=0,
                files_fixed=0,
                total_issues_before=0,
                total_issues_after=0,
                total_fixes_applied=0,
            )
            report.file_results.append(FixResult(
                filepath=str(target),
                original_issues=0,
                fixes_applied=0,
                success=False,
                error=f"Target not found: {target}"
            ))
            return report

    def _fix_file_workflow(self, filepath: Path, verify: bool) -> FixReport:
        """Fix a single file."""
        # Initial scan
        initial_scan = self.scanner.scan_file(filepath)

        targeted_scan = self._targeted_scan(initial_scan)
        report = FixReport(
            target=str(filepath),
            files_scanned=1,
            files_fixed=0,
            total_issues_before=targeted_scan.total_findings,
            total_issues_after=targeted_scan.total_findings,
            total_fixes_applied=0,
            other_issues_before=initial_scan.total_findings - targeted_scan.total_findings,
            other_issues_after=initial_scan.total_findings - targeted_scan.total_findings,
        )

        if targeted_scan.total_findings == 0:
            report.verification_passed = True
            return report

        # Apply fixes
        fix_result = self._fix_file(filepath, targeted_scan)
        report.file_results.append(fix_result)

        if fix_result.success and fix_result.fixes_applied > 0:
            report.files_fixed = 1
            report.total_fixes_applied = fix_result.fixes_applied

        # Verification scan
        if verify and not self.dry_run:
            verify_scan = self.scanner.scan_file(filepath)
            verify_targeted = self._targeted_scan(verify_scan)
            report.total_issues_after = verify_targeted.total_findings
            report.other_issues_after = verify_scan.total_findings - verify_targeted.total_findings
            report.verification_passed = verify_targeted.total_findings == 0

        return report

    def _fix_directory_workflow(self, directory: Path, verify: bool) -> FixReport:
        """Fix all files in a directory."""
        # Initial scan
        initial_scan = self.scanner.scan_directory(directory)

        targeted_scan = self._targeted_scan(initial_scan)
        report = FixReport(
            target=str(directory),
            files_scanned=initial_scan.files_scanned,
            files_fixed=0,
            total_issues_before=targeted_scan.total_findings,
            total_issues_after=targeted_scan.total_findings,
            total_fixes_applied=0,
            other_issues_before=initial_scan.total_findings - targeted_scan.total_findings,
            other_issues_after=initial_scan.total_findings - targeted_scan.total_findings,
        )

        if targeted_scan.total_findings == 0:
            report.verification_passed = True
            return report

        # Group findings by file
        findings_by_file = {}
        for finding in targeted_scan.findings:
            filepath = finding.file_path
            if filepath not in findings_by_file:
                findings_by_file[filepath] = []
            findings_by_file[filepath].append(finding)

        # Fix each file with issues
        for filepath, findings in findings_by_file.items():
            file_scan = ScanResult()
            file_scan.findings = findings

            fix_result = self._fix_file(Path(filepath), file_scan)
            report.file_results.append(fix_result)

            if fix_result.success and fix_result.fixes_applied > 0:
                report.files_fixed += 1
                report.total_fixes_applied += fix_result.fixes_applied

        # Verification scan
        if verify and not self.dry_run:
            verify_scan = self.scanner.scan_directory(directory)
            verify_targeted = self._targeted_scan(verify_scan)
            report.total_issues_after = verify_targeted.total_findings
            report.other_issues_after = verify_scan.total_findings - verify_targeted.total_findings
            report.verification_passed = verify_targeted.total_findings == 0

        return report

    def _targeted_scan(self, scan_result: ScanResult) -> ScanResult:
        """Keep only the two categories this fixer is authorized to modify."""
        targeted = ScanResult(
            files_scanned=scan_result.files_scanned,
            tools_analyzed=scan_result.tools_analyzed,
            servers_found=scan_result.servers_found,
            parse_errors=list(scan_result.parse_errors),
        )
        targeted.findings = [
            finding for finding in scan_result.findings
            if (finding.attack_id or {"tool_poisoning": "MCP03", "prompt_injection": "MCP06"}.get(
                finding.vulnerability_type)) in self.categories
        ]
        return targeted

    def _fix_file(self, filepath: Path, scan_result: ScanResult) -> FixResult:
        """Apply fixes to a single file."""
        result = FixResult(
            filepath=str(filepath),
            original_issues=scan_result.total_findings,
            fixes_applied=0,
        )

        try:
            # Read source code
            source_code = filepath.read_text(encoding='utf-8')

            # Transform code
            transform_result = self.transformer.transform(source_code, scan_result.findings)

            if not transform_result.success:
                result.success = False
                result.error = transform_result.error
                return result

            if not transform_result.changes_made:
                # No changes needed
                return result

            result.changes = transform_result.changes_made
            result.fixes_applied = len(transform_result.changes_made)

            if self.dry_run:
                # Don't write changes in dry run mode
                return result

            # Create backup if configured
            if self.create_backup:
                backup_path = filepath.with_suffix(filepath.suffix + '.bak')
                shutil.copy2(filepath, backup_path)
                result.backup_path = str(backup_path)

            # Write transformed code
            filepath.write_text(transform_result.transformed_code, encoding='utf-8')

        except Exception as e:
            result.success = False
            result.error = str(e)

        return result


def fix_and_report(
    target: str,
    verify: bool = False,
    dry_run: bool = False,
    backup: bool = True,
    verbose: bool = False,
) -> int:
    """
    Convenience function to fix and print report.

    Args:
        target: File or directory to fix
        verify: Run verification scan after fixing
        dry_run: Preview changes without writing
        backup: Create backup files
        verbose: Verbose output

    Returns:
        Exit code (0 = success, 1 = issues remain, 2 = errors)
    """
    fixer = MCPFixer(
        create_backup=backup,
        dry_run=dry_run,
        verbose=verbose,
    )

    report = fixer.fix(target, verify=verify)

    # Print report
    print_fix_report(report, dry_run=dry_run, verbose=verbose)

    # Determine exit code
    if any(not r.success for r in report.file_results):
        return 2  # Errors occurred
    elif verify and not report.verification_passed:
        return 1  # Issues remain after fix
    elif report.total_fixes_applied == 0 and report.total_issues_before > 0:
        return 1  # No fixes could be applied
    else:
        return 0  # Success


def print_fix_report(report: FixReport, dry_run: bool = False, verbose: bool = False):
    """Print a formatted fix report."""
    mode = "[DRY RUN] " if dry_run else ""

    print(f"""
{'='*64}
{mode}MCP Security Fixer - Auto-Remediation Report
{'='*64}

Target: {report.target}
Files scanned: {report.files_scanned}
Files fixed: {report.files_fixed}

Issues before: {report.total_issues_before}
Fixes applied: {report.total_fixes_applied}
Issues after:  {report.total_issues_after}
Other detected categories (not modified): {report.other_issues_after}
""")

    if report.file_results:
        print("-" * 64)
        print("File Details:")
        print("-" * 64)

        for result in report.file_results:
            status = "OK" if result.success else "ERROR"
            print(f"\n  [{status}] {result.filepath}")
            print(f"       Issues: {result.original_issues} -> Fixes: {result.fixes_applied}")

            if result.backup_path:
                print(f"       Backup: {result.backup_path}")

            if result.error:
                print(f"       Error: {result.error}")

            if verbose and result.changes:
                print("       Changes:")
                for change in result.changes:
                    print(f"         - {change}")

    print("-" * 64)

    if dry_run and report.total_fixes_applied > 0:
        print("\n  DRY RUN COMPLETE - Changes were previewed; no files were modified.")
    elif report.verification_passed:
        print("\n  VERIFICATION PASSED - All vulnerabilities fixed!")
    elif report.total_issues_after == 0:
        print("\n  All detected issues have been addressed.")
    elif report.total_issues_after < report.total_issues_before:
        remaining = report.total_issues_after
        print(f"\n  Partial fix: {remaining} issues remain (may require manual review)")
    else:
        print("\n  No automatic fixes could be applied. Manual review required.")

    print()
