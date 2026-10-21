"""Interactive security scan, targeted remediation, and HTML reports.

Each run creates an isolated working copy of the bundled MCP server files.
Only static analysis is performed: the servers are never executed.
Server files are restored after evaluation; reports retain the repaired scan.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path
import shutil
import sys
from uuid import uuid4

from demo_report import render_html
from mcp_scanner.fixer import MCPFixer
from mcp_scanner.reporters.console import ConsoleReporter
from mcp_scanner.reporters.colors import SEVERITY_COLORS
from mcp_scanner.reporters.json_reporter import JsonReporter
from mcp_scanner.scanner import MCPScanner

ROOT = Path(__file__).resolve().parent
CATEGORIES = {"MCP03", "MCP06"}
SAMPLES = ("vulnerable_tool_poisoning.py", "vulnerable_prompt_injection.py")


def prepare_project(run_dir):
    project = run_dir / "project"
    project.mkdir(parents=True)
    for name in SAMPLES:
        shutil.copy2(ROOT / "tests" / "samples" / name, project / name)
    return project


def serialize_scan(result, target):
    info = dict(target=str(target), **result.to_dict(), check=None)
    return json.loads(JsonReporter().report(result.findings, info))


def print_scan_summary(result, report, verbose=False):
    if result.parse_errors:
        print('Scan incomplete.')
    if verbose and result.findings:
        ConsoleReporter(use_colors=sys.stdout.isatty(), verbose=True).report(result.findings, report['scan_info'])
        return
    print(f'Files: {result.files_scanned} | Tools: {result.tools_analyzed} | '
          f'Findings: {len(result.findings)} | Errors: {len(result.parse_errors)}')
    if not result.findings:
        if not result.parse_errors:
            print('No findings detected.')
        return
    counts = report['summary']['by_severity']
    levels = []
    for level, (ansi, _) in SEVERITY_COLORS.items():
        if counts.get(level):
            label = f'{level}: {counts[level]}'
            levels.append(f'{ansi}{label}\033[0m' if sys.stdout.isatty() else label)
    print('Urgency: ' + ' | '.join(levels))
    print('Categories: ' + ' | '.join(f'{key}: {value}' for key, value in sorted(report['summary']['by_attack'].items())))


def restore_samples(originals):
    """Restore exact pre-fix bytes, including after a partial fix or report error."""
    errors = []
    for path, original in originals.items():
        try:
            path.write_bytes(original)
            if path.read_bytes() != original:
                raise OSError('Restored content does not match the original')
        except OSError as exc:
            errors.append(f'{path}: {exc}')
    if errors:
        raise OSError('Server file restoration failed: ' + '; '.join(errors))


def choose_categories(available):
    print("\nAuto-fix available: " + ", ".join(sorted(available)))
    print("MCP03 = tool poisoning | MCP06 = untrusted content in model context")
    while True:
        try:
            answer = input("Apply auto-fix? [yes/both, MCP03, MCP06, no]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nAuto-fix cancelled. No fixes applied.")
            return set()
        if answer in {"no", "n"}:
            return set()
        if answer in {"yes", "y", "both"}:
            return set(available)
        if answer.upper() in available:
            return {answer.upper()}
        print("Enter yes (all available categories), an available category, or no.")


def fix_payload(before, after, fix_report, selected):
    return dict(selected_categories=sorted(selected), fix=asdict(fix_report), before=before, after=after)


def fix_summary(before, after, fix_report, selected):
    before_counts = Counter(f['attack_id'] for f in before['findings'])
    after_counts = Counter(f['attack_id'] for f in after['findings'])
    errors = after['scan_info']['parse_errors'] or any(not f.success for f in fix_report.file_results)
    remaining_selected = sum(after_counts[c] for c in selected)
    if errors:
        status = "Fix verification incomplete"
    elif remaining_selected:
        status = "Auto-fix complete - manual review remains"
    else:
        status = "Selected categories verified clear"
    rows = ''.join(
        f'<tr><td>{escape(category or "Unknown")}</td><td>{before_counts[category]}</td>'
        f'<td>{after_counts[category]}</td><td>{"Selected for auto-fix" if category in selected else "Review only in this run"}</td></tr>'
        for category in sorted(before_counts.keys() | after_counts.keys(), key=str)
    )
    files = []
    for result in fix_report.file_results:
        changes = ''.join(f'<li>{escape(change)}</li>' for change in result.changes)
        backup = (f'<p>Backup: <a href="{Path(result.backup_path).resolve().as_uri()}">'
                  f'{escape(Path(result.backup_path).name)}</a></p>') if result.backup_path else ''
        error = f'<p>Error: {escape(result.error)}</p>' if result.error else ''
        source = (f'<p>Server file (restored after evaluation): <a href="{Path(result.filepath).resolve().as_uri()}">'
                  f'{escape(Path(result.filepath).name)}</a></p>')
        files.append(f'<details class="file-change"><summary>{escape(Path(result.filepath).name)}'
                     f' <span class="meta">({result.fixes_applied} edits)</span></summary>'
                     f'<ul>{changes}</ul>{source}{backup}{error}</details>')
    summary = f'''<section>
<h2>Before and after</h2>
<p>Selected: {escape(', '.join(sorted(selected)))}. Files changed: {fix_report.files_fixed}.
Source edits applied: {fix_report.total_fixes_applied} (edits and findings are different counts).</p>
<p>The fixer wrote changes to the MCP server files. A new scanner read those same files
from disk to produce the after counts and remaining findings below.</p>
<p>After evaluation, the server files are restored to their original state.
This report preserves the verification results from before restoration; it is not
a scan of the restored files.</p>
<table style="width:100%;text-align:left;line-height:2"><thead><tr><th>Category</th><th>Before</th><th>After</th><th>Scope</th></tr></thead><tbody>{rows}</tbody></table>
<p><a href="scan.html">Open the original scan report</a></p>
<p>Only eligible high-confidence MCP03/MCP06 findings in the selected categories are automatically repaired.
Other categories receive no targeted edits; their fresh scan results remain visible below.</p>
<h2>Applied changes and backups</h2>{''.join(files) or '<p>No automatic edits were made.</p>'}
<h2>Remaining findings from the verification scan</h2></section>'''
    return render_html(after, heading=status, summary_html=summary,
                       footer_note="Automatic fixes were applied only to the selected categories. Backups are retained. Verification is static analysis.",
                       download_report=fix_payload(before, after, fix_report, selected), download_filename='fix.json')


def show_report(label, path):
    print(f"\n{label}: {path.resolve().as_uri()}", flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verbose', action='store_true', help='Include full evidence in terminal output')
    args = parser.parse_args(argv)
    run_id = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-') + uuid4().hex[:8]
    run_dir = ROOT / 'evaluation' / 'work' / ('scan-' + run_id)
    originals = {}
    try:
        project = prepare_project(run_dir)
        reports = run_dir / 'reports'
        reports.mkdir()
        print('MCP SECURITY SCANNER | SCAN -> FIX -> VERIFY', flush=True)
        print(f'MCP project: {project}')
        print('Analyzing MCP server source files. Static analysis only.\n')
        scanner = MCPScanner()
        initial = scanner.scan(project)
        before = serialize_scan(initial, project)
        scan_html = reports / 'scan.html'
        scan_html.write_text(render_html(before), encoding='utf-8')
        (reports / 'scan.json').write_text(json.dumps(before, indent=2), encoding='utf-8')
        print_scan_summary(initial, before, args.verbose)
        show_report('Scan HTML report', scan_html)
        if initial.parse_errors:
            for error in initial.parse_errors:
                print(f'Scan error: {error}', file=sys.stderr)
            return 2
        available = {f.attack_id for f in initial.findings if f.fixable and f.attack_id in CATEGORIES}
        if not available:
            print('No eligible automatic fixes found.')
            return 1 if initial.findings else 0
        selected = choose_categories(available)
        if not selected:
            print('No fixes applied. The scan report is available above.')
            return 1 if initial.findings else 0
        print('\nApplying ' + ', '.join(sorted(selected)) + ' fixes with backups...', flush=True)
        # Snapshot every sample before invoking the fixer, so even a failure
        # before it returns its backup paths cannot leave demo edits behind.
        originals = {path: path.read_bytes() for path in project.glob('*.py')}
        fix = MCPFixer(categories=selected, create_backup=True).fix(str(project), verify=True)
        for result in fix.file_results:
            if result.success and result.fixes_applied:
                print(f'Updated server file: {Path(result.filepath).name} ({result.fixes_applied} edits; backup saved)')
                if args.verbose:
                    for change in result.changes:
                        print(f'  - {change}')
                    if result.backup_path:
                        print(f'  Original backup: {result.backup_path}')
        print('\nVERIFICATION SCAN - reading the updated server files from disk', flush=True)
        after_result = MCPScanner().scan(project)
        after = serialize_scan(after_result, project)
        print_scan_summary(after_result, after, args.verbose)
        fix_html = reports / 'fix.html'
        fix_html.write_text(fix_summary(before, after, fix, selected), encoding='utf-8')
        (reports / 'fix.json').write_text(json.dumps(fix_payload(before, after, fix, selected), indent=2), encoding='utf-8')
        print(f'Files changed: {fix.files_fixed} | Source edits: {fix.total_fixes_applied}')
        for category in sorted(CATEGORIES):
            count_before = sum(f.attack_id == category for f in initial.findings)
            count_after = sum(f.attack_id == category for f in after_result.findings)
            print(f'{category}: {count_before} -> {count_after} findings')
        remaining = sum(f.attack_id in selected for f in after_result.findings)
        other = len(after_result.findings) - remaining
        print(f'Selected-category findings remaining: {remaining}')
        print(f'Other findings for manual review: {other}')
        failures = [f.error for f in fix.file_results if not f.success]
        for error in failures + after_result.parse_errors:
            print(f'Verification error: {error}', file=sys.stderr)
        if not failures and not after_result.parse_errors:
            print('Verification: ' + ('selected categories clear.' if not remaining else 'manual review remains.'))
        show_report('Fix HTML report', fix_html)
        # Completion concerns the selected fix scope; other risks remain in the report.
        return 2 if failures or after_result.parse_errors else (1 if remaining else 0)
    except (OSError, ValueError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print('\nScan and fix interrupted.', file=sys.stderr)
        return 2
    finally:
        if originals:
            try:
                restore_samples(originals)
            except OSError as exc:
                print(f'Error: {exc}', file=sys.stderr)
                return 2


if __name__ == '__main__':
    raise SystemExit(main())
