"""Scan a supplied MCP server, or explicitly run the sample walkthrough."""

from __future__ import annotations

import subprocess
import sys
import argparse
import json
from datetime import datetime, timezone
from uuid import uuid4
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent


@dataclass(frozen=True)
class DemoStep:
    title: str
    args: tuple[str, ...]
    expected_codes: tuple[int, ...]
    explanation: str


STEPS = (
    DemoStep(
        "Attack catalog",
        ("-m", "mcp_scanner", "rules"),
        (0,),
        "Shows the versioned MCP01-MCP16 detection contract.",
    ),
    DemoStep(
        "Clean MCP server",
        ("-m", "mcp_scanner", "scan", "tests/samples/clean_server.py"),
        (0,),
        "A normal calculator server should produce no findings.",
    ),
    DemoStep(
        "Tool poisoning",
        ("-m", "mcp_scanner", "scan", "tests/samples/vulnerable_tool_poisoning.py", "--check", "MCP03"),
        (1,),
        "Hidden tool-description instructions request file theft, exfiltration, and unauthorized tool chaining.",
    ),
    DemoStep(
        "Indirect prompt injection",
        ("-m", "mcp_scanner", "scan", "tests/samples/vulnerable_prompt_injection.py", "--check", "MCP06"),
        (1,),
        "Untrusted HTTP, file, database, and process content is returned to the model without a trust boundary.",
    ),
    DemoStep(
        "Safe remediation preview",
        ("-m", "mcp_scanner", "fix", "tests/samples/vulnerable_prompt_injection.py", "--dry-run", "--verbose"),
        (0, 1),
        "Previews high-confidence MCP03/MCP06 edits without modifying the sample.",
    ),
    DemoStep(
        "Automated regression tests",
        ("-m", "unittest", "discover", "-v"),
        (0,),
        "Confirms catalog coverage, clean behavior, redaction, and fixer safety.",
    ),
)


def run_walkthrough() -> int:
    print("MCP Security Scanner - End-to-End Demo", flush=True)
    print("=" * 48, flush=True)
    for number, step in enumerate(STEPS, 1):
        print(f"\n[{number}/{len(STEPS)}] {step.title}", flush=True)
        print(step.explanation, flush=True)
        print(f"> {Path(sys.executable).name} {' '.join(step.args)}\n", flush=True)
        completed = subprocess.run((sys.executable, *step.args), cwd=ROOT)
        if completed.returncode not in step.expected_codes:
            expected = ", ".join(map(str, step.expected_codes))
            print(f"\nDEMO FAILED: {step.title} returned {completed.returncode}; expected {expected}.")
            return 1
        print(f"\nStep completed with expected exit code {completed.returncode}.")

    print("\n" + "=" * 48)
    print("END-TO-END DEMO PASSED")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the MCP analyzer on a server file or project directory and show fresh results.",
        epilog='Example: python demo.py "C:\\projects\\my-server\\server.py"',
    )
    parser.add_argument("target", nargs="?", help="Path to an MCP server file or project directory")
    parser.add_argument("--format", choices=("console", "json"), default="console",
                        help="Result format (default: detailed console report)")
    parser.add_argument("--output", "-o", help="Save JSON results to this file (requires --format json)")
    parser.add_argument("--check", help="Limit the scan to a category or stable rule, e.g. MCP05")
    parser.add_argument("--html", type=Path, help="HTML report path (default: a unique file under .mcp-scanner-cache/reports)")
    parser.add_argument("--walkthrough", action="store_true",
                        help="Run the built-in sample walkthrough and regression tests")
    args = parser.parse_args(argv)
    if args.walkthrough:
        if args.target or args.output or args.check or args.html or args.format != "console":
            parser.error("--walkthrough cannot be combined with a target or scan options")
        return run_walkthrough()
    if not args.target:
        parser.print_help()
        return 0
    if args.output and args.format != "json":
        parser.error("--output requires --format json")

    from mcp_scanner.scanner import MCPScanner
    from mcp_scanner.reporters.console import ConsoleReporter
    from mcp_scanner.reporters.json_reporter import JsonReporter
    from demo_report import render_html

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"Error: Target not found: {target}", file=sys.stderr)
        return 2
    filename = datetime.now(timezone.utc).strftime('scan-%Y%m%d-%H%M%S-') + uuid4().hex[:8] + '.html'
    html_path = (args.html or Path('.mcp-scanner-cache/reports') / filename).resolve()
    output_path = Path(args.output).resolve() if args.output else None
    if html_path == target or output_path == target or html_path == output_path:
        print('Error: Report paths must differ from the input file and from each other.', file=sys.stderr)
        return 2
    try:
        # One scan supplies both reports, so the HTML matches the terminal.
        result = MCPScanner(check=args.check).scan(target)
        info = dict(target=str(target), files_scanned=result.files_scanned,
                    tools_analyzed=result.tools_analyzed, servers_found=result.servers_found,
                    parse_errors=result.parse_errors, check=args.check)
        serialized = JsonReporter().report(result.findings, info)
        report = json.loads(serialized)
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(render_html(report), encoding='utf-8')
        if output_path:
            output_path.write_text(serialized, encoding='utf-8')
    except (ValueError, OSError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 2

    if args.format == 'json':
        if not output_path:
            print(serialized)
    elif result.parse_errors and not result.findings:
        print(f'Scan incomplete: {target}')
    else:
        ConsoleReporter(use_colors=sys.stdout.isatty(), verbose=True).report(result.findings, info)
    for error in result.parse_errors:
        print(f'Scan error: {error}', file=sys.stderr)
    # JSON stdout stays machine-readable; its report link goes to stderr.
    print(f'HTML report: {html_path.as_uri()}', file=sys.stderr if args.format == 'json' else sys.stdout)
    return 2 if result.parse_errors else (1 if result.findings else 0)


if __name__ == "__main__":
    raise SystemExit(main())
