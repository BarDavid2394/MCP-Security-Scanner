"""
MCP Security Scanner - Command Line Interface

Usage:
    python -m mcp_scanner scan <target> [options]
    python -m mcp_scanner fix <target> [options]
    python -m mcp_scanner scan server.py
    python -m mcp_scanner fix server.py --verify
"""

import argparse
import sys
from pathlib import Path

from .scanner import scan_and_report, MCPScanner, ScanResult
from .fixer import fix_and_report
from .reporters.console import ConsoleReporter
from .catalog import ATTACK_CATEGORIES, RULES, CATALOG_VERSION


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="mcp-scanner",
        description="MCP Security Scanner - Detect and fix vulnerabilities in MCP server implementations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan server.py                    Scan a single file
  %(prog)s scan ./servers/                   Scan a directory
  %(prog)s scan server.py --format json      Output as JSON
  %(prog)s scan server.py -v                 Verbose output

  %(prog)s fix server.py                     Auto-fix vulnerabilities
  %(prog)s fix server.py --verify            Fix and verify with rescan
  %(prog)s fix server.py --dry-run           Preview fixes without applying
  %(prog)s fix ./servers/ --no-backup        Fix without creating backups

Workflow:
  1. %(prog)s scan server.py          # Find vulnerabilities
  2. %(prog)s fix server.py --verify  # Fix and verify
  3. %(prog)s scan server.py          # Confirm all fixed

Vulnerability Types:
  tool-poisoning     Malicious instructions hidden in tool descriptions
  prompt-injection   Unsafe handling of external data enabling injection

For more information, visit: https://github.com/mcp-security/mcp-scanner
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan MCP server files for vulnerabilities"
    )
    scan_parser.add_argument(
        "target",
        help="File or directory to scan"
    )
    scan_parser.add_argument(
        "--format", "-f",
        choices=["console", "json"],
        default="console",
        help="Output format (default: console)"
    )
    scan_parser.add_argument(
        "--output", "-o",
        help="Output file for report (default: stdout)"
    )
    scan_parser.add_argument(
        "--check", "-c",
        help="Only check one legacy name, MCP attack ID, or stable rule ID"
    )
    scan_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    scan_parser.add_argument(
        "--review",
        choices=["none", "llm"],
        default="none",
        help="Optionally attach constrained semantic reviews to ambiguous findings"
    )
    scan_parser.add_argument(
        "--review-model",
        default="gpt-5.6-luna",
        help="OpenAI model for --review llm (default: gpt-5.6-luna)"
    )
    scan_parser.add_argument(
        "--review-limit",
        type=int,
        default=25,
        help="Maximum ambiguous findings sent for semantic review (default: 25)"
    )

    # Fix command
    fix_parser = subparsers.add_parser(
        "fix",
        help="Auto-fix detected vulnerabilities"
    )
    fix_parser.add_argument(
        "target",
        help="File or directory to fix"
    )
    fix_parser.add_argument(
        "--verify",
        action="store_true",
        help="Run verification scan after fixing"
    )
    fix_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without modifying files"
    )
    fix_parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Don't create backup files before fixing"
    )
    fix_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )

    subparsers.add_parser("rules", help="List the versioned attack and rule catalog")

    # Version
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 2.0.0"
    )

    return parser


def main(args=None):
    """Main entry point."""
    parser = create_parser()
    parsed_args = parser.parse_args(args)

    if parsed_args.command is None:
        parser.print_help()
        return 0

    if parsed_args.command == "scan":
        return run_scan(parsed_args)
    elif parsed_args.command == "fix":
        return run_fix(parsed_args)
    elif parsed_args.command == "rules":
        print(f"MCP attack catalog {CATALOG_VERSION}")
        for attack_id, category in ATTACK_CATEGORIES.items():
            print(f"{attack_id}  {category.name}")
            for rule_id, (owner, title) in RULES.items():
                if owner == attack_id:
                    print(f"  {rule_id}: {title}")
        return 0

    return 0


def run_scan(args) -> int:
    """Execute the scan command."""
    target = Path(args.target)

    if not target.exists():
        print(f"Error: Target not found: {target}", file=sys.stderr)
        return 2

    try:
        exit_code = scan_and_report(
            target=str(target), output_format=args.format,
            output_file=args.output, verbose=args.verbose, check=args.check,
            review=args.review, review_model=args.review_model,
            review_limit=args.review_limit,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    return exit_code


def run_fix(args) -> int:
    """Execute the fix command."""
    target = Path(args.target)

    if not target.exists():
        print(f"Error: Target not found: {target}", file=sys.stderr)
        return 2

    exit_code = fix_and_report(
        target=str(target),
        verify=args.verify,
        dry_run=args.dry_run,
        backup=not args.no_backup,
        verbose=args.verbose,
    )

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
