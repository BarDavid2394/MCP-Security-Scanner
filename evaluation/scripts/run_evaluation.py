"""Run the static scanner over the pinned corpus without importing target code."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from mcp_scanner.catalog import CATALOG_VERSION  # noqa: E402
from mcp_scanner.reporters.json_reporter import JsonReporter  # noqa: E402
from mcp_scanner.scanner import MCPScanner  # noqa: E402

EVALUATION = ROOT / "evaluation"
CORPUS = EVALUATION / "corpus"
RESULTS = EVALUATION / "raw-results"
WORK = EVALUATION / "work"


def source_inventory(target: Path) -> dict:
    inventory = Counter(python_files=0, syntax_errors=0, decorated_tools=0,
                        low_level_handlers=0, tool_constructors=0)
    for path in target.rglob("*.py"):
        if any(part in {".git", ".venv", "venv", "node_modules"} for part in path.parts):
            continue
        inventory["python_files"] += 1
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, SyntaxError):
            inventory["syntax_errors"] += 1
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    expression = decorator.func if isinstance(decorator, ast.Call) else decorator
                    if isinstance(expression, ast.Attribute):
                        if expression.attr == "tool":
                            inventory["decorated_tools"] += 1
                        elif expression.attr in {"call_tool", "list_tools"}:
                            inventory["low_level_handlers"] += 1
            if isinstance(node, ast.Call):
                func = node.func
                if ((isinstance(func, ast.Name) and func.id == "Tool") or
                        (isinstance(func, ast.Attribute) and func.attr == "Tool")):
                    inventory["tool_constructors"] += 1
    return dict(inventory)


def scan_target(target_id: str, target: Path) -> dict:
    result = MCPScanner().scan(target)
    inventory = source_inventory(target)
    scan_info = {
        "target_id": target_id,
        "target": str(target.relative_to(ROOT)),
        "files_scanned": result.files_scanned,
        "tools_analyzed": result.tools_analyzed,
        "servers_found": result.servers_found,
        "parse_errors": result.parse_errors,
        "source_inventory": inventory,
    }
    output = RESULTS / f"{target_id}.json"
    JsonReporter(pretty=True).report(result.findings, scan_info, str(output))
    return {
        **scan_info,
        "findings": len(result.findings),
        "by_attack": dict(sorted(Counter(f.attack_id for f in result.findings).items())),
        "fixable": sum(f.fixable for f in result.findings),
        "parser_coverage": (
            result.tools_analyzed / inventory["decorated_tools"]
            if inventory["decorated_tools"] else None
        ),
    }


def run_fixtures() -> dict:
    fixture_results = {}
    for path in sorted((EVALUATION / "fixtures").glob("*.py")):
        result = MCPScanner().scan(path)
        fixture_results[path.stem] = {
            "findings": len(result.findings),
            "rules": sorted({f.rule_id for f in result.findings if f.rule_id}),
            "fixable": sum(f.fixable for f in result.findings),
        }
        JsonReporter(pretty=True).report(
            result.findings,
            {"target_id": path.stem, "files_scanned": result.files_scanned,
             "tools_analyzed": result.tools_analyzed, "parse_errors": result.parse_errors},
            str(RESULTS / f"fixture-{path.stem}.json"),
        )
    return fixture_results


def run_fixer_checks() -> dict:
    WORK.mkdir(parents=True, exist_ok=True)
    checks = {}
    for name in ("mutated_tool_poisoning", "mutated_prompt_injection"):
        source = EVALUATION / "fixtures" / f"{name}.py"
        target = WORK / f"{name}.py"
        target.write_bytes(source.read_bytes())
        before = target.read_bytes()
        dry = subprocess.run(
            [sys.executable, "-m", "mcp_scanner", "fix", str(target), "--dry-run", "--verbose"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        dry_unchanged = target.read_bytes() == before
        applied = subprocess.run(
            [sys.executable, "-m", "mcp_scanner", "fix", str(target), "--verify"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        ast.parse(target.read_text(encoding="utf-8"))
        after_first = target.read_bytes()
        second = subprocess.run(
            [sys.executable, "-m", "mcp_scanner", "fix", str(target), "--verify"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        checks[name] = {
            "dry_run_exit": dry.returncode,
            "dry_run_unchanged": dry_unchanged,
            "apply_exit": applied.returncode,
            "changed": after_first != before,
            "syntax_valid": True,
            "backup_created": target.with_suffix(target.suffix + ".bak").exists(),
            "second_exit": second.returncode,
            "idempotent": target.read_bytes() == after_first,
        }
    return checks


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((EVALUATION / "corpus-manifest.json").read_text(encoding="utf-8"))
    summaries = []
    for entry in manifest["targets"]:
        target = (CORPUS / entry["repository"] / entry["path"]).resolve()
        if not target.exists():
            raise FileNotFoundError(f"Missing corpus target: {target}")
        print(f"Scanning {entry['id']} ...", flush=True)
        summaries.append(scan_target(entry["id"], target))
    report = {
        "catalog_version": CATALOG_VERSION,
        "targets": summaries,
        "fixtures": run_fixtures(),
        "fixer_checks": run_fixer_checks(),
    }
    (RESULTS / "summary.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
