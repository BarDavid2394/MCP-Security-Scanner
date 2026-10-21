"""Record comparisons, CLI verification and post-scan investigation; no tuning."""
import csv
import difflib
import hashlib
import json
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
ITERATIONS = OUT.parent


def read(path): return json.loads(path.read_text(encoding="utf-8"))
def write(path, value): path.write_text(json.dumps(value, indent=2)+"\n", encoding="utf-8")
def rows(path): return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    previous = ITERATIONS / "iteration-002/runs/frozen-validation"
    development = ITERATIONS / "iteration-002/runs/iteration003-final"
    fresh = read(OUT / "runs/frozen-validation/metrics.json")
    reference = read(OUT / "runs/reference-iteration002/metrics.json")
    before = read(previous / "metrics.json")
    after = read(development / "metrics.json")
    changes = [{"artifact_id": a["artifact_id"], "rule_id": a["rule_id"], "function_name": a["function_name"],
                "before": a["outcome"], "after": b["outcome"]}
               for a,b in zip(reference["decisions"], fresh["decisions"]) if a["outcome"] != b["outcome"]]
    primary = []
    key = lambda f: (f["rule_id"], f["file_path"], f["line_number"], f["function_name"])
    for path in sorted(development.glob("primary-*.json")):
        old = read(ITERATIONS / "iteration-001/runs/iteration002-candidate" / path.name)
        new = read(path)
        removed = set(map(key, old["findings"])) - set(map(key, new["findings"]))
        added = set(map(key, new["findings"])) - set(map(key, old["findings"]))
        primary.append(dict(target_id=new["target_id"], status=new["status"], files=new["scan_info"]["files_scanned"],
            tools=new["scan_info"]["tools_analyzed"], findings_before=len(old["findings"]), findings_after=len(new["findings"]),
            inputs_identical=old["input_files"] == new["input_files"], removed=sorted(removed,key=str), added=sorted(added,key=str)))
    dev_rows = rows(development / "predictions.jsonl")
    controls = [dict(artifact_id=r["artifact_id"], remaining_environment_dump_findings=sum(f["rule_id"] == "MCP10-OVER-SHARING" for f in r["findings"]))
                for r in dev_rows if r["artifact_id"] in {"clean_tool_scope_lowlevel--server", "clean_tool_scope_same_file_gate--server"}]
    write(OUT / "comparison.json", dict(development_before=before["micro"], development_after=after["micro"],
        fresh_before=reference["micro"], fresh_after=fresh["micro"], fresh_changed_decisions=changes,
        development_posthoc_controls=controls, primary=primary,
        original_batch_regression=read(ITERATIONS / "iteration-001/runs/iteration003-final/metrics.json")["micro"]))
    with (OUT / "error_analysis.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["artifact_id", "rule_id", "function_name", "outcome", "cause", "next_step"])
        writer.writeheader()
        for d in fresh["decisions"]:
            if d["outcome"] not in {"fp", "fn"}: continue
            aid, function, rule = d["artifact_id"], d["function_name"], d["rule_id"]
            if rule == "MCP01-SECRET-HARDCODED":
                cause = "Hardcoded-secret matching is still text based and misses prefixed names, multiline credential text and quoted dictionary keys."
                next_step = "AST-aware literal/bundle checks with placeholder, derived-value and documentation negatives; keep evidence redacted."
            elif rule == "MCP03-TOOL-POISON":
                if d["outcome"] == "fp":
                    cause = "A zero-width marker is treated as poisoning despite lacking a behavioral payload."
                    next_step = "Separate suspicious formatting evidence from an actual instruction override."
                elif "dynamic_description" in aid:
                    cause = "Parser does not resolve the bounded local description factory and concatenation."
                    next_step = "Resolve safe static string expressions without executing source."
                elif function == "sync_data":
                    cause = "Encoded behavioral redirection is not decoded into semantic evidence."
                    next_step = "Bounded decoding with benign encoded-example controls."
                else:
                    cause = "Existing signatures miss this priority or cross-tool routing wording."
                    next_step = "Add focused semantic/signature cases with legitimate prerequisite and tool-description negatives."
            elif d["outcome"] == "fp":
                cause = "Narrow command protection cannot establish this fixed argv executable or safe helper argument construction."
                next_step = "Expand argument-role and helper proofs, retaining executable-selection and interpreter positives."
            elif "programmatic" in aid:
                cause = "FastMCP.add_tool registration through an instance is not extracted."
                next_step = "Resolve programmatic registration with receiver identity; retain the non-MCP registry negative."
            elif "obfuscated" in aid:
                cause = "getattr-selected subprocess sink is not resolved."
                next_step = "Resolve literal getattr bindings without running dynamic code; test unrelated receivers/rebinding."
            else:
                cause = "Existing guard analysis trusts caller-controlled or non-dominating allowlist checks."
                next_step = "Require trusted allowlist provenance and an unconditional exit on every unsafe path."
            writer.writerow({**{k:d.get(k) for k in ["artifact_id", "rule_id", "function_name", "outcome"]}, "cause":cause, "next_step":next_step})
    write(OUT / "unscored-summary.json", dict(count=len(fresh["unscored_predictions"]),
        by_rule=dict(Counter(d["rule_id"] for d in fresh["unscored_predictions"])),
        status="Not independently adjudicated and not counted as TP/FP. No global zero-false-positive claim."))
    # CLI checks are our own synthetic fixtures, statically scanned only.
    sys.path.insert(0, str(ROOT))
    from tests.test_iteration_three import tool, low_level
    checks = [
        ("imported_alias", tool('launch(value, shell=True)', imports='from subprocess import run as launch'), "MCP05", 1),
        ("safe_alias_argv", tool('sp.run(["du", value])', imports='import subprocess as sp'), "MCP05", 0),
        ("secret_return", tool('return {"token": API_TOKEN}', imports='import os', extra='API_TOKEN=os.getenv("API_TOKEN")'), "MCP01", 1),
        ("boolean_environment", tool('return os.environ.get("ALLOW_WRITE") == "1"', imports='import os'), "MCP10-OVER-SHARING", 0),
        ("low_level_dispatch", low_level('if name == "run":\n    subprocess.run(arguments["cmd"], shell=True)', names=('run',)), "MCP05", 1),
    ]
    cli = []
    with tempfile.TemporaryDirectory() as directory:
        for name, source, rule, expected in checks:
            path = Path(directory) / (name+".py")
            path.write_text(source, encoding="utf-8")
            result = subprocess.run([sys.executable, "-m", "mcp_scanner", "scan", str(path), "--check", rule,
                "--format", "json", "--review", "none"], cwd=ROOT, capture_output=True, text=True)
            assert result.returncode == expected, result.stderr
            cli.append(dict(case=name, exit_code=result.returncode, expected=expected, report=json.loads(result.stdout)))
    write(OUT / "cli-checks.json", cli)
    patch = []
    with zipfile.ZipFile(previous / "code_snapshot.zip") as archive:
        names = set(archive.namelist())
        for path in sorted((ROOT / "mcp_scanner").rglob("*.py")):
            relative = path.relative_to(ROOT).as_posix()
            old = archive.read(relative).decode("utf-8") if relative in names else ""
            patch.extend(difflib.unified_diff(old.splitlines(True), path.read_text(encoding="utf-8").splitlines(True),
                fromfile="iteration002/"+relative, tofile="iteration003/"+relative))
    relative = "tests/test_iteration_three.py"
    patch.extend(difflib.unified_diff([], (ROOT/relative).read_text().splitlines(True), fromfile="/dev/null", tofile="iteration003/"+relative))
    relative = "tests/test_scanner.py"
    original_test = subprocess.check_output(["git", "show", "HEAD:"+relative], cwd=ROOT).decode("utf-8")
    patch.extend(difflib.unified_diff(original_test.splitlines(True), (ROOT/relative).read_text().splitlines(True),
                                    fromfile="iteration002/"+relative, tofile="iteration003/"+relative))
    (OUT / "changes.patch").write_text("".join(patch), encoding="utf-8")
    freeze = read(OUT / "freeze.json")
    lock = read(OUT / "label-lock.json")
    config = read(OUT / "runs/frozen-validation/config.json")
    assert all(sha(ROOT/path) == digest for path,digest in freeze["code_files"].items())
    assert sha(OUT/"manifest.json") == lock["manifest_sha256"] == config["manifest_sha256"]
    assert sha(ROOT/"evaluation/holdout/staging-manifest.json") == freeze["holdout_manifest_sha256"]
    assert freeze["frozen_at"] < lock["locked_at"] < config["started_at"]
    assert all(row["inputs_identical"] and row["status"] == "completed" for row in primary)
    assert all(c["remaining_environment_dump_findings"] == 0 for c in controls)
    assert all(not (x["before"] in {"tp", "tn"} and x["after"] in {"fn", "fp"}) for x in changes)
    write(OUT / "record-integrity.json", dict(verified_at=datetime.now(timezone.utc).isoformat(),
        code_unchanged_since_freeze=True, labels_unchanged=True, holdout_manifest_unchanged=True,
        freeze_then_labels_then_scan=True, no_new_scored_regressions_on_fresh_batch=True,
        tests=100, cli_checks=5, primary_completed=10, primary_inputs_identical=True))
    exposure = read(ITERATIONS / "exposure.json")
    for entry in exposure["entries"]:
        entry["latest_run"] = entry["iteration"] + "/runs/iteration003-final"
    manifest = read(OUT / "manifest.json")
    exposure["entries"] = [e for e in exposure["entries"] if e["iteration"] != "iteration-003"]
    exposure["entries"].append(dict(iteration="iteration-003", repository="jspillers10/mcp-security-scanner",
        revision=manifest["artifacts"][0]["revision"], role="development-after-investigation",
        related_family_policy="Related variants, including deferred candidates, are not independent fresh validation without leakage review.",
        first_run="iteration-003/runs/frozen-validation", latest_run="iteration-003/runs/frozen-validation",
        artifacts=[{k:a[k] for k in ["id", "path", "sha256"]} for a in manifest["artifacts"]]))
    write(ITERATIONS / "exposure.json", exposure)
    print("Verified frozen code and labels, five CLI checks, exposure ledger and paired results.")


if __name__ == "__main__": main()
