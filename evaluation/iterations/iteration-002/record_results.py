"""Assemble iteration evidence without modifying scanner code or labels."""
import csv
import difflib
import hashlib
import json
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
DEV = OUT.parent / "iteration-001/runs"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.write_text(json.dumps(value, indent=2)+"\n", encoding="utf-8")


def main():
    freeze = read(OUT / "freeze.json")
    fresh = read(OUT / "runs/frozen-validation/metrics.json")
    reference = read(OUT / "runs/reference-iteration001/metrics.json")
    before = read(DEV / "after/metrics.json")
    after = read(DEV / "iteration002-candidate/metrics.json")
    primary = []
    for path in sorted((DEV / "after").glob("primary-*.json")):
        previous = read(path)
        current = read(DEV / "iteration002-candidate" / path.name)
        primary.append(dict(target_id=current["target_id"], status=current["status"],
            files=current["scan_info"]["files_scanned"], tools=current["scan_info"]["tools_analyzed"],
            findings_before=len(previous["findings"]), findings_after=len(current["findings"]),
            findings_identical=previous["findings"] == current["findings"],
            inputs_identical=previous["input_files"] == current["input_files"]))
    write(OUT / "comparison.json", dict(development_before=before["micro"], development_after=after["micro"],
        fresh=fresh["micro"], fresh_reference=reference["micro"],
        fresh_decisions_identical=fresh["decisions"] == reference["decisions"], primary=primary))
    with (OUT / "error_analysis.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["artifact_id", "rule_id", "function_name", "outcome", "cause", "next_step"])
        writer.writeheader()
        for decision in fresh["decisions"]:
            if decision["outcome"] not in {"fp", "fn"}: continue
            aid = decision["artifact_id"]
            if "aliased_subprocess" in aid or "bare_imported_sinks" in aid:
                cause = "Command sink matching uses literal call names, without resolving imported aliases."
                step = "Resolve imports with lexical scope and rebinding checks; test non-subprocess run/call lookalikes."
            elif decision["rule_id"] == "MCP05-COMMAND-INJECTION":
                cause = "Low-level declarations live in module _TOOLS rather than inline list_tools; zero tools are extracted."
                step = "Resolve static tool lists and connect dispatch branches to argument flow, without executing source."
            elif aid == "vuln_secret--config":
                cause = "Secret-output text check recognizes logger/logging names, but misses log.info's password argument."
                step = "Track logging aliases and actual secret values with AST evidence."
            else:
                cause = "Secret-output text check misses dictionaries, environment values and aliases; low-level cases also have zero extracted tools."
                step = "Track sensitive values into tool return containers/helpers; distinguish boolean presence and pagination metadata."
            writer.writerow({**{key:decision.get(key) for key in ["artifact_id", "rule_id", "function_name", "outcome"]}, "cause":cause, "next_step":step})
    # Findings outside locked labels stay out of the confusion matrix.
    write(OUT / "posthoc_followups.json", dict(scoring="Not retroactively added to locked labels", items=[
        dict(artifact_id="clean_tool_scope_lowlevel--server", rule_id="MCP10-OVER-SHARING", assessment="suspected false positive", reason="check_permission returns a boolean comparison of an environment value, not the environment object."),
        dict(artifact_id="clean_tool_scope_same_file_gate--server", rule_id="MCP10-OVER-SHARING", assessment="suspected false positive", reason="_write_enabled returns a boolean membership check, not an environment dump."),
        dict(artifact_id="clean_tool_scope_same_file_gate--server", rule_id="MCP08-MISSING-AUDIT", assessment="unscored plausible finding", reason="The executable-selecting tool has no visible audit logging.")]))
    # CLI smoke checks use our synthetic source, which is statically scanned.
    checks = []
    prefix = 'import subprocess\nimport shlex\nfrom mcp.server.fastmcp import FastMCP\nmcp=FastMCP("check")\n@mcp.tool()\ndef inspect(value: str):\n'
    with tempfile.TemporaryDirectory() as directory:
        for title, body, expected in [
            ("fixed_argv", '    subprocess.run(["du", "-sh", value])\n', 0),
            ("quoted_shell_argument", '    subprocess.run(f"du -sh {shlex.quote(value)}", shell=True)\n', 0),
            ("unprotected_shell_argument", '    subprocess.run(f"du -sh {value}", shell=True)\n', 1)]:
            path = Path(directory) / (title+".py")
            path.write_text(prefix+body, encoding="utf-8")
            result = subprocess.run([sys.executable, "-m", "mcp_scanner", "scan", str(path), "--check", "MCP05", "--format", "json", "--review", "none"], cwd=ROOT, capture_output=True, text=True)
            assert result.returncode == expected, result.stderr
            payload = json.loads(result.stdout)
            checks.append(dict(case=title, exit_code=result.returncode, expected_exit_code=expected, report=payload))
    write(OUT / "cli-checks.json", checks)
    # The diff is relative to iteration 001's final archived code, not Git HEAD.
    patch = []
    with zipfile.ZipFile(DEV / "after/code_snapshot.zip") as archive:
        names = set(archive.namelist())
        for path in sorted((ROOT / "mcp_scanner").rglob("*.py")):
            relative = path.relative_to(ROOT).as_posix()
            original = archive.read(relative).decode("utf-8") if relative in names else ""
            current = path.read_text(encoding="utf-8")
            patch.extend(difflib.unified_diff(original.splitlines(True), current.splitlines(True), fromfile="iteration001/"+relative, tofile="iteration002/"+relative))
    relative = "tests/test_command_safety.py"
    patch.extend(difflib.unified_diff([], (ROOT/relative).read_text().splitlines(True), fromfile="/dev/null", tofile="iteration002/"+relative))
    (OUT / "changes.patch").write_text("".join(patch), encoding="utf-8")
    lock = read(OUT / "label-lock.json")
    config = read(OUT / "runs/frozen-validation/config.json")
    code_unchanged = all(hashlib.sha256((ROOT/f).read_bytes()).hexdigest() == h for f,h in freeze["code_files"].items())
    holdout_unchanged = hashlib.sha256((ROOT / "evaluation/holdout/staging-manifest.json").read_bytes()).hexdigest() == freeze["holdout_manifest_sha256"]
    labels_unchanged = hashlib.sha256((OUT / "manifest.json").read_bytes()).hexdigest() == lock["manifest_sha256"] == config["manifest_sha256"]
    ordered = freeze["frozen_at"] < lock["locked_at"] < config["started_at"]
    assert code_unchanged and holdout_unchanged and labels_unchanged and ordered
    assert fresh["decisions"] == reference["decisions"]
    assert all(row["findings_identical"] and row["inputs_identical"] for row in primary)
    write(OUT / "record-integrity.json", dict(verified_at=datetime.now(timezone.utc).isoformat(),
        code_unchanged_since_freeze=code_unchanged, labels_unchanged=labels_unchanged,
        holdout_manifest_unchanged=holdout_unchanged, freeze_then_labels_then_scan=ordered,
        no_new_scored_regressions_against_archived_reference=True,
        primary_findings_and_inputs_identical=True, tests=82, cli_cases=3))
    exposure = read(OUT.parent / "exposure.json")
    exposure["entries"][0]["latest_run"] = "iteration-001/runs/iteration002-candidate"
    manifest = read(OUT / "manifest.json")
    entry = dict(iteration="iteration-002", repository="jaimenbell/mcp-security-scanner",
        revision=manifest["artifacts"][0]["revision"], role="development-after-investigation",
        related_family_policy="All related variants, including deferred files from this repository, require leakage review; do not count as a new independent source batch.",
        first_run="iteration-002/runs/frozen-validation", latest_run="iteration-002/runs/frozen-validation",
        artifacts=[{key:a[key] for key in ["id", "sha256", "path"]} for a in manifest["artifacts"]])
    exposure["entries"] = [e for e in exposure["entries"] if e["iteration"] != "iteration-002"] + [entry]
    write(OUT.parent / "exposure.json", exposure)
    print("Verified frozen code/labels, primary comparisons, reference comparison and CLI checks.")


if __name__ == "__main__":
    main()
