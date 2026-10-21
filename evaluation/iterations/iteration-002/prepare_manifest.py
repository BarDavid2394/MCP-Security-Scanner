"""Record source-reviewed labels BEFORE the first frozen-candidate scan.

This only hashes/reads inert snapshots; it never imports their code.
Labels describe our rule semantics, not the upstream fixture's directory name.
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
BASE = ROOT / "deliverables/data_expansion"
PREFIX = "snapshots/jaimenbell__mcp-security-scanner/tests/fixtures/"
COMMAND = "MCP05-COMMAND-INJECTION"
SECRET = "MCP01-SECRET-HARDCODED"
OUTPUT = "MCP01-SECRET-OUTPUT"


def label(rule, polarity, rationale, function=None):
    return dict(rule_id=rule, polarity=polarity, function_name=function, rationale=rationale)


LABELS = {
    "clean_secret/config.py": [label(SECRET, "negative", "Environment credentials and an explicit your-api-key-here placeholder; no embedded credential.")],
    "vuln_secret/config.py": [label(SECRET, "positive", "Fixture embeds credential-shaped hardcoded values."), label(OUTPUT, "positive", "log.info formats the supplied password into a log record.")],
    "clean_secret_leak/server.py": [label(OUTPUT, "negative", "Tools return token presence as a boolean, tokenizer version and passwordless mode, without credential values."), label(SECRET, "negative", "Token is read from the environment; non-secret literals describe status.")],
    "vuln_secret_leak/server.py": [label(OUTPUT, "positive", "Tools return the process environment, the configured API token and a key literal."), label(SECRET, "positive", "get_key_tool embeds a credential-shaped literal.")],
    "clean_secret_leak_lowlevel/server.py": [label(OUTPUT, "negative", "Dispatcher and helper return query/count or status, not credentials.")],
    "vuln_secret_leak_lowlevel/server.py": [label(OUTPUT, "positive", "A dispatched helper exposes the server environment. File-level label avoids requiring branch attribution.")],
    "vuln_secret_leak_lowlevel_negated_guard/server.py": [label(OUTPUT, "positive", "The else branch returns the server environment.")],
    "vuln_secret_leak_pagination/server.py": [label(OUTPUT, "positive", "get_creds_tool returns an access token; pagination-only sibling functions are not separate scored negatives."), label(SECRET, "positive", "get_creds_tool embeds an access_token fixture literal. JWT validity is not assumed.")],
    "clean_tool_scope_lowlevel/server.py": [label(COMMAND, "negative", "File removal does not execute a command; permission-gate quality is outside this label.")],
    "vuln_tool_scope_lowlevel/server.py": [label(COMMAND, "positive", "call_tool passes caller-controlled cmd to subprocess.run with shell=True.")],
    "vuln_tool_scope_lowlevel_negated_guard/server.py": [label(COMMAND, "negative", "os.remove is file deletion, not command execution. Other security properties are unlabelled.")],
    "vuln_tool_scope_lowlevel_sibling_gate/server.py": [label(COMMAND, "negative", "File reads/removal introduce no process execution, regardless of the inadequate gate.")],
    "clean_tool_scope_same_file_gate/server.py": [label(COMMAND, "positive", "When the deployment write gate is enabled, caller cmd selects the executable in subprocess.run(cmd, shell=False). Authorization does not constrain the executable.", "run_shell_tool"), label(COMMAND, "negative", "delete_file_tool calls os.remove without process execution.", "delete_file_tool")],
    "vuln_tool_scope_same_file_class_collision/server.py": [label(COMMAND, "negative", "ReportHandlers.helper removes a path; no command is executed.")],
    "clean_tool_scope_subprocess_name_no_real_sink/server.py": [label(COMMAND, "negative", "The subprocess-named helper performs only arithmetic.")],
    "vuln_tool_scope_subprocess_readonly_probe/server.py": [label(COMMAND, "negative", "The tool supplies a constant nvidia-smi argv and constant timeout; no user command input reaches the helper.")],
    "vuln_tool_scope_aliased_subprocess/server.py": [label(COMMAND, "positive", "Caller supplies the entire argv, including executable, to aliased subprocess.run.", "probe_status_tool"), label(COMMAND, "positive", "Caller cmd reaches aliased subprocess.run with shell=True.", "check_task_tool")],
    "vuln_tool_scope_bare_imported_sinks/server.py": [label(COMMAND, "positive", "Caller cmd reaches directly imported subprocess.run with shell=True.", "check_state_tool"), label(COMMAND, "positive", "Caller cmd reaches directly imported subprocess.call with shell=True.", "fetch_report_tool"), label(COMMAND, "negative", "Directly imported os.remove deletes a file without command execution.", "sync_status_tool"), label(COMMAND, "negative", "Directly imported shutil.rmtree removes a directory without command execution.", "refresh_cache_tool")],
}
REVIEWED_EXCLUSIONS = {
    "clean_param/safe.py", "vuln_param/sinks.py", "clean_auth/app.py", "vuln_auth/app.py",
    "vuln_param_http_client_bound/server.py", "vuln_param_http_sink_surface/server.py",
}


def main():
    if (OUT / "manifest.json").exists():
        raise SystemExit("Refusing to overwrite reviewed labels")
    freeze = json.loads((OUT / "freeze.json").read_text())
    assert all(hashlib.sha256((ROOT/f).read_bytes()).hexdigest() == h for f,h in freeze["code_files"].items())
    provenance = {a["local_path"]: a for a in json.loads((BASE / "download_manifest.json").read_text())}
    candidates = json.loads((BASE / "iteration_plan.json").read_text())["groups"][1]["files"]
    artifacts, admission = [], []
    previous = json.loads((OUT.parent / "iteration-001/manifest.json").read_text())["artifacts"]
    old_hashes = {a["sha256"] for a in previous}
    reserve_hashes = {a["sha256"] for a in provenance.values() if a.get("repository") == "autod3structeur/MCP-DecayBench" and "sha256" in a}
    for path in candidates:
        relative = path.removeprefix(PREFIX).removesuffix(".txt")
        if relative in LABELS:
            source = provenance[path]
            digest = hashlib.sha256((BASE / path).read_bytes()).hexdigest()
            assert digest == source["sha256"]
            assert digest not in old_hashes | reserve_hashes
            artifacts.append(dict(id=relative.removesuffix(".py").replace("/", "--"),
                path="deliverables/data_expansion/"+path, source_filename=source["upstream_path"],
                sha256=digest, source_url=source["url"], repository=source["repository"],
                revision=source["revision"], labels=LABELS[relative]))
            status, reason = "admitted", "Standalone command/secret case with source-reviewed rule-specific labels."
        elif relative in REVIEWED_EXCLUSIONS:
            status, reason = "excluded-after-source-review", "Generic application or HTTP helper without visible MCP registration; outside this batch's MCP tool-flow evaluation."
        else:
            status, reason = "deferred-without-source-review", "Outside the bounded 24-file standalone source review; includes multi-file and other fixture families. Not scanned or counted as validation."
        admission.append(dict(path="deliverables/data_expansion/"+path, status=status, reason=reason))
    assert len(artifacts) == 18 and len(candidates) == 97
    manifest = dict(schema_version=1, iteration="iteration-002", created_at=datetime.now(timezone.utc).isoformat(),
        purpose="Fresh source-batch validation of a frozen rule-development candidate; not final holdout or weight training",
        review_status="Assistant source review before first batch scan; independent human adjudication pending",
        label_unit="artifact + rule + optional function scope; unlabelled outcomes are unknown",
        scope="MCP01 hardcoded/output secrets and MCP05 command injection only",
        assumptions=["Credential literals are synthetic fixtures, not verified active credentials.",
            "Caller selection of an executable is a positive command-flow label even with shell=False or an enablement gate.",
            "Only command injection is labelled on file-deletion examples; a negative is not overall safety.",
            "Related variants remain one development family, not independent statistical observations.",
            "No exact-byte duplicate among iteration 001 or proposed MCP-DecayBench reserve; semantic/template overlap is not excluded."],
        frozen_code_fingerprint=freeze["code_fingerprint"], artifacts=artifacts)
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2)+"\n", encoding="utf-8")
    (OUT / "admission.json").write_text(json.dumps(dict(candidate_files=97, reviewed_files=24, admitted_files=18,
        excluded_files=6, deferred_files=73, decisions=admission), indent=2)+"\n", encoding="utf-8")
    (OUT / "label-lock.json").write_text(json.dumps(dict(locked_at=datetime.now(timezone.utc).isoformat(),
        manifest_sha256=hashlib.sha256((OUT / "manifest.json").read_bytes()).hexdigest(),
        code_fingerprint=freeze["code_fingerprint"], phase="before first batch 2 prediction"),indent=2)+"\n")
    print("Admitted", len(artifacts), "artifacts and", sum(len(a["labels"]) for a in artifacts), "labels")


if __name__ == "__main__":
    main()
