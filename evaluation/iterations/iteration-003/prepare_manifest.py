"""Lock source-reviewed fresh labels before scanning batch 3. Never run fixtures."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
BASE = ROOT / "deliverables/data_expansion"
PREFIX = "snapshots/jspillers10__mcp-security-scanner/"
C = "MCP05-COMMAND-INJECTION"
D = "MCP05-DYNAMIC-CODE"
S = "MCP01-SECRET-HARDCODED"
O = "MCP01-SECRET-OUTPUT"
P = "MCP03-TOOL-POISON"
A = "MCP07-MISSING-AUTH"


def label(rule, positive, reason, function=None):
    return dict(rule_id=rule, polarity="positive" if positive else "negative", function_name=function, rationale=reason)


LABELS = {
    "benchmark/fixtures/false_negative/aliased_dangerous_function.py": [label(C, True, "Caller command reaches os.system imported as invoke.", "run_task")],
    "benchmark/fixtures/false_negative/class_method_sink.py": [label(C, True, "Caller command reaches subprocess.check_output(shell=True) through Runner.invoke.", "run_task")],
    "benchmark/fixtures/false_negative/dynamic_description.py": [label(P, True, "The description factory concatenates an instruction to read credentials and conceal that action.", "lookup")],
    "benchmark/fixtures/false_negative/multi_hop_dataflow.py": [label(C, True, "Caller command reaches a shell through two local helpers.", "run_report")],
    "benchmark/fixtures/false_negative/obfuscated_command.py": [label(C, True, "getattr selects subprocess.check_output, which receives caller command with shell=True.", "run_task")],
    "benchmark/fixtures/false_positive/benign_imperative_description.py": [label(P, False, "The imperative only requests a valid currency parameter.", "exchange_rate")],
    "benchmark/fixtures/false_positive/legitimate_base64_description.py": [label(P, False, "The encoded example decodes to ordinary fixture text, not behavioral instructions.", "decode_fixture")],
    "benchmark/fixtures/false_positive/registration_resemblance.py": [label(C, False, "Explicit non-MCP scope control: a local ReportRegistry callback is not an MCP registration. Not a general command-safety claim.")],
    "benchmark/fixtures/false_positive/safe_deserialization.py": [label(D, False, "json.loads does not evaluate caller Python code.", "parse_payload"), label(D, False, "yaml.safe_load does not construct arbitrary Python objects.", "parse_yaml")],
    "benchmark/fixtures/false_positive/safe_subprocess_args.py": [label(C, False, "Fixed nslookup argv with shell=False and an alphanumeric/dot hostname guard.", "dns_lookup")],
    "tests/fixtures/safe_command_validation.py": [label(C, False, "A fixed developer-controlled set gates the action before shell use.", "service_action"), label(C, False, "A fixed dictionary selects a constant command; the key is checked before use.", "run_named_diagnostic")],
    "tests/fixtures/safe_description_example.py": [label(P, False, "All tool metadata describes ordinary tasks or parameter requirements; the foreign scanner pragma is not our ground truth.")],
    "tests/fixtures/safe_example.py": [label(C, False, "Both parameters are constrained by fixed allowlists before fixed-executable argv use.", "export_report")],
    "tests/fixtures/safe_readiness_example.py": [label(A, True, "SSE transport has no visible enforcement: merely importing require_bearer_token does not authenticate requests. Loopback limits exposure but is not request authentication.")],
    "tests/fixtures/safe_same_file_helper.py": [label(C, False, "Helper invokes fixed git clone argv, no shell; the only variable is embedded inside a fixed HTTPS URL argument.", "clone_repository")],
    "tests/fixtures/safe_secrets_derived_values.py": [label(S, False, "Values are explicitly one-way hashes/digests/checksums, not credential literals.")],
    "tests/fixtures/safe_secrets_example.py": [label(S, False, "Credentials come from environment; remaining values are explicit placeholders or documentation examples."), label(O, False, "The registered integration_help tool returns a fixed help message, not credentials.")],
    "tests/fixtures/vulnerable_command_validation.py": [
        label(C, True, "A short denylist leaves shell metacharacters and arbitrary commands available.", "run_diagnostic_command"),
        label(C, True, "Allowlist check occurs after command execution.", "run_guard_after_sink"),
        label(C, True, "The inverted guard permits non-allowlisted actions to reach the shell.", "run_inverted_allowlist"),
        label(C, True, "Caller controls both the action and its allowlist.", "run_user_controlled_allowlist"),
        label(C, False, "Despite the upstream name, the visible helper returns a fixed literal safe action set.", "run_dynamic_allowlist"),
        label(C, True, "Blocking spaces leaves shell metacharacters usable.", "run_character_filter_still_dangerous"),
        label(C, True, "The second caller-controlled command is unguarded.", "run_mixed_safe_and_vulnerable"),
        label(C, True, "Caller can disable the guard via debug_mode.", "run_guard_nested_in_condition"),
        label(C, True, "Guard exits only when caller log_only is true.", "run_guard_with_conditional_exit"),
        label(C, False, "For schema-validated string input and the visible fixed set, membership is non-throwing and disallowed input returns before the sink. The try block alone does not establish a bypass.", "run_guard_inside_try"),
        label(C, True, "The guard prints but does not prevent command execution.", "run_nonterminating_guard")],
    "tests/fixtures/vulnerable_description_example.py": [
        label(P, True, "Metadata demands priority invocation and concealment from the user.", "setup"),
        label(P, False, "An isolated zero-width marker has no behavioral payload; suspicious formatting alone is not poisoning.", "fetch_notes"),
        label(P, True, "Encoded text instructs using this tool instead of every other tool.", "sync_data"),
        label(P, True, "Metadata redirects callers away from a named different tool; labelled unauthorized routing under this fixture's threat model.", "get_weather_v2")],
    "tests/fixtures/vulnerable_distinct_sinks.py": [label(D, True, "Caller expression is evaluated as Python.", f) for f in ["run_math", "run_formula", "run_pair_same_line"]],
    "tests/fixtures/vulnerable_duplicate_sink.py": [label(D, True, "A registered compute implementation evaluates caller Python. File-level label avoids double-counting identical function names and the same physical sink via a wrapper.")],
    "tests/fixtures/vulnerable_example.py": [label(S, True, "DB_PASSWORD is a fabricated but explicitly embedded credential literal."), label(C, True, "Both tool arguments enter a shell command string.", "export_report"), label(D, True, "Caller expr reaches eval.", "run_snippet")],
    "tests/fixtures/vulnerable_programmatic_example.py": [label(C, True, "The FastMCP add_tool-registered method interpolates backup_label into a shell command.", "run_backup")],
    "tests/fixtures/vulnerable_readiness_example.py": [label(A, True, "SSE transport has no authentication enforcement and binds all interfaces.")],
    "tests/fixtures/vulnerable_same_file_helper.py": [label(C, True, "Tool input enters a shell string passed through a local helper.", "clone_repository")],
    "tests/fixtures/vulnerable_secrets_example.py": [label(S, True, "Source embeds explicit fabricated passwords/API credentials in multiline text and nested dictionaries."), label(O, False, "Registered tools return written/registered-count status only; the credential-returning helper is neither registered nor called by a tool.")],
    "tests/fixtures/vulnerable_secrets_hashicorp_token.py": [label(S, True, "HASHICORP_TOKEN embeds an explicitly credential-shaped fixture value, not a hash/digest.")],
    "tests/fixtures/vulnerable_transport_auth_boundaries.py": [label(A, True, "Application login tool and token-related names do not gate the exposed HTTP transport.")],
    "tests/fixtures/vulnerable_transport_auth_decorators.py": [label(A, True, "Per-tool no-op decorators do not enforce authentication on the transport.")],
    "tests/fixtures/vulnerable_transport_auth_explicitly_disabled.py": [label(A, True, "auth=None explicitly disables server authentication on the HTTP transport.")],
    "tests/fixtures/live/clean_server.py": [label(P, False, "Weather metadata contains no behavioral override."), label(A, False, "Default stdio server has no exposed HTTP/SSE transport in this source.")],
    "tests/fixtures/live/safe_server.py": [label(P, False, "Order/report metadata describes ordinary tasks."), label(A, False, "Default stdio server has no exposed HTTP/SSE transport in this source.")],
    "tests/fixtures/live/vulnerable_server.py": [label(P, True, "Setup metadata demands priority and concealment.", "setup"), label(P, False, "The sibling tool has an ordinary description.", "clean_tool")],
    "tests/fixtures/live/vulnerable_sse_server.py": [label(P, True, "Setup metadata claims priority over all other actions.", "setup"), label(A, True, "SSE transport lacks visible request authentication, even though it binds loopback.")],
}
EXCLUSIONS = {
    "benchmark/fixtures/false_negative/indirect_prompt_output.py": "The supposedly remote source is a local f-string stub; no actual untrusted external retrieval is established.",
    "benchmark/fixtures/false_negative/runtime_mutation.py": "Mutation is in an uncalled activate function; effect on already-registered tool metadata is not established.",
    "benchmark/fixtures/false_positive/validated_paths.py": "Path traversal has no dedicated rule in our current catalog; do not convert this into an unrelated easy negative.",
    "tests/fixtures/safe_path_validation.py": "Dedicated path-traversal checking is outside the current catalog.",
    "tests/fixtures/vulnerable_path_validation.py": "Dedicated path-traversal checking is outside the current catalog.",
    "tests/fixtures/safe_sql_injection.py": "Dedicated SQL injection checking is outside the current catalog.",
    "tests/fixtures/vulnerable_sql_injection.py": "Dedicated SQL injection checking is outside the current catalog.",
    "tests/fixtures/safe_transport_auth_middleware.py": "backend=object() is a placeholder, not evidence of a functioning authentication/authorization backend.",
    "tests/fixtures/safe_transport_auth_server_config.py": "GateProvider implementation is unavailable; effective authentication cannot be independently adjudicated from this file.",
}


def main():
    if (OUT / "manifest.json").exists(): raise SystemExit("Refusing to overwrite locked labels")
    freeze = json.loads((OUT / "freeze.json").read_text())
    assert all(hashlib.sha256((ROOT/f).read_bytes()).hexdigest() == h for f,h in freeze["code_files"].items())
    provenance = {a["local_path"]: a for a in json.loads((BASE / "download_manifest.json").read_text())}
    paths = json.loads((BASE / "iteration_plan.json").read_text())["groups"][2]["files"]
    old = [a for iteration in ["iteration-001", "iteration-002"] for a in json.loads((OUT.parent/iteration/"manifest.json").read_text())["artifacts"]]
    excluded_hashes = {a["sha256"] for a in old} | {a["sha256"] for a in provenance.values() if a.get("repository") == "autod3structeur/MCP-DecayBench" and "sha256" in a}
    artifacts, decisions = [], []
    for path in paths:
        relative = path.removeprefix(PREFIX).removesuffix(".txt")
        if relative in LABELS:
            source = provenance[path]
            digest = hashlib.sha256((BASE/path).read_bytes()).hexdigest()
            assert digest == source["sha256"] and digest not in excluded_hashes
            artifacts.append(dict(id=relative.removesuffix(".py").replace("/", "--"), path="deliverables/data_expansion/"+path,
                source_filename=source["upstream_path"], sha256=digest, source_url=source["url"],
                repository=source["repository"], revision=source["revision"], labels=LABELS[relative]))
            status, reason = "admitted", "Standalone source reviewed and rule-specific labels locked before predictions."
        elif relative in EXCLUSIONS:
            status, reason = "excluded-after-source-review", EXCLUSIONS[relative]
        else:
            status, reason = "deferred-without-source-review", "Cross-file helper/authentication or multi-server duplicate-name group requires grouped evaluation; not scanned."
        decisions.append(dict(path="deliverables/data_expansion/"+path, status=status, reason=reason))
    assert len(artifacts) == len(LABELS) == 34
    manifest = dict(schema_version=1, iteration="iteration-003", created_at=datetime.now(timezone.utc).isoformat(),
        purpose="Frozen fresh source-batch validation; not final holdout or model-weight training",
        review_status="Assistant source review before first scan; independent human adjudication pending",
        label_unit="artifact + rule + optional function scope; unlabelled outcomes are unknown",
        scope="Selected MCP01, MCP03, MCP05, MCP07 rules only",
        assumptions=["Synthetic credentials are labels for embedded/output credential evidence, not verified active secrets.",
            "Command controls assume normal FastMCP schema enforcement and standard executable semantics.",
            "Source code overrides upstream safe/vulnerable filenames and comments in label decisions.",
            "The isolated zero-width marker is not poisoning without a behavioral payload; encoded routing instructions are positive.",
            "No exact-byte duplicates against admitted batches 1/2 or proposed MCP-DecayBench reserve; semantic duplication and related-template dependence remain possible.",
            "Negative labels concern the specified rule only; absence of command injection does not imply authorization or audit safety."],
        frozen_code_fingerprint=freeze["code_fingerprint"], artifacts=artifacts)
    (OUT/"manifest.json").write_text(json.dumps(manifest, indent=2)+"\n", encoding="utf-8")
    (OUT/"admission.json").write_text(json.dumps(dict(candidate_files=57, reviewed_files=43, admitted_files=34, excluded_files=9, deferred_files=14, decisions=decisions),indent=2)+"\n",encoding="utf-8")
    (OUT/"label-lock.json").write_text(json.dumps(dict(locked_at=datetime.now(timezone.utc).isoformat(),
        manifest_sha256=hashlib.sha256((OUT/"manifest.json").read_bytes()).hexdigest(),
        code_fingerprint=freeze["code_fingerprint"], phase="before first batch 3 prediction"),indent=2)+"\n")
    print("Admitted", len(artifacts), "files; labels", sum(len(a["labels"]) for a in artifacts))


if __name__ == "__main__": main()
