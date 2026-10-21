"""Source-adjudicated labels locked before any batch 4 scanner predictions.

Only parses/reads snapshots. Never imports or executes a fixture.
"""
import ast
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
BASE = ROOT / 'deliverables/data_expansion'
PREFIX = 'snapshots/cisco-ai-defense__mcp-scanner/'
DATA = 'evals/behavioral-analysis/data/'
C = 'MCP05-COMMAND-INJECTION'
D = 'MCP05-DYNAMIC-CODE'
P = 'MCP03-TOOL-POISON'
R = 'MCP13-SSRF'
A = 'MCP07-MISSING-AUTH'
S = 'MCP01-SECRET-HARDCODED'
LABELS = {}


def label(rule, positive, reason, function=None):
    return dict(rule_id=rule, polarity='positive' if positive else 'negative', function_name=function, rationale=reason)


def add(group, name, rule, positive, function, reason):
    path = DATA + group + '/' + name + '.py'
    LABELS.setdefault(path, []).append(label(rule, positive, reason, function))


for name, function, reason in [
    ('command_injection_grep', 'search_logs', 'Caller pattern is interpolated inside shell quotes without escaping; a quote can terminate the argument.'),
    ('curl_command_injection', 'fetch_url', 'URL prefix checking does not constrain shell metacharacters; caller custom options and other fields enter a shell command through HTTPClient.'),
    ('format_string_injection', 'create_backup', 'Caller custom_flags, directory and destination reach os.system through percent formatting.'),
    ('os_system_injection_archives', 'compress_file', 'Caller filename/output_name reaches shell strings in FileCompressor; file-existence checking is not shell escaping.'),
    ('template_command_injection', 'process_file', 'Caller processor and flags fill a string.Template command executed with shell=True.'),
]:
    add('injection-attacks', name, C, True, function, reason)
add('injection-attacks', 'shell_injection_network_diagnostics', C, False, 'ping_host',
    'Hostname regex restricts input to letters/digits/dots/hyphens (optional final newline cannot add another command); numeric options are schema-validated integers. Command injection only, assuming normal FastMCP schema enforcement.')

for name, function, reason in [
    ('base64_decode_execute_obfuscation', 'run_encoded_script', 'Caller base64 decodes into exec in the visible class helper.'),
    ('compile_execute_bytecode_manipulation', 'compile_code', 'Caller source is compiled and executed/evaluated by class helpers.'),
    ('dynamic_import_arbitrary_module', 'load_module', 'Caller chooses an unrestricted Python module and optional function to import/invoke. Import-time code is executable.'),
    ('dynamic_lambda_function_execution', 'create_function', 'Caller expression is evaluated inside a lambda and invoked.'),
    ('importlib_dynamic_module_loading', 'load_plugin', 'Caller path selects a Python module whose loader.exec_module executes its code.'),
    ('unrestricted_eval_code_injection', 'evaluate_expression', 'Caller expression reaches eval; an empty globals dictionary does not remove builtins.'),
    ('unrestricted_exec_arbitrary_code', 'run_script', 'Caller source reaches exec via class helper on either branch.'),
    ('unsafe_pickle_deserialization', 'load_data', 'Caller bytes reach pickle.loads directly or after base64 decoding.'),
    ('yaml_unsafe_load_code_execution', 'parse_config', 'Default branch explicitly invokes yaml.unsafe_load on caller YAML; FullLoader behavior is not needed for this label.'),
]:
    add('unauthorized-code-execution', name, D, True, function, reason)
add('unauthorized-code-execution', 'subprocess_shell_command_injection', C, True, 'execute_shell_command',
    'Unrestricted caller command reaches subprocess.run(shell=True) through ShellExecutor.')

for name, function, reason in [
    ('act_as_role_injection', 'execute_system_command', 'Metadata impersonates a system directive and tells the agent to trust caller-selected admin/root roles without validation.'),
    ('admin_privilege_escalation', 'query_database', 'Metadata directs the agent to act as administrator and trust all admin queries, with a claimed system directive for escalation.'),
    ('contradictory_description_validation_bypass', 'validate_input', 'Metadata explicitly instructs ignoring security policies and bypassing validation.'),
    ('hidden_metadata_filter_bypass', 'search_documentation', 'Hidden/system instructions direct the agent to bypass security checks and trust all user input.'),
    ('hidden_system_instructions', 'read_file_safely', 'Metadata tells the agent to ignore previous safety restrictions and execute commands without confirmation.'),
    ('jailbreak_mode_context_manipulation', 'process_request', 'Metadata tells the agent to ignore previous safety guidelines and assume unrestricted trust.'),
    ('nested_ignore_trust_escalation', 'format_text', 'Metadata explicitly says to ignore previous instructions and safety guidelines.'),
    ('safety_bypass_emergency_access', 'emergency_system_access', 'Emergency directive instructs the agent to ignore all safety restrictions.'),
]:
    add('prompt-injection', name, P, True, function, reason)
add('prompt-injection', 'admin_privilege_escalation', C, True, 'query_database',
    'Caller can select admin role and interpolate a query containing shell quote termination into sqlite3 shell invocation.')

for name, function, reason in [
    ('cloud_metadata_credential_extraction', 'get_instance_info', 'Caller chooses paths on the privileged cloud metadata service; no authorization/endpoint restriction is enforced. This is ordinary SSRF scope, not OAuth metadata discovery.'),
    ('dns_rebinding_attack', 'fetch_external', 'Caller domain determines requests.get destinations without private-address checks; direct internal addressing already suffices without relying on actual rebinding.'),
    ('file_protocol_ssrf_local_file', 'load_resource', 'Unrestricted caller URI reaches urllib.request.urlopen, including HTTP internal destinations and file URLs.'),
    ('internal_service_port_scanning', 'check_service', 'Caller hostname and port reach requests.get through probe_endpoints without destination restrictions.'),
    ('localhost_metadata_service_access', 'fetch_data', 'Caller chooses arbitrary paths on localhost and can enable privileged metadata probing without authorization.'),
    ('private_ip_range_scanning', 'probe_network', 'Caller IP reaches requests.get; the private-IP check enables extra scanning rather than rejecting internal targets.'),
    ('redirect_chain_internal_service', 'download_file', 'Caller URL is fetched with redirects before internal-destination checks, which only annotate results.'),
    ('redirect_following_open_redirect', 'download_file', 'Caller URL is fetched with redirects and no destination restriction.'),
    ('ssrf_url_manipulation_internal_network', 'fetch_resource', 'Caller controls both base URL and urljoin path; result is fetched without destination checks.'),
]:
    add('unauthorized-network-access', name, R, True, function, reason)
add('resource-exhaustion', 'network_bandwidth_exhaustion', R, True, 'download_files',
    'Caller URL list reaches requests.get through class helpers and iteration. Label concerns SSRF, not the out-of-catalog resource-exhaustion behavior.')

# Explicit semantic extension already implemented by the scanner: materially
# deceptive metadata/implementation mismatch. Report this stratum separately.
for name, function, reason, network in [
    ('behavioral_profiling_user_tracking', 'search_products', 'Advertises product search, but only profiles and transmits user queries and returns a fixed placeholder.', True),
    ('hidden_analytics_location_tracking', 'calculate_distance', 'Advertises coordinate arithmetic but also sends coordinates and session tracking to unrelated services without disclosure.', True),
    ('hidden_data_collection_model_training', 'translate_text', 'Advertises translation, but sends input into a training dataset explicitly marked consent=False and returns a placeholder.', True),
    ('hidden_monetization_affiliate_tracking', 'shorten_url', 'Advertises URL shortening, but adds affiliate parameters and undisclosed tracking instead.', True),
    ('incomplete_security_fake_encryption', 'encrypt_data', 'Falsely advertises AES-256; returns reversible base64 without encryption or use of the supplied key.' , False),
    ('misleading_functionality_fake_operations', 'compress_image', 'Falsely advertises compression; only renames/copies files and writes fake compression metadata.', False),
    ('undisclosed_tracking_data_collection', 'validate_email', 'Advertises email format validation but transmits email and host/user/home information to an undisclosed tracking endpoint.', True),
]:
    add('general-description-code-mismatch', name, P, True, function,
        'Semantic description/behavior mismatch stratum (not an explicit instruction override): '+reason)
    if network:
        add('general-description-code-mismatch', name, R, False, function,
            'Network destinations are fixed HTTPS literals; caller values are request bodies, not URLs. Other hidden tracking risks remain positive. Assumes standard endpoint behavior, without speculative redirects.')

safe = 'evals/behavioral-analysis/scripts/safe_fastmcp_server.py'
LABELS[safe] = [label(rule, False, 'Echo/arithmetic tools have ordinary metadata, no command/code/network sinks, no credential literal and only default stdio transport.') for rule in [P,C,D,R,S,A]]
for name in ['GitHub_tools', 'azure_tools', 'discord_tools']:
    LABELS['evals/remote/benign/'+name+'.py'] = [
        label(P, False, 'All registered descriptions describe ordinary API tasks without behavioral overrides; implementations are response stubs.'),
        label(C, False, 'AST call inventory contains only response construction, builtins, timestamps and MCP/uvicorn setup; no command execution sink.'),
        label(D, False, 'No evaluation, deserialization or dynamic import sink; implementation only constructs responses.'),
        label(R, False, 'Returned URL strings are data; no outbound network-client calls occur.'),
        label(A, True, 'Despite benign tool behavior, sse_app is served by uvicorn on 0.0.0.0 with no authentication middleware or provider.'),
    ]
LABELS['evals/remote/malicious/malicious_mcp_server.py'] = [
    label(C, False, 'Despite malicious naming/description, this function only returns a dictionary and never executes the command.', 'cmdi_shell_execute'),
    label(D, False, 'Despite eval/exec wording, this function only returns code length and flags.', 'cmdi_python_eval'),
    label(R, False, 'Despite exfiltration wording, this function returns endpoint/length metadata and performs no HTTP request.', 'exfil_http_post'),
]


def normalized(source):
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                node.body = node.body[1:] or [ast.Pass()]
    return hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest()


def main():
    assert not (OUT/'manifest.json').exists(), 'Labels already locked'
    freeze = json.loads((OUT/'freeze.json').read_text())
    assert all(hashlib.sha256((ROOT/p).read_bytes()).hexdigest()==h for p,h in freeze['code_files'].items())
    provenance = {a['local_path']:a for a in json.loads((BASE/'download_manifest.json').read_text())}
    paths = json.loads((BASE/'iteration_plan.json').read_text())['groups'][3]['files']
    old = [a for i in range(1,4) for a in json.loads((OUT.parent/f'iteration-{i:03}/manifest.json').read_text())['artifacts']]
    excluded_hashes = {a['sha256'] for a in old} | {a['sha256'] for a in provenance.values() if a.get('repository')=='autod3structeur/MCP-DecayBench' and 'sha256' in a}
    old_ast = {normalized((ROOT/a['path']).read_text(encoding='utf-8')) for a in old}
    artifacts, decisions, seen = [], [], set()
    for path in paths:
        rel = path.removeprefix(PREFIX).removesuffix('.txt')
        group = rel.split('/')[-2]
        if rel in LABELS:
            source=provenance[path];digest=hashlib.sha256((BASE/path).read_bytes()).hexdigest()
            assert digest==source['sha256'] and digest not in excluded_hashes and digest not in seen
            assert normalized((BASE/path).read_text(encoding='utf-8')) not in old_ast
            seen.add(digest)
            artifacts.append(dict(id=rel.removesuffix('.py').replace('/','--'), path='deliverables/data_expansion/'+path,
                source_filename=source['upstream_path'], sha256=digest, source_url=source['url'],
                repository=source['repository'], revision=source['revision'], labels=LABELS[rel]))
            status,reason='admitted','Source-reviewed rule-specific labels locked before predictions.'
        elif group=='resource-exhaustion':
            status,reason='excluded-after-source-review','Resource exhaustion has no dedicated rule in catalog 2026.1; do not relabel as MCP16.'
        elif group=='general-description-code-mismatch':
            status,reason='excluded-after-source-review','External processing or persistence alone needs a clearer consent/threat model to establish malicious metadata; deferred for adjudication.'
        elif rel.endswith('/unix_socket_docker_exploitation.py'):
            status,reason='excluded-after-source-review','requests.get(http+unix://...) lacks the required transport adapter; reachable exploitation through this tool is not established.'
        elif rel.endswith(('/system_prompt_override.py','/override_instruction_injection.py')):
            status,reason='excluded-after-source-review','Describes configurable behavior and claims directives; ambiguity between configuration documentation and agent-directed override requires independent adjudication.'
        else:
            status,reason='deferred-after-structural-inventory','Only AST structure inventoried. Detailed source-to-catalog adjudication remains; not scanned in this batch. Related Cisco family is now exposed.'
        decisions.append(dict(path='deliverables/data_expansion/'+path,status=status,reason=reason))
    assert len(artifacts)==len(LABELS)==46
    manifest=dict(schema_version=1, iteration='iteration-004',created_at=datetime.now(timezone.utc).isoformat(),
        purpose='Frozen fresh source-batch validation; not final holdout or model-weight training',
        review_status='Assistant source adjudication before predictions; independent human adjudication pending',
        label_unit='artifact + rule + optional function scope; unlabelled outcomes are unknown',
        scope='Selected MCP01/MCP03/MCP05/MCP07/MCP13 rules; seven MCP03 semantic-mismatch cases reported separately',
        assumptions=['Synthetic source fixtures are statically evaluated, never executed. Runtime importability/exploit success is not established.',
            'FastMCP schema validation and standard library/executable semantics are assumed where explicitly noted.',
            'Source behavior overrides upstream category names: simulated attacks can be negative controls.',
            'Seven materially deceptive metadata/behavior mismatches extend MCP03 beyond explicit malicious instructions; separate stratum required.',
            'No exact-byte or comment/docstring-independent exact AST duplicates with batches 1-3. Related templates and semantic dependence remain.',
            'Negatives are rule-specific; benign response tools still expose unauthenticated network services.'],
        frozen_code_fingerprint=freeze['code_fingerprint'],artifacts=artifacts)
    write=lambda name,obj:(OUT/name).write_text(json.dumps(obj,indent=2)+'\n',encoding='utf-8')
    write('manifest.json',manifest)
    counts=Counter(d['status'] for d in decisions)
    write('admission.json',dict(candidate_files=len(paths),admitted_files=len(artifacts),status_counts=dict(counts),decisions=decisions))
    write('label-lock.json',dict(locked_at=datetime.now(timezone.utc).isoformat(),manifest_sha256=hashlib.sha256((OUT/'manifest.json').read_bytes()).hexdigest(),
        code_fingerprint=freeze['code_fingerprint'],phase='Before first batch 4 prediction'))
    print('Admitted',len(artifacts),'files;',sum(len(a['labels']) for a in artifacts),'labels',counts)


if __name__=='__main__': main()
