"""Project-wide static checks for MCP attack categories other than MCP03/MCP06."""

import ast
import re
import unicodedata
from pathlib import Path
from typing import Iterable, List, Optional

from .base import Finding, Severity
from ..catalog import ATTACK_CATEGORIES, RULES
from ..evidence import Evidence
from ..dataflow import PythonDataFlow
from ..security_graph import SecurityGraph
from ..secret_flow import SecretFlow
from ..external_content import carries_file_text, carries_http_text
from ..script_flow import code_mask, arguments as script_arguments, safe_git_argv, file_text_returns
from ..literal_secrets import hardcoded_lines
from ..reachable_python import ReachablePython, CODE_SINKS, depends, fixed_public_origin, privileged_origin, prefix
from ..parsers.python_parser import MCPServerInfo, ToolDefinition


MCP_SECURITY_REFERENCE = "https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices"
OWASP_REFERENCE = "https://github.com/OWASP/www-project-mcp-top-10"


class ProjectRiskAnalyzer:
    """Combines AST checks with conservative project/configuration signatures."""

    SECRET_PATTERNS = [
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"gh[pousr]_[A-Za-z0-9_]{30,}"),
        re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
        re.compile(r"(?i)\b(api[_-]?key|client[_-]?secret|access[_-]?token|password)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ]
    BROAD_SCOPE = re.compile(r"(?i)(?:scope|scopes)[^\n]{0,80}(?:\*|admin(?::\*|\b)|files:\*|db:\*|full[_-]?access)")
    DANGEROUS_STARTUP = re.compile(r"(?i)(?:curl\s+[^\n|;&]+\|\s*(?:sh|bash)|wget\s+[^\n|;&]+\|\s*(?:sh|bash)|sudo\b|rm\s+-rf|powershell[^\n]*(?:-enc|-command)|cmd(?:\.exe)?\s+/c)")
    # Match executable package/source references, not arbitrary documentation or
    # project URLs. Git URLs are handled as dependencies by manifest-specific
    # checks; a README/homepage link to /main is not a server registration.
    MUTABLE_RUNNER = re.compile(r"(?i)(?:\bnpx\s+(?:-y\s+)?(?![^\n]*@\d)|\buvx\s+(?![^\n]*==)|\"command\"\s*:\s*\"(?:npx|uvx)\"(?![^\]]*(?:@\d|==\d))|github:[^\s#\"]+(?:[\s\"]|$))")

    def analyze_python(self, info: MCPServerInfo) -> List[Finding]:
        findings: List[Finding] = []
        source = info.source_code
        findings.extend(self._text_checks(info.filepath, source, "python"))

        try:
            tree = ast.parse(source)
        except SyntaxError:
            return findings

        for line in hardcoded_lines(tree):
            findings.append(self._finding("MCP01-SECRET-HARDCODED", info.filepath, line,
                "Python source embeds a credential-like literal.",
                "Move credentials to a secret manager and rotate any exposed value.", "HIGH", "python", "[REDACTED]"))

        self._network_helpers = self._summarize_network_helpers(tree)
        self._module_constants = self._collect_module_constants(tree)
        self._command_helpers = PythonDataFlow().summarize_command_helpers(tree)
        self._command_context = tree
        self._reachable = ReachablePython(tree)

        for tool in info.tools:
            findings.extend(self._analyze_tool_ast(tool))

        # Global mutable context is especially risky when tools share it without
        # an authenticated user/session key.
        for node in tree.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = node.value
                names = [target.id for target in targets if isinstance(target, ast.Name)]
                for name in names:
                    if re.search(r"(?i)(context|memory|history|session|cache|state)", name) and isinstance(value, (ast.Dict, ast.List, ast.Set, ast.Call)):
                        findings.append(self._finding("MCP10-SHARED-CONTEXT", info.filepath, node.lineno,
                            f"Global mutable state '{name}' may be shared across users or sessions.",
                            "Store context per authenticated user and session with expiry and explicit field allowlists.", "MEDIUM", matched=name))

        secret_flow = SecretFlow(tree)
        for tool in info.tools:
            if not isinstance(tool.raw_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            returned, _ = secret_flow.analyze(tool.raw_node)
            for node, flags in returned:
                if "secret" in flags:
                    findings.append(self._finding("MCP01-SECRET-OUTPUT", info.filepath, node.lineno,
                        "Credential-bearing data can reach a tool return value.",
                        "Return selected non-secret fields and redact credentials before producing tool output.",
                        "HIGH", "python", "[REDACTED]", tool.name))
                if "broad" in flags:
                    findings.append(self._finding("MCP10-OVER-SHARING", info.filepath, node.lineno,
                        "A tool can return an entire environment or broad context object.",
                        "Return explicitly selected fields without unrelated session data or credentials.",
                        "HIGH", "python", "[REDACTED]", tool.name))
        module_scope = ast.FunctionDef(name="<module>", args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]),
                                       body=tree.body, decorator_list=[])
        functions = [module_scope] + [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for function in functions:
            _, logs = secret_flow.analyze(function)
            for call in logs:
                findings.append(self._finding("MCP01-SECRET-OUTPUT", info.filepath, call.lineno,
                    "Credential-bearing data can reach a logging call.",
                    "Redact credentials before writing logs.", "HIGH", "python", "[REDACTED]", function.name))

        network_transport = re.search(r"(?i)(streamable[_-]?http|transport\s*=\s*['\"](?:http|sse)|fastapi|starlette|uvicorn)", source)
        server_construction = re.search(
            r"(?i)(?:\b(?:FastMCP|MCPServer|Server)\s*\(|\.run\s*\([^)]*transport|\.http_app\s*\(|mcp_app\s*=)",
            source,
        )
        if network_transport and server_construction and not self._has_auth_enforcement(source):
            findings.append(self._finding("MCP07-MISSING-AUTH", info.filepath, self._line(source, network_transport.start()),
                "A network-capable MCP transport has no visible authentication or authorization enforcement.",
                "Authenticate every request and authorize each tool/resource operation.", "MEDIUM"))

        lower = source.lower()
        if ("authorization" in lower and "redirect_uri" in lower and
                not all(term in lower for term in ("state", "consent", "client_id"))):
            findings.append(self._finding("MCP11-CONFUSED-DEPUTY", info.filepath, 1,
                "OAuth proxy flow does not show per-client consent, state, and client binding controls.",
                "Bind consent and OAuth state to each client_id and exactly validate redirect_uri.", "MEDIUM"))

        if re.search(r"(?i)(authorization|bearer|access_token).{0,120}(requests|httpx|aiohttp)\.", source, re.DOTALL):
            if not re.search(r"(?i)(audience|\baud\b|token_exchange|client_credentials|validate_token)", source):
                findings.append(self._finding("MCP12-TOKEN-PASSTHROUGH", info.filepath, 1,
                    "An inbound credential appears near a downstream HTTP request without visible audience validation or token exchange.",
                    "Accept only tokens issued for this MCP server and obtain a separate downstream token.", "MEDIUM"))

        if re.search(r"(?i)(session_id|mcpsessionid)\s*=\s*(?:str\()?uuid\.uuid1|session_id\s*=\s*(?:request\.|params)", source):
            findings.append(self._finding("MCP14-WEAK-SESSION", info.filepath, 1,
                "Session identifiers appear predictable or directly client-controlled.",
                "Generate cryptographically random IDs, expire them, and bind them to the authenticated user.", "HIGH"))
        if re.search(r"(?i)if\s+.*session_id.*(?:authorized|authenticated)|sessions?\s*\[\s*session_id\s*\]", source):
            findings.append(self._finding("MCP14-SESSION-AUTH", info.filepath, 1,
                "A session identifier appears to act as the authorization decision or sole state key.",
                "Authorize every request and key shared session state by authenticated user plus session ID.", "MEDIUM"))

        if re.search(r"(?i)(webbrowser\.open|window\.open|startfile)\s*\([^)]*(authorization|auth|endpoint|url)", source) or re.search(r"(?i)(subprocess|os\.system)[^\n]*(authorization|auth)_?url", source):
            findings.append(self._finding("MCP15-UNSAFE-AUTH-URL", info.filepath, 1,
                "A dynamic authorization URL is opened without visible scheme validation.",
                "Allow only HTTPS (or development loopback HTTP) and never open URLs through a shell.", "HIGH"))

        if re.search(r"(?i)(subprocess\.(?:run|popen)|os\.system)\s*\([^\n]*(request|params|command|args)", source) and "stdio" in lower:
            findings.append(self._finding("MCP16-ARBITRARY-SPAWN", info.filepath, 1,
                "A stdio/proxy path appears able to spawn a request-controlled command.",
                "Use a fixed executable allowlist, fixed argument schemas, sandboxing, and explicit authorization.", "HIGH"))
        return self._dedupe(findings)

    def analyze_name_collisions(self, names: Iterable[tuple[str, str, str]]) -> List[Finding]:
        """Detect exact and Unicode/confusable names across server/tool sources."""
        findings: List[Finding] = []
        seen = {}
        for kind, name, path in names:
            normalized = "".join(ch for ch in unicodedata.normalize("NFKC", name).casefold() if ch.isalnum())
            key = (kind, normalized)
            if normalized and key in seen and (seen[key][0] != name or seen[key][1] != path):
                previous_name, previous_path = seen[key]
                # Identical names in different source files commonly represent
                # independent examples, transports, or applications. Without an
                # application/registration graph there is no evidence that they
                # coexist. Retain Unicode/punctuation confusables, where the raw
                # names differ but normalize to the same identifier.
                if previous_name == name:
                    continue
                findings.append(self._finding("MCP09-CONFUSABLE-NAME", path, 1,
                    f"{kind.title()} name '{name}' conflicts with '{previous_name}' from {previous_path}.",
                    "Use globally unique names and an approved server inventory; reject ambiguous registrations.", "MEDIUM", "config", name))
            else:
                seen[key] = (name, path)
        return findings

    def analyze_cross_file_flows(self, graph: SecurityGraph,
                                 tools: list[ToolDefinition]) -> List[Finding]:
        findings = []
        for tool, flow, definition_path in graph.cross_file_command_flows(tools):
            finding = self._finding("MCP05-COMMAND-INJECTION", tool.source_file, flow.line,
                f"Tool-controlled data reaches a command wrapper defined in {definition_path.name}.",
                "Validate the tool input before the helper call and use a fixed executable with an argument allowlist.",
                "HIGH", "python", flow.sink, tool.name)
            finding.metadata["evidence"] = Evidence(finding.rule_id, flow.source, flow.sink,
                list(flow.path), [], ["validated arguments", "fixed executable"]).to_dict()
            finding.metadata["related_definition"] = str(definition_path)
            findings.append(finding)
        return self._dedupe(findings)

    def analyze_artifact(self, path: str | Path, text: str) -> List[Finding]:
        path = str(path)
        kind = self._source_kind(path)
        findings = self._text_checks(path, text, kind)
        lower_name = Path(path).name.lower()

        if self.DANGEROUS_STARTUP.search(text):
            match = self.DANGEROUS_STARTUP.search(text)
            findings.append(self._finding("MCP16-DANGEROUS-STARTUP", path, self._line(text, match.start()),
                "Configuration contains a dangerous local startup command.",
                "Replace shell startup with a fixed executable and arguments; require explicit user consent.", "HIGH", kind, match.group(0)))
        if self.MUTABLE_RUNNER.search(text):
            match = self.MUTABLE_RUNNER.search(text)
            findings.append(self._finding("MCP09-UNMANAGED-SERVER", path, self._line(text, match.start()),
                "MCP server configuration executes a mutable or unpinned package/source.",
                "Pin the package/version or immutable commit and record it in the approved server inventory.", "HIGH", kind, match.group(0)))

        dependency_file = any(token in lower_name for token in ("requirements", "pyproject", "pipfile", "poetry.lock", "uv.lock", "package.json", "package-lock"))
        if dependency_file:
            for index, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if self._looks_unpinned_dependency(stripped, lower_name):
                    findings.append(self._finding("MCP04-MUTABLE-DEPENDENCY", path, index,
                        "Dependency or executable package is not pinned to an immutable version.",
                        "Pin exact versions and commit hashes and commit the corresponding lockfile.", "MEDIUM", kind, stripped))
            if re.search(r"(?i)\"(?:preinstall|install|postinstall)\"\s*:\s*\"[^\"]*(?:curl|wget|powershell|bash|sh\s)", text):
                match = re.search(r"(?i)\"(?:preinstall|install|postinstall)\"", text)
                findings.append(self._finding("MCP04-INSTALL-HOOK", path, self._line(text, match.start()),
                    "Package manifest contains a network or shell-capable install hook.",
                    "Remove the hook or constrain and review it as privileged supply-chain code.", "HIGH", kind))
        return self._dedupe(findings)

    def _analyze_tool_ast(self, tool: ToolDefinition) -> List[Finding]:
        findings: List[Finding] = []
        try:
            low_level = tool.registration_style == "low_level" and isinstance(tool.raw_node, (ast.FunctionDef, ast.AsyncFunctionDef))
            module = ast.Module(body=[tool.raw_node], type_ignores=[]) if low_level else ast.parse(tool.function_body)
        except SyntaxError:
            return findings
        params = set(tool.parameters)
        sensitive = False
        audited = bool(re.search(r"(?i)(audit|logger\.|logging\.|telemetry|trace)", tool.function_body))
        flow_parameters = tool.parameters + ([a.arg for a in tool.raw_node.args.args] if low_level else [])
        command_flows = PythonDataFlow().command_flows(module, flow_parameters, getattr(self, "_command_helpers", {}),
                                                      getattr(self, "_command_context", None), tool.raw_node)
        flow_lines = {flow.line: flow for flow in command_flows}
        for node in ast.walk(module):
            if not isinstance(node, ast.Call):
                continue
            name = self._call_name(node.func).lower()
            dump = ast.dump(node)
            uses_param = any(re.search(rf"\b{re.escape(param)}\b", dump) for param in params)
            line = getattr(node, "lineno", 1) if low_level else tool.line_number + getattr(node, "lineno", 1) - 1
            flow = flow_lines.get(getattr(node, "lineno", 1))
            if flow:
                sensitive = True
                finding = self._finding("MCP05-COMMAND-INJECTION", tool.source_file, line,
                    "Tool-controlled data can reach a command execution sink.",
                    "Use a fixed executable and argument allowlist; never use shell=True with tool input.",
                    "HIGH", "python", flow.sink, tool.name)
                finding.metadata["evidence"] = Evidence(finding.rule_id, flow.source, flow.sink,
                    list(flow.path), list(flow.protections), ["fixed executable", "argument allowlist"]).to_dict()
                findings.append(finding)
            if name in {"os.system", "os.popen", "subprocess.run", "subprocess.popen", "subprocess.call", "subprocess.check_output"}:
                sensitive = True
            if name in {"eval", "exec", "compile"} and uses_param:
                sensitive = True
            if name in {"open", "pathlib.path.read_text", "pathlib.path.read_bytes"} or name.startswith(("subprocess.", "os.remove", "shutil.")):
                sensitive = True
        findings.extend(self._analyze_reachable_calls(tool))
        if sensitive and not audited:
            findings.append(self._finding("MCP08-MISSING-AUDIT", tool.source_file, tool.line_number,
                "A sensitive tool performs file/process operations without visible audit telemetry.",
                "Record actor, tool, approved parameters, outcome, and correlation ID without logging secrets.", "LOW", "python", function_name=tool.name))
        return findings

    def _analyze_reachable_calls(self, tool):
        root = tool.raw_node
        context = getattr(self, "_command_context", None)
        if not isinstance(root, (ast.FunctionDef, ast.AsyncFunctionDef)) or context is None: return []
        analysis = self._reachable
        parameters = list(tool.parameters)
        if tool.registration_style == "low_level": parameters += [a.arg for a in root.args.args]
        calls = analysis.analyze(root, parameters)
        findings = []
        if any(carries_file_text(value) for value in analysis.returns):
            findings.append(self._finding("MCP06-UNTRUSTED-CONTEXT", tool.source_file, tool.line_number,
                "External file text reaches a tool return through a visible pathlib call path.",
                "Keep external content separate from instructions and return validated structured data where possible.",
                "MEDIUM", "python", "pathlib file text returned", tool.name))
        if any(carries_http_text(value) for value in analysis.returns):
            findings.append(self._finding('MCP06-UNTRUSTED-CONTEXT', tool.source_file, tool.line_number,
                'HTTP response text or a textual JSON field reaches a tool return through aliases or helpers.',
                'Treat response text as untrusted and apply a content boundary before returning it.',
                'MEDIUM', 'python', 'HTTP text returned', tool.name))
        for call in calls:
            if call.name in CODE_SINKS | {'importlib.loader.exec_module'} and any(depends(a, analysis.parameters) for a in call.args):
                finding = self._finding("MCP05-DYNAMIC-CODE", tool.source_file, call.line,
                    "Tool input reaches code execution, dynamic import or unsafe deserialization through a visible call path.",
                    "Use a strict parser or an explicit operation/module allowlist.", "HIGH", "python", call.name, tool.name)
                finding.metadata['evidence'] = Evidence(finding.rule_id, 'tool-controlled parameter', call.name, list(call.path)+[call.name], [], ['safe parser', 'operation allowlist']).to_dict()
                findings.append(finding)
            if call.http and (depends(call.destination, analysis.parameters) or privileged_origin(call.destination)) and not fixed_public_origin(call.destination):
                sink = call.path[1].split('.')[-1] if len(call.path)>1 else call.name
                finding = self._finding("MCP13-SSRF", tool.source_file, call.line,
                    "A tool can request a caller-controlled destination or privileged internal endpoint through a visible HTTP client.",
                    "Allowlist schemes and destinations, block private/reserved addresses and validate redirects.", "HIGH", "python", call.name, tool.name)
                finding.metadata['evidence'] = Evidence(finding.rule_id, 'tool-controlled parameter', sink+' destination', list(call.path)+[call.name+'(destination)'], [], ['destination validation']).to_dict()
                destination = call.destination
                if (isinstance(destination, ast.Call) and destination.args and fixed_public_origin(destination.args[0])
                        and re.match(r'^https?://[^/?#]+[/?#]', prefix(destination.args[0])[0])):
                    qualified = getattr(destination, '_resolved_name', '')
                    if qualified and '.' in qualified:
                        finding.metadata['unresolved_url_transform'] = qualified
                findings.append(finding)
        return findings

    def analyze_script(self, info: MCPServerInfo) -> List[Finding]:
        """Analyze TypeScript/JavaScript tools using the common source/sink model."""
        findings = self._text_checks(info.filepath, info.source_code, "typescript")
        command_names = set()
        command_kinds = {}
        namespace_names = set()
        for imports in re.findall(r"import\s*\{([^}]+)\}\s*from\s*['\"](?:node:)?child_process['\"]", info.source_code):
            for item in imports.split(","):
                parts = re.split(r"\s+as\s+", item.strip())
                if parts and parts[0] in {"exec", "execSync", "spawn", "spawnSync", "execFile"}:
                    command_names.add(parts[-1])
                    command_kinds[parts[-1]] = parts[0]
        namespace_names.update(re.findall(r"import\s+\*\s+as\s+(\w+)\s+from\s*['\"](?:node:)?child_process['\"]", info.source_code))
        for destructured in re.findall(r"(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\(['\"](?:node:)?child_process['\"]\)", info.source_code):
            command_names.update(x.strip().split(":")[-1].strip() for x in destructured.split(",") if x.strip())
        command_patterns = [rf"(?<![.\w$]){re.escape(name)}\s*\(" for name in command_names]
        command_patterns += [rf"\b{re.escape(ns)}\.(?:exec|execSync|spawn|spawnSync|execFile)\s*\(" for ns in namespace_names]
        command_pattern = "|".join(command_patterns)
        for tool in info.tools:
            body = tool.implementation_source or tool.function_body
            executable = code_mask(body)
            params = {p for p in tool.parameters if p}
            tainted = set(params)
            # Propagate aliases and template/string construction for four rounds.
            for _ in range(4):
                for match in re.finditer(r"(?m)\b([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)", body):
                    if any(re.search(rf"\b{re.escape(p)}\b", match.group(2)) for p in tainted):
                        if not re.search(r"(?i)(allowlist|validate|sanitize|shellescape|quote)\s*\(", match.group(2)):
                            tainted.add(match.group(1))
            sink_prefix = rf"(?:{command_pattern}|(?<![.\w$])eval\s*\(|(?<![.\w$])Function\s*\()" if command_pattern else r"(?:(?<![.\w$])eval\s*\(|(?<![.\w$])Function\s*\()"
            sink_re = re.compile(sink_prefix + r"([^;\n]*)")
            for match in sink_re.finditer(body):
                if not executable[match.start():match.start()+1].strip(): continue
                opening = body.find('(', match.start())
                args = script_arguments(body, opening)
                if not args: continue
                expression = ','.join(args)
                used = next((p for p in tainted if re.search(rf"\b{re.escape(p)}\b", expression)), None)
                if not used:
                    continue
                sink = re.search(r"([A-Za-z]+)\s*\(", match.group(0)).group(1)
                if safe_git_argv(command_kinds.get(sink, sink), args, body, match.start()): continue
                rule = "MCP05-DYNAMIC-CODE" if sink in {"eval", "Function"} else "MCP05-COMMAND-INJECTION"
                line = tool.implementation_line + body.count("\n", 0, match.start())
                finding = self._finding(rule, info.filepath, line,
                    "Tool-controlled data can reach a command or code execution sink.",
                    "Use a fixed executable and validated argument array; do not construct code or shell commands.",
                    "HIGH", "typescript", sink, tool.name)
                finding.metadata["evidence"] = Evidence(rule, used, sink, [used, sink], [],
                    ["fixed executable", "argument allowlist"]).__dict__
                findings.append(finding)
            filesystems = re.findall(r"import\s+(?:\*\s+as\s+)?(\w+)\s+from\s*['\"](?:node:)?fs(?:/promises)?['\"]", info.source_code)
            for offset, name in file_text_returns(body, filesystems):
                findings.append(self._finding('MCP06-UNTRUSTED-CONTEXT', info.filepath,
                    (tool.implementation_line or tool.line_number)+body.count('\n',0,offset),
                    'Whole file content reaches tool-visible output through a local alias.',
                    'Return selected fields or introduce an explicit untrusted-content boundary.',
                    'MEDIUM', 'typescript', name, tool.name))
            audited = bool(re.search(r"(?i)(audit|logger\.|console\.(?:info|warn|error)|telemetry|trace)", body))
            # Destination-specific network flow. A fixed origin with only a
            # tainted path/query is not SSRF.
            for match in re.finditer(r"\b(fetch|axios\.(?:get|post|request)|https?\.(?:get|request))\s*\(([^,;\n]+)", body):
                expression = match.group(2)
                used = next((p for p in tainted if re.search(rf"\b{re.escape(p)}\b", expression)), None)
                fixed_origin = bool(re.search(r"['\"`]https?://[A-Za-z0-9._:-]+/", expression))
                protected = bool(re.search(r"(?i)(allowlist|validateUrl|safeUrl|isPrivate|isLoopback|new\s+URL)", body))
                if used and not fixed_origin and not protected:
                    line = tool.implementation_line + body.count("\n", 0, match.start())
                    finding = self._finding("MCP13-SSRF", info.filepath, line,
                        "Tool-controlled data can determine an outbound request destination.",
                        "Require HTTPS, allowlist destinations, resolve DNS safely, and block private/link-local addresses.",
                        "HIGH", "typescript", match.group(1), tool.name)
                    finding.metadata["evidence"] = Evidence(finding.rule_id, used, match.group(1),
                        [used, match.group(1)], [], ["origin allowlist", "private-address rejection"]).to_dict()
                    findings.append(finding)
                # Raw external response returned to the caller/model context.
                response_names = re.findall(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?" + re.escape(match.group(1)), body)
                if response_names and any(re.search(rf"\breturn\b[^;\n]*\b{re.escape(name)}\b", body) for name in response_names):
                    line = tool.implementation_line + body.count("\n", 0, match.start())
                    findings.append(self._finding("MCP06-UNTRUSTED-CONTEXT", info.filepath, line,
                        "External response content is returned toward model context without a visible trust boundary.",
                        "Return structured allowlisted fields and mark or sanitize external content as untrusted.",
                        "MEDIUM", "typescript", match.group(1), tool.name))
            if re.search(r"(?is)return[\s\S]{0,240}(?:process\.env|Deno\.env|Bun\.env)", body):
                findings.append(self._finding("MCP01-SECRET-OUTPUT", info.filepath,
                    tool.implementation_line or tool.line_number,
                    "Environment data appears in tool-visible output.",
                    "Return only explicitly selected non-secret fields and redact credentials.",
                    "HIGH", "typescript", "[REDACTED]", tool.name))
            sensitive = bool(sink_re.search(body) or re.search(r"\b(?:readFile|writeFile|unlink)(?:Sync)?\s*\(", body))
            if sensitive and not audited:
                findings.append(self._finding("MCP08-MISSING-AUDIT", info.filepath, tool.implementation_line or tool.line_number,
                    "A sensitive TypeScript/JavaScript tool has no visible audit telemetry.",
                    "Record actor, tool, approved parameters, outcome, and correlation ID without secrets.",
                    "LOW", "typescript", function_name=tool.name))
        source = info.source_code
        network_server = re.search(r"(?i)(\.listen\s*\(|transport\s*:\s*['\"](?:sse|streamable)|StreamableHTTP|SSEServerTransport)", source)
        if network_server and not self._has_auth_enforcement(source):
            findings.append(self._finding("MCP07-MISSING-AUTH", info.filepath,
                self._line(source, network_server.start()),
                "A network-capable MCP server has no visible authentication enforcement.",
                "Authenticate the transport and authorize every tool/resource operation.", "MEDIUM", "typescript"))
        broad_bind = re.search(r"(?i)(?:listen\s*\([^)]*['\"]0\.0\.0\.0['\"]|host\s*:\s*['\"]0\.0\.0\.0['\"])", source)
        if broad_bind and not self._has_auth_enforcement(source):
            findings.append(self._finding("MCP07-PERMISSIVE-BIND", info.filepath,
                self._line(source, broad_bind.start()),
                "The MCP service binds to all interfaces without visible authorization.",
                "Require authentication or bind to localhost/a protected network interface.", "HIGH", "typescript"))
        return self._dedupe(findings)

    def _analyze_network_destinations(self, tool: ToolDefinition) -> List[Finding]:
        """Find tool-controlled values used specifically as HTTP destinations.

        This deliberately ignores tool data placed only in a request body or
        query for a fixed endpoint, removing the broad whole-call AST heuristic.
        """
        root = tool.raw_node
        if root is None:
            return []
        tainted = {
            name for name in tool.parameters
            if name.lower() not in {"self", "cls", "ctx", "context"}
        }
        predecessors = {name: [] for name in tool.parameters}
        low_level_arguments = tool.registration_style == "low_level"
        fixed_origins = set()
        constants = getattr(self, "_module_constants", {})

        def is_tainted(node: ast.AST) -> bool:
            if isinstance(node, ast.Name):
                return node.id in tainted or (low_level_arguments and node.id in {"arguments", "params"})
            if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
                if low_level_arguments and node.value.id in {"arguments", "params"}:
                    return True
            return any(is_tainted(child) for child in ast.iter_child_nodes(node))

        def has_fixed_origin(node: ast.AST) -> bool:
            """Whether an expression preserves a statically known HTTP origin."""
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return bool(re.match(r"https?://[^/?#]+", node.value))
            if isinstance(node, ast.Name):
                value = constants.get(node.id)
                return node.id in fixed_origins or (
                    isinstance(value, str) and bool(re.match(r"https?://[^/?#]+", value))
                )
            if isinstance(node, ast.JoinedStr):
                prefix = ""
                trusted_base = False
                path_separator_after_base = False
                for value in node.values:
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        prefix += value.value
                        if trusted_base and value.value.startswith("/"):
                            path_separator_after_base = True
                    elif isinstance(value, ast.FormattedValue):
                        if is_tainted(value.value):
                            break
                        resolved = constants.get(value.value.id) if isinstance(value.value, ast.Name) else None
                        if isinstance(resolved, str):
                            prefix += resolved
                        else:
                            trusted_base = True
                return bool(re.match(r"https?://[^/?#]+", prefix)) or path_separator_after_base
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                return has_fixed_origin(node.left)
            if isinstance(node, ast.Call) and node.args:
                # Common helpers append query/path information to an existing URL.
                return has_fixed_origin(node.args[0])
            return False

        # Bounded intra-procedural propagation is sufficient for common aliases,
        # string transformations, and URL construction inside one tool branch.
        for _ in range(4):
            changed = False
            for node in ast.walk(root):
                assigned_value = getattr(node, "value", None)
                call_value = assigned_value.value if isinstance(assigned_value, ast.Await) else assigned_value
                fixed_network_result = (
                    isinstance(call_value, ast.Call)
                    and call_value.args
                    and self._call_name(call_value.func).lower() in getattr(self, "_network_helpers", set())
                    and has_fixed_origin(call_value.args[0])
                )
                if (isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value
                        and is_tainted(node.value) and not fixed_network_result):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        if isinstance(target, ast.Name) and target.id not in tainted:
                            tainted.add(target.id)
                            predecessors[target.id] = [
                                part.id for part in ast.walk(node.value)
                                if isinstance(part, ast.Name)
                                and (part.id in tainted or (low_level_arguments and part.id in {"arguments", "params"}))
                            ]
                            changed = True
                if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value and has_fixed_origin(node.value):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    fixed_origins.update(target.id for target in targets if isinstance(target, ast.Name))
            if not changed:
                break

        findings = []
        for node in ast.walk(root):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            name = self._call_name(node.func).lower()
            http_method = bool(re.search(r"(?:^|\.)(?:get|post|put|patch|delete|request)$", name))
            direct_http = name.startswith(("requests.", "httpx.", "aiohttp.")) and http_method
            client_http = http_method
            helper_http = name in getattr(self, "_network_helpers", set())
            if not (direct_http or client_http or helper_http) or not is_tainted(node.args[0]):
                continue
            if has_fixed_origin(node.args[0]):
                continue
            destination_names = [
                part.id for part in ast.walk(node.args[0])
                if isinstance(part, ast.Name) and part.id in tainted
            ]
            path = []
            current = destination_names[0] if destination_names else "tool input"
            visited = set()
            while current not in visited:
                visited.add(current)
                path.insert(0, current)
                parents = predecessors.get(current, [])
                if not parents:
                    break
                current = parents[0]
            path.append(f"{name}(destination)")
            line = getattr(node, "lineno", tool.implementation_line or tool.line_number)
            evidence = Evidence(
                rule_id="MCP13-SSRF",
                source="tool-controlled parameter",
                sink=f"{name} destination",
                path=path,
                missing_protections=["scheme/host allowlist", "private-address rejection", "redirect validation"],
            )
            finding = self._finding("MCP13-SSRF", tool.source_file, line,
                "A tool-controlled value is used as the HTTP request destination.",
                "Allowlist schemes and hosts, block private/reserved addresses, and validate every redirect.",
                "HIGH", "python", name, tool.name)
            finding.metadata["evidence"] = evidence.to_dict()
            findings.append(finding)
        return findings

    @staticmethod
    def _collect_module_constants(tree: ast.AST) -> dict[str, object]:
        constants = {}
        for item in getattr(tree, "body", []):
            if not isinstance(item, (ast.Assign, ast.AnnAssign)) or not isinstance(item.value, ast.Constant):
                continue
            targets = item.targets if isinstance(item, ast.Assign) else [item.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    constants[target.id] = item.value.value
        return constants

    def _summarize_network_helpers(self, tree: ast.AST) -> set[str]:
        """Find local helpers whose parameter becomes an HTTP destination."""
        helpers = set()
        for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
            parameters = {arg.arg for arg in function.args.args}
            for call in (node for node in ast.walk(function) if isinstance(node, ast.Call) and node.args):
                name = self._call_name(call.func).lower()
                if not re.search(r"(?:^|\.)(?:get|post|put|patch|delete|request)$", name):
                    continue
                destination_names = {part.id for part in ast.walk(call.args[0]) if isinstance(part, ast.Name)}
                if parameters & destination_names:
                    helpers.add(function.name.lower())
        return helpers

    def _text_checks(self, path: str, text: str, kind: str) -> List[Finding]:
        findings: List[Finding] = []
        for pattern in self.SECRET_PATTERNS if kind != "python" else []:
            for match in pattern.finditer(text):
                findings.append(self._finding("MCP01-SECRET-HARDCODED", path, self._line(text, match.start()),
                    "A credential-like value is hard-coded in a scanned artifact.",
                    "Move the secret to a secret manager, rotate it, and remove it from history.", "HIGH", kind, "[REDACTED]"))
        for match in self.BROAD_SCOPE.finditer(text):
            findings.append(self._finding("MCP02-BROAD-SCOPE", path, self._line(text, match.start()),
                "A wildcard or administrative scope expands the impact of token compromise.",
                "Request minimal scopes and elevate incrementally for privileged operations.", "MEDIUM", kind, match.group(0)))
        if re.search(r"(?i)(resource_metadata|authorization_servers|token_endpoint).{0,160}(requests|httpx|urlopen)", text, re.DOTALL) and not re.search(r"(?i)(allowlist|private[_ ]?ip|ipaddress|validate_url|https)", text):
            findings.append(self._finding("MCP13-METADATA-SSRF", path, 1,
                "OAuth discovery metadata appears to drive network requests without destination validation.",
                "Require HTTPS and reject private, loopback, link-local, and redirect destinations.", "MEDIUM", kind))
        if re.search(r"(?i)(host|bind)\s*[:=]\s*['\"]0\.0\.0\.0['\"]", text) and not re.search(r"(?i)(auth|bearer|oauth|token|middleware)", text):
            findings.append(self._finding("MCP07-PERMISSIVE-BIND", path, 1,
                "An MCP-related service binds to all interfaces without visible authorization.",
                "Require authentication or bind to a restricted local/IPC transport.", "HIGH", kind))
        return findings

    def _finding(self, rule_id: str, path: str, line: int, description: str, recommendation: str,
                 confidence: str, source_kind: str = "python", matched: Optional[str] = None,
                 function_name: Optional[str] = None) -> Finding:
        attack_id, title = RULES[rule_id]
        category = ATTACK_CATEGORIES[attack_id]
        severity = Severity.HIGH if confidence == "HIGH" else Severity.MEDIUM if confidence == "MEDIUM" else Severity.LOW
        return Finding(vulnerability_type=category.name.lower().replace(" ", "_"), severity=severity,
            title=f"{attack_id}: {title}", description=description, file_path=path, line_number=max(1, line),
            function_name=function_name, matched_pattern=rule_id, matched_text=matched,
            recommendation=recommendation, attack_id=attack_id, rule_id=rule_id, confidence=confidence,
            fixable=False, source_kind=source_kind,
            references=[OWASP_REFERENCE if category.source == "OWASP" else MCP_SECURITY_REFERENCE])

    @staticmethod
    def _call_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name): return node.id
        if isinstance(node, ast.Attribute):
            base = ProjectRiskAnalyzer._call_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return ""

    @staticmethod
    def _line(text: str, position: int) -> int: return text[:position].count("\n") + 1

    @staticmethod
    def _has_auth_enforcement(text: str) -> bool:
        return bool(re.search(
            r"(?is)(add_middleware\s*\([^)]*auth|middleware\s*=\s*[^\n]*auth|"
            r"\.use\s*\([^)]*(?:auth|permission)|"
            r"Depends\s*\([^)]*(?:auth|token|permission)|(?:require_auth|verify_token|authorize)\s*\(|"
            r"if\s+not\s+[^\n]*(?:auth|token|permission)|@\w*(?:auth|permission))",
            text,
        ))

    @staticmethod
    def _source_kind(path: str) -> str:
        suffix = Path(path).suffix.lower()
        return "dependency" if Path(path).name.lower() in {"requirements.txt", "pyproject.toml", "pipfile", "poetry.lock", "uv.lock", "package.json", "package-lock.json"} else "config" if suffix in {".json", ".yaml", ".yml", ".toml"} else "text"

    @staticmethod
    def _looks_unpinned_dependency(line: str, filename: str) -> bool:
        if not line or line.startswith(("#", "[", "{", "}")): return False
        if "requirements" in filename:
            return bool(re.match(r"^[A-Za-z0-9_.-]+(?:\[[^]]+\])?(?:\s*$|\s*[><~=])", line)) and "==" not in line
        if filename == "package.json":
            return bool(re.search(r'"[^"/]+"\s*:\s*"(?:latest|\*|\^|~|github:|https?:)', line))
        if filename in {"pyproject.toml", "pipfile"}:
            # Project/interpreter compatibility metadata is not an installable
            # dependency and cannot be pinned like a package requirement.
            if re.match(r"(?i)^requires-python\s*=", line):
                return False
            return bool(re.search(r"(?i)^[A-Za-z0-9_.-]+\s*=\s*['\"](?:\*|latest|\^|~|>=|>)", line))
        return False

    @staticmethod
    def _dedupe(findings: Iterable[Finding]) -> List[Finding]:
        result, seen = [], set()
        for finding in findings:
            key = (finding.rule_id, finding.file_path, finding.line_number, finding.function_name)
            if key not in seen:
                seen.add(key); result.append(finding)
        return result
