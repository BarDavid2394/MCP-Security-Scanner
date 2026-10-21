"""Project-level graph and bounded read-only security context."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from .dataflow import PythonDataFlow
from .parsers.python_parser import ToolDefinition
from .reachable_python import ReachablePython, prefix


AUTH_RE = re.compile(r"(?i)(authorization|oauth|bearer|authmiddleware|verify_token|require_auth|permission)")
AUTH_ENFORCEMENT_RE = re.compile(
    r"(?is)(add_middleware\s*\([^)]*auth|middleware\s*=\s*[^\n]*auth|"
    r"Depends\s*\([^)]*(?:auth|token|permission)|(?:require_auth|verify_token|authorize)\s*\(|"
    r"if\s+not\s+[^\n]*(?:auth|token|permission)|@\w*(?:auth|permission))"
)
NETWORK_RE = re.compile(r"(?i)(streamable[_-]?http|transport\s*=\s*['\"](?:http|sse)|fastapi|starlette|uvicorn|\.http_app\s*\()")


@dataclass
class SecurityGraph:
    root: Path
    imports: dict[Path, set[str]] = field(default_factory=dict)
    definitions: dict[str, list[tuple[Path, int, str]]] = field(default_factory=dict)
    calls: dict[str, list[tuple[Path, int]]] = field(default_factory=dict)
    auth_files: set[Path] = field(default_factory=set)
    auth_enforced_files: set[Path] = field(default_factory=set)
    network_files: set[Path] = field(default_factory=set)
    command_helpers: dict[str, list[tuple[Path, int | tuple[int, ...], str]]] = field(default_factory=dict)
    sources: dict[Path, str] = field(default_factory=dict)

    @classmethod
    def build(cls, root: Path, files: list[Path]) -> "SecurityGraph":
        graph = cls(root.resolve())
        for path in files:
            suffix = path.suffix.lower()
            if suffix not in {".py", ".ts", ".tsx", ".js", ".jsx"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            resolved = path.resolve()
            graph.sources[resolved] = text
            if AUTH_RE.search(text):
                graph.auth_files.add(resolved)
            if AUTH_ENFORCEMENT_RE.search(text):
                graph.auth_enforced_files.add(resolved)
            if NETWORK_RE.search(text):
                graph.network_files.add(resolved)
            if suffix == ".py":
                graph._add_python(resolved, text)
            else:
                graph._add_script(resolved, text)
        return graph

    def _add_python(self, path: Path, text: str) -> None:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return
        for name, (index, sink) in PythonDataFlow().summarize_command_helpers(tree).items():
            self.command_helpers.setdefault(name, []).append((path, index, sink))
        modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                snippet = "\n".join(text.splitlines()[node.lineno - 1:min(getattr(node, "end_lineno", node.lineno), node.lineno + 40)])
                self.definitions.setdefault(node.name, []).append((path, node.lineno, snippet))
            elif isinstance(node, ast.Import):
                modules.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module)
            elif isinstance(node, ast.Call):
                name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
                if name:
                    self.calls.setdefault(name, []).append((path, node.lineno))
        self.imports[path] = modules

    def _add_script(self, path: Path, text: str) -> None:
        self.imports[path] = set(re.findall(r"(?:from\s+|require\(['\"])([\w./@-]+)", text))
        for match in re.finditer(r"(?m)(?:function\s+|(?:const|let|var)\s+)([A-Za-z_$][\w$]*)", text):
            line = text.count("\n", 0, match.start()) + 1
            self.definitions.setdefault(match.group(1), []).append((path, line, text[match.start():match.start() + 1500]))

    def protected_network_files(self) -> set[Path]:
        """Network entrypoints plausibly linked to authentication enforcement."""
        protected = self.auth_enforced_files & self.network_files
        if not self.auth_files:
            return protected
        auth_stems = {p.stem for p in self.auth_files}
        for path in self.network_files:
            source = self.sources.get(path, "")
            if AUTH_ENFORCEMENT_RE.search(source) and any(
                any(stem in module for stem in auth_stems) for module in self.imports.get(path, set())
            ):
                protected.add(path)
        return protected

    def project_has_auth(self) -> bool:
        return bool(self.protected_network_files())

    def preserves_url_origin(self, qualified_name: str) -> bool:
        """Prove a uniquely linked local transform preserves its first URL arg.

        Only suppress when every visible return retains the exact sentinel
        origin. Unknown calls/branches remain unproven. No source execution.
        """
        module, _, name = qualified_name.rpartition('.')
        suffix = module.replace('.', '/') + '.py'
        matches = [p for p in self.sources if p.as_posix().endswith('/'+suffix)]
        if len(matches) != 1: return False
        try:
            tree = ast.parse(self.sources[matches[0]])
        except SyntaxError:
            return False
        functions = [n for n in tree.body if isinstance(n, (ast.FunctionDef,ast.AsyncFunctionDef)) and n.name == name]
        if len(functions) != 1: return False
        function = functions[0]
        if any(isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store,ast.Del)) and n.id == name for n in ast.walk(tree)): return False
        unsupported = (ast.Match,ast.NamedExpr,ast.Global,ast.Nonlocal,ast.Delete,ast.Yield,ast.YieldFrom)
        if any(isinstance(n, unsupported) for n in ast.walk(function)): return False
        args = function.args.posonlyargs + function.args.args
        if not args or function.decorator_list: return False
        marker = 'https://scanner-origin.invalid/path?query=fixed'
        analysis = ReachablePython(tree)
        analysis.analyze(function, [a.arg for a in args], {args[0].arg:ast.Constant(marker)})
        if any(c.name in {'eval','exec','globals','locals','setattr','__import__'} for c in analysis.calls): return False
        def retained(value):
            if isinstance(value, ast.Tuple): return bool(value.elts) and all(retained(v) for v in value.elts)
            text, _ = prefix(value)
            return text.startswith(marker)
        return bool(analysis.returns) and analysis.remaining > 0 and all(retained(value) for value in analysis.returns)

    def cross_file_command_flows(self, tools: list[ToolDefinition]):
        """Find tool calls into command wrappers defined in another module."""
        helpers = {name: (items[0][1], items[0][2]) for name, items in self.command_helpers.items()
                   if len(items) == 1}
        for tool in tools:
            if tool.raw_node is None:
                continue
            try:
                context = ast.parse(self.sources.get(Path(tool.source_file).resolve(), ""))
            except SyntaxError:
                context = None
            parameters = tool.parameters + ([a.arg for a in tool.raw_node.args.args]
                if tool.registration_style == "low_level" and isinstance(tool.raw_node, (ast.FunctionDef, ast.AsyncFunctionDef)) else [])
            for flow in PythonDataFlow().command_flows(tool.raw_node, parameters, helpers, context):
                helper = next((part[:-2] for part in flow.path if part.endswith("()")), None)
                definitions = self.command_helpers.get(helper or "", [])
                if definitions and all(path.resolve() != Path(tool.source_file).resolve() for path, _, _ in definitions):
                    yield tool, flow, definitions[0][0]

    def context_for(self, path: Path, function: str | None, max_chars: int = 6000) -> str:
        """Return bounded definitions/callers/auth context without model tools."""
        chunks: list[str] = []
        if function:
            for def_path, line, snippet in self.definitions.get(function, [])[:2]:
                chunks.append(f"DEFINITION {def_path.name}:{line}\n{snippet}")
            callers = self.calls.get(function, [])[:8]
            if callers:
                chunks.append("CALLERS " + ", ".join(f"{p.name}:{line}" for p, line in callers))
        for auth_path in sorted(self.auth_files)[:3]:
            try:
                lines = auth_path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeError):
                continue
            selected = [f"{i + 1}: {line}" for i, line in enumerate(lines) if AUTH_RE.search(line)][:20]
            if selected:
                chunks.append(f"AUTH/MIDDLEWARE {auth_path.name}\n" + "\n".join(selected))
        return "\n\n".join(chunks)[:max_chars]
