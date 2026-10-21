"""Narrow, contextual proofs for common command-injection negative controls.

These checks concern command injection only. They do not prove that an operation
is authorized, that a path is allowed, or that command output is safe for a model.
Unknown bindings, shell syntax, and execution-capable programs remain findings.
"""
import ast
import re
from .python_bindings import PythonBindings


READ_ONLY_PROGRAMS = {"cat", "df", "du", "head", "ls", "pwd", "stat", "tail", "wc"}
WORD = re.compile(r"^[A-Za-z0-9_./-]+$")
SAFE_REGEXES = {r"^[\w./-]+$", r"[\w./-]+", r"^[A-Za-z0-9_./-]+$", r"[A-Za-z0-9_./-]+"}


def name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return name(node.value) + "." + node.attr
    return ""


class CommandSafety:
    def __init__(self, module, function, registration=None):
        self.module = module
        self.function = function
        self.registration = registration or function
        self.bindings = {}
        self.imports = {}
        self.invalid = set()
        if module is None or function is None:
            return
        # Only unique, top-level bindings are accepted. Rebinding or monkey
        # patching anywhere in the module invalidates the corresponding proof.
        counts = {}
        for node in ast.walk(module):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                counts[node.id] = counts.get(node.id, 0) + 1
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
                self.invalid.add(name(node).split(".")[0])
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.invalid.add(node.name)
        for stmt in module.body:
            if isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    local = alias.asname or alias.name.split(".")[0]
                    self._import(local, alias.name, counts)
            elif isinstance(stmt, ast.ImportFrom):
                for alias in stmt.names:
                    if stmt.level == 0:
                        self._import(alias.asname or alias.name, (stmt.module or "") + "." + alias.name, counts)
            elif isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                for target in targets:
                    if isinstance(target, ast.Name) and counts.get(target.id) == 1:
                        self.bindings[target.id] = stmt.value
        args = function.args
        self.locals = {a.arg for a in args.posonlyargs + args.args + args.kwonlyargs}
        if args.vararg: self.locals.add(args.vararg.arg)
        if args.kwarg: self.locals.add(args.kwarg.arg)
        self.locals.update(n.id for n in ast.walk(function) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store))
        self.locals.update(n.name for n in ast.walk(function) if n is not function and isinstance(n, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)))
        for stmt in ast.walk(function):
            if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                self.locals.update(a.asname or a.name.split(".")[0] for a in stmt.names)

    def _import(self, local, qualified, counts):
        if local in self.imports or counts.get(local):
            self.invalid.add(local)
        self.imports[local] = qualified

    def qualified(self, expr):
        parts = name(expr).split(".")
        if parts[0] in self.invalid or parts[0] in self.locals:
            return ""
        return ".".join([self.imports.get(parts[0], "?")] + parts[1:])

    def fastmcp_schema(self):
        # Accept only direct @instance.tool registrations of an imported SDK
        # FastMCP constructor. Other decorators can alter arguments, so abstain.
        decorators = self.registration.decorator_list
        if len(decorators) != 1:
            return False
        decorator = decorators[0]
        if isinstance(decorator, ast.Call): decorator = decorator.func
        if not isinstance(decorator, ast.Attribute) or decorator.attr != "tool" or not isinstance(decorator.value, ast.Name):
            return False
        binding = decorator.value.id
        if binding in self.invalid or binding in self.locals:
            return False
        constructor = self.bindings.get(binding)
        return isinstance(constructor, ast.Call) and self.qualified(constructor.func) in {"mcp.server.fastmcp.FastMCP", "fastmcp.FastMCP", "mcp.FastMCP"}

    def unchanged(self, variable, line):
        # Refuse to infer aliases/reassignments or mutation through a preceding
        # branch. This deliberately favors reporting an unknown flow.
        return not any(isinstance(n, ast.Name) and n.id == variable and isinstance(n.ctx, ast.Store)
                       and getattr(n, "lineno", 0) <= line for n in ast.walk(self.function))

    def safe_parameter(self, variable, line):
        if not self.unchanged(variable, line): return False
        if self.fastmcp_schema():
            args = self.function.args
            parameter = next((a for a in args.posonlyargs + args.args + args.kwonlyargs if a.arg == variable), None)
            annotation = parameter.annotation if parameter else None
            # An imported/shadowed 'int' must not receive builtin validation credit.
            if isinstance(annotation, ast.Name) and annotation.id == "int" and "int" not in self.invalid and "int" not in self.locals and "int" not in self.bindings and "int" not in self.imports:
                return True
            if isinstance(annotation, ast.Subscript) and self.qualified(annotation.value) == "typing.Literal":
                values = annotation.slice.elts if isinstance(annotation.slice, ast.Tuple) else [annotation.slice]
                if values and all(isinstance(v, ast.Constant) and
                                  (type(v.value) is int or isinstance(v.value, str) and WORD.fullmatch(v.value)) for v in values):
                    return True
        for guard in self.function.body:
            if getattr(guard, "end_lineno", 10**9) >= line: continue
            if not isinstance(guard, ast.If) or len(guard.body) != 1 or not isinstance(guard.body[0], (ast.Raise, ast.Return)):
                continue
            test = guard.test
            if not isinstance(test, ast.UnaryOp) or not isinstance(test.op, ast.Not) or not isinstance(test.operand, ast.Call): continue
            match = test.operand
            if len(match.args) != 1 or match.keywords or not isinstance(match.args[0], ast.Name) or match.args[0].id != variable: continue
            if not isinstance(match.func, ast.Attribute) or match.func.attr != "fullmatch" or not isinstance(match.func.value, ast.Name): continue
            regex_name = match.func.value.id
            if regex_name in self.locals or regex_name in self.invalid: continue
            regex = self.bindings.get(regex_name)
            if not isinstance(regex, ast.Call) or self.qualified(regex.func) != "re.compile" or len(regex.args) != 1 or regex.keywords: continue
            pattern = regex.args[0]
            if isinstance(pattern, ast.Constant) and pattern.value in SAFE_REGEXES:
                return True
        return False

    def shell_word(self, expr, line):
        if isinstance(expr, ast.Name): return self.safe_parameter(expr.id, line)
        if isinstance(expr, ast.Constant):
            return type(expr.value) is int or isinstance(expr.value, str) and bool(WORD.fullmatch(expr.value))
        return (isinstance(expr, ast.Call) and self.qualified(expr.func) == "shlex.quote"
                and len(expr.args) == 1 and not expr.keywords)

    def shell_command(self, expr, line):
        if not isinstance(expr, ast.JoinedStr) or not expr.values: return False
        parts = expr.values
        first = parts[0]
        # No interpolation as executable; no quotes, substitutions, backslashes,
        # redirections or other shell syntax around escaped whole-word arguments.
        if not isinstance(first, ast.Constant) or not isinstance(first.value, str): return False
        if not re.fullmatch(r"[A-Za-z0-9_./-]+(?:[ \t]+[A-Za-z0-9_./=-]+)*[ \t]+", first.value): return False
        words = first.value.split()
        executable = words[0]
        program = executable.rsplit("/", 1)[-1]
        if executable not in {program, "/bin/"+program, "/usr/bin/"+program}:
            return False
        known_command = program in READ_ONLY_PROGRAMS
        if program == "git" and len(words) >= 2 and words[1] in {"log", "show"}:
            known_command = all(w in {"--oneline", "-n"} or w.isdecimal() for w in words[2:])
        if words == ["systemctl", "restart"]:
            known_command = True
        if not known_command:
            return False
        for i, part in enumerate(parts):
            if isinstance(part, ast.Constant):
                if not isinstance(part.value, str) or not re.fullmatch(r"[A-Za-z0-9_./= \t-]*", part.value): return False
                continue
            if not isinstance(part, ast.FormattedValue) or part.conversion != -1 or part.format_spec is not None: return False
            if i == 0 or not isinstance(parts[i-1], ast.Constant) or not parts[i-1].value.endswith((" ", "\t")): return False
            if i+1 < len(parts) and (not isinstance(parts[i+1], ast.Constant) or not parts[i+1].value.startswith((" ", "\t"))): return False
            if not self.shell_word(part.value, line): return False
        return True

    def protects(self, call, helper=None):
        if self.function is None or self.module is None: return False
        # Additional positional options can replace the executable or change
        # shell semantics. Only the single-command calling form is established.
        if len(call.args) != 1: return False
        allowed_options = {"shell", "capture_output", "text", "check", "timeout", "encoding", "errors"}
        if any(k.arg not in allowed_options or not isinstance(k.value, ast.Constant) for k in call.keywords): return False
        if helper and call.keywords: return False
        shell = next((kw.value for kw in call.keywords if kw.arg == "shell"), None)
        sink = PythonBindings(self.module, self.function).resolve(call.func, allow_unbound=True).lower()
        index = helper[0] if helper else 0
        if not isinstance(index, int): return False
        if index >= len(call.args): return False
        argument = call.args[index]
        if helper:
            # Local wrapper only, with a visible shell sink. Cross-file helper
            # summaries alone do not establish escaping semantics.
            helper_name = name(call.func)
            definitions = [n for n in self.module.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == helper_name]
            if len(definitions) != 1: return False
            definition = definitions[0]
            statements = definition.body
            if statements and isinstance(statements[0], ast.Expr) and isinstance(statements[0].value, ast.Constant) and isinstance(statements[0].value.value, str):
                statements = statements[1:]
            # A local wrapper that executes one fixed argv then returns a
            # constant cannot reinterpret its argument through another sink.
            calls_in_body = [n for s in statements for n in ast.walk(s) if isinstance(n, ast.Call)]
            if (len(statements) == 2 and isinstance(statements[0], ast.Expr)
                    and isinstance(statements[1], ast.Return) and isinstance(statements[1].value, ast.Constant)
                    and len(calls_in_body) == 1 and statements[0].value is calls_in_body[0]):
                inner = calls_in_body[0]
                if CommandSafety(self.module, definition).protects(inner): return True
            if len(statements) != 1 or not isinstance(statements[0], (ast.Return, ast.Expr)): return False
            calls = [n for n in ast.walk(definition) if isinstance(n, ast.Call)]
            if len(calls) == 1 and CommandSafety(self.module, definition).protects(calls[0]):
                # A single visible safe subprocess call may return stdout.
                # No additional invocation exists to reinterpret caller data.
                return True
            sinks = [n for n in calls if name(n.func).lower() == helper[1]]
            params = definition.args.args
            if len(sinks) != 1 or len(calls) != 1 or index >= len(params): return False
            if len(sinks[0].args) != 1: return False
            forwarded = sinks[0].args[0] if sinks[0].args else None
            if not isinstance(forwarded, ast.Name) or forwarded.id != params[index].arg: return False
            if any(k.arg not in allowed_options or not isinstance(k.value, ast.Constant) for k in sinks[0].keywords): return False
            # Require an imported sink and no wrapper-side rebinding. This proof
            # is intentionally unavailable to transforming or ambiguous helpers.
            if self.qualified(sinks[0].func).lower() != helper[1]: return False
            if any(a.arg == name(sinks[0].func).split(".")[0] for a in params): return False
            shell_mode = bool(sinks) and all(name(n.func).lower() in {"os.system", "os.popen"} or
                             any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in n.keywords) for n in sinks)
        else:
            if self.qualified(call.func).lower() != sink: return False
            shell_mode = sink in {"os.system", "os.popen"} or isinstance(shell, ast.Constant) and shell.value is True
        if shell_mode:
            return self.shell_command(argument, call.lineno)
        if helper or sink not in {"subprocess.run", "subprocess.popen", "subprocess.call", "subprocess.check_call", "subprocess.check_output"}: return False
        if shell is not None and not (isinstance(shell, ast.Constant) and shell.value is False): return False
        if any(k.arg not in {"shell", "capture_output", "text", "check", "timeout", "encoding", "errors"} or
               not isinstance(k.value, ast.Constant) for k in call.keywords): return False
        return self.fixed_argv(argument, call.lineno)

    def fixed_argv(self, argument, line):
        if not isinstance(argument, (ast.List, ast.Tuple)) or not argument.elts: return False
        executable = argument.elts[0]
        if not isinstance(executable, ast.Constant) or not isinstance(executable.value, str): return False
        if executable.value in {prefix+p for prefix in ("", "/bin/", "/usr/bin/") for p in READ_ONLY_PROGRAMS}: return True
        if executable.value in {"printf", "/bin/printf", "/usr/bin/printf"} and len(argument.elts) >= 3:
            fmt = argument.elts[1]
            return (isinstance(fmt, ast.Constant) and isinstance(fmt.value, str)
                    and bool(re.fullmatch(r"(?:[^%]|%%|%s)*", fmt.value)))
        if executable.value == "git" and len(argument.elts) == 3:
            command, url = argument.elts[1:]
            if isinstance(command, ast.Constant) and command.value == "clone" and isinstance(url, ast.JoinedStr):
                first = url.values[0]
                return (isinstance(first, ast.Constant) and isinstance(first.value, str)
                        and bool(re.fullmatch(r"https://[A-Za-z0-9.-]+/[^\s]*", first.value)))
        if executable.value == "nslookup" and len(argument.elts) == 2 and isinstance(argument.elts[1], ast.Name):
            variable = argument.elts[1].id
            if not self.unchanged(variable, line): return False
            for guard in self.function.body:
                if not isinstance(guard, ast.If) or guard.end_lineno >= line or len(guard.body) != 1 or not isinstance(guard.body[0], (ast.Return, ast.Raise)): continue
                test = guard.test.operand if isinstance(guard.test, ast.UnaryOp) and isinstance(guard.test.op, ast.Not) else None
                if not isinstance(test, ast.Call) or test.args or test.keywords or not isinstance(test.func, ast.Attribute) or test.func.attr != "isalnum": continue
                replace = test.func.value
                if not isinstance(replace, ast.Call) or not isinstance(replace.func, ast.Attribute) or replace.func.attr != "replace": continue
                if (isinstance(replace.func.value, ast.Name) and replace.func.value.id == variable and not replace.keywords
                        and len(replace.args) == 2 and all(isinstance(a, ast.Constant) for a in replace.args)
                        and [a.value for a in replace.args] == [".", ""]): return True
        return False
