"""Small, shared source-to-sink data-flow primitives used by analyzers."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from .command_safety import CommandSafety
from .python_bindings import PythonBindings
from .static_values import StaticValues
from .command_safety import WORD


@dataclass(frozen=True)
class Flow:
    source: str
    sink: str
    line: int
    path: tuple[str, ...]
    protections: tuple[str, ...] = ()


COMMAND_SINKS = {
    "os.system", "os.popen", "subprocess.run", "subprocess.popen",
    "subprocess.call", "subprocess.check_call", "subprocess.check_output",
}
VALIDATOR_HINTS = ("allowlist", "whitelist", "validate", "sanitize", "quote", "literal_eval")


def call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


class PythonDataFlow:
    """Conservative bounded intra-procedural taint propagation.

    It follows parameters through aliases, formatting, containers and helper
    calls. Recognized validation/sanitization calls stop a path and are kept as
    protection evidence instead of being silently ignored.
    """

    def summarize_command_helpers(self, tree: ast.AST) -> dict[str, tuple[int | tuple[int, ...], str]]:
        """Return helpers whose parameter reaches a command sink.

        The value is ``(parameter index, sink)``. A small fixed-point also
        follows wrappers around already summarized helpers.
        """
        functions = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        summaries: dict[str, tuple[int | tuple[int, ...], str]] = {}
        for _ in range(4):
            changed = False
            for function in functions:
                bindings = PythonBindings(tree, function)
                params = [arg.arg for arg in function.args.args]
                aliases = {p: {p} for p in params}
                for _ in range(4):
                    for statement in ast.walk(function):
                        if isinstance(statement, (ast.Assign, ast.AnnAssign)) and statement.value:
                            source = set().union(*(aliases.get(n.id, set()) for n in ast.walk(statement.value) if isinstance(n, ast.Name)))
                            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                            for target in targets:
                                if isinstance(target, ast.Name): aliases.setdefault(target.id, set()).update(source)
                for call in (n for n in ast.walk(function) if isinstance(n, ast.Call)):
                    name = bindings.resolve(call.func, allow_unbound=True).lower()
                    sink = name if name in COMMAND_SINKS else None
                    nested = summaries.get(call_name(call.func).split(".")[-1])
                    for index, param in enumerate(params):
                        indices = ((nested[0],) if isinstance(nested[0], int) else nested[0]) if nested else ()
                        expressions = ([call.args[i] for i in indices if i < len(call.args)] if nested and indices and all(i < len(call.args) for i in indices)
                                       else list(call.args) + [kw.value for kw in call.keywords])
                        if (sink or nested) and any(any(isinstance(x, ast.Name) and param in aliases.get(x.id, set()) for x in ast.walk(expr))
                                                    for expr in expressions):
                            prior = summaries.get(function.name)
                            previous_indices = ((prior[0],) if isinstance(prior[0], int) else prior[0]) if prior else ()
                            indices = tuple(sorted(set(previous_indices) | {index}))
                            value = (indices[0] if len(indices) == 1 else indices, sink or nested[1])
                            if summaries.get(function.name) != value:
                                summaries[function.name] = value
                                changed = True
            if not changed:
                break
        return summaries

    def command_flows(self, node: ast.AST, parameters: list[str],
                      helpers: dict[str, tuple[int, str]] | None = None,
                      context: ast.AST | None = None,
                      registration: ast.AST | None = None) -> list[Flow]:
        function = node if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else next(
            (n for n in getattr(node, "body", []) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))), None)
        safety = CommandSafety(context, function, registration)
        bindings = PythonBindings(context, function)
        taint: dict[str, tuple[str, ...]] = {
            p: (p,) for p in parameters if p.lower() not in {"self", "cls", "ctx", "context"}
        }
        protected: dict[str, tuple[str, ...]] = {}
        helpers = helpers or {}
        literals = StaticValues(context)
        # Recognize fail-closed allowlist/validator guards before propagation.
        command_lines = [getattr(n, "lineno", 0) for n in ast.walk(node)
                         if isinstance(n, ast.Call) and (bindings.resolve(n.func, allow_unbound=True).lower() in COMMAND_SINKS
                             or call_name(n.func).split(".")[-1] in helpers)]
        first_command = min(command_lines, default=10**9)
        guards = list(function.body) if function else []
        # A literal-return guard inside a try cannot be bypassed by a handler
        # when schema-validated strings are checked against a static string set.
        for statement in list(guards):
            if (isinstance(statement, ast.Try) and len(statement.body) == 1 and not statement.finalbody
                    and isinstance(statement.body[0], ast.If) and safety.fastmcp_schema()):
                inner = statement.body[0]
                if len(inner.body) == 1 and isinstance(inner.body[0], ast.Return) and isinstance(inner.body[0].value, ast.Constant):
                    if isinstance(inner.test, ast.Compare) and isinstance(inner.test.left, ast.Name):
                        param = next((a for a in function.args.args if a.arg == inner.test.left.id), None)
                        if param and isinstance(param.annotation, ast.Name) and param.annotation.id == "str": guards.append(inner)
        for guard in (n for n in guards if isinstance(n, ast.If) and getattr(n, "end_lineno", first_command) < first_command):
            exits = len(guard.body) == 1 and isinstance(guard.body[0], (ast.Raise, ast.Return))
            if not exits:
                continue
            if isinstance(guard.test, ast.Compare) and isinstance(guard.test.left, ast.Name):
                if len(guard.test.ops) == 1 and isinstance(guard.test.ops[0], ast.NotIn):
                    name = guard.test.left.id
                    try:
                        allowed = literals.resolve(guard.test.comparators[0], literals.local_values(function, guard.lineno))
                        trusted = isinstance(allowed, (tuple, dict)) and bool(allowed) and all(
                            type(v) is int or isinstance(v, str) and WORD.fullmatch(v) for v in allowed)
                    except (ValueError, TypeError):
                        trusted = False
                    if name in taint and trusted and safety.unchanged(name, first_command):
                        protected[name] = ("fail-closed allowlist guard",)
                        taint.pop(name, None)
            if isinstance(guard.test, ast.UnaryOp) and isinstance(guard.test.op, ast.Not) and isinstance(guard.test.operand, ast.Call):
                validator = call_name(guard.test.operand.func)
                if any(h in validator.lower() for h in VALIDATOR_HINTS):
                    for arg in guard.test.operand.args:
                        if isinstance(arg, ast.Name) and arg.id in taint:
                            protected[arg.id] = (validator,)
                            taint.pop(arg.id, None)

        def sources(expr: ast.AST) -> tuple[str, ...]:
            if isinstance(expr, ast.Call) and any(h in call_name(expr.func).lower() for h in VALIDATOR_HINTS):
                return ()
            found: list[str] = []
            for child in ast.walk(expr):
                if isinstance(child, ast.Name) and child.id in taint:
                    found.extend(taint[child.id])
            return tuple(dict.fromkeys(found))

        def assigned_names(target: ast.AST) -> list[str]:
            if isinstance(target, ast.Name):
                return [target.id]
            return [n.id for n in ast.walk(target) if isinstance(n, ast.Name)]

        statements = sorted(ast.walk(node), key=lambda n: (getattr(n, "lineno", 0), getattr(n, "col_offset", 0)))
        for statement in statements:
            if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                value = statement.value
                # An annotation such as ``argument: str`` does not assign a
                # value. Preserve any existing taint and inspect later sinks.
                if value is None:
                    continue
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                src = sources(value)
                if not src:
                    continue
                validator = next((call_name(c.func) for c in ast.walk(value)
                                  if isinstance(c, ast.Call) and any(h in call_name(c.func).lower() for h in VALIDATOR_HINTS)), None)
                for target in targets:
                    for name in assigned_names(target):
                        if validator:
                            protected[name] = (validator,)
                            taint.pop(name, None)
                        else:
                            taint[name] = src + (name,)

        flows: list[Flow] = []
        helpers = helpers or {}
        for call in (n for n in ast.walk(node) if isinstance(n, ast.Call)):
            sink = bindings.resolve(call.func, allow_unbound=True).lower()
            helper_name = call_name(call.func).split(".")[-1]
            helper = helpers.get(helper_name)
            if sink not in COMMAND_SINKS and not helper:
                continue
            indices = ((helper[0],) if isinstance(helper[0], int) else helper[0]) if helper else ()
            expressions = ([call.args[i] for i in indices] if helper and all(i < len(call.args) for i in indices)
                           else list(call.args) + [kw.value for kw in call.keywords if kw.arg != "shell"])
            if helper:
                # Schema-validated integer arguments cannot introduce shell
                # syntax. Keep every other contributing argument in the flow.
                numeric = {a.arg for a in function.args.args if isinstance(a.annotation, ast.Name) and a.annotation.id == 'int'} if function else set()
                expressions = [e for e in expressions if not (isinstance(e, ast.Name) and e.id in numeric and safety.safe_parameter(e.id, call.lineno))]
            src = tuple(dict.fromkeys(s for expr in expressions for s in sources(expr)))
            shell_true = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                             for kw in call.keywords)
            if src:
                if safety.protects(call, helper):
                    continue
                actual_sink = helper[1] if helper else sink
                path = src + ((f"{helper_name}()", actual_sink) if helper else (sink,))
                flows.append(Flow(src[0], actual_sink, getattr(call, "lineno", 1), path))
            elif shell_true and any(sources(expr) for expr in expressions):
                flows.append(Flow("tool input", sink, getattr(call, "lineno", 1), ("tool input", sink)))
        return flows
