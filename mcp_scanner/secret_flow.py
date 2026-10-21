"""Bounded AST evidence for credentials reaching returns or logging calls.

Only provenance flags are retained. Secret values never enter findings.
"""
import ast
import re
from .python_bindings import PythonBindings, dotted, scope_nodes

SECRET_NAME = re.compile(r"^(?:token|secret|password|passwd|credentials?|authorization|cookie|(?:api|access|auth|refresh|client|private|session|secret)[_-]?(?:key|token|secret|password))$", re.I)
SECRET_SHAPE = re.compile(r"(?:gh[pousr]_[A-Za-z0-9_]{30,}|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{20,})")
SECRET = frozenset({"secret"})
BROAD = frozenset({"broad"})


def credential_environment_key(value):
    return bool(SECRET_NAME.fullmatch(value) or re.search(r"_(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY)$", value, re.I))


class SecretFlow:
    def __init__(self, module):
        self.module = module
        self.functions = {}
        for node in module.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[node.name] = node if node.name not in self.functions else None
        self.module_bindings = PythonBindings(module)
        self.global_values = {}
        self.loggers = set()
        for statement in module.body:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)) and statement.value is not None:
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        value = self.value(statement.value, self.global_values, self.module_bindings, ())
                        self.global_values[target.id] = self.assigned(target.id, statement.value, value)
                        if target.id in {"context", "memory", "history", "session"} and isinstance(statement.value, (ast.Dict, ast.List, ast.Call)):
                            self.global_values[target.id] |= BROAD
                        if isinstance(statement.value, ast.Call) and self.module_bindings.resolve(statement.value.func) == "logging.getLogger":
                            self.loggers.add(target.id)
                        else:
                            self.loggers.discard(target.id)

    @staticmethod
    def assigned(name, expression, flags):
        # A named literal credential is evidence; boolean presence indicators,
        # explicit masks, and empty defaults are not credential values.
        if (SECRET_NAME.fullmatch(name) and isinstance(expression, ast.Constant)
                and isinstance(expression.value, str) and expression.value
                and expression.value not in {"[REDACTED]", "***", "****", "your-api-key-here"}):
            return flags | SECRET
        return flags

    def value(self, node, state, bindings, stack):
        if node is None: return frozenset()
        if isinstance(node, ast.Name):
            if node.id in state: return state[node.id]
            if SECRET_NAME.fullmatch(node.id): return SECRET
            if node.id in {"context", "memory", "history", "session"}: return BROAD
            return frozenset()
        if isinstance(node, ast.Constant):
            return SECRET if isinstance(node.value, str) and SECRET_SHAPE.search(node.value) else frozenset()
        if isinstance(node, ast.Compare) or isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return frozenset()
        if isinstance(node, ast.IfExp):
            return self.value(node.body, state, bindings, stack) | self.value(node.orelse, state, bindings, stack)
        if isinstance(node, ast.Attribute):
            if bindings.resolve(node) == "os.environ": return SECRET | BROAD
            if node.attr in {"status_code", "returncode"}: return frozenset()
            return self.value(node.value, state, bindings, stack)
        if isinstance(node, ast.Dict):
            result = frozenset()
            for key, item in zip(node.keys, node.values):
                flags = self.value(item, state, bindings, stack)
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    flags = self.assigned(key.value, item, flags)
                result |= flags
            return result
        if isinstance(node, ast.Call):
            qualified = bindings.resolve(node.func, allow_unbound=True)
            if qualified in {"bool", "len", "isinstance", "hasattr"}: return frozenset()
            if isinstance(node.func, ast.Attribute) and node.func.attr == "keys" and not node.args and not node.keywords:
                return frozenset()
            if qualified in {"globals", "locals"}: return BROAD
            if qualified in {"os.getenv", "os.environ.get"}:
                key = node.args[0] if node.args else None
                return SECRET if isinstance(key, ast.Constant) and isinstance(key.value, str) and credential_environment_key(key.value) else frozenset()
            if isinstance(node.func, ast.Name) and len(stack) < 4 and node.func.id not in stack:
                helper = self.functions.get(node.func.id)
                if helper is not None and node.func.id not in bindings.local_bindings:
                    args = [self.value(a, state, bindings, stack) for a in node.args]
                    kwargs = {k.arg: self.value(k.value, state, bindings, stack) for k in node.keywords if k.arg}
                    params = helper.args.posonlyargs + helper.args.args
                    supplied = {p.arg: flag for p, flag in zip(params, args)}
                    supplied.update(kwargs)
                    returns, _ = self.analyze(helper, supplied, stack + (node.func.id,))
                    return frozenset().union(*(flags for _, flags in returns))
            if isinstance(node.func, ast.Attribute) and node.func.attr == "get" and node.args:
                key = node.args[0]
                if isinstance(key, ast.Constant) and isinstance(key.value, str) and SECRET_NAME.fullmatch(key.value):
                    return SECRET
            # Unknown transformations retain provenance; do not trust a helper
            # merely because its name contains "sanitize" or "redact".
            values = list(node.args) + [k.value for k in node.keywords]
            if isinstance(node.func, ast.Attribute): values.append(node.func.value)
            return frozenset().union(*(self.value(a, state, bindings, stack) for a in values))
        if isinstance(node, ast.Subscript) and bindings.resolve(node.value) == "os.environ":
            key = node.slice
            return SECRET if isinstance(key, ast.Constant) and isinstance(key.value, str) and credential_environment_key(key.value) else frozenset()
        return frozenset().union(*(self.value(child, state, bindings, stack) for child in ast.iter_child_nodes(node)))

    def analyze(self, function, supplied=None, stack=()):
        bindings = PythonBindings(self.module, function)
        state = dict(self.global_values)
        # Local bindings shadow globals. Ordinary local names such as a token
        # in a tokenizer loop do not establish credential provenance.
        for local in bindings.local_bindings:
            state[local] = frozenset()
        params = function.args.posonlyargs + function.args.args + function.args.kwonlyargs
        for param in params:
            state[param.arg] = SECRET if SECRET_NAME.fullmatch(param.arg) else frozenset()
        if supplied: state.update(supplied)
        returns, logs = [], []
        loggers = self.loggers - set(bindings.local_bindings)
        conditional = {id(child) for branch in ast.walk(function)
                       if isinstance(branch, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.Match))
                       for child in ast.walk(branch)}
        for statement in scope_nodes(function.body):
            if isinstance(statement, (ast.For, ast.AsyncFor)):
                flags = self.value(statement.iter, state, bindings, stack)
                for target in ast.walk(statement.target):
                    if isinstance(target, ast.Name): state[target.id] = flags
            elif isinstance(statement, (ast.Assign, ast.AnnAssign)) and statement.value is not None:
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                flags = self.value(statement.value, state, bindings, stack)
                for target in targets:
                    if isinstance(target, ast.Name):
                        # Union over possible branches favors retaining evidence.
                        value = self.assigned(target.id, statement.value, flags)
                        state[target.id] = state.get(target.id, frozenset()) | value if id(statement) in conditional else value
                        if isinstance(statement.value, ast.Call) and bindings.resolve(statement.value.func) == "logging.getLogger":
                            loggers.add(target.id)
                        else:
                            loggers.discard(target.id)
            elif isinstance(statement, ast.Return):
                returns.append((statement, self.value(statement.value, state, bindings, stack)))
            elif isinstance(statement, ast.Call):
                qualified = bindings.resolve(statement.func)
                parts = dotted(statement.func).split(".")
                if ((qualified.startswith("logging.") and qualified.split(".")[-1] in {"debug", "info", "warning", "error", "exception", "critical", "log"})
                        or len(parts) == 2 and parts[0] in loggers and parts[1] in {"debug", "info", "warning", "error", "exception", "critical", "log"}):
                    flags = frozenset().union(*(self.value(a, state, bindings, stack) for a in statement.args + [k.value for k in statement.keywords]))
                    if "secret" in flags: logs.append(statement)
        return returns, logs
