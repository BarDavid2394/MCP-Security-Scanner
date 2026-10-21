"""Bounded import resolution without importing or executing inspected code."""
import ast


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        root = dotted(node.value)
        return root + "." + node.attr if root else ""
    return ""


def scope_nodes(body):
    """Visit one lexical scope; nested definitions bind names but own their bodies."""
    for node in body:
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield from scope_nodes(ast.iter_child_nodes(node))


class PythonBindings:
    def __init__(self, module, function=None):
        self.global_bindings = self._collect(getattr(module, "body", []))
        self.local_bindings = self._collect(function.body) if function else {}
        self.aliases = {}
        bodies = [(getattr(module, "body", []), False)] + ([(function.body, True)] if function else [])
        for body, local in bodies:
            if local:
                for key in self.local_bindings: self.aliases.pop(key, None)
            nodes = list(scope_nodes(body))
            counts = {}
            for node in nodes:
                if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                    counts[node.id] = counts.get(node.id, 0) + 1
            for node in nodes:
                if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    key = node.targets[0].id
                    if counts.get(key) == 1 and isinstance(node.value, ast.Call):
                        if dotted(node.value.func) == "getattr" and len(node.value.args) == 2 and not node.value.keywords:
                            self.aliases[key] = (node.value, node.lineno if local else 0)
        if function:
            args = function.args
            for arg in args.posonlyargs + args.args + args.kwonlyargs + [a for a in (args.vararg, args.kwarg) if a]:
                self.local_bindings[arg.arg] = None
                self.aliases.pop(arg.arg, None)

    @staticmethod
    def _collect(body):
        values = {}
        def bind(key, value=None):
            values[key] = value if key not in values else None
        for node in scope_nodes(body):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    bind(alias.asname or alias.name.split(".")[0], alias.name if alias.asname else alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    bind(alias.asname or alias.name, (node.module or "") + "." + alias.name if not node.level else None)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                bind(node.id)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                bind(node.name)
            elif isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
                value = node
                while isinstance(value, (ast.Attribute, ast.Subscript)):
                    value = value.value
                if isinstance(value, ast.Name): bind(value.id)
        return values

    def resolve(self, node, allow_unbound=False, _seen=()):
        if isinstance(node, ast.Call) and dotted(node.func) == "getattr":
            if self.local_bindings.get("getattr", self.global_bindings.get("getattr", "getattr")) != "getattr": return ""
            if len(node.args) == 2 and not node.keywords and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                base = self.resolve(node.args[0], _seen=_seen)
                return base + "." + node.args[1].value if base else ""
            return ""
        value = dotted(node)
        if not value: return ""
        root, *tail = value.split(".")
        if not tail and root in self.aliases:
            expression, line = self.aliases[root]
            if root in _seen: return ""
            if line < getattr(node, "lineno", 0): return self.resolve(expression, _seen=_seen+(root,))
        table = self.local_bindings if root in self.local_bindings else self.global_bindings
        if root in table:
            binding = table[root]
            return ".".join([binding] + tail) if binding else ""
        return value if allow_unbound else ""
