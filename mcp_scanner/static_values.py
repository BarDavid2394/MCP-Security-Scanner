"""Small non-executing evaluator for literal metadata and fixed allowlists."""
import ast
from .python_bindings import scope_nodes
from .python_bindings import PythonBindings


class StaticValues:
    def __init__(self, module):
        self.values, self.functions = {}, {}
        self.bindings = PythonBindings(module)
        for node in getattr(module, "body", []):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        self.values[target.id] = node.value if target.id not in self.values else None
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[node.name] = node if node.name not in self.functions else None
        for node in ast.walk(module) if module is not None else []:
            if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
                root = node.value
                while isinstance(root, (ast.Attribute, ast.Subscript)): root = root.value
                if isinstance(root, ast.Name): self.values[root.id] = None
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"add", "update", "append", "extend", "insert", "clear", "pop", "remove", "discard", "setdefault"}:
                if isinstance(node.func.value, ast.Name): self.values[node.func.value.id] = None

    def local_values(self, function, before):
        result = {}
        if function is None: return result
        for node in scope_nodes(function.body):
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                result[node.id] = None
        for arg in function.args.posonlyargs + function.args.args + function.args.kwonlyargs:
            result[arg.arg] = None
        counts = {}
        for node in scope_nodes(function.body):
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                counts[node.id] = counts.get(node.id, 0) + 1
        for statement in function.body:
            if getattr(statement, "end_lineno", before) >= before: break
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    if isinstance(target, ast.Name) and counts.get(target.id) == 1:
                        result[target.id] = statement.value
        for node in scope_nodes(function.body):
            root = None
            if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
                root = node.value
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                # Any method may mutate a local collection; abstain rather than
                # assuming that only familiar method names are mutators.
                root = node.func.value
            while isinstance(root, (ast.Attribute, ast.Subscript)):
                root = root.value
            if isinstance(root, ast.Name) and root.id in result:
                result[root.id] = None
        return result

    def resolve(self, node, local=None, seen=(), depth=0):
        if depth > 8: raise ValueError("Static expression too deep")
        local = local or {}
        recurse = lambda item: self.resolve(item, local, seen, depth+1)
        if isinstance(node, ast.Constant): return node.value
        if isinstance(node, ast.Name) and node.id not in seen:
            value = local[node.id] if node.id in local else self.values.get(node.id)
            return self.resolve(value, local, seen+(node.id,), depth+1)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)) and len(node.elts) <= 256:
            return tuple(recurse(item) for item in node.elts)
        if isinstance(node, ast.Dict) and len(node.keys) <= 256:
            return {recurse(k): recurse(v) for k,v in zip(node.keys, node.values)}
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = recurse(node.left), recurse(node.right)
            if isinstance(left, str) and isinstance(right, str) and len(left)+len(right) <= 16384:
                return left+right
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == 'chr' and 'chr' not in local
                and self.bindings.resolve(node.func, allow_unbound=True) == 'chr'
                and len(node.args) == 1 and not node.keywords):
            value = recurse(node.args[0])
            if type(value) is int and 0 <= value <= 0x10ffff:
                return chr(value)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and not node.args and not node.keywords:
            key = node.func.id
            function = self.functions.get(key)
            if key in local or key in self.values or key in seen or function is None: raise ValueError("Unknown factory")
            body = function.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant): body = body[1:]
            if (isinstance(function, ast.FunctionDef) and not function.decorator_list
                    and not (function.args.args or function.args.posonlyargs or function.args.kwonlyargs
                             or function.args.vararg or function.args.kwarg)
                    and len(body) == 1 and isinstance(body[0], ast.Return)):
                return self.resolve(body[0].value, {}, seen+(key,), depth+1)
        raise ValueError("Not a bounded literal expression")
