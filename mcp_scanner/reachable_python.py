"""Bounded symbolic traversal of visible Python helpers; never executes source.

Values are AST expressions carrying caller provenance, not concrete objects.
Unknown calls remain unknown. Branches are joined; this is evidence of possible
flows, not a proof of runtime reachability or authorization.
"""
import ast
import copy
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit
from .python_bindings import PythonBindings, dotted

HTTP_METHODS = {'get', 'post', 'put', 'patch', 'delete', 'request', 'head', 'options'}
HTTP_CLIENTS = {'requests.Session', 'requests.sessions.Session', 'httpx.Client', 'httpx.AsyncClient', 'aiohttp.ClientSession'}
CODE_SINKS = {'eval', 'exec', 'compile', '__import__', 'importlib.import_module',
              'pickle.loads', 'pickle.load', 'yaml.unsafe_load'}


@dataclass
class Call:
    name: str
    args: list
    keywords: dict
    line: int
    path: tuple
    http: bool = False

    @property
    def destination(self):
        index = 1 if self.name.endswith('.request') else 0
        return self.keywords.get('url', self.args[index] if len(self.args) > index else None)


def joined(values):
    values = [v for v in values if v is not None]
    unique = {}
    for value in values: unique.setdefault(ast.dump(value, include_attributes=False), value)
    values = list(unique.values())
    if not values: return ast.Constant(None)
    if len(values) == 1: return values[0]
    return ast.Tuple(elts=values, ctx=ast.Load())


def depends(value, parameters):
    return value is not None and any(isinstance(n, ast.Name) and n.id in parameters for n in ast.walk(value))


def prefix(value):
    if isinstance(value, ast.Constant) and isinstance(value.value, str): return value.value, True
    parts = value.values if isinstance(value, ast.JoinedStr) else ([value.left, value.right] if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add) else [])
    if isinstance(value, ast.FormattedValue): return prefix(value.value)
    text = ''
    for part in parts:
        piece, complete = prefix(part)
        text += piece
        if not complete: return text, False
    return text, bool(parts)


def fixed_public_origin(value):
    text, complete = prefix(value)
    # A variable immediately after a host prefix could change its authority.
    if not re.match(r'^https?://[^/?#]+(?:[/?#]|$)', text): return False
    if not complete and not re.match(r'^https?://[^/?#]+[/?#]', text): return False
    return not privileged_origin(value)


def privileged_origin(value):
    text, _ = prefix(value)
    try:
        host = urlsplit(text).hostname or ''
        if host.lower() in {'localhost', 'metadata.google.internal'} or host.lower().endswith('.localhost'): return True
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False


class ReachablePython:
    def __init__(self, module):
        self.module = module
        self.functions, self.classes, self.globals = {}, {}, {}
        self.calls, self.returns = [], []
        self.bindings = {}
        self.remaining = 5000
        for node in module.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[node.name] = node if node.name not in self.functions else None
            elif isinstance(node, ast.ClassDef):
                self.classes[node.name] = node if node.name not in self.classes else None
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name): self.globals[target.id] = node.value if target.id not in self.globals else None

    def analyze(self, function, parameters, parameter_values=None):
        self.calls, self.returns, self.remaining = [], [], 5000
        self.parameters = set(parameters) - {'self', 'cls', 'ctx', 'context'}
        env = {a.arg: ast.Name(id=a.arg, ctx=ast.Load()) for a in function.args.posonlyargs+function.args.args+function.args.kwonlyargs}
        env.update(parameter_values or {})
        self.returns = self._body(function.body, env, function, (function.name,))
        return self.calls

    def _qualified(self, node, function):
        key = id(function)
        if key not in self.bindings: self.bindings[key] = PythonBindings(self.module, function)
        return self.bindings[key].resolve(node, allow_unbound=True)

    def _helper(self, func, env):
        if isinstance(func, ast.Name) and func.id not in env and func.id not in self.globals:
            function = self.functions.get(func.id)
            if function and function.decorator_list: return None, None, ''
            return function, None, func.id
        if isinstance(func, ast.Attribute):
            receiver = func.value
            if isinstance(receiver, ast.Name): receiver = env.get(receiver.id, receiver)
            instance = isinstance(receiver, ast.Call)
            clsname = getattr(receiver, '_local_class', '') if instance else dotted(receiver)
            if isinstance(func.value, ast.Name) and func.value.id in env and isinstance(receiver, ast.Name):
                return None, None, ''
            cls = self.classes.get(clsname)
            if cls is not None and clsname not in self.globals:
                methods = [n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == func.attr]
                if len(methods) == 1:
                    method = methods[0]
                    decorators = {dotted(d) for d in method.decorator_list}
                    if decorators - {'staticmethod', 'classmethod'}: return None, None, ''
                    bound = receiver if instance and 'staticmethod' not in decorators or 'classmethod' in decorators else None
                    return method, bound, clsname+'.'+func.attr
        return None, None, ''

    def _expr(self, node, env, function, path, depth=0):
        if node is None or depth > 14 or self.remaining <= 0: return ast.Constant(None)
        self.remaining -= 1
        if isinstance(node, ast.Name):
            if node.id in env: return copy.deepcopy(env[node.id])
            if node.id in self.globals:
                # Recursive globals are bounded by expression depth.
                return self._expr(self.globals[node.id], env, function, path, depth+1)
            return copy.deepcopy(node)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in self.classes:
            cls = self.classes[node.value.id]
            for statement in cls.body if cls else []:
                if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                    targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                    if any(isinstance(t, ast.Name) and t.id == node.attr for t in targets):
                        return self._expr(statement.value, env, function, path, depth+1)
        if isinstance(node, ast.Await): return self._expr(node.value, env, function, path, depth+1)
        if isinstance(node, ast.Call):
            args = [self._expr(a, env, function, path, depth+1) for a in node.args]
            kwargs = {k.arg:self._expr(k.value, env, function, path, depth+1) for k in node.keywords}
            helper, bound, label = self._helper(node.func, env)
            if helper is not None and len(path) < 6 and label not in path:
                params = helper.args.posonlyargs+helper.args.args
                actual = ([bound] if bound is not None else []) + args
                local = {p.arg:v for p,v in zip(params, actual)}
                for p,default in zip(params[-len(helper.args.defaults):],helper.args.defaults):
                    if p.arg not in local: local[p.arg] = self._expr(default,env,function,path,depth+1)
                local.update({p.arg:kwargs.get(p.arg, ast.Constant(None)) for p in params if p.arg not in local})
                local.update({p.arg:kwargs.get(p.arg, ast.Constant(None)) for p in helper.args.kwonlyargs})
                return joined(self._body(helper.body,local,helper,path+(label,)))
            name = self._qualified(node.func, function)
            transformed_func = self._expr(node.func, env, function, path, depth+1)
            # Resolve methods only on imported HTTP client constructors.
            if isinstance(transformed_func, ast.Attribute) and isinstance(transformed_func.value, ast.Call):
                constructor = getattr(transformed_func.value, '_resolved_name', '')
                if constructor in HTTP_CLIENTS and transformed_func.attr in HTTP_METHODS:
                    name = constructor+'.'+transformed_func.attr
            http = (name.rsplit('.',1)[-1] in HTTP_METHODS and name.startswith(('requests.','httpx.','aiohttp.'))) or name == 'urllib.request.urlopen'
            # A shadowed parameter is never an imported HTTP client.
            root = dotted(node.func).split('.')[0]
            if root in env and isinstance(env[root], ast.Name) and env[root].id in self.parameters: http = False
            if name == 'yaml.load':
                loader = kwargs.get('Loader')
                if dotted(loader) in {'yaml.Loader','yaml.UnsafeLoader'}: name = 'yaml.unsafe_load'
            if isinstance(transformed_func, ast.Attribute) and transformed_func.attr == 'exec_module':
                # Establish an actual importlib module-spec loader chain.
                receiver = transformed_func.value
                if isinstance(receiver, ast.Attribute) and receiver.attr == 'loader' and isinstance(receiver.value, ast.Call):
                    if getattr(receiver.value, '_resolved_name', '') == 'importlib.util.spec_from_file_location': name = 'importlib.loader.exec_module'
            self.calls.append(Call(name, args, kwargs, node.lineno, path, http))
            if http:
                response = ast.Name(id='__scanner_network_response',ctx=ast.Load())
                response._external_response = True
                return response
            result = ast.Call(func=transformed_func,args=args,keywords=[ast.keyword(arg=k,value=v) for k,v in kwargs.items()])
            result._resolved_name = name
            constructor = dotted(node.func)
            if constructor in self.classes and constructor not in env and constructor not in self.globals and constructor not in self.functions:
                result._local_class = constructor
            return result
        result = copy.copy(node)
        for field,value in ast.iter_fields(node):
            if isinstance(value,ast.AST):setattr(result,field,self._expr(value,env,function,path,depth+1))
            elif isinstance(value,list):setattr(result,field,[self._expr(v,env,function,path,depth+1) if isinstance(v,ast.AST) else v for v in value])
        return result

    def _body(self, body, env, function, path):
        returned=[]
        def assign(target,value):
            if isinstance(target,ast.Name):env[target.id]=value
            elif isinstance(target,(ast.Tuple,ast.List)):
                for part in target.elts:assign(part,value)
        for node in body:
            if self.remaining <= 0:break
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):continue
            if isinstance(node,(ast.Assign,ast.AnnAssign)):
                value=self._expr(node.value,env,function,path)
                for target in node.targets if isinstance(node,ast.Assign) else [node.target]:assign(target,value)
            elif isinstance(node,ast.AugAssign):assign(node.target,joined([self._expr(node.target,env,function,path),self._expr(node.value,env,function,path)]))
            elif isinstance(node,ast.Return):
                returned.append(self._expr(node.value,env,function,path));break
            elif isinstance(node,ast.If):
                self._expr(node.test,env,function,path)
                branches=[]
                for branch in [node.body,node.orelse]:
                    branch_env=dict(env);returned.extend(self._body(branch,branch_env,function,path));branches.append(branch_env)
                for key in set(branches[0])|set(branches[1]):env[key]=joined([b.get(key,env.get(key)) for b in branches])
            elif isinstance(node,(ast.With,ast.AsyncWith)):
                for item in node.items:
                    value=self._expr(item.context_expr,env,function,path)
                    if item.optional_vars:assign(item.optional_vars,value)
                returned.extend(self._body(node.body,env,function,path))
            elif isinstance(node,(ast.For,ast.AsyncFor)):
                value=self._expr(node.iter,env,function,path);assign(node.target,value)
                returned.extend(self._body(node.body,env,function,path));returned.extend(self._body(node.orelse,env,function,path))
            elif isinstance(node,ast.Try):
                returned.extend(self._body(node.body,env,function,path))
                for handler in node.handlers:returned.extend(self._body(handler.body,dict(env),function,path))
                returned.extend(self._body(node.orelse+node.finalbody,env,function,path))
            elif isinstance(node,ast.While):
                self._expr(node.test,env,function,path);returned.extend(self._body(node.body+node.orelse,env,function,path))
            elif isinstance(node,ast.Expr):self._expr(node.value,env,function,path)
        return returned
