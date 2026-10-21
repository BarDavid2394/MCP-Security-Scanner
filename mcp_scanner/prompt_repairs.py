"""Conservative local provenance for MCP06 return repairs; never executes code.

Detection remains the analyzers' responsibility. This planner only authorizes
wrapping return expressions with known external text/JSON/SQLite provenance.
Unknown helpers, custom objects and complex control flow remain report-only.
"""
import ast

from .python_bindings import PythonBindings


SANITIZERS = {
    f'{module}.{name}' for module in ('mcp_scanner.defenses', 'mcp_scanner.defenses.sanitizers')
    for name in ('sanitize_content', 'sanitize_data')
}
HTTP_CALLS = {f'{module}.{method}' for module in ('requests', 'httpx')
              for method in ('get', 'post', 'put', 'patch', 'delete', 'request', 'head', 'options')}
HTTP_CLIENTS = {'requests.Session', 'requests.sessions.Session', 'httpx.Client', 'httpx.AsyncClient',
                'aiohttp.ClientSession'}
CONTENT = {'text', 'bytes', 'data'}


def return_repairs(module, function):
    """Return (Return node, sanitizer name) pairs supported by local evidence."""
    bindings = PythonBindings(module, function)
    repairs = []

    def kind(node, env):
        if node is None:
            return ''
        if isinstance(node, ast.Name):
            return env.get(node.id, '')
        if isinstance(node, ast.Await):
            return kind(node.value, env)
        if isinstance(node, ast.Attribute):
            receiver = kind(node.value, env)
            if receiver == 'http' and node.attr == 'text':
                return 'text'
            if receiver == 'http' and node.attr == 'content':
                return 'bytes'
            if receiver == 'process' and node.attr in {'stdout', 'stderr'}:
                return 'data'  # subprocess may return either text or bytes.
            return ''
        if isinstance(node, ast.JoinedStr):
            return 'text' if any(kind(part.value, env) in CONTENT for part in node.values
                                 if isinstance(part, ast.FormattedValue)) else ''
        if isinstance(node, ast.Call):
            name = bindings.resolve(node.func)
            if name in SANITIZERS:
                return ''
            if name in HTTP_CALLS:
                return 'http'
            if name in HTTP_CLIENTS:
                return 'http_client'
            if name == 'subprocess.run':
                return 'process'
            if name == 'sqlite3.connect':
                if len(node.args) <= 1 and not any(k.arg in {None, 'factory', 'detect_types'} for k in node.keywords):
                    return 'connection'
                return ''
            if name == 'urllib.request.urlopen':
                return 'file'
            if bindings.resolve(node.func, allow_unbound=True) == 'open':
                # Binary/text mode affects the value type; sanitize_data handles both.
                return 'file'
            if isinstance(node.func, ast.Attribute):
                receiver, method = kind(node.func.value, env), node.func.attr
                if receiver == 'http_client' and method in {'get', 'post', 'put', 'patch', 'delete', 'request'}:
                    return 'http'
                if receiver == 'http' and method == 'json':
                    return 'data' if not node.args and not node.keywords else ''
                if receiver == 'connection' and method == 'cursor':
                    return 'cursor' if not node.args and not node.keywords else ''
                if receiver == 'cursor' and method in {'fetchall', 'fetchone', 'fetchmany'}:
                    return 'data'
                if receiver == 'file' and method == 'read':
                    return 'data'
            # These known text transforms do not establish an instruction/data boundary.
            if name == 'html.escape' and node.args and kind(node.args[0], env) == 'text':
                return 'text'
            if name in {'re.sub', 're.subn'} and len(node.args) >= 3 and kind(node.args[2], env) == 'text':
                return 'text' if name == 're.sub' else 'data'
        return ''

    def body(statements, env):
        for statement in statements:
            if isinstance(statement, (ast.Import, ast.ImportFrom, ast.Pass)):
                continue
            if isinstance(statement, ast.Expr):
                if isinstance(statement.value, ast.Constant):
                    continue  # Docstring.
                call = statement.value
                if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                        and kind(call.func.value, env) == 'cursor'
                        and call.func.attr in {'execute', 'executemany'}):
                    continue
                # Unknown side effects may mutate a response/cursor or its aliases.
                return False
            elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                if not all(isinstance(target, ast.Name) for target in targets):
                    return False
                value_kind = kind(statement.value, env)
                if not value_kind and isinstance(statement.value, ast.Call):
                    # An unknown transformation may mutate or replace an aliased
                    # external object. Do not treat its old provenance as proof.
                    call = statement.value
                    builtin = bindings.resolve(call.func, allow_unbound=True)
                    if builtin not in {'len', 'bool', 'int', 'float', 'str'} and any(
                            isinstance(n, ast.Name) and env.get(n.id)
                            for argument in [*call.args, *(k.value for k in call.keywords)]
                            for n in ast.walk(argument)):
                        return False
                for target in targets:
                    env[target.id] = value_kind
            elif isinstance(statement, ast.Return):
                value_kind = kind(statement.value, env)
                if value_kind in CONTENT:
                    repairs.append((statement, 'sanitize_content' if value_kind == 'text' else 'sanitize_data'))
                return True
            elif isinstance(statement, ast.If):
                # Only terminal branches; joining mutable aliases is not a repair proof.
                if not (statement.body and statement.orelse
                        and isinstance(statement.body[-1], ast.Return)
                        and isinstance(statement.orelse[-1], ast.Return)):
                    return False
                return body(statement.body, dict(env)) and body(statement.orelse, dict(env))
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    if not isinstance(item.optional_vars, ast.Name):
                        return False
                    env[item.optional_vars.id] = kind(item.context_expr, env)
                if not body(statement.body, env):
                    return False
            else:
                return False
        return True

    return repairs if body(function.body, {}) else []


def mark_fixable_returns(server_info, findings):
    """Share the actual repair planner with scanner eligibility reporting."""
    try:
        module = ast.parse(server_info.source_code)
    except SyntaxError:
        return
    for tool in server_info.tools:
        node = tool.raw_node
        if tool.registration_style != 'decorator' or not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        plan = return_repairs(module, node)
        for finding in findings:
            if finding.attack_id != 'MCP06' or finding.function_name != tool.name:
                continue
            finding.fixable = bool(plan)
            if plan:
                finding.confidence = 'HIGH'
                finding.metadata['auto_fix'] = {
                    'strategy': 'wrap_proven_external_return',
                    'function_line': node.lineno,
                    'return_lines': [ret.lineno for ret, _ in plan],
                }
