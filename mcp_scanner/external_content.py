"""Recognize visible pathlib text flowing to a tool return, including helpers."""
import ast


def carries_file_text(node):
    if node is None: return False
    if isinstance(node, (ast.Compare, ast.Constant)): return False
    if isinstance(node, ast.IfExp):
        return carries_file_text(node.body) or carries_file_text(node.orelse)
    if isinstance(node, ast.Call):
        if getattr(node, "_resolved_name", "") in {"len", "bool", "isinstance", "hasattr", "int", "float"}:
            return False
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"read_text", "read_bytes"}:
            receiver = node.func.value
            if isinstance(receiver, ast.Call) and getattr(receiver, "_resolved_name", "") in {
                    "pathlib.Path", "pathlib.PosixPath", "pathlib.WindowsPath"}:
                return True
    return any(carries_file_text(child) for child in ast.iter_child_nodes(node))


def carries_http_text(node):
    """Recognize response text and explicitly textual JSON projections.

    Status, counts and other structured projections are not inferred to carry
    instructions. The response tag is set only by resolved HTTP call analysis.
    """
    def response(value):
        return bool(getattr(value, '_external_response', False))

    def json_payload(value):
        return (isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)
                and value.func.attr == 'json' and response(value.func.value))

    if node is None or isinstance(node, (ast.Compare, ast.Constant)): return False
    if isinstance(node, ast.Attribute):
        return node.attr in {'text', 'content', 'data'} and response(node.value)
    if isinstance(node, ast.Subscript):
        return (isinstance(node.slice, ast.Constant)
                and node.slice.value in {'text', 'content', 'body', 'extract', 'description', 'html', 'markdown'}
                and json_payload(node.value))
    if isinstance(node, ast.Call):
        resolved = getattr(node, '_resolved_name', '')
        if resolved in {'len','bool','int','float','isinstance','hasattr',
                        'mcp_scanner.defenses.sanitize_content','mcp_scanner.defenses.sanitizers.sanitize_content',
                        'mcp_scanner.defenses.sanitize_data','mcp_scanner.defenses.sanitizers.sanitize_data'}:
            return False
        if isinstance(node.func, ast.Attribute):
            if response(node.func.value): return node.func.attr in {'text','read'}
            if json_payload(node.func.value) and node.func.attr == 'get':
                return bool(node.args and isinstance(node.args[0],ast.Constant)
                            and node.args[0].value in {'text','content','body','extract','description','html','markdown'})
    if isinstance(node, ast.IfExp):
        return carries_http_text(node.body) or carries_http_text(node.orelse)
    return any(carries_http_text(child) for child in ast.iter_child_nodes(node))
