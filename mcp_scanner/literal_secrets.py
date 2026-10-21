"""Credential-literal evidence from Python syntax; never return secret values."""
import ast
import re
from .secret_flow import SECRET_SHAPE

NAME = re.compile(r"(?:^|_)(?:password|passwd|secret|token|api_key|access_key|private_key|client_secret)$", re.I)
FIELD = re.compile(r"(?im)\b(?:password|api[ _]key|access[ _]token|client[ _]secret)\s*:\s*([^\s]{8,})")


def credential_name(value):
    return bool(NAME.search(value.replace(" ", "_")))


def credential_literal(value):
    if not isinstance(value, str) or len(value) < 8: return False
    lower = value.lower().strip()
    if lower in {"changeme", "[redacted]", "redacted", "password", "placeholder"}: return False
    if re.match(r"(?:your|insert|replace)[ _-]|<.*>$|\*+$", lower): return False
    if lower.startswith(("/", "./", "../", "http://", "https://", "${")): return False
    return True


def hardcoded_lines(tree):
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                docstrings.add(id(first.value))
    lines = set()
    def named(key, value):
        if credential_name(key) and isinstance(value, ast.Constant) and credential_literal(value.value):
            lines.add(value.lineno)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, (ast.Name, ast.Attribute)):
                    named(target.id if isinstance(target, ast.Name) else target.attr, node.value)
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and isinstance(key.value, str): named(key.value, value)
        elif isinstance(node, ast.keyword) and node.arg:
            named(node.arg, node.value)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
            if SECRET_SHAPE.search(node.value): lines.add(node.lineno)
            for match in FIELD.finditer(node.value):
                if credential_literal(match.group(1)):
                    lines.add(node.lineno + node.value[:match.start()].count("\n"))
    return sorted(lines)
