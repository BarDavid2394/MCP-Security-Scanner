"""
Python AST parser for MCP server files.

Extracts tool definitions, their descriptions, and function bodies
for security analysis.
"""

import ast
import copy
import textwrap
from ..static_values import StaticValues
from ..python_bindings import PythonBindings, dotted
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any


@dataclass
class ToolDefinition:
    """Represents an MCP tool definition extracted from source code."""
    name: str
    description: str
    docstring: Optional[str]
    line_number: int
    end_line_number: int
    function_body: str
    parameters: List[str]
    decorators: List[str]
    source_file: str
    registration_style: str = "decorator"
    declaration_line: Optional[int] = None
    implementation_line: Optional[int] = None
    implementation_source: str = ""
    raw_node: Any = field(repr=False, default=None)
    description_derived: bool = False

    @property
    def full_description(self) -> str:
        """Get combined description from decorator and docstring."""
        parts = []
        if self.description:
            parts.append(self.description)
        if self.docstring:
            parts.append(self.docstring)
        return "\n".join(parts)


@dataclass
class MCPServerInfo:
    """Information about an MCP server file."""
    filepath: str
    server_name: Optional[str]
    tools: List[ToolDefinition]
    imports: List[str]
    source_code: str
    parse_errors: List[str] = field(default_factory=list)


class PythonMCPParser:
    """
    Parser for Python MCP server implementations.

    Extracts tool definitions marked with @server.tool() or similar decorators.
    """

    # Common MCP tool decorator patterns
    TOOL_DECORATORS = [
        "tool",
        "server.tool",
        "mcp.tool",
        "app.tool",
    ]

    def __init__(self):
        self.source_code = ""
        self.source_lines = []
        self._constant_values: Dict[str, Any] = {}

    def parse_file(self, filepath: str | Path) -> MCPServerInfo:
        """
        Parse an MCP server Python file.

        Args:
            filepath: Path to the Python file.

        Returns:
            MCPServerInfo containing extracted tool definitions.
        """
        filepath = Path(filepath)

        try:
            self.source_code = filepath.read_text(encoding="utf-8")
            self.source_lines = self.source_code.split("\n")
        except Exception as e:
            return MCPServerInfo(
                filepath=str(filepath),
                server_name=None,
                tools=[],
                imports=[],
                source_code="",
                parse_errors=[f"Could not read file: {e}"],
            )

        try:
            tree = ast.parse(self.source_code)
        except SyntaxError as e:
            return MCPServerInfo(
                filepath=str(filepath),
                server_name=None,
                tools=[],
                imports=[],
                source_code=self.source_code,
                parse_errors=[f"Syntax error: {e}"],
            )

        # Extract information
        server_name = self._find_server_name(tree)
        tools = self._extract_tools(tree, str(filepath))
        imports = self._extract_imports(tree)

        return MCPServerInfo(
            filepath=str(filepath),
            server_name=server_name,
            tools=tools,
            imports=imports,
            source_code=self.source_code,
        )

    def parse_source(self, source_code: str, filename: str = "<string>") -> MCPServerInfo:
        """
        Parse MCP server source code directly.

        Args:
            source_code: Python source code string.
            filename: Optional filename for error messages.

        Returns:
            MCPServerInfo containing extracted tool definitions.
        """
        self.source_code = source_code
        self.source_lines = source_code.split("\n")

        try:
            tree = ast.parse(source_code)
        except SyntaxError as e:
            return MCPServerInfo(
                filepath=filename,
                server_name=None,
                tools=[],
                imports=[],
                source_code=source_code,
                parse_errors=[f"Syntax error: {e}"],
            )

        server_name = self._find_server_name(tree)
        tools = self._extract_tools(tree, filename)
        imports = self._extract_imports(tree)

        return MCPServerInfo(
            filepath=filename,
            server_name=server_name,
            tools=tools,
            imports=imports,
            source_code=source_code,
        )

    def _find_server_name(self, tree: ast.AST) -> Optional[str]:
        """Find the MCP server name from Server() instantiation."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "server":
                        if isinstance(node.value, ast.Call):
                            if self._get_call_name(node.value) in ["Server", "FastMCP"]:
                                # Extract server name from first argument
                                if node.value.args:
                                    arg = node.value.args[0]
                                    if isinstance(arg, ast.Constant):
                                        return arg.value
        return None

    def _extract_tools(self, tree: ast.AST, filepath: str) -> List[ToolDefinition]:
        """Extract all tool definitions from the AST."""
        tools = []
        self._constant_values = self._collect_static_constants(tree)
        self._literal_evaluator = StaticValues(tree)

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                tool_info = self._check_tool_decorator(node)
                if tool_info:
                    tool = self._create_tool_definition(node, tool_info, filepath)
                    tools.append(tool)

        tools.extend(self._extract_low_level_tools(tree, filepath))
        tools.extend(self._extract_programmatic_tools(tree, filepath, tools))

        return tools

    def _extract_programmatic_tools(self, tree, filepath, existing):
        """Resolve direct add_tool calls on a visibly constructed FastMCP receiver."""
        bindings = PythonBindings(tree)
        tools = []
        seen = {id(t.raw_node) for t in existing}
        scopes = [tree] + [n for n in tree.body if isinstance(n, ast.ClassDef)]
        for scope in scopes:
            nodes = list(ast.walk(scope)) if isinstance(scope, ast.ClassDef) else list(scope.body)
            constructors, writes = {}, {}
            for node in nodes:
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        key = dotted(target)
                        writes[key] = writes.get(key, 0)+1
                        if isinstance(node.value, ast.Call) and bindings.resolve(node.value.func) in {"fastmcp.FastMCP", "mcp.server.fastmcp.FastMCP"}:
                            constructors[key] = node.lineno
            definitions = {}
            for node in scope.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    definitions[node.name] = node if node.name not in definitions else None
            calls = [n for node in nodes for n in ([node.value] if isinstance(node, ast.Expr) else [node]) if isinstance(n, ast.Call)]
            for call in calls:
                # FastMCP also exposes the decorator as mcp.tool(...)(handler).
                registration = call.func if isinstance(call.func, ast.Call) else call
                method = registration.func
                curried = registration is not call
                if not isinstance(method, ast.Attribute) or method.attr != ("tool" if curried else "add_tool") or len(call.args) != 1: continue
                receiver = dotted(method.value)
                if receiver not in constructors or writes.get(receiver) != 1 or call.lineno <= constructors[receiver]: continue
                handler = call.args[0]
                if isinstance(scope, ast.ClassDef):
                    if not isinstance(handler, ast.Attribute) or not isinstance(handler.value, ast.Name) or handler.value.id != "self": continue
                    target = definitions.get(handler.attr)
                else:
                    target = definitions.get(handler.id) if isinstance(handler, ast.Name) else None
                if target is None or id(target) in seen: continue
                info = {"description": ""}
                for keyword in registration.keywords:
                    if keyword.arg == "description":
                        try:
                            value = self._literal_evaluator.resolve(keyword.value)
                            if isinstance(value, str): info["description"] = value
                        except (ValueError, TypeError): pass
                tool = self._create_tool_definition(target, info, filepath)
                # Resolve a single explicit __doc__ assignment before registration.
                # Never execute the handler or metadata expression.
                doc_writes = [n for n in nodes if isinstance(n, ast.Assign) and any(
                    isinstance(t, ast.Attribute) and t.attr == "__doc__"
                    and isinstance(t.value, ast.Name) and t.value.id == target.name for t in n.targets)]
                if len(doc_writes) == 1 and target.lineno < doc_writes[0].lineno < call.lineno:
                    try:
                        doc = self._literal_evaluator.resolve(doc_writes[0].value)
                        if isinstance(doc, str): tool.docstring = doc
                    except (ValueError, TypeError): pass
                tool.description_derived = True
                tool.registration_style = "programmatic"
                tool.declaration_line = call.lineno
                tools.append(tool)
                seen.add(id(target))
        return tools

    def _extract_low_level_tools(self, tree: ast.AST, filepath: str) -> List[ToolDefinition]:
        """Extract Tool(...) metadata registered through list_tools handlers.

        Low-level MCP servers advertise tools separately from their call_tool
        dispatcher. Keep the declaration and linked implementation branch in one
        representation so later analyzers do not need to understand registration
        style.
        """
        list_handlers = []
        call_handlers = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            decorators = {self._get_decorator_name(dec) for dec in node.decorator_list}
            if any(name == "list_tools" or name.endswith(".list_tools") for name in decorators):
                list_handlers.append(node)
            if any(name == "call_tool" or name.endswith(".call_tool") for name in decorators):
                call_handlers.append(node)

        tools = []
        seen = set()
        # Resolve only uniquely assigned literal lists returned by a handler.
        # Do not execute factories or guess across conflicting assignments.
        lists = {}
        for statement in tree.body:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        lists[target.id] = statement.value if target.id not in lists else None
        def declarations_in(value, visited=frozenset()):
            if isinstance(value, ast.Name) and value.id not in visited:
                return declarations_in(lists.get(value.id), visited | {value.id})
            if isinstance(value, (ast.List, ast.Tuple)):
                return [item for item in value.elts if isinstance(item, ast.Call) and self._get_call_name(item) == "Tool"]
            return []
        for handler in list_handlers:
            declarations = []
            for returned in (n for n in ast.walk(handler) if isinstance(n, ast.Return)):
                declarations.extend(declarations_in(returned.value))
            receiver = next(self._get_decorator_name(d).rsplit(".", 1)[0] for d in handler.decorator_list
                            if self._get_decorator_name(d).endswith(".list_tools")) if any(
                                self._get_decorator_name(d).endswith(".list_tools") for d in handler.decorator_list) else ""
            linked_handlers = [h for h in call_handlers if any(
                self._get_decorator_name(d) == (receiver + "." if receiver else "") + "call_tool" for d in h.decorator_list)]
            for node in declarations:
                name = self._constant_call_argument(node, "name", 0)
                if not isinstance(name, str) or name in seen:
                    continue
                description = self._constant_call_argument(node, "description", 1)
                description = description if isinstance(description, str) else ""
                parameters = self._schema_properties(node)
                implementation = self._find_dispatch_branch(linked_handlers, name)
                if implementation is None and len(declarations) == 1 and len(linked_handlers) == 1:
                    implementation = linked_handlers[0]
                implementation_source = ast.unparse(implementation) if implementation else ""
                implementation_line = self._node_line(implementation) if implementation else None
                tools.append(ToolDefinition(
                    name=name,
                    description=description,
                    docstring=None,
                    line_number=node.lineno,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    # Project analyzers use the isolated raw implementation.
                    # Keep legacy text/fixer analyzers away from a synthetic body.
                    function_body="def _low_level_tool():\n    pass",
                    parameters=parameters,
                    decorators=["server.list_tools", "server.call_tool"] if implementation else ["server.list_tools"],
                    source_file=filepath,
                    registration_style="low_level",
                    declaration_line=node.lineno,
                    implementation_line=implementation_line,
                    implementation_source=implementation_source,
                    raw_node=implementation or node,
                ))
                seen.add(name)
        return tools

    def _constant_call_argument(self, call: ast.Call, keyword_name: str, position: int) -> Any:
        for keyword in call.keywords:
            if keyword.arg == keyword_name:
                return self._resolve_static_value(keyword.value)
        if len(call.args) > position:
            return self._resolve_static_value(call.args[position])
        return None

    @staticmethod
    def _collect_static_constants(tree: ast.AST) -> Dict[str, Any]:
        values: Dict[str, Any] = {}
        for node in tree.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = node.value
                if isinstance(value, ast.Constant):
                    for target in targets:
                        if isinstance(target, ast.Name):
                            values[target.id] = value.value
            if isinstance(node, ast.ClassDef):
                for child in node.body:
                    if isinstance(child, (ast.Assign, ast.AnnAssign)):
                        targets = child.targets if isinstance(child, ast.Assign) else [child.target]
                        value = child.value
                        if isinstance(value, ast.Constant):
                            for target in targets:
                                if isinstance(target, ast.Name):
                                    values[f"{node.name}.{target.id}"] = value.value
        return values

    def _resolve_static_value(self, node: ast.AST) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            key = ".".join(reversed(parts))
            if key.endswith(".value"):
                key = key[:-6]
            return self._constant_values.get(key)
        if isinstance(node, ast.Name):
            return self._constant_values.get(node.id)
        return None

    @staticmethod
    def _schema_properties(call: ast.Call) -> List[str]:
        """Extract literal inputSchema.properties keys when statically available."""
        schema = None
        for keyword in call.keywords:
            if keyword.arg in {"inputSchema", "input_schema"}:
                schema = keyword.value
                break
        if not isinstance(schema, ast.Dict):
            return []
        for key, value in zip(schema.keys, schema.values):
            if isinstance(key, ast.Constant) and key.value == "properties" and isinstance(value, ast.Dict):
                return [
                    item.value for item in value.keys
                    if isinstance(item, ast.Constant) and isinstance(item.value, str)
                ]
        return []

    def _find_dispatch_branch(self, handlers: List[ast.AST], tool_name: str) -> Optional[ast.AST]:
        """Build a function with the shared prelude and only the matched branch.

        Including an entire if/elif chain incorrectly attributes sibling sinks.
        Ambiguous comparisons are deliberately left unlinked.
        """
        matches = []
        for handler in handlers:
            if not handler.args.args: continue
            discriminant = handler.args.args[0].arg
            prefix = []
            for statement in handler.body:
                selected = None
                node = statement
                while isinstance(node, ast.If):
                    test = node.test
                    if (isinstance(test, ast.Compare) and isinstance(test.left, ast.Name)
                            and test.left.id == discriminant and len(test.ops) == len(test.comparators) == 1
                            and self._resolve_static_value(test.comparators[0]) == tool_name):
                        if isinstance(test.ops[0], ast.Eq): selected = node.body
                        elif isinstance(test.ops[0], ast.NotEq): selected = node.orelse
                        break
                    node = node.orelse[0] if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If) else None
                if isinstance(statement, ast.Match) and isinstance(statement.subject, ast.Name) and statement.subject.id == discriminant:
                    for case in statement.cases:
                        if isinstance(case.pattern, ast.MatchValue) and self._resolve_static_value(case.pattern.value) == tool_name:
                            selected = case.body
                if selected:
                    function = copy.deepcopy(handler)
                    function.body = copy.deepcopy(prefix + selected)
                    function.decorator_list = []
                    matches.append(function)
                    break
                prefix.append(statement)
        return matches[0] if len(matches) == 1 else None

    def _node_source(self, node: ast.AST) -> str:
        start_line = self._node_line(node) or 1
        start = max(0, start_line - 1)
        end = getattr(node, "end_lineno", None)
        if end is None and isinstance(node, ast.match_case) and node.body:
            end = getattr(node.body[-1], "end_lineno", start_line)
        end = end or start_line
        return "\n".join(self.source_lines[start:end])

    @staticmethod
    def _node_line(node: ast.AST) -> Optional[int]:
        line = getattr(node, "lineno", None)
        if line is None and isinstance(node, ast.match_case):
            line = getattr(node.pattern, "lineno", None)
        return line

    def _check_tool_decorator(self, node: ast.FunctionDef) -> Optional[Dict[str, Any]]:
        """Check if a function has a tool decorator and extract its info."""
        for decorator in node.decorator_list:
            decorator_name = self._get_decorator_name(decorator)

            # Check if it's a tool decorator
            if decorator_name == "tool" or decorator_name.endswith(".tool"):
                info = {"decorator_name": decorator_name, "description": ""}

                # Extract description from decorator arguments
                if isinstance(decorator, ast.Call):
                    # Check for description keyword argument
                    for keyword in decorator.keywords:
                        if keyword.arg == "description":
                            try:
                                value = self._literal_evaluator.resolve(keyword.value)
                                if isinstance(value, str):
                                    info["description"] = value
                                    info["description_derived"] = not isinstance(keyword.value, ast.Constant)
                            except (ValueError, TypeError): pass

                    # Check for positional description argument
                    if decorator.args:
                        first_arg = decorator.args[0]
                        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                            info["description"] = first_arg.value

                return info

        return None

    def _get_decorator_name(self, decorator: ast.expr) -> str:
        """Get the full name of a decorator."""
        if isinstance(decorator, ast.Name):
            return decorator.id
        elif isinstance(decorator, ast.Attribute):
            parts = []
            node = decorator
            while isinstance(node, ast.Attribute):
                parts.append(node.attr)
                node = node.value
            if isinstance(node, ast.Name):
                parts.append(node.id)
            return ".".join(reversed(parts))
        elif isinstance(decorator, ast.Call):
            return self._get_decorator_name(decorator.func)
        return ""

    def _get_call_name(self, call: ast.Call) -> str:
        """Get the name of a function call."""
        if isinstance(call.func, ast.Name):
            return call.func.id
        elif isinstance(call.func, ast.Attribute):
            return call.func.attr
        return ""

    def _create_tool_definition(
        self,
        node: ast.FunctionDef,
        tool_info: Dict[str, Any],
        filepath: str
    ) -> ToolDefinition:
        """Create a ToolDefinition from a function node."""
        # Get function body as source code
        start_line = node.lineno - 1
        end_line = node.end_lineno if node.end_lineno else start_line + 1
        function_body = textwrap.dedent("\n".join(self.source_lines[start_line:end_line]))

        # Extract parameter names
        parameters = []
        for arg in node.args.args:
            parameters.append(arg.arg)

        # Extract decorator names
        decorators = []
        for dec in node.decorator_list:
            decorators.append(self._get_decorator_name(dec))

        # Get docstring
        docstring = ast.get_docstring(node)

        return ToolDefinition(
            name=node.name,
            description=tool_info.get("description", ""),
            docstring=docstring,
            line_number=node.lineno,
            end_line_number=end_line,
            function_body=function_body,
            parameters=parameters,
            decorators=decorators,
            source_file=filepath,
            registration_style="decorator",
            declaration_line=node.lineno,
            implementation_line=node.lineno,
            implementation_source=function_body,
            raw_node=node,
            description_derived=tool_info.get("description_derived", False),
        )

    def _extract_imports(self, tree: ast.AST) -> List[str]:
        """Extract all import statements."""
        imports = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    imports.append(f"{module}.{alias.name}")

        return imports
