"""Dependency-free parser for common TypeScript/JavaScript MCP APIs."""

from __future__ import annotations

import re

from .python_parser import MCPServerInfo, ToolDefinition


SCRIPT_SUFFIXES = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}


class TypeScriptMCPParser:
    """Extract MCP tools without requiring a Node toolchain.

    This is deliberately structural rather than a complete TypeScript grammar:
    it recognizes the official SDK's ``tool`` and ``registerTool`` forms while
    balancing braces so multiline handlers are analyzed as one unit.
    """

    SERVER = re.compile(r"new\s+(?:McpServer|Server)\s*\(\s*(?:\{[^}]*?name\s*:\s*)?['\"]([^'\"]+)", re.S)
    TOOL = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\.\s*(tool|registerTool)\s*\(\s*['\"]([^'\"]+)['\"]", re.S)

    def parse_file(self, path):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            return MCPServerInfo(str(path), None, [], [], "", [f"Could not read file: {exc}"])
        return self.parse_source(text, str(path))

    def parse_source(self, text: str, filename: str = "<string>.ts") -> MCPServerInfo:
        server = self.SERVER.search(text)
        named_handlers = self._named_handlers(text)
        tools: list[ToolDefinition] = []
        for match in self.TOOL.finditer(text):
            end = self._balanced_end(text, match.start())
            block = text[match.start():end]
            name = match.group(3)
            line = text.count("\n", 0, match.start()) + 1
            implementation_line = line
            description_match = re.search(r"\bdescription\s*:\s*(['\"`])([\s\S]*?)\1", block)
            if not description_match and match.group(2) == "tool":
                description_match = re.search(r"^[\s\S]*?['\"]" + re.escape(name) + r"['\"]\s*,\s*(['\"`])([\s\S]*?)\1", block)
            description = description_match.group(2) if description_match else ""
            handler = re.search(r"(?:async\s*)?\(([^()]*)\)\s*=>\s*\{", block)
            if not handler:
                handler = re.search(r"(?:async\s+)?function\s*\w*\s*\(([^)]*)\)\s*\{", block)
            implementation = block
            raw_params = handler.group(1) if handler else ""
            if not handler:
                reference = re.search(r",\s*([A-Za-z_$][\w$]*)\s*\)\s*$", block)
                resolved = named_handlers.get(reference.group(1)) if reference else None
                if resolved:
                    raw, implementation, implementation_line = resolved
                    raw_params = raw
            params = []
            if raw_params:
                for part in raw_params.split(","):
                    cleaned = re.sub(r"[?:].*$", "", part.strip()).strip("{} ")
                    params.extend(re.findall(r"[A-Za-z_$][\w$]*", cleaned))
            # Schema keys are the effective sources when a handler destructures
            # its first argument or omits explicit type annotations.
            for key in re.findall(r"\b([A-Za-z_$][\w$]*)\s*:\s*z\.", block):
                if key not in params:
                    params.append(key)
            tools.append(ToolDefinition(name, description, None, line,
                text.count("\n", 0, end) + 1, block, params, [], filename,
                registration_style=f"typescript_{match.group(2)}",
                declaration_line=line, implementation_line=implementation_line,
                implementation_source=implementation, raw_node=None))
        tools.extend(self._low_level_tools(text, filename, {tool.name for tool in tools}))
        imports = re.findall(r"(?:from\s+|require\(['\"])([\w./@-]+)", text)
        return MCPServerInfo(filename, server.group(1) if server else None, tools, imports, text)

    def _low_level_tools(self, text: str, filename: str, existing: set[str]) -> list[ToolDefinition]:
        """Link ListTools declarations to CallTool switch/if branches."""
        list_match = re.search(r"setRequestHandler\s*\(\s*ListToolsRequestSchema", text)
        if not list_match:
            return []
        list_end = self._balanced_end(text, list_match.start())
        declaration = text[list_match.start():list_end]
        call_match = re.search(r"setRequestHandler\s*\(\s*CallToolRequestSchema", text)
        call_end = self._balanced_end(text, call_match.start()) if call_match else len(text)
        dispatcher = text[call_match.start():call_end] if call_match else ""
        result = []
        for name_match in re.finditer(r"\bname\s*:\s*['\"]([^'\"]+)['\"]", declaration):
            name = name_match.group(1)
            if name in existing:
                continue
            window = declaration[name_match.start():name_match.start() + 1200]
            desc_match = re.search(r"\bdescription\s*:\s*(['\"`])([\s\S]*?)\1", window)
            schema_match = re.search(r"\b(?:inputSchema|properties)\s*:\s*\{([\s\S]{0,1200}?)\}", window)
            params = re.findall(r"\b([A-Za-z_$][\w$]*)\s*:", schema_match.group(1)) if schema_match else []
            implementation = dispatcher
            implementation_line = text.count("\n", 0, call_match.start()) + 1 if call_match else 1
            branch = re.search(
                rf"(?:case\s*['\"]{re.escape(name)}['\"]\s*:|(?:params\.)?name\s*===?\s*['\"]{re.escape(name)}['\"])([\s\S]*?)(?=\bcase\s*['\"]|else\s+if|default\s*:|$)",
                dispatcher,
            )
            if branch:
                implementation = branch.group(0)
                implementation_line += dispatcher.count("\n", 0, branch.start())
            line = text.count("\n", 0, list_match.start() + name_match.start()) + 1
            result.append(ToolDefinition(name, desc_match.group(2) if desc_match else "", None,
                line, line, declaration, params or ["arguments"], [], filename,
                registration_style="typescript_low_level", declaration_line=line,
                implementation_line=implementation_line, implementation_source=implementation, raw_node=None))
        return result

    def _named_handlers(self, text: str) -> dict[str, tuple[str, str, int]]:
        result = {}
        pattern = re.compile(
            r"(?m)(?:async\s+function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{|"
            r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>\s*\{)"
        )
        for match in pattern.finditer(text):
            name = match.group(1) or match.group(3)
            params = match.group(2) or match.group(4) or ""
            brace = match.end() - 1
            end = self._balanced_brace_end(text, brace)
            result[name] = (params, text[match.start():end], text.count("\n", 0, match.start()) + 1)
        return result

    @staticmethod
    def _balanced_brace_end(text: str, start: int) -> int:
        depth, quote, escaped = 0, None, False
        for index in range(max(0, start), len(text)):
            char = text[index]
            if quote:
                if escaped: escaped = False
                elif char == "\\": escaped = True
                elif char == quote: quote = None
                continue
            if char in "'\"`": quote = char
            elif char == "{": depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0: return index + 1
        return len(text)

    @staticmethod
    def _balanced_end(text: str, start: int) -> int:
        depth = 0
        quote = None
        escaped = False
        opened = False
        for index in range(start, len(text)):
            char = text[index]
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                continue
            if char in "'\"`":
                quote = char
            elif char == "(":
                depth += 1
                opened = True
            elif char == ")" and opened:
                depth -= 1
                if depth == 0:
                    return index + 1
        return len(text)
