"""
AST-based code transformations for auto-fixing MCP security vulnerabilities.

Transforms:
1. Docstring cleaning - removes tool poisoning patterns
2. Return statement wrapping - adds sanitize_content() calls
"""

import ast
import re
from typing import List, Tuple, Optional, Set
from dataclasses import dataclass, field

from .sanitizers import DescriptionSanitizer, DESCRIPTION_POISON_PATTERNS
from ..prompt_repairs import return_repairs


@dataclass
class TransformResult:
    """Result of code transformation."""
    original_code: str
    transformed_code: str
    changes_made: List[str] = field(default_factory=list)
    lines_modified: List[int] = field(default_factory=list)
    imports_added: List[str] = field(default_factory=list)
    success: bool = True
    error: Optional[str] = None


@dataclass
class FixableIssue:
    """Represents an issue that can be auto-fixed."""
    issue_type: str  # 'tool_poisoning' or 'prompt_injection'
    line_number: int
    function_name: str
    description: str
    fix_action: str


class CodeTransformer:
    """
    Transforms Python source code to fix MCP security vulnerabilities.

    Uses line-based transformation (not AST rewriting) to preserve
    original formatting and comments.
    """

    def __init__(self):
        self.description_sanitizer = DescriptionSanitizer()
        self._poison_patterns = [
            (re.compile(pattern, re.MULTILINE | re.DOTALL), name)
            for pattern, name in DESCRIPTION_POISON_PATTERNS
        ]

    def transform(self, source_code: str, findings: List = None) -> TransformResult:
        """
        Transform source code to fix security vulnerabilities.

        Args:
            source_code: Original Python source code
            findings: Optional list of Finding objects from scanner

        Returns:
            TransformResult with transformed code and metadata
        """
        result = TransformResult(
            original_code=source_code,
            transformed_code=source_code
        )

        try:
            # Parse to get structure
            tree = ast.parse(source_code)
        except SyntaxError as e:
            result.success = False
            result.error = f"Syntax error: {e}"
            return result

        lines = source_code.split('\n')
        sanitizer_imports = set()
        modified_lines: Set[int] = set()
        changes = []
        findings = findings or []
        report_only_poison = {
            finding.function_name for finding in findings
            if getattr(finding, "attack_id", None) == "MCP03" and not getattr(finding, "fixable", False)
            # These supporting signatures also match the same instruction as
            # stronger, fixable findings. They do not independently authorize
            # an edit, but should not veto an otherwise supported repair.
            # Explicit semantic/decoded/derived report-only evidence still
            # blocks the whole-docstring sanitizer, which cannot isolate it.
            and not (
                finding.matched_pattern in {"tool_chaining", "imperative_must"}
                and finding.severity.value == "MEDIUM"
                and finding.metadata.get("source") in {"description", "docstring"}
                and not finding.metadata.get("needs_semantic_review")
            )
        }
        poison_targets = {
            finding.function_name for finding in findings
            if getattr(finding, "attack_id", None) == "MCP03"
            and getattr(finding, "fixable", False)
            and finding.function_name not in report_only_poison
            and getattr(finding, "severity", None).value in {"CRITICAL", "HIGH"}
            and finding.function_name
        }
        prompt_targets = {
            finding.metadata.get('auto_fix', {}).get('function_line') for finding in findings
            if getattr(finding, "attack_id", None) == "MCP06"
            and getattr(finding, "fixable", False)
            and finding.metadata.get('auto_fix', {}).get('strategy') == 'wrap_proven_external_return'
            and finding.function_name
        }
        # Avoid capturing any existing global/local binding, including arguments.
        occupied = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        occupied.update(n.arg for n in ast.walk(tree) if isinstance(n, ast.arg))
        occupied.update(n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
        occupied.update(n.asname or n.name.split('.')[0] for n in ast.walk(tree) if isinstance(n, ast.alias))
        sanitizer_names = {}
        for name in ('sanitize_content', 'sanitize_data'):
            alias = name
            while alias in occupied:
                alias = '_' + alias
            sanitizer_names[name] = alias

        # Find all tool functions and sort by line number (descending)
        # Processing from bottom to top prevents line number shifts from affecting later fixes
        tool_functions = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if self._is_tool_function(node):
                    tool_functions.append(node)

        # Sort by line number descending (fix from bottom to top)
        tool_functions.sort(key=lambda n: n.lineno, reverse=True)

        for node in tool_functions:
            # Edit lower return lines before replacing an earlier docstring so
            # original AST line spans remain valid throughout this function.
            return_result = (self._fix_return_statements(node, lines, tree, sanitizer_names)
                             if node.lineno in prompt_targets else None)
            if return_result:
                lines, ret_changes, ret_lines, needed_imports = return_result
                changes.extend(ret_changes)
                modified_lines.update(ret_lines)
                sanitizer_imports.update(needed_imports)

            docstring_result = self._fix_docstring(node, lines) if node.name in poison_targets else None
            if docstring_result:
                lines, doc_changes, doc_lines = docstring_result
                changes.extend(doc_changes)
                modified_lines.update(doc_lines)

        # Add import if needed
        imports_added = []
        if sanitizer_imports:
            # Reparse after edits: original line numbers may have shifted.
            updated_tree = ast.parse('\n'.join(lines))
            import_line = 0
            for statement in updated_tree.body:
                if (isinstance(statement, (ast.Import, ast.ImportFrom)) or
                        import_line == 0 and isinstance(statement, ast.Expr)
                        and isinstance(statement.value, ast.Constant) and isinstance(statement.value.value, str)):
                    import_line = statement.end_lineno
                else:
                    break
            for name in sorted(sanitizer_imports):
                alias = sanitizer_names[name]
                statement = 'from mcp_scanner.defenses import ' + name
                if alias != name:
                    statement += ' as ' + alias
                lines.insert(import_line, statement)
                import_line += 1
                imports_added.append(statement)
                changes.insert(0, f'Added {name} import')

        result.transformed_code = '\n'.join(lines)
        result.changes_made = changes
        result.lines_modified = sorted(modified_lines)
        result.imports_added = imports_added

        try:
            ast.parse(result.transformed_code)
        except SyntaxError as exc:
            result.success = False
            result.error = f"Transformation produced invalid Python: {exc}"
            result.transformed_code = source_code
            result.changes_made = []
        return result

    def _is_tool_function(self, node: ast.FunctionDef) -> bool:
        """Check if function has a tool decorator."""
        for decorator in node.decorator_list:
            dec_name = self._get_decorator_name(decorator)
            if dec_name == 'tool' or dec_name.endswith('.tool'):
                return True
        return False

    def _get_decorator_name(self, decorator) -> str:
        """Get full decorator name."""
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
            return '.'.join(reversed(parts))
        elif isinstance(decorator, ast.Call):
            return self._get_decorator_name(decorator.func)
        return ''

    def _fix_docstring(self, node: ast.FunctionDef, lines: List[str]) -> Optional[Tuple[List[str], List[str], List[int]]]:
        """
        Fix tool poisoning in docstring.

        Returns:
            Tuple of (modified_lines, changes, line_numbers) or None if no changes
        """
        docstring = ast.get_docstring(node)
        if not docstring:
            return None

        # Check if docstring has issues
        has_issues = False
        for pattern, _ in self._poison_patterns:
            if pattern.search(docstring):
                has_issues = True
                break

        if not has_issues:
            return None

        # Sanitize the docstring
        sanitized = self.description_sanitizer.sanitize(docstring)

        if sanitized.content == docstring:
            return None

        # Find docstring location in source
        # Docstring is first statement in function body
        if node.body and isinstance(node.body[0], ast.Expr):
            if isinstance(node.body[0].value, ast.Constant):
                doc_node = node.body[0]
                start_line = doc_node.lineno - 1  # 0-indexed
                end_line = doc_node.end_lineno - 1

                # Detect quote style
                original_doc_text = '\n'.join(lines[start_line:end_line + 1])
                if '"""' in original_doc_text:
                    quote = '"""'
                else:
                    quote = "'''"

                # Get indentation from the original docstring line
                indent = len(lines[start_line]) - len(lines[start_line].lstrip())
                indent_str = ' ' * indent

                # Build new docstring with proper formatting
                new_docstring_lines = []
                sanitized_content = sanitized.content.strip()
                sanitized_lines = sanitized_content.split('\n')

                # Clean up empty lines and normalize
                sanitized_lines = [line.strip() for line in sanitized_lines]
                # Remove consecutive empty lines
                cleaned_lines = []
                prev_empty = False
                for line in sanitized_lines:
                    if line == '':
                        if not prev_empty:
                            cleaned_lines.append(line)
                        prev_empty = True
                    else:
                        cleaned_lines.append(line)
                        prev_empty = False

                # Remove leading/trailing empty lines
                while cleaned_lines and cleaned_lines[0] == '':
                    cleaned_lines.pop(0)
                while cleaned_lines and cleaned_lines[-1] == '':
                    cleaned_lines.pop()

                if len(cleaned_lines) == 0:
                    # Empty docstring after cleaning
                    new_docstring_lines.append(f'{indent_str}{quote}Tool function.{quote}')
                elif len(cleaned_lines) == 1:
                    # Single line docstring
                    new_docstring_lines.append(f'{indent_str}{quote}{cleaned_lines[0]}{quote}')
                else:
                    # Multi-line docstring
                    new_docstring_lines.append(f'{indent_str}{quote}')
                    for line in cleaned_lines:
                        if line:
                            new_docstring_lines.append(f'{indent_str}{line}')
                        else:
                            new_docstring_lines.append('')
                    new_docstring_lines.append(f'{indent_str}{quote}')

                # Replace lines
                lines = lines[:start_line] + new_docstring_lines + lines[end_line + 1:]

                changes = [f"Cleaned docstring in {node.name}(): removed {len(sanitized.patterns_removed)} poisoning patterns"]
                modified_lines = list(range(start_line + 1, start_line + len(new_docstring_lines) + 1))

                return lines, changes, modified_lines

        return None

    def _fix_return_statements(self, node, lines, module, sanitizer_names):
        """Wrap only proven return-value AST spans, preserving surrounding code."""
        plan = return_repairs(module, node)
        changes, modified_lines, needed_imports = [], [], set()
        for statement, sanitizer in sorted(plan, key=lambda item: (item[0].lineno, item[0].col_offset), reverse=True):
            value = statement.value
            start, end = value.lineno - 1, value.end_lineno - 1
            # AST columns are UTF-8 byte offsets, not Python character offsets.
            chunk = '\n'.join(lines[start:end + 1]).encode('utf-8')
            end_offset = sum(len(line.encode('utf-8')) + 1 for line in lines[start:end]) + value.end_col_offset
            expression = chunk[value.col_offset:end_offset]
            replacement = sanitizer_names[sanitizer].encode('utf-8') + b'((' + expression + b'))'
            rewritten = chunk[:value.col_offset] + replacement + chunk[end_offset:]
            lines[start:end + 1] = rewritten.decode('utf-8').split('\n')
            changes.append(f'Wrapped external return in {node.name}() with {sanitizer}()')
            modified_lines.extend(range(start + 1, end + 2))
            needed_imports.add(sanitizer)
        return (lines, changes, modified_lines, needed_imports) if changes else None


def transform_file(filepath: str, findings: List = None) -> TransformResult:
    """
    Convenience function to transform a file.

    Args:
        filepath: Path to Python file
        findings: Optional scanner findings

    Returns:
        TransformResult
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        source_code = f.read()

    transformer = CodeTransformer()
    return transformer.transform(source_code, findings)
