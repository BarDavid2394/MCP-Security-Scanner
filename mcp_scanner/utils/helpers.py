"""
Utility functions for the MCP Security Scanner.
"""

from pathlib import Path
from typing import List, Optional


def read_file(filepath: str | Path) -> Optional[str]:
    """
    Read file content safely.

    Args:
        filepath: Path to the file to read.

    Returns:
        File content as string, or None if file cannot be read.
    """
    try:
        path = Path(filepath)
        if not path.exists():
            return None
        if not path.is_file():
            return None
        return path.read_text(encoding="utf-8")
    except Exception as e:
        print(f"Warning: Could not read {filepath}: {e}")
        return None


def get_python_files(directory: str | Path) -> List[Path]:
    """
    Recursively find all Python files in a directory.

    Args:
        directory: Path to search for Python files.

    Returns:
        List of Path objects for all .py files found.
    """
    path = Path(directory)

    if path.is_file():
        if path.suffix == ".py":
            return [path]
        return []

    if not path.is_dir():
        return []

    python_files = []
    for item in path.rglob("*.py"):
        # Skip common non-source directories
        parts = item.parts
        skip_dirs = {"__pycache__", ".git", ".venv", "venv", "node_modules", ".tox", ".mcp-scanner-cache"}
        if any(skip_dir in parts for skip_dir in skip_dirs):
            continue
        python_files.append(item)

    return sorted(python_files)


SCANNABLE_CONFIG_SUFFIXES = {".json", ".yaml", ".yml", ".toml"}
SCANNABLE_SOURCE_SUFFIXES = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
SCANNABLE_MANIFESTS = {
    "requirements.txt", "pyproject.toml", "pipfile", "poetry.lock", "uv.lock",
    "package.json", "package-lock.json", ".mcp.json", "claude_desktop_config.json",
}


def get_project_files(directory: str | Path) -> List[Path]:
    """Return Python, MCP configuration, and dependency artifacts."""
    path = Path(directory)
    if path.is_file():
        return [path]
    if not path.is_dir():
        return []
    files = []
    skip_dirs = {"__pycache__", ".git", ".venv", "venv", "node_modules", ".tox", "dist", "build", ".mcp-scanner-cache"}
    for item in path.rglob("*"):
        if not item.is_file() or any(part in skip_dirs for part in item.parts):
            continue
        name = item.name.lower()
        if item.suffix.lower() in SCANNABLE_SOURCE_SUFFIXES or name in SCANNABLE_MANIFESTS or item.suffix.lower() in SCANNABLE_CONFIG_SUFFIXES:
            files.append(item)
    return sorted(set(files))


def truncate_string(s: str, max_length: int = 100) -> str:
    """Truncate a string to max_length, adding ellipsis if truncated."""
    if len(s) <= max_length:
        return s
    return s[:max_length - 3] + "..."


def get_line_number(source: str, position: int) -> int:
    """Get line number from character position in source."""
    return source[:position].count("\n") + 1


def extract_context(source: str, line_number: int, context_lines: int = 2) -> str:
    """
    Extract source code context around a specific line.

    Args:
        source: Full source code.
        line_number: Target line number (1-indexed).
        context_lines: Number of lines before/after to include.

    Returns:
        Source code snippet with context.
    """
    lines = source.split("\n")
    start = max(0, line_number - 1 - context_lines)
    end = min(len(lines), line_number + context_lines)

    context = []
    for i in range(start, end):
        prefix = ">>> " if i == line_number - 1 else "    "
        context.append(f"{i + 1:4d} {prefix}{lines[i]}")

    return "\n".join(context)
