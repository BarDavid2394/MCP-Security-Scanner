"""
MCP Security Defenses Module

Provides sanitization and auto-fix capabilities for MCP security vulnerabilities.
"""

from .sanitizers import (
    sanitize_content,
    sanitize_data,
    sanitize_description,
    strip_html,
    strip_prompt_injections,
    ContentSanitizer,
    DescriptionSanitizer,
)

__all__ = [
    "sanitize_content",
    "sanitize_data",
    "sanitize_description",
    "strip_html",
    "strip_prompt_injections",
    "ContentSanitizer",
    "DescriptionSanitizer",
]
