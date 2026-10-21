"""
Sanitization functions for MCP security defenses.

Provides runtime sanitization for:
1. External content (HTTP responses, file contents, DB results) - prevents prompt injection
2. Tool descriptions - prevents tool poisoning
"""

import re
import html
import unicodedata
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class SanitizationConfig:
    """Configuration for sanitization behavior."""
    max_length: int = 10000
    strip_html: bool = True
    strip_urls: bool = False  # For content, URLs might be legitimate
    strip_prompt_patterns: bool = True
    strip_hidden_instructions: bool = True
    preserve_newlines: bool = True


@dataclass
class SanitizationResult:
    """Result of sanitization with metadata."""
    content: str
    original_length: int
    was_truncated: bool
    patterns_removed: list = field(default_factory=list)
    warnings: list = field(default_factory=list)


# =============================================================================
# PROMPT INJECTION PATTERNS TO STRIP FROM EXTERNAL CONTENT
# =============================================================================

PROMPT_INJECTION_PATTERNS = [
    # Direct instruction attempts
    (r"(?i)\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|context)", "ignore_instructions"),
    (r"(?i)\b(you\s+are|you're)\s+(now\s+)?(a|an)\s+\w+", "role_override"),
    (r"(?i)\bnew\s+instructions?:\s*", "new_instructions"),
    (r"(?i)\bsystem\s*:\s*", "system_prompt_injection"),
    (r"(?i)\b(assistant|ai|bot)\s*:\s*", "assistant_injection"),
    (r"(?i)\[system\]|\[instruction\]|\[important\]|\[hidden\]", "hidden_markers"),

    # Action commands
    (r"(?i)\b(you\s+must|always|never)\s+(send|read|execute|call|access)", "imperative_commands"),
    (r"(?i)\b(send|transmit|post)\s+(this|the|all)\s+(data|information|content)\s+to", "exfiltration_attempt"),
    (r"(?i)\b(read|access|get)\s+(the\s+)?(file|content|data)\s+(from|at)\s+[\/~]", "file_access_attempt"),

    # Jailbreak patterns
    (r"(?i)pretend\s+(you're|you\s+are|to\s+be)", "pretend_jailbreak"),
    (r"(?i)act\s+as\s+(if|though|a)", "act_as_jailbreak"),
    (r"(?i)roleplay\s+as", "roleplay_jailbreak"),
    (r"(?i)DAN\s*mode|jailbreak|bypass\s+(safety|filter|restriction)", "explicit_jailbreak"),
]

# =============================================================================
# TOOL POISONING PATTERNS TO STRIP FROM DESCRIPTIONS
# =============================================================================

DESCRIPTION_POISON_PATTERNS = [
    # Hidden instruction markers - match the bracket and any following content until double newline
    (r"(?i)\[(?:important|note|instruction|system|hidden|internal|admin)\][\s\S]*?(?=\n\n|\Z)", "hidden_marker"),
    (r"(?i)\((?:important|note|instruction|system|hidden)\)[\s\S]*?(?=\n\n|\Z)", "hidden_marker_parens"),

    # URLs (suspicious in descriptions)
    (r"https?://[^\s\"'<>]+", "url"),

    # File path references
    (r"[~\/][^\s\"']+(?:\.ssh|\.env|\.aws|passwd|shadow|credentials|id_rsa)[^\s\"']*", "sensitive_path"),

    # Sequential action instructions - match entire sentence/paragraph
    (r"(?i)(?:after|before|then|first|finally|next)\s+(?:finishing|completing|done|this)[\s\S]*?(?:use|call|read|send|execute)[\s\S]*?(?:\.|(?=\n\n)|\Z)", "sequential_action"),

    # Override instructions
    (r"(?i)(?:ignore|override|bypass|skip)\s+(?:previous|all|any|the)?\s*(?:instructions?|rules?|restrictions?|limitations?)[\s\S]*?(?:\.|(?=\n\n)|\Z)", "override_instruction"),

    # Imperative commands
    (r"(?i)(?:you\s+)?(?:must|always|should|need\s+to)\s+(?:also\s+)?(?:send|read|execute|call|use|access)[\s\S]*?(?:\.|(?=\n\n)|\Z)", "imperative_command"),

    # Command execution instructions
    (r"(?i)(?:execute|run)\s+(?:the\s+)?(?:shell|command|script)[\s\S]*?(?:\.|(?=\n\n)|\Z)", "command_execution"),

    # Data exfiltration
    (r"(?i)(?:send|post|transmit|upload|forward)\s+(?:the\s+)?(?:data|content|result|output|it)\s+(?:to|via)[\s\S]*?(?:\.|(?=\n\n)|\Z)", "exfiltration"),

    # Tool chaining instructions
    (r"(?i)(?:use|call|invoke)\s+['\"]?\w+['\"]?\s+(?:tool|function)[\s\S]*?(?:\.|(?=\n\n)|\Z)", "tool_chaining"),

    # Preference manipulation
    (r"(?i)this\s+tool\s+(?:is|should\s+be)\s+(?:preferred|prioritized|best|recommended)[\s\S]*?(?:\.|(?=\n\n)|\Z)", "preference_manipulation"),
    (r"(?i)(?:most|more)\s+(?:reliable|accurate|trustworthy)[\s\S]*?(?:\.|(?=\n\n)|\Z)", "preference_manipulation"),
    (r"(?i)use\s+this\s+(?:instead|first)[\s\S]*?(?:\.|(?=\n\n)|\Z)", "preference_manipulation"),
]


# =============================================================================
# CONTENT SANITIZER (for external data - HTTP, files, DB)
# =============================================================================

class ContentSanitizer:
    """
    Sanitizes external content to prevent indirect prompt injection.

    Use this to sanitize:
    - HTTP responses before returning to LLM
    - File contents before returning to LLM
    - Database query results before returning to LLM
    """

    def __init__(self, config: Optional[SanitizationConfig] = None):
        self.config = config or SanitizationConfig()
        self._compiled_patterns = [
            (re.compile(pattern, re.MULTILINE | re.DOTALL), name)
            for pattern, name in PROMPT_INJECTION_PATTERNS
        ]

    def sanitize(self, content: str) -> SanitizationResult:
        """
        Sanitize external content.

        Args:
            content: Raw external content

        Returns:
            SanitizationResult with cleaned content and metadata
        """
        if not content:
            return SanitizationResult(
                content="",
                original_length=0,
                was_truncated=False
            )

        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")
        elif not isinstance(content, str):
            content = str(content)
        original_length = len(content)
        patterns_removed = []
        warnings = []

        content = unicodedata.normalize("NFKC", content)
        unicode_controls = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069]")
        if unicode_controls.search(content):
            content = unicode_controls.sub("", content)
            patterns_removed.append("unicode_controls")
            warnings.append("Removed invisible or bidirectional Unicode controls")

        # Strip HTML if configured
        if self.config.strip_html:
            content = strip_html(content)

        # Remove prompt injection patterns
        if self.config.strip_prompt_patterns:
            for compiled_pattern, pattern_name in self._compiled_patterns:
                if compiled_pattern.search(content):
                    content = compiled_pattern.sub("[FILTERED]", content)
                    patterns_removed.append(pattern_name)
                    warnings.append(f"Removed suspicious pattern: {pattern_name}")

        # Truncate if too long
        was_truncated = False
        if len(content) > self.config.max_length:
            content = content[:self.config.max_length]
            was_truncated = True
            warnings.append(f"Content truncated from {original_length} to {self.config.max_length} characters")

        content = f"[BEGIN UNTRUSTED DATA]\n{content}\n[END UNTRUSTED DATA]"
        return SanitizationResult(
            content=content,
            original_length=original_length,
            was_truncated=was_truncated,
            patterns_removed=patterns_removed,
            warnings=warnings
        )


# =============================================================================
# DESCRIPTION SANITIZER (for tool descriptions/docstrings)
# =============================================================================

class DescriptionSanitizer:
    """
    Sanitizes tool descriptions to prevent tool poisoning.

    Use this to clean docstrings and description parameters in @server.tool()
    """

    def __init__(self, config: Optional[SanitizationConfig] = None):
        self.config = config or SanitizationConfig(strip_urls=True)
        self._compiled_patterns = [
            (re.compile(pattern, re.MULTILINE | re.DOTALL), name)
            for pattern, name in DESCRIPTION_POISON_PATTERNS
        ]

    def sanitize(self, description: str) -> SanitizationResult:
        """
        Sanitize a tool description.

        Args:
            description: Raw tool description/docstring

        Returns:
            SanitizationResult with cleaned description and metadata
        """
        if not description:
            return SanitizationResult(
                content="",
                original_length=0,
                was_truncated=False
            )

        original_length = len(description)
        patterns_removed = []
        warnings = []
        content = description
        content = unicodedata.normalize("NFKC", content)
        content = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069]", "", content)

        # Remove poisoning patterns
        for compiled_pattern, pattern_name in self._compiled_patterns:
            if compiled_pattern.search(content):
                content = compiled_pattern.sub("", content)
                patterns_removed.append(pattern_name)
                warnings.append(f"Removed tool poisoning pattern: {pattern_name}")

        # Clean up extra whitespace from removals
        content = re.sub(r'\n\s*\n\s*\n', '\n\n', content)  # Multiple blank lines
        content = re.sub(r'  +', ' ', content)  # Multiple spaces
        content = content.strip()

        return SanitizationResult(
            content=content,
            original_length=original_length,
            was_truncated=False,
            patterns_removed=patterns_removed,
            warnings=warnings
        )


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

# Global sanitizer instances for convenience functions
_content_sanitizer = ContentSanitizer()
_description_sanitizer = DescriptionSanitizer()


def sanitize_content(content: str, max_length: int = 10000) -> str:
    """
    Sanitize external content (HTTP responses, file contents, etc.)

    This is the main function to use in MCP tools to prevent prompt injection.

    Args:
        content: Raw external content
        max_length: Maximum content length (default 10000)

    Returns:
        Sanitized content string

    Example:
        @server.tool()
        def fetch_webpage(url: str) -> str:
            response = requests.get(url)
            return sanitize_content(response.text)
    """
    config = SanitizationConfig(max_length=max_length)
    sanitizer = ContentSanitizer(config)
    result = sanitizer.sanitize(content)
    return result.content


def sanitize_data(value, max_length: int = 10000):
    """Bound external text while preserving built-in JSON/SQLite value shapes.

    Dictionary keys remain schema keys. Strings and bytes in values receive the
    same filtering and untrusted-data boundary as sanitize_content. Numbers,
    booleans and None retain their values. Custom objects and cyclic/deep data
    are rejected instead of being silently stringified or returned untreated.
    This is a mitigation, not a guarantee against all prompt injection.
    """
    active = set()

    def visit(item, depth):
        if depth > 64:
            raise ValueError('External data exceeds the supported nesting depth')
        if type(item) is str:
            return sanitize_content(item, max_length=max_length)
        if type(item) is bytes:
            return sanitize_content(item, max_length=max_length).encode('utf-8')
        if item is None or type(item) in (bool, int, float):
            return item
        if type(item) not in (dict, list, tuple):
            raise TypeError('Unsupported external data type: ' + type(item).__name__)
        if id(item) in active:
            raise ValueError('External data contains a cycle')
        active.add(id(item))
        try:
            if type(item) is dict:
                return {key: visit(child, depth + 1) for key, child in item.items()}
            return type(item)(visit(child, depth + 1) for child in item)
        finally:
            active.remove(id(item))

    return visit(value, 0)


def sanitize_description(description: str) -> str:
    """
    Sanitize a tool description/docstring.

    Args:
        description: Raw tool description

    Returns:
        Sanitized description string
    """
    result = _description_sanitizer.sanitize(description)
    return result.content


def strip_html(content: str) -> str:
    """
    Strip HTML tags and decode entities from content.

    Args:
        content: Content potentially containing HTML

    Returns:
        Content with HTML removed
    """
    # Remove script and style tags with content
    content = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.DOTALL | re.IGNORECASE)
    content = re.sub(r'<style[^>]*>.*?</style>', '', content, flags=re.DOTALL | re.IGNORECASE)

    # Remove HTML tags
    content = re.sub(r'<[^>]+>', '', content)

    # Decode HTML entities
    content = html.unescape(content)

    return content


def strip_prompt_injections(content: str) -> str:
    """
    Strip common prompt injection patterns from content.

    Args:
        content: Content to filter

    Returns:
        Content with injection patterns removed
    """
    for pattern, _ in PROMPT_INJECTION_PATTERNS:
        content = re.sub(pattern, "[FILTERED]", content, flags=re.MULTILINE | re.DOTALL)
    return content
