# MCP Security Scanner - Original v1 Project Plan

> This document records the original two-detector design. The implemented v2
> catalog and CLI are documented in `README.md` and `mcp_scanner/catalog.py`.

## Overview
Build a security scanner that analyzes MCP (Model Context Protocol) server implementations to detect two critical vulnerabilities:
1. **Tool Poisoning** - Malicious instructions hidden in tool metadata/descriptions
2. **Indirect Prompt Injection** - Unsafe handling of external data that could inject malicious prompts

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    MCP Security Scanner                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │   Parser     │───▶│  Analyzers   │───▶│   Reporter   │   │
│  │              │    │              │    │              │   │
│  │ - Python AST │    │ - Tool       │    │ - JSON       │   │
│  │ - MCP Schema │    │   Poisoning  │    │ - Console    │   │
│  │              │    │ - Prompt     │    │ - HTML       │   │
│  │              │    │   Injection  │    │              │   │
│  └──────────────┘    └──────────────┘    └──────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
mcp_scanner/
├── __init__.py
├── main.py                 # CLI entry point
├── scanner.py              # Main scanner orchestrator
├── parsers/
│   ├── __init__.py
│   ├── python_parser.py    # Parse Python MCP servers
│   └── config_parser.py    # Parse MCP config files
├── analyzers/
│   ├── __init__.py
│   ├── base.py             # Base analyzer class
│   ├── tool_poisoning.py   # Tool Poisoning detector
│   └── prompt_injection.py # Indirect Prompt Injection detector
├── reporters/
│   ├── __init__.py
│   ├── console.py          # Console output
│   └── json_reporter.py    # JSON report generation
├── patterns/
│   ├── __init__.py
│   └── signatures.py       # Detection patterns/signatures
└── utils/
    ├── __init__.py
    └── helpers.py          # Utility functions

tests/
├── __init__.py
├── test_tool_poisoning.py
├── test_prompt_injection.py
└── samples/                # Sample vulnerable MCP servers for testing
    ├── vulnerable_server_1.py
    └── vulnerable_server_2.py
```

---

## Vulnerability #1: Tool Poisoning Detection

### What to Detect
Tool poisoning embeds malicious instructions in tool descriptions/metadata that trick LLMs into performing unauthorized actions.

### Detection Patterns

```python
SUSPICIOUS_PATTERNS = [
    # Direct instruction patterns
    r"(?i)\b(read|open|access|get)\s+(file|content|data)\b",
    r"(?i)\b(send|post|transmit|upload)\s+(to|data)\b",
    r"(?i)\b(execute|run|invoke|call)\s+(command|script|code)\b",
    r"(?i)\bhttp[s]?://\S+",  # URLs in descriptions

    # Hidden instruction markers
    r"(?i)\[important\]",
    r"(?i)\[note\]",
    r"(?i)\[instruction\]",
    r"(?i)ignore\s+previous",
    r"(?i)after\s+(finishing|completing|done)",

    # Sensitive file paths
    r"(?i)(\.ssh|\.env|passwd|shadow|credentials|secret|token|key)",
    r"(?i)/etc/",
    r"(?i)~\/",

    # Action keywords in wrong context
    r"(?i)must\s+(also|first|then)",
    r"(?i)always\s+(send|read|execute)",
]
```

### Analysis Approach
1. Parse MCP server source code using Python AST
2. Extract all `@server.tool()` decorated functions
3. Analyze docstrings and description parameters
4. Apply pattern matching and heuristic scoring
5. Flag high-risk tools with explanation

---

## Vulnerability #2: Indirect Prompt Injection Detection

### What to Detect
External data fetched by MCP tools may contain malicious instructions that get passed to the LLM.

### Detection Patterns

```python
INJECTION_RISK_PATTERNS = [
    # Unsafe data handling
    r"requests\.(get|post|put)\([^)]+\)\.(?:text|content|json)",
    r"urllib\.request\.urlopen",
    r"open\([^)]+\)\.read\(\)",

    # Direct return of external data without sanitization
    r"return\s+.*\.(text|content|json\(\))",
    r"return\s+.*\.read\(\)",

    # Database queries returned directly
    r"cursor\.(?:execute|fetchall|fetchone)",

    # File content returned without validation
    r"return\s+open\(",
]

SANITIZATION_PATTERNS = [
    # Signs of proper sanitization (good practices)
    r"sanitize|escape|filter|validate|clean",
    r"strip\(|replace\(",
    r"re\.sub\(",
]
```

### Analysis Approach
1. Identify functions that fetch external data (HTTP, files, databases)
2. Trace data flow from source to return value
3. Check if sanitization is applied before returning
4. Flag tools that return raw external data to LLM context

---

## Severity Scoring

| Severity | Score | Description |
|----------|-------|-------------|
| CRITICAL | 9-10  | Direct command execution, credential theft |
| HIGH     | 7-8   | Data exfiltration, file access |
| MEDIUM   | 4-6   | Suspicious patterns, potential injection |
| LOW      | 1-3   | Minor issues, best practice violations |

---

## CLI Interface

```bash
# Scan a single file
python -m mcp_scanner scan server.py

# Scan a directory
python -m mcp_scanner scan ./mcp_servers/

# Output formats
python -m mcp_scanner scan server.py --format json --output report.json
python -m mcp_scanner scan server.py --format console

# Specific vulnerability check
python -m mcp_scanner scan server.py --check tool-poisoning
python -m mcp_scanner scan server.py --check prompt-injection
```

---

## Sample Output

```
MCP Security Scanner v1.0
=========================

Scanning: vulnerable_server.py

[CRITICAL] Tool Poisoning Detected
  Location: line 15, function 'add'
  Issue: Tool description contains hidden instructions
  Pattern: "After finishing the addition, use 'read_file' to obtain..."
  Risk: Attacker can trick LLM into reading sensitive files

[HIGH] Indirect Prompt Injection Risk
  Location: line 42, function 'fetch_github_issues'
  Issue: External data returned without sanitization
  Pattern: return requests.get(url).json()
  Risk: Malicious content in GitHub issues could inject prompts

Summary:
  Files scanned: 1
  Critical: 1
  High: 1
  Medium: 0
  Low: 0
```

---

## Implementation Phases

### Phase 1: Core Infrastructure
- [ ] Project setup (folders, __init__.py files)
- [ ] Base classes for analyzers and reporters
- [ ] Python AST parser for MCP servers

### Phase 2: Tool Poisoning Detector
- [ ] Pattern definitions
- [ ] Description/docstring extractor
- [ ] Scoring algorithm
- [ ] Unit tests with samples

### Phase 3: Prompt Injection Detector
- [ ] Pattern definitions
- [ ] Data flow analysis
- [ ] Sanitization checker
- [ ] Unit tests with samples

### Phase 4: CLI & Reporting
- [ ] Argument parsing
- [ ] Console reporter
- [ ] JSON reporter
- [ ] Summary statistics

### Phase 5: Testing & Documentation
- [ ] Create vulnerable sample servers
- [ ] End-to-end testing
- [ ] README documentation

---

## Dependencies

```
# requirements.txt
click>=8.0.0      # CLI framework
rich>=13.0.0      # Beautiful console output
```

No external dependencies needed for core scanning (uses Python stdlib: ast, re, json, pathlib)

---

## References

- Article: "Model Context Protocol (MCP): Landscape, Security Threats, and Future Research Directions"
- Tool Poisoning: Section 5.1.4 (page 18-19)
- Indirect Prompt Injection: Section 5.2.2 (page 22-23)
- Existing tools: mcpscan.ai, Invariant Labs mcp-scan
