# Curated public MCP security data inventory

No scanner was invoked while producing this inventory. A sample is one unique, pinned source artifact with at least one explicit maintainer/benchmark label mapped to a stable scanner rule.

- Accepted sources: 7
- Unique static samples: 33
- Rule labels: 50 (30 positive, 20 negative)

| Rule | Positive | Negative | Total |
|---|---:|---:|---:|
| MCP01-SECRET-HARDCODED | 2 | 2 | 4 |
| MCP01-SECRET-OUTPUT | 3 | 2 | 5 |
| MCP02-BROAD-SCOPE | 1 | 0 | 1 |
| MCP03-TOOL-POISON | 5 | 5 | 10 |
| MCP05-COMMAND-INJECTION | 5 | 5 | 10 |
| MCP05-DYNAMIC-CODE | 5 | 2 | 7 |
| MCP06-UNTRUSTED-CONTEXT | 4 | 0 | 4 |
| MCP07-PERMISSIVE-BIND | 1 | 1 | 2 |
| MCP09-CONFUSABLE-NAME | 2 | 0 | 2 |
| MCP13-SSRF | 2 | 3 | 5 |

## Rejected or deferred

| Source | Count | Reason |
|---|---:|---|
| Connor | 134 | Only corpus-level benign/malicious labels; 114 PoCs lack exact MCP01-MCP16 rule labels and 20 dataset servers include third-party overlap. |
| CrossMCP-Bench | 277 | Runtime authorization traces, not static source artifacts. |
| mcpsec runtime cases | 64 | Gateway runtime tests requiring a different analyzer adapter. |
| three unverified Hugging Face sets | 186 | Schema/provenance or static-source compatibility is not yet verified. |
| Appsecco outdated-packages lab | 1 | Known-vulnerable pinned dependencies do not match our mutable-dependency rule. |
| DVMCP challenges 1, 4, and 10 | 3 | Direct user prompt injection, runtime rug pull, or multi-vector label is not an exact single static rule label. |
