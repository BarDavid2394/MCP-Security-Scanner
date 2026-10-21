# Follow-up development and validation — 17 October 2026

Three development rounds are complete. On the previously consumed 33-artifact
set, recall increased from **43.3% to 53.3%** (13 to 16 of 30 positive labels),
and false alarms fell from one to zero. However, the subsequent reserved
MCP-DecayBench evaluation missed both positive labels: **0% recall on that
small, single-family set**. Development gains did not resolve registration
coverage for hand-written JSON-RPC servers.

## Changes

- Python parsing recognizes `mcp.tool()(handler)` on a visibly constructed
  FastMCP instance and a single preceding `handler.__doc__` assignment. Bounded
  literal `chr()` expressions are resolved without executing source; shadowed
  builtins remain unresolved. Derived metadata is report-only.
- Metadata analysis detects mandatory sensitive-data collection and external
  transmission when all elements occur within a bounded span. Negative tests
  cover ordinary authenticated requests, local diagnostics, negation and quoted
  research. The new signal is report-only.
- JavaScript analysis separates executable calls from quoted examples and
  comments, recognizes narrow safe git argument arrays, and retains findings
  for controlled executables, shell execution and interpreters. Zero-argument
  handler parsing no longer treats description words as tool inputs.
- File-text aliases reaching JavaScript results and explicit HTTP text
  projections reaching Python returns are detected. Numeric lengths, status,
  count fields and recognized sanitized outputs have focused negative tests.

## Development measurements

These are paired development retests, not independent final validations.

| Round | Data and unit | Baseline TP / FP / FN / TN | Final TP / FP / FN / TN | Recall before → after |
|---|---|---|---|---|
| 008 | Consumed final set: 33 artifacts, 50 unchanged rule labels | 13 / 1 / 17 / 19 | 16 / 0 / 14 / 20 | 43.3% → 53.3% |
| 009 | 12 newly admitted adapted Vault records, 12 MCP03 labels | 2 / 0 / 4 / 6 | 6 / 0 / 0 / 6 | 33.3% → 100% |
| 010 | 12 synthetic fixtures, six paired behavior families | 4 / 4 / 2 / 2 | 6 / 0 / 0 / 6 | 66.7% → 100% |

Round 008's immediate parser retest recovered one positive; subsequent round
010 changes recovered two more and removed its false alarm. The table uses
the final frozen candidate throughout. Recovered old labels concern derived
Python metadata, JavaScript dynamic code, and Python HTTP content.

Round 009 labels were assigned before its baseline. Its source family was
already exposed in iteration 007. The existing docstring adapter preserves
text but changes its original context. Round 010 is synthetic. Additional HTTP
tests added during repair are not counted as fresh validation cases.

The saved initial scanner and the final candidate were compared on all ten
development manifests. **Every individual labeled outcome in rounds 001–007
was unchanged**, including their existing misses and false alarm. This checks
individual decisions, not only aggregate totals, but covers only labeled scope.

## Reserved evaluation

The scanner was frozen after tests and regression comparisons, before reviewing
final fixture source. Ten native, unmodified MCP-DecayBench files at revision
`7ce4e4541b494b7f1df1840499ee14e6a5fed69b` received ten explicit MCP03 labels:
two positive and eight negative. Labels were assigned before predictions; no
scanner output was used to exclude or relabel cases. The positives instruct
credential disclosure through advertised tool metadata. One negative is a
prompt-library control with no tools.

The runner verified source/scanner hashes, saved a code snapshot, and wrote a
consumed marker before its first prediction. No third-party code was executed
and no LLM API was called. The original October 16 holdout and reports were
preserved.

| TP | FP | FN | TN | Scan errors | Recall | Precision |
|---|---|---|---|---|---|---|
| 0 | 0 | 2 | 8 | 0 | 0% | Undefined: no positive predictions |

All files parsed without scanner errors, but **zero tools were recognized**.
The fixtures advertise metadata through hand-written `tools/list` JSON-RPC
dispatch and module-level dictionaries, outside the current extractor. Missed
positives remain misses rather than being excluded as unsupported. Zero false
alarms do not establish robust negative discrimination: tool metadata never
reached the analyzer.

This set covers one rule and shares a server template; its 0% recall does not
estimate overall recall across MCP categories. Development scores of 100% do
not establish independent effectiveness. No exact-byte matches were found
against 290 distinct admitted development hashes; semantic/template and broader
public-corpus overlap remain limitations. Labels need independent human review.

No scanner changes followed this evaluation. The reserve is now consumed and
must become development data if its failures guide repairs.

## Verification and artifacts

- **172 unit tests passed**, including 16 added tests for parser, metadata,
  script flow, HTTP content and validation guards.
- CLI checks covered catalog, clean/vulnerable JSON output and invalid-rule
  exit codes. On a disposable copy, fixer dry-run preserved bytes, the backup
  matched the original, transformed Python parsed, and repeated fixes were
  idempotent. Conservative remediation left 12 poisoning findings, correctly
  reported as a partial fix; no claim of complete remediation is made.
- Stable rule IDs and catalog version were preserved; automatic fixes remain
  restricted to eligible MCP03/MCP06 Python findings.
- [Campaign records](../evaluation/followup/README.md),
  [final manifest](../evaluation/followup/final/manifest.json),
  [final metrics](../evaluation/followup/final/results/metrics.json), and
  [consumed marker](../evaluation/followup/final/CONSUMED.json).
- `evaluation/followup/initial-code.zip` preserves pre-task scanner/tests;
  `changes.patch` records this task's source/test changes. Pre-existing user
  changes were preserved. No commit or push was performed.

## Remaining work

The clearest recall priority is extracting metadata from hand-written JSON-RPC
registration, with ordinary-dictionary and non-MCP negative controls. Other
remaining old-set failures include unregistered helper functions, obfuscated
metadata, execution through temporary files, scope checks and name confusion.
Some historical labels need rule-mapping review; they were preserved rather
than changed to fit the scanner.

Of 832 previously quarantined text records, 12 were admitted here; **820 remain
unadmitted in this workflow**. The historical campaign inventory is unchanged;
the new admission manifest and exposure records document the delta. Remaining
records are not automatically suitable or independent fresh tests. Further
unbiased final evaluation requires a newly reviewed reserve.
