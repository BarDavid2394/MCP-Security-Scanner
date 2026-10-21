# Real-world MCP scanner evaluation

## Executive result

Catalog `2026.1` was evaluated against ten pinned targets from eight public
repositories. Third-party code was downloaded and statically read only: it was
not imported, installed, or executed.

The improved scanner processed 566 supported artifacts and reported 83 findings.
It recognized 398 tools. Finding-level review labeled 13 findings as credible
risky evidence, 32 as false positives, and 38 as deployment- or
context-dependent. Precision among conclusive labels was 28.9%; contextual
labels are deliberately excluded from that calculation.

These labels evaluate the evidence produced by the rule, not whether an entire
project is definitively vulnerable or safe.

## Corpus and reproducibility

`corpus-manifest.json` records every repository, full commit SHA, license, target
subdirectory, class, and expected capability. The corpus contains:

- Official Fetch, Git, and Time reference servers.
- Official Python SDK examples and Python weather quickstart.
- FastMCP framework examples.
- MCP Atlassian, Microsoft MarkItDown MCP, a community HTTP/FastMCP server, and
  the AWS Documentation MCP server.

The official server repository describes its implementations as educational
references rather than production-ready solutions:
https://github.com/modelcontextprotocol/servers

Acquisition is reproducible with `scripts/acquire.ps1`. Sparse checkouts are
detached at the manifest SHAs. Generated third-party source, results, and fixer
workspaces are ignored by Git.

## Aggregate scan results

| Measure | Result |
|---|---:|
| Targets | 10 |
| Public repositories | 8 |
| Supported artifacts scanned | 566 |
| Decorated tools independently inventoried | 379 |
| Tools reported by scanner | 398 |
| Low-level list/call handlers in official references | 6 |
| Explicit `Tool(...)` constructors inventoried | 58 |
| Findings | 83 |
| Fixable findings reported in real code | 0 |
| Parse errors | 0 |

Finding distribution: MCP07 37, MCP01 11, MCP10 9, MCP11 7, MCP04 6,
MCP06 6, MCP15 3, MCP08 2, MCP09 1, and MCP13 1. No findings were
reported for MCP02, MCP05, MCP12, MCP14, or MCP16 in this corpus.

The scanner/tool inventory difference is caused by its accepting bare `@tool`
decorators that the independent inventory intentionally counted only as
attribute decorators. It does not compensate for the low-level API gap below.

## Parser coverage

Decorator-based targets had full observed extraction coverage. The new low-level
adapter also extracts the official Fetch, Git, and Time servers' 1, 12, and 2
tools from `@server.list_tools()` and links them to `@server.call_tool()`
branches. Their metadata now receives MCP03 analysis, and linked implementations
are available to the structured evidence/data-flow layer.

The official Fetch source is also associated with a public SSRF report:
https://github.com/modelcontextprotocol/servers/issues/4143. The pinned current
source provides a valuable known-pattern test. The improved scanner now follows
`arguments -> args -> url -> fetch_url(destination)` and reports MCP13 for this
target. The issue is supporting evidence, not an independent confirmation by
this evaluation.

## Finding-level review

All 83 findings and their rationales are recorded in
`labels/finding-labels.csv`.

| Label | Count | Interpretation |
|---|---:|---|
| TP | 13 | The reported risky precursor is visibly present. |
| FP | 32 | Source review contradicts the detector's claim. |
| Needs context | 38 | Deployment or surrounding trust controls decide. |

The strongest useful evidence included unpinned executable dependencies, one
unpinned `uvx` MCP registration, two tools returning file content without an
explicit trust boundary, two sensitive file tools without visible audit
telemetry, and one broad unauthenticated bind example.

The most frequent remaining false-positive causes were:

1. Duplicate example tool names treated as confusable registrations when a
   framework's independent examples were scanned as one directory.
2. Fixed AWS API destinations reported as SSRF because a tool parameter appeared
   elsewhere in the HTTP call's enclosing function.
3. Cache constants and process state treated as cross-user model context.
4. File-local authentication heuristics losing middleware or multi-file context.

An analyzer refinement made after the baseline evaluation removed all 47 of the
findings caused by Python compatibility metadata, project `/main/` links, and
standalone benign MCP03 URLs/guidance. All removed findings had been labeled
false positives. Subsequent low-level parsing and destination-aware data flow
added the credible official Fetch SSRF evidence while removing fixed-origin AWS,
weather, and Atlassian SSRF warnings. Structural MCP09/MCP07 checks then removed
unsupported collisions across independent examples and client/helper auth
warnings. Finally, MCP03 runtime strings and benign file/URL documentation were
excluded unless primary poisoning evidence is present. Conclusive precision is
now 28.9%, with all controlled MCP03/MCP06 fixtures still detected.

## Controlled positives and negative

Three explicit fixtures use genuine FastMCP source structure:

- Clean arithmetic tool: zero findings.
- MCP03 mutation: MCP03 detected; four overlapping signatures were emitted for
  one poisoned docstring.
- MCP06 mutation: MCP06 detected, plus MCP13 for the tool-controlled URL.

This gives 100% detection for the two intentionally injected fixable categories
and zero findings on the controlled negative. It is a three-case functional
check, not a statistically meaningful general recall estimate.

## Fixer evaluation

The MCP03 and MCP06 fixtures were copied to the ignored `work/` directory. For
both categories:

- Dry run exited successfully and left bytes unchanged.
- Apply/verify exited successfully and changed the target.
- The result parsed as valid Python.
- A `.bak` file was created.
- A second application produced no further change.

No fixer was run against canonical corpus snapshots, and no report-only category
was modified.

## Recommendations

1. Make name-collision analysis aware of independent example/application roots.
2. Extend parameter-to-network-destination data flow with validation summaries
   and URL-component provenance across modules.
3. Analyze authentication and OAuth controls across modules/configuration before
   producing a high-confidence conclusion.
4. Preserve `Needs context` as a first-class report outcome rather than forcing
   heuristic evidence into vulnerability/clean language.

## Commands executed

```powershell
powershell -ExecutionPolicy Bypass -File evaluation/scripts/acquire.ps1
python evaluation/scripts/run_evaluation.py
python evaluation/scripts/triage_results.py
python -m unittest tests.test_scanner -v
python -m unittest tests.test_fixer -v
python -m unittest discover -v
```

All focused tests passed (7 scanner and 2 fixer tests), followed by all 9 tests
passing under discovery.
