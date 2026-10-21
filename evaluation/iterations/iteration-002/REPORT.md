# Iteration 002 — 16 October 2026

**Completed: improve command false positives on exposed development data,
freeze the candidate, evaluate a fresh source batch, and investigate its errors.**
Eight development false positives were removed without losing a previously
detected positive. Fresh validation exposed substantial recall gaps. The candidate
was not modified after fresh predictions were inspected. This is static rule
development, not model-weight training; LLM review was disabled and API calls were zero.

## Changes and development retest

The command-flow analyzer previously treated safe argument handling much like
unrestricted process execution. `mcp_scanner/command_safety.py` now checks a narrow
set of contextual protections before suppressing an MCP05 command finding:

- A fixed, recognized data-processing executable with an argv list and no shell.
- Whole-argument `shlex.quote` interpolation into restricted POSIX command shapes.
- A preceding, fail-closed full-match guard with a recognized restrictive regex.
- Integer or safe `Literal` parameters on a recognized FastMCP registration.
- A visible local wrapper that directly forwards the command without transformation.

Unknown bindings, unsafe quoting contexts, execution-capable programs, additional
positional options, executable overrides, and reassignment retain findings in
the focused tests. These checks concern command injection, not authorization,
path access, output safety, or all possible runtime monkeypatching. Typed negatives
assume FastMCP schema enforcement; quoted shell negatives assume POSIX behavior.

The same 13 iteration-001 files and 24 locked labels were retested. This is
development evidence, because their earlier errors motivated the changes.

| Measure | Iteration 001 final | Iteration 002 candidate |
| --- | ---: | ---: |
| True positives | 4 | 4 |
| False positives | 9 | 1 |
| False negatives | 4 | 4 |
| True negatives | 7 | 15 |
| Precision | 30.8% | 80.0% |
| Recall | 50.0% | 50.0% |
| False-positive rate | 56.3% | 6.3% |

All eight guarded-command false positives were removed. The ordinary-prerequisite
MCP03 false positive remains, as do the four previous misses. The retest is in
[iteration002-candidate](../iteration-001/runs/iteration002-candidate/metrics.json).

## Fresh data admission and freeze

The second proposed repository, `jaimenbell/mcp-security-scanner`, contained
**97 candidate files**. A bounded source review examined 24 standalone candidates:

- **18 files admitted**, with 27 rule/function labels: 14 positive and 13 negative.
- **6 excluded** because the application/HTTP helpers had no visible MCP registration.
- **73 deferred**, without source review or scanning in this iteration.

Labels cover three rules in **MCP01 and MCP05 only**. MCP02–MCP04 and MCP06–MCP16
have no scored fresh labels in this batch. Negative command labels on file
deletion cases mean “no command execution,” not “safe tool.” An upstream “clean”
tool that permits caller-selected executables is a positive under our command
rule, even when a deployment enablement gate exists. Labels were assigned from
source behavior before predictions; independent human adjudication is pending.

The code freeze precedes the label lock, which precedes the first scan. The
candidate fingerprint is
`2d2c7318d5fa1965490a83d1b27e4b29801c4050f9f962cf2f205653caf48b7d`.
[freeze.json](freeze.json), [label-lock.json](label-lock.json),
[manifest.json](manifest.json), and [admission.json](admission.json) record the
ordering, pinned upstream revision, hashes, rationales, and exclusions.
There are no exact-byte duplicates against iteration 001's admitted files or the
proposed MCP-DecayBench reserve. Semantic/template independence is not established.
Related examples are one source family, not independent incidents.

## Fresh results

| Rule | Positive labels | Negative labels | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| MCP01-SECRET-HARDCODED | 3 | 2 | 3 | 0 | 0 | 2 |
| MCP01-SECRET-OUTPUT | 5 | 2 | 0 | 0 | 5 | 2 |
| MCP05-COMMAND-INJECTION | 6 | 9 | 1 | 0 | 5 | 9 |
| **Total** | **14** | **13** | **4** | **0** | **10** | **13** |

All 18 artifacts parsed without errors; 20 tools were extracted. Seven low-level
SDK files had zero extracted tools because their declarations are held in module
lists. This is a coverage failure, not evidence that those files are safe.

On the locked labels, precision is **100% (4/4)**, recall **28.6% (4/14)**, and
false-positive rate **0% (0/13)**. Small denominators, related fixtures, narrow
category coverage, and assistant-reviewed labels prevent a broad performance
claim. Fresh scores must not be compared directly with development percentages
as if the cases were the same.

There were also three unscored findings. Two MCP10 environment-sharing findings
appear to be false positives: the functions return boolean checks, not whole
environments. The third is a plausible missing-audit finding. These post-hoc
assessments are recorded separately and do not alter locked labels or scores.
Therefore, **zero scored false positives does not mean zero false positives
across all scanner output**. See [posthoc_followups.json](posthoc_followups.json).

## Investigation and the next development cycle

The ten missed labels break down as follows:

| Gap | Missed labels | Required improvement |
| --- | ---: | --- |
| Imported command aliases | 4 | Resolve `subprocess as sp` and bare `from subprocess import run, call`, respecting scope and rebinding. |
| Low-level command dispatcher | 1 | Resolve static module tool lists and analyze linked dispatch branches and argument flow. |
| Secret output and logging | 5 | Track sensitive values into return dictionaries, aliases, helpers, and logging calls; two cases also need low-level dispatch support. |

The previous iteration's archived scanner was subsequently run against these
same labels as a retrospective regression check. It produced **identical scored
decisions: 4 TP, 0 FP, 10 FN, 13 TN**. These gaps therefore predate this candidate;
the reference run is not another independent validation experiment.
See [error_analysis.csv](error_analysis.csv) for each miss and
[comparison.json](comparison.json) for paired evidence.

For iteration 003, use these now-exposed cases as development data, add focused
positive and negative tests for the three gaps, and address the boolean
environment-check false positives. Preserve the existing quoting/argv/regex
controls. Freeze again before admitting the proposed `jspillers10` batch
(57 candidates, not yet 57 usable labelled tests). The 73 deferred files here
remain related development material and must not be advertised as an independent
new source batch.

## Verification and records

- **82 unit tests pass**, including 13 new command-protection test methods with
  positive, negative, bypass, and directory-scan controls. See [tests.txt](tests.txt).
- Three CLI checks confirm exit 0 for fixed argv and quoted arguments, and exit 1
  for the unprotected command. See [cli-checks.json](cli-checks.json).
- All **10 exposed primary targets** complete: **566 files, 398 tools, 104 findings**.
  Input hashes and full finding records are identical to iteration 001's final run.
  These unlabelled primary findings do not enter precision/recall.
- The final holdout remains unconsumed; its staging manifest hash is unchanged.
  No third-party fixture was imported or executed.
- [record-integrity.json](record-integrity.json) confirms the frozen code and labels
  remained unchanged. [changes.patch](changes.patch) is relative to iteration 001's
  archived final scanner, rather than the older Git HEAD.

The two completed batches have now exposed **31 distinct source files and 51
explicit labels**. These are reusable development cases, not a fresh test set
for subsequent tuning. [exposure.json](../exposure.json) is the current usage
ledger; acquisition-manifest `used_in_our_scanner` fields describe acquisition-time
status and are not updated usage counters.

To repeat the frozen candidate on the admitted files, use its archived scanner
and runner in an isolated checkout, restore the hash-verified snapshots, and run:

```powershell
python evaluation/scripts/run_iteration.py --manifest evaluation/iterations/iteration-002/manifest.json --run-id reproduction
```

Run IDs cannot be overwritten. Running current working code instead evaluates
that current code, which may differ from the archived candidate.
