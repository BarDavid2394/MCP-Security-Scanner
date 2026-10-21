# Iteration 001 — 16 October 2026

**Completed one development iteration: baseline, error investigation, three
focused fixes, and a paired retest.** Detection improved modestly; false positives
remain a substantial weakness. The final holdout and later source batches were
not scanned. No model weights were trained and no LLM/API calls were made.

## Data and label review

The proposed first group contained 25 Python fixtures from
`akanthed/SecureAI-Scan`, pinned at
`f1f2b423b3a67127295c5aeba3016d5e0f352d0c`. Before obtaining predictions, source
review admitted **13 files** and excluded **12 generic AI/vector/application
fixtures** without an MCP path. Excluded cases are not counted as negatives.
See [admission.csv](admission.csv) and [manifest.json](manifest.json).

The admitted set has **24 explicit rule/function labels: 8 positive and 16
negative**, covering selected rules in MCP01, MCP03, MCP05, MCP06 and MCP13.
These labels are assistant-reviewed; independent human adjudication is pending.
This is one source family with related fixtures, not 24 independent incidents.

One upstream “safe” fixture filters non-printable characters from an external
message. Ordinary malicious instructions survive that transformation, so its
MCP06 label here is **positive**. Negative labels are scoped: a shell-guarded
tool can still lack audit logging. Typed-input negatives assume FastMCP enforces
its int/Literal schemas; fixed-host SSRF controls do not model upstream redirects.

## Paired results

| Metric | Before | After stability fixes | After all fixes |
| --- | ---: | ---: | ---: |
| True positives | 3 | 3 | 4 |
| False positives | 9 | 9 | 9 |
| False negatives | 5 | 5 | 4 |
| True negatives | 7 | 7 | 7 |
| Precision | 25.0% | 25.0% | 30.8% |
| Recall on labeled positives | 37.5% | 37.5% | 50.0% |
| False-positive rate on labeled negatives | 56.3% | 56.3% | 56.3% |
| Failed labeled-case scans | 0 | 0 | 0 |

Scores use one artifact/rule/function decision, not the number of warning
messages. Repeated findings do not create extra true positives. Fifteen
incidental finding instances outside the reviewed scopes remain unscored, not
automatic false positives. The after results reuse inspected development cases;
they do **not** demonstrate unseen-data generalization.

### After results by category

| Category | Positive labels | Negative labels | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| MCP01 | 0 | 1 | 0 | 0 | 0 | 1 |
| MCP03 | 3 | 3 | 2 | 1 | 1 | 2 |
| MCP05 | 3 | 9 | 2 | 8 | 1 | 1 |
| MCP06 | 2 | 1 | 0 | 0 | 2 | 1 |
| MCP13 | 0 | 2 | 0 | 0 | 0 | 2 |

All other categories have **no scored labels in this batch**. MCP01/MCP13 recall
is unavailable because there are no positives. Tiny negative samples with zero
false positives are not evidence of a zero population false-positive rate.

## Changes and investigations

Hypotheses were written before editing production code in
[HYPOTHESES.md](HYPOTHESES.md). All 14 baseline FP/FN decisions have an individual
root-cause assessment and next action in [error_analysis.csv](error_analysis.csv).

1. **Fixed an AST crash.** Annotation-only declarations such as `color: str`
   have no assigned value. Command-flow analysis now skips those declarations,
   preserving existing taint and continuing to inspect later commands.
2. **Excluded generated scanner caches.** Discovery no longer treats
   `.mcp-scanner-cache` contents as project input. Real adjacent configurations
   remain scanned. Sixteen generated files were excluded across the primary
   corpus, including six in the previously completed Atlassian target.
3. **Fixed singular-only exfiltration wording.** The existing signature now
   accepts `contents`, `results` and `outputs`, retaining its transmission-verb
   and `to/via` requirements. This detects the previously missed credential
   exfiltration description. Stable rule IDs and fixer implementation are unchanged.

The stability-only intermediate run left all 24 decisions unchanged. The noun
change converted one FN to TP; no other reviewed decision changed. This is a
narrow improvement, not a solution to the remaining false positives.

## Primary-corpus and regression verification

The already exposed primary corpus provides a separate operational check:

| Measurement | Before | After |
| --- | ---: | ---: |
| Targets completed | 9 / 10 | 10 / 10 |
| Files scanned on completed targets | 431 | 566 |
| Tools analyzed on completed targets | 242 | 398 |
| Findings on completed targets | 71 | 104 |

FastMCP now completes with 141 files and 33 findings. **Those 33 additional
findings come from restored scan coverage, not 33 proven vulnerabilities.**
All nine targets that completed both times have identical findings. Shared
input-file hashes are unchanged; the discovery difference is the generated
cache exclusion. These operational counts are not a new precision/recall study.

- Existing full suite before changes: **59 passed**.
- Focused changed-behavior and scoring checks: **54 passed**.
- Full suite after changes: **69 passed**.
- CLI checks: clean fixture exits **0**, vulnerable fixture exits **1**.
- The scorer's tests verify failed scans are not TN, unknown predictions are
  not FP, and function scoping/deduplication preserves denominators.
- Code/manifest fingerprints were stable during each run. The reserved holdout
  manifest is unchanged and no freeze/consume lifecycle step was invoked.

## Decision and next iteration

Keep these narrow fixes as the next development baseline. This iteration is
complete, but the scanner is not ready for a strong all-category performance
claim. **Nine false positives and four false negatives remain in this batch.**

Prioritize MCP05 protection evidence next: fixed executable/argument lists,
quoting context, anchored fail-closed regex guards, and trusted typed inputs.
Avoid blanket suppression of subprocess calls or any function named `sanitize`.
Also queued: ordinary sibling-tool prerequisites, low-level Python dispatch,
HTTP response aliases, and unquoted cross-tool redirection.

Use this batch for development and regression from now on. Review/admit the next
source group before scanning it; freeze the next candidate before obtaining its
fresh validation results. Continue preserving the final holdout.

## Reproducibility

- [Comparison](comparison.json): paired metrics, primary input changes and
  identical-finding checks.
- [Before](runs/before/config.json), [stability](runs/stability/config.json),
  [after](runs/after/config.json): Git base plus actual code fingerprints.
- Each run includes `manifest.json`, `code_snapshot.zip`, `predictions.jsonl`,
  `metrics.json` and `completion.json`. Before/after also include primary-corpus
  input hashes and raw results.
- [Production patch](changes.patch), [tests before](tests-before.txt),
  [tests after](tests-after.txt), and [CLI checks](cli-checks.json).

The code changes are in the working tree; the recorded Git base alone is not
the after version. The saved code snapshots and hashes identify each version.
