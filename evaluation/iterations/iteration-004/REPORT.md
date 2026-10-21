# Iteration 004 — fresh validation and development results

**Subsequent user-requested repairs:** see the separate
[development retest report](remediation/REPORT.md). It resolves the 34 misses and
three post-test false alarms on exposed cases. The fresh results below remain
the original frozen measurement.

**Fresh Cisco batch: 10 true positives, 34 false negatives, 0 false positives and
27 true negatives on 71 labels locked before testing. Recall is 22.7% and the
miss rate is 77.3%. This is poor detection coverage.** The archived iteration 003
scanner produces exactly the same scored decisions on these cases: there is no
measured fresh-batch improvement.

Precision is `TP / (TP + FP) = 10 / 10 = 100%` **only on the locked labels**.
Recall is `TP / (TP + FN) = 10 / 44 = 22.7%`. Missed vulnerabilities reduce recall,
not precision. This does not mean 100% accuracy, overall safety, or absence of
false alarms. Investigation of 16 unscored findings identified **three additional
false positives**: dictionary `.get()` calls mistaken for HTTP requests. Thirteen
other findings remain unadjudicated. These post-test judgments are saved
separately and do not retroactively change the preregistered score.

This is static scanner development, not model-weight training. LLM review was
disabled; zero model/API calls were made. Third-party code was read and parsed
as inert text, never executed, imported or installed.

## Fresh data and results

Source: `cisco-ai-defense/mcp-scanner`, pinned revision
`5d147dc7e3635606e41104112fa297b45444b05c`.

| Candidate disposition | Files |
| --- | ---: |
| Proposed Cisco batch, structurally inventoried | 145 |
| Source-reviewed, admitted and scanned | **46** |
| Excluded after source review | 15 |
| Deferred after structural inventory | 84 |

The 46 files contain **44 positive and 27 negative labels**, covering seven rules
in five categories. All scans completed without parse errors; 512 tools were
extracted. Many tools are response stubs in a few large files. Neither 512 tools
nor 71 labels represents that many independent real-world vulnerabilities.

| Category / rule | Positive labels | Negative labels | TP | FN | FP | TN | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| MCP01 hardcoded credentials | 0 | 1 | 0 | 0 | 0 | 1 | Not measured |
| MCP03 tool poisoning / deceptive metadata | 15 | 4 | 1 | 14 | 0 | 4 | 6.7% |
| MCP05 command execution | 7 | 6 | 6 | 1 | 0 | 6 | 85.7% |
| MCP05 dynamic code | 9 | 5 | 0 | 9 | 0 | 5 | 0% |
| MCP07 missing network authentication | 3 | 1 | 3 | 0 | 0 | 1 | 100% |
| MCP13 SSRF | 10 | 10 | 0 | 10 | 0 | 10 | 0% |
| **Total** | **44** | **27** | **10** | **34** | **0** | **27** | **22.7%** |

MCP02, MCP04, MCP06, MCP08–MCP12 and MCP14–MCP16 have **no locked labels in this
batch**. Findings outside the scored rules/functions are not automatically true
or false positives. MCP01 has no positive cases here, so its detection ability
was not tested by this fresh batch.

Seven MCP03 positives test materially deceptive description/implementation
mismatches, extending beyond explicit malicious instructions. All seven were
missed. The explicit metadata-instruction stratum detected 1 of 8 positives.
Excluding the seven semantic-mismatch cases gives 10 TP, 27 FN, 0 FP and 27 TN:
**27.0% recall**, still poor. This distinction is recorded in
[comparison.json](comparison.json) so the broader semantic interpretation is
visible rather than hidden in an aggregate.

## Label decisions and limits

Labels follow visible behavior, not upstream filenames. The network-diagnostic
example restricts hostnames and uses schema-validated numeric options; it is a
command-injection negative under those stated assumptions. Three functions in
the nominally malicious remote server merely return dictionaries or lengths:
they are negative controls for command execution, dynamic code and SSRF.
Conversely, three benign remote-tool files expose unauthenticated SSE services
on all interfaces and are positive for missing authentication.

Resource-exhaustion cases have no dedicated rule in this catalog and were not
relabeled as MCP16. The Unix-socket example lacks the HTTP transport adapter
needed for its intended request path. Ambiguous configuration descriptions and
three cases needing a clearer consent/threat model were excluded. The remaining
84 candidates require detailed adjudication; they were not evaluated. The whole
Cisco family now needs leakage review before any future independent split.

All labels are assistant-adjudicated and still need independent human review.
The cases are synthetic, heavily related within upstream templates and selected
for reviewable rule mappings. They do not estimate deployment prevalence or
population performance. Runtime compatibility and exploitation were not tested.
No exact-byte or comment/docstring-independent exact AST duplicates were found
against admitted batches 1–3; semantic duplicates remain possible.

## What was improved before this fresh test

Iteration 3's 12 misses and 3 false positives were used for development. Changes
include AST credential-literal checks, bounded static metadata evaluation,
programmatic FastMCP registration, literal-selected command sinks, stronger
allowlist guard analysis and narrow safe-command proofs. Encoded metadata is
inspected without executing it. An invisible Unicode character now needs a
behavioral payload to count as poisoning. Derived/decoded metadata findings are
marked report-only. An older conversation-disclosure regression discovered
during development was corrected before freezing.

| Exposed development batch | Before this iteration: TP / FP / FN / TN | Final retest: TP / FP / FN / TN |
| --- | --- | --- |
| Batch 1, 13 files / 24 labels | 4 / 1 / 4 / 15 | 4 / 1 / 4 / 15 |
| Batch 2, 18 files / 27 labels | 14 / 0 / 0 / 13 | 14 / 0 / 0 / 13 |
| Batch 3, 34 files / 59 labels | 24 / 3 / 12 / 20 | **36 / 0 / 0 / 23** |

These are repeated development tests, not fresh validation. Batch 3's perfect
retest does not demonstrate generalization, as the fresh Cisco result shows.
Batch 1 still has four missed positives and one false positive.

The already exposed primary corpus was also checked: 10 targets, identical input
inventories, 566 files, 398 tools. Findings increased from 94 to 99: four demo
credential literals and one nested tool's caller-controlled URL. These are
reviewable heuristic additions, not verified production credential leaks. This
unlabelled corpus has no precision/recall score.

Verification: **117 unit tests pass**, including 17 iteration-four regression
test methods with positive and negative controls. Four CLI checks verify sink
detection, benign Unicode handling, conversation-disclosure detection and secret
redaction. Clean-sample scanning and fixer dry-run also completed successfully.
The exact production delta against the iteration 3 archive is in
[changes.patch](changes.patch).

## Investigation and next development work

The 34 misses are recorded individually in [error_analysis.csv](error_analysis.csv):

1. **Nine dynamic-code misses:** execution, unsafe deserialization and dynamic
   imports occur inside class helpers. The current rule looks for direct
   tool-body evaluation rather than following these calls.
2. **Ten SSRF misses:** requests occur behind class helpers, URL construction
   and URL-list iteration. Privileged fixed destinations also need explicit
   modeling.
3. **Seven explicit metadata misses:** role impersonation and system/safety
   directives use wording outside the current narrow signatures.
4. **Seven semantic mismatch misses:** the lexical heuristic cannot establish
   false functionality claims or track hidden behavior through helpers.
5. **One command miss:** the helper summary does not propagate caller values
   through local assignments and branches before `os.system(cmd)`.

Separately, **three confirmed post-test false positives** arise from
`searcher.LOG_PATHS.get`, `rm.ROLES.get` and `validation_levels.get`. The HTTP
heuristic currently treats any `.get()` as a possible network method without
establishing receiver identity. See
[posthoc-investigation.json](posthoc-investigation.json). Resolve HTTP receiver
bindings first, then extend bounded helper analysis for dynamic execution and
network destinations with matching clean controls. Keep semantic metadata tests
separate and independently reviewed. No fixes were made after viewing fresh
batch 4 predictions.

## Reproducibility and remaining data

Frozen scanner fingerprint:
`3103680048ee4176254a5abf2a99b1b5ca49c21e146938fa816246c57ff82df5`.
Code was frozen before Cisco source review; the 71 labels were locked before the
first prediction. The archived iteration 3 scanner was then evaluated against
the same locked labels for a retrospective paired comparison. That comparison
is not another independent batch.

- [Admission decisions](admission.json), [source/label manifest](manifest.json),
  [code freeze](freeze.json), [label lock](label-lock.json).
- [Fresh metrics](runs/frozen-validation/metrics.json),
  [raw predictions](runs/frozen-validation/predictions.jsonl),
  [exact scanner snapshot](runs/frozen-validation/code_snapshot.zip).
- [Archived iteration 3 comparison](runs/reference-iteration003/metrics.json),
  [paired and development comparisons](comparison.json).
- [Test log](tests-final.txt), [CLI checks](cli-checks.json),
  [record integrity](record-integrity.json),
  [unscored findings](unscored-summary.json).

Across batches 1–4, **111 unique admitted files and 181 locked labels** have now
been used. Keep all of them as development/regression data. Do not mix them into
the final holdout or report another pass over them as fresh testing.

The final staging holdout remains unconsumed: 33 artifacts / 50 labels, with
unchanged manifest hash
`2a2d41a117e52952d9823f369abde6c948275bdd90b4cbcf3d237bfe5c12ef52`.
The separate ten-file MCP-DecayBench candidate reserve was also not scanned;
candidate count is not an admitted or guaranteed usable test set. The planned
fresh development groups are now exhausted. Further repair/retest cycles can
use exposed data, but a new independent development validation requires another
admitted, untouched source family. Fix and review the demonstrated gaps before
consuming the final holdout.

Changes and records are local; no commit or push was performed for this iteration.
