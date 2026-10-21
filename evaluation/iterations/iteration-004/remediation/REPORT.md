# Iteration 004 repairs — development retest

**All 34 missed positives and all three additionally confirmed false positives
from iteration 4 are resolved on the reviewed cases.** The repaired scanner
scores 44 TP, 0 FN, 0 FP and 30 TN on 74 development labels across the same 46
Cisco files. This is a retest after examining the data, not a fresh validation
result or evidence of generalization.

| Same exposed cases | Before repairs | After repairs |
| --- | ---: | ---: |
| Positives detected | 10 / 44 | **44 / 44** |
| Positives missed | 34 / 44 | **0 / 44** |
| Negative controls falsely flagged | 3 / 30 | **0 / 30** |
| Negative controls correctly rejected | 27 / 30 | **30 / 30** |
| Recall | 22.7% | **100%** |
| Precision on these reviewed labels | 76.9% | **100%** |

The before/after table includes the three dictionary-lookup false alarms
adjudicated after the original scan. The original fresh test had only 71 locked
labels: 10 TP, 34 FN, 0 FP and 27 TN, with 100% scoped precision and 22.7% recall.
That original result, its labels, code snapshot and raw predictions remain
unchanged. Replaying the repaired predictions against only those original
labels gives 44 TP, 0 FN, 0 FP and 27 TN.

Fourteen other predictions remain outside the reviewed label set: eight audit
findings, three contextual-payload findings, two poisoning findings and one
authentication finding. They are not counted as correct alerts. Zero false
positives on these controls is not a claim of zero false alarms overall.

## Repairs

- Added bounded symbolic tracing through visible same-file functions and class
  methods, including return values, assignments, branches, loops and common HTTP
  clients. Source is parsed, never executed. Known calls retain caller provenance
  and a call path in finding evidence.
- Extended dynamic-code detection to helper-contained evaluation, unsafe
  deserialization and dynamic imports, including importlib loaders. Safe JSON
  and YAML parsers, shadowed functions and unrelated receivers have negative
  controls.
- Replaced broad network-method matching with imported client/constructor
  identification. Dictionary `.get()` is no longer treated as HTTP. Destination
  analysis separates caller-supplied request bodies from URL control and follows
  helper-contained requests and URL lists.
- Extended command-helper summaries through local assignments and preserved
  multiple contributing arguments. Schema-validated numeric parameters do not
  hide another unsafe string argument.
- Added focused role-impersonation and system-policy-bypass signatures, with
  ordinary administration, negated security instructions and quoted-example
  controls.
- Added report-only metadata/behavior checks for undisclosed tracking or training
  transfers, encoding advertised as AES-256 and renaming advertised as image
  compression. These are heuristic review findings, not proofs of intent or
  general semantic correctness.
- Enforced report-only status in the source transformer. A function with
  report-only poisoning evidence is not automatically rewritten. Fixer tests
  check dry-run, unchanged content, no unnecessary backup, repeated-run behavior
  and unresolved verification status; existing fixable-fixture tests still verify
  syntax, backups, idempotence and preservation of report-only categories.

## Regression checks

| Exposed batch | TP | FN | FP | TN | Change against pre-repair scanner |
| --- | ---: | ---: | ---: | ---: | --- |
| Batch 1 | 4 | 4 | 1 | 15 | Unchanged |
| Batch 2 | 14 | 0 | 0 | 13 | Unchanged |
| Batch 3 | 36 | 0 | 0 | 23 | Unchanged |
| Batch 4 plus post-test controls | 44 | 0 | 0 | 30 | 34 misses and 3 false alarms resolved |

**Batch 1 still has four missed positives and one false positive.** This repair
pass targets the confirmed iteration 4 error set; it does not eliminate every
known limitation of the scanner.

All **134 unit tests passed**, including 17 new repair test methods. Four CLI
checks cover dictionary lookup, helper-contained code execution, helper-contained
HTTP requests and honest base64 metadata. Tests include positive/negative cases
for import aliases, client constructors, shadowed classes, recursive helpers,
URL-authority suffix manipulation, privileged fixed hosts, request-body input,
multiple helper arguments and cross-file URL transformations.

The primary-corpus check completed on the same 10 targets, 566 files and 398
tools with identical input inventories. Findings changed from 99 to 100. The
additional finding is a separately located HTTP request in the official fetch
server's robots-check helper. A new false alarm in AWS documentation search was
investigated during development: the imported helper only appends a query
parameter to a fixed public URL. A bounded, uniquely linked source check now
establishes that origin preservation. Controls ensure a helper that replaces
the destination, or appends to an unclosed host authority, is still reported.
This primary corpus remains unlabelled; finding counts are not precision or
recall measurements.

## Limits and next step

All results here use exposed development data. The seven semantic-mismatch cases
still need independent human adjudication and are reported as review evidence.
Tracing is bounded by depth and work limits, skips unknown receiver bindings and
does not establish runtime reachability, authorization, dependency behavior or
all Python semantics. The wider MCP01–MCP16 catalog has not been comprehensively
validated by these samples.

Keep batches 1–4 as regression data. Address the remaining batch 1 cases and use
an independently admitted, untouched source family for the next fresh
development measurement. Do not interpret this 100% development recall as a
replacement for iteration 4's original 22.7% fresh recall. The final holdout
remains unconsumed and its manifest hash is unchanged.

## Records

Final scanner fingerprint:
`f2d201d1016452fa69ce0e33cf383a409929798104cd241dc75450d1edb16740`.

- [Development manifest](manifest.json): original 71 labels plus three explicit
  post-test negative controls; 74 labels total.
- [Repaired metrics](runs/repaired-final/metrics.json),
  [raw predictions](runs/repaired-final/predictions.jsonl),
  [exact scanner snapshot](runs/repaired-final/code_snapshot.zip).
- [Before/after comparisons](comparison.json),
  [all 37 resolved cases](resolved-cases.csv),
  [original-label-only retest](original-labels-after-repair.json).
- [134-test log](tests-final.txt), [CLI checks](cli-checks.json),
  [code delta](changes.patch), [record integrity](record-integrity.json).
- [Preserved original fresh report](../REPORT.md).

LLM review was disabled; zero model/API calls were made. No third-party source
was executed or installed. No commit or push was performed for these repairs.
