# Iteration 003 — fresh batch results, 16 October 2026

**Fresh batch 3: 24 true positives, 3 false positives, 12 false negatives and
20 true negatives. Precision 88.9%; recall 66.7%; false-positive rate 13.0%.**
The same cases scored 23 TP, 3 FP, 13 FN and 20 TN with iteration 002's archived
scanner. This is one additional correct detection on fresh data, with no new
scored regressions. Development improvements were larger and are reported
separately below.

This iteration is static scanner rule development, not model-weight training.
LLM review was disabled; no model/API calls were made. Third-party source was
parsed as inert text, never imported, installed, or executed.

## Fresh source and admission

Source: `jspillers10/mcp-security-scanner`, pinned revision
`9bfc641ec37607025b2dae63d0f96cb7b85dbc92`.

| Candidate disposition | Files |
| --- | ---: |
| Proposed batch | 57 |
| Source reviewed | 43 |
| Admitted and scanned | **34** |
| Excluded after review | 9 |
| Deferred grouped/multi-file cases | 14 |

The admitted files have **59 locked labels: 36 positive and 23 negative**,
covering selected rules in MCP01, MCP03, MCP05 and MCP07. All 34 parsed without
errors; 64 tools were extracted. Each label is an artifact/rule and optional
function judgment, not a distinct independent real-world vulnerability.

Code was frozen before batch 3 source review, labels were locked before its
first scan, and neither changed after fresh predictions. See
[freeze.json](freeze.json), [label-lock.json](label-lock.json),
[manifest.json](manifest.json), and [admission.json](admission.json).
Frozen code fingerprint:
`aec4f0a007bff15a9a18777403b9a9d9e2ae98679bc2087853fa0e114a1f7bc8`.

Source behavior overrides upstream filenames. For example, importing an unused
authentication helper does not protect a transport, while a visible helper that
returns a fixed allowlist can protect a command despite its upstream vulnerable
label. An isolated zero-width marker without a behavioral payload is labelled
negative for poisoning. Those judgments and their assumptions are explicit in
the manifest and require independent human adjudication.

Excluded cases include unsupported path/SQL rules, a simulated remote-data stub,
an uncalled runtime metadata mutation, and authentication placeholders whose
effective enforcement cannot be established. They are not scored as clean.
There are no exact-byte duplicates against batches 1/2's admitted files or the
proposed MCP-DecayBench reserve. Semantic duplication and dependence among
related templates remain possible.

## Fresh results by category

| Category | Positive labels | Negative labels | TP | FP | FN | TN | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| MCP01 — secrets | 3 | 4 | 0 | 0 | 3 | 4 | 0.0% |
| MCP03 — tool metadata poisoning | 6 | 7 | 2 | 1 | 4 | 6 | 33.3% |
| MCP05 — command/code execution | 21 | 10 | 16 | 2 | 5 | 8 | 76.2% |
| MCP07 — missing authentication | 6 | 2 | 6 | 0 | 0 | 2 | 100.0% |
| **Total** | **36** | **23** | **24** | **3** | **12** | **20** | **66.7%** |

The MCP05 subtotal includes command injection (11 TP, 2 FP, 5 FN, 6 TN) and
dynamic Python evaluation (5 TP, 0 FP, 0 FN, 2 TN). MCP01 contains three missed
hardcoded-credential cases, two hardcoded negatives, and two output-secret
negatives. **There are no fresh positive output-secret or low-level dispatcher
labels in this batch**, so their development gains are not independently
validated here. Authentication negatives are stdio scope controls, not successful
authentication on a protected network server.

MCP02, MCP04, MCP06 and MCP08–MCP16 have no scored fresh labels in this batch.
Scores cannot establish performance across all 16 categories. There are also
**48 unscored predictions**: 30 MCP08 audit, 15 MCP06 context, and one each under
MCP03 poisoning, MCP05 command injection and MCP07 permissive bind. They have
not been independently adjudicated and do not enter TP/FP denominators. See
[unscored-summary.json](unscored-summary.json).

## Paired comparison on these same fresh cases

After recording fresh predictions, the archived iteration-002 scanner was run
retrospectively against the same locked labels. This is a regression comparison,
not another independent experiment.

| Measure | Iteration 002 archived scanner | Iteration 003 frozen scanner |
| --- | ---: | ---: |
| True positives | 23 | **24** |
| False positives | 3 | 3 |
| False negatives | 13 | **12** |
| True negatives | 20 | 20 |
| Precision | 88.5% | **88.9%** |
| Recall | 63.9% | **66.7%** |
| False-positive rate | 13.0% | 13.0% |

The changed decision is `aliased_dangerous_function.py`: `from os import system
as invoke` is now resolved, and `run_task` is detected. All other locked-label
decisions are identical. Do not compare batch 2's original 28.6% recall directly
with batch 3's 66.7% as a causal gain: those are different cases and label mixes.

## Development fixes and retests

The iteration-002 errors motivated these changes before the freeze:

- Resolve module and direct import aliases with local shadowing/rebinding checks.
- Resolve literal module tool lists and link low-level dispatch branches by
  server receiver, excluding sibling branches from a tool's implementation.
- Track credential provenance through tool return containers, local aliases,
  bounded helpers and logging calls, keeping finding evidence redacted.
- Replace environment-dump text matching with return-value analysis so boolean
  guards and credential-presence indicators do not look like environment dumps.

The first development candidate also exposed false alarms on ordinary storage
keys, word tokens, HTTP status codes and credential-field names in the primary
corpus. These were corrected before batch 3 source review; both intermediate
and final development runs are preserved.

| Iteration-002 exposed labels | Before this iteration | After fixes |
| --- | ---: | ---: |
| TP | 4 | **14** |
| FP | 0 | 0 |
| FN | 10 | **0** |
| TN | 13 | 13 |
| Precision | 100.0% | 100.0% |
| Recall | 28.6% | **100.0%** |
| False-positive rate | 0.0% | 0.0% |

Both separately recorded MCP10 boolean-environment false alarms were removed.
The original iteration-001 locked labels remain 4 TP, 1 FP, 4 FN and 15 TN;
their remaining metadata, prompt-context and undeclared low-level-tool cases
were not addressed by this iteration's targeted fixes.

## Investigation and next fixes

All 15 fresh scored errors are recorded in [error_analysis.csv](error_analysis.csv).

| Failure class | Count | Investigation / proposed next fix |
| --- | ---: | --- |
| Missed hardcoded credentials | 3 | Prefixed names, multiline text and quoted nested dictionary keys need AST-aware literal checks, with placeholder/hash/documentation negatives. |
| Missed metadata poisoning | 4 | Local description factory, encoded routing, cross-tool redirection and priority wording exceed current extraction/signature coverage. |
| Missed command execution | 5 | Literal `getattr` sink selection, programmatic `add_tool`, caller-controlled allowlists and guards that do not block every unsafe path need stronger analysis. |
| Command false positives | 2 | Safe nslookup argv and a fixed-origin git helper exceed the narrow protection proofs. |
| Metadata false positive | 1 | A zero-width marker is treated as poisoning despite lacking a behavioral payload. |

For iteration 004, use these now-exposed failures as development cases, add
focused bypass and negative controls, and freeze again before admitting the
proposed Cisco batch (145 candidates, not 145 validated labelled examples).
Do not tune on batch 3 and continue describing it as fresh. Its deferred related
variants also require leakage review before an independent split.

## Verification and reproduction

- **100 unit tests pass**, including 18 new focused methods. See
  [tests-final.txt](tests-final.txt). The parser test now checks the isolated
  function representation, replacing its earlier whole-branch-text assumption.
- **Five CLI checks pass**: imported command alias, safe argv, secret return,
  boolean environment guard and low-level command dispatch. See
  [cli-checks.json](cli-checks.json).
- All **10 exposed primary targets complete**, with identical input hashes:
  **566 files and 398 tools**. Findings change from 104 to 94; ten previous
  text-pattern findings disappear and no new findings appear in the final
  candidate. These are unlabelled regression observations, not ten independently
  adjudicated true fixes. Full additions/removals are in [comparison.json](comparison.json).
- The final holdout is unconsumed; its staging manifest hash is unchanged.
- [record-integrity.json](record-integrity.json) verifies the frozen scanner,
  unchanged labels, ordering, CLI checks and paired fresh comparison.
- [changes.patch](changes.patch) records production changes relative to iteration
  002's archived scanner and associated tests.

Across three batches, **65 distinct source files and 110 explicit labels** have
now been exposed. They are development/regression material for later cycles.
[exposure.json](../exposure.json) is the current usage ledger; acquisition-time
`used_in_our_scanner` fields are historical metadata.

Raw fresh evidence: [metrics](runs/frozen-validation/metrics.json),
[predictions](runs/frozen-validation/predictions.jsonl),
[code archive](runs/frozen-validation/code_snapshot.zip), and
[reference metrics](runs/reference-iteration002/metrics.json).
Restore the hash-verified snapshots and use the archived scanner/runner in an
isolated checkout for reproduction:

```powershell
python evaluation/scripts/run_iteration.py --manifest evaluation/iterations/iteration-003/manifest.json --run-id reproduction
```

The runner refuses to overwrite a run. Using working code instead evaluates
that current version, which may differ from the frozen archive.
