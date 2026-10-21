# Recorded development iterations

These are rule-development experiments, not model-weight training or final
holdout results. Sources are statically parsed and never executed. The optional
LLM reviewer is disabled in iterations 001–004.

| Iteration | Status | Evidence |
| --- | --- | --- |
| [001](iteration-001/REPORT.md) | Completed baseline, investigation, focused fixes and paired retest | 13 admitted files, 24 rule/function labels; 10-target primary-corpus check |
| [002](iteration-002/REPORT.md) | Completed command false-positive fixes, frozen fresh validation and error investigation | 8 development false positives removed; fresh 18 files / 27 labels: 4 TP, 0 FP, 10 FN, 13 TN |
| [003](iteration-003/REPORT.md) | Completed iteration-002 failure fixes, frozen fresh batch and paired reference comparison | Fresh 34 files / 59 labels: 24 TP, 3 FP, 12 FN, 20 TN; one additional fresh detection versus archived iteration 002 |
| [004](iteration-004/REPORT.md) | Frozen Cisco validation followed by [user-requested repairs](iteration-004/remediation/REPORT.md) | Fresh: 10 TP, 0 FP, 34 FN, 27 TN (22.7% recall). Exposed development retest: 44 TP, 0 FP, 0 FN, 30 TN including 3 post-test controls; 134 tests pass |
| [005](iteration-005/REPORT.md) | Adapted public metadata development | 78 labels: baseline 2 TP / 2 FP / 46 FN / 28 TN; repaired 45 / 0 / 3 / 30 |
| [006](iteration-006/REPORT.md) | Synthetic paired source behavior development | 24 labels: baseline 8 TP / 2 FP / 4 FN / 10 TN; repaired 12 / 0 / 0 / 12 |
| [007](iteration-007/REPORT.md) | Adapted Vault source-family validation, then repairs | 20 labels: baseline 2 TP / 0 FP / 8 FN / 10 TN; repaired 9 / 0 / 1 / 10 |
| [008](../../deliverables/Followup_Validation_Report.md) | Consumed-final development and registration repair | Final candidate: 16 TP / 0 FP / 14 FN / 20 TN versus initial 13 / 1 / 17 / 19 |
| [009](../../deliverables/Followup_Validation_Report.md) | 12 newly admitted related-family Vault metadata records | 2 TP / 0 FP / 4 FN / 6 TN to 6 / 0 / 0 / 6 |
| [010](../../deliverables/Followup_Validation_Report.md) | Six paired synthetic source families and flow repairs | 4 TP / 4 FP / 2 FN / 2 TN to 6 / 0 / 0 / 6 |

The subsequent ten-file MCP-DecayBench reserve was consumed on 17 October:
0 TP, 0 FP, 2 FN, 8 TN. Zero tools were recognized in its hand-written JSON-RPC
servers. See the follow-up report for limits; this is separate from the earlier
33-artifact final evaluation below.

The subsequent [final validation report](../../deliverables/Final_Validation_Report.md)
records the one-shot reserved evaluation: 13 TP, 1 FP, 17 FN, 19 TN;
92.9% scoped precision and 43.3% recall. The final reserve is now consumed.
Its original staging manifest is retained as historical input, not an available
fresh test set. The optional LLM reviewer remained disabled in rounds 005–007
and final validation.

Each iteration records admission decisions and labels before the first scan.
Labels can be positive or negative for a specific rule and optional function;
unlabeled outcomes are unknown. A failed scan is an error, not a clean result.
The first labels are assistant-reviewed and need independent human adjudication.

Run a new, uniquely named evaluation from the repository root:

```powershell
python evaluation/scripts/run_iteration.py --manifest evaluation/iterations/iteration-001/manifest.json --run-id another-development-run --primary
```

The runner refuses to overwrite an existing run. It verifies source hashes,
records the Git revision and actual working-code hashes, saves a ZIP of the
scanner and runner, and stores raw predictions, scoped metrics, and completion
metadata. `--primary` additionally scans only the previously exposed primary
corpus. Its unlabelled findings do not enter precision/recall denominators.

Restore pinned local source snapshots from the acquisition manifests before
reproducing this on another checkout. For historical reproduction, use the
scanner and runner saved in that run's `code_snapshot.zip` in an isolated
checkout; running today's code with an old manifest evaluates today's code.
No third-party target code needs to be installed or imported.

Once a batch has been investigated, it is development/regression data. Keep
related sources and variants together; use an admitted, untouched source group
for fresh validation of a later frozen candidate. Do not route final holdout
data through this development runner. The holdout lifecycle is separate; check
`evaluation/holdout/CONSUMED.json` before making any availability claim.
