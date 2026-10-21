# Iteration 5: recorded development experiment

Public metadata: 22 exposed pilot records plus 56 additional related records.

| Run | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| Baseline | 2 | 2 | 46 | 28 | 50.0% | 4.2% |
| Repaired, same cases | 45 | 0 | 3 | 30 | 100.0% | 93.8% |

Changes: Compound instruction overrides, bounded Unicode/spacing/leet normalization, credential directives, and local masking of quoted research examples. New semantic signals are report-only.

Labels were locked in `evaluation/campaign/schedule.json` before campaign detector changes. Assistant semantic review is not independent human adjudication. Unlabelled outcomes are unknown. After-repair scores are exposed development results, not fresh validation. Initial unscored predictions: 0; repaired: 0. Scan errors: 0 before / 0 after.

See `error_analysis.csv` for resolved and remaining failures, `tests-final.txt` for the unit suite, and `runs/` for exact predictions, labels, scanner archives, hashes, and timestamps. The earlier batches were rerun before proceeding; their scoped scores did not regress.
