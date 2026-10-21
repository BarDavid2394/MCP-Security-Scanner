# Iteration 6: recorded development experiment

Synthetic paired source behaviors: exposed pilot; six families, two structural variants.

| Run | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| Baseline | 8 | 2 | 4 | 10 | 80.0% | 66.7% |
| Repaired, same cases | 12 | 0 | 0 | 12 | 100.0% | 100.0% |

Changes: Prefixed environment credential provenance, safe presence-only outputs, pathlib content through helpers, and fixed-format printf argument-list safety.

Labels were locked in `evaluation/campaign/schedule.json` before campaign detector changes. Assistant semantic review is not independent human adjudication. Unlabelled outcomes are unknown. After-repair scores are exposed development results, not fresh validation. Initial unscored predictions: 9; repaired: 8. Scan errors: 0 before / 0 after.

See `error_analysis.csv` for resolved and remaining failures, `tests-final.txt` for the unit suite, and `runs/` for exact predictions, labels, scanner archives, hashes, and timestamps. The earlier batches were rerun before proceeding; their scoped scores did not regress.
