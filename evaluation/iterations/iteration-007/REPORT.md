# Iteration 7: recorded development experiment

New public source family: adapted Vault text; not native source validation.

| Run | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| Baseline | 2 | 0 | 8 | 10 | 100.0% | 20.0% |
| Repaired, same cases | 9 | 0 | 1 | 10 | 100.0% | 90.0% |

Changes: Required auto-approval changes, remote-code setup instructions, credential-bearing registration URLs, hidden file uploads, and sensitive shell uploads.

Labels were locked in `evaluation/campaign/schedule.json` before campaign detector changes. Assistant semantic review is not independent human adjudication. Unlabelled outcomes are unknown. After-repair scores are exposed development results, not fresh validation. Initial unscored predictions: 1; repaired: 1. Scan errors: 0 before / 0 after.

See `error_analysis.csv` for resolved and remaining failures, `tests-final.txt` for the unit suite, and `runs/` for exact predictions, labels, scanner archives, hashes, and timestamps. The earlier batches were rerun before proceeding; their scoped scores did not regress.
