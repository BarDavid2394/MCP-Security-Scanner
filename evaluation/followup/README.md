# Completed follow-up campaign

Completed 17 October 2026. See the [report](../../deliverables/Followup_Validation_Report.md).

- `schedule.json`: development order and reserve policy.
- `initial-git-status.txt`, `initial-code.zip`: preserved pre-task state.
- `reference-regressions.json`, `working-regressions.json`: predictions and
  scoped metrics from initial and final code on rounds 001–010.
- `comparison.json`: changed label outcomes; none in rounds 001–007.
- `tests-final.txt`, `cli-checks.json`: 172 passing tests and CLI/fixer checks.
- `changes.patch`: session-only source/test changes against the baseline.
- `final/`: code/manifest locks, overlap audit, code snapshot, predictions,
  metrics and consumed marker.

The final reserve is **consumed**. Its two MCP03 positives were missed because
hand-written JSON-RPC tools were not extracted. Zero tools were recognized
in all ten fixtures. No detector tuning followed the final result.

Reproduce development with a new run ID:

```powershell
python evaluation/scripts/run_iteration.py --manifest evaluation/iterations/iteration-008/manifest.json --run-id my-development-retest
```

Historical results require their saved scanner version. Do not rerun final
data as an untouched test or overwrite the original holdout state.
