# Real-world MCP scanner evaluation

This directory contains the reproducible metadata, scripts, labels, and reports
for evaluating the scanner against pinned public MCP source code.

Third-party repositories are downloaded into `corpus/` and are never installed
or executed. Generated JSON is written to `raw-results/`; disposable fixer
experiments use `work/`. Those directories are intentionally ignored by Git.

Run from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File evaluation/scripts/acquire.ps1
python evaluation/scripts/run_evaluation.py
```

See `REPORT.md` for findings, limitations, and interpretation guidance.

The completed October campaign is documented in
[the final validation report](../deliverables/Final_Validation_Report.md).
It includes three additional development rounds, the frozen one-shot evaluation,
and a [presentation demo](../deliverables/Demo.html). The final reserve has been
consumed; its results must not be reused as untouched validation.

The [17 October follow-up](../deliverables/Followup_Validation_Report.md)
completed rounds 008–010 and consumed the separate ten-file MCP-DecayBench
reserve. Development recall improved, but both reserved positives were missed
because hand-written JSON-RPC registrations were not extracted. See
[follow-up records](followup/README.md) for the preserved baseline, comparisons,
and separate one-shot validation state. The October 16 report remains a
historical result for its original frozen scanner.

## Development iterations

See [recorded iterations](iterations/README.md) for versioned baseline/fix/retest
experiments, explicit case labels, error investigations, and reproducible code
snapshots. These development runs are separate from the final holdout.

## Holdout protocol

The original holdout has a separate, one-way workflow under `holdout/`. It has
already been consumed; its saved results are historical evidence. Its source
directory, results, and one-time authorization token are ignored. Normal
evaluation commands never read or scan it. See `holdout/README.md` before adding
labels or consuming the holdout.
