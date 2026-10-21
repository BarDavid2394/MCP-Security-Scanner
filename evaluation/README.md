# Evaluation utilities

This directory contains source acquisition and evaluation utilities, a pinned
public-source manifest, and illustrative source fixtures.

Third-party repositories are downloaded into `corpus/` and are never installed
or executed. Local scan output is written to `raw-results/`; disposable fixer
experiments use `work/`.

Run from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File evaluation/scripts/acquire.ps1
python evaluation/scripts/run_evaluation.py
```

The additional iteration, campaign, and holdout utilities require local input
manifests, labels, source snapshots, and lifecycle metadata. Those records are
not bundled. Their paths and validation requirements are defined in the scripts.
Unit tests create temporary fixtures and do not require downloaded corpora.
