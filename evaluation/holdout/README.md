# Frozen holdout evaluation

This directory describes the clean evaluation set without containing third-party
source code. Clean artifacts are acquired into ignored storage and must never be
passed to the scanner while detector development is in progress.

The lifecycle is deliberately one way:

1. Add candidates to `staging-manifest.json` with exact provenance and labels.
2. Validate and freeze it with `freeze_holdout.py`.
3. Acquire exact revisions with `acquire_holdout.py` (source is not executed).
4. When detector development is finished, generate a one-time authorization
   token with `run_holdout.py --issue-token`.
5. Run exactly once with `run_holdout.py --token <token>`.
6. Produce per-rule metrics with `score_holdout.py`.

Freezing and acquisition do not invoke `MCPScanner`. The runner refuses a changed
manifest, an already-consumed holdout, missing artifact hashes, or a token that
does not match the frozen manifest fingerprint.

Label unit: one `(artifact_id, rule_id, polarity)` record. A positive label says
the exact artifact contains the rule. A negative label says the exact artifact
was reviewed for that rule and does not contain it. Absence of a label is
unknown, not negative.

