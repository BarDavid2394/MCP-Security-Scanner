# Iteration 001: hypotheses recorded before fixes

Baseline: 13 admitted source files, 24 explicit rule/function labels, one upstream repository. Twelve generic AI fixtures excluded before scanning. The first observed result is 3 TP, 9 FP, 5 FN, 7 TN; labels are assistant-reviewed, not independently adjudicated.

1. **Robustness:** a valueless annotated assignment has AST value=None. The command-flow assignment pass walks that value and crashes. Skip annotation-only declarations; do not clear existing taint, and continue scanning later dangerous operations.
2. **Input isolation:** generated .mcp-scanner-cache files are discovered as configuration inputs. Exclude the generated directory from source discovery; real adjacent configuration files must still be scanned.
3. **Metadata detection:** the existing data_exfiltration signature recognizes singular content/result/output but misses their plural forms. Extend only those nouns, retaining the existing transmission verb and to/via requirement. Verify plural attack descriptions and benign content-processing controls.

Run a stability-only intermediate evaluation before the signature change, then a final paired evaluation on the same labels. The final run is an in-sample development retest, not a fresh independent test. Do not consume another source batch or final holdout in this iteration.

Deferred: eight guarded-command false positives, one legitimate prerequisite false positive, low-level Python dispatcher extraction, HTTP result aliases (including ineffective sanitization), and unquoted cross-tool redirection. These need dedicated behavior and negative controls; no broad relaxation is justified by one small batch.
