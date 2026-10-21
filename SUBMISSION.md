# Submission contents and reproduction

This distribution contains the current scanner source, tests, interactive scan
and fix workflow, dataset acquisition metadata, and preserved evaluation records.
It is a working-tree source snapshot of the MCPVul project; it is not a copy of
the original Git history. File hashes and the source commit are recorded in
`SUBMISSION_MANIFEST.json`.

## Run locally

Python 3 is sufficient for the scanner and tests; no core packages need installing.

```powershell
python -m unittest discover -v
python -m mcp_scanner rules
python -m mcp_scanner scan tests/samples/clean_server.py
python scan_and_fix.py
```

The interactive workflow uses isolated copies of the bundled intentionally
vulnerable MCP fixtures. It displays HTML/JSON report links, asks which eligible
MCP03/MCP06 findings to repair, rescans the edited files, and restores the working
copies after reporting. It does not execute a target server. Its successful
repairs are an illustrative demonstration, not an independent effectiveness
benchmark.

## Evaluation and data

- `deliverables/Final_Project_Results.md`: dated aggregate results, separating
  exposed development cases from reserved evaluations.
- `deliverables/Final_Validation_Report.md` and
  `deliverables/Final_Validation_Evidence.zip`: original frozen validation,
  including predictions and the evaluated code snapshot.
- `deliverables/Followup_Validation_Report.md` and `evaluation/followup/final/`:
  subsequent reserved evaluation and its provenance.
- `evaluation/iterations/`: development manifests, saved runs, metrics, and
  reproducible code snapshots.
- `evaluation/corpus-manifest.json`, `evaluation/holdout/`, and
  `deliverables/data_expansion/`: pinned sources, hashes, labels, and acquisition
  metadata. See the acquisition instructions before restoring external data.
- `tests/samples/` and `evaluation/fixtures/`: bundled illustrative fixtures.

Historical reports describe their recorded code versions. The current source
contains later changes and must not be claimed to have those historical benchmark
results without a corresponding evaluation. Consumed reserves are not untouched
test sets. Development and reserved metrics must not be pooled or substituted.

Downloaded third-party checkouts and large local data snapshots are not bundled;
the manifests preserve their origins and checksums. Restore those inputs to
reproduce data-dependent development runs. Ordinary unit tests and the interactive
workflow work without those downloads. Historical documents may refer to optional
presentation materials that are not part of this source distribution.

## Packaging

Private working notes, agent configuration, temporary reports, caches, document
intermediates, credentials, and the original `.git` directory are excluded.
Evaluation evidence is retained as recorded. The file manifest provides integrity
checks; it does not certify absence of every possible security or privacy issue.
