# Project submission and validation package

Prepared for **Bar David and Noam Ben Lulu**, B.Sc. in Electrical and Computer Engineering, Technion. Supervisor: **רועי מטרני**, as in the supplied example. Submission: **21 October 2026**. Evidence snapshot: **11 October 2026**.

## Start here

1. [Project book — PDF](MCP_Project_Book.pdf): **34 pages**, matching the NSSL example's chapter order and page allocation. Includes architecture, implementation, charts, measured results, limitations and bibliography.
2. [Project book — editable Word](MCP_Project_Book.docx): same content, figures and explicit page breaks. The PDF is the checked fixed-layout version; Word pagination can vary by installation. [Markdown source](MCP_Project_Book.md) is also supplied.
3. [Data and validation audit](DATA_AUDIT.md): complete inventory, evidence of use, historical/current results, labeling gaps, duplicate handling and review-pilot analysis.
4. [Additional-data research](NEW_DATA_RESEARCH.md): six new acquired sources, benign controls, compatibility, existing-data overlap, advisory-backed leads and a false-positive evaluation plan.

## Findings that affect the submission

- Existing corpus: **43 checkouts / 42 remotes**, **4,741 files**, **2,496 source copies / 2,365 unique source hashes**.
- Historical primary evaluation: **566 artifacts, 398 tools, 83 findings**; **13 TP, 32 FP, 38 contextual**; **28.9% conclusive precision**. No defensible overall recall/FPR from these labels.
- Additional historical use: **638 artifact-processing slots** after removing repeated/nested report scopes. Combined **1,204 slots** are not independent labeled samples.
- Reserved set: **33 artifacts, 50 labels (30 positive / 20 negative)**; still **staging**, not a completed final holdout.
- Current tests: **59 pass**. Current corpus validation: **9/10 targets complete**, **71 findings** on completed targets. FastMCP triggers an AST data-flow exception; scanner caches also enter discovery.
- New material: **115 text snapshots from six new sources**, with pinned revisions/hashes. Not scanned, executed or admitted as final ground truth.

The book reports the observed state, including the validation defects. It does not claim that final independent validation or model training has been completed. Production scanner code and the original evaluation records were left unchanged.

## Supporting records

| File | Contents |
| --- | --- |
| repository_inventory.csv | All existing checkouts, file/source counts, bytes, remotes, commits and matching report paths |
| scan_records.csv | Historical saved scans/review exports, timestamps, target scopes and counts |
| data_audit.json | Detailed computed inventory, holdout hashes, review identities and test inventory |
| reviewed_rule_metrics.csv | TP/FP/context labels per historical rule |
| staged_rule_coverage.csv | Positive/negative counts for the reserved rule labels |
| dataset_record_inventory.csv | 535 benchmark list/row containers; these units must not be blindly summed |
| source_duplicates.json | Exact duplicate source-file paths and hashes |
| new_sample_manifest.json | Every downloaded candidate/document, immutable URL and hash |
| new_sample_overlap.json | Narrow exact-byte overlap check against existing source/config artifacts |
| validation/ | Fresh primary-corpus reports, failure traceback, CLI outputs and summary |
| assets/ | PNG and SVG figures used in the book |
| working/ | Extraction/layout checks and test log; intermediate material, not submission content |

## Latest final project materials (17 October 2026)

- [Final results (PDF)](Final_Project_Results.pdf), [HTML](Final_Project_Results.html),
  and [Markdown](Final_Project_Results.md).
- [Short slide-ready results (PDF)](Final_Results_Slide_Content.pdf),
  [HTML](Final_Results_Slide_Content.html), and [Markdown](Final_Results_Slide_Content.md).
- [Computed full-project metrics](final_project_metrics.json),
  [per-round CSV](final_project_rounds.csv), and [calculation script](summarize_final_results.py).
- [Follow-up validation](Followup_Validation_Report.md),
  [original validation](Final_Validation_Report.md), and its
  [evidence archive](Final_Validation_Evidence.zip).
- Development chart: [SVG](final_results_development.svg) or
  [PNG](final_results_development.png).

The book and earlier records are dated snapshots. Use the final results
for the recorded evaluation figures and the root README for demo instructions. For a
fresh scan, run `python demo.py tests/samples/vulnerable_tool_poisoning.py` from
the repository root and open the HTML link printed by the command.

## Rebuilding

The scanner still requires no added core dependencies. Document generation uses `python-docx`, `matplotlib` and `reportlab`; PDF inspection used `pymupdf`. Additional document packages were installed in the temporary `mcp-book-libs` folder, not in project requirements.

```powershell
python deliverables\audit_data.py
python deliverables\write_audit_report.py
python deliverables\build_book.py
python deliverables\build_pdf.py
```

`audit_data.py` reads and hashes existing records without scanning holdout source. `validate_primary.py` deliberately scans only the already-used main corpus and stores errors per target. The Markdown book is a curated snapshot; if results change, update its statements and tables before rebuilding. The record-container ledger and research acquisition are timestamped evidence snapshots, not automatically updated by the book builder.

The original NSSL template contains 34 A4 pages. This book retains cover (1), contents (2), abstract (3), background (4–6), core mechanism/catalog (7–10), installation (11–13), experimental framework (14–16), system diagram (17), implementation (18–26), statistics (27–32), conclusions (33), and bibliography (34). English text uses left-to-right layout while preserving the supervisor's Hebrew spelling. No institutional logo or signature was invented.

## Expanded collection and iteration plan (13 October 2026)

See [expanded data and iteration capacity](data_expansion/EXPANDED_DATA_AND_ITERATIONS.md) for the additional downloads, verified counts, category gaps, and proposed four development rounds plus one reserved final evaluation. The original audit and book remain dated snapshots.

## GitHub package

The repository includes the book (PDF, Word and Markdown), figures, audit reports, validation records, acquisition scripts and pinned dataset manifests. Downloaded third-party snapshots, document intermediates and Word lock files remain local, following the repository's existing corpus policy. Dataset counts describe the local research collection; the downloaded corpora are not bundled in this Git commit.

Use `new_sample_manifest.json` for the first collection and `data_expansion/download_manifest.json` for the expanded collection. They record upstream URLs, revisions, file sizes and SHA-256 hashes. Some URLs are GitHub file-view links; retrieve their raw content at the recorded revision when restoring a snapshot. `data_expansion/acquire.py` acquires its listed GitHub subset; the complete inventory, including the additional repositories and Hugging Face datasets, is in the manifests. Restore those local inputs before rerunning the complete data summaries.
