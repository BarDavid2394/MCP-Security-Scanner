# Final results — slide-ready version

**Six results slides for the final presentation · 17 October 2026**

Copy the “On slide” content into PowerPoint. Keep the scope footnotes visible. The full explanation and auditable data are in [Final_Project_Results.pdf](Final_Project_Results.pdf).

## Slide 1 — What we delivered and measured

**On slide**

- Working static scanner: **16 threat categories, 25 rules**, console/JSON/HTML reports, and conservative Python fixes.
- **Development only:** 290 artifacts, 377 reviewed labels across ten batches.
- **99.5% precision · 89.7% recall · 94.3% F1** on those development labels.
- Reserved tests: **43.3% recall** originally; **0/2 positives detected** in the latest small reserve.

**Visible footnote:** Development cases were used for tuning; 188 unscored findings are excluded. Reserved tests use different data and scanner snapshots.

**Say:** “We delivered the full workflow and strong development results. Unseen implementation styles remain a limitation.”

## Slide 2 — What precision and recall mean

**On slide**

| Measure | Meaning | Development result |
|---|---|---|
| Precision | How often a scored alarm is correct | 192 / 193 = **99.5%** |
| Recall | How many positive labels we catch | 192 / 214 = **89.7%** |
| F1 | Balance of precision and recall | **94.3%** |

- Remaining misses: **22 of 214** positives.
- False alarms: **1 of 163** negative labels (**0.6% false-positive rate**).

**Say:** “Higher recall means fewer missed signals. High precision alone does not mean we detect every threat.”

## Slide 3 — Detection strengths and gaps

**On slide**

| Category | Detected / positive labels | Development recall |
|---|---:|---:|
| Tool poisoning | 89 / 95 | **93.7%** |
| Command/code execution | 58 / 64 | **90.6%** |
| Secret exposure | 16 / 18 | **88.9%** |
| Untrusted context | 6 / 10 | **60.0%** |

**Visible footnote:** Selected development labels; adapted/synthetic examples included. Overall labeled coverage: 8 of 16 categories, 11 of 25 rules. Broad-privilege and confusable-name positives were all missed in tiny groups (1 and 2 labels).

**Say:** “Our largest reviewed groups are poisoning and execution. Coverage and recall still vary by category.”

<div class="page-break"></div>

## Slide 4 — Improvements we can demonstrate

**On slide**

- Safe command handling: false alarms **9 → 1** on the same development cases.
- Helper/metadata repairs: **10 → 44 of 44** positives detected in the exposed Cisco batch.
- Original reserve, after becoming development data: recall **43.3% → 53.3%**; false alarms **1 → 0**.
- **180 passing unit tests**; earlier labeled outcomes stayed unchanged during the last three rounds.

**Visual:** Insert [final_results_development.svg](final_results_development.svg) or [PNG](final_results_development.png).

**Visible footnote:** Paired development retests, not independent validations. Original Cisco labels only; existing misses in other batches remain.

## Slide 5 — Reserved tests reveal the boundary

**On slide**

| Reserved run | Precision | Recall | Scope |
|---|---:|---:|---|
| Original frozen scanner | **92.9%** | **43.3%** | 33 artifacts; 50 labels |
| Latest frozen scanner | **Undefined** | **0% (0/2)** | 10 files; one MCP03 rule |

- Latest reserve: **zero tools recognized**, despite zero scan errors.
- Cause: unsupported handwritten JSON-RPC `tools/list` registration.
- Next priority: extract that metadata, then evaluate a new reserve.

**Visible footnote:** Original run excludes 37 unscored predictions. Latest reserve shares one implementation family; zero false alarms does not establish reliable negative discrimination.

**Say:** “The failure is retained in the score. It identifies a concrete extraction gap; it is not an estimate of recall across all MCP servers.”

## Slide 6 — Final contribution and live proof

**On slide**

- **Delivered:** source-path scanning, evidence-backed reports, conservative remediation.
- **Measured:** high performance on reviewed development labels; incomplete generalization.
- **Next:** wider registration coverage and independent label review.

```powershell
python demo.py .\tests\samples\vulnerable_tool_poisoning.py --html scan-report.html
```

**Say:** “We can run the workflow today, explain its improvements, and show where it still fails.” Open the printed HTML link and explain one finding. The target server is read statically, never executed.

**Keep on the final slide:** “Review aid; no guarantee that a server is safe.” Do not describe the 99.5%/89.7% development scores as unseen accuracy, or average them with the reserved results.

Source: [complete report](Final_Project_Results.md), [computed metrics](final_project_metrics.json), and [all ten development rounds](final_project_rounds.csv).
