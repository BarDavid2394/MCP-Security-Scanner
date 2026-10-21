# Completed evaluation campaign

Dataset and schedule lock: `schedule.json`, `preparation-lock.json`. No prediction
was used to change admission labels during this campaign. Standard MCP tool
syntax supplies the adapter; security behavior supplies the labels. This is
assistant semantic review, not independent human adjudication.

| Order | Activity | Outcome |
|---|---|---|
| 1 | Convert public materials and freeze labels | 930 conversions; 98 public cases admitted; 832 quarantined; 24 synthetic fixtures |
| 2 | Iteration 005: metadata | 2/48 to 45/48 detected; false alarms 2 to 0 |
| 3 | Iteration 006: synthetic code behavior | 8/12 to 12/12 detected; false alarms 2 to 0 |
| 4 | Iteration 007: adapted Vault cases | 2/10 to 9/10 detected; false alarms 0 throughout |
| 5 | Prior-batch regression and demo rehearsal | Earlier scores unchanged; demo checks passed |
| 6 | Freeze scanner and final protocol | 156 unit tests passed; code lock and overlap audit recorded |
| 7 | Acquire/verify and consume final reserve once | 33 artifacts / 50 labels; 13 TP, 1 FP, 17 FN, 19 TN |
| 8 | Produce final report and demo handoff | Reports, evidence archive, presenter notes, and interactive HTML |

Run timestamps are in each iteration's `runs/*/config.json` and
`completion.json`; final timestamps are in `../holdout/CONSUMED.json`.

The adapted pilot and synthetic pilot were exploratory measurements before this
schedule. Their cases are reused and not additional independent evidence. The
six synthetic families are paired scenarios with inline/helper variants, not
24 independent incidents. The 140 deepset-derived records, other Vault records,
ATR skills, and Bordair MCP records are converted but unscored; their original
contexts or labels still need review. MCP-FBAs preference data and other Bordair
modalities do not supply direct source-scanner ground truth.

The final reserve is consumed. No detector changes were made after its results.
MCP-DecayBench's ten proposed reserve candidates remain unused; preparing them
for a future final evaluation still requires labels and overlap review.

See [final report](../../deliverables/Final_Validation_Report.html),
[demo](../../deliverables/Demo.html), and
[presenter notes](../../deliverables/PRESENTER_NOTES.md).
