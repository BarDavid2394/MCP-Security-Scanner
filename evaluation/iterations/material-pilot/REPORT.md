# Material conversion pilot

This exploratory pilot preceded the locked three-round campaign. It generated
218 adapted public-text candidates, admitted 22 reviewed MCP03 examples, and
created 24 synthetic fixtures in six families. The remaining 196 conversions
were unreviewed at pilot time. The later campaign reviewed additional records;
use `evaluation/campaign/schedule.json` for the final admission counts.

| Track | Positive labels | Negative labels | TP | FP | FN | TN |
|---|---:|---:|---:|---:|---:|---:|
| Adapted text | 12 | 10 | 0 | 2 | 12 | 8 |
| Synthetic source | 12 | 12 | 6 | 2 | 6 | 10 |

All 46 cases parsed successfully. The adapter preserved exact payload text as a
literal, and tools were recognized. The results exposed gaps in instruction
matching, environment credential names, pathlib returns, and command safety.
These cases became development data and were reused in iterations 005 and 006;
do not add their counts a second time when describing independent evidence.

The final holdout was not used in this pilot. It was consumed later, after the
three recorded development rounds, demo rehearsal, and scanner freeze.
