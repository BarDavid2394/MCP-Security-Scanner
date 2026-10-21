# Data and validation audit — 11 October 2026

The folder contains **43 existing repository checkouts from 42 distinct remote repositories/datasets**, holding **4,741 working-tree files**, **2,496 source-file copies**, and **2,365 byte-distinct source files**. Their logical size is **745,416,472 bytes (710.88 MiB)**, excluding Git internals, selected dependency/cache folders and backups. Upstream result files and derived datasets remain included. These are inventory counts, not counts of labeled security examples.

The most defensible completed evaluation remains the historical ten-target run: **566 supported artifacts, 398 recognized tools, 83 reviewed findings**. Its labels are **13 TP, 32 FP, 38 Needs context**. Precision among conclusive labels is **28.9%**. This does **not** mean 28.9% accuracy, nor is 32/83 a false-positive rate.

The current scanner was also checked on 11 October: **59/59 unit tests passed**, while a new primary-corpus run completed **9/10 targets** and failed on a valid Python annotation in FastMCP. The nine completed targets yielded **431 processed artifacts, 242 tools and 71 findings**. That partial, newly unreviewed result cannot replace the older complete labeled result.

## 1. What was counted

| Unit | Meaning | Can it be added to the other units? |
| --- | --- | --- |
| Repository checkout | One local directory/revision | No: multiple revisions can share a remote. |
| File | One on-disk artifact, including documents and results | No: a file can contain hundreds of cases. |
| Source file | .py/.js/.jsx/.ts/.tsx/.mjs/.cjs; includes framework and harness code | No: most are not labeled samples. |
| Tool | One parser-recognized tool registration | No: several tools can share a file. |
| Finding | One emitted heuristic warning | No: several signatures can describe one defect. |
| Label | One reviewer judgment or artifact/rule/polarity tuple | No: multiple labels can apply to one artifact. |
| Benchmark record | Task, description, payload, trace or upstream result | Only within a documented schema. |

There is no implemented model-fitting pipeline or documented train/validation/test split for a learned detector. Here, “training” primarily means engineering detector rules and reviewing examples. The optional LLM reviewer performs inference with an existing model; the saved records do not demonstrate fine-tuning.

## 2. Inventory and use

| Location | Checkouts | Files | Logical bytes |
| --- | --- | --- | --- |
| corpus | 8 | 791 | 10,759,322 |
| corpus-external | 35 | 3950 | 734,657,150 |

All 4,741 file copies reduce to 4,360 exact file hashes. The 2,496 source-file copies reduce to 2,365 exact hashes: **131 redundant source copies**. Byte equality is only one form of overlap; renamed or reformatted examples and common upstream families require an additional review. Empty files also share hashes and are not meaningful security examples.

Saved scanner reports reference **14 of the 43 checkout directories (13 distinct remotes)**. The remaining **29 directories have no matching saved scanner report in the audited locations**. This is absence of recorded use, not proof that nobody ever read or scanned them. Development discussions, deleted results and external runs are not recoverable from these files.

Selecting one historical report per non-nested target scope gives **1,204 recorded artifact-processing slots**: 566 in the main corpus and 638 additional slots across MCPTox, MSB, MCPSecBench, two Excel revisions and MCPSafety. Repeated MCPTox runs, the repeated Fetch run, and the nested benign-add scan are not added again. This total still includes version overlap, configuration files and third-party shared code; it is **not 1,204 independent labeled samples**. There is no reliable per-file scan ledger for all clean files, so an exact percentage of the available labeled data used cannot be reconstructed.

There are **28 saved scan-report files** in the historical audit: 24 under `raw-results` plus four LLM-review exports. `raw-results/summary.json` is an aggregate and is not counted as another run. The six local fixture files (three under `tests/samples`, three under `evaluation/fixtures`) are separate from third-party inventory. Inline unit-test examples are not additional external samples.

### Complete checkout inventory

The counts below exclude Git/dependency/cache/backup content. “Report evidence” is a count of saved report files, including repeated runs and review exports; it is not a count of independent evaluations. Full commits, remotes, sizes and report paths are in `repository_inventory.csv`.

| Group / directory | Files | Source files | Report evidence |
| --- | --- | --- | --- |
| corpus/awslabs-mcp | 56 | 28 | 1 |
| corpus/fastmcp | 192 | 123 | 2 |
| corpus/markitdown | 18 | 4 | 1 |
| corpus/mcp-atlassian | 134 | 117 | 4 |
| corpus/official-servers | 47 | 13 | 4 |
| corpus/python-sdk | 317 | 225 | 1 |
| corpus/quickstart-resources | 10 | 1 | 1 |
| corpus/simple-mcp-server | 17 | 8 | 1 |
| corpus-external/AgentDefense-Bench | 113 | 36 | 0 |
| corpus-external/bad-mcp | 69 | 0 | 0 |
| corpus-external/curate-agentinel | 79 | 49 | 0 |
| corpus-external/curate-allen-mcpaudit | 38 | 21 | 0 |
| corpus-external/curate-appsecco | 54 | 11 | 0 |
| corpus-external/curate-connor | 473 | 170 | 0 |
| corpus-external/curate-dvmcp | 69 | 31 | 0 |
| corpus-external/curate-glatinone-mcpscan | 92 | 57 | 0 |
| corpus-external/curate-mception | 80 | 55 | 0 |
| corpus-external/curate-sachin-mcpaudit | 648 | 366 | 0 |
| corpus-external/excel-mcp-0.1.7 | 26 | 14 | 1 |
| corpus-external/excel-mcp-0.1.8 | 31 | 15 | 1 |
| corpus-external/malicious-demo-mcp-server | 4 | 1 | 0 |
| corpus-external/mcp-attack-labs | 141 | 78 | 0 |
| corpus-external/mcp-ctf-challenge | 42 | 26 | 0 |
| corpus-external/mcp-injection-experiments | 4 | 3 | 0 |
| corpus-external/mcp-poisoning-poc | 38 | 22 | 0 |
| corpus-external/mcp-security-benchmark | 56 | 7 | 0 |
| corpus-external/mcp_vulnerable_testbed | 0 | 0 | 0 |
| corpus-external/MCPSafety | 471 | 190 | 1 |
| corpus-external/MCPSecBench | 85 | 10 | 2 |
| corpus-external/MCPTox-Benchmark | 489 | 485 | 3 |
| corpus-external/MSB | 163 | 108 | 1 |
| corpus-external/new-holdout-dvmcp | 19 | 8 | 0 |
| corpus-external/new-holdout-mcp-attack-surface | 9 | 3 | 0 |
| corpus-external/new-holdout-mcp-insecure-demo | 37 | 22 | 0 |
| corpus-external/new-holdout-mcp-vulnerabilities | 42 | 31 | 0 |
| corpus-external/new-holdout-mcpguard | 15 | 6 | 0 |
| corpus-external/new-holdout-mcppt | 26 | 16 | 0 |
| corpus-external/new-holdout-unbound-mcp-security-test | 12 | 3 | 0 |
| corpus-external/new-holdout-vulnerablemcp | 48 | 6 | 0 |
| corpus-external/safe-mcp | 318 | 46 | 0 |
| corpus-external/vuln-mcp | 28 | 10 | 0 |
| corpus-external/web-hf-crossmcp-bench | 127 | 71 | 0 |
| corpus-external/web-hf-mcpshield-scan | 4 | 0 | 0 |

The `mcp_vulnerable_testbed` checkout has zero working-tree files. Its Git metadata does not make it an available source dataset. The two Excel directories are two revisions of one remote, accounting for the difference between 43 checkouts and 42 remotes.

## 3. Historical main evaluation (10 August 2026)

| Target | Artifacts | Tools | Findings |
| --- | --- | --- | --- |
| official-fetch | 7 | 1 | 1 |
| official-git | 6 | 12 | 0 |
| official-time | 6 | 2 | 0 |
| python-sdk-examples | 243 | 117 | 45 |
| quickstart-weather | 3 | 2 | 0 |
| fastmcp-examples | 141 | 156 | 20 |
| mcp-atlassian | 117 | 98 | 13 |
| markitdown-mcp | 5 | 1 | 1 |
| simple-mcp-server | 8 | 2 | 0 |
| aws-documentation | 30 | 7 | 3 |

| Label | Count | Share of emitted findings |
| --- | ---: | ---: |
| TP: credible risky precursor | 13 | 15.7% |
| FP: claim contradicted by review | 32 | 38.6% |
| Needs context | 38 | 45.8% |

Conclusive precision = 13/(13+32) = 28.9%. True negatives and missed vulnerabilities were not exhaustively labeled, so corpus recall, specificity, accuracy and FPR are **unavailable**. A TP is evidence for the rule's risk, not confirmation of exploitability. The CSV labels are encoded review decisions, with no documented second independent annotator or inter-rater agreement. The triage script is not an independent ground-truth oracle.

Historical findings by category: MCP01 11; MCP04 6; MCP06 6; MCP07 37; MCP08 2; MCP09 1; MCP10 9; MCP11 7; MCP13 1; MCP15 3. The other six categories had no emitted finding in this run. Absence of a finding is not measured coverage.

The report describes earlier improvements from 238 warnings to 83 and precision from 10.1% to 28.9%. The initial 238-finding raw export was not found in the audited result directory. Treat that baseline as a historical narrative, not an independently recomputed paired experiment. Existing `REPORT.md` says nine unit tests passed, and `SESSION_HANDOFF.md` says 29; both are stale relative to today's 59-test suite.

## 4. External datasets and the records actually present

| Dataset | Available units verified locally | Evidence of this scanner using it | Interpretation |
| --- | --- | --- | --- |
| MCPTox | 485 Python files under `def_tool`; 485 entries in 45 groups in `pure_tool.json`; 1,348 `malicious_instance` records in `response_all.json` | Three exports for the same 485-file scope; last two each contain 1,107 findings across 393 files | 393/485 = 81.0% file flagging on exposed attack material; 92 files unflagged. Not independent recall. |
| MCPTox clean context | 353 tool-name entries and 357 clean-query entries across 45 response groups | No separate clean-context scan export found | Entries embedded in benchmark contexts need extraction, deduplication and independent labels. `pure_tool.json` is **not a benign set**: its records contain attack paradigm/risk fields. |
| MSB | 108 Python files in full checkout; JSONL files contain 10 agent-task lines, 5 attack-task lines, 1 attack-type line | 64 supported artifacts, 267 tools, 14 findings in `data/tools/attack_tools` | JSONL lines can package nested tasks; do not equate them to the paper's experiment count. No exact rule-level recall labels. |
| MCPSecBench | 9 Python files, 1 JS file and 4 JSON files in checkout, plus documents/media | Code scope: 13 artifacts, 19 tools, 16 findings; nested add server: 1 artifact, 2 tools, no findings | The nested scan overlaps the broader scan. A benign arithmetic control does not validate all categories. |
| MCPSafety | 190 Python and 253 JSON files in checkout | Existing `holdout-mcpsafety-clean-mcp03.json`: 40 artifacts, 156 tools, zero findings | Previously exposed; filename indicates MCP03-specific intent but the exact invocation is not saved. Not an untouched holdout or proof of whole-project safety. |
| Excel MCP | Versions 0.1.7 and 0.1.8, 14 and 15 Python files | 17/19 supported artifacts; 25 tools each; 1/2 findings | Version pair alone is not a verified vulnerable/fixed pair for a scanner rule. |
| AgentDefense-Bench | Consolidated lists: 640 tier-1, 27,122 tier-2, 5,606 tier-3, 250 benign; separate benign baseline 93, benign classification list 516; many upstream derivatives | No saved scanner report found | Mostly prompts, runtime messages and derived benchmark records. 33,368 consolidated attack entries and 250 benign entries are not 33,618 unique MCP source examples. Overlapping views must not be summed. |
| Connor | 473 checkout files, including 170 Python files; previously recorded 114 PoCs plus 20 dataset servers | No saved scanner report found | Directory-level malicious/benign labels and overlapping third-party servers; not exact static-rule ground truth. |
| CrossMCP-Bench | 134 nonempty lines in local `data/scenarios.jsonl` | No saved scanner report found | Runtime scenarios; older discovery note reports 277, which is not the local row count. |
| MCPShield scan dataset | 4,867 rows in root JSONL and 1,900 in `data/` JSONL | No saved scanner report found | Upstream scanner outputs, not manual labels. Do not sum the two files as unique servers without a join. |

`dataset_record_inventory.csv` inventories 535 list/row containers across the seven principal benchmark/data checkouts. It intentionally calls them containers: schema versions, duplicate views, task groups and upstream results prevent a defensible global sample total. Sizes quoted above are the local pinned snapshot, not necessarily the current upstream release or paper headline.

## 5. Reserved evaluation set

The actual manifest state is **staging** (created 20 August 2026). There is no frozen manifest, `holdout-corpus` directory or `holdout-results` directory. No final holdout score is present. All 33 manifest artifact hashes match locally available source copies.

The set has **7 sources, 33 distinct artifacts and 50 explicit rule labels: 30 positive and 20 negative**. There are 23 artifacts with positive labels and 10 with negative labels, with no artifact overlap between those groups. Fifty labels are not fifty source samples. The JSON inventory, JSONL candidates and staging manifest represent the **same** 33 artifacts; they must not be counted three times.

| Rule | Positive labels | Negative labels |
| --- | --- | --- |
| MCP01-SECRET-HARDCODED | 2 | 2 |
| MCP01-SECRET-OUTPUT | 3 | 2 |
| MCP02-BROAD-SCOPE | 1 | 0 |
| MCP03-TOOL-POISON | 5 | 5 |
| MCP05-COMMAND-INJECTION | 5 | 5 |
| MCP05-DYNAMIC-CODE | 5 | 2 |
| MCP06-UNTRUSTED-CONTEXT | 4 | 0 |
| MCP07-PERMISSIVE-BIND | 1 | 1 |
| MCP09-CONFUSABLE-NAME | 2 | 0 |
| MCP13-SSRF | 2 | 3 |

Labels cover 10 of 25 stable rules and 8 of 16 categories. Explicit negatives cover 7 rules in only 5 categories. There are no negative labels for MCP06, despite prompt injection being one of the original core goals. Categories MCP04, MCP08, MCP10, MCP11, MCP12, MCP14, MCP15 and MCP16 have no staged labels at all.

Three lifecycle concerns need resolution before independent testing: prove that the staged families were not used to tune rules; deduplicate against previously exposed repositories and common upstream examples; and freeze the manifest only after labels and splits are finalized. Inspecting metadata/hashes in this audit did not invoke the scanner on staged artifacts. The existing MCPSafety run is separate from the newer seven-source staging set, but it cannot be reclassified as unseen just because its filename says holdout.

## 6. Optional LLM review: recorded evidence

Four exports contain **18 review appearances, representing 16 distinct finding/model/prompt identities**. The one-finding Atlassian run appears again as a cached export and inside the pilot. No new paid API calls were made in this audit.

| Export | Reviews | Cached entries | Verdicts | Exact label agreement |
| --- | --- | --- | --- | --- |
| atlassian-llm-pilot.json | 6 | 1 | LIKELY: 1, UNLIKELY: 2, NEEDS_CONTEXT: 3 | 2/6 |
| atlassian-llm-review-cached.json | 1 | 1 | LIKELY: 1 | 0/1 |
| atlassian-llm-review.json | 1 | 0 | LIKELY: 1 | 0/1 |
| fastmcp-llm-pilot.json | 10 | 0 | NEEDS_CONTEXT: 4, LIKELY: 4, UNLIKELY: 2 | 7/10 |

The 16 unique review identities contain 9 human-FP labels, 6 contextual labels and 1 TP label. Verdicts: 5 LIKELY, 4 UNLIKELY, 7 NEEDS_CONTEXT. Exact three-way agreement is **9/16 (56.25%)**. Among the 10 conclusive human labels, 7 receive decisive model verdicts; 5/7 agree. 2 human-FP cases are endorsed LIKELY. There is only one human-TP example, so no reliable false-negative estimate is possible.

These joins use the historical target, normalized path, rule and source line, rather than blindly joining changing finding indices. They do not prove that source text is identical between runs because the historical exports lack a complete source fingerprint. Saved reviews use prompt version `2026.1-review-1`; current source uses `2026.1-review-2`. The stored pilots therefore do not validate the current reviewer implementation. Token usage, costs and latency are not recorded sufficiently for a financial/performance assessment. Cached flags do not equal unique paid requests.

## 7. Fresh validation and blocking defects

| Target | Status | Artifacts | Tools | Findings |
| --- | --- | --- | --- | --- |
| official-fetch | completed | 7 | 1 | 1 |
| official-git | completed | 6 | 12 | 0 |
| official-time | completed | 6 | 2 | 0 |
| python-sdk-examples | completed | 243 | 117 | 53 |
| quickstart-weather | completed | 3 | 2 | 0 |
| fastmcp-examples | failed | — | — | — |
| mcp-atlassian | completed | 123 | 98 | 13 |
| markitdown-mcp | completed | 5 | 1 | 1 |
| simple-mcp-server | completed | 8 | 2 | 0 |
| aws-documentation | completed | 30 | 7 | 3 |

The new run uses the current working tree, deterministic scanning and `--review none` semantics. It saves separate files under `deliverables/validation`; historical evidence was not overwritten. Results were not manually relabeled, so the historical 28.9% precision must not be assigned to these 71 findings.

**Crash:** `evaluation/corpus/fastmcp/examples/elicitation.py` contains valid valueless annotated assignments such as `favorite_color: str`. `PythonDataFlow.command_flows` passes `AnnAssign.value == None` into `ast.walk`, producing `AttributeError: 'NoneType' object has no attribute '_fields'`. The complete traceback is in `validation/fastmcp-examples-error.txt`. This is a scanner failure, not a vulnerable finding and not a fixture-creation permission problem.

**Cache contamination:** Atlassian's count rose from 117 to 123 because six JSON review-cache files inside `src/.mcp-scanner-cache` are admitted by artifact discovery. The current `get_project_files` skip list does not exclude this cache directory. Existing repository rules require generated caches to be excluded; this implementation gap also compromises apples-to-apples artifact counts. FastMCP has a cache directory too. The audit inventory excludes these caches, while the scanner's recorded count includes them. Neither source code nor caches were modified to hide the discrepancy.

The 59 tests took 0.616 seconds in this environment; they cover 44 scanner tests, 5 reviewer tests, 5 holdout tests, 3 CLI tests and 2 fixer tests. CLI smoke checks produced exit 0 for the clean sample and exit 1 for the intentionally poisoned sample. Passing unit tests does not override the real-corpus crash. The fresh complete target portions took about 16 seconds, but a total performance claim is inappropriate while one target fails.

Historical fixer records report successful dry runs, valid syntax, backups and idempotence for the two controlled mutations. Today's fixer unit tests passed too. These checks demonstrate mechanical properties on fixtures, not proof that sanitizer rewrites eliminate arbitrary prompt injection. No canonical corpus source was rewritten.

## 8. Recommended validation sequence before submission

1. Resolve the valueless-annotation crash and add a focused positive/negative regression; exclude scanner-generated caches and verify artifact counts.
2. Repeat the already-used primary corpus, save scanner commit, source hashes, command, environment and per-file outcome ledger, then relabel changed findings.
3. Keep exposed corpora for development. Independently review the staged set and additional sources, with exact rule-specific negative labels.
4. Group splits by upstream repository, shared sample family and vulnerable/fixed pair; apply byte and normalized-source deduplication before splitting.
5. Freeze a separate final set and run it once after the scanner configuration is locked. Preserve failures and unsupported cases in the denominator policy.
6. Report per-rule TP/FP/FN/TN, precision, recall, FPR, abstentions, parse failures, and confidence intervals. Include negative cases with legitimate files, URLs, shell descriptions and cross-file authentication.

For a pre-specified, approximately independent binary negative sample, observing zero FP in 100 negatives still gives a one-sided 95% upper bound of about 3%, not proof of zero risk. Related examples are clustered and reduce effective sample size. Prefer several independent repositories over many clones of one easy template.

## Reproducibility and deliverables

`python deliverables/audit_data.py` regenerates the metadata/hash audit without scanning any corpus. `python deliverables/validate_primary.py` scans only the already-exposed main manifest, records target failures, and never consumes the holdout. `repository_inventory.csv`, `scan_records.csv`, `reviewed_rule_metrics.csv`, `staged_rule_coverage.csv`, `dataset_record_inventory.csv`, `source_duplicates.json` and `data_audit.json` contain the detailed ledgers.

The separate `NEW_DATA_RESEARCH.md` describes six newly retrieved candidate sources and additional research leads. Their 115 downloaded text snapshots are excluded from the original 4,741-file inventory; the acquisition manifest records every exact revision, URL and SHA-256. They have not been scanned or silently assigned final evaluation labels.
