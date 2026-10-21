# Expanded data collection and iteration capacity

Collection snapshot: 11 October 2026. Inventory and proposed schedule finalized: 13 October 2026.

**Recommendation: plan four focused development/validation rounds followed by one reserved final evaluation. This is a proposed allocation of collected source groups, conditional on rule-level labeling and family-overlap review. There are currently zero ready, balanced rounds covering all MCP01?MCP16.**

The implemented scanner is based on static rules. Here, training means improving rules or reviewer prompts using development examples. It does not mean fitting model weights. Repeated development runs are unlimited; genuinely new test evidence is limited by independent labeled cases. No new source was imported, installed, executed, or scanned. The existing final reserve remains in staging.

## What was actually acquired

This expansion contains **1,267 files**, **62.96 MiB**, from **18 GitHub repositories and two Hugging Face datasets**. This is additional to the earlier 115-file collection. Of these, 1,266 files passed hash readback; one Cisco fixture returned an OS read error and is excluded from the proposed batches. There are 1,251 distinct whole-file hashes. The 12 matches against previous local collections are empty initializer files. Semantic overlap has not been ruled out.

Counts include documentation, licenses, test harnesses and upstream results: 1,267 is not a sample count. Files are saved as inert `.txt` snapshots, with upstream paths, pinned revisions and hashes in `download_manifest.json`.

| Collection | Locally counted data | Relevance and limits |
|---|---:|---|
| Five Python fixture sources | 342 file copies; 334 nonempty, readable, distinct files | Candidate static fixtures; includes helpers and 31 unclassified files. Requires our rule-level case labels. |
| [Bordair](https://github.com/n1ps/bordair-dataset) selected subset | 38,772 attack + 14,763 benign records | 53,535 records, largely synthetic and augmented. Only 34 records explicitly belong to the two MCP-named categories. |
| Bordair text-only subset | 14,899 attack records; 13,836 distinct attack texts; 14,763 distinct benign texts | Text inputs need an adapter and scoped labels. These are not 28,599 independent static vulnerability cases. Other modalities are not covered by this scanner. |
| [MCP-FBAs](https://huggingface.co/datasets/johnhalloran/mcp-fbas) | 2,646 preference training pairs; 109 attack + 171 benign test rows | Predefined train/test split for agent behavior. Not source-code scanner ground truth; CC BY-NC 4.0. |
| [Vault](https://github.com/vaultmcp/vault) v2 evaluation | 80 attack/suspicious + 100 benign documents | 50 novel and 30 paraphrase attack-side records; 18 are labeled suspicious rather than malicious. Do not silently collapse that distinction. |
| Vault additional material | 200 pattern-bank entries, 188 old attack records, 110 old benign documents, 70 encoded benign controls | Older attack set is explicitly marked burned upstream. Counts are separate pools, not proof of independence. |
| [Prompt-injection-bench](https://github.com/andyscott88/prompt-injection-bench) current set | 118 attack + 100 benign cases | 140 cases derive from deepset; older saved versions are not extra cases. |
| [ATR skill benchmark](https://huggingface.co/datasets/Agent-Threat-Rule/atr-skill-benchmark) | 32 malicious + 466 benign records | Mostly skill/document text. Only seven records have the mcp-official source-family label. Requires an appropriate text evaluator. |
| [Python SDK session advisory](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-jpw9-pfvf-9f58) | Two affected source files and their two patched counterparts | MCP14 candidate pair from v1.27.1/v1.27.2. One vulnerability family, not four independent incidents. |

Further pinned snapshots include MCP security patterns, vulnerable demonstration servers, MCPRadar test/validation material, and a 12-scenario security benchmark. Their files are inventoried, but harness code and scanner-generated results are not promoted into labeled examples.

## Concrete proposed rounds

| Round | New validation source group | Readable nonempty candidate files | Upstream positive / negative / unclassified hints |
|---|---|---:|---|
| 1  | [akanthed/SecureAI-Scan](https://github.com/akanthed/SecureAI-Scan) | 25 | 10 / 15 / 0 |
| 2  | [jaimenbell/mcp-security-scanner](https://github.com/jaimenbell/mcp-security-scanner) | 97 | 38 / 31 / 28 |
| 3  | [jspillers10/mcp-security-scanner](https://github.com/jspillers10/mcp-security-scanner) | 57 | 29 / 25 / 3 |
| 4  | [cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) | 145 | 141 / 4 / 0 |
| 5 (final reserve) | [autod3structeur/MCP-DecayBench](https://github.com/autod3structeur/MCP-DecayBench) | 10 | 2 / 8 / 0 |

**Rounds 1?4 contain 324 candidate files.** Begin development with already exposed data, validate against the next source group, then move that group into development once its results inform changes. These are sequential development batches, not a claim that each contains every vulnerability category. Keep multi-file fixtures together and remove helper-only files from the scored case denominator.

**Round 5 proposes reserving all ten MCP-DecayBench servers**, including eight hard negatives. Keep the existing 33-artifact, 50-rule-label staging reserve untouched alongside it; any addition must pass labeling and duplicate-family checks before freezing. The ten new servers have not been added to the existing holdout manifest. The combined proposed final pool has 43 artifact slots, with overlapping category labels and incomplete category coverage.

The source labels above are hints. For example, jspillers boundary cases include seven cases explicitly excluded from that upstream scanner scope; a benign fixture may be clean only for one rule, and a file may contain several tools or depend on another file. Our own categories and evaluation scope must decide admission before scoring.

## MCP01?MCP16 readiness

This table counts existing reserved artifacts per category, not findings. An artifact may occur in several rows. No new downloaded candidate has yet been accepted into this rule-labeled reserve. Zero accepted new labels does not mean zero relevant candidates.

| Category | Reserved positive files | Reserved negative files | Recorded reserve use |
|---|---:|---:|---:|
| MCP01 | 3 | 2 | 0 |
| MCP02 | 1 | 0 | 0 |
| MCP03 | 5 | 5 | 0 |
| MCP04 | 0 | 0 | 0 |
| MCP05 | 9 | 5 | 0 |
| MCP06 | 4 | 0 | 0 |
| MCP07 | 1 | 1 | 0 |
| MCP08 | 0 | 0 | 0 |
| MCP09 | 2 | 0 | 0 |
| MCP10 | 0 | 0 | 0 |
| MCP11 | 0 | 0 | 0 |
| MCP12 | 0 | 0 | 0 |
| MCP13 | 2 | 3 | 0 |
| MCP14 | 0 | 0 | 0 |
| MCP15 | 0 | 0 | 0 |
| MCP16 | 0 | 0 | 0 |

New-source review priorities: secret fixtures for MCP01; tool descriptions and hard negatives for MCP03; command/dataflow fixtures for MCP05; contextual payloads for MCP06; auth controls for MCP07; URL sinks for MCP13; and the advisory-backed affected/patched pair for MCP14. MCP02, MCP04, MCP08?MCP12 and MCP15?MCP16 still need particularly careful collection and labeling; keywords or similarly numbered upstream taxonomies are not enough.

## How many iterations does a dataset buy?

- **Development reruns:** unlimited reuse, with diminishing independent evidence. Record every version, prompt and configuration.
- **Proposed source-group batches:** four development/validation batches plus one final evaluation, after admission review. This is a practical schedule, not a statistically derived maximum.
- **Fully balanced MCP01?MCP16 rounds ready now:** zero, because some categories lack reviewed positive or negative examples.
- **Model training, if added later:** MCP-FBAs supplies 2,646 training pairs and one predefined 280-row final test. Three epochs would be 7,938 training-pair presentations, not 7,938 unique examples or three fresh tests. It does not train the current static scanner without a new model component.

For a stipulated batch size of p positive and n negative independent cases per category, the numerical upper bound on disjoint full-category test rounds is min over categories of floor(P/p) and floor(N/n), after excluding training and reserved final cases. Family grouping can reduce this further. For example, four development-validation batches plus one final batch with 10 positive and 10 negative cases in each of 16 categories requires 1,600 category-case slots. The same incident labeled under several categories still counts as one underlying family. Our downloaded record totals do not establish that requirement.

## Remaining work and limitations

1. Review candidate cases against this project?s stable rule IDs, including what constitutes a negative. Use reviewers independent of scanner predictions.
2. Group by repository, original incident, template/seed, and vulnerable/fixed family; check semantic overlap with MCPTox, DVMCP and other already exposed corpora.
3. Admit supported Python/config/dependency cases to a static benchmark. Keep metadata, prompts, skills and agent traces in separately named tracks with adapters.
4. Address the already observed FastMCP scan crash and generated-cache discovery issue before using corpus-wide scores in the book. These collection changes did not modify scanner behavior.
5. Freeze the final reserve once. After final-test results guide changes, a further unbiased final evaluation needs a new reserve.

Some leads were unavailable: ferentin-net/mcp-guard returned repository-not-found; the prodnull repository-text dataset returned HTTP 401. Neither is counted as acquired data. The large Bordair derivative external bank and most scaled benign variants were not downloaded; their advertised totals are not added to local counts. License metadata and attribution must follow each source; missing license metadata is not assumed to grant redistribution rights.

Reproducibility files: `download_manifest.json`, `verified_counts.json`, `native_fixture_candidates.json`, `exact_file_overlaps.json`, `category_readiness.csv`, and `iteration_plan.json`. The original book and audit remain dated snapshots; this report is their data-expansion addendum.
