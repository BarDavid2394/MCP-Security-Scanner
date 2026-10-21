# Additional data research — 11 October 2026

The most useful next additions are **source fixtures with explicit negative controls**, plus **reviewed vulnerable/fixed source pairs**. Large prompt collections can supplement MCP03/MCP06 research, but they do not directly measure this source scanner's performance on authentication, dependencies, session isolation or SSRF.

Six sources not present in the original 43-checkout inventory were inspected through their public repositories. **115 files were downloaded at full commit revisions**, stored under `new_samples/` with `.txt` appended, and hashed in `new_sample_manifest.json`. They are inert source/data snapshots: none was imported, installed, executed, scanned, or admitted to the staged holdout. Files include examples, label manifests, documentation and licenses; 115 is a file count, not a sample count.

## 1. New sources, ranked by practical usefulness

| Priority / source | Verified available units in selected snapshot | Negative controls | Fit for this project | Acquisition / license |
| --- | --- | --- | --- | --- |
| 1. windshock/mcpscan | 11 source-server fixtures: 8 labeled vulnerable, 3 labeled normal | `normal-strict`, `normal-realistic`, `normal-tricky` | Direct Python/TypeScript source; provisional MCP03/MCP05/MCP13 and configuration mappings | 20 files saved; MIT |
| 2. m4vic/detonate | 6 malicious MCP server sources and 1 honest server; per-fixture ground-truth YAML | `testdata/honest/server.py` | Direct Python; metadata attacks, covert implementation behavior and transformations. Some ground truth is runtime-only | 15 files saved; Apache-2.0 |
| 3. Ventrova/sentinel-scan-cli | 40 JSON manifests: 20 malicious and 20 clean | Sandboxed file reader, weather, password-strength and other benign tool manifests | Metadata/config adapter and rule mapping needed; especially MCP03 and name/scope heuristics | 43 files saved; MIT |
| 4. ksek87/fuzzd | 24 tool-poisoning corpus JSON files and 20 clean tool-description records | File access, SQL, email and shell-tool descriptions with `is_attack:false` | Strong MCP03 lexical hard negatives; metadata adapter required | 26 files saved; no repository license file found in pinned tree/API |
| 5. mzquadri/mcp-policy-gateway | 26 attack `Case(...)` definitions and 21 benign definitions, counted by AST without import | Quoted attack strings in advisories, installation guidance, benign path normalization | Runtime request/response cases; useful for future MCP06 payload support and sanitizer behavior, not native source-scan accuracy | 4 files saved; MIT |
| 6. glatinone/mcp-security-preflight | 5 synthetic JSON fixture manifests, 24 tools, 15 upstream planted findings | `safe_notes` plus clean tools inside mixed cases | Structured metadata/policy fixtures; adapter and taxonomy mapping needed | 7 files saved; license not established by API metadata |

Counts above deliberately use different units and must not be summed as a unified benchmark. “Benign” means the upstream author's control for a stated task; it does not establish absence of every MCP01–MCP16 risk.

### Why the first two are the best immediate additions

**windshock/mcpscan** supplies ordinary, realistic and deliberately misleading controls alongside positive source fixtures. Its expected-findings manifest also *tolerates missing-auth warnings* for some “normal” servers. Therefore, use a control as a negative only for the specific reviewed rule; do not assign all-category clean labels. The runtime-only fixture must remain a separate capability test. [Pinned expected findings](https://github.com/windshock/mcpscan/blob/e696db0ff8f54d3b84307d69c927a000583d6808/runner/expected-findings.json)

**detonate** includes an honest Python MCP server and positive fixtures with explicit locations in `ground-truth.yaml`. It offers useful variations beyond obvious poisoned docstrings. Several labels describe side effects observed during execution; translate only the source-visible subset into this scanner's labels. Keep the six related malicious fixtures in one split family where appropriate. [Pinned corpus documentation](https://github.com/m4vic/detonate/blob/4a54502d2a9ed177028d9a817fd86128d265dc6e/testdata/corpus/README.md), [honest server](https://github.com/m4vic/detonate/blob/4a54502d2a9ed177028d9a817fd86128d265dc6e/testdata/honest/server.py)

### Metadata and runtime additions

**Sentinel** has a readable manifest enumerating all 40 cases and their expected outcomes. Its ten techniques include conditions such as resource exhaustion and runtime schema changes that are not equivalent to the project's 25 static rules. Preserve the original label, store a separate scanner-rule mapping and mark unsupported cases explicitly. [Pinned manifest](https://github.com/Ventrova/sentinel-scan-cli/blob/5cde4b12221178b0ac41213a6b332f9c03fdccc4/fixtures/benchmark/manifest.json)

**fuzzd** is especially useful because the clean descriptions include legitimate operations that contain security-related language. A normal shell-tool description can be an MCP03 negative while its implementation still merits MCP05 review. Its MCPTox-derived attack bank overlaps the project's existing corpus, so that bank was not downloaded again. [Pinned clean descriptions](https://github.com/ksek87/fuzzd/blob/f739e120cd7dc253fead2a1f13668f9535e4d8a5/bench/clean_tools.json)

**mcp-policy-gateway** includes close benign counterparts to attack strings. Some benign response cases intentionally expect sanitization rather than a completely unchanged response. Use that expectation when evaluating a sanitizer; do not convert every benign scenario into “no source finding” ground truth. [Pinned benign cases](https://github.com/mzquadri/mcp-policy-gateway/blob/e15fa0df31cd4a0c38e3dec84ce40fe62c977201/corpus/benign.py)

**mcp-security-preflight** adds safe and mixed business-tool manifests. Its MCP-001-style IDs are its own taxonomy, not this project's MCP01–MCP16 IDs. The selected September report lists 15 findings, even though an earlier web headline mentioned 14; the pinned artifact is authoritative for the selected snapshot. [Pinned results](https://github.com/glatinone/mcp-security-preflight/blob/aa3950cd9891b741c4ae31e6e87a521c1caf0686/benchmark/RESULTS.md)

## 2. Sources already present: useful, but not additional data

| Existing source | Best use | Current limitation |
| --- | --- | --- |
| [Agentinel](https://github.com/markusweldon/agentinel) | Python poison/Unicode positives and four clean source controls | Already part of the seven-source staging manifest; re-downloading adds no independent examples. |
| [allenwu-blip/mcpaudit](https://github.com/allenwu-blip/mcpaudit) | JS vulnerable, clean and borderline fixture projects | Already staged. Review per-rule expectations, especially harmless token-like strings and command lookalikes. |
| [mception](https://github.com/soufianetahiri/mception) | `regex.exec` and method-name negatives versus actual process execution | Already staged; very relevant to MCP05 false positives. |
| [Appsecco vulnerable MCP labs](https://github.com/appsecco/vulnerable-mcp-servers-lab) | Documented Python/JS positive examples | Already downloaded/staged subset; positive-only labs cannot establish FPR. |
| [Damn Vulnerable MCP Server](https://github.com/harishsg993010/damn-vulnerable-MCP-server) | Documented challenges for source-visible attack classes | Seven admitted files already staged; direct-prompt and runtime-only cases need separate handling. |
| [Connor](https://github.com/yiheng98/Connor) | Additional malicious implementations and repository-level benign candidates | Already downloaded; 114 PoCs are structured by attack/path families. Third-party dataset projects may overlap official servers, and labels are not this scanner's exact rules. |
| [MCPTox](https://github.com/zhiqiangwang4/MCPTox-Benchmark) | Tool-poisoning development regressions and extracting benign tool context | Already heavily exposed during development; the paper's 1,312 cases, local 485 files and local 1,348 result instances are distinct units. |
| [MSB](https://github.com/dongsenzhang/MSB) and [MCPSecBench](https://github.com/AIS2Lab/MCPSecBench) | More varied tool/response attacks and runtime research | Already downloaded and partly scanned; framework outcomes are not static source TP/FN labels. |
| [MCP-SafetyBench](https://github.com/xjzzzzzzzz/MCPSafety) | Diverse tasks, tool metadata and realistic benign operation candidates | A 40-artifact subset already has a saved scan; cannot be called an unseen holdout. |
| [Official Python SDK](https://github.com/modelcontextprotocol/python-sdk) / [official servers](https://github.com/modelcontextprotocol/servers) | Authentic benign-operation patterns and parser coverage | Already main-corpus development data. Official origin is not a clean label, and example roots need separate application boundaries. |

Research benchmark context: [MCPTox paper](https://arxiv.org/abs/2508.14925), [MSB paper](https://arxiv.org/abs/2510.15994), [MCPSecBench paper](https://arxiv.org/abs/2508.13220). These papers evaluate agent/host behavior under their own threat models. Their reported success rates are not results for this project.

## 3. Advisory-backed positive/fixed pairs

This is the strongest route to realistic negatives: identify the affected implementation and its actual fix, then label the **specific repaired property** on each side. A newer release is not automatically a clean sample.

| Primary source | Candidate property | What must be checked before admission |
| --- | --- | --- |
| [Official MCP server advisories](https://github.com/modelcontextprotocol/servers/security/advisories) | Git argument injection and path-validation regressions | Whether the exact sink maps to MCP05, or requires a new path-traversal rule. Keep both revisions in one split family. |
| [Chainlit 2.12.0 MCP advisory](https://github.com/Chainlit/chainlit/blob/2.12.0/docs/security-advisory-2026-mcp.md) | stdio command injection and URL-based MCP connection SSRF | These are host/client paths; this scanner focuses on server registrations, so parser/sink support must be tested before scoring misses. |
| [n8n MCP Client SSRF advisory](https://github.com/n8n-io/n8n/security/advisories/GHSA-vhf8-cg2h-cg3p) | Bypass of SSRF protection in user-supplied MCP endpoints | Maintainer lists fixes in 2.31.5 and 2.32.1. Inspect actual patch and TS dependencies; no affected/fixed source pair was acquired in this task. |
| [Excel MCP maintainer advisories](https://github.com/haris-musa/excel-mcp-server/security/advisories) | Source-visible file/network/credential risks; additional availability cases | Some recently published issues concern VBA/ZIP/formula behavior outside current rules. Existing 0.1.7/0.1.8 downloads do not automatically match these advisories. |

No CVE-positive or patched-negative labels were invented from an advisory title. The four routes above are verified research leads; precise patch SHAs, file hashes, compatibility checks and two-person label review remain admission work.

## 4. A false-positive evaluation that can support a degree-project claim

Evaluate **rule-specific negatives**, including both straightforward clean cases and difficult legitimate behavior. The first set of cases should target the false-positive clusters already visible in the project's labels:

| Rule area | Negative behavior to include | Positive counterpart |
| --- | --- | --- |
| MCP01 secrets | Environment-variable *names*, fake placeholders, masked logs, test tokens | Actual secret literal or sensitive value returned to callers |
| MCP03 metadata | Honest file/email/shell tool descriptions, documentation URLs, quoted attacks, human installation instructions | Description that directs a model to override intent or perform an unrelated privileged action |
| MCP04 dependencies | Python compatibility metadata and non-executable documentation URLs | Mutable executable dependency or unsafe install hook |
| MCP05 execution | `regex.exec`, ordinary methods named `exec`, argument arrays, validated enumerations | Untrusted input reaching a shell or dynamic interpreter |
| MCP06 content | Structured output and explicit trust boundaries, benign quoted security guidance | Untrusted external text passed into model context without the reviewed boundary |
| MCP07 auth | stdio-only tools, client modules, imported and enforced middleware | Exposed network server with the specific control absent |
| MCP09 names | Same tool name in independent applications | Confusable registrations within one application |
| MCP10 state | Immutable TTL/config constants and properly scoped caches | User/context data shared across unauthorized sessions |
| MCP11/12/15 OAuth | Per-client approval, proper audience separation, validated auth URLs | Matched cases missing the specific protection |
| MCP13 SSRF | Fixed origin with user-controlled query, validated destinations | User-controlled host reaching a network sink |
| MCP14 sessions | Cryptographically generated, identity-bound session handles | Predictable/unbound handle used as authorization |
| MCP16 startup | Pinned, intended local process configuration | Untrusted executable/arguments crossing the startup boundary |

These are **proposed coverage requirements**, not a claim that the downloaded sources satisfy every row. The existing staged set has only 20 negative labels across seven rules, and no MCP06 negatives. Fill those gaps before making broad claims.

Recommended design: reserve independent repository families for the final set; balance positives and negatives **within each evaluated rule**; include multiple benign styles; and record `unknown/unsupported` explicitly. For common, high-risk rules, aim for at least 100 independently reviewed negative units if feasible. Even zero false positives in 100 independent negatives permits a one-sided 95% FPR bound of roughly 3%; correlated fixtures weaken that inference.

Use `FPR = FP/(FP+TN)` for a declared negative sampling unit. Use `precision = TP/(TP+FP)` and `recall = TP/(TP+FN)` with the same declared prediction/label unit. Do not use emitted-warning counts as the FPR denominator. Include parse/runtime failures separately and publish the scoring policy before the final run.

## 5. Admission and provenance

Each accepted case needs: source URL, full revision, original path, SHA-256, license/provenance, upstream label, exact local rule ID, polarity, rationale, source span, application boundary, language, adapter status, reviewer, review date, family ID and split. Unknown fields remain unknown.

For the six downloaded sources, immutable URLs and hashes are already recorded. Label quality, semantic duplication and mapping to this scanner still need review. Metadata adapters must preserve strings and schemas; wrapping every description in a fabricated Python server changes the experiment and must be documented. Runtime traces should stay in a separate benchmark until supported.

An exact-byte comparison of the new artifacts against existing source/configuration files found no matches (`new_sample_overlap.json`). This narrow check does not exclude paraphrases, shared upstream families, adapted examples or overlap inside multi-record JSON files.

License metadata is confirmed only as shown above; it is not a legal assessment. Existing license files were retained when located. Resolve missing license provenance before redistributing the fuzzd/preflight snapshots in a public submission package. No third-party code needs to run to complete source labeling.

The original staging manifest was left unchanged. The downloaded candidates are not assigned to training or final testing yet; finalize group splits before using scanner outcomes to select or discard cases.
