"""Build a conservative, file-level public candidate inventory without scanning code."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXT = ROOT / "evaluation" / "corpus-external"
OUT = ROOT / "evaluation" / "holdout"

SOURCES = {
    "agentinel": ("curate-agentinel", "https://github.com/markusweldon/agentinel", "daaede15274643040d79326a1e6626f710e4b042"),
    "allen-mcpaudit": ("curate-allen-mcpaudit", "https://github.com/allenwu-blip/mcpaudit", "b9ec7aa6d86497a02932dce314ccaac93b66feb8"),
    "appsecco-labs": ("curate-appsecco", "https://github.com/appsecco/vulnerable-mcp-servers-lab", "47b7f2082261136b667daa7be9273698e66e479e"),
    "dvmcp": ("curate-dvmcp", "https://github.com/harishsg993010/damn-vulnerable-MCP-server", "79734c19f5104cd11486c90926d245560f53befa"),
    "mception": ("curate-mception", "https://github.com/soufianetahiri/mception", "45bbd1a5a73aea8bd26663569c059b9ab371717b"),
    "sachin-mcpaudit": ("curate-sachin-mcpaudit", "https://github.com/sachinML/MCPAudit", "2bbaa163e93935e61c8b3adb84ae5b8b76a22c35"),
    "glatinone-mcpscan": ("curate-glatinone-mcpscan", "https://github.com/glatinone/mcpscan", "3878ab808912d68d0625f6c24c9d80d67412422c"),
}

# path -> [(rule, polarity, rationale)]. Only explicit maintainer fixture/docs
# mappings that exactly overlap our stable rules are admitted.
ITEMS = {
    "agentinel": {
        "fixtures/vulnerable/poisoned_server.py": [("MCP03-TOOL-POISON", "positive", "Maintainer's poisoned-server fixture.")],
        "fixtures/vulnerable/unicode_smuggle_server.py": [("MCP03-TOOL-POISON", "positive", "Maintainer labels invisible/bidi metadata as tool poisoning.")],
        **{f"fixtures/clean/{name}": [("MCP03-TOOL-POISON", "negative", "Maintainer clean-control server; tool-poisoning regression expects no finding.")]
           for name in ("comms_only_server.py", "echo_server.py", "fetch_only_server.py", "files_only_server.py")},
    },
    "allen-mcpaudit": {
        "test/fixtures/vulnerable-server/src/index.js": [
            ("MCP01-SECRET-HARDCODED", "positive", "Fixture comment and test label a realistic hard-coded token."),
            ("MCP01-SECRET-OUTPUT", "positive", "Fixture explicitly returns process.env to tool output."),
            ("MCP05-COMMAND-INJECTION", "positive", "Fixture labels interpolated tool input reaching child_process.exec."),
            ("MCP05-DYNAMIC-CODE", "positive", "Fixture labels tool input reaching eval/vm execution."),
            ("MCP13-SSRF", "positive", "Fixture labels fully attacker-controlled fetch destination."),
        ],
        **{f"test/fixtures/{kind}-server/src/index.js": [
            (rule, "negative", f"Maintainer {kind} fixture is asserted to produce zero findings, including the mapped rule.")
            for rule in ("MCP01-SECRET-HARDCODED", "MCP01-SECRET-OUTPUT", "MCP05-COMMAND-INJECTION", "MCP05-DYNAMIC-CODE", "MCP13-SSRF")]
           for kind in ("clean", "borderline")},
    },
    "appsecco-labs": {
        "vulnerable-mcp-server-filesystem-workspace-actions/vulnerable-mcp-server-filesystem-workspace-actions-mcp.py": [("MCP05-DYNAMIC-CODE", "positive", "Per-server documentation labels unsandboxed Python execution.")],
        "vulnerable-mcp-server-indirect-prompt-injection/index.js": [("MCP06-UNTRUSTED-CONTEXT", "positive", "Per-server documentation labels verbatim untrusted document injection.")],
        "vulnerable-mcp-server-indirect-prompt-injection-remote-mcp/index.js": [("MCP06-UNTRUSTED-CONTEXT", "positive", "Per-server documentation labels remote untrusted document injection.")],
        "vulnerable-mcp-server-malicious-code-exec/index.js": [("MCP05-DYNAMIC-CODE", "positive", "Per-server documentation labels attacker-controlled eval execution.")],
        "vulnerable-mcp-server-malicious-tools/index.js": [("MCP03-TOOL-POISON", "positive", "Per-server documentation labels malicious tool instructions/fabricated behavior.")],
        "vulnerable-mcp-server-namespace-typosquatting/index.js": [("MCP09-CONFUSABLE-NAME", "positive", "Per-server documentation labels a deliberately confusable MCP namespace.")],
        "vulnerable-mcp-server-secrets-pii/index.js": [("MCP01-SECRET-HARDCODED", "positive", "Per-server documentation labels embedded secrets/PII."), ("MCP01-SECRET-OUTPUT", "positive", "Per-server documentation labels leakage through logs/tool behavior.")],
        "vulnerable-mcp-server-wikipedia-http-streamable/wikipedia-mcp.py": [("MCP06-UNTRUSTED-CONTEXT", "positive", "Per-server documentation labels unsanitized public content entering agent context.")],
    },
    "dvmcp": {
        "challenges/easy/challenge2/server.py": [("MCP03-TOOL-POISON", "positive", "Challenge 2 is explicitly Tool Poisoning.")],
        "challenges/easy/challenge3/server.py": [("MCP02-BROAD-SCOPE", "positive", "Challenge 3 explicitly demonstrates excessive permission scope.")],
        "challenges/medium/challenge5/server.py": [("MCP09-CONFUSABLE-NAME", "positive", "Challenge 5 explicitly demonstrates tool shadowing/name conflict.")],
        "challenges/medium/challenge6/server.py": [("MCP06-UNTRUSTED-CONTEXT", "positive", "Challenge 6 explicitly demonstrates indirect prompt injection through external data.")],
        "challenges/medium/challenge7/server.py": [("MCP01-SECRET-OUTPUT", "positive", "Challenge 7 explicitly demonstrates token theft through server behavior.")],
        "challenges/hard/challenge8/server.py": [("MCP05-DYNAMIC-CODE", "positive", "Challenge 8 explicitly demonstrates arbitrary code execution.")],
        "challenges/hard/challenge9/server.py": [("MCP05-COMMAND-INJECTION", "positive", "Challenge 9 explicitly documents unvalidated input passed to system commands.")],
    },
    "mception": {
        "tests/fixtures/servers/node_figma_plugin/code.js": [("MCP05-DYNAMIC-CODE", "positive", "expected.json requires NODE-CMDI-002 dynamic execution." )],
        "tests/fixtures/servers/node_real_exec/src/index.js": [("MCP05-COMMAND-INJECTION", "positive", "expected.json requires critical NODE-CMDI-001." )],
        "tests/fixtures/servers/node_regex_exec/src/index.js": [("MCP05-COMMAND-INJECTION", "negative", "expected.json explicitly forbids command-injection finding for regex.exec." )],
        "tests/fixtures/servers/python_method_exec/mcp_server.py": [("MCP05-COMMAND-INJECTION", "negative", "expected.json explicitly forbids command-injection finding for a method named exec." )],
        "tests/fixtures/servers/python_subprocess/mcp_server.py": [("MCP05-COMMAND-INJECTION", "positive", "expected.json requires critical Python subprocess command injection." )],
    },
    "sachin-mcpaudit": {
        "tests/fixtures/behavioral-eval/data/fake_encrypt/server.py": [("MCP03-TOOL-POISON", "positive", "Behavior fixture deliberately contradicts the advertised AES encryption behavior." )],
        "tests/fixtures/behavioral-eval/data/benign_add/server.py": [("MCP03-TOOL-POISON", "negative", "Behavior fixture is the explicit benign description/implementation control." )],
    },
    "glatinone-mcpscan": {
        "tests/fixtures/vulnerable/server.py": [
            ("MCP05-COMMAND-INJECTION", "positive", "Fixture explicitly labels interpolated shell command sinks."),
            ("MCP13-SSRF", "positive", "Fixture explicitly labels tool-controlled outbound request."),
            ("MCP07-PERMISSIVE-BIND", "positive", "Fixture explicitly labels unauthenticated all-interface bind."),
        ],
        "tests/fixtures/clean/server.py": [
            ("MCP05-COMMAND-INJECTION", "negative", "Clean fixture uses argument arrays without a shell."),
            ("MCP13-SSRF", "negative", "Clean fixture has no attacker-controlled outbound destination."),
            ("MCP07-PERMISSIVE-BIND", "negative", "Clean fixture binds locally and authenticates process spawning."),
        ],
    },
}

REJECTIONS = [
    {"source": "Connor", "count": 134, "reason": "Only corpus-level benign/malicious labels; 114 PoCs lack exact MCP01-MCP16 rule labels and 20 dataset servers include third-party overlap."},
    {"source": "CrossMCP-Bench", "count": 277, "reason": "Runtime authorization traces, not static source artifacts."},
    {"source": "mcpsec runtime cases", "count": 64, "reason": "Gateway runtime tests requiring a different analyzer adapter."},
    {"source": "three unverified Hugging Face sets", "count": 186, "reason": "Schema/provenance or static-source compatibility is not yet verified."},
    {"source": "Appsecco outdated-packages lab", "count": 1, "reason": "Known-vulnerable pinned dependencies do not match our mutable-dependency rule."},
    {"source": "DVMCP challenges 1, 4, and 10", "count": 3, "reason": "Direct user prompt injection, runtime rug pull, or multi-vector label is not an exact single static rule label."},
]


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    sources, artifacts, labels, records = [], [], [], []
    seen_hashes: dict[str, str] = {}
    duplicates = []
    for source_id, entries in ITEMS.items():
        dirname, url, revision = SOURCES[source_id]
        source = {"id": source_id, "kind": "git", "url": url, "revision": revision}
        sources.append(source)
        for relative, mapped in entries.items():
            path = EXT / dirname / relative
            if not path.is_file():
                raise FileNotFoundError(path)
            sha = digest(path)
            artifact_id = source_id + "--" + relative.replace("/", "--").replace(".", "-")
            if sha in seen_hashes:
                duplicates.append({"duplicate": artifact_id, "canonical": seen_hashes[sha]})
                continue
            seen_hashes[sha] = artifact_id
            artifact = {"id": artifact_id, "source_id": source_id, "path": relative, "sha256": sha}
            artifacts.append(artifact)
            item_labels = [{"artifact_id": artifact_id, "rule_id": rule, "polarity": polarity,
                            "provenance": "maintainer-fixture", "rationale": rationale}
                           for rule, polarity, rationale in mapped]
            labels.extend(item_labels)
            records.append({"source": source, "artifact": artifact, "labels": item_labels})
    inventory = {
        "schema_version": 1,
        "created_at": "2026-08-20",
        "definition": "One sample is one unique source artifact with at least one explicit mapped rule label.",
        "accepted": {"sources": sources, "artifacts": artifacts, "labels": labels},
        "rejected_or_deferred": REJECTIONS,
        "duplicates": duplicates,
        "summary": {
            "sources": len(sources), "unique_samples": len(artifacts), "labels": len(labels),
            "positive_labels": sum(x["polarity"] == "positive" for x in labels),
            "negative_labels": sum(x["polarity"] == "negative" for x in labels),
            "by_rule": dict(sorted(Counter(x["rule_id"] for x in labels).items())),
            "positive_by_rule": dict(sorted(Counter(x["rule_id"] for x in labels if x["polarity"] == "positive").items())),
            "negative_by_rule": dict(sorted(Counter(x["rule_id"] for x in labels if x["polarity"] == "negative").items())),
        },
    }
    (OUT / "curated-public-inventory.json").write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
    (OUT / "candidates.jsonl").write_text("".join(json.dumps(x) + "\n" for x in records), encoding="utf-8")
    summary = inventory["summary"]
    rules = sorted(set(summary["positive_by_rule"]) | set(summary["negative_by_rule"]))
    report = [
        "# Curated public MCP security data inventory", "",
        "No scanner was invoked while producing this inventory. A sample is one unique, pinned source artifact with at least one explicit maintainer/benchmark label mapped to a stable scanner rule.", "",
        f"- Accepted sources: {summary['sources']}",
        f"- Unique static samples: {summary['unique_samples']}",
        f"- Rule labels: {summary['labels']} ({summary['positive_labels']} positive, {summary['negative_labels']} negative)", "",
        "| Rule | Positive | Negative | Total |", "|---|---:|---:|---:|",
    ]
    for rule in rules:
        positive = summary["positive_by_rule"].get(rule, 0)
        negative = summary["negative_by_rule"].get(rule, 0)
        report.append(f"| {rule} | {positive} | {negative} | {positive + negative} |")
    report.extend(["", "## Rejected or deferred", "", "| Source | Count | Reason |", "|---|---:|---|"])
    report.extend(f"| {row['source']} | {row['count']} | {row['reason']} |" for row in REJECTIONS)
    (OUT / "CURATED_INVENTORY.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    print(json.dumps(inventory["summary"], indent=2))


if __name__ == "__main__":
    main()
