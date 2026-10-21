"""Apply the documented manual-review decisions to every real-corpus finding."""

from __future__ import annotations

import csv
import glob
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "evaluation" / "raw-results"
LABELS = ROOT / "evaluation" / "labels"


def decision(finding: dict) -> tuple[str, str]:
    rule = finding["rule_id"]
    path = finding["file_path"].replace("\\", "/").lower()
    matched = str(finding.get("matched_text") or "")

    if rule == "MCP04-MUTABLE-DEPENDENCY":
        if matched.startswith("requires-python"):
            return "FP", "Python interpreter compatibility is not an executable dependency pin."
        return "TP", "The manifest permits a dependency version range or unpinned package."
    if rule == "MCP09-UNMANAGED-SERVER":
        if '"command": "uvx"' in matched:
            return "TP", "The MCP configuration launches an unpinned uvx package."
        return "FP", "A project/documentation URL containing main is not an MCP startup registration."
    if rule == "MCP09-CONFUSABLE-NAME":
        return "Needs context", "The names collide only when independently deployable examples/modules are aggregated into one scan root."
    if rule == "MCP03-TOOL-POISON":
        return "FP", "Reviewed metadata is functional documentation, an example URL, validation text, or benign tool guidance—not a hidden instruction."
    if rule == "MCP06-UNTRUSTED-CONTEXT":
        if finding.get("function_name") == "read_file":
            return "TP", "A tool returns file content to model context without a visible content trust boundary."
        return "Needs context", "The value is external/user elicitation data, but exploitability depends on how the host treats structured output."
    if rule == "MCP07-PERMISSIVE-BIND":
        return "TP", "The example binds broadly without authentication visible in the scanned artifact."
    if rule == "MCP07-MISSING-AUTH":
        if any(token in path for token in ("/clients/", "auth0", "authkit", "simple-auth")):
            return "FP", "The file is a client or an authentication example; file-local keyword matching loses surrounding auth context."
        return "Needs context", "A network transport is visible, but this example may be local/demo-only or protected by deployment middleware."
    if rule == "MCP08-MISSING-AUDIT":
        return "TP", "The tool performs file access with no audit telemetry visible in its implementation."
    if rule in {"MCP10-SHARED-CONTEXT", "MCP10-OVER-SHARING"}:
        return "FP", "The matched object is cache/configuration/process state, not demonstrated cross-user model context."
    if rule == "MCP13-SSRF":
        if "official-servers/src/fetch" in path:
            return "TP", "Tool-controlled URL reaches the Fetch server's HTTP helper without host or private-address restrictions."
        return "FP", "Manual data-flow review shows a fixed AWS API destination; tool input is query/body data rather than the destination host."
    if rule in {"MCP11-CONFUSED-DEPUTY", "MCP15-UNSAFE-AUTH-URL"}:
        return "FP", "The heuristic is file-local/textual; reviewed examples include state or fixed provider URLs and do not show the reported flow."
    if rule in {"MCP01-SECRET-OUTPUT", "MCP01-SECRET-HARDCODED"}:
        return "FP", "The broad text match hits example/auth variable handling; no real embedded or emitted credential was shown."
    return "Needs context", "No reliable static conclusion after source review."


def main() -> None:
    LABELS.mkdir(parents=True, exist_ok=True)
    rows = []
    for filename in sorted(glob.glob(str(RESULTS / "*.json"))):
        path = Path(filename)
        if path.name == "summary.json" or path.name.startswith("fixture-"):
            continue
        report = json.loads(path.read_text(encoding="utf-8"))
        for index, finding in enumerate(report["findings"], 1):
            label, rationale = decision(finding)
            rows.append({
                "target": path.stem,
                "finding_index": index,
                "label": label,
                "rule_id": finding["rule_id"],
                "file": finding["file_path"],
                "line": finding["line_number"],
                "function": finding.get("function_name") or "",
                "matched_text": finding.get("matched_text") or "",
                "rationale": rationale,
            })
    with (LABELS / "finding-labels.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    counts = Counter(row["label"] for row in rows)
    conclusive = counts["TP"] + counts["FP"]
    metrics = {
        "findings_reviewed": len(rows),
        "labels": dict(counts),
        "precision_on_conclusive_labels": counts["TP"] / conclusive if conclusive else None,
        "contextual_rate": counts["Needs context"] / len(rows) if rows else None,
        "method": "Finding-level manual source review encoded as repeatable decisions; contextual findings are excluded from precision.",
    }
    (LABELS / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
