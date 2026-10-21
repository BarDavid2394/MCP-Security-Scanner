"""Score consumed holdout results against explicit positive and negative labels."""

from __future__ import annotations

import json
from collections import defaultdict

from holdout_common import CONSUMED, RESULTS, ROOT, verify_frozen


def ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def main() -> int:
    data, fingerprint = verify_frozen()
    if not CONSUMED.exists():
        raise SystemExit("Holdout has not been consumed")
    consumed = json.loads(CONSUMED.read_text(encoding="utf-8"))
    if consumed.get("manifest_fingerprint") != fingerprint:
        raise SystemExit("Consumed record does not match frozen manifest")
    if consumed.get("status") != "completed" or not consumed.get("code_unchanged"):
        raise SystemExit("Holdout run is incomplete or its code changed")

    expected = {(x["artifact_id"], x["rule_id"]): x["polarity"] for x in data["labels"]}
    predicted = set()
    failed = set()
    for artifact in data["artifacts"]:
        report = json.loads((RESULTS / f"{artifact['id']}.json").read_text(encoding="utf-8"))
        info = report.get("scan_info", {})
        if info.get("parse_errors") or not info.get("files_scanned"):
            failed.add(artifact["id"])
        predicted.update((artifact["id"], f["rule_id"]) for f in report["findings"] if f.get("rule_id"))

    rules = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "errors": 0, "unscored_predictions": 0})
    decisions = []
    for key, polarity in expected.items():
        aid, rule = key
        hit = key in predicted
        bucket = rules[rule]
        if aid in failed:
            outcome = "errors"
        elif polarity == "positive":
            outcome = "tp" if hit else "fn"
        else:
            outcome = "fp" if hit else "tn"
        bucket[outcome] += 1
        decisions.append(dict(artifact_id=aid, rule_id=rule, polarity=polarity, outcome=outcome))
    for aid, rule in predicted:
        if (aid, rule) not in expected:
            rules[rule]["unscored_predictions"] += 1

    output = {"manifest_fingerprint": fingerprint, "rules": {}, "decisions": decisions,
              "unscored_predictions": [dict(artifact_id=a, rule_id=r) for a,r in sorted(predicted - set(expected))]}
    totals = {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "errors": 0}
    for rule, counts in sorted(rules.items()):
        for key in totals:
            totals[key] += counts[key]
        output["rules"][rule] = {
            **counts,
            "precision": ratio(counts["tp"], counts["tp"] + counts["fp"]),
            "recall": ratio(counts["tp"], counts["tp"] + counts["fn"]),
        }
    output["micro"] = {
        **totals,
        "precision": ratio(totals["tp"], totals["tp"] + totals["fp"]),
        "recall": ratio(totals["tp"], totals["tp"] + totals["fn"]),
        "false_positive_rate": ratio(totals["fp"], totals["fp"] + totals["tn"]),
        "label_coverage": ratio(sum(totals.values())-totals["errors"], sum(totals.values())),
    }
    destination = ROOT / "evaluation" / "holdout" / "metrics.json"
    destination.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
