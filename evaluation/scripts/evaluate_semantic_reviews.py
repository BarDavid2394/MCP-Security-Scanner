#!/usr/bin/env python3
"""Compare advisory semantic reviews with finding-level human labels."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path


EXPECTED_VERDICT = {
    "TP": "LIKELY",
    "FP": "UNLIKELY",
    "Needs context": "NEEDS_CONTEXT",
}


def load_labels(path: Path, target: str) -> dict[int, dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return {
            int(row["finding_index"]): row
            for row in csv.DictReader(handle)
            if row["target"] == target
        }


def evaluate(report: dict, labels: dict[int, dict[str, str]]) -> dict:
    rows = []
    for index, finding in enumerate(report.get("findings", []), start=1):
        review = (finding.get("metadata") or {}).get("llm_review")
        if not review:
            continue
        label = labels.get(index, {}).get("label", "UNLABELED")
        verdict = review.get("verdict", "MISSING")
        rows.append({
            "finding_index": index,
            "rule_id": finding.get("rule_id"),
            "label": label,
            "verdict": verdict,
            "confidence": review.get("confidence"),
            "cached": bool(review.get("cached")),
            "agreement": EXPECTED_VERDICT.get(label) == verdict,
        })

    decisive = [
        row for row in rows
        if row["label"] in {"TP", "FP"} and row["verdict"] in {"LIKELY", "UNLIKELY"}
    ]
    return {
        "reviewed": len(rows),
        "labeled": sum(row["label"] != "UNLABELED" for row in rows),
        "cached": sum(row["cached"] for row in rows),
        "label_counts": dict(Counter(row["label"] for row in rows)),
        "verdict_counts": dict(Counter(row["verdict"] for row in rows)),
        "exact_agreement": sum(row["agreement"] for row in rows),
        "exact_agreement_rate": (
            sum(row["agreement"] for row in rows) / len(rows) if rows else None
        ),
        "decisive_reviews": len(decisive),
        "decisive_agreement": sum(row["agreement"] for row in decisive),
        "decisive_agreement_rate": (
            sum(row["agreement"] for row in decisive) / len(decisive) if decisive else None
        ),
        "false_negatives": sum(
            row["label"] == "TP" and row["verdict"] == "UNLIKELY" for row in rows
        ),
        "false_positive_endorsements": sum(
            row["label"] == "FP" and row["verdict"] == "LIKELY" for row in rows
        ),
        "review_failures": sum(row["verdict"] == "INSUFFICIENT_EVIDENCE" for row in rows),
        "reviews": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="Scanner JSON report with llm_review metadata")
    parser.add_argument("--target", required=True, help="Target name in finding-labels.csv")
    parser.add_argument(
        "--labels", type=Path,
        default=Path(__file__).resolve().parents[1] / "labels" / "finding-labels.csv",
    )
    parser.add_argument("--output", type=Path, help="Optional metrics JSON output path")
    args = parser.parse_args()

    report = json.loads(args.report.read_text(encoding="utf-8"))
    result = evaluate(report, load_labels(args.labels, args.target))
    rendered = json.dumps(result, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
