"""Summarize saved results without scanning corpora or consuming a reserve."""
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "deliverables"
COUNTS = ("tp", "fp", "fn", "tn", "errors")


def measures(counts):
    tp, fp, fn, tn = (counts[k] for k in COUNTS[:4])
    ratio = lambda a, b: a / b if b else None
    return {**counts, "labels": tp + fp + fn + tn,
            "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
            "f1": ratio(2 * tp, 2 * tp + fp + fn),
            "false_positive_rate": ratio(fp, fp + tn),
            "miss_rate": ratio(fn, tp + fn), "specificity": ratio(tn, tn + fp),
            "accuracy": ratio(tp + tn, tp + fp + fn + tn)}


def summarize():
    inputs = {}

    def read(rel):
        data = (ROOT / rel).read_bytes()
        inputs[rel] = hashlib.sha256(data).hexdigest()
        return json.loads(data)

    working = read("evaluation/followup/working-regressions.json")
    totals = Counter({k: 0 for k in COUNTS})
    categories = defaultdict(lambda: Counter({k: 0 for k in COUNTS}))
    hashes, scopes, rules = set(), set(), set()
    scope_functions = defaultdict(set)
    rounds = []
    for n in range(1, 11):
        manifest_path = f"evaluation/iterations/iteration-{n:03}/manifest.json"
        manifest = read(manifest_path)
        metrics = working[str(n)]["metrics"]
        predictions = working[str(n)]["predictions"]
        decision_counts = Counter(row["outcome"] for row in metrics["decisions"])
        counts = {k: metrics["micro"][k] for k in COUNTS}
        assert counts == {k: decision_counts[k] for k in COUNTS}
        labels = 0
        expected = set()
        for artifact in manifest["artifacts"]:
            digest = artifact["sha256"].removeprefix("sha256:")
            assert digest not in hashes, "Repeated artifact bytes: do not silently pool"
            hashes.add(digest)
            for label in artifact["labels"]:
                function = label.get("function_name")
                scope = (digest, label["rule_id"], function)
                assert scope not in scopes, "Repeated label scope"
                scopes.add(scope)
                scope_functions[scope[:2]].add(function)
                rules.add(label["rule_id"])
                expected.add((artifact["id"], label["rule_id"], function, label["polarity"]))
                labels += 1
        actual = {(d["artifact_id"], d["rule_id"], d.get("function_name"), d["polarity"])
                  for d in metrics["decisions"]}
        assert actual == expected
        assert labels == sum(counts.values())
        assert len(predictions) == len(manifest["artifacts"])
        assert all(p["status"] == "completed" for p in predictions)
        by_id = {p["artifact_id"]: p for p in predictions}
        assert len(by_id) == len(predictions)
        for decision in metrics["decisions"]:
            findings = by_id[decision["artifact_id"]]["findings"]
            hit = any(f["rule_id"] == decision["rule_id"] and
                      (decision.get("function_name") is None or
                       f.get("function_name") == decision["function_name"])
                      for f in findings)
            outcome = ("tp" if hit else "fn") if decision["polarity"] == "positive" else ("fp" if hit else "tn")
            assert outcome == decision["outcome"]
        totals.update(counts)
        for cat, values in metrics["by_category"].items():
            categories[cat].update({k: values[k] for k in COUNTS})
        rounds.append({"round": n, "manifest": manifest_path,
                       "artifacts": len(manifest["artifacts"]), **measures(counts),
                       "unscored_predictions": len(metrics["unscored_predictions"])})
    assert all(None not in functions or len(functions) == 1
               for functions in scope_functions.values()), "Overlapping whole-artifact/function labels"
    assert all(sum(c[k] for c in categories.values()) == totals[k] for k in COUNTS)
    original = read("evaluation/holdout/metrics.json")
    reserve = read("evaluation/followup/final/results/metrics.json")
    historical = []
    for n in (2, 3, 4):
        path = f"evaluation/iterations/iteration-{n:03}/runs/frozen-validation/metrics.json"
        result = read(path)
        historical.append({"round": n, "source": path,
                           **measures({k: result["micro"][k] for k in COUNTS}),
                           "unscored_predictions": len(result["unscored_predictions"])})
    return {
        "snapshot_date": "2026-10-17",
        "scope": "Final frozen scanner on exposed development manifests 001-010; labeled scope only",
        "unit": "artifact bytes + rule + optional function; not independent incidents",
        "development": {**measures(dict(totals)), "artifacts": len(hashes),
                        "unique_label_scopes": len(scopes), "categories": len(categories),
                        "rules": len(rules),
                        "unscored_predictions": sum(r["unscored_predictions"] for r in rounds)},
        "rounds": rounds,
        "by_category": {k: measures(dict(v)) for k, v in sorted(categories.items())},
        "original_reserved": {**measures({k: original["micro"][k] for k in COUNTS}),
                              "unscored_predictions": len(original["unscored_predictions"])},
        "new_reserved": {**measures({k: reserve["micro"][k] for k in COUNTS}),
                         "unscored_predictions": len(reserve["unscored_predictions"])},
        "historical_frozen_batches": historical,
        "limitations": ["Exposed development data; not an unseen-performance estimate",
                        "Adapted and synthetic records, related source families, and selected labels",
                        "Unscored predictions excluded; independent human label review pending",
                        "Original reserve is also round 008: never add it to development totals twice"],
        "input_sha256": inputs,
    }


if __name__ == "__main__":
    summary = summarize()
    (OUT / "final_project_metrics.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    fields = ["round", "artifacts", "labels", *COUNTS, "precision", "recall", "f1",
              "false_positive_rate", "unscored_predictions"]
    with (OUT / "final_project_rounds.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(summary["rounds"])
    print(json.dumps(summary["development"], indent=2))
