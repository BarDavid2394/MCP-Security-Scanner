"""Validate mappings and deduplicate staged holdout records without scanning code."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from holdout_common import HOLDOUT, validate


def dedupe_key(artifact: dict) -> tuple:
    """Prefer immutable content identity; fall back to pinned source/path."""
    return (
        artifact.get("sha256") or "",
        artifact.get("source_id"),
        artifact.get("path"),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=str(HOLDOUT / "candidates.jsonl"))
    parser.add_argument("--output", default=str(HOLDOUT / "staging-manifest.json"))
    args = parser.parse_args()
    records = [json.loads(line) for line in Path(args.input).read_text(encoding="utf-8").splitlines() if line.strip()]

    sources = {}
    artifacts = {}
    labels = {}
    duplicates = []
    for record in records:
        source = record["source"]
        artifact = record["artifact"]
        source_id, artifact_id = source["id"], artifact["id"]
        if source_id in sources and sources[source_id] != source:
            raise SystemExit(f"Conflicting source definitions: {source_id}")
        sources[source_id] = source
        key = dedupe_key(artifact)
        existing = next((x for x in artifacts.values() if dedupe_key(x) == key), None)
        canonical_id = existing["id"] if existing else artifact_id
        if existing and canonical_id != artifact_id:
            duplicates.append({"duplicate": artifact_id, "canonical": canonical_id})
        else:
            artifacts[artifact_id] = artifact
        for label in record["labels"]:
            normalized = {**label, "artifact_id": canonical_id}
            label_key = (canonical_id, label["rule_id"], label["polarity"])
            labels[label_key] = normalized

    data = {
        "schema_version": 1,
        "state": "staging",
        "created_at": "2026-08-20",
        "catalog_version": "2026.1",
        "safety_policy": "Download and inspect provenance only. Never install, import, execute, or scan before the holdout is explicitly consumed.",
        "sources": sorted(sources.values(), key=lambda x: x["id"]),
        "artifacts": sorted(artifacts.values(), key=lambda x: x["id"]),
        "labels": sorted(labels.values(), key=lambda x: (x["rule_id"], x["artifact_id"], x["polarity"])),
    }
    errors = validate(data, frozen=False)
    polarities = defaultdict(set)
    for label in data["labels"]:
        polarities[(label["artifact_id"], label["rule_id"])].add(label["polarity"])
    conflicts = [key for key, values in polarities.items() if len(values) > 1]
    if conflicts:
        errors.append(f"positive/negative label conflicts: {conflicts}")
    if errors:
        raise SystemExit("Curation failed:\n- " + "\n- ".join(errors))
    Path(args.output).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    report = {
        "sources": len(data["sources"]), "artifacts": len(data["artifacts"]),
        "labels": len(data["labels"]), "duplicates": duplicates,
        "by_rule": dict(sorted(Counter(x["rule_id"] for x in data["labels"]).items())),
        "by_polarity": dict(Counter(x["polarity"] for x in data["labels"])),
    }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

