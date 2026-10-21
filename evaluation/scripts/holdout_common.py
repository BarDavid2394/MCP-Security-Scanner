"""Shared validation and fingerprinting for the clean holdout."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HOLDOUT = ROOT / "evaluation" / "holdout"
FROZEN = HOLDOUT / "frozen-manifest.json"
LOCK = HOLDOUT / "frozen-manifest.sha256"
CORPUS = ROOT / "evaluation" / "holdout-corpus"
RESULTS = ROOT / "evaluation" / "holdout-results"
CONSUMED = HOLDOUT / "CONSUMED.json"

RULE_RE = re.compile(r"^MCP(?:0[1-9]|1[0-6])-[A-Z0-9-]+$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def canonical_bytes(data: dict) -> bytes:
    return (json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def fingerprint(data: dict) -> str:
    return hashlib.sha256(canonical_bytes(data)).hexdigest()


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate(data: dict, *, frozen: bool = False) -> list[str]:
    errors: list[str] = []
    if data.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    expected_state = "frozen" if frozen else "staging"
    if data.get("state") != expected_state:
        errors.append(f"state must be {expected_state!r}")

    sources = data.get("sources")
    artifacts = data.get("artifacts")
    labels = data.get("labels")
    if not isinstance(sources, list) or not isinstance(artifacts, list) or not isinstance(labels, list):
        return errors + ["sources, artifacts, and labels must be arrays"]

    source_ids = set()
    for source in sources:
        sid = source.get("id")
        if not sid or sid in source_ids:
            errors.append(f"missing or duplicate source id: {sid!r}")
        source_ids.add(sid)
        if source.get("kind") == "git" and not SHA_RE.fullmatch(str(source.get("revision", ""))):
            errors.append(f"git source {sid!r} requires a 40-character revision")
        if source.get("kind") not in {"git", "archive"}:
            errors.append(f"source {sid!r} kind must be git or archive")

    artifact_ids = set()
    for artifact in artifacts:
        aid = artifact.get("id")
        if not aid or aid in artifact_ids:
            errors.append(f"missing or duplicate artifact id: {aid!r}")
        artifact_ids.add(aid)
        if artifact.get("source_id") not in source_ids:
            errors.append(f"artifact {aid!r} references unknown source")
        if not artifact.get("path"):
            errors.append(f"artifact {aid!r} requires a path")
        if frozen and not HASH_RE.fullmatch(str(artifact.get("sha256", ""))):
            errors.append(f"frozen artifact {aid!r} requires sha256:<64 hex>")

    label_keys = set()
    scoped_polarities = {}
    for label in labels:
        key = (label.get("artifact_id"), label.get("rule_id"), label.get("polarity"))
        if key in label_keys:
            errors.append(f"duplicate label: {key!r}")
        label_keys.add(key)
        scope = (label.get("artifact_id"), label.get("rule_id"))
        prior = scoped_polarities.setdefault(scope, label.get("polarity"))
        if prior != label.get("polarity"):
            errors.append(f"conflicting polarities for {scope!r}")
        if label.get("artifact_id") not in artifact_ids:
            errors.append(f"label references unknown artifact: {key!r}")
        if not RULE_RE.fullmatch(str(label.get("rule_id", ""))):
            errors.append(f"invalid rule id: {label.get('rule_id')!r}")
        if label.get("polarity") not in {"positive", "negative"}:
            errors.append(f"invalid polarity: {label.get('polarity')!r}")
        if label.get("provenance") not in {"reviewed-advisory", "benchmark", "maintainer-fixture", "manual-review"}:
            errors.append(f"invalid provenance for {key!r}")
    return errors


def verify_frozen() -> tuple[dict, str]:
    data = load(FROZEN)
    errors = validate(data, frozen=True)
    actual = fingerprint(data)
    expected = LOCK.read_text(encoding="ascii").strip()
    if errors:
        raise ValueError("Invalid frozen manifest:\n- " + "\n- ".join(errors))
    if actual != expected:
        raise ValueError("Frozen manifest fingerprint mismatch")
    return data, actual
