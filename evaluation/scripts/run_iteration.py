"""Record a static development run without executing targets or consuming holdout.

Each output directory is created once. Explicit labels are scored independently
of incidental findings; failed scans remain errors, never true negatives.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import sys
import time
import traceback
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from mcp_scanner.catalog import CATALOG_VERSION, RULES
from mcp_scanner.scanner import MCPScanner
from mcp_scanner.utils.helpers import get_project_files


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def ratio(a, b):
    return a / b if b else None


def score(manifest: dict, predictions: list[dict]) -> dict:
    by_id = {row["artifact_id"]: row for row in predictions}
    counts = defaultdict(lambda: dict(tp=0, fp=0, fn=0, tn=0, errors=0))
    decisions = []
    unscored = []
    for artifact in manifest["artifacts"]:
        row = by_id[artifact["id"]]
        labels = artifact["labels"]
        for label in labels:
            rule, function = label["rule_id"], label.get("function_name")
            hit = any(f["rule_id"] == rule and (function is None or f.get("function_name") == function)
                      for f in row.get("findings", []))
            if row["status"] != "completed":
                outcome = "errors"
            elif label["polarity"] == "positive":
                outcome = "tp" if hit else "fn"
            else:
                outcome = "fp" if hit else "tn"
            counts[rule][outcome] += 1
            decisions.append(dict(artifact_id=artifact["id"], **label, outcome=outcome))
        for finding in row.get("findings", []):
            if not any(label["rule_id"] == finding["rule_id"] and
                       (label.get("function_name") is None or label["function_name"] == finding.get("function_name"))
                       for label in labels):
                unscored.append(dict(artifact_id=artifact["id"], rule_id=finding["rule_id"],
                                     function_name=finding.get("function_name")))
    totals = {k: sum(v[k] for v in counts.values()) for k in ("tp", "fp", "fn", "tn", "errors")}
    categories = defaultdict(lambda: dict(tp=0, fp=0, fn=0, tn=0, errors=0))
    for rule, values in counts.items():
        for key, value in values.items(): categories[rule.split("-")[0]][key] += value
    def metrics(v):
        return {**v, "precision": ratio(v["tp"], v["tp"] + v["fp"]),
                "recall": ratio(v["tp"], v["tp"] + v["fn"]),
                "false_positive_rate": ratio(v["fp"], v["fp"] + v["tn"]),
                "label_coverage": ratio(v["tp"]+v["fp"]+v["fn"]+v["tn"], sum(v.values()))}
    return dict(unit=manifest["label_unit"], micro=metrics(totals),
                by_rule={k: metrics(v) for k,v in sorted(counts.items())},
                by_category={k: metrics(v) for k,v in sorted(categories.items())},
                decisions=decisions, unscored_predictions=unscored,
                note="Scores concern explicitly reviewed labels only; errors excluded from confusion matrix and counted separately.")


def safe_source(artifact: dict) -> Path:
    path = (ROOT / artifact["path"]).resolve()
    # Development runner cannot point at the reserved holdout, even through a symlink.
    if not path.is_relative_to(ROOT / "deliverables/data_expansion/snapshots"):
        raise ValueError("Only development snapshot inputs are admitted by this runner")
    if sha(path.read_bytes()) != artifact["sha256"]:
        raise ValueError(f"Hash mismatch: {artifact['id']}")
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--primary", action="store_true", help="Also measure the already exposed primary corpus")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]+", args.run_id):
        parser.error("run-id must contain letters, numbers, underscores or hyphens")
    manifest_path = args.manifest.resolve()
    if not manifest_path.is_relative_to(ROOT / "evaluation/iterations"):
        parser.error("manifest must be under evaluation/iterations")
    data = manifest_path.read_bytes()
    manifest = json.loads(data)
    ids = set()
    for artifact in manifest["artifacts"]:
        if artifact["id"] in ids: raise ValueError("Duplicate artifact ID")
        ids.add(artifact["id"])
        safe_source(artifact)
        keys = set()
        for label in artifact["labels"]:
            key = (label["rule_id"], label.get("function_name"))
            if key in keys or label["rule_id"] not in RULES or label["polarity"] not in {"positive", "negative"}:
                raise ValueError("Invalid/duplicate label")
            keys.add(key)
    out = manifest_path.parent / "runs" / args.run_id
    out.mkdir(parents=True, exist_ok=False)
    (out / "manifest.json").write_bytes(data)
    holdout = ROOT / "evaluation/holdout/staging-manifest.json"
    holdout_hash = sha(holdout.read_bytes())
    code = {p.relative_to(ROOT).as_posix(): sha(p.read_bytes()) for p in sorted((ROOT / "mcp_scanner").rglob("*.py"))}
    code[Path(__file__).relative_to(ROOT).as_posix()] = sha(Path(__file__).read_bytes())
    with zipfile.ZipFile(out / "code_snapshot.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for path in code: archive.write(ROOT / path, path)
    config = dict(started_at=datetime.now(timezone.utc).isoformat(),
                  git_head=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                  code_files=code, code_fingerprint=sha(json.dumps(code, sort_keys=True).encode()),
                  manifest_sha256=sha(data), python=sys.version, platform=platform.platform(),
                  catalog_version=CATALOG_VERSION, review="none", llm_calls=0,
                  holdout_manifest_sha256=holdout_hash, primary=args.primary)
    write_json(out / "config.json", config)
    predictions=[]
    for artifact in manifest["artifacts"]:
        start = time.perf_counter()
        row = dict(artifact_id=artifact["id"], sha256=artifact["sha256"])
        try:
            result = MCPScanner().scan_source(safe_source(artifact).read_text(encoding="utf-8"),
                                              filename=artifact["source_filename"])
            row.update(status="completed" if not result.parse_errors else "parse_error",
                       scan_info=result.to_dict(), findings=[f.to_dict() for f in result.findings])
        except Exception as exc:
            row.update(status="failed", error_type=type(exc).__name__, error=str(exc), traceback=traceback.format_exc())
        row["elapsed_seconds"]=round(time.perf_counter()-start,6)
        predictions.append(row)
    (out / "predictions.jsonl").write_text("".join(json.dumps(x)+"\n" for x in predictions), encoding="utf-8")
    metrics = score(manifest, predictions)
    write_json(out / "metrics.json", metrics)
    print(args.run_id, "labeled results:", metrics["micro"], flush=True)
    primary=[]
    if args.primary:
        corpus_manifest=(ROOT / "evaluation/corpus-manifest.json").read_bytes()
        (out / "primary_manifest.json").write_bytes(corpus_manifest)
        for target in json.loads(corpus_manifest)["targets"]:
            path=(ROOT / "evaluation/corpus" / target["repository"] / target["path"]).resolve()
            if not path.is_relative_to(ROOT / "evaluation/corpus"): raise ValueError("Invalid primary target")
            start=time.perf_counter()
            row=dict(target_id=target["id"], target=path.relative_to(ROOT).as_posix())
            try:
                inputs={p.relative_to(path).as_posix():sha(p.read_bytes()) for p in get_project_files(path)}
                row["input_files"]=inputs
                if not inputs: raise ValueError("Primary target has no inputs")
                result=MCPScanner().scan(path)
                row.update(status="completed" if not result.parse_errors else "parse_error",
                           scan_info=result.to_dict(), findings=[f.to_dict() for f in result.findings])
            except Exception as exc:
                row.update(status="failed",error_type=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
            row["elapsed_seconds"]=round(time.perf_counter()-start,6)
            primary.append(row)
            write_json(out / ("primary-"+target["id"]+".json"),row)
            print(target["id"],row["status"],row.get("scan_info",{}).get("files_scanned"),flush=True)
    assert sha(holdout.read_bytes())==holdout_hash, "Holdout manifest changed during run"
    assert all(sha((ROOT/path).read_bytes())==digest for path,digest in code.items()), "Scanner changed during run"
    write_json(out / "completion.json", dict(finished_at=datetime.now(timezone.utc).isoformat(),
               artifacts=len(predictions),primary_targets=len(primary),holdout_unchanged=True,
               manifest_unchanged=sha(manifest_path.read_bytes())==sha(data),code_unchanged=True))


if __name__ == "__main__":
    main()
