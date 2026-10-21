"""Retrospective regression check against iteration 001's archived scanner.

Run after the frozen validation. This is NOT another independent test batch.
Only trusted scanner code is imported from the archive; fixtures stay inert.
"""
import hashlib
import importlib.util
import json
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
REFERENCE = OUT.parent / "iteration-001/runs/after"
ARCHIVE = REFERENCE / "code_snapshot.zip"
# A new interpreter is required so no current scanner modules are cached.
assert "mcp_scanner" not in sys.modules
sys.path.insert(0, str(ARCHIVE))
import mcp_scanner
from mcp_scanner.scanner import MCPScanner
assert str(ARCHIVE) in mcp_scanner.__file__


def main():
    output = OUT / "runs/reference-iteration001"
    output.mkdir(parents=True, exist_ok=False)
    config = json.loads((REFERENCE / "config.json").read_text())
    with zipfile.ZipFile(ARCHIVE) as archive:
        assert all(hashlib.sha256(archive.read(path)).hexdigest() == digest for path,digest in config["code_files"].items())
    runner_path = ROOT / "evaluation/scripts/run_iteration.py"
    assert hashlib.sha256(runner_path.read_bytes()).hexdigest() == config["code_files"]["evaluation/scripts/run_iteration.py"]
    spec = importlib.util.spec_from_file_location("reference_runner", runner_path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    data = (OUT / "manifest.json").read_bytes()
    manifest = json.loads(data)
    holdout = ROOT / "evaluation/holdout/staging-manifest.json"
    before = hashlib.sha256(holdout.read_bytes()).hexdigest()
    rows = []
    for artifact in manifest["artifacts"]:
        start = time.perf_counter()
        result = MCPScanner().scan_source(runner.safe_source(artifact).read_text(encoding="utf-8"), filename=artifact["source_filename"])
        rows.append(dict(artifact_id=artifact["id"], sha256=artifact["sha256"],
            status="completed" if not result.parse_errors else "parse_error",
            scan_info=result.to_dict(), findings=[f.to_dict() for f in result.findings],
            elapsed_seconds=round(time.perf_counter()-start,6)))
    scores = runner.score(manifest, rows)
    runner.write_json(output / "metrics.json", scores)
    (output / "manifest.json").write_bytes(data)
    (output / "predictions.jsonl").write_text("".join(json.dumps(row)+"\n" for row in rows), encoding="utf-8")
    runner.write_json(output / "config.json", dict(recorded_at=datetime.now(timezone.utc).isoformat(),
        purpose="Retrospective paired regression check, not fresh validation",
        reference_run="iteration-001/runs/after", code_fingerprint=config["code_fingerprint"],
        code_archive_sha256=hashlib.sha256(ARCHIVE.read_bytes()).hexdigest(),
        manifest_sha256=hashlib.sha256(data).hexdigest(), module_origin=mcp_scanner.__file__,
        review="none", llm_calls=0, holdout_manifest_sha256=before))
    assert hashlib.sha256(holdout.read_bytes()).hexdigest() == before
    runner.write_json(output / "completion.json", dict(finished_at=datetime.now(timezone.utc).isoformat(),
        artifacts=len(rows), holdout_unchanged=True))
    print(scores["micro"])


if __name__ == "__main__":
    main()
