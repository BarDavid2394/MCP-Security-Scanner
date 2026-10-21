"""Guarded, one-shot execution of the clean holdout."""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from holdout_common import CONSUMED, CORPUS, RESULTS, ROOT, verify_frozen

TOKEN_FILE = ROOT / "evaluation" / "holdout" / ".run-token"


def preflight_artifacts(data: dict, corpus: Path) -> list[Path]:
    targets = []
    for artifact in data["artifacts"]:
        target = (corpus / artifact["source_id"] / artifact["path"]).resolve()
        if not target.is_relative_to(corpus.resolve()) or not target.is_file():
            raise ValueError(f"Missing or invalid holdout path: {artifact['id']}")
        actual = "sha256:" + hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != artifact["sha256"]:
            raise ValueError(f"Holdout hash mismatch: {artifact['id']}")
        targets.append(target)
    return targets


def token_digest(token: str, fingerprint: str) -> str:
    return hashlib.sha256(f"{fingerprint}:{token}".encode()).hexdigest()


def issue_token(fingerprint: str) -> None:
    if CONSUMED.exists():
        raise SystemExit("Holdout has already been consumed")
    token = secrets.token_urlsafe(24)
    TOKEN_FILE.write_text(token_digest(token, fingerprint), encoding="ascii")
    print(token)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--issue-token", action="store_true")
    parser.add_argument("--token")
    args = parser.parse_args()
    data, frozen_fingerprint = verify_frozen()
    if args.issue_token:
        issue_token(frozen_fingerprint)
        return 0
    if CONSUMED.exists():
        raise SystemExit("Holdout has already been consumed; refusing a second run")
    if not args.token or not TOKEN_FILE.exists():
        raise SystemExit("A one-time token is required")
    if not secrets.compare_digest(TOKEN_FILE.read_text(encoding="ascii"), token_digest(args.token, frozen_fingerprint)):
        raise SystemExit("Invalid one-time token")

    targets = preflight_artifacts(data, CORPUS)

    # Import only after all clean-holdout guards have passed.
    sys.path.insert(0, str(ROOT))
    from mcp_scanner.reporters.json_reporter import JsonReporter
    from mcp_scanner.scanner import MCPScanner

    RESULTS.mkdir(parents=True, exist_ok=False)
    code_paths = sorted((ROOT / "mcp_scanner").rglob("*.py")) + [Path(__file__), ROOT / "evaluation/scripts/score_holdout.py", ROOT / "evaluation/scripts/holdout_common.py"]
    code_hashes = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in code_paths}
    with zipfile.ZipFile(RESULTS / "code_snapshot.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for path in code_paths: archive.write(path, path.relative_to(ROOT))
    record = {"started_at": datetime.now(timezone.utc).isoformat(), "status": "in-progress",
              "manifest_fingerprint": frozen_fingerprint, "artifacts": len(targets),
              "code_files": code_hashes, "review": "none", "llm_calls": 0}
    # Consume before the first prediction, including interrupted/failed runs.
    with CONSUMED.open("x", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2)
    summaries = []
    try:
        for artifact, target in zip(data["artifacts"], targets):
            output = RESULTS / f"{artifact['id']}.json"
            try:
                result = MCPScanner().scan(target)
            except Exception as exc:
                JsonReporter(pretty=True).report([], {"artifact_id": artifact["id"], "files_scanned": 0,
                    "parse_errors": [f"{type(exc).__name__}: {exc}"]}, str(output))
                summaries.append({"artifact_id": artifact["id"], "status": "failed", "findings": 0})
                continue
            JsonReporter(pretty=True).report(
                result.findings,
                {"artifact_id": artifact["id"], "files_scanned": result.files_scanned,
                 "tools_analyzed": result.tools_analyzed, "parse_errors": result.parse_errors},
                str(output),
            )
            summaries.append({"artifact_id": artifact["id"], "findings": len(result.findings),
                              "status": "completed" if not result.parse_errors and result.files_scanned else "failed"})
    finally:
        TOKEN_FILE.unlink(missing_ok=True)
    record.update(consumed_at=datetime.now(timezone.utc).isoformat(), status="completed", results=summaries,
                  code_unchanged=all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p,h in code_hashes.items()))
    if not record["code_unchanged"]: record["status"] = "invalid-code-changed"
    CONSUMED.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
