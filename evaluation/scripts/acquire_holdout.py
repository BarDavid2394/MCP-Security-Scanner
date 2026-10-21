"""Acquire pinned holdout source without installing, importing, or scanning it."""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import urllib.request
import zipfile
from pathlib import Path

from holdout_common import CORPUS, ROOT, verify_frozen


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def acquire_git(source: dict, destination: Path) -> None:
    subprocess.run(["git", "clone", "--filter=blob:none", "--no-checkout", source["url"], str(destination)],
                   cwd=ROOT, check=True)
    subprocess.run(["git", "checkout", "--detach", source["revision"]], cwd=destination, check=True)


def acquire_archive(source: dict, destination: Path) -> None:
    archive = destination.with_suffix(".zip")
    urllib.request.urlretrieve(source["url"], archive)
    if sha256(archive) != source.get("archive_sha256"):
        archive.unlink(missing_ok=True)
        raise ValueError(f"archive hash mismatch for {source['id']}")
    destination.mkdir(parents=True)
    with zipfile.ZipFile(archive) as bundle:
        bundle.extractall(destination)
    archive.unlink()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    data, _ = verify_frozen()
    CORPUS.mkdir(parents=True, exist_ok=True)
    by_source = {source["id"]: source for source in data["sources"]}
    if not args.verify_only:
        for source in data["sources"]:
            destination = CORPUS / source["id"]
            if destination.exists():
                continue
            acquire_git(source, destination) if source["kind"] == "git" else acquire_archive(source, destination)

    failures = []
    for artifact in data["artifacts"]:
        path = CORPUS / artifact["source_id"] / artifact["path"]
        if not path.is_file():
            failures.append(f"missing: {artifact['id']} ({path})")
        elif sha256(path) != artifact["sha256"]:
            failures.append(f"hash mismatch: {artifact['id']}")
    if failures:
        raise SystemExit("Holdout verification failed:\n- " + "\n- ".join(failures))
    print(f"Verified {len(data['artifacts'])} frozen artifacts; scanner was not invoked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

