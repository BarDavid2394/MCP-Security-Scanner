"""Freeze a fully labeled holdout manifest without reading or scanning artifacts."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from holdout_common import CONSUMED, FROZEN, HOLDOUT, LOCK, fingerprint, load, validate


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default=str(HOLDOUT / "staging-manifest.json"))
    args = parser.parse_args()
    if FROZEN.exists() or LOCK.exists() or CONSUMED.exists():
        raise SystemExit("Refusing to replace an existing frozen or consumed holdout")
    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = Path.cwd() / manifest_path
    data = load(manifest_path)
    errors = validate(data, frozen=False)
    if errors:
        raise SystemExit("Invalid staging manifest:\n- " + "\n- ".join(errors))
    if not data["artifacts"] or not data["labels"]:
        raise SystemExit("Refusing to freeze an empty holdout")
    data["state"] = "frozen"
    data["frozen_at"] = datetime.now(timezone.utc).isoformat()
    FROZEN.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    digest = fingerprint(data)
    LOCK.write_text(digest + "\n", encoding="ascii")
    print(f"Frozen {len(data['artifacts'])} artifacts and {len(data['labels'])} labels: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
