import importlib.util
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "evaluation" / "scripts"
sys.path.insert(0, str(SCRIPTS))


def load_module(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


holdout_common = load_module("holdout_common")


class HoldoutTests(unittest.TestCase):
    def manifest(self):
        return {
            "schema_version": 1,
            "state": "staging",
            "sources": [{
                "id": "source", "kind": "git", "url": "https://example.invalid/repo.git",
                "revision": "a" * 40,
            }],
            "artifacts": [{"id": "artifact", "source_id": "source", "path": "server.py"}],
            "labels": [{
                "artifact_id": "artifact", "rule_id": "MCP05-COMMAND-INJECTION",
                "polarity": "positive", "provenance": "reviewed-advisory",
            }],
        }

    def test_staging_manifest_validation(self):
        self.assertEqual([], holdout_common.validate(self.manifest()))

    def test_frozen_manifest_requires_artifact_hash(self):
        data = self.manifest()
        data["state"] = "frozen"
        errors = holdout_common.validate(data, frozen=True)
        self.assertTrue(any("requires sha256" in error for error in errors))

    def test_unknown_is_not_implicitly_negative(self):
        data = self.manifest()
        self.assertEqual(1, len(data["labels"]))
        self.assertNotIn(("artifact", "MCP13-SSRF"), {
            (label["artifact_id"], label["rule_id"]) for label in data["labels"]
        })

    def test_fingerprint_is_stable_across_key_order(self):
        data = self.manifest()
        reordered = json.loads(json.dumps(data, sort_keys=True))
        self.assertEqual(holdout_common.fingerprint(data), holdout_common.fingerprint(reordered))

    def test_token_is_bound_to_manifest(self):
        run_holdout = load_module("run_holdout")
        token = "one-time"
        self.assertNotEqual(
            run_holdout.token_digest(token, "a" * 64),
            run_holdout.token_digest(token, "b" * 64),
        )

    def test_conflicting_labels_are_rejected(self):
        data = self.manifest()
        data["labels"].append({**data["labels"][0], "polarity": "negative"})
        self.assertTrue(any("conflicting" in e for e in holdout_common.validate(data)))

    def test_preflight_rechecks_artifact_hashes(self):
        runner = load_module("run_holdout")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source/server.py"
            source.parent.mkdir()
            source.write_bytes(b"original")
            data = self.manifest()
            data["artifacts"][0]["sha256"] = "sha256:" + hashlib.sha256(b"original").hexdigest()
            self.assertEqual([source.resolve()], runner.preflight_artifacts(data, root))
            source.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                runner.preflight_artifacts(data, root)

    def test_preflight_rejects_paths_outside_corpus(self):
        runner = load_module("run_holdout")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = self.manifest()
            data["artifacts"][0]["path"] = "../../outside.py"
            with self.assertRaises(ValueError): runner.preflight_artifacts(data, root)

    def test_failed_negative_is_not_scored_clean(self):
        scorer = load_module("score_holdout")
        data = self.manifest()
        data["labels"][0]["polarity"] = "negative"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "evaluation/holdout"
            destination.mkdir(parents=True)
            results = root / "results"
            results.mkdir()
            consumed = destination / "CONSUMED.json"
            consumed.write_text(json.dumps(dict(manifest_fingerprint="frozen", status="completed", code_unchanged=True)))
            (results / "artifact.json").write_text(json.dumps(dict(findings=[], scan_info=dict(files_scanned=0, parse_errors=["failed"]))))
            with patch.multiple(scorer, ROOT=root, RESULTS=results, CONSUMED=consumed,
                                verify_frozen=lambda: (data, "frozen")), patch("builtins.print"):
                self.assertEqual(0, scorer.main())
            result = json.loads((destination / "metrics.json").read_text())
            self.assertEqual(1, result["micro"]["errors"])
            self.assertEqual(0, result["micro"]["tn"])


if __name__ == "__main__":
    unittest.main()
