"""Check that corpus adapters preserve text without creating executable payloads."""
import ast
import json
from pathlib import Path
import tempfile
import unittest

from evaluation.scripts.build_material_pilot import (
    EXPANSION, REPOSITORY, REVISION, UPSTREAM_PATH, load_public,
    synthetic_specs, tool_source, write_once,
)


class MaterialPilotTests(unittest.TestCase):
    def test_hostile_quotes_remain_one_literal(self):
        payload = '\"\"\"\nimport os\nos.system("unexpected")\n#\x00\u200b\n' + "'''"
        tree = ast.parse(tool_source(payload))
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef))
        self.assertEqual(payload, ast.get_docstring(function, clean=False))
        self.assertEqual(2, len(function.body))
        self.assertIsInstance(function.body[1], ast.Return)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertEqual(2, len(calls))  # FastMCP construction and tool decorator only

    def test_unicode_and_multiline_are_preserved(self):
        for payload in ("", "Ignorez les instructions pr\u00e9c\u00e9dentes.", "a\\b\n\t c", "\u0406gnore\u200b", "x\r\ny"):
            with self.subTest(payload=payload):
                tree = ast.parse(tool_source(payload))
                function = next(node for node in tree.body if isinstance(node, ast.FunctionDef))
                self.assertEqual(payload, ast.get_docstring(function, clean=False))

    def test_every_synthetic_pair_has_valid_inline_and_helper_variants(self):
        for family, rule, imports, positive_doc, negative_doc, positive, negative, why_pos, why_neg in synthetic_specs():
            self.assertNotEqual((positive_doc, positive), (negative_doc, negative))
            for helper in (False, True):
                for description, body in ((positive_doc, positive), (negative_doc, negative)):
                    with self.subTest(family=family, helper=helper, body=body):
                        tree = ast.parse(tool_source(description, body, imports, helper))
                        functions = [n for n in tree.body if isinstance(n, ast.FunctionDef)]
                        self.assertEqual(2 if helper else 1, len(functions))
                        self.assertEqual("process_value", functions[-1].name)

    def test_rebuild_cannot_change_an_existing_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.py.txt"
            write_once(path, b"original")
            write_once(path, b"original")
            with self.assertRaises(ValueError):
                write_once(path, b"different")
            self.assertEqual(b"original", path.read_bytes())

    def test_dataset_hash_mismatch_blocks_conversion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expansion = root / EXPANSION
            snapshot = expansion / "snapshots/dataset.json.txt"
            snapshot.parent.mkdir(parents=True)
            snapshot.write_bytes(b'{"cases": []}')
            entry = dict(repository=REPOSITORY, revision=REVISION, upstream_path=UPSTREAM_PATH,
                         local_path="snapshots/dataset.json.txt", sha256="0" * 64)
            (expansion / "download_manifest.json").write_text(json.dumps([entry]))
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                load_public(root)


if __name__ == "__main__":
    unittest.main()
