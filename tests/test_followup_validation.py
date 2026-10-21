import hashlib
import tempfile
import unittest
from pathlib import Path
from evaluation.scripts.run_followup_validation import preflight


class FollowupValidationTests(unittest.TestCase):
    def test_source_code_and_label_guards(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            source=root/'deliverables/data_expansion/snapshots/example.py.txt'
            source.parent.mkdir(parents=True)
            source.write_text('pass',encoding='utf-8')
            code=root/'scanner.py'
            code.write_text('pass',encoding='utf-8')
            digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
            lock={'code_files':{'scanner.py':digest(code)}}
            item=dict(id='a',path=source.relative_to(root).as_posix(),sha256=digest(source),
                      labels=[dict(rule_id='MCP03-TOOL-POISON',polarity='negative',rationale='No metadata')])
            manifest={'artifacts':[item]}
            preflight(root,manifest,lock)
            code.write_text('changed')
            with self.assertRaisesRegex(ValueError,'code changed'): preflight(root,manifest,lock)
            code.write_text('pass')
            source.write_text('changed')
            with self.assertRaisesRegex(ValueError,'hash mismatch'): preflight(root,manifest,lock)
            source.write_text('pass')
            item['labels'].append(dict(item['labels'][0],polarity='positive'))
            with self.assertRaisesRegex(ValueError,'duplicate label'): preflight(root,manifest,lock)

    def test_source_outside_snapshot_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            manifest={'artifacts':[dict(id='a',path='../outside.py')]}
            with self.assertRaisesRegex(ValueError,'outside snapshot'): preflight(root,manifest,{'code_files':{}})
