"""Verify the recording workflow using real scans and fixes in isolated copies."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import scan_and_fix
from mcp_scanner.scanner import MCPScanner
from tests.test_fixer import VULNERABLE


class VideoDemoTests(unittest.TestCase):
    def run_demo(self, root, answers):
        output = io.StringIO()
        with patch.object(scan_and_fix, 'ROOT', root), patch('builtins.input', side_effect=answers), \
                contextlib.redirect_stdout(output):
            code = scan_and_fix.main([])
        return code, output.getvalue()

    def make_samples(self, root, source=VULNERABLE):
        samples = root / 'tests' / 'samples'
        samples.mkdir(parents=True)
        for name in scan_and_fix.SAMPLES:
            (samples / name).write_text(source, encoding='utf-8')

    def test_yes_creates_linked_reports_and_keeps_original_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_samples(root)
            evaluated = {}
            show_report = scan_and_fix.show_report
            def inspect_evaluated_files(label, path):
                if label == 'Fix HTML report':
                    project = path.parent.parent / 'project'
                    evaluated['scan'] = MCPScanner().scan(project)
                    evaluated['sources'] = {p.name: p.read_text(encoding='utf-8')
                                            for p in project.glob('*.py')}
                show_report(label, path)
            with patch.object(scan_and_fix, 'show_report', side_effect=inspect_evaluated_files):
                code, output = self.run_demo(root, ['yes'])
            self.assertEqual(0, code)
            self.assertIn('Scan HTML report: file:///', output)
            self.assertIn('Fix HTML report: file:///', output)
            self.assertIn('Updated server file:', output)
            self.assertIn('VERIFICATION SCAN - reading the updated server files from disk', output)
            self.assertIn('Urgency:', output)
            self.assertIn('Categories:', output)
            self.assertNotIn('    Issue:', output)
            self.assertNotIn('    Match:', output)
            self.assertNotIn('    Location:', output)
            report_dir = next((root / 'evaluation' / 'work').glob('*/reports'))
            data = json.loads((report_dir / 'fix.json').read_text(encoding='utf-8'))
            self.assertEqual(['MCP03', 'MCP06'], data['selected_categories'])
            self.assertTrue(data['fix']['verification_passed'])
            self.assertGreater(data['fix']['other_issues_after'], 0)
            html = (report_dir / 'fix.html').read_text(encoding='utf-8')
            self.assertIn('Before and after', html)
            self.assertIn('scan.html', html)
            self.assertIn('Remaining findings', html)
            self.assertNotIn('No automatic fixes were applied.', html)
            self.assertIn('Server file (restored after evaluation):', html)
            self.assertIn('before restoration', html)
            self.assertNotIn('Server files restored', output)
            self.assertTrue(output.strip().endswith((report_dir / 'fix.html').resolve().as_uri()))
            project = report_dir.parent / 'project'
            for name in scan_and_fix.SAMPLES:
                self.assertEqual(VULNERABLE, (root / 'tests' / 'samples' / name).read_text(encoding='utf-8'))
                fixed = evaluated['sources'][name]
                self.assertNotEqual(VULNERABLE, fixed)
                self.assertNotIn('Ignore previous instructions', fixed)
                self.assertIn('sanitize_content(', fixed)
                self.assertEqual((root / 'tests' / 'samples' / name).read_bytes(),
                                 (project / name).read_bytes())
                self.assertEqual(VULNERABLE, (project / (name + '.bak')).read_text(encoding='utf-8'))
            # The report must match an independent scan of the repaired files
            # before restoration, not a fabricated change to the counts.
            fresh = evaluated['scan']
            self.assertEqual(len(scan_and_fix.SAMPLES), fresh.files_scanned)
            self.assertEqual([f.to_dict() for f in fresh.findings], data['after']['findings'])
            self.assertFalse(any(f.attack_id in scan_and_fix.CATEGORIES for f in fresh.findings))
            restored = MCPScanner().scan(project)
            self.assertEqual([f.to_dict() for f in restored.findings], data['before']['findings'])
            verification_output = output.split('VERIFICATION SCAN', 1)[1]
            self.assertNotIn('Tool Poisoning:', verification_output)
            self.assertIn('MCP05', verification_output)

    def test_report_error_restores_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_samples(root)
            with patch.object(scan_and_fix, 'fix_summary', side_effect=OSError('Cannot write report')), \
                    contextlib.redirect_stderr(io.StringIO()):
                code, output = self.run_demo(root, ['yes'])
            self.assertEqual(2, code)
            self.assertIn('Updated server file:', output)
            self.assertNotIn('Server files restored', output)
            for path in root.glob('evaluation/work/*/project/*.py'):
                self.assertEqual((root / 'tests' / 'samples' / path.name).read_bytes(), path.read_bytes())

    def test_interrupted_partial_fix_restores_exact_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_samples(root)
            # Exercise preservation of Windows newlines, not just text equality.
            for path in (root / 'tests' / 'samples').glob('*.py'):
                path.write_bytes(VULNERABLE.replace('\n', '\r\n').encode('utf-8'))
            def interrupt_fix(target, verify):
                (Path(target) / scan_and_fix.SAMPLES[0]).write_text('partial edit', encoding='utf-8')
                raise KeyboardInterrupt()
            with patch.object(scan_and_fix.MCPFixer, 'fix', side_effect=interrupt_fix), \
                    contextlib.redirect_stderr(io.StringIO()):
                code, output = self.run_demo(root, ['yes'])
            self.assertEqual(2, code)
            self.assertNotIn('Server files restored', output)
            for path in root.glob('evaluation/work/*/project/*.py'):
                self.assertEqual((root / 'tests' / 'samples' / path.name).read_bytes(), path.read_bytes())

    def test_no_and_eof_do_not_fix_and_repeated_runs_are_fresh(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_samples(root)
            for answer in ('no', EOFError()):
                code, output = self.run_demo(root, [answer])
                self.assertEqual(1, code)
                self.assertIn('No fixes applied', output)
            runs = list((root / 'evaluation' / 'work').iterdir())
            self.assertEqual(2, len(runs))
            for run in runs:
                self.assertTrue((run / 'reports' / 'scan.html').exists())
                self.assertFalse((run / 'reports' / 'fix.html').exists())
                self.assertFalse(list(run.rglob('*.bak')))
                for path in (run / 'project').glob('*.py'):
                    self.assertEqual(VULNERABLE, path.read_text(encoding='utf-8'))

    def test_single_category_and_invalid_answer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_samples(root)
            code, output = self.run_demo(root, ['MCP05', 'MCP03'])
            self.assertEqual(0, code)
            self.assertIn('Enter yes', output)
            report = next(root.glob('evaluation/work/*/reports/fix.json'))
            data = json.loads(report.read_text(encoding='utf-8'))
            self.assertEqual(['MCP03'], data['selected_categories'])
            self.assertTrue(any(f['attack_id'] == 'MCP06' for f in data['after']['findings']))

    def test_incomplete_scan_does_not_prompt_or_modify_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_samples(root, 'def broken(:')
            with contextlib.redirect_stderr(io.StringIO()):
                code, output = self.run_demo(root, [])
            self.assertEqual(2, code)
            self.assertIn('Scan incomplete', output)
            self.assertFalse(list(root.rglob('*.bak')))

    def test_report_escapes_change_descriptions_and_shows_partial_verification(self):
        from mcp_scanner.fixer import FixReport, FixResult
        from mcp_scanner.scanner import MCPScanner
        result = MCPScanner().scan_source(VULNERABLE, 'server.py')
        report = scan_and_fix.serialize_scan(result, 'server.py')
        fix = FixReport('server.py', 1, 0, 1, 1, 0,
                        file_results=[FixResult('server.py', 1, 0, changes=['<script>bad</script>'])])
        html = scan_and_fix.fix_summary(report, report, fix, {'MCP03'})
        self.assertIn('manual review remains', html)
        self.assertIn('&lt;script&gt;', html)
        self.assertNotIn('<script>', html)


if __name__ == '__main__':
    unittest.main()
