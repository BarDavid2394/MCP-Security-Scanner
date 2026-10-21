"""Presentation reports keep details accessible and downloadable offline."""
import base64
from html.parser import HTMLParser
import json
import unittest

from demo_report import render_html
from mcp_scanner.reporters.colors import SEVERITY_COLORS
from mcp_scanner.reporters.console import ConsoleReporter
from mcp_scanner.scanner import MCPScanner
from mcp_scanner.fixer import FixReport
from scan_and_fix import serialize_scan, fix_summary, fix_payload
from tests.test_fixer import VULNERABLE


class ReportParser(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.cards, self.downloads, self.summaries = [], [], []
        self.in_summary = False
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'details' and 'finding' in attrs.get('class', '').split():
            self.cards.append(attrs)
        if tag == 'a' and 'download' in attrs:
            self.downloads.append(attrs)
        if tag == 'summary':
            self.in_summary = True
            self.summaries.append('')

    def handle_endtag(self, tag):
        if tag == 'summary':
            self.in_summary = False

    def handle_data(self, data):
        if self.in_summary:
            self.summaries[-1] += data


class DemoReportTests(unittest.TestCase):
    def setUp(self):
        self.report = serialize_scan(MCPScanner().scan_source(VULNERABLE, 'server.py'), 'server.py')

    def test_cards_are_collapsed_with_confidence_and_urgency_visible(self):
        html = render_html(self.report)
        parsed = ReportParser(html)
        self.assertEqual(len(self.report['findings']), len(parsed.cards))
        self.assertTrue(all('open' not in card for card in parsed.cards))
        self.assertTrue(all('Urgency:' in text and 'Confidence:' in text for text in parsed.summaries))
        for finding in self.report['findings']:
            self.assertIn(finding['title'], html)
        self.assertIn('Recommendation:', html)
        for level, (ansi, css) in SEVERITY_COLORS.items():
            self.assertEqual(ansi, ConsoleReporter.COLORS[level])
            self.assertIn(f'.severity-{level.lower()}{{--severity:{css};}}', html)

    def test_offline_download_contains_exact_scan_and_fix_data(self):
        fix = FixReport('server.py', 1, 1, 2, 0, 2)
        after = serialize_scan(MCPScanner().scan_source('pass', 'server.py'), 'server.py')
        cases = [
            (render_html(self.report), 'scan.json', self.report),
            (fix_summary(self.report, after, fix, {'MCP03', 'MCP06'}), 'fix.json',
             fix_payload(self.report, after, fix, {'MCP03', 'MCP06'})),
        ]
        for html, filename, expected in cases:
            with self.subTest(filename=filename):
                download, = ReportParser(html).downloads
                self.assertEqual(filename, download['download'])
                self.assertTrue(download['href'].startswith('data:application/json;base64,'))
                actual = json.loads(base64.b64decode(download['href'].split(',', 1)[1]))
                self.assertEqual(expected, actual)


if __name__ == '__main__':
    unittest.main()
