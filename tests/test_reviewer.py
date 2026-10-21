import json
import tempfile
import unittest
from pathlib import Path

from mcp_scanner.main import create_parser
from mcp_scanner.reviewer import OpenAIReviewer
from mcp_scanner.scanner import MCPScanner


SERVER = '''
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("remote")
password = "correct-horse-battery-staple"
mcp.run(transport="streamable-http")
'''


class ReviewerTests(unittest.TestCase):
    def finding(self, root: Path):
        path = root / "server.py"
        path.write_text(SERVER, encoding="utf-8")
        return next(f for f in MCPScanner().scan_file(path).findings if f.rule_id == "MCP07-MISSING-AUTH")

    def test_review_is_structured_redacted_and_cached(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding = self.finding(root)
            calls = []

            def transport(payload):
                calls.append(payload)
                return {"output_text": json.dumps({
                    "verdict": "NEEDS_CONTEXT", "confidence": 0.8,
                    "reason": "Middleware may be configured elsewhere.",
                    "evidence": ["line 5 starts HTTP transport"],
                    "missing_context": ["deployment middleware"],
                })}

            reviewer = OpenAIReviewer("test-model", cache_dir=root / "cache", transport=transport)
            first = reviewer.review(finding, root)
            second = reviewer.review(finding, root)
            self.assertEqual("NEEDS_CONTEXT", first.verdict)
            self.assertFalse(first.cached)
            self.assertTrue(second.cached)
            self.assertEqual(1, len(calls))
            self.assertNotIn("correct-horse", calls[0]["input"])
            self.assertIn("[REDACTED]", calls[0]["input"])
            self.assertFalse(calls[0]["store"])

    def test_review_failure_never_removes_static_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding = self.finding(root)
            reviewer = OpenAIReviewer("test-model", transport=lambda payload: (_ for _ in ()).throw(RuntimeError("offline")))
            findings = reviewer.review_findings([finding], root)
            self.assertEqual([finding], findings)
            self.assertEqual("INSUFFICIENT_EVIDENCE", finding.metadata["llm_review"]["verdict"])

    def test_only_ambiguous_rules_are_eligible(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            auth = self.finding(root)
            ssrf_source = '''
from mcp.server import Server
import requests
server = Server("x")
@server.tool()
def fetch(url: str):
    return requests.get(url).text
'''
            ssrf = next(f for f in MCPScanner().scan_source(ssrf_source).findings if f.rule_id == "MCP13-SSRF")
            self.assertEqual([auth], OpenAIReviewer.eligible([auth, ssrf]))

    def test_cli_exposes_bounded_review_options(self):
        args = create_parser().parse_args(["scan", "server.py", "--review", "llm", "--review-limit", "3"])
        self.assertEqual("llm", args.review)
        self.assertEqual(3, args.review_limit)

    def test_review_context_includes_bounded_related_auth(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            finding = self.finding(root)
            (root / "guards.py").write_text("def verify_token(request):\n    return request.headers['Authorization']\n", encoding="utf-8")
            captured = []
            reviewer = OpenAIReviewer("test", transport=lambda payload: captured.append(payload) or {
                "output_text": json.dumps({"verdict": "NEEDS_CONTEXT", "confidence": .5,
                    "reason": "linked auth", "evidence": [], "missing_context": []})}, max_source_chars=2000)
            reviewer.review(finding, root)
            self.assertIn("AUTH/MIDDLEWARE guards.py", captured[0]["input"])
            self.assertLessEqual(len(json.loads(captured[0]["input"])["source_excerpt_untrusted"]), 2000)


if __name__ == "__main__":
    unittest.main()
