"""End-to-end scan CLI tests. AI review and fixer are intentionally excluded."""

import contextlib
import io
import json
import tempfile
import time
import unittest
from pathlib import Path

from mcp_scanner.main import main
from mcp_scanner.scanner import MCPScanner


class CliIntegrationTests(unittest.TestCase):
    def test_typescript_json_scan_and_rule_filter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "server.ts"
            output = root / "report.json"
            target.write_text('''
import { exec } from "node:child_process";
const server = new McpServer({ name: "x", version: "1" });
server.tool("run", "Run command", { command: z.string() }, async ({ command }) => {
  exec(`tool ${command}`);
});
''', encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(["scan", str(target), "--check", "MCP05", "--format", "json", "--output", str(output)])
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(1, code)
            self.assertEqual({"MCP05-COMMAND-INJECTION"}, {f["rule_id"] for f in report["findings"]})
            self.assertEqual(1, report["summary"]["by_rule"]["MCP05-COMMAND-INJECTION"])
            evidence = report["findings"][0]["metadata"]["evidence"]
            self.assertEqual("command", evidence["source"])
            self.assertTrue(evidence["missing_protections"])

    def test_clean_cli_exit_and_invalid_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "server.py"
            path.write_text('''
from mcp.server import Server
server = Server("safe")
@server.tool()
def add(a: int, b: int):
    return a + b
''', encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(0, main(["scan", str(path), "--format", "json"]))
                self.assertEqual(2, main(["scan", str(path), "--check", "MCP99"]))

    def test_synthetic_project_performance_smoke(self):
        tools = "\n".join(
            f'''@server.tool()\ndef tool_{index}(value: str):\n    return "item-{index}:" + value\n'''
            for index in range(200)
        )
        source = 'from mcp.server import Server\nserver = Server("scale")\n' + tools
        started = time.perf_counter()
        result = MCPScanner().scan_source(source, "synthetic_scale.py")
        elapsed = time.perf_counter() - started
        self.assertEqual(200, result.tools_analyzed)
        self.assertLess(elapsed, 10.0)


if __name__ == "__main__":
    unittest.main()
