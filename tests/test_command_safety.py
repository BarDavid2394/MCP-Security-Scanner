"""Positive and bypass controls for iteration 002 command protection evidence."""
import tempfile
from pathlib import Path
import unittest
from mcp_scanner.scanner import MCPScanner


def server(body, parameter="value: str", extra="", constructor="FastMCP"):
    return f'''import subprocess
import shlex
import re
from typing import Literal
from mcp.server.fastmcp import FastMCP
from mcp.server import Server
mcp = {constructor}("test")
{extra}
@mcp.tool()
def execute({parameter}):
''' + "\n".join("    " + line for line in body.splitlines()) + "\n"


class CommandProtectionTests(unittest.TestCase):
    def flags(self, source):
        return [f for f in MCPScanner(check="MCP05").scan_source(source).findings if f.rule_id == "MCP05-COMMAND-INJECTION"]

    def test_safe_fixed_argv(self):
        self.assertFalse(self.flags(server('subprocess.run(["du", "-sh", value])')))

    def test_execution_capable_argv_and_overrides_still_report(self):
        for body in ['subprocess.run(["sh", "-c", value])',
                     'subprocess.run(["python", "-c", value])',
                     'subprocess.run([value, "-sh"])',
                     'subprocess.run(["du", value], shell=True)',
                     'subprocess.run(["du", value], executable=value)',
                     'subprocess.run(["du", value], env={"PATH": value})',
                     'subprocess.Popen(["du", value], -1, value)',
                     'subprocess.run(["find", ".", "-exec", value, ";"])']:
            with self.subTest(body=body): self.assertTrue(self.flags(server(body)))

    def test_whole_word_quoting(self):
        self.assertFalse(self.flags(server('subprocess.run(f"du -sh {shlex.quote(value)}", shell=True)')))

    def test_unsafe_quoting_contexts_still_report(self):
        for body in ['subprocess.run(f"du -sh \'{shlex.quote(value)}\'", shell=True)',
                     'subprocess.run(f"du -sh x{shlex.quote(value)}", shell=True)',
                     'subprocess.run(f"{shlex.quote(value)}", shell=True)',
                     'subprocess.run(f"bash -c {shlex.quote(value)}", shell=True)',
                     'subprocess.run(f"ssh host {shlex.quote(value)}", shell=True)',
                     'subprocess.run(f"du -sh {shlex.quote(value)}", shell=True, executable=value)',
                     'subprocess.run(f"git -c {shlex.quote(value)} fetch", shell=True)']:
            with self.subTest(body=body): self.assertTrue(self.flags(server(body)))

    def test_shadowed_and_monkeypatched_quote_not_trusted(self):
        for extra, param in [('shlex.quote = lambda x: x', 'value: str'),
                             ('class shlex:\n    quote = lambda x: x', 'value: str'),
                             ('', 'value: str, shlex=None')]:
            with self.subTest(extra=extra,param=param):
                self.assertTrue(self.flags(server('subprocess.run(f"du -sh {shlex.quote(value)}", shell=True)', param, extra)))

    def test_typed_fastmcp_inputs(self):
        for param in ['value: int', 'value: Literal["web", "worker"]']:
            with self.subTest(param=param):
                self.assertFalse(self.flags(server('subprocess.run(f"tail -n {value}", shell=True)', param)))

    def test_types_without_enforcement_and_reassignment_still_report(self):
        self.assertTrue(self.flags(server('subprocess.run(f"tail -n {value}", shell=True)', 'value: int', constructor='Server')))
        self.assertTrue(self.flags(server('value = other\nsubprocess.run(f"tail -n {value}", shell=True)', 'value: int, other: str')))
        self.assertTrue(self.flags(server('value = other; subprocess.run(f"tail -n {value}", shell=True)', 'value: int, other: str')))
        self.assertTrue(self.flags(server('subprocess.run(f"tail -n {value}", shell=True)', 'value: Literal["web; id"]')))
        self.assertTrue(self.flags(server('subprocess.run(f"tail -n {value}", shell=True)', 'value: int', 'int = str')))

    def test_regex_fail_closed_guard(self):
        extra='SAFE = re.compile(r"^[\\w./-]+$")'
        body='if not SAFE.fullmatch(value):\n    raise ValueError("invalid")\nsubprocess.run(f"du -sh {value}", shell=True)'
        self.assertFalse(self.flags(server(body,extra=extra)))

    def test_regex_guard_bypasses_still_report(self):
        extra='SAFE = re.compile(r"^[\\w./-]+$")'
        bodies=[
            'subprocess.run(f"du -sh {value}", shell=True)\nif not SAFE.fullmatch(value):\n    raise ValueError("invalid")',
            'if not SAFE.fullmatch(value):\n    print("invalid")\nsubprocess.run(f"du -sh {value}", shell=True)',
            'if not SAFE.match(value):\n    raise ValueError("invalid")\nsubprocess.run(f"du -sh {value}", shell=True)',
            'if value:\n    if not SAFE.fullmatch(value):\n        raise ValueError("invalid")\nsubprocess.run(f"du -sh {value}", shell=True)',
            'if not SAFE.fullmatch(value):\n    raise ValueError("invalid")\nvalue = other\nsubprocess.run(f"du -sh {value}", shell=True)']
        for body in bodies:
            with self.subTest(body=body): self.assertTrue(self.flags(server(body,'value: str, other: str',extra)))
        self.assertTrue(self.flags(server('if not SAFE.fullmatch(value):\n    raise ValueError()\nsubprocess.run(f"du -sh {value}", shell=True)',extra='SAFE = re.compile(r".*")')))

    def test_direct_helper_forwarding_protection(self):
        extra='def launch(command):\n    return subprocess.run(command, shell=True)'
        self.assertFalse(self.flags(server('return launch(f"du -sh {shlex.quote(value)}")',extra=extra)))

    def test_transforming_helper_still_reports(self):
        extra='def launch(command):\n    return subprocess.run("bash -c "+command, shell=True)'
        self.assertTrue(self.flags(server('return launch(f"du -sh {shlex.quote(value)}")',extra=extra)))

    def test_unprotected_sibling_sink_is_not_hidden(self):
        source=server('subprocess.run(f"du -sh {shlex.quote(value)}", shell=True)\nsubprocess.run(value, shell=True)')
        self.assertEqual(1,len(self.flags(source)))

    def test_directory_scan_keeps_protected_local_helper_clean(self):
        extra='def launch(command):\n    return subprocess.run(command, shell=True)'
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'server.py'
            path.write_text(server('return launch(f"du -sh {shlex.quote(value)}")',extra=extra),encoding='utf-8')
            self.assertFalse([f for f in MCPScanner(check='MCP05').scan_directory(directory).findings if f.rule_id=='MCP05-COMMAND-INJECTION'])


if __name__ == '__main__':
    unittest.main()
