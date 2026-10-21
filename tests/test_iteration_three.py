"""Iteration 003 controls derived from exposed iteration 002 error classes."""
import json
import unittest
from mcp_scanner.scanner import MCPScanner
from mcp_scanner.parsers.python_parser import PythonMCPParser


def tool(body, params="value: str", imports="", extra=""):
    return ('from fastmcp import FastMCP\n' + imports + '\nmcp=FastMCP("test")\n' + extra +
            '\n@mcp.tool()\ndef inspect(' + params + '):\n' + '\n'.join('    '+line for line in body.splitlines()) + '\n')


def low_level(body, names=("run", "status"), extra=""):
    return ("import subprocess\nimport os\nfrom mcp.server import Server\nfrom mcp import types\nserver=Server('test')\n" +
            "TOOLS = [" + ','.join(f"types.Tool(name={name!r}, description='test', inputSchema={{'type':'object'}})" for name in names) + "]\n" +
            extra + "\n@server.list_tools()\nasync def list_tools():\n    return TOOLS\n" +
            "@server.call_tool()\nasync def call_tool(name, arguments):\n" + '\n'.join('    '+line for line in body.splitlines()) + '\n')


class IterationThreeTests(unittest.TestCase):
    def findings(self, source, rule):
        return [f for f in MCPScanner().scan_source(source).findings if f.rule_id == rule]

    def command(self, source):
        return self.findings(source, "MCP05-COMMAND-INJECTION")

    def secrets(self, source):
        return self.findings(source, "MCP01-SECRET-OUTPUT")

    def test_module_and_direct_command_aliases(self):
        for imp, call in [('import subprocess as sp', 'sp.run'), ('from subprocess import run as launch', 'launch'), ('from os import system', 'system')]:
            with self.subTest(imp=imp):
                self.assertTrue(self.command(tool(f'{call}(value)', imports=imp)))

    def test_local_import_alias(self):
        self.assertTrue(self.command(tool('from subprocess import run as launch\nlaunch(value, shell=True)')))

    def test_import_shadowing_and_unrelated_run_are_not_sinks(self):
        cases = [tool('sp.run(value)', 'value: str, sp=None', 'import subprocess as sp'),
                 tool('sp = client\nsp.run(value)', 'value: str, client=None', 'import subprocess as sp'),
                 tool('run(value)', imports='from unrelated import run'),
                 tool('subprocess.run(value)', imports='import unrelated as subprocess'),
                 tool('run(value)', imports='from subprocess import run', extra='def run(value):\n    return value')]
        for source in cases:
            with self.subTest(source=source): self.assertFalse(self.command(source))

    def test_safe_aliased_argv_and_unsafe_executable(self):
        self.assertFalse(self.command(tool('sp.run(["du", value])', imports='import subprocess as sp')))
        self.assertTrue(self.command(tool('sp.run([value])', imports='import subprocess as sp')))

    def test_helper_with_aliased_sink(self):
        self.assertTrue(self.command(tool('return launch(value)', imports='import subprocess as sp', extra='def launch(cmd):\n    return sp.run(cmd, shell=True)')))

    def test_module_tool_list_and_sibling_isolation(self):
        source = low_level('if name == "run":\n    subprocess.run(arguments["cmd"], shell=True)\nelif name == "status":\n    return {"ok": True}')
        parsed = PythonMCPParser().parse_source(source)
        self.assertEqual(2, len(parsed.tools))
        self.assertEqual({'run'}, {f.function_name for f in self.command(source)})
        self.assertNotIn('subprocess.run', next(t for t in parsed.tools if t.name == 'status').implementation_source)

    def test_negated_low_level_guard(self):
        source = low_level('if name != "run":\n    return None\nelse:\n    subprocess.run(arguments["cmd"], shell=True)', names=('run',))
        self.assertTrue(self.command(source))

    def test_multiple_servers_do_not_share_dispatchers(self):
        source = low_level('if name == "run":\n    return "safe"', names=('run',))
        source += "\nother=Server('other')\n@other.call_tool()\nasync def other_call(name, arguments):\n    subprocess.run(arguments['cmd'], shell=True)\n"
        self.assertFalse(self.command(source))

    def test_secret_values_in_containers_aliases_and_helpers(self):
        for body in ['return {"token": API_TOKEN}', 'alias=API_TOKEN\nreturn {"nested": [alias]}', 'return reveal()']:
            source = tool(body, imports='import os', extra='API_TOKEN=os.getenv("API_TOKEN")\ndef reveal():\n    return {"env": os.environ}')
            with self.subTest(body=body): self.assertTrue(self.secrets(source))

    def test_low_level_secret_helper_and_clean_sibling(self):
        source = low_level('if name == "run":\n    return reveal()\nelif name == "status":\n    return {"ok": True}', extra='def reveal():\n    return {"env": os.environ}\n')
        self.assertEqual({'run'}, {f.function_name for f in self.secrets(source)})

    def test_logging_aliases_function_and_module_scope(self):
        source = 'import logging as lg\nlog=lg.getLogger(__name__)\npassword="sensitive-fixture-value"\nlog.info("password %s", password)\ndef connect(password):\n    log.info("password %s", password)\n'
        self.assertEqual(2, len(self.secrets(source)))

    def test_logging_shadow_is_not_assumed_logger(self):
        source = 'import logging\nlog=logging.getLogger(__name__)\ndef inspect(log, password):\n    log.info(password)\n'
        self.assertFalse(self.secrets(source))

    def test_status_pagination_and_explicit_redaction_are_negative(self):
        bodies = ['return {"connected": bool(API_TOKEN), "tokenizer_version": "v2", "passwordless_mode": True}',
                  'next_token="opaque-cursor"\nreturn {"next_token": next_token}',
                  'token=API_TOKEN\ntoken="[REDACTED]"\nreturn {"token": token}',
                  'return redact(API_TOKEN)']
        for body in bodies:
            source = tool(body, imports='import os', extra='API_TOKEN=os.getenv("API_TOKEN")\ndef redact(value):\n    return "[REDACTED]"')
            with self.subTest(body=body): self.assertFalse(self.secrets(source))

    def test_boolean_environment_guard_is_not_dump(self):
        for body in ['return os.environ.get("ALLOW_WRITE") == "1"', 'return bool(os.environ)', 'return enabled()']:
            source = tool(body, imports='import os', extra='def enabled():\n    return os.environ.get("ALLOW_WRITE", "").strip() in ("1", "yes")')
            with self.subTest(body=body):
                self.assertFalse(self.findings(source, "MCP10-OVER-SHARING"))
                self.assertFalse(self.secrets(source))
        self.assertTrue(self.findings(tool('return {"env": os.environ}', imports='import os'), "MCP10-OVER-SHARING"))

    def test_secret_output_is_redacted_in_serialization(self):
        source = tool('return {"key": "sk-abcdefghijklmnopqrstuvwxyz123456"}')
        result = MCPScanner().scan_source(source)
        self.assertTrue(self.secrets(source))
        serialized = json.dumps([f.to_dict() for f in result.findings])
        self.assertNotIn('sk-abcdefghijklmnopqrstuvwxyz123456', serialized)

    def test_storage_keys_and_lexical_tokens_are_not_credentials(self):
        self.assertFalse(self.secrets(tool('return f"Key {key} not found"', params='key: str')))
        source = 'import logging\nlogger=logging.getLogger(__name__)\ndef words(text):\n    for token in text.split():\n        logger.info("word %s", token)\n'
        self.assertFalse(self.secrets(source))

    def test_http_status_does_not_inherit_request_credential(self):
        source = 'import logging\nlogger=logging.getLogger(__name__)\ndef request(client, token):\n    response=client.post("https://api.example", data={"token": token})\n    logger.info("Status %s", response.status_code)\n'
        self.assertFalse(self.secrets(source))

    def test_credential_mapping_keys_and_values_are_distinct(self):
        self.assertFalse(self.secrets(tool('return list(credentials.keys())', params='credentials: dict')))
        self.assertTrue(self.secrets(tool('return list(credentials.values())', params='credentials: dict')))


if __name__ == '__main__':
    unittest.main()
