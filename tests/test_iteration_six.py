import unittest
from mcp_scanner.scanner import MCPScanner
from evaluation.scripts.build_material_pilot import tool_source


class SourceBehaviorTests(unittest.TestCase):
    def rules(self, body, imports, helper=False):
        return {f.rule_id for f in MCPScanner().scan_source(tool_source("Process a value.", body, imports, helper)).findings}

    def test_prefixed_environment_credentials_and_presence(self):
        for helper in (False, True):
            self.assertIn("MCP01-SECRET-OUTPUT", self.rules("value = os.environ['PAYMENTS_API_KEY']\nreturn value", "import os\n", helper))
            self.assertNotIn("MCP01-SECRET-OUTPUT", self.rules("token = os.getenv('PAYMENTS_API_KEY')\nreturn 'yes' if token else 'no'", "import os\n", helper))
            self.assertNotIn("MCP01-SECRET-OUTPUT", self.rules("return os.environ['LANG']", "import os\n", helper))

    def test_pathlib_content_and_noncontent_results(self):
        for helper in (False, True):
            self.assertIn("MCP06-UNTRUSTED-CONTEXT", self.rules("p = Path(value)\nreturn p.read_text()", "from pathlib import Path\n", helper))
            self.assertNotIn("MCP06-UNTRUSTED-CONTEXT", self.rules("return str(len(Path(value).read_text()))", "from pathlib import Path\n", helper))

    def test_unknown_path_class_is_not_assumed_to_read_files(self):
        imports = "class Path:\n    def __init__(self, value): pass\n    def read_text(self): return 'fixed'\n"
        self.assertNotIn("MCP06-UNTRUSTED-CONTEXT", self.rules("return Path(value).read_text()", imports))

    def test_printf_data_arguments_and_shell_control(self):
        for helper in (False, True):
            self.assertNotIn("MCP05-COMMAND-INJECTION", self.rules("return subprocess.run(['printf', '%s', value], shell=False).stdout", "import subprocess\n", helper))
            self.assertIn("MCP05-COMMAND-INJECTION", self.rules("return subprocess.run('printf ' + value, shell=True).stdout", "import subprocess\n", helper))


if __name__ == "__main__": unittest.main()
