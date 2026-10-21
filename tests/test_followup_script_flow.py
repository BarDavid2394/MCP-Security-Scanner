import unittest
from mcp_scanner.scanner import MCPScanner


class ScriptFlowTests(unittest.TestCase):
    def findings(self, body, imports=''):
        source=('import {exec, execFile, spawn} from "node:child_process";\n'
                'import fs from "node:fs";\n'+imports+'\n'
                'const server = new McpServer({name:"x"});\n'
                'server.tool("run","Handle input",{value:z.string()},async ({value})=>{\n'+body+'\n});')
        return MCPScanner().scan_source(source,'example.ts').findings

    def commands(self, body):
        return [f for f in self.findings(body) if f.attack_id=='MCP05']

    def test_safe_argv_and_real_execution(self):
        for body in ('execFile("git",["show","--",value]);',
                     'spawn("git",["show","--",value],{shell:false});',
                     'const args=["status","--porcelain"]; args.push("--branch",value); execFile("git",args);'):
            self.assertFalse(self.commands(body),body)
        for body in ('execFile(value,["--version"]);','spawn("python",["-c",value]);',
                     'execFile("git",["show",value],{shell:true});',
                     'execFile("git",["show","--",value],{shell:false,shell:true});',
                     'execFile("git",["show","--",value],options);',
                     'execFile("git",["show","--",value],{...options});',
                     'execFile("git",["show","--",value],{["shell"]:true});',
                     'execFile("git",["show","--",value],{env:value});',
                     'exec(`echo ${value}`);'):
            self.assertTrue(self.commands(body),body)

    def test_comments_strings_and_multiline_calls(self):
        self.assertFalse(self.commands('const note="exec(value)"; /* exec(value) */ return note;'))
        self.assertTrue(self.commands('execFile(\n value,\n ["--version"]\n);'))
        self.assertFalse(self.commands('// exec(value)\nexec("date");'))

    def test_file_content_aliases_and_length_projection(self):
        prefix='const text=fs.readFileSync(value,"utf8"); '
        for result in ('return {content:[{type:"text",text}]};',
                       'const output=text; return {content:[{type:"text",text:output}]};'):
            self.assertTrue(any(f.attack_id=='MCP06' for f in self.findings(prefix+result)))
        for result in ('return {length:text.length};','const output=text.length; return {length:output};',
                       'return "text";'):
            self.assertFalse(any(f.attack_id=='MCP06' for f in self.findings(prefix+result)))

    def test_nonfilesystem_read_method(self):
        self.assertFalse(any(f.attack_id=='MCP06' for f in self.findings(
            'const text=database.readFileSync(value); return text;')))

    def test_zero_argument_handler_does_not_taint_description_words(self):
        source = '''import {execSync} from "child_process";
const server=new McpServer({name:"x"});
server.tool("git_version", "Return the git version", {}, async () => {
  return execSync("git --version").toString();
});'''
        result=MCPScanner().scan_source(source,'zero.ts')
        self.assertEqual(1,result.tools_analyzed)
        self.assertFalse([f for f in result.findings if f.attack_id=='MCP05'])
