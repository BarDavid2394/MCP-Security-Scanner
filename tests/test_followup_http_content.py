import unittest
from mcp_scanner.scanner import MCPScanner


class HttpContentTests(unittest.TestCase):
    def scan(self, expression):
        source='''from fastmcp import FastMCP
import httpx
from mcp_scanner.defenses import sanitize_content
mcp=FastMCP("x")
@mcp.tool()
async def article(title: str):
    async with httpx.AsyncClient() as client:
        response=await client.get("https://example.invalid/", params={"title":title})
        data=response.json()
        return '''+expression+'\n'
        return [f for f in MCPScanner().scan_source(source).findings if f.attack_id=='MCP06']

    def test_text_projection_and_alias(self):
        for expression in ('data["extract"]', 'f"Article: {data[\'extract\']}"', 'data.get("body", "")'):
            self.assertTrue(self.scan(expression),expression)

    def test_status_counts_and_sanitized_text(self):
        for expression in ('response.status_code', 'data["count"]', 'len(data["extract"])',
                           'sanitize_content(data["extract"])'):
            self.assertFalse(self.scan(expression),expression)

    def test_unrelated_json_method_not_http(self):
        source='''from fastmcp import FastMCP
mcp=FastMCP("x")
@mcp.tool()
def extract(database):
    data=database.json()
    return data['extract']
'''
        self.assertFalse([f for f in MCPScanner().scan_source(source).findings if f.attack_id=='MCP06'])
