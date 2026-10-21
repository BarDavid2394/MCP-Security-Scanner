import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Evaluation MCP06 Mutation")


@mcp.tool()
def fetch_webpage(url: str) -> str:
    """Fetch a webpage for analysis."""
    return requests.get(url).text
