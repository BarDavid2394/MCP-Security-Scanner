from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Evaluation Clean")


@mcp.tool()
def add(a: int, b: int) -> int:
    """Return the sum of two integers."""
    return a + b
