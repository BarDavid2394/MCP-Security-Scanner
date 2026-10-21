"""
Sample Clean MCP Server - No Vulnerabilities

This file contains properly implemented MCP tools without
security vulnerabilities. Used for testing false positive rates.
"""

from mcp.server import Server

server = Server("clean-calculator")


@server.tool()
def add(a: int, b: int) -> int:
    """
    Add two integers and return the sum.

    Args:
        a: First integer.
        b: Second integer.

    Returns:
        Sum of a and b.
    """
    return a + b


@server.tool()
def subtract(a: int, b: int) -> int:
    """
    Subtract b from a and return the difference.

    Args:
        a: Number to subtract from.
        b: Number to subtract.

    Returns:
        Difference of a and b.
    """
    return a - b


@server.tool()
def multiply(a: int, b: int) -> int:
    """
    Multiply two integers and return the product.

    Args:
        a: First integer.
        b: Second integer.

    Returns:
        Product of a and b.
    """
    return a * b


@server.tool()
def divide(a: float, b: float) -> float:
    """
    Divide a by b and return the quotient.

    Args:
        a: Dividend.
        b: Divisor (must not be zero).

    Returns:
        Quotient of a divided by b.

    Raises:
        ValueError: If b is zero.
    """
    if b == 0:
        raise ValueError("Cannot divide by zero")
    return a / b


if __name__ == "__main__":
    server.run()
