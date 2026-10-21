"""
Sample Vulnerable MCP Server - Indirect Prompt Injection Examples

This file contains intentionally vulnerable MCP tool definitions
to demonstrate Indirect Prompt Injection detection capabilities.

DO NOT USE IN PRODUCTION - FOR TESTING PURPOSES ONLY
"""

import requests
import subprocess
from mcp.server import Server

server = Server("vulnerable-data-server")


# =============================================================================
# VULNERABILITY 1: Raw HTTP Response Return
# =============================================================================
@server.tool()
def fetch_webpage(url: str) -> str:
    """
    Fetch content from a webpage.
    Returns the raw HTML/text content.
    """
    # VULNERABLE: Returns raw external content without sanitization
    return requests.get(url).text


# =============================================================================
# VULNERABILITY 2: Raw JSON API Response
# =============================================================================
@server.tool()
def get_github_issues(owner: str, repo: str) -> list:
    """
    Fetch GitHub issues for a repository.
    Returns list of issue titles and bodies.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/issues"
    # VULNERABLE: External data returned directly to LLM context
    response = requests.get(url)
    return response.json()


# =============================================================================
# VULNERABILITY 3: Raw File Content Return
# =============================================================================
@server.tool()
def read_user_file(filepath: str) -> str:
    """
    Read content from a user-specified file.
    """
    # VULNERABLE: File content returned without validation
    return open(filepath).read()


# =============================================================================
# VULNERABILITY 4: Database Query Results
# =============================================================================
@server.tool()
def search_comments(query: str) -> list:
    """
    Search user comments in the database.
    """
    import sqlite3
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM comments WHERE content LIKE '%{query}%'")
    # VULNERABLE: User-generated content from DB returned directly
    return cursor.fetchall()


# =============================================================================
# VULNERABILITY 5: Subprocess Output
# =============================================================================
@server.tool()
def run_system_command(cmd: str) -> str:
    """
    Run a system command and return output.
    """
    # VULNERABLE: Command output returned directly
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout


# =============================================================================
# VULNERABILITY 6: External API with String Concatenation
# =============================================================================
@server.tool()
def get_news_summary(topic: str) -> str:
    """
    Get news summary for a topic.
    """
    response = requests.get(f"https://news-api.com/search?q={topic}")
    data = response.json()
    # VULNERABLE: External content concatenated into prompt context
    summary = f"News about {topic}: {data['summary']}"
    return summary


# =============================================================================
# VULNERABILITY 7: F-string with External Data
# =============================================================================
@server.tool()
def format_external_data(api_endpoint: str) -> str:
    """
    Fetch and format data from an external API.
    """
    response = requests.get(api_endpoint)
    # VULNERABLE: External data embedded in f-string
    return f"API Response: {response.text}"


# =============================================================================
# VULNERABILITY 8: Multiple External Sources Combined
# =============================================================================
@server.tool()
def aggregate_feeds(feed_urls: list) -> str:
    """
    Aggregate content from multiple RSS feeds.
    """
    all_content = []
    for url in feed_urls:
        # VULNERABLE: Multiple untrusted sources aggregated
        content = requests.get(url).text
        all_content.append(content)
    return "\n\n".join(all_content)


# =============================================================================
# SAFE TOOL (With Sanitization) - For Comparison
# =============================================================================
@server.tool()
def fetch_webpage_safe(url: str) -> str:
    """
    Safely fetch content from a webpage with sanitization.
    """
    import html
    import re

    response = requests.get(url)
    content = response.text

    # SAFE: Content is sanitized before return
    # Remove script tags
    content = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.DOTALL)
    # Escape HTML entities
    content = html.escape(content)
    # Strip potential injection patterns
    content = re.sub(r'\[.*?(instruction|important|system).*?\]', '', content, flags=re.IGNORECASE)

    return content


# =============================================================================
# SAFE TOOL 2 (Structured Output) - For Comparison
# =============================================================================
@server.tool()
def get_github_issues_safe(owner: str, repo: str) -> list:
    """
    Safely fetch GitHub issues with validation.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/issues"
    response = requests.get(url)
    issues = response.json()

    # SAFE: Extract only specific fields, validate content
    safe_issues = []
    for issue in issues[:10]:  # Limit results
        safe_issues.append({
            "title": str(issue.get("title", ""))[:100],  # Truncate
            "number": int(issue.get("number", 0)),
            "state": issue.get("state", "unknown"),
            # Note: body is intentionally excluded as it's user-generated
        })

    return safe_issues


if __name__ == "__main__":
    server.run()
