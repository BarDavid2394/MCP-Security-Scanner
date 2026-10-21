"""
Allow running as: python -m mcp_scanner
"""

from .main import main
import sys

if __name__ == "__main__":
    sys.exit(main())
