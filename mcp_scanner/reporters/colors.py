"""Shared severity hues for terminal output and standalone HTML reports.

Terminal themes control exact ANSI shades; HTML uses readable equivalents.
"""

SEVERITY_COLORS = {
    'CRITICAL': ('\033[91m', '#ff7b7b'),  # Red
    'HIGH': ('\033[93m', '#f5d76e'),      # Yellow
    'MEDIUM': ('\033[94m', '#82aaff'),    # Blue
    'LOW': ('\033[92m', '#7cdda1'),       # Green
    'INFO': ('\033[90m', '#aab6c8'),      # Gray
}
