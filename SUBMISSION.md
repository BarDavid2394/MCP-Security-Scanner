# Submission contents and reproduction

This distribution contains the scanner source, tests, interactive scan and fix
workflow, evaluation utilities, and the project book.

## Run locally

Python 3 is sufficient for the scanner and tests; no core packages need installing.

```powershell
python -m unittest discover -v
python -m mcp_scanner rules
python -m mcp_scanner scan tests/samples/clean_server.py
python scan_and_fix.py
```

The interactive workflow uses isolated copies of the bundled intentionally
vulnerable MCP fixtures. It displays HTML/JSON report links, asks which eligible
MCP03/MCP06 findings to repair, rescans the edited files, and restores the working
copies after reporting. It does not execute a target server.

## Contents

- `mcp_scanner/`: scanner, analyzers, reporters, and repair helpers.
- `tests/` and `evaluation/fixtures/`: tests and illustrative source fixtures.
- `evaluation/scripts/` and `evaluation/corpus-manifest.json`: evaluation
  utilities and pinned source acquisition metadata; see `evaluation/README.md`.
- `demo.py`, `scan_and_fix.py`, and `presentation_demo.py`: local demonstrations.
- `deliverables/`: the project book, its figures, and document build scripts.

Downloaded third-party source and local evaluation data are not bundled.
Ordinary unit tests and the interactive workflow work without those downloads.
