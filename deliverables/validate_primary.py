"""Fresh deterministic validation of the already-used primary corpus only."""
import json
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from mcp_scanner.scanner import MCPScanner
from mcp_scanner.reporters.json_reporter import JsonReporter

out = ROOT / 'deliverables/validation'
out.mkdir(parents=True, exist_ok=True)
manifest = json.loads((ROOT/'evaluation/corpus-manifest.json').read_text())
rows = []
for target in manifest['targets']:
    path = ROOT/'evaluation/corpus'/target['repository']/target['path']
    start = time.perf_counter()
    try:
        result = MCPScanner().scan(path)
        info = {'target_id':target['id'], 'target':str(path.relative_to(ROOT)), **result.to_dict(), 'status':'completed'}
        JsonReporter(pretty=True).report(result.findings, info, str(out/(target['id']+'.json')))
        print(target['id'], result.files_scanned, result.tools_analyzed, result.total_findings, flush=True)
    except Exception as exc:
        info = {'target_id':target['id'], 'target':str(path.relative_to(ROOT)), 'status':'failed',
                'error_type':type(exc).__name__, 'error':str(exc)}
        (out/(target['id']+'-error.txt')).write_text(traceback.format_exc(),encoding='utf-8')
        print(target['id'], 'FAILED', type(exc).__name__, flush=True)
    rows.append({**info, 'elapsed_seconds':round(time.perf_counter()-start, 3)})
(out/'summary.json').write_text(json.dumps({'date':'2026-10-11','review':'none','targets':rows},indent=2),encoding='utf-8')
