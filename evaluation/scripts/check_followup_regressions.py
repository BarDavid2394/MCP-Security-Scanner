"""Compare initial and working scanners on exposed development manifests."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

ROOT=Path(__file__).resolve().parents[2]


def worker(package, output):
    sys.path.insert(0,str(package))
    from mcp_scanner.scanner import MCPScanner
    sys.path.append(str(ROOT))
    from evaluation.scripts.run_iteration import score
    results={}
    for number in range(1,11):
        path=ROOT/f'evaluation/iterations/iteration-{number:03}/manifest.json'
        manifest=json.loads(path.read_text(encoding='utf-8'))
        predictions=[]
        for artifact in manifest['artifacts']:
            source=ROOT/artifact['path']
            raw=source.read_bytes()
            assert hashlib.sha256(raw).hexdigest()==artifact['sha256']
            row={'artifact_id':artifact['id']}
            try:
                result=MCPScanner().scan_source(raw.decode('utf-8'),artifact['source_filename'])
                row.update(status='parse_error' if result.parse_errors else 'completed',
                           findings=[f.to_dict() for f in result.findings],scan_info=result.to_dict())
            except Exception as exc:
                row.update(status='failed',error=type(exc).__name__+': '+str(exc))
            predictions.append(row)
        results[str(number)]=dict(metrics=score(manifest,predictions),predictions=predictions)
        print(number,results[str(number)]['metrics']['micro'],flush=True)
    with output.open('x',encoding='utf-8') as handle: json.dump(results,handle,indent=2)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--worker',type=Path)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if args.worker:
        worker(args.worker,args.output)
        return
    out=ROOT/'evaluation/followup'
    with tempfile.TemporaryDirectory() as directory:
        with zipfile.ZipFile(out/'initial-code.zip') as archive:
            for name in archive.namelist():
                if name.startswith('mcp_scanner/') and name.endswith('.py'): archive.extract(name,directory)
        subprocess.run([sys.executable,__file__,'--worker',directory,'--output',str(out/'reference-regressions.json')],check=True)
    subprocess.run([sys.executable,__file__,'--worker',str(ROOT),'--output',str(out/'working-regressions.json')],check=True)


if __name__=='__main__': main()
