"""One-shot follow-up validation, with independent locks and consumed marker.

This preserves the original holdout and its consumed status. Labels and scanner
hashes must be locked before predictions. No target is imported or executed.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import zipfile

ROOT=Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def preflight(root, manifest, lock):
    from mcp_scanner.catalog import RULES
    if not manifest.get('artifacts'): raise ValueError('Empty validation set')
    for relative, expected in lock['code_files'].items():
        path=(root/relative).resolve()
        if not path.is_relative_to(root.resolve()) or digest(path)!=expected:
            raise ValueError('Frozen code changed: '+relative)
    ids=set()
    for artifact in manifest['artifacts']:
        if artifact['id'] in ids: raise ValueError('Duplicate artifact ID')
        ids.add(artifact['id'])
        path=(root/artifact['path']).resolve()
        if not path.is_relative_to((root/'deliverables/data_expansion/snapshots').resolve()):
            raise ValueError('Source outside snapshot root')
        if digest(path)!=artifact['sha256']: raise ValueError('Source hash mismatch')
        if not artifact.get('labels'): raise ValueError('Missing reviewed labels')
        keys=set()
        for label in artifact['labels']:
            rule=label['rule_id']
            if rule in keys or rule not in RULES or label['polarity'] not in {'positive','negative'}:
                raise ValueError('Invalid or duplicate label')
            if not label.get('rationale'): raise ValueError('Missing label rationale')
            keys.add(rule)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--manifest',type=Path,required=True)
    args=parser.parse_args()
    path=args.manifest.resolve()
    if not path.is_relative_to(ROOT/'evaluation/followup/final'):
        parser.error('Follow-up final manifest required')
    consumed=path.parent/'CONSUMED.json'
    if consumed.exists(): raise SystemExit('Follow-up reserve already consumed')
    if digest(path)!=(path.parent/'manifest.sha256').read_text().strip():
        raise SystemExit('Manifest lock mismatch')
    manifest=json.loads(path.read_text())
    lock=json.loads((path.parent/'code-lock.json').read_text())
    sys.path.insert(0,str(ROOT))
    preflight(ROOT,manifest,lock)
    out=path.parent/'results'
    out.mkdir(exist_ok=False)
    with zipfile.ZipFile(out/'code_snapshot.zip','x',zipfile.ZIP_DEFLATED) as archive:
        for relative in lock['code_files']: archive.write(ROOT/relative,relative)
    record=dict(status='in-progress',started_at=datetime.now(timezone.utc).isoformat(),
                manifest_sha256=digest(path),review='none',target_execution=False)
    with consumed.open('x',encoding='utf-8') as handle: json.dump(record,handle,indent=2)
    from mcp_scanner.scanner import MCPScanner
    from evaluation.scripts.run_iteration import score
    predictions=[]
    for artifact in manifest['artifacts']:
        row=dict(artifact_id=artifact['id'])
        try:
            source=ROOT/artifact['path']
            result=MCPScanner().scan_source(source.read_text(encoding='utf-8'),artifact['source_filename'])
            row.update(status='parse_error' if result.parse_errors else 'completed',
                       findings=[f.to_dict() for f in result.findings],scan_info=result.to_dict())
        except Exception as exc:
            row.update(status='failed',error=type(exc).__name__+': '+str(exc))
        predictions.append(row)
    (out/'predictions.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in predictions),encoding='utf-8')
    preflight(ROOT,manifest,lock)
    if digest(path)!=record['manifest_sha256']: raise ValueError('Manifest changed during validation')
    metrics=score(manifest,predictions)
    (out/'metrics.json').write_text(json.dumps(metrics,indent=2)+'\n',encoding='utf-8')
    record.update(status='completed',completed_at=datetime.now(timezone.utc).isoformat(),
                  code_unchanged=True,artifacts=len(predictions),micro=metrics['micro'])
    consumed.write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(record,indent=2))


if __name__=='__main__': main()
