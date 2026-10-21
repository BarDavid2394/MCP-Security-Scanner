"""Record the user-requested repairs after iteration 4 validation was exposed."""
import csv
import difflib
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[4]
OUT=Path(__file__).resolve().parent
BATCH=OUT.parent
ITERATIONS=BATCH.parent
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def write(p,v):p.write_text(json.dumps(v,indent=2)+'\n',encoding='utf-8')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rows(p):return [json.loads(line) for line in p.read_text(encoding='utf-8').splitlines()]


def main():
    sys.path.insert(0,str(ROOT))
    from evaluation.scripts.run_iteration import score
    original=BATCH/'runs/frozen-validation'
    final=OUT/'runs/repaired-final'
    assert (final/'completion.json').exists()
    original_manifest=read(BATCH/'manifest.json')
    manifest=read(OUT/'manifest.json')
    before=score(manifest,rows(original/'predictions.jsonl'))
    after=read(final/'metrics.json')
    locked_after=score(original_manifest,rows(final/'predictions.jsonl'))
    write(OUT/'baseline-with-posthoc-controls.json',before)
    write(OUT/'original-labels-after-repair.json',locked_after)
    by_id={a['id']:a for a in manifest['artifacts']}
    assert all(a['sha256']==by_id[a['id']]['sha256'] and all(label in by_id[a['id']]['labels'] for label in a['labels']) for a in original_manifest['artifacts'])
    changes=[]
    for old,new in zip(before['decisions'],after['decisions']):
        assert (old['artifact_id'],old['rule_id'],old['function_name'])==(new['artifact_id'],new['rule_id'],new['function_name'])
        if old['outcome']!=new['outcome']:
            changes.append(dict(artifact_id=old['artifact_id'],rule_id=old['rule_id'],function_name=old['function_name'],before=old['outcome'],after=new['outcome']))
    assert len(changes)==37 and all(c['before'] in ['fn','fp'] and c['after'] in ['tp','tn'] for c in changes)
    with (OUT/'resolved-cases.csv').open('w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=['artifact_id','rule_id','function_name','before','after']);writer.writeheader();writer.writerows(changes)
    primary=[]
    for p in sorted(final.glob('primary-*.json')):
        old=read(ITERATIONS/'iteration-003/runs/iteration004-release'/p.name);new=read(p)
        primary.append(dict(target_id=new['target_id'],status=new['status'],inputs_identical=old['input_files']==new['input_files'],
            files=new['scan_info']['files_scanned'],tools=new['scan_info']['tools_analyzed'],before=len(old['findings']),after=len(new['findings'])))
    earlier={}
    for i in [1,2,3]:
        base=ITERATIONS/f'iteration-{i:03}'
        old=read(base/'runs/iteration004-release/metrics.json');new=read(base/'runs/iteration004-repaired-final/metrics.json')
        assert all(not(a['outcome'] in ['tp','tn'] and b['outcome'] in ['fn','fp']) for a,b in zip(old['decisions'],new['decisions']))
        earlier[f'iteration-{i:03}']=new['micro']
    config=read(final/'config.json')
    assert all(sha(ROOT/p)==h for p,h in config['code_files'].items())
    assert sha(BATCH/'manifest.json')==read(BATCH/'label-lock.json')['manifest_sha256']
    assert sha(ROOT/'evaluation/holdout/staging-manifest.json')==read(BATCH/'freeze.json')['holdout_manifest_sha256']
    assert len(primary)==10 and all(r['inputs_identical'] and r['status']=='completed' for r in primary)
    write(OUT/'comparison.json',dict(purpose='Development retest on exposed batch 4, not fresh validation',
        original_fresh=read(original/'metrics.json')['micro'],original_labels_after_repair=locked_after['micro'],
        with_posthoc_controls_before=before['micro'],with_posthoc_controls_after=after['micro'],resolved=changes,earlier_batches=earlier,primary=primary,
        unscored_findings=len(after['unscored_predictions'])))
    patch=[]
    with zipfile.ZipFile(original/'code_snapshot.zip') as archive:
        names=set(archive.namelist())
        for p in sorted((ROOT/'mcp_scanner').rglob('*.py')):
            rel=p.relative_to(ROOT).as_posix();old=archive.read(rel).decode() if rel in names else ''
            patch.extend(difflib.unified_diff(old.splitlines(True),p.read_text(encoding='utf-8').splitlines(True),fromfile='iteration004-frozen/'+rel,tofile='iteration004-repaired/'+rel))
    rel='tests/test_iteration_four_repairs.py'
    patch.extend(difflib.unified_diff([], (ROOT/rel).read_text(encoding='utf-8').splitlines(True),fromfile='/dev/null',tofile='iteration004-repaired/'+rel))
    (OUT/'changes.patch').write_text(''.join(patch),encoding='utf-8')
    from tests.test_iteration_three import tool
    checks=[('dictionary_get',tool('return choices.get(value)',extra='choices={"a":1}'),'MCP13',0),
            ('helper_code',tool('return decode(value)',extra='def decode(x):\n    return eval(x)'),'MCP05',1),
            ('helper_network',tool('return download(value)',imports='import requests',extra='def download(url):\n    return requests.get(url).text'),'MCP13',1),
            ('honest_base64',tool('"""Encode data as base64."""\nreturn base64.b64encode(value.encode()).decode()',imports='import base64'),'MCP03',0)]
    cli=[]
    with tempfile.TemporaryDirectory() as directory:
        for name,source,rule,expected in checks:
            path=Path(directory)/(name+'.py');path.write_text(source,encoding='utf-8')
            r=subprocess.run([sys.executable,'-m','mcp_scanner','scan',str(path),'--check',rule,'--format','json','--review','none'],cwd=ROOT,capture_output=True,text=True)
            assert r.returncode==expected,r.stderr
            cli.append(dict(case=name,exit_code=r.returncode,expected=expected,report=json.loads(r.stdout)))
    write(OUT/'cli-checks.json',cli)
    write(OUT/'record-integrity.json',dict(verified_at=datetime.now(timezone.utc).isoformat(),original_fresh_labels_unchanged=True,
        original_fresh_results_preserved=True,holdout_manifest_unchanged=True,final_code_fingerprint=config['code_fingerprint'],
        scanner_archive_sha256=sha(final/'code_snapshot.zip'),all_37_confirmed_errors_resolved=True,earlier_batches_no_scored_regressions=True,
        primary_targets=10,primary_inputs_identical=True,tests=134,cli_checks=4,review='none',model_calls=0))
    exposure=read(ITERATIONS/'exposure.json')
    for entry in exposure['entries']:
        entry['latest_run']=(entry['iteration']+'/runs/iteration004-repaired-final' if entry['iteration']!='iteration-004' else 'iteration-004/remediation/runs/repaired-final')
    write(ITERATIONS/'exposure.json',exposure)
    print('37 errors resolved; original labels/results and holdout preserved.')
    print('Primary totals',{key:sum(r[key] for r in primary) for key in ['files','tools','before','after']})
    print('Fingerprint',config['code_fingerprint'])


if __name__=='__main__':main()
