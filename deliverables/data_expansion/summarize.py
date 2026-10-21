"""Recount acquired files and records without executing upstream programs."""
import ast
import collections
import csv
import hashlib
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parent.parent

def digest(data): return hashlib.sha256(data).hexdigest()
def dump(name, data): (ROOT/name).write_text(json.dumps(data, indent=2), encoding='utf-8')
def read(path): return json.loads(path.read_text(encoding='utf-8'))

manifest=[]
for p in (ROOT/'snapshots').glob('*/SNAPSHOT.json'): manifest.extend(read(p)['files'])
for p in (ROOT/'huggingface').glob('*_download.json'): manifest.extend(read(p))
manifest.extend(read(ROOT/'advisory_pairs/manifest.json'))
for x in manifest:
    p=Path(x['local_path'])
    if not p.is_absolute() and not p.exists(): p=ROOT/p
    try:
        data=p.read_bytes()
        assert len(data)==x['bytes'] and digest(data)==x['sha256'], str(p)
        x['readback_status']='verified'
    except OSError as e:
        x['readback_status']='unreadable: '+str(e)
    x['local_path']=p.resolve().relative_to(ROOT).as_posix()
dump('download_manifest.json',manifest)

existing={}
excluded={'.git','.venv','node_modules','__pycache__','.mcp-scanner-cache'}
for folder in ['evaluation/corpus','evaluation/corpus-external','tests/samples','evaluation/fixtures','deliverables/new_samples']:
    for p in (PROJECT/folder).rglob('*'):
        if not p.is_file() or any(t in excluded for t in p.parts) or p.suffix=='.bak': continue
        try: data=p.read_bytes()
        except OSError: continue
        existing.setdefault(digest(data),[]).append(p.relative_to(PROJECT).as_posix())
overlaps=[]
for x in manifest:
    if x['sha256'] in existing:
        overlaps.append(dict(local_path=x['local_path'],upstream_path=x['upstream_path'],matches=existing[x['sha256']]))
dump('exact_file_overlaps.json',overlaps)

native=[]
for x in manifest:
    repo=x.get('repository','');p=x['upstream_path']
    if not p.endswith('.py'):continue
    include=False;polarity='unclassified';group=p
    if repo=='autod3structeur/MCP-DecayBench' and p.startswith('corpus/'):
        include=True;group='/'.join(p.split('/')[:3]);polarity='negative' if '/benign/' in p else 'positive'
    elif repo=='cisco-ai-defense/mcp-scanner' and (p.startswith(('evals/behavioral-analysis/data/','evals/remote/')) or p.endswith('/safe_fastmcp_server.py')):
        include=True;polarity='positive' if '/data/' in p or '/malicious/' in p else 'negative'
        group='/'.join(p.split('/')[:-1]) if '/data/' in p else p
    elif repo=='akanthed/SecureAI-Scan' and p.startswith('test-fixtures/'):
        include=True;polarity='negative' if '/safe/' in p else 'positive'
    elif repo=='jaimenbell/mcp-security-scanner' and p.startswith('tests/fixtures/'):
        include=True;group=p.split('/')[2]
        if group.startswith('clean_'):polarity='negative'
        elif group.startswith('vuln_'):polarity='positive'
    elif repo=='jspillers10/mcp-security-scanner' and '/fixtures/' in p:
        include=True
        if any(s in p for s in ('/safe_', '/clean_', '/false_positive/','/cross_file_safe/')):polarity='negative'
        elif any(s in p for s in ('/vulnerable_', '/false_negative/','/cross_file_vulnerable/','/cross_file_two_hops/')):polarity='positive'
        # Seven false-negative boundary cases are explicitly excluded by upstream's scanner scope.
    if not include:continue
    try:
        text=(ROOT/x['local_path']).read_text(encoding='utf-8-sig')
        try: tree=ast.parse(text);syntax='valid'
        except SyntaxError:syntax='invalid'
    except OSError:
        text='unreadable';syntax='unreadable'
    native.append(dict(repository=repo,upstream_path=p,local_path=x['local_path'],sha256=x['sha256'],family_group=repo+':'+group,upstream_polarity_hint=polarity,python_syntax=syntax,empty=not text.strip(),label_status='candidate: requires our rule-level review',used_in_our_scanner=False))
dump('native_fixture_candidates.json',native)
native_summary=[]
for repo in sorted({x['repository'] for x in native}):
    rows=[x for x in native if x['repository']==repo]
    native_summary.append(dict(repository=repo,files=len(rows),exact_unique_files=len({x['sha256'] for x in rows}),nonempty_files=sum(not x['empty'] for x in rows),polarity_hints=dict(collections.Counter(x['upstream_polarity_hint'] for x in rows)),syntax=dict(collections.Counter(x['python_syntax'] for x in rows))))

bord=[]
for p in (ROOT/'snapshots/n1ps__bordair-dataset').rglob('*.json.txt'):
    data=read(p)
    if isinstance(data,list):bord.extend(x for x in data if isinstance(x,dict) and 'expected_detection' in x)
bstats={}
for label in [True,False]:
    rows=[x for x in bord if x['expected_detection']==label]
    textrows=[x for x in rows if x.get('modalities')==['text']]
    bstats['attack' if label else 'benign']=dict(records=len(rows),distinct_text_fields=len({x.get('text','') for x in rows}),text_only_records=len(textrows),distinct_text_only=len({x.get('text','') for x in textrows}),categories=dict(collections.Counter(x['category'] for x in rows)))
bstats['explicit_mcp_records']=sum(x['category'] in ('mcp_tool_injection','mcp_cross_server_exfil') for x in bord)

vault=[]
for p in (ROOT/'snapshots/vaultmcp__vault').rglob('*.json.txt'):
    d=read(p)
    if isinstance(d,list):vault.append(dict(file=p.relative_to(ROOT).as_posix(),records=len(d),labels=dict(collections.Counter(x.get('expected_verdict','pattern-bank-unlabelled') for x in d))))
andy=read(ROOT/'snapshots/andyscott88__prompt-injection-bench/attack-test-set.json.txt')['cases']
atr=[json.loads(s) for s in (ROOT/'huggingface/Agent-Threat-Rule__atr-skill-benchmark/atr-skill-benchmark.jsonl.txt').read_text(encoding='utf-8').splitlines() if s.strip()]
sys.path.insert(0,str(Path(tempfile.gettempdir())/'mcp-book-libs'))
import pyarrow.parquet as pq
fbas=[]
for p in (ROOT/'huggingface/johnhalloran__mcp-fbas').rglob('*.parquet.txt'):
    t=pq.read_table(p)
    fbas.append(dict(split=p.parent.name,rows=t.num_rows,columns=t.column_names))
stats=dict(downloaded_files=len(manifest),readback_verified_files=sum(x['readback_status']=='verified' for x in manifest),unique_file_hashes=len({x['sha256'] for x in manifest}),downloaded_bytes=sum(x['bytes'] for x in manifest),github_repositories=len({x['repository'] for x in manifest if 'repository' in x}),hf_datasets=len({x['dataset'] for x in manifest if 'dataset' in x}),exact_overlap_files=len(overlaps),native_fixture_candidates=native_summary,native_total=len(native),native_unique=len({x['sha256'] for x in native}),native_nonempty=sum(not x['empty'] for x in native),native_unique_nonempty=len({x['sha256'] for x in native if not x['empty']}),bordair=bstats,vault=vault,andy=dict(records=len(andy),labels=dict(collections.Counter(x['expected'] for x in andy))),atr=dict(records=len(atr),labels=dict(collections.Counter(x['label'] for x in atr)),source_families=dict(collections.Counter(x['source_family'] for x in atr))),fbas=fbas)
dump('verified_counts.json',stats)
print(json.dumps({k:v for k,v in stats.items() if k not in ('bordair','vault','atr')},indent=2))
print('Bordair:',json.dumps({k:{a:b for a,b in v.items() if a!='categories'} if isinstance(v,dict) else v for k,v in bstats.items()}))
