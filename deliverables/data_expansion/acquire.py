"""Acquire pinned, inert research snapshots. Never import or execute upstream code."""
import concurrent.futures as cf
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parent
HEADERS = {"User-Agent": "MCP-degree-validation-research"}

def fetch(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=HEADERS), timeout=90) as r:
        return r.read()

def selected(repo, path):
    low = path.lower()
    if low in ('readme.md', 'license', 'license.md', 'license.txt', 'copying'):
        return True
    if repo == 'autod3structeur/MCP-DecayBench':
        return path.startswith('corpus/')
    if repo == 'cisco-ai-defense/mcp-scanner':
        return path.startswith(('evals/behavioral-analysis/data/', 'evals/remote/', 'tests/readiness/fixtures/')) or path in ('evals/README.md', 'evals/behavioral-analysis/scripts/safe_fastmcp_server.py')
    if repo == 'akanthed/SecureAI-Scan':
        return path.startswith('test-fixtures/') and '/skills/' not in path and Path(path).suffix in ('.py','.ts','.json','.yaml')
    if repo == 'vaultmcp/vault':
        return path.startswith('packages/eval/datasets/') or path in ('packages/corpus/corpus-sources.md','packages/corpus/injection-patterns.json','packages/proxy/test/fixtures/benign-encoded/fixtures.json')
    if repo == 'n1ps/bordair-dataset':
        return (path.startswith(('payloads/', 'payloads_v2/', 'payloads_v3/', 'payloads_v4/', 'payloads_v5/')) and path.endswith('.json')) or path in ('benign/text_only.json','benign/summary.json')
    if repo == 'ferentin-net/mcp-guard':
        return any(t in low for t in ('fixture','dataset','corpus','sample','benchmark','test/','tests/')) and Path(path).suffix in ('.py','.json','.jsonl','.yaml','.yml','.md','.ts','.txt')
    if repo == 'dnyandeobharambe/mcp-security-patterns':
        return Path(path).suffix in ('.py','.json','.yaml','.yml','.md')
    if repo == 'johnhalloran321/mcp_safety_training':
        return Path(path).suffix in ('.json','.jsonl','.csv','.md')
    return Path(path).suffix in ('.py','.js','.ts','.json','.md','.yaml','.yml') and 'lock' not in low

REPOS = [
    'autod3structeur/MCP-DecayBench', 'cisco-ai-defense/mcp-scanner',
    'akanthed/SecureAI-Scan', 'vaultmcp/vault', 'n1ps/bordair-dataset',
    'ferentin-net/mcp-guard', 'dnyandeobharambe/mcp-security-patterns',
    'johnhalloran321/mcp_safety_training', 'osuleimen/sekrd-mcp-vuln-test',
    'vedikasaklani/mcp-code-vulns', 'abhijeet497/vuln-cmdinjection-node-mcp',
    'abhijeet497/vuln-ssrf-node-mcp', 'ak4hit/mcp-hardening-benchmark',
]

def acquire(repo):
    sha = subprocess.check_output(['git','ls-remote','https://github.com/'+repo+'.git','HEAD'], text=True, timeout=45).split()[0]
    folder = ROOT/'snapshots'/repo.replace('/','__')
    folder.mkdir(parents=True, exist_ok=True)
    rows=[]
    def save(path, data):
        rel=Path(path)
        if rel.is_absolute() or '..' in rel.parts:
            raise ValueError('Unsafe upstream path')
        dest=folder/(path+'.txt')
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_bytes(data)
        rows.append(dict(repository=repo,revision=sha,upstream_path=path,local_path=dest.relative_to(ROOT).as_posix(),bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),url=f'https://github.com/{repo}/blob/{sha}/{path}',used_in_our_scanner=False))
    if repo == 'n1ps/bordair-dataset':
        # Avoid the 481 MB derivative/ingested external bank and 98 MB mostly augmented benign bank.
        tree=json.loads((ROOT/'trees'/(repo.replace('/','__')+'.json')).read_text())
        paths=[r['path'] for r in tree['files'] if selected(repo,r['path'])]
        def one(path): return path, fetch(f'https://raw.githubusercontent.com/{repo}/{sha}/{path}')
        with cf.ThreadPoolExecutor(max_workers=5) as pool:
            for path,data in pool.map(one,paths): save(path,data)
    else:
        data=fetch(f'https://codeload.github.com/{repo}/tar.gz/{sha}')
        with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as tar:
            for member in tar:
                if not member.isfile(): continue
                path=member.name.partition('/')[2]
                if selected(repo,path): save(path,tar.extractfile(member).read())
    (folder/'SNAPSHOT.json').write_text(json.dumps(dict(repository=repo,revision=sha,files=rows),indent=2),encoding='utf-8')
    return dict(repository=repo,revision=sha,files=len(rows),bytes=sum(r['bytes'] for r in rows))

if __name__=='__main__':
    results=[]
    with cf.ThreadPoolExecutor(max_workers=3) as pool:
        jobs={pool.submit(acquire,repo):repo for repo in REPOS}
        for job in cf.as_completed(jobs):
            try: result=job.result()
            except Exception as e: result=dict(repository=jobs[job],error=str(e))
            results.append(result);print(json.dumps(result),flush=True)
    (ROOT/'acquisition_summary.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
    rows=[]
    for p in (ROOT/'snapshots').glob('*/SNAPSHOT.json'): rows.extend(json.loads(p.read_text())['files'])
    (ROOT/'download_manifest.json').write_text(json.dumps(rows,indent=2),encoding='utf-8')
