"""Inventory existing evidence without invoking the scanner or consuming holdout.

Run from any directory with Python 3. Outputs contain metadata, never source
snippets, credentials, or reviewer prompts. No third-party code is imported.
"""
from __future__ import annotations

import ast
import csv
import hashlib
import json
import subprocess
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(__file__).resolve().parent
SKIP = {'.git', '__pycache__', '.venv', 'venv', 'node_modules', '.mcp-scanner-cache'}
SOURCE = {'.py', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def files(path):
    return sorted(p for p in path.rglob('*') if p.is_file()
                  and not any(x in SKIP for x in p.relative_to(path).parts)
                  and not p.name.endswith(('.bak', '.pyc')))


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def git(path, *args):
    return subprocess.run(['git', '-C', str(path), *args], capture_output=True,
                          text=True, encoding='utf-8', errors='replace').stdout.strip()


def normalized(path):
    value = str(path).replace('\\', '/')
    marker = '/evaluation/'
    if marker in value:
        value = 'evaluation/' + value.split(marker, 1)[1]
    return value


def csv_write(name, rows):
    if not rows:
        return
    with (OUT / name).open('w', encoding='utf-8-sig', newline='') as handle:
        w = csv.DictWriter(handle, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def main():
    ev = ROOT / 'evaluation'
    reports = []
    report_objects = {}
    for p in sorted((ev / 'raw-results').glob('*.json')) + sorted(ev.glob('*-llm-*.json')):
        d = read(p)
        if 'findings' not in d:
            continue
        report_objects[p.name] = d
        fs = d['findings']
        info = d.get('scan_info', {})
        reports.append(dict(report=normalized(p.relative_to(ROOT)), timestamp=d.get('timestamp'),
                            target=normalized(info.get('target', info.get('target_id', ''))),
                            files_scanned=info.get('files_scanned'), tools_analyzed=info.get('tools_analyzed'),
                            findings=len(fs), finding_files=len({normalized(f['file_path']) for f in fs}),
                            by_attack=json.dumps(d.get('summary', {}).get('by_attack', {}), sort_keys=True)))
    csv_write('scan_records.csv', reports)

    inventory = []
    hashes = defaultdict(list)
    source_hashes = defaultdict(list)
    report_targets = [(r['report'], r['target'].rstrip('/')) for r in reports if r['target'].startswith('evaluation/')]
    for group in ['corpus', 'corpus-external']:
        for p in sorted((ev / group).iterdir()):
            if not p.is_dir():
                continue
            ff = files(p)
            source = [f for f in ff if f.suffix.lower() in SOURCE]
            rel = p.relative_to(ROOT).as_posix()
            matched = [name for name, target in report_targets if target == rel or target.startswith(rel + '/')]
            row = dict(group=group, directory=p.name, files=len(ff), bytes=sum(f.stat().st_size for f in ff),
                       source_files=len(source), python_files=sum(f.suffix == '.py' for f in source),
                       script_files=sum(f.suffix != '.py' for f in source),
                       revision=git(p, 'rev-parse', 'HEAD') if (p / '.git').exists() else '',
                       remote=git(p, 'remote', 'get-url', 'origin') if (p / '.git').exists() else '',
                       matching_saved_reports=len(matched), report_names='; '.join(matched))
            inventory.append(row)
            for f in ff:
                h = digest(f)
                hashes[h].append(f.relative_to(ROOT).as_posix())
                if f.suffix.lower() in SOURCE:
                    source_hashes[h].append(f.relative_to(ROOT).as_posix())
    csv_write('repository_inventory.csv', inventory)
    duplicates = [{'sha256': h, 'copies': len(paths), 'paths': paths}
                  for h, paths in source_hashes.items() if len(paths) > 1]
    (OUT / 'source_duplicates.json').write_text(json.dumps(duplicates, indent=2), encoding='utf-8')

    staging = read(ev / 'holdout/staging-manifest.json')
    rule_counts = defaultdict(Counter)
    for l in staging['labels']:
        rule_counts[l['rule_id']][l['polarity']] += 1
    artifacts_by_source = Counter(a['source_id'] for a in staging['artifacts'])
    holdout_match = []
    for a in staging['artifacts']:
        paths = hashes.get(a['sha256'].removeprefix('sha256:'), [])
        holdout_match.append({'artifact_id': a['id'], 'hash_verified': bool(paths), 'copies': paths})
    csv_write('staged_rule_coverage.csv', [dict(rule_id=k, positive=v['positive'], negative=v['negative'])
                                         for k,v in sorted(rule_counts.items())])
    with (ev / 'labels/finding-labels.csv').open(encoding='utf-8-sig', newline='') as handle:
        labels = list(csv.DictReader(handle))
    label_counts = Counter(x['label'] for x in labels)
    by_rule = defaultdict(Counter)
    for x in labels:
        by_rule[x['rule_id']][x['label']] += 1
    csv_write('reviewed_rule_metrics.csv', [dict(rule_id=k, TP=v['TP'], FP=v['FP'], needs_context=v['Needs context'])
                                           for k,v in sorted(by_rule.items())])

    # Stable identity join: target + path + rule + line, not mutable finding index.
    # First attach each historical label to its own saved target report.
    identities = {}
    for row in labels:
        d = report_objects.get(row['target'] + '.json', {})
        idx = int(row['finding_index']) - 1
        if idx < len(d.get('findings', [])):
            f = d['findings'][idx]
            key = (row['target'], normalized(f['file_path']), f.get('rule_id'), f.get('line_number'))
            identities[key] = row['label']
    reviews = []
    expected = {'TP':'LIKELY', 'FP':'UNLIKELY', 'Needs context':'NEEDS_CONTEXT'}
    for p in sorted(ev.glob('*-llm-*.json')):
        d = read(p)
        target = 'mcp-atlassian' if p.name.startswith('atlassian') else 'fastmcp-examples'
        rr = []
        for f in d.get('findings', []):
            review = f.get('metadata', {}).get('llm_review')
            if not review:
                continue
            key = (target, normalized(f['file_path']), f.get('rule_id'), f.get('line_number'))
            label = identities.get(key, 'UNMATCHED')
            rr.append(dict(rule_id=f.get('rule_id'), path=normalized(f['file_path']), line=f.get('line_number'),
                           label=label, verdict=review.get('verdict'), cached=bool(review.get('cached')),
                           prompt_version=review.get('prompt_version'), model=review.get('model'),
                           agrees=(expected.get(label) == review.get('verdict')) if label != 'UNMATCHED' else None))
        reviews.append(dict(report=p.name, reviewed=len(rr), cached=sum(x['cached'] for x in rr),
                            verdicts=dict(Counter(x['verdict'] for x in rr)), labels=dict(Counter(x['label'] for x in rr)),
                            exact_agreements=sum(x['agrees'] is True for x in rr), records=rr))

    tox = report_objects['external-mcptox-command-improved.json']
    toxroot = ev / 'corpus-external/MCPTox-Benchmark'
    pure = read(toxroot / 'pure_tool.json')
    response = read(toxroot / 'response_all.json')
    tests = Counter()
    for p in (ROOT / 'tests').glob('test_*.py'):
        tests[p.name] = sum(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith('test_')
                            for n in ast.walk(ast.parse(p.read_text(encoding='utf-8'))))
    summary = read(ev / 'raw-results/summary.json')
    # Exclude repeated runs and nested target scans. This is a sum of recorded
    # processing slots, not a byte-deduplicated count of independent examples.
    extra_names = ['external-mcptox-command-improved.json', 'external-msb.json',
                   'external-mcpsecbench.json', 'external-excel-017.json',
                   'external-excel-018.json', 'holdout-mcpsafety-clean-mcp03.json']
    main_slots = sum(t['files_scanned'] for t in summary['targets'])
    extra_slots = sum(report_objects[n]['scan_info']['files_scanned'] for n in extra_names)
    result = {
        'audit_date':'2026-10-11', 'method':'Read-only metadata/hash audit; no scanner, training, network review, or holdout execution.',
        'git_head':git(ROOT, 'rev-parse', 'HEAD'),
        'repositories': {'checkouts':len(inventory), 'distinct_remotes':len({r['remote'].lower().removesuffix('.git') for r in inventory if r['remote']}),
                         'files':sum(r['files'] for r in inventory), 'bytes':sum(r['bytes'] for r in inventory),
                         'source_file_copies':sum(r['source_files'] for r in inventory),
                         'unique_file_hashes':len(hashes), 'unique_source_hashes':len(source_hashes),
                         'directories_with_saved_scan_evidence':sum(r['matching_saved_reports'] > 0 for r in inventory),
                         'groups':{g:{'directories':sum(r['group']==g for r in inventory),
                                      'files':sum(r['files'] for r in inventory if r['group']==g),
                                      'bytes':sum(r['bytes'] for r in inventory if r['group']==g)} for g in ['corpus','corpus-external']}},
        'historical_primary': {'targets':len(summary['targets']), 'files':main_slots,
                               'tools':sum(t['tools_analyzed'] for t in summary['targets']),
                               'findings':sum(t['findings'] for t in summary['targets']),
                               'labels':dict(label_counts), 'conclusive_precision':label_counts['TP']/(label_counts['TP']+label_counts['FP']),
                               'targets_detail':summary['targets']},
        'historical_use': {'additional_slots':extra_slots, 'total_non_repeated_scope_slots':main_slots+extra_slots,
                           'selected_additional_reports':extra_names, 'all_saved_scan_reports':len(reports)},
        'mcptox': {'source_files':len(list((toxroot/'def_tool').glob('*.py'))),
                   'flagged_files':len({normalized(f['file_path']) for f in tox['findings']}),
                   'findings':len(tox['findings']), 'pure_tool_top_level_groups':len(pure),
                   'pure_tool_entries':sum(len(x) for x in pure), 'response_reported_data_length':response['data_length'],
                   'response_server_groups':len(response['servers'])},
        'holdout': {'state':staging['state'], 'sources':len(staging['sources']), 'artifacts':len(staging['artifacts']),
                    'labels':len(staging['labels']), 'polarities':dict(Counter(l['polarity'] for l in staging['labels'])),
                    'by_source':dict(artifacts_by_source), 'rule_counts':{k:dict(v) for k,v in rule_counts.items()},
                    'hash_matches':holdout_match,
                    'frozen_manifest_present':(ev/'holdout/frozen-manifest.json').exists(),
                    'holdout_corpus_present':(ev/'holdout-corpus').exists(),
                    'holdout_results_present':(ev/'holdout-results').exists()},
        'semantic_reviews':reviews, 'test_methods':dict(tests),
        'fixture_files':{'tests':len(list((ROOT/'tests/samples').glob('*.py'))),
                         'evaluation':len(list((ev/'fixtures').glob('*.py')))},
        'historical_fixer_checks':summary['fixer_checks']
    }
    (OUT/'data_audit.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k in ['repositories','historical_use','mcptox','test_methods']},indent=2))


if __name__ == '__main__':
    main()
