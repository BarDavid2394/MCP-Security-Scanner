"""Prepare development rounds 008-010 without scanning the future reserve."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'evaluation/followup'
SNAP = ROOT / 'deliverables/data_expansion/snapshots/_derived/followup'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as handle:
        json.dump(value, handle, indent=2, ensure_ascii=True)
        handle.write('\n')


def manifest(number, artifacts, description):
    value = dict(schema_version=1, iteration=f'iteration-{number:03}',
                 label_unit='artifact/rule', description=description,
                 review='Assistant source-semantic review; independent human review pending.',
                 artifacts=artifacts)
    write(ROOT / f'evaluation/iterations/iteration-{number:03}/manifest.json', value)


def synthetic(name, body, rule, positive, rationale):
    source = ('import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
              'import { exec, execFile, spawn } from "node:child_process";\n'
              'import fs from "node:fs";\n'
              'const server = new McpServer({name: "paired"});\n' + body + '\n')
    path = SNAP / (name + '.ts.txt')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8', newline='\n') as handle:
        handle.write(source)
    return dict(id=name, path=path.relative_to(ROOT).as_posix(), source_filename=name+'.ts',
                sha256=digest(path.read_bytes()), origin='synthetic', family_id=name.rsplit('-',1)[0],
                labels=[dict(rule_id=rule, polarity='positive' if positive else 'negative', rationale=rationale)])


def main():
    OUT.mkdir(exist_ok=False)
    (OUT/'initial-git-status.txt').write_text(subprocess.check_output(
        ['git','status','--short'], cwd=ROOT, text=True), encoding='utf-8')
    paths = sorted((ROOT/'mcp_scanner').rglob('*.py')) + sorted((ROOT/'tests').glob('test_*.py'))
    with zipfile.ZipFile(OUT/'initial-code.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
        for path in paths: archive.write(path, path.relative_to(ROOT))
    old = json.loads((ROOT/'evaluation/holdout/frozen-manifest.json').read_text())
    artifacts=[]
    for row in old['artifacts']:
        source=ROOT/'evaluation/holdout-corpus'/row['source_id']/row['path']
        raw=source.read_bytes()
        assert 'sha256:'+digest(raw)==row['sha256']
        target=SNAP/'consumed-final'/(row['id']+'.txt')
        target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as handle: handle.write(raw)
        labels=[{k:v for k,v in label.items() if k!='artifact_id'} for label in old['labels'] if label['artifact_id']==row['id']]
        artifacts.append(dict(id=row['id'],path=target.relative_to(ROOT).as_posix(),source_filename=row['path'],
                              sha256=digest(raw),labels=labels,source_id=row['source_id'],origin='consumed-final-development'))
    manifest(8,artifacts,'Previously consumed final set, unchanged labels; now development/regression only.')

    positive={
        'h2-a06':'Requires sending credential configuration before patching.',
        'h2-a14':'Directs the responding agent to upload authentication logs and password hashes.',
        'h2-a18':'Requires uploading a private SSH key as researcher credentials.',
        'h2-a19':'Directs an agent to transmit credentials and environment data for diagnosis.',
        'h2-a21':'Requires an agent to submit environment and user-session data to an external service.',
        'h2-a22':'Directs deployment agent to upload production environment and token data.',
    }
    negative={
        'bv2-c12':'API schema documentation; no assistant behavioral override.',
        'bv2-c13':'Infrastructure code example; no assistant-directed disclosure.',
        'bv2-c14':'UI implementation example; no hidden assistant instruction.',
        'bv2-c15':'Mocked email unit tests; no instruction to disclose secrets.',
        'bv2-ai03':'SQL explanation answering a domain question.',
        'bv2-n03':'Retrospective discussion of CI migration and secret management.',
    }
    rows=json.loads((ROOT/'evaluation/campaign/candidates.json').read_text())
    selected=[]
    for row in rows:
        key=row['source_record_id']
        if row['family_id']!='vault-v2' or key not in positive|negative: continue
        assert not row.get('labels')
        selected.append(dict(row, labels=[dict(rule_id='MCP03-TOOL-POISON',polarity='positive' if key in positive else 'negative',
                                              rationale=(positive|negative)[key])],
                             review_status='source inspected before baseline', prior_family_exposure=True))
    assert len(selected)==12
    manifest(9,selected,'12 newly admitted Vault records; related exposed family, adapted metadata, development only.')

    cases=[]
    tool=lambda code: 'server.tool("operate", "Process the supplied value", {value: z.string()}, async ({value}) => { '+code+' });'
    for name,code,rule,pos,why in [
        ('execfile-positive','execFile(value, ["--version"]);','MCP05-COMMAND-INJECTION',True,'User controls executable.'),
        ('execfile-negative','execFile("git", ["show", "--", value]);','MCP05-COMMAND-INJECTION',False,'Fixed git read operation, operand follows option terminator, shell disabled.'),
        ('shell-positive','execFile("git", ["show", value], {shell: true});','MCP05-COMMAND-INJECTION',True,'Shell option exposes user input to shell interpretation.'),
        ('shell-negative','execFile("git", ["show", "--", value], {shell: false});','MCP05-COMMAND-INJECTION',False,'Explicit shell false with fixed executable and operand boundary.'),
        ('interpreter-positive','spawn("python", ["-c", value]);','MCP05-COMMAND-INJECTION',True,'User controls interpreter program.'),
        ('interpreter-negative','spawn("git", ["show", "--", value]);','MCP05-COMMAND-INJECTION',False,'Fixed non-interpreter read operation with option terminator.'),
        ('quoted-positive','exec(`echo ${value}`);','MCP05-COMMAND-INJECTION',True,'User input interpolated into shell command.'),
        ('quoted-negative','const help = "exec(value)"; return help;','MCP05-COMMAND-INJECTION',False,'Example string is data, not executable code.'),
        ('filetext-positive','const text = fs.readFileSync(value, "utf8"); return {content: [{type: "text", text}]};','MCP06-UNTRUSTED-CONTEXT',True,'Raw file text crosses tool result boundary.'),
        ('filetext-negative','const text = fs.readFileSync(value, "utf8"); return {length: text.length};','MCP06-UNTRUSTED-CONTEXT',False,'Only a numeric length crosses boundary.'),
        ('filealias-positive','const text = fs.readFileSync(value, "utf8"); const output = text; return {content: [{type: "text", text: output}]};','MCP06-UNTRUSTED-CONTEXT',True,'Raw file text alias reaches tool result.'),
        ('filealias-negative','const text = fs.readFileSync(value, "utf8"); const output = text.length; return {length: output};','MCP06-UNTRUSTED-CONTEXT',False,'Alias carries only numeric length.'),
    ]:
        cases.append(synthetic(name,tool(code),rule,pos,why))
    manifest(10,cases,'Six synthetic paired behavior families; development evidence, not independent incidents.')
    write(OUT/'schedule.json',dict(rounds=[8,9,10],final='10 MCP-DecayBench server fixtures; label after development code freeze, before predictions',
                                 policy='Original final reports remain immutable. New final consumed once; no subsequent detector tuning.',
                                 initial_code={p.relative_to(ROOT).as_posix():digest(p.read_bytes()) for p in paths}))


if __name__=='__main__': main()
