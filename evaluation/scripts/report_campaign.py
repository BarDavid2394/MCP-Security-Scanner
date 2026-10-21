"""Produce the presentation report from immutable recorded predictions."""
from __future__ import annotations
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import hashlib
from html import escape
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def read(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def write(path, value):
    (ROOT / path).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def percent(value):
    return "—" if value is None else f"{value*100:.1f}%"


def table(headers, rows):
    return '<table><thead><tr>'+''.join('<th>'+escape(str(x))+'</th>' for x in headers)+'</tr></thead><tbody>'+''.join('<tr>'+''.join('<td>'+escape(str(x))+'</td>' for x in row)+'</tr>' for row in rows)+'</tbody></table>'


def main():
    campaign = read("evaluation/campaign/schedule.json")
    freeze = read("evaluation/campaign/final-code-lock.json")
    consumed = read("evaluation/holdout/CONSUMED.json")
    assert consumed["status"] == "completed" and consumed["code_unchanged"]
    assert all(hashlib.sha256((ROOT/p).read_bytes()).hexdigest()==h for p,h in freeze["scanner_files"].items())
    holdout = read("evaluation/holdout/frozen-manifest.json")
    final = read("evaluation/holdout/metrics.json")
    rows, comparisons = [], []
    descriptions = {
        5: "Compound instruction overrides, bounded Unicode/spacing/leet normalization, credential directives, and local masking of quoted research examples. New semantic signals are report-only.",
        6: "Prefixed environment credential provenance, safe presence-only outputs, pathlib content through helpers, and fixed-format printf argument-list safety.",
        7: "Required auto-approval changes, remote-code setup instructions, credential-bearing registration URLs, hidden file uploads, and sensitive shell uploads.",
    }
    for number in (5,6,7):
        base = f"evaluation/iterations/iteration-{number:03}"
        manifest = read(base + "/manifest.json")
        before = read(base + "/runs/baseline/metrics.json")
        after = read(base + "/runs/repaired-final/metrics.json")
        a = before["micro"]; b = after["micro"]
        comparison = dict(iteration=number, artifacts=len(manifest["artifacts"]), before=a, after=b,
                          purpose=manifest["description"], changes=descriptions[number],
                          before_unscored=len(before["unscored_predictions"]), after_unscored=len(after["unscored_predictions"]))
        comparisons.append(comparison)
        write(base + "/comparison.json", comparison)
        by_id = {r["id"]:r for r in manifest["artifacts"]}
        old = {(d["artifact_id"],d["rule_id"]):d["outcome"] for d in before["decisions"]}
        with (ROOT/base/"error_analysis.csv").open("w",newline="",encoding="utf-8") as handle:
            writer=csv.writer(handle);writer.writerow(["artifact_id","source_record_id","rule","before","after","label_rationale"])
            for d in after["decisions"]:
                prior=old[(d["artifact_id"],d["rule_id"])]
                if prior in {"fn","fp"} or d["outcome"] in {"fn","fp"}:
                    writer.writerow([d["artifact_id"],by_id[d["artifact_id"]].get("source_record_id","synthetic"),d["rule_id"],prior,d["outcome"],d["rationale"]])
        report = f"""# Iteration {number}: recorded development experiment

{manifest['description']}.

| Run | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| Baseline | {a['tp']} | {a['fp']} | {a['fn']} | {a['tn']} | {percent(a['precision'])} | {percent(a['recall'])} |
| Repaired, same cases | {b['tp']} | {b['fp']} | {b['fn']} | {b['tn']} | {percent(b['precision'])} | {percent(b['recall'])} |

Changes: {descriptions[number]}

Labels were locked in `evaluation/campaign/schedule.json` before campaign detector changes. Assistant semantic review is not independent human adjudication. Unlabelled outcomes are unknown. After-repair scores are exposed development results, not fresh validation. Initial unscored predictions: {len(before['unscored_predictions'])}; repaired: {len(after['unscored_predictions'])}. Scan errors: {a['errors']} before / {b['errors']} after.

See `error_analysis.csv` for resolved and remaining failures, `tests-final.txt` for the unit suite, and `runs/` for exact predictions, labels, scanner archives, hashes, and timestamps. The earlier batches were rerun before proceeding; their scoped scores did not regress.
"""
        (ROOT/base/"REPORT.md").write_text(report,encoding="utf-8")
        rows.append([number,len(manifest["artifacts"]),f"{a['tp']}/{a['tp']+a['fn']}",f"{b['tp']}/{b['tp']+b['fn']}",f"{a['fp']} → {b['fp']}",percent(b['precision']),percent(b['recall'])])

    by_category = defaultdict(lambda: Counter(tp=0,fp=0,fn=0,tn=0,errors=0))
    for d in final["decisions"]:by_category[d["rule_id"].split('-')[0]][d["outcome"]]+=1
    category_rows=[]
    for i in range(1,17):
        name=f"MCP{i:02}";counts=by_category[name];p=counts['tp']+counts['fn'];n=counts['tn']+counts['fp']
        category_rows.append([name,p,n,counts['tp'],counts['fn'],counts['fp'],counts['tn'],percent(counts['tp']/p if p else None),"Scored" if p+n else "Not covered"])
    artifact_map={a['id']:a for a in holdout['artifacts']}
    missing_tools=[]
    failure_rows=[]
    for d in final['decisions']:
        if d['outcome'] not in {'fn','fp'}:continue
        report=read('evaluation/holdout-results/'+d['artifact_id']+'.json')
        tools=report['scan_info']['tools_analyzed']
        failure_rows.append([d['artifact_id'],d['rule_id'],d['outcome'].upper(),tools])
        if d['outcome']=='fn' and tools==0:missing_tools.append(d['artifact_id'])
    with (ROOT/'deliverables/final_validation_cases.csv').open('w',newline='',encoding='utf-8') as handle:
        writer=csv.DictWriter(handle,fieldnames=['artifact_id','rule_id','polarity','outcome']);writer.writeheader();writer.writerows(final['decisions'])
    write('evaluation/campaign/comparisons.json',comparisons)
    write('evaluation/campaign/final-analysis.json',dict(by_category={k:dict(v) for k,v in by_category.items()},
          missed_labels_in_zero_tool_files=len(missing_tools),zero_tool_files=len(set(missing_tools)),
          unscored_predictions=final['unscored_predictions'],note='Post-final analysis only; no detector changes made.'))

    # Preserve existing exposure entries and append the completed source groups.
    ledger=read('evaluation/iterations/exposure.json')
    for entry in ledger['entries']:
        if entry.get('iteration') in {f'iteration-{i:03}' for i in range(1,5)}:
            entry['latest_run']=entry['iteration']+('/remediation' if entry['iteration']=='iteration-004' else '')+'/runs/iteration007-regression'
    for number in (5,6,7):
        iteration=f'iteration-{number:03}'
        artifacts=read('evaluation/iterations/'+iteration+'/manifest.json')['artifacts']
        entry=dict(iteration=iteration,role='development-after-investigation',
                   repository='synthetic six-family pilot' if number==6 else ('andyscott88/prompt-injection-bench' if number==5 else 'vaultmcp/vault'),
                   related_family_policy='All related records and derived wrappers remain development-only; no random split into final validation.',
                   artifacts=[{k:r[k] for k in ('id','path','sha256')} for r in artifacts],
                   first_run=iteration+'/runs/baseline',latest_run=iteration+'/runs/'+('repaired-final' if number==7 else 'iteration007-regression'))
        ledger['entries']=[e for e in ledger['entries'] if e.get('iteration')!=iteration]+[entry]
    write('evaluation/iterations/exposure.json',ledger)

    m=final['micro']; date=consumed['consumed_at'][:10]
    summary=(f"On the reserved final set, the scanner detected {m['tp']} of {m['tp']+m['fn']} positive rule labels and raised {m['fp']} false alarm among {m['fp']+m['tn']} negative labels: "
             f"{percent(m['precision'])} precision and {percent(m['recall'])} recall. These results support a working heuristic prototype with substantial remaining recall limitations; they do not establish production readiness.")
    method=("The final evaluation used 33 pinned public artifacts from seven repositories, with 50 explicit artifact/rule labels (30 positive, 20 negative). "
            "The unit is a rule label, not a unique vulnerability incident. A file can have multiple labels. Only labeled rule outcomes enter precision and recall. "
            "All 33 artifacts were hash-verified before a single guarded scan. A consumed marker prevents reuse as an untouched final test. "
            "The optional LLM reviewer was disabled; no target program was executed. There were no scan errors. The code was frozen before final predictions and has not changed since.")
    limits=("The final labels cover eight MCP categories and ten specific rules. MCP04, MCP08, MCP10, MCP11, MCP12, MCP14, MCP15, and MCP16 lack final scored coverage. "
            "The 37 unscored artifact/rule predictions have unknown correctness; 92.9% precision applies only to the explicitly labeled scope. "
            "Small, correlated public fixtures do not establish population-wide performance. Source labels and assistant mappings need independent human review. "
            "No exact file-hash overlap was found against 779 distinct recorded development/primary hashes; this does not rule out semantic/template overlap.")
    data=("Converted 930 records: 218 prompt-injection-bench, 180 Vault v2, 498 ATR skill records, and 34 explicitly MCP-tagged Bordair records. "
          "Admitted 98 public-text records; 832 remain quarantined and unscored. Added 24 synthetic fixtures from six scenario families, with inline/helper variants and paired vulnerable/safe behavior. "
          "The three campaign rounds contain 122 labeled fixtures, reusing the 22 adapted and 24 synthetic pilot cases. They are not 122 independent incidents. "
          "Text was preserved verbatim in standard MCP tool docstrings, changing its original context. Dataset labels were never copied blindly into scanner ground truth. "
          "MCP-FBAs preference pairs and unrelated Bordair modalities were excluded because they do not supply static-source vulnerability labels.")
    findings=(f"Six of the 17 missed labels occur in five files where no tool was recognized. This is evidence of registration/parser coverage gaps, although it is not a complete causal diagnosis. "
              "Other misses remain in scope detection, dynamic execution, contextual content, permissive binding, and confusable names. The one false positive is a command-injection label in the borderline JavaScript fixture. "
              "All final artifacts were scanned individually; project-wide and cross-file behaviors are not comprehensively evaluated by that protocol. "
              "The 100% synthetic retest contrasts with 43.3% final recall: success on constructed examples does not establish generalization. No final failures were used to repair this frozen version.")
    schedule=("Completed order: dataset conversion and label lock → iteration 5 baseline/investigation/repair/retest → iteration 6 → iteration 7 → prior-batch regression checks → demo rehearsal → "
              "156 passing unit tests → scanner freeze → final manifest freeze and acquisition verification → one final validation → this report. "
              "The ten MCP-DecayBench candidate servers remain unused for a possible future reserve, subject to label and overlap review. The consumed 33-artifact set must become development data if its results guide a future version.")
    columns=['Iteration','Fixtures','Detected before','Detected after','False alarms','Retest precision','Retest recall']
    category_columns=['Category','Positive labels','Negative labels','TP','FN','FP','TN','Recall','Coverage']
    md=[f'# Final validation report — MCP Security Scanner\n\nBar David and Noam Ben Lulu · Technion · B.Sc. Electrical and Computer Engineering\n\nEvaluation completed: {date}. Submission: 21 October 2026.\n',
        '## Main result\n\n'+summary,'## Data and preparation\n\n'+data,'## Execution schedule\n\n'+schedule,'## Development iterations\n',
        '| '+' | '.join(columns)+' |','|'+ '|'.join(['---']*len(columns))+'|']
    md += ['| '+' | '.join(map(str,r))+' |' for r in rows]
    md += ['\nRetests reuse exposed cases. Iteration 5 includes a previously inspected source family; iteration 6 is synthetic. Iteration 7 began with a new source family, but its repaired score is also development-only. All earlier scoped scores remained unchanged. Iteration 1 still has four misses and one false alarm.',
           '## Final protocol\n\n'+method, f"\nFinal confusion matrix: TP={m['tp']}, FP={m['fp']}, FN={m['fn']}, TN={m['tn']}. Precision={percent(m['precision'])}; recall={percent(m['recall'])}; false-positive rate={percent(m['false_positive_rate'])}. Label coverage=100%.",
           '## Final category coverage\n','| '+' | '.join(category_columns)+' |','|'+ '|'.join(['---']*len(category_columns))+'|']
    md += ['| '+' | '.join(map(str,r))+' |' for r in category_rows]
    md += ['## Interpretation and remaining work\n\n'+findings,'## Limitations\n\n'+limits,
           '## Demonstration\n\nRun `python presentation_demo.py`, then open [Demo.html](Demo.html). The five steps show a clean tool, poisoned metadata, verified remediation, command injection, and a safer implementation. See [presenter notes](PRESENTER_NOTES.md). This is an illustrative demo, separate from evaluation cases.',
           f'## Reproducibility\n\nScanner fingerprint: `{freeze["scanner_fingerprint"]}`. Final manifest fingerprint: `{consumed["manifest_fingerprint"]}`.\n\nRaw final reports and the executed code snapshot are retained locally in `evaluation/holdout-results/`; a portable evidence copy is `deliverables/Final_Validation_Evidence.zip`. The 50 decisions are [available as CSV](final_validation_cases.csv). Campaign manifests, locks, comparisons, and error analyses are under `evaluation/campaign/` and `evaluation/iterations/iteration-005` through `iteration-007`.',
           '## Design references\n\nScenario reasoning follows the [MCP security guidance](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/docs/2026-07-28/tutorials/security/security_best_practices.mdx) for authorization boundaries and the [Python subprocess security considerations](https://docs.python.org/3/library/subprocess.html#security-considerations) for command execution. These references inform scenario semantics; passing our scanner was not the criterion for assigning labels.']
    (ROOT/'deliverables/Final_Validation_Report.md').write_text('\n\n'.join(md)+'\n',encoding='utf-8')
    css='''body{font-family:system-ui,sans-serif;background:#f3f6fa;color:#15253d;margin:0}main{max-width:1150px;margin:auto;padding:42px 28px}header{border-bottom:4px solid #238778;padding-bottom:25px}h1{font-size:38px;line-height:1.15}h2{margin-top:36px}p{line-height:1.7;max-width:1050px}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:25px 0}.card{background:white;border:1px solid #d7e0e9;border-radius:12px;padding:22px}.card b{display:block;font-size:32px}.alert{border-left:5px solid #d08b28;background:#fff5df;padding:15px 22px}.table{overflow-x:auto}table{border-collapse:collapse;background:white;width:100%;font-size:14px}td,th{text-align:left;padding:10px;border-bottom:1px solid #dde4ec}th{background:#e6edf4}a{color:#126f83}code{overflow-wrap:anywhere;font-size:12px}small{color:#516179}details{margin-top:20px}@media(max-width:750px){.cards{grid-template-columns:1fr 1fr}main{padding:24px 14px}}@media print{body{background:white}.card{break-inside:avoid}details{display:block}button{display:none}}'''
    html=f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>MCP Scanner — Final Validation</title><style>{css}</style><main><header><small>TECHNION · FINAL PROJECT EVALUATION</small><h1>MCP Security Scanner<br>Final validation report</h1><p>Bar David &amp; Noam Ben Lulu · B.Sc. Electrical and Computer Engineering<br>Evaluation: {date} · Submission: 21 October 2026</p></header>'
    html+='<div class="cards">'+''.join(f'<div class="card"><b>{v}</b>{label}</div>' for v,label in [(percent(m['precision']),'Scoped precision'),(percent(m['recall']),'Recall'),('17 / 30','Missed positive labels'),('1 / 20','False alarms')])+'</div>'
    html+='<p class="alert">'+escape(summary)+'</p>'
    for title,body in [('Data preparation',data),('Completed schedule',schedule)]:html+=f'<h2>{title}</h2><p>{escape(body)}</p>'
    html+='<h2>Development baseline → repair → retest</h2><div class="table">'+table(columns,rows)+'</div><p>These repaired scores use exposed development cases. They must not be presented as final-validation performance. Earlier batches showed no scoring regression.</p>'
    html+='<h2>Final validation protocol</h2><p>'+escape(method)+'</p><div class="table">'+table(['Actual label','Detected','Not detected'],[['Positive',m['tp'],m['fn']],['Negative',m['fp'],m['tn']]])+'</div>'
    html+='<p>Precision = TP / (TP + FP). Recall = TP / (TP + FN). False-positive rate = FP / (FP + TN). A missed positive reduces recall even when precision is high.</p>'
    html+='<h2>Category results and coverage</h2><div class="table">'+table(category_columns,category_rows)+'</div>'
    html+='<h2>What the failures show</h2><p>'+escape(findings)+'</p><h2>Limits of the evidence</h2><p>'+escape(limits)+'</p>'
    html+='<details><summary>All final missed labels and false alarms</summary><div class="table">'+table(['Artifact','Rule','Outcome','Tools recognized'],failure_rows)+'</div></details>'
    html+='<h2>Show how it works</h2><p><a href="Demo.html">Open the five-step demo</a> · <a href="PRESENTER_NOTES.md">Presenter notes</a> · <a href="final_validation_cases.csv">All 50 scored decisions</a> · <a href="Final_Validation_Evidence.zip">Portable evidence archive</a></p><p>Reproduce the demonstration with <code>python presentation_demo.py</code>. Do not rerun the final reserve during a presentation.</p>'
    html+=f'<h2>Reproducibility</h2><p>156 unit tests passed. Scanner fingerprint: <code>{freeze["scanner_fingerprint"]}</code><br>Final manifest: <code>{consumed["manifest_fingerprint"]}</code></p><p>Scenario references: <a href="https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/docs/2026-07-28/tutorials/security/security_best_practices.mdx">MCP security guidance</a>; <a href="https://docs.python.org/3/library/subprocess.html#security-considerations">Python subprocess security</a>.</p><button onclick="window.print()">Print / Save PDF</button></main></html>'
    (ROOT/'deliverables/Final_Validation_Report.html').write_text(html,encoding='utf-8')
    # Portable reports contain redacted evidence and exact scanner code, not the
    # separately licensed third-party target source repositories.
    with zipfile.ZipFile(ROOT/'deliverables/Final_Validation_Evidence.zip','w',zipfile.ZIP_DEFLATED) as archive:
        paths=list((ROOT/'evaluation/holdout-results').glob('*.json'))+[ROOT/'evaluation/holdout-results/code_snapshot.zip']
        paths += [ROOT/'evaluation/holdout'/n for n in ('metrics.json','CONSUMED.json','frozen-manifest.json','frozen-manifest.sha256')]
        paths += list((ROOT/'evaluation/campaign').glob('*.json'))+[ROOT/'evaluation/campaign/tests-final.txt']
        for p in paths:archive.write(p,p.relative_to(ROOT))
    write('evaluation/campaign/completion.json',dict(completed_at=datetime.now(timezone.utc).isoformat(),iterations=[5,6,7],
          unit_tests=156,final=final['micro'],scanner_unchanged_since_final=True,demo_checks=read('deliverables/demo_results.json')['checks'],
          report='deliverables/Final_Validation_Report.html',demo='deliverables/Demo.html'))
    print(summary)


if __name__ == '__main__':main()
