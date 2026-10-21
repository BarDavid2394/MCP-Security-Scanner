"""Render a standalone HTML view of a live scan's serialized findings."""
from html import escape
import base64
import json
from mcp_scanner.reporters.colors import SEVERITY_COLORS


def render_html(report, *, heading=None, summary_html='', footer_note='No automatic fixes were applied.',
                download_report=None, download_filename='scan.json'):
    def esc(value):
        return escape(str(value), quote=True)

    info = report['scan_info']
    errors = info.get('parse_errors', [])
    findings = report['findings']
    json_data = json.dumps(report if download_report is None else download_report, indent=2, ensure_ascii=False)
    download_url = 'data:application/json;base64,' + base64.b64encode(json_data.encode('utf-8')).decode('ascii')
    status = 'Scan incomplete' if errors else ('Findings detected' if findings else 'No findings in selected scope')
    cards = []
    order = {level: index for index, level in enumerate(SEVERITY_COLORS)}
    for finding in sorted(findings, key=lambda f: order.get(f['severity'], len(order))):
        level = finding['severity'] if finding['severity'] in SEVERITY_COLORS else 'INFO'
        details = []
        for label, value in (
            ('Matched evidence', finding.get('matched_text')),
            ('Source excerpt', finding.get('code_snippet')),
            ('Data-flow evidence', finding.get('metadata', {}).get('evidence')),
        ):
            if value:
                text = json.dumps(value, indent=2, ensure_ascii=False) if isinstance(value, dict) else value
                details.append(f'<h3>{label}</h3><pre>{esc(text)}</pre>')
        location = f"{finding['file_path']}:{finding['line_number']}"
        if finding.get('function_name'):
            location += ' · ' + finding['function_name']
        cards.append(f'''<details class="finding severity-{level.lower()}">
<summary>
<span class="card-top"><span class="rule">{esc(finding.get('rule_id') or finding.get('attack_id') or '')}</span><span class="expand-icon" aria-hidden="true">+</span></span>
<strong class="finding-title">{esc(finding['title'])}</strong>
<span class="tags"><span class="urgency badge">Urgency: {esc(finding['severity'])}</span><span class="confidence badge">Confidence: {esc(finding.get('confidence', 'unknown'))}</span></span>
</summary>
<div class="finding-body"><p class="location">{esc(location)}</p>
<p>{esc(finding['description'])}</p>{''.join(details)}
<p><strong>Recommendation:</strong> {esc(finding.get('recommendation') or 'Review the evidence in context.')}</p>
<small>{'Eligible for targeted remediation' if finding.get('fixable') else 'Manual review required'}</small>
</div></details>''')
    error_html = ('<aside><h2>Scan errors</h2><ul>' + ''.join(f'<li>{esc(e)}</li>' for e in errors) + '</ul></aside>') if errors else ''
    coverage = ('<aside>No tool definitions were recognized. Tool-specific coverage may be incomplete.</aside>'
                if not info.get('tools_analyzed') else '')
    empty = '<p>No findings were produced. Review the scan errors above.</p>' if errors else '<p>No findings in the selected scope.</p>'
    severity = ''.join(f'<span class="severity-{level.lower()} urgency badge">{level}: {report["summary"]["by_severity"][level]}</span>'
                       for level in SEVERITY_COLORS if report['summary']['by_severity'].get(level))
    color_css = ''.join(f'.severity-{level.lower()}{{--severity:{colors[1]};}}' for level, colors in SEVERITY_COLORS.items())
    return '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>MCP Security Scanner — Scan report</title>
<style>
:root{font-family:system-ui,sans-serif;color:#e8eef8;background:#101827;color-scheme:dark}
body{max-width:1100px;margin:auto;padding:32px}header{border-bottom:1px solid #34435d;padding-bottom:24px}
h1{font-size:32px;margin:10px 0}h2{font-size:20px}h3{font-size:15px;margin:20px 0 8px}p{line-height:1.6}small,.location,.meta{color:#becbe0}
.location{overflow-wrap:anywhere}.stats{display:flex;flex-wrap:wrap;gap:16px;margin:24px 0}
.stat{background:#1b2940;border-radius:10px;padding:18px;min-width:135px}.stat strong{display:block;font-size:28px}
.finding-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;align-items:start;margin:20px 0}
.finding{border:1px solid #394a65;border-left:4px solid var(--severity);border-radius:10px;background:#152136;min-width:0;overflow:hidden}
.finding>summary{padding:16px;list-style:none;cursor:pointer}.finding>summary::-webkit-details-marker{display:none}
.finding>summary:hover{background:#1b2a43}.finding>summary:focus-visible{outline:2px solid var(--severity);outline-offset:-3px;border-radius:8px}
.card-top{display:flex;justify-content:space-between;gap:12px;align-items:center}.rule{font-size:12px;letter-spacing:.04em;color:var(--severity);overflow-wrap:anywhere}
.expand-icon{font-size:22px;color:#becbe0;line-height:1;transition:transform .15s}.finding[open] .expand-icon{transform:rotate(45deg)}
.finding-title{display:block;font-size:16px;line-height:1.45;margin:10px 0 14px;overflow-wrap:anywhere}
.tags,.legend{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.badge{display:inline-block;padding:4px 8px;border-radius:6px;font-size:12px;line-height:1.5;border:1px solid #43516b}
.urgency{color:var(--severity);border-color:var(--severity)}.confidence{color:#d0daea;background:#202e45}
.finding[open]{grid-column:1/-1}.finding-body{padding:0 20px 20px;border-top:1px solid #394a65}.finding-body>p:first-child{margin-top:18px}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0c1220;padding:16px;border-radius:8px;font-size:13px;line-height:1.6}
.file-change{border:1px solid #394a65;padding:14px 18px;border-radius:8px;margin:12px 0}.file-change>summary{cursor:pointer;overflow-wrap:anywhere}
a{color:#a8c5ff;overflow-wrap:anywhere}aside{background:#392f21;border:1px solid #806b40;padding:18px;margin:20px 0;border-radius:8px}
.download{display:inline-block;padding:10px 16px;border:1px solid #82aaff;border-radius:8px;background:#203558;color:#e8eef8;text-decoration:none;font-size:14px;font-weight:600}
.download:hover{background:#2b4670}.download:focus-visible{outline:2px solid #a8c5ff;outline-offset:3px}
footer{border-top:1px solid #34435d;margin-top:28px;padding-top:16px;color:#becbe0}
@media(max-width:700px){body{padding:16px}.finding-grid{grid-template-columns:1fr}.stat{min-width:95px}.finding-title{font-size:15px}}
@media(prefers-reduced-motion:reduce){.expand-icon{transition:none}}
@media print{:root{color:black;background:white;color-scheme:light}pre,.stat{background:#eee}.finding{break-inside:avoid}small,.location,.meta,footer{color:#333}}
''' + color_css + '''</style></head><body>''' + f'''
<header><p class="meta">MCP Security Scanner · Catalog {esc(report['catalog_version'])}</p>
<h1>{esc(heading or status)}</h1><p class="location"><strong>Target:</strong> {esc(info['target'])}</p>
<p class="meta">Generated: {esc(report['timestamp'])} · Scope: {esc(info.get('check') or 'All rules')}</p>
<a class="download" href="{download_url}" download="{esc(download_filename)}">Download JSON</a></header>
<div class="stats"><div class="stat"><strong>{info['files_scanned']}</strong>Files scanned</div>
<div class="stat"><strong>{info['tools_analyzed']}</strong>Tools recognized</div>
<div class="stat"><strong>{len(findings)}</strong>Findings</div>
<div class="stat"><strong>{len(errors)}</strong>Scan errors</div></div>
<div class="legend" aria-label="Findings by urgency">{severity}</div>{error_html}{coverage}{summary_html}
{'<p class="meta">Click a finding to expand its evidence and recommendation. Urgency reflects severity; confidence reflects the strength of the evidence.</p>' if cards else ''}
<div class="finding-grid">{''.join(cards) or empty}</div>
<footer>Results from this scan of the supplied path. Source was statically analyzed; the target server was not executed.
Findings are heuristic evidence. No findings do not prove safety. {esc(footer_note)}</footer>
</body></html>'''
