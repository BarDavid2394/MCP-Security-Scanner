"""Narrow, report-only contrasts between advertised and reachable behavior."""
import ast
import re
from .reachable_python import ReachablePython, depends, prefix


def discrepancies(analysis: ReachablePython, function, parameters, description):
    calls = analysis.analyze(function, parameters)
    description = description.lower()
    results = []
    # Evidence of secondary tracking, not a claim that all network use is bad.
    disclosed = re.search(r'\b(track\w*|analytics|profil\w*|training|dataset|affiliate|monetiz\w*|collect\w*|telemetry)\b', description)
    if not disclosed:
        for call in calls:
            if not call.http: continue
            destination, _ = prefix(call.destination)
            tracking = re.search(r'(?i)(track|analytics|profil|training|dataset|affiliate|monetiz|data-collect|ml-pipeline)', destination)
            payloads = [call.keywords.get(k) for k in ['json','data','params']]
            if tracking and any(depends(v, analysis.parameters) for v in payloads):
                results.append((call.line, 'undisclosed_tracking',
                    'Caller data reaches a tracking/profiling or training endpoint not disclosed in tool metadata.', call.path))
                break
    if re.search(r'\baes[- ]?256\b', description):
        returned_encodings = [n for value in analysis.returns for n in ast.walk(value)
                              if isinstance(n, ast.Call) and getattr(n, '_resolved_name', '') in {'base64.b64encode','base64.standard_b64encode'}]
        encryption = any(re.search(r'(?i)(encrypt|cipher|fernet|aes)', call.name) for call in calls)
        if returned_encodings and not encryption:
            results.append((function.lineno, 'encoding_claimed_as_encryption',
                'Metadata claims AES-256, but the visible return path is base64 encoding without a reachable encryption operation.', (function.name,)))
    if re.search(r'\bcompress(?:ion)?\b.*\bimage\b|\bimage\b.*\bcompress', description):
        rename = next((call for call in calls if call.name in {'os.rename','os.replace'} and any(depends(a, analysis.parameters) for a in call.args)), None)
        compressor = any(re.search(r'(?i)(compress|encode|\.save$|resize|thumbnail)', call.name) for call in calls)
        if rename and not compressor and all(isinstance(v, ast.Constant) for v in analysis.returns):
            results.append((rename.line, 'rename_claimed_as_compression',
                'Metadata claims image compression, while the visible path renames/copies files and returns a constant success response.', rename.path))
    return results
