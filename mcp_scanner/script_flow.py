"""Bounded lexical helpers for common JavaScript source-to-sink checks.

This is not a JavaScript interpreter or a complete grammar. Offsets are retained
while quoted data and comments are masked for executable-call searches.
"""
import re


def code_mask(text):
    chars = list(text)
    i = 0
    while i < len(text):
        start = i
        if text.startswith('//', i):
            end = text.find('\n', i)
            i = len(text) if end < 0 else end
        elif text.startswith('/*', i):
            end = text.find('*/', i+2)
            i = len(text) if end < 0 else end+2
        elif text[i] in "'\"`":
            quote = text[i]
            i += 1
            while i < len(text):
                if text[i] == '\\': i += 2
                elif text[i] == quote:
                    i += 1
                    break
                else: i += 1
        else:
            i += 1
            continue
        for j in range(start, min(i, len(text))):
            if chars[j] != '\n': chars[j] = ' '
    return ''.join(chars)


def arguments(text, opening):
    """Return the top-level arguments of a call/array, respecting quoted data."""
    mask = code_mask(text)
    stack = [text[opening]]
    start = opening+1
    result=[]
    for i in range(start, len(text)):
        ch=mask[i]
        if ch in '([{': stack.append(ch)
        elif ch in ')]}':
            if not stack or '([{'.index(stack[-1]) != ')]}'.index(ch): return []
            stack.pop()
            if not stack:
                tail=text[start:i].strip()
                if tail: result.append(tail)
                return result
        elif ch==',' and len(stack)==1:
            result.append(text[start:i].strip())
            start=i+1
    return []


def literal(expression):
    match=re.fullmatch(r'''\s*(['"])([^'"\\]*)\1\s*''', expression)
    return match.group(2) if match else None


def safe_git_argv(kind, args, body, before):
    """Recognize a narrow non-shell git read operation with bounded operands."""
    if kind not in {'execFile', 'execFileSync', 'spawn', 'spawnSync'} or len(args)<2:
        return False
    if literal(args[0]) != 'git': return False
    options = args[2] if len(args)>2 else ''
    if options.startswith('{'):
        properties=arguments(options,0)
        seen=set()
        for prop in properties:
            entry=re.fullmatch(r'(\w+)\s*:\s*(.+)',prop,re.S)
            if not entry or entry.group(1) in seen: return False
            key,value=entry.groups()
            seen.add(key)
            if key not in {'cwd','shell','encoding','timeout','maxBuffer'}: return False
            if key=='shell' and value.strip()!='false': return False
    # Unknown option objects and spread properties may enable shell execution.
    if options and not options.startswith('{') and not re.match(r'(?:\([^)]*\)|\w+)\s*=>|function\b',options): return False
    if '...' in options or re.search(r'\b(?:shell|env)\s*[,}]', options): return False
    argv=args[1]
    extra=[]
    if re.fullmatch(r'[A-Za-z_$][\w$]*',argv):
        prefix=body[:before]
        assigned=list(re.finditer(r'\b(?:const|let|var)\s+'+re.escape(argv)+r'\s*=\s*(\[)',prefix))
        if len(assigned)!=1: return False
        if len(re.findall(r'\b'+re.escape(argv)+r'\s*=',prefix))!=1: return False
        for use in re.finditer(r'\b'+re.escape(argv)+r'\s*(\.[A-Za-z]+|\[)',prefix):
            if use.group(1)!='.push': return False
            opening=prefix.find('(',use.end())
            extra.extend(arguments(prefix,opening))
        values=arguments(prefix,assigned[0].start(1))+extra
    elif argv.startswith('['): values=arguments(argv,0)
    else: return False
    if not values or any('...' in value for value in values): return False
    operation=literal(values[0])
    if operation=='status':
        # Status does not execute operands; permit only fixed status options.
        for value in values[1:]:
            fixed=literal(value)
            if fixed is not None and fixed.startswith('-') and fixed not in {'--porcelain','--short','--branch','--'}: return False
        return True
    if operation not in {'show','log'}: return False
    boundary=next((i for i,v in enumerate(values) if literal(v)=='--'),None)
    return boundary is not None and all(literal(v) is not None for v in values[:boundary])


def file_text_returns(body, filesystem_names):
    """Track whole file text and aliases, excluding length-only projections."""
    names=set()
    mask=code_mask(body)
    fs='|'.join(re.escape(name) for name in filesystem_names)
    if not fs: return []
    assignments=list(re.finditer(r'\b(?:const|let|var)\s+(\w+)\s*=\s*([^;]+);',body))
    for _ in range(4):
        for match in assignments:
            if not mask[match.start():match.start()+5].strip(): continue
            value=match.group(2)
            if re.search(r'\b(?:'+fs+r')\.readFileSync\s*\(',code_mask(value)):
                names.add(match.group(1))
            elif any(re.fullmatch(r'(?:await\s+)?'+re.escape(name),value.strip()) for name in names):
                names.add(match.group(1))
    results=[]
    for match in re.finditer(r'\breturn\b',mask):
        end=body.find(';',match.end())
        expression=body[match.end():end if end>=0 else len(body)]
        for name in names:
            projected=re.sub(r'\b'+re.escape(name)+r'\s*\.\s*length\b','0',expression)
            if re.search(r'\b'+re.escape(name)+r'\b',code_mask(projected)):
                results.append((match.start(),name))
                break
    return results
