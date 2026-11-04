# Build extension/data.js from a leakwatch checkout: profile registrations (profiles.py) + seeds/sites.json.
# Usage: python3 scripts/build-dumper-data.py [/path/to/leakwatch]  (then the two hand-fixed profiles are appended)
import re, json, ast, sys, pathlib
LW = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else '/home/user/leakwatch')
src = open(LW/"leakwatch"/"parsers"/"profiles.py", encoding="utf-8").read()
block = src[src.index('PROFILES: list[Profile] = ['):]
# split into Profile( ... ) entries at top level
entries = []
i = 0
while True:
    j = block.find('Profile(', i)
    if j < 0: break
    depth = 0; k = j + len('Profile(') - 1; instr = None
    while k < len(block):
        ch = block[k]
        if instr:
            if ch == '\\': k += 1
            elif ch == instr: instr = None
        elif ch in '"\'': instr = ch
        elif ch in '([{': depth += 1
        elif ch in ')]}':
            depth -= 1
            if depth == 0: break
        k += 1
    entries.append(block[j:k + 1]); i = k + 1
CSS_START = re.compile(r'^(?:[a-z][a-z0-9]*|[.#\[*])', re.I)
def is_css(v):
    v = v.strip()
    if not v or v in ('-', 'none'): return False
    if ' + ' in v and not re.match(r'^[.#a-z]', v): return False
    if re.search(r"\b(own text|text|href|from|in |of |and |or |onclick|last|first|after|before|whose|the |with|via|'|\(|\)|<|>)", v) and not re.match(r'^[.#\[a-z][\w.#\[\]=\'"*:>~+ ,-]*$', v): return False
    return bool(CSS_START.match(v)) and not re.search(r'\b(text|href|own|onclick|from|and|or|with)\b', v)
out = []
for e in entries:
    m = re.match(r'Profile\(\s*"([^"]+)"\s*,\s*(.*?),\s*(p_[a-z0-9_]+)\s*,\s*"((?:[^"\\]|\\.)*)"\s*,\s*"((?:[^"\\]|\\.)*)"\s*,?\s*(\{.*\})?\s*(?:,\s*paginate\s*=\s*("[^"]*"|None))?\s*\)\s*$', e, re.S)
    if not m: out.append({'name': '?', 'raw': e[:120]}); continue
    name, match, fn, note, fpdesc, spec, pag = m.groups()
    fps = []
    for mm in re.finditer(r'_has\(\s*"((?:[^"\\]|\\.)*)"\s*\)', match): fps.append(mm.group(1))
    for mm in re.finditer(r'select_one\(\s*(["\'])(.*?)\1\s*\)', match): fps.append(mm.group(2))
    for mm in re.finditer(r'select\(\s*(["\'])(.*?)\1\s*\)', match): fps.append(mm.group(2))
    textneed = re.findall(r'(["\'])((?:[^"\'\\]|\\.)+)\1\s+in\s+h\b', match)
    spec_d = {}
    if spec:
        try: spec_d = ast.literal_eval(spec)
        except Exception: spec_d = {}
    rec = {'name': name, 'note': note, 'fp': fps, 'fpText': [t[1] for t in textneed], 'fn': fn}
    for k in ('item', 'title', 'link', 'date', 'desc'):
        v = spec_d.get(k, '')
        rec[k] = v if is_css(v) else ''
        if v and not rec[k]: rec.setdefault('hints', {})[k] = v
    if 'own text' in (spec_d.get('title') or ''): rec['titleOwn'] = True
    if pag and pag != 'None': rec['paginate'] = pag.strip('"')
    out.append(rec)
good = [r for r in out if r.get('name') != '?']
print('profiles parsed:', len(good), 'failed:', len(out) - len(good))
print('with fingerprint css:', sum(1 for r in good if r['fp']), '| with item css:', sum(1 for r in good if r['item']), '| with title css:', sum(1 for r in good if r['title']))
for r in out:
    if r.get('name') == '?': print('FAILED:', r['raw'])
# host -> group map
sites = json.load(open(LW/'seeds'/'sites.json'))
hosts = {}
for s in sites:
    h = re.sub(r'^https?://', '', s['url']).split('/')[0].lower()
    if h: hosts[h] = s['group']
print('hosts:', len(hosts), 'groups:', len(set(hosts.values())))


prof = good + [
 {'name':'panzer','note':'Panzer React blog cards (rendered)','fp':['meta[name="panzer-site"]','article[aria-label^="Read more about"] h3'],'fpText':[],'item':'article[aria-label^="Read more about"]','title':'h3','link':'','date':'','desc':''},
 {'name':'blacklocks','note':'BlackLocks sidebar list','fp':['nav.sidebar a.sidebar-item[href*="/leaks/"] .fw-semibold span'],'fpText':[],'item':'nav.sidebar a.sidebar-item[href*="/leaks/"]','title':'.fw-semibold span','link':'','date':'div.position-absolute','desc':''},
]
slim = [{k: v for k, v in p.items() if k in ('name','note','fp','fpText','item','title','link','date','desc','titleOwn','paginate') and v} for p in prof]
out = ("// Dumper data tables, generated from sxi9/leakwatch (leakwatch/parsers/profiles.py registrations and\n"
       "// seeds/sites.json) by scripts/build-dumper-data.py. Do not edit by hand; re-run the builder.\n"
       "window.__dumperData = {\n  profiles: " + json.dumps(slim, ensure_ascii=False, separators=(',', ':')) +
       ",\n  hosts: " + json.dumps(hosts, ensure_ascii=False, separators=(',', ':')) + "\n};\n")
target = pathlib.Path(__file__).resolve().parents[1]/'extension'/'data.js'
target.write_text(out)
print('wrote', target, len(out), 'bytes;', len(slim), 'profiles;', len(hosts), 'hosts')
