#!/usr/bin/env python3
"""Render leak-site cards as PNGs from a Dumper JSON dump.

Usage: python3 scripts/render-cards.py <dump.json> <out_dir> [--scale 2]

Dumper 2.0 dumps carry each victim's cardHtml plus the site's pageCss and image assets, so every
card is rebuilt exactly as the site styled it (Tor Browser cannot rasterise in-page: canvas reads
are noise there). Older Gentlemen-only dumps (no cardHtml) are rebuilt from title / description /
timer line / logo with the Gentlemen card CSS. Output: <out_dir>/<slug>.png + cards.json.
"""
import json, sys, re, html, pathlib, subprocess, tempfile, os
dump_path, out_dir = sys.argv[1], pathlib.Path(sys.argv[2]).resolve()
scale = int(sys.argv[sys.argv.index('--scale') + 1]) if '--scale' in sys.argv else 2
out_dir.mkdir(parents=True, exist_ok=True)
d = json.load(open(dump_path, encoding='utf-8'))
assets = d.get('assets', {})
GENT_CSS = """body{margin:0;background:#181818}.wrap{background:#181818;padding:14px;font-family:'DejaVu Sans Mono',monospace;color:#eee;display:inline-block}
.card{background:#202024;border-radius:18px;box-shadow:0 2px 12px #000a;width:330px;min-height:140px;padding:16px 16px 22px 16px;display:flex;flex-direction:column;align-items:center;position:relative}
.card img{max-width:96px;margin-bottom:14px;border-radius:7px}.pin{position:absolute;top:10px;right:13px;font-size:16px;opacity:.8}.t{font-size:1.2em;margin-bottom:7px;color:#6cf;font-weight:bold;text-align:center}
.d{font-size:1em;color:#bbb;margin-bottom:15px;text-align:center;overflow-wrap:anywhere;word-break:break-all}.b{margin-top:auto;display:flex;gap:10px;justify-content:center}.btn{background:#181838;color:#fff;border:1px solid #444;padding:7px 12px;border-radius:7px;font-size:1em}"""
def data_uri_for(src):
    for u, a in assets.items():
        if a.get('data') and (u == src or u.endswith(src.lstrip('./')) or src.endswith(u.split('/')[-1])):
            return f"data:{a['mime']};base64,{a['data']}"
    return ''
slug = lambda s: re.sub(r'[^a-z0-9]+', '-', s.lower()).strip('-')
pages, names = [], {}
for e in d['entries']:
    s = slug(e['title']); names[s] = e['title']
    if e.get('cardHtml'):
        css = (d.get('pageCss') or '').replace('@import', '/*@import*/')
        card = re.sub(r'(src=["\'])([^"\']+)(["\'])', lambda m: m.group(1) + (data_uri_for(m.group(2)) or '') + m.group(3), e['cardHtml'])
        bg = '#181818'
        page = f'<!doctype html><meta charset="utf-8"><style>html,body{{margin:0;background:{bg}}}{css}</style><div class="wrap" style="display:inline-block;padding:12px;background:{bg};max-width:1200px">{card}</div>'
    else:
        a = assets.get(e.get('logoUrl') or '', {})
        logo = f'<img src="data:{a["mime"]};base64,{a["data"]}">' if a.get('data') else ''
        pin = '<div class="pin">💎</div>' if e.get('pinned') else ''
        media = '<span class="btn">Media</span>' if e.get('mediaLinks') else ''
        desc = e.get('descriptionHtml') or html.escape(e.get('description', ''))
        page = f'<!doctype html><meta charset="utf-8"><style>{GENT_CSS}</style><div class="wrap"><div class="card">{pin}{logo}<div class="t">{html.escape(e["title"])}</div><div class="d">{desc}</div><div class="b"><span class="btn">{html.escape(e.get("timerLine") or "")}</span>{media}</div></div></div>'
    p = out_dir / f'{s}.html'; p.write_text(page, encoding='utf-8'); pages.append((s, str(p)))
js = """const { chromium } = require('playwright');
(async () => { const [,, listPath, scale] = process.argv; const list = JSON.parse(require('fs').readFileSync(listPath));
  const b = await chromium.launch(); const pg = await b.newPage({ viewport: { width: 1280, height: 900 }, deviceScaleFactor: +scale });
  for (const [s, f, out] of list) { await pg.goto('file://' + f); await pg.waitForTimeout(150); const el = await pg.$('.wrap'); await (el || pg).screenshot({ path: out }); }
  await b.close(); console.log('rendered', list.length); })();"""
with tempfile.TemporaryDirectory() as td:
    lst = [(s, f, str(out_dir / f'{s}.png')) for s, f in pages]
    json.dump(lst, open(os.path.join(td, 'list.json'), 'w')); open(os.path.join(td, 'shot.js'), 'w').write(js)
    subprocess.run(['node', os.path.join(td, 'shot.js'), os.path.join(td, 'list.json'), str(scale)], check=True)
for s, f in pages: os.remove(f)
json.dump(names, open(out_dir / 'cards.json', 'w'), indent=1, ensure_ascii=False)
print('wrote', len(pages), 'cards to', out_dir)
