// Dumper 2.0 — universal leak-site dumper (page-world script).
// Finds the victim list on ANY leak site with, in order: (1) data adapters for sites that keep their
// list in a JS global (The Gentlemen `companies`, or any array of victim-like objects), (2) the 101
// site profiles ported from sxi9/leakwatch (fingerprint + item/title/link/date/desc selectors),
// (3) generic card heuristics (ported from leakwatch parse_auto), (4) custom selectors typed in the
// panel. Groups victims by date, lets the analyst tick them, optionally fetches each victim's own
// page, and downloads ONE JSON dump (text in visual order, IOCs, links, card HTML + page CSS, images
// as base64, a card PNG when the browser allows canvas reads).
(() => {
  if (window.__dumper) { window.__dumper.toggle(); return; }
  const D = window.__dumperData || { profiles: [], hosts: {} };
  const LS_DONE = 'dumper.done.v2', LS_SEL = 'dumper.sel.v2', LS_CUSTOM = 'dumper.custom.v2';
  const host = location.hostname.toLowerCase();
  const pad = n => String(n).padStart(2, '0');
  const load = (k, d) => { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch (e) { return d; } };
  const save = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} };
  const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const clean = s => String(s ?? '').replace(/\s+/g, ' ').trim();
  const abs = (u, base) => { try { return new URL(u, base || location.href).href; } catch (e) { return null; } };
  const log = (...a) => console.log('[dumper]', ...a);

  // ---------- group name from the leakwatch site list ----------
  function groupFromHost() {
    const g = D.hosts[host]; if (g) return prettyGroup(g);
    const t = clean(document.title).split(/[|–—:-]/)[0].trim(); if (t && t.length <= 30 && !/^(index|home|blog|news|leaks?)$/i.test(t)) return t;
    const m = /^(?:www\.)?([a-z0-9]+)/.exec(host); return m ? m[1].slice(0, 12) : host;
  }
  const GROUP_NAMES = { thegentlemen: 'The Gentlemen', 'global secret group': 'GLOBAL SECRET GROUP', incransom: 'INC Ransom', 'inc ransom': 'INC Ransom', dragonforce: 'DragonForce', safepay: 'SafePay', nightspire: 'NightSpire', lockbit: 'LockBit', braincipher: 'BrainCipher', ransomhouse: 'RansomHouse', metaencryptor: 'Metaencryptor', blacklocks: 'BlackLocks', darkproject: 'Dark Project', 'booba project': 'Booba Project', wallstreet: 'Wallstreet', everest: 'Everest', qilin: 'Qilin', akira: 'Akira', play: 'Play', rhysida: 'Rhysida', clop: 'Clop', byod: 'BYOD', leaknet: 'Leaknet', nitrogen: 'Nitrogen', pear: 'Pear', storm: 'Storm', genesis: 'GENESIS', chaos: 'Chaos', handala: 'Handala' };
  const prettyGroup = g => GROUP_NAMES[g.toLowerCase()] || g;

  // ---------- noise rules (ported from leakwatch is_noise_title, trimmed) ----------
  const NAV = new Set(['home', 'about', 'contact', 'login', 'log in', 'sign in', 'register', 'news', 'blog', 'leaks', 'leak', 'faq', 'rules', 'chat', 'press', 'mirror', 'mirrors', 'next', 'prev', 'previous', 'more', 'read more', 'download', 'menu', 'search', 'all', 'support', 'help', 'main', 'index', 'back', 'top', 'page', 'pages', 'companies', 'victims', 'published', 'archive', 'share', 'rss', 'feed', 'contacts', 'email', 'session', 'telegram', 'tox', 'jabber', 'copy', 'qtox', 'signal', 'pgp', 'close', 'open', 'view', 'details', 'show', 'hide', 'files', 'file', 'data', 'proof', 'proofs', 'images', 'learn more', 'see more', 'more info', 'browse files', 'go to post', 'view all', 'visit', 'detail', 'data size', 'site', 'post', 'gallery', 'clearnet', 'verify', 'verification', 'notice', 'password', 'list of files', 'folder', 'release countdown', 'country', 'size', 'leaked', 'paid', 'pinned', 'new', 'updated', 'expired', 'publish', 'overview', 'breaking', 'recent', 'latest', 'timer', 'countdown', 'loading', 'loading...', 'index of /', 'parent directory', 'database', 'leaked data', 'negotiations', 'about us', 'company url', 'zoom info', 'zoominfo', 'time till publication', 'publication date', 'deadline', 'status', 'revenue', 'employees', 'industry', 'website', 'description', 'data published', 'samples', 'sample', 'full leak', 'affiliates', 'affiliate', 'public', 'welcome', 'welcome!', 'place bid', 'documents', 'open', 'close', 'classified', 'pending', 'coming soon', 'soon', 'sold', 'for sale', 'free download', 'download now', 'download all', 'buy', 'price', 'bid', 'auction', 'auctions', 'the', 'stolen', 'sample data', 'view details', 'next page', 'tag', 'tags', 'posts', 'live', 'utc', 'media', 'report', 'activates in', 'name published', 'records open in', 'company website', 'visit site', 'company name', 'victim name', 'company', 'name', 'victim', 'target', 'organization', 'extracted data', 'full dump', 'proof of hack', 'evidence', 'contact us', 'terms', 'partnership', 'all posts', 'latest posts', 'published data', 'disclosures']);
  const DATE_RX = /(\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}|(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.? \d{1,2},? \d{4}|\d{1,2} (?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]* \d{4})/i;
  const FILE_RX = /\.(zip|rar|7z|tar|gz|tgz|bz2|xz|txt|csv|xlsx?|docx?|pdf|sql|bak|json|xml|log|iso|img|mp4|avi|mov|png|jpe?g|gif|torrent|zst|dat|db|pst|eml|msg|pptx?|dmp|z\d{2}|part\d+)(\b|$)/i;
  const DOMAIN_RX = /^(?:https?:\/\/)?(?:www\.)?[a-z0-9-]+(\.[a-z0-9-]+)+\/?$/i;
  const ITEM_HINT = /(post|card|item|victim|company|entry|article|leak|blog|news|target|tile|block|publication)/i;
  const TITLE_HINT = /(title|name|company|victim|target|head|org|domain)/i;
  function isNoise(t) {
    t = clean(t); const tl = t.toLowerCase();
    if (t.length < 3 || t.length > 200 || NAV.has(tl) || NAV.has(tl.replace(/[?!.:]+$/, ''))) return true;
    if (/^\d{1,2}:\d{2}(:\d{2})?\s*(am|pm)?$/i.test(t) || /^(activates in|ends in|publish(ed|es)? in|expires in|time left|deadline)\b/i.test(tl)) return true;
    if (/^(no|nothing|0)\s+(companies|results?|posts?|data|victims?|records?|entries|items?)?\s*(found|yet|available)?[.!]?$/.test(tl)) return true;
    if (/^please\b/.test(tl) || /^\d{4}-\d{2}-\d{2}([ t]\d{2}:\d{2})?/.test(tl) || /^(added|published|updated|posted|date)[: ]+\d/.test(tl)) return true;
    if (/^(https?:\/\/)?[a-z2-7]{16,56}\.onion\/?$/.test(tl) || /^(error|loading|connecting|retry|try again)\b/.test(tl) || /^(incorrect|invalid|wrong|an error|thank you|thanks|success)\b/.test(tl)) return true;
    if (/^[\w .&'-]{2,30}\s+(blog|leaks?|news|archive)$/.test(tl) || (t.endsWith('?') && t.split(' ').length >= 3)) return true;
    if (/^(\d{1,4}|[\W_]+|(?:page )?\d+ of \d+|[\w.+-]+@[\w-]+\.[\w.]+|https?:\/\/\S+)$/i.test(t) || /^\s*(\d{3}\s+)?(forbidden|not found|bad gateway|unauthorized|access denied|service unavailable)/i.test(t)) return true;
    if (DATE_RX.test(t) && t.replace(DATE_RX, '').trim().length < 3) return true;
    if (/^[\d.,]+\s*[kKmM]?\s*(files?|folders?|docs?|gb|mb|tb|kb|records?|rows?|items?|posts?|views?|likes?|photos?|images?|leaks?|visits?)$/i.test(t)) return true;
    if ((t.endsWith('.') || t.endsWith('!')) && t.split(' ').length >= 5 && !/\b(inc|ltd|co|corp|llc|s\.?a|gmbh|plc|bv|srl|pty|llp|ag|sas|sl|srl|kg|oy|ab|as)\.?$/i.test(t)) return true;
    if (/^(select|choose|pick|filter by|sort by|search )/.test(tl) || /(\.\.\.|…)$/.test(tl) || /^(new attack|breaking|hot news|announcement|attention|warning)/.test(tl)) return true;
    if (/^(publication|published|posted|added|updated|date|deadline|created|views?|size|revenue|status|country|industry|website|company|victim|data size|files?|price)\s*[:：]/i.test(t)) return true;
    if (/^\$?\s*[\d.,]+\s*(million|billion|thousand|m\$|b\$|k\$|m|b|k|usd|eur|btc)\.?$/i.test(t) || /^\d+\s*d(ays?)?\s+\d+\s*h/i.test(t) || /^[\d.,]+\s*(gb|mb|tb|kb|gib|mib)\b/i.test(t)) return true;
    if (/^[A-Za-z0-9+/=_-]{20,}$/.test(t) && !t.includes('.')) return true;
    if (t.split(' ').length >= 9 && !DOMAIN_RX.test(t)) return true;
    if (/^(\/\/|--|==|\*\*|>>|#|\+ )/.test(t) || (/^\[.*\]$/.test(t)) || (/^\(.*\)$/.test(t))) return true;
    if (FILE_RX.test(t) && !DOMAIN_RX.test(t)) return true;
    if ((t.match(/[a-z]/gi) || []).length < 3) return true;
    return false;
  }
  function stripCounters(t) {
    let x = t.replace(/(\s*[|\-–·:,]?\s*(views?|visits?|posts?|comments?|files?|likes?|size|revenue|employees?|downloads?)\s*[:=]?\s*[\d.,]+\s*[kKmMgGtT]?[bB]?\s*)+$/i, '').trim();
    let y = x.replace(/\s*[|·\-–]?\s*(create|created|update|updated|upd|added|posted|published|deadline|views?)\s*[:：]\s*.*$/i, '').trim(); if (y.length >= 3) x = y;
    y = x.replace(/^(leak|victim|company|target|new|breaking|published|disclosed|full leak|stolen|release|released)\s*[:\-–]?\s+/i, '').trim(); if (y.length >= 3) x = y;
    y = x.replace(/(\s+(proof|encrypted|data published|published|full dump))+$/i, '').trim(); if (y.length >= 3) x = y;
    return x.length >= 3 ? x : t;
  }

  // ---------- DOM helpers ----------
  const q1 = (root, sel) => { try { return sel ? root.querySelector(sel) : null; } catch (e) { return null; } };
  const qa = (root, sel) => { try { return sel ? [...root.querySelectorAll(sel)] : []; } catch (e) { return []; } };
  const visibleEl = el => !!el && (el.offsetParent !== null || getComputedStyle(el).position === 'fixed');
  function blockText(root) {    // visible text with line breaks, in document order (the Code-block transcription)
    const out = [];
    const walk = n => {
      if (n.nodeType === 3) { const t = n.nodeValue.replace(/\s+/g, ' '); if (t.trim()) out.push(t); return; }
      if (n.nodeType !== 1) return;
      const tag = n.tagName.toLowerCase();
      if (['script', 'style', 'noscript', 'svg', 'template', 'select', 'option'].includes(tag) || n.id === 'dumper' || n.id === 'dumper-toggle-btn') return;
      try { const cs = getComputedStyle(n); if (cs.display === 'none' || cs.visibility === 'hidden') return; } catch (e) {}
      const block = /^(p|div|li|tr|h[1-6]|br|section|article|header|footer|span|a|button|td|th|time|pre|blockquote|label|dt|dd|small|strong|b)$/.test(tag);
      if (block) out.push('\n'); n.childNodes.forEach(walk); if (block) out.push('\n');
    };
    walk(root);
    return out.join('').split('\n').map(s => s.trim()).filter(Boolean).join('\n');
  }
  function ownText(el) { return clean([...el.childNodes].filter(n => n.nodeType === 3).map(n => n.nodeValue).join(' ')); }
  function cardLink(c) {
    const anchors = (c.tagName === 'A' ? [c] : []).concat(qa(c, 'a[href]'));
    for (const a of anchors) { const h = a.getAttribute('href') || ''; if (h && !/^(#|javascript:|mailto:)/.test(h) && !FILE_RX.test(h) && !/download/i.test(h)) return abs(h); }
    for (const a of anchors) { const h = a.getAttribute('href') || ''; if (h && !/^(#|javascript:|mailto:)/.test(h)) return abs(h); }
    for (const el of [c, ...qa(c, '*').slice(0, 25)]) { const oc = el.getAttribute && el.getAttribute('onclick'); const m = oc && /(?:window\.open|location(?:\.href)?\s*=|open)\s*\(?\s*['"]([^'"]+)['"]/.exec(oc); if (m) return abs(m[1]); }
    return null;
  }
  function cardTitle(c) {
    for (const h of qa(c, 'h1,h2,h3,h4,h5')) { const t = clean(h.textContent); if (t && !isNoise(t)) return t; }
    for (const el of qa(c, '*')) { const id = (el.className && typeof el.className === 'string' ? el.className : '') + ' ' + (el.id || ''); if (TITLE_HINT.test(id) && !ITEM_HINT.test(id)) { const t = clean(el.textContent); if (t && !isNoise(t) && t.length <= 150) return t; } }
    for (const line of blockText(c).split('\n')) { if (line && !isNoise(line) && line.length <= 120) return line; }
    return null;
  }
  function timerLine(c) {
    const lines = blockText(c).split('\n');
    const kw = /(activates? in|ends? in|publish(ed|es)?\s*(in|after)?|deadline|time (left|till)|countdown|records? open|\b\d{1,3}:\d{2}:\d{2}\b|\b\d+\s*d(ays?)?\s+\d+\s*h\b|expires?|remaining)/i;
    const hit = lines.find(l => kw.test(l) && /\d/.test(l) && l.length < 80);
    if (hit) return hit;
    for (let i = 0; i < lines.length; i++) { if (kw.test(lines[i]) && lines[i].length < 60 && lines[i + 1] && /\d/.test(lines[i + 1]) && lines[i + 1].length < 40) return lines[i] + ' ' + lines[i + 1]; }   // label on one line, value on the next
    const first = lines.find(l => kw.test(l) && l.length < 80); if (first) return first;
    const btn = qa(c, 'button, .btn, a.button, [class*="btn"]').map(b => clean(b.textContent)).find(t => t && t.length < 60);
    return btn || '';
  }
  function parseDate(text) {
    if (!text) return '';
    if (/^\d{9,13}$/.test(String(text).trim())) { let n = +String(text).trim(); if (n > 1e11) n = Math.floor(n / 1000); return new Date(n * 1000).toISOString().slice(0, 10); }   // unix epoch (Leaknet timestamps)
    let m = /(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})/.exec(text); if (m) return `${m[1]}-${pad(m[2])}-${pad(m[3])}`;
    m = /(?:(jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?\s+(\d{1,2}),?\s+(\d{4}))/i.exec(text) || /(\d{1,2})\s+(jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?,?\s+(\d{4})/i.exec(text);
    if (m) { const mon = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec']; const a = isNaN(+m[1]) ? [m[1], m[2], m[3]] : [m[2], m[1], m[3]]; const mi = mon.indexOf(a[0].slice(0, 3).toLowerCase()); if (mi >= 0) return `${a[2]}-${pad(mi + 1)}-${pad(a[1])}`; }
    m = /(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})/.exec(text); if (m) { const d = +m[1], mo = +m[2]; return d > 12 ? `${m[3]}-${pad(mo)}-${pad(d)}` : `${m[3]}-${pad(d)}-${pad(mo)}`; }   // DD/MM/YYYY when unambiguous, else assume MM/DD
    return '';
  }
  function extractIocs(text, links) {
    const set = new Map(); const add = (v, t) => { v = v.toLowerCase(); if (!set.has(v)) set.set(v, t); };
    (String(text || '').match(/https?:\/\/www\.zoominfo\.com\/c\/[^\s"'<>)]+/gi) || []).forEach(u => add(u.replace(/[.,;)]+$/, ''), 'profile'));
    const re = /\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b/gi; let m;
    const t = String(text || '').replace(/https?:\/\/www\.zoominfo\.com\/c\/\S+/gi, ' ');
    while ((m = re.exec(t)) !== null) { const d = m[1]; if (!FILE_RX.test(d) && !/\.onion$/i.test(d) && !/^(e\.g|i\.e|node\.js|vue\.js|react\.js)/i.test(d) && !/^\d+\.\d+/.test(d)) add(d.replace(/^www\./, ''), 'domain'); }
    (links || []).forEach(l => { try { const u = new URL(l); if (!/\.onion$/.test(u.hostname) && u.hostname !== host && !/(zoominfo|linkedin|facebook|twitter|x|instagram|youtube|wikipedia|google|bloomberg|crunchbase|opencorporates|tinyurl|bit)\.(com|ly|org)$/i.test(u.hostname.replace(/^www\./, ''))) add(u.hostname.replace(/^www\./, ''), 'domain'); } catch (e) {} });
    return [...set].map(([value, type]) => ({ type, value }));
  }

  // ---------- extractors ----------
  function fromItems(items, spec, name) {
    const out = [];
    for (const c of items) {
      if (!visibleEl(c) && c.tagName !== 'TR') continue;
      const text = blockText(c).replace(/\n/g, ' '); if (text.length < 3 || text.length > 6000) continue;
      let title = '';
      if (spec.titleOwn) title = ownText(c);
      else if (spec.title) { const t = q1(c, spec.title); title = t ? clean(t.textContent) : ''; }
      if (!title || isNoise(title)) title = cardTitle(c) || '';
      title = stripCounters(title);
      if (!title || isNoise(title)) continue;
      const linkEl = spec.link ? q1(c, spec.link) : null;
      const url = (linkEl && linkEl.getAttribute('href') && abs(linkEl.getAttribute('href'))) || cardLink(c);
      const dateEl = spec.date ? q1(c, spec.date) : null; const dateText = dateEl ? clean(dateEl.textContent) : (DATE_RX.exec(text) || [''])[0];
      const descEl = spec.desc ? q1(c, spec.desc) : null; const description = descEl ? clean(descEl.textContent) : text.slice(0, 1500);
      out.push({ el: c, title, url, dateText, description });
    }
    const seen = new Set();
    return out.filter(p => { const k = p.title.toLowerCase() + '|' + (p.url || ''); if (seen.has(k)) return false; seen.add(k); return true; });
  }
  function tryProfiles() {
    for (const p of D.profiles) {
      if (!p.fp || !p.fp.length) continue;
      if (!p.fp.every(sel => q1(document, sel))) continue;
      if (p.fpText && p.fpText.length && !p.fpText.every(t => document.documentElement.innerHTML.includes(t))) continue;
      const items = p.item ? qa(document, p.item) : [];
      const posts = items.length ? fromItems(items, p, p.name) : [];
      if (posts.length) return { name: 'profile:' + p.name, note: p.note, posts };
    }
    return null;
  }
  function tryGeneric() {
    const sig = el => el.tagName + '.' + [...el.classList].sort().join('.');
    const cands = [...document.querySelectorAll('article, div, li, a, section, tr')].filter(el => {
      if (el.closest('#dumper, #dumper-toggle-btn, nav, header, footer, [role="dialog"], .modal')) return false;
      const id = (typeof el.className === 'string' ? el.className : '') + ' ' + (el.id || '');
      return el.tagName === 'ARTICLE' || ITEM_HINT.test(id);
    });
    const groups = {}; cands.forEach(c => (groups[sig(c)] = groups[sig(c)] || []).push(c));
    const ranked = Object.values(groups).filter(g => g.length >= 2).sort((a, b) => b.length - a.length || depth(a[0]) - depth(b[0]));
    function depth(el) { let d = 0; while (el.parentElement) { d++; el = el.parentElement; } return d; }
    let best = [];
    for (const g of ranked.slice(0, 6)) { const got = fromItems(g, {}, 'generic'); if (got.length > best.length) best = got; }
    // table rows
    const rows = [];
    for (const tr of document.querySelectorAll('tr')) { if (tr.closest('thead') || tr.querySelector('th')) continue; const cells = [...tr.querySelectorAll('td')].map(td => clean(td.textContent)).filter(Boolean); if (!cells.length || ['name', 'company', 'date', 'status', '#'].includes(cells[0].toLowerCase())) continue; const title = stripCounters(cells[0]); if (isNoise(title)) continue; rows.push({ el: tr, title, url: cardLink(tr), dateText: (DATE_RX.exec(cells.join(' ')) || [''])[0], description: cells.join(' | ').slice(0, 1500) }); }
    const headings = [];
    for (const h of document.querySelectorAll('h1,h2,h3,h4')) { if (h.closest('#dumper, nav, header, footer, [role="dialog"], .modal')) continue; const t = stripCounters(clean(h.textContent)); if (!t || isNoise(t)) continue; const a = h.querySelector('a[href]') || (h.parentElement && h.parentElement.querySelector('a[href]')); const box = h.closest('article, li, .card, [class*="post"], [class*="item"]') || h.parentElement; headings.push({ el: box || h, title: t, url: a ? abs(a.getAttribute('href')) : null, dateText: (DATE_RX.exec(clean((box || h).textContent)) || [''])[0], description: clean((box || h).textContent).slice(0, 1500) }); }
    const visual = visualGroups();
    const strategies = [['cards', best], ['visual', visual], ['table', rows], ['headings', headings]];
    let [name, posts] = strategies.reduce((a, b) => (b[1].length > a[1].length ? b : a));
    if (name !== 'table' && posts.length < 5 && rows.length) posts = posts.concat(rows);
    const navText = new Set([...document.querySelectorAll('nav a, header a, footer a')].map(a => clean(a.textContent).toLowerCase()));
    posts = posts.filter(p => !navText.has(p.title.toLowerCase()));
    return posts.length ? { name: 'generic:' + name, note: 'heuristic card detection', posts } : null;
  }
  // Visual structure detection: repeated blocks of the same rendered shape, whatever their class names.
  function visualGroups() {
    const els = [...document.body.querySelectorAll('div, li, article, section, tr, a, td')].filter(e => !e.closest('#dumper')).slice(0, 6000);
    const groups = {};
    for (const el of els) {
      if (el.closest('#dumper, #dumper-toggle-btn, nav, header, footer, [role="dialog"], .modal, script, style')) continue;
      const r = el.getBoundingClientRect(); if (r.width < 120 || r.height < 36 || r.height > 1500) continue;
      const text = clean(el.textContent); if (text.length < 10 || text.length > 3000) continue;
      const kids = [...el.children].slice(0, 6).map(k => k.tagName).join('>'); if (!kids) continue;
      const key = `${el.tagName}|${Math.round(r.width / 24)}|${kids}|${el.children.length > 6 ? '+' : ''}`;
      (groups[key] = groups[key] || []).push(el);
    }
    let best = [];
    for (const g of Object.values(groups)) {
      if (g.length < 3) continue;
      const members = new Set(g); const leaves = g.filter(el => ![...el.querySelectorAll('*')].some(d => members.has(d)));   // drop containers that wrap other members
      if (leaves.length < 3) continue;
      const hs = leaves.map(el => el.getBoundingClientRect().height).sort((a, b) => a - b); if (hs[hs.length - 1] > hs[0] * 6) continue;
      const got = fromItems(leaves, {}, 'visual'); if (got.length > best.length) best = got;
    }
    return best;
  }
  // Pick-a-card: the analyst clicks one victim block; every block built the same way becomes the list.
  function sameShape(el) {
    const sig = e => e.tagName + '|' + [...e.children].slice(0, 6).map(k => k.tagName).join('>');
    const target = sig(el); const cls = [...el.classList].filter(c => !/^(active|selected|hover|odd|even|first|last|\d+)$/.test(c));
    let cands = [];
    if (cls.length) { try { cands = [...document.querySelectorAll(el.tagName + '.' + cls.map(c => CSS.escape(c)).join('.'))]; } catch (e) {} }
    if (cands.length < 2 && el.parentElement) cands = [...el.parentElement.children].filter(c => c.tagName === el.tagName);
    if (cands.length < 2) cands = [...document.querySelectorAll(el.tagName)].filter(c => sig(c) === target && Math.abs(c.getBoundingClientRect().width - el.getBoundingClientRect().width) < 40);
    cands = cands.filter(c => sig(c) === target || cls.length);
    const members = new Set(cands); return cands.filter(c => ![...c.querySelectorAll('*')].some(d => members.has(d)));
  }
  let picking = false, pickHover = null;
  function startPick() {
    if (picking) return; picking = true; status('Pick mode: move over a victim card and click it. Esc cancels.');
    const over = e => { const el = e.target.closest('div, li, article, section, tr, a, td'); if (!el || el.closest('#dumper, #dumper-toggle-btn')) return; if (pickHover) pickHover.style.outline = ''; pickHover = el; el.style.outline = '3px dashed #e0a23c'; };
    const stop = () => { picking = false; document.removeEventListener('mouseover', over, true); document.removeEventListener('click', click, true); document.removeEventListener('keydown', key, true); if (pickHover) pickHover.style.outline = ''; pickHover = null; };
    const click = e => { if (e.target.closest('#dumper, #dumper-toggle-btn')) return; e.preventDefault(); e.stopPropagation(); let el = e.target.closest('div, li, article, section, tr, a, td'); if (!el) return;
      // climb while the block is tiny (a title inside a card) and the parent is still card-sized
      for (let i = 0; i < 4 && el.parentElement && el.getBoundingClientRect().height < 60 && el.parentElement.getBoundingClientRect().height < 900 && el.parentElement.tagName !== 'BODY'; i++) el = el.parentElement;
      stop(); window.__dumperPicked = el; const items = sameShape(el); const posts = fromItems(items, {}, 'picked');
      result = { name: 'picked', note: `${items.length} block(s) shaped like the one you clicked`, posts }; all = result.posts.map((p, i) => Object.assign({ idx: i }, p));
      const c = load(LS_CUSTOM, {}); c[host] = Object.assign(c[host] || {}, { pickedTag: el.tagName, pickedClasses: [...el.classList] }); save(LS_CUSTOM, c);
      render(); status(`Picked: ${all.length} victim(s) from ${items.length} matching block(s). Rescan keeps this; change the mode box to go back to auto.`); };
    const key = e => { if (e.key === 'Escape') { stop(); status('Pick cancelled.'); } };
    document.addEventListener('mouseover', over, true); document.addEventListener('click', click, true); document.addEventListener('keydown', key, true);
  }
  function tryAdapters() {
    // The Gentlemen: global `companies`
    try { if (typeof companies !== 'undefined' && Array.isArray(companies) && companies.length && companies[0].title !== undefined) {
      const now = Math.floor(Date.now() / 1000);
      const posts = companies.filter(c => !c.hidden).map(c => { const rem = (c.timerHours || 0) * 3600 - (now - (c.timerStart || 0)); const tl = rem <= 0 ? 'Data' : 'Activates in ' + (Math.floor(rem / 3600) > 0 ? `${Math.floor(rem / 3600)}:${pad(Math.floor(rem % 3600 / 60))}:${pad(rem % 60)}` : `${Math.floor(rem / 60)}:${pad(rem % 60)}`); const d = document.createElement('div'); d.innerHTML = c.description || ''; const desc = clean(d.textContent);
        return { el: null, data: c, title: c.title || '', url: null, dateText: c.timerStart ? new Date(c.timerStart * 1000).toISOString().slice(0, 10) : '', description: desc, descriptionHtml: c.description || '', timerLine: tl, mediaLinks: c.mediaLinks || [], logoUrl: c.img ? abs(c.img) : null, pinned: !!c.pinned, extra: { timerStart: c.timerStart, timerHours: c.timerHours, dataAlias: c.fa || null, reportUrl: (typeof reportsMap !== 'undefined' && reportsMap && reportsMap[c.id]) ? abs('/reports/' + c.id + '.html') : null } }; });
      return { name: 'adapter:gentlemen', note: 'global companies[]', posts, gentlemen: true };
    } } catch (e) {}
    // Any global array of victim-like objects, or a JSON literal inside a <script> (Leaknet INIT_DATA style)
    const KEYS = ['title', 'name', 'company', 'company_name', 'victim', 'target', 'organization', 'domain', 'website', 'article_title', 'headline', 'subject_site', 'company_title'];
    try { for (const k of Object.keys(window)) { let v; try { v = window[k]; } catch (e) { continue; } if (!v || typeof v !== 'object' || v === window || v.nodeType || k.startsWith('__dumper') || k === 'companies') continue;
      const found = []; const walk = (o, depth) => { if (!o || depth > 4 || found.length) return; if (Array.isArray(o)) { if (o.length >= 3 && o.every(x => x && typeof x === 'object') && KEYS.some(kk => typeof o[0][kk] === 'string')) found.push(o); else o.slice(0, 30).forEach(x => walk(x, depth + 1)); } else if (typeof o === 'object' && !o.nodeType) Object.values(o).slice(0, 60).forEach(x => walk(x, depth + 1)); };
      try { walk(v, 0); } catch (e) {} if (!found.length) continue; v = found[0]; const tk = KEYS.find(x => typeof v[0][x] === 'string'); if (!tk) continue;
      const posts = v.map(o => ({ el: null, data: o, title: clean(o[tk]), url: ['url', 'link', 'href'].map(x => o[x]).find(x => typeof x === 'string') ? abs(['url', 'link', 'href'].map(x => o[x]).find(x => typeof x === 'string')) : null, dateText: String(['date', 'published', 'created', 'created_at', 'timestamp', 'time'].map(x => o[x]).find(x => x) || ''), description: clean(['description', 'desc', 'text', 'summary', 'body', 'content'].map(x => o[x]).find(x => typeof x === 'string') || ''), timerLine: '' })).filter(p => p.title && !isNoise(p.title));
      if (posts.length >= 3) return { name: 'adapter:global:' + k, note: 'JS array window.' + k, posts }; } } catch (e) {}
    return null;
  }
  const JSON_KEYS = ['title', 'name', 'company', 'company_name', 'victim', 'target', 'organization', 'domain', 'website', 'article_title', 'headline', 'subject_site', 'company_title'];
  function scriptJson(KEYS) {
    const found = [];
    const walk = (o, depth) => { if (!o || depth > 6) return; if (Array.isArray(o)) { if (o.length >= 3 && o.every(x => x && typeof x === 'object') && KEYS.some(k => typeof o[0][k] === 'string')) found.push(o); else o.slice(0, 50).forEach(x => walk(x, depth + 1)); } else if (typeof o === 'object') Object.values(o).forEach(v => walk(v, depth + 1)); };
    for (const sc of document.querySelectorAll('script:not([src])')) {
      const txt = sc.textContent; if (!txt || txt.length < 200 || !/[{[]/.test(txt) || txt.includes('__dumperData') || txt.includes('__dumper')) continue;
      const tpl = /JSON\.parse\(`([\s\S]*?)`\)/.exec(txt);
      if (tpl) { try { const raw = tpl[1].replace(/\\(.)/g, '$1'); walk(JSON.parse(raw), 0); } catch (e) {} if (found.length) break; }
      for (const m of txt.matchAll(/[=:(]\s*([{[])/g)) {
        const start = m.index + m[0].length - 1; let depth = 0, instr = null, i = start;
        for (; i < txt.length && i < start + 2000000; i++) { const ch = txt[i]; if (instr) { if (ch === '\\') i++; else if (ch === instr) instr = null; } else if (ch === '"' || ch === "'") instr = ch; else if (ch === '{' || ch === '[') depth++; else if (ch === '}' || ch === ']') { depth--; if (!depth) break; } }
        if (depth) continue; const lit = txt.slice(start, i + 1); if (lit.length < 100) continue;
        let o = null; try { o = JSON.parse(lit); } catch (e) { continue; }
        walk(o, 0); if (found.length) break;
      }
      if (found.length) break;
    }
    if (!found.length) return null;
    const arr = found.sort((a, b) => b.length - a.length)[0]; const tk = KEYS.find(k => typeof arr[0][k] === 'string');
    const posts = arr.map(o => { const site = typeof o.subject_site === 'string' ? o.subject_site : ''; let title = clean(o[tk] || ''); if (tk === 'article_title' && site && !/tinyurl|news/.test(site)) title = site.replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0];
      return { el: null, data: o, title, url: ['url', 'link', 'href', 'article_link_name_default'].map(x => o[x]).find(x => typeof x === 'string') ? abs(String(['url', 'link', 'href', 'article_link_name_default'].map(x => o[x]).find(x => typeof x === 'string')).replace(/^(?!https?:|\/)/, 'view_article.php?article=')) : null, dateText: String(['date', 'published', 'created', 'created_at', 'article_published_timestamp', 'timestamp', 'time'].map(x => o[x]).find(x => x) || ''), description: clean([o.article_title, ['description', 'desc', 'text', 'summary', 'body', 'content', 'brief'].map(x => o[x]).find(x => typeof x === 'string')].filter(Boolean).join(' · ')), timerLine: '' }; }).filter(p => p.title && !isNoise(p.title));
    return posts.length >= 3 ? { name: 'adapter:script-json', note: 'JSON literal in a <script> (' + tk + ')', posts } : null;
  }
  function tryRememberedPick(c) {
    if (!c || !c.pickedTag) return null;
    const cls = (c.pickedClasses || []).filter(Boolean); let items = [];
    try { items = cls.length ? [...document.querySelectorAll(c.pickedTag + '.' + cls.map(x => CSS.escape(x)).join('.'))] : []; } catch (e) {}
    const posts = items.length >= 2 ? fromItems(items, {}, 'picked') : [];
    return posts.length ? { name: 'picked (remembered)', note: `${items.length} block(s) like the one picked last time`, posts } : null;
  }
  // ---------- AI assist: relay to the extension background (content.js bridges window <-> runtime) ----------
  let aiSeq = 0; const aiWaiters = {};
  window.addEventListener('message', e => { const m = e.data; if (!m || m.dumper !== 'ai-response' || !aiWaiters[m.id]) return; const w = aiWaiters[m.id]; delete aiWaiters[m.id]; clearTimeout(w.t); w.res(m); });
  function aiCall(kind, payload, timeoutMs) {
    return new Promise(res => { const id = 'ai' + (++aiSeq); aiWaiters[id] = { res, t: setTimeout(() => { delete aiWaiters[id]; res({ error: 'no answer from the extension (is it loaded as an extension, not pasted?)' }); }, timeoutMs || 90000) }; window.postMessage({ dumper: 'ai-request', id, kind, payload }, '*'); });
  }
  function trimmedHtml(root, cap) {
    const c = (root || document.body).cloneNode(true);
    c.querySelectorAll('script, style, noscript, svg, iframe, link, meta, #dumper, #dumper-toggle-btn').forEach(n => n.remove());
    c.querySelectorAll('*').forEach(n => { for (const a of [...n.attributes]) { if (/^on/i.test(a.name) || a.name === 'style' || a.value.length > 300) n.removeAttribute(a.name); } if (n.tagName === 'IMG') n.setAttribute('src', ''); });
    let h = c.outerHTML.replace(/\s+/g, ' ').replace(/> </g, '><');
    if (h.length > cap) h = h.slice(0, cap) + '<!-- truncated -->';
    return h;
  }
  const PROFILE_RULES = `Return ONLY a JSON object: {"name": "<short lowercase id>", "note": "<one line: what template this is>", "fingerprint": "<CSS selector matching ONLY this template>", "item": "<CSS selector of the repeated container, one per victim>", "title": "<CSS selector RELATIVE to item whose text is the organisation name, or "" if the title is the item's own text>", "title_own": false, "link": "<relative selector of an <a> whose href is the victim/post link, or "">", "link_attr": "href", "date": "<relative selector of the publish date element, or "">", "desc": "<relative selector of the description/excerpt element, or "">", "timer": "<relative selector of a countdown/status/button line, or "">", "paginate": "", "sample_titles": ["first 5 victim names these selectors would yield"]}. Rules: item must select exactly one element per victim and nothing else; title must be the organisation name, never a label, button, size, date, country or status; prefer stable class names over nth-child; fingerprint must not be a generic framework class alone (.card, .row, .container).`;
  function buildAiPrompt(kind, extra) {
    if (kind === 'page') return `You configure a ransomware leak-site parser. Below is the trimmed HTML of one leak site's victim listing (page title: ${JSON.stringify(document.title)}, URL path ${JSON.stringify(location.pathname)}). Produce a CSS "profile" that extracts one record per victim.\n${PROFILE_RULES}\n\nHTML:\n${trimmedHtml(document.body, 60000)}`;
    if (kind === 'card') return `You configure a ransomware leak-site parser. Below is the HTML of ONE victim card the analyst clicked on a leak site, followed by up to two sibling cards, and the trimmed page HTML for context. Produce a CSS "profile": "item" must match every card like these across the page; the other selectors are relative to the card.\n${PROFILE_RULES}\n\nCLICKED CARD:\n${extra.card}\n\nSIBLINGS:\n${extra.siblings}\n\nPAGE (trimmed):\n${trimmedHtml(document.body, 25000)}`;
    return `You fix a ransomware leak-site parser. The current profile ${JSON.stringify(extra.current)} produced these WRONG or noisy victim titles on the page: ${JSON.stringify(extra.badTitles)}. Below are three of the matched items' HTML. Return a corrected profile (same JSON shape) whose "title" selects the organisation name and whose "item" matches one element per victim.\n${PROFILE_RULES}\n\nITEMS:\n${extra.items}\n\nPAGE (trimmed):\n${trimmedHtml(document.body, 25000)}`;
  }
  function parseAiJson(text) { try { return JSON.parse(text); } catch (e) {} const m = /\{[\s\S]*\}/.exec(text || ''); if (m) { try { return JSON.parse(m[0]); } catch (e) {} } return null; }
  function specFromProfile(pr) { return { item: pr.item || '', title: pr.title || '', titleOwn: !!pr.title_own, link: pr.link || '', date: pr.date || '', desc: pr.desc || '', timer: pr.timer || '', name: pr.name || 'ai', note: pr.note || '', fingerprint: pr.fingerprint || '' }; }
  function testSpec(spec) { const items = qa(document, spec.item); const posts = items.length ? fromItems(items, spec, 'ai') : []; return { items: items.length, posts }; }
  let aiProfile = null, aiTest = null;
  async function aiScan(kind) {
    const st = await aiCall('status', {}, 5000);
    if (st.error || !st.configured) { status('AI not configured: right-click the Dumper icon → Options, paste one or more Gemini API keys and tick the consent box.' + (st.error ? ' (' + st.error + ')' : '')); return; }
    if (!st.usable) { status(`All ${st.keys} key(s) are parked or invalid — wait, or "Un-park" them in Options.`); return; }
    let extra = {};
    if (kind === 'card') { const el = window.__dumperPicked; if (!el) { status('Pick a card first ("Pick a card"), then "Scan card (AI)".'); return; } const sib = [...el.parentElement.children].filter(x => x !== el).slice(0, 2); extra = { card: trimmedHtml(el, 8000), siblings: sib.map(x => trimmedHtml(x, 4000)).join('\n') }; }
    if (kind === 'fix') { const items = result && result.posts.slice(0, 3).map(p => p.el).filter(Boolean); if (!items || !items.length) { status('Nothing to fix: no detected items on this page. Try "Scan page (AI)".'); return; } extra = { current: (load(LS_CUSTOM, {}))[host] || { source: result.name }, badTitles: result.posts.slice(0, 8).map(p => p.title), items: items.map(x => trimmedHtml(x, 5000)).join('\n') }; }
    status(`Asking ${st.model || 'Gemini'} (${st.usable}/${st.keys} key(s) usable, round robin)… page HTML is sent to Google, trimmed, no scripts/images`);
    const r = await aiCall('generate', { prompt: buildAiPrompt(kind, extra) }, 120000);
    if (r.error) { status('AI error: ' + r.error); return; }
    console.log('[dumper] AI answered via key', r.key, `(${r.keyIndex}/${r.keys})`, 'model', r.model); const pr = parseAiJson(r.text); if (!pr || !pr.item) { status('AI returned no usable profile. Raw answer is in the console.'); console.log('[dumper] AI answer:', r.text); return; }
    aiProfile = pr; const spec = specFromProfile(pr); aiTest = testSpec(spec);
    panel.querySelector('#dumper-ai-out').textContent = `AI profile "${pr.name}": ${pr.note || ''}\nitem ${pr.item} → ${aiTest.items} element(s), ${aiTest.posts.length} victim(s)\ntitle ${pr.title || '(own text)'} · link ${pr.link || '-'} · date ${pr.date || '-'} · desc ${pr.desc || '-'}\nfirst: ${aiTest.posts.slice(0, 5).map(p => p.title).join(' | ') || '(none)'}`;
    panel.querySelector('#dumper-ai-save').disabled = !aiTest.posts.length; panel.querySelector('#dumper-ai-copy').disabled = false;
    if (aiTest.posts.length) { result = { name: 'ai:' + pr.name, note: pr.note || 'AI profile (unsaved)', posts: aiTest.posts }; all = result.posts.map((p, i) => Object.assign({ idx: i }, p)); render(); status(`AI profile found ${aiTest.posts.length} victim(s). Check the titles, then "Save profile" to keep it for this site.`); }
    else status('AI profile matched nothing on this page. Try "Pick a card" + "Scan card (AI)".');
  }
  async function aiSave() {
    if (!aiProfile) return; const spec = specFromProfile(aiProfile);
    const c = load(LS_CUSTOM, {}); c[host] = Object.assign(c[host] || {}, spec, { savedAt: new Date().toISOString() }); save(LS_CUSTOM, c);
    const r = await aiCall('save-profile', { host, profile: Object.assign({}, aiProfile, { host, site: location.origin, savedAt: new Date().toISOString() }) }, 5000);
    status(r.error ? 'Saved for this site in this browser (extension store unavailable: ' + r.error + ').' : `Profile "${aiProfile.name}" saved for ${host}. Auto mode uses it from now on; "Copy profile JSON" exports it for leakwatch.`);
  }
  function aiCopy() { if (!aiProfile) return; const out = { name: aiProfile.name, note: aiProfile.note, fingerprint: aiProfile.fingerprint, item: aiProfile.item, title: aiProfile.title, title_own: !!aiProfile.title_own, link: aiProfile.link || '', link_attr: aiProfile.link_attr || 'href', date: aiProfile.date || '', desc: aiProfile.desc || '', paginate: aiProfile.paginate || '', host, site: location.origin }; const t = JSON.stringify(out, null, 1); navigator.clipboard.writeText(t).then(() => status('Profile JSON copied (leakwatch custom-profile format).'), () => { console.log(t); status('Clipboard blocked — profile JSON printed in the console.'); }); }
  function tryCustom(spec) { if (!spec || !spec.item) return null; const items = qa(document, spec.item); const posts = fromItems(items, spec, 'custom'); return { name: spec.name ? 'saved:' + spec.name : 'custom', note: spec.note || spec.item, posts }; }
  const okOrNull = (r, _why) => (r && r.posts.length ? r : null);

  // ---------- JSON-feed adapters (ported from leakwatch p_inc_json / p_ransomhouse_json / p_akira_json) ----------
  // Leak sites that serve their victim list as JSON (the API URL shows raw JSON, or the SPA holds it in a global /
  // <script>).  These parse the three known shapes, then fall back to a generic nested walk, so any JSON feed of
  // victim objects - even one whose name is nested under a child object - becomes cards like every other site.
  const _dec = s => { try { return decodeURIComponent(String(s == null ? '' : s)); } catch (e) { return String(s == null ? '' : s); } };
  const _akUnwrap = s => clean(String(s == null ? '' : s).replace(/\[\[[^\]]*\]([^\]]*)\]/g, '$1').replace(/\[\[|\]\]/g, ''));
  function _incVictims(data) {
    const anns = data && data.payload && data.payload.announcements;
    if (!Array.isArray(anns)) return null;
    const out = anns.map(a => { const c = a.company || {}; const name = c.company_name || c.name || a.title; if (!name) return null;
      const d = Array.isArray(a.description) ? a.description.filter(x => typeof x === 'string').map(_dec).join(' ') : (typeof a.description === 'string' ? _dec(a.description) : '');
      const desc = [(a.categories || []).join(', '), c.country || '', c.revenue ? 'revenue ' + c.revenue : '', d].filter(Boolean).join(' · ');
      return { el: null, data: a, title: clean(_dec(name)), url: a._id ? '#' + a._id : null, dateText: a.createdAt != null ? String(a.createdAt) : '', description: clean(desc).slice(0, 1500), timerLine: '' }; }).filter(Boolean);
    return out.length ? out : null;
  }
  function _rhVictims(data) {
    const arr = data && data.data; if (!Array.isArray(arr)) return null;
    const out = arr.filter(it => it && it.display !== 'animated' && it.header).map(it => {
      const desc = [it.status || '', it.action || '', it.published ? 'published ' + it.published : '', it.revenue || '', it.info || ''].filter(Boolean).join(' · ');
      return { el: null, data: it, title: clean(it.header), url: it.url || null, dateText: it.actionDate != null ? String(it.actionDate) : '', description: clean(desc).slice(0, 1500), timerLine: '' }; });
    return out.length ? out : null;
  }
  function _akVictims(data) {
    const arr = data && data.objects; if (!Array.isArray(arr)) return null;
    const out = arr.filter(x => x && typeof x === 'object').map(it => { let title, desc, url = null;
      if (it.name != null) { title = _akUnwrap(it.name); desc = _akUnwrap(it.desc); const m = /(https?:\/\/[^\]\s"']+)/.exec(it.url || ''); url = m ? m[1] : null; }
      else { title = _akUnwrap(it.title); desc = 'announcement · ' + _akUnwrap(it.content); }
      if (!title) return null;
      return { el: null, data: it, title, url, dateText: it.date != null ? String(it.date) : '', description: clean(desc).slice(0, 1500), timerLine: '' }; }).filter(Boolean);
    return out.length ? out : null;
  }
  function _genericJsonVictims(data) {   // find an array of victim-like objects anywhere, name direct or nested one level
    let best = null;
    const nameOf = o => { for (const k of JSON_KEYS) if (typeof o[k] === 'string' && o[k].trim()) return o[k];
      for (const v of Object.values(o)) if (v && typeof v === 'object' && !Array.isArray(v)) for (const k of JSON_KEYS) if (typeof v[k] === 'string' && v[k].trim()) return v[k];
      return null; };
    const walk = (o, d) => { if (!o || d > 6 || best) return;
      if (Array.isArray(o)) { if (o.length >= 3 && o.every(x => x && typeof x === 'object') && nameOf(o[0])) best = o; else o.slice(0, 60).forEach(x => walk(x, d + 1)); }
      else if (typeof o === 'object') Object.values(o).forEach(v => walk(v, d + 1)); };
    try { walk(data, 0); } catch (e) {}
    if (!best) return null;
    const pick = (o, keys) => { for (const k of keys) if (o[k] != null && o[k] !== '') return o[k]; return ''; };
    const out = best.map(o => { const name = nameOf(o); if (!name) return null;
      return { el: null, data: o, title: clean(_dec(name)), url: (() => { const u = pick(o, ['url', 'link', 'href']); return typeof u === 'string' && u ? abs(u) : null; })(),
        dateText: String(pick(o, ['date', 'published', 'created', 'created_at', 'createdAt', 'actionDate', 'timestamp', 'time']) || ''),
        description: clean(String(pick(o, ['description', 'desc', 'text', 'summary', 'body', 'content', 'info']) || '')).slice(0, 1500), timerLine: '' }; })
      .filter(p => p && p.title && !isNoise(p.title));
    return out.length >= 3 ? out : null;
  }
  const jsonVictims = data => _incVictims(data) || _rhVictims(data) || _akVictims(data) || _genericJsonVictims(data);
  function parseBodyJson() {   // the page itself is a raw JSON feed (analyst opened the API URL)
    let txt = '';
    const pre = q1(document, 'pre');
    if (pre) { const s = clean(pre.textContent).slice(0, 1) ? pre.textContent.trim() : ''; if (s && '{['.includes(s[0])) txt = s; }
    if (!txt) { const b = (document.body ? document.body.innerText : '') || ''; const s = b.trim(); if (s && '{['.includes(s[0]) && s.length < 50e6) txt = s; }
    if (!txt) return null;
    try { return JSON.parse(txt); } catch (e) { return null; }
  }
  function tryJsonFeed() {
    const body = parseBodyJson();
    if (body) { const posts = jsonVictims(body); if (posts && posts.length) return { name: 'json:page', note: 'raw JSON feed on the page', posts }; }
    for (const k of Object.keys(window)) { let v; try { v = window[k]; } catch (e) { continue; } if (!v || typeof v !== 'object' || v === window || v.nodeType || k.startsWith('__dumper')) continue;
      let posts = null; try { posts = jsonVictims(v); } catch (e) {} if (posts && posts.length >= 3) return { name: 'json:global:' + k, note: 'JSON victim feed in window.' + k, posts }; }
    return null;
  }

  // ---------- capture ----------
  const assets = {};
  async function grab(url) {
    if (!url || assets[url]) return assets[url];
    try { if (url.startsWith('data:')) { const m = /^data:([^;,]+)[^,]*,(.*)$/.exec(url); assets[url] = { mime: m ? m[1] : 'image/png', data: m ? m[2] : '', bytes: 0 }; return assets[url]; }
      const r = await fetch(url, { credentials: 'include' }); if (!r.ok) throw new Error('HTTP ' + r.status); const b = await r.blob();
      const data = await new Promise((res, rej) => { const fr = new FileReader(); fr.onload = () => res(fr.result.split(',')[1]); fr.onerror = rej; fr.readAsDataURL(b); });
      assets[url] = { mime: b.type, bytes: b.size, data }; } catch (e) { assets[url] = { error: String(e) }; }
    return assets[url];
  }
  function canvasIsTrusted() { try { const cv = document.createElement('canvas'); cv.width = cv.height = 4; const ctx = cv.getContext('2d'); ctx.fillStyle = '#3c7dd9'; ctx.fillRect(0, 0, 4, 4); const px = ctx.getImageData(1, 1, 1, 1).data; return px[0] === 0x3c && px[1] === 0x7d && px[2] === 0xd9; } catch (e) { return false; } }
  const CANVAS_OK = canvasIsTrusted();
  const STYLE_PROPS = ['display', 'flex-direction', 'flex-wrap', 'justify-content', 'align-items', 'gap', 'grid-template-columns', 'width', 'min-width', 'max-width', 'height', 'min-height', 'padding', 'margin', 'border', 'border-radius', 'box-shadow', 'background-color', 'background-image', 'color', 'font-family', 'font-size', 'font-weight', 'font-style', 'line-height', 'letter-spacing', 'text-align', 'text-decoration', 'text-transform', 'white-space', 'word-break', 'overflow-wrap', 'opacity', 'vertical-align', 'list-style', 'overflow', 'box-sizing', 'position', 'top', 'right', 'bottom', 'left'];
  async function cardPng(el) {
    if (!CANVAS_OK || !el) return null;
    try {
      const rect = el.getBoundingClientRect(); if (rect.width < 40 || rect.height < 20 || rect.width > 1600 || rect.height > 4000) return null;
      const clone = el.cloneNode(true); const src = [el, ...el.querySelectorAll('*')], dst = [clone, ...clone.querySelectorAll('*')];
      for (let i = 0; i < src.length; i++) { const cs = getComputedStyle(src[i]); let st = ''; for (const p of STYLE_PROPS) { let v = cs.getPropertyValue(p); if (!v) continue; if (p === 'position' && (v === 'fixed' || v === 'sticky')) v = 'relative'; st += `${p}:${v};`; } dst[i].setAttribute('style', st); dst[i].removeAttribute('onclick'); if (dst[i].tagName === 'IMG') { const a = assets[abs(src[i].getAttribute('src'))]; dst[i].setAttribute('src', a && a.data ? `data:${a.mime};base64,${a.data}` : ''); } }
      clone.querySelectorAll('script, iframe, video, canvas').forEach(n => n.remove());
      const bg = getComputedStyle(document.body).backgroundColor;
      const W = Math.ceil(rect.width) + 24, H = Math.ceil(rect.height) + 24;
      const wrap = document.createElement('div'); wrap.setAttribute('style', `background:${bg === 'rgba(0, 0, 0, 0)' ? '#181818' : bg};padding:12px;width:${W}px;box-sizing:border-box`); wrap.appendChild(clone);
      const xhtml = new XMLSerializer().serializeToString(wrap);
      const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}"><foreignObject width="100%" height="100%"><div xmlns="http://www.w3.org/1999/xhtml">${xhtml}</div></foreignObject></svg>`;
      return await new Promise(res => { const img = new Image(); img.onload = () => { try { const cv = document.createElement('canvas'); cv.width = W * 2; cv.height = H * 2; const ctx = cv.getContext('2d'); ctx.scale(2, 2); ctx.drawImage(img, 0, 0); res(cv.toDataURL('image/png').split(',')[1]); } catch (e) { res(null); } }; img.onerror = () => res(null); img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg); });
    } catch (e) { return null; }
  }
  async function pageCss() {
    const parts = [];
    for (const ss of document.styleSheets) { try { parts.push([...ss.cssRules].map(r => r.cssText).join('\n')); } catch (e) { if (ss.href) { const a = await grab(ss.href); if (a && a.data) try { parts.push(atob(a.data)); } catch (err) {} } } }
    return parts.join('\n');
  }
  async function detailPage(url) {
    try { const r = await fetch(url, { credentials: 'include' }); const html = await r.text(); const doc = new DOMParser().parseFromString(html, 'text/html');
      const main = doc.querySelector('main, article, .post, .content, #content, body');
      const images = []; for (const im of doc.querySelectorAll('img')) { const u = abs(im.getAttribute('src'), url); if (u && !/^data:/.test(u)) { await grab(u); images.push(u); } }
      const links = [...doc.querySelectorAll('a[href]')].map(a => ({ text: clean(a.textContent), href: abs(a.getAttribute('href'), url) })).filter(l => l.href);
      const t = main ? main.cloneNode(true) : null; t && t.querySelectorAll('script,style,noscript').forEach(n => n.remove());
      return { status: r.status, title: clean(doc.title), html, text: t ? t.textContent.split('\n').map(s => s.trim()).filter(Boolean).join('\n') : '', images, links }; }
    catch (e) { return { error: String(e) }; }
  }

  // ---------- UI ----------
  const css = `
    #dumper{position:fixed;top:0;right:0;height:100vh;width:480px;z-index:2147483000;background:#14161b;color:#e5e7eb;font:13px system-ui,sans-serif;box-shadow:-4px 0 24px #000c;display:flex;flex-direction:column}
    #dumper *{box-sizing:border-box}#dumper header{padding:10px 12px;border-bottom:1px solid #2a2e37;display:flex;align-items:center;gap:8px}#dumper header b{color:#e0a23c;font-size:14px}
    #dumper .bar{display:flex;flex-wrap:wrap;gap:6px;padding:8px 12px;border-bottom:1px solid #2a2e37;align-items:center}
    #dumper input[type=text],#dumper input[type=date],#dumper select{background:#1f232b;color:#eee;border:1px solid #3a3f4a;border-radius:6px;padding:5px 7px;font:12px system-ui}#dumper input[type=text]{flex:1;min-width:100px}
    #dumper button{background:#2a2f3a;color:#eee;border:1px solid #3a3f4a;border-radius:6px;padding:5px 9px;cursor:pointer;font:12px system-ui}#dumper button.pri{background:#2f7d4f;border-color:#2f7d4f;font-weight:600}#dumper button.warn{background:#7a3b2e;border-color:#7a3b2e}
    #dumper label.chk{display:inline-flex;align-items:center;gap:4px;color:#aab}#dumper .src{color:#8b929e;font-size:11px;padding:4px 12px;border-bottom:1px solid #2a2e37}#dumper .src b{color:#4ba3a0}
    #dumper .list{flex:1;overflow:auto;padding:6px 0}#dumper .grp{padding:6px 12px 2px;background:#1b1f27;border-top:1px solid #2a2e37;border-bottom:1px solid #2a2e37;display:flex;align-items:center;gap:8px;position:sticky;top:0}#dumper .grp b{color:#4ba3a0}
    #dumper .row{display:flex;gap:8px;padding:5px 12px;align-items:flex-start;border-bottom:1px solid #1d2129}#dumper .row:hover{background:#1a1e26}#dumper .row .n{font-weight:600;color:#fff}#dumper .row .m{color:#8b929e;font-size:11px}
    #dumper .row .done{color:#e0a23c;font-size:10px;border:1px solid #e0a23c;border-radius:4px;padding:0 4px;margin-left:6px}#dumper footer{padding:8px 12px;border-top:1px solid #2a2e37;color:#8b929e;font-size:11px;min-height:34px}
    #dumper .custom{display:none;flex-wrap:wrap;gap:6px;padding:8px 12px;border-bottom:1px solid #2a2e37}#dumper .custom.show{display:flex}#dumper .custom input{min-width:90px}
    #dumper-toggle-btn{position:fixed;top:12px;right:12px;z-index:2147483001;background:#e0a23c;color:#14161b;font:600 12px system-ui;border:0;border-radius:6px;padding:6px 10px;cursor:pointer;box-shadow:0 2px 8px #0008}`;
  let all = [], result = null, panel, toggleBtn, sel = new Set(load(LS_SEL, [])), done = load(LS_DONE, {});
  const state = { q: '', from: '', to: '', onlyNew: false, mode: 'auto' };
  const key = p => host + '|' + p.title.toLowerCase();
  const dateOf = p => parseDate(p.dateText) || 'no-date';

  function extract(mode) {
    const custom = (load(LS_CUSTOM, {}))[host];
    let r = null;
    if (mode === 'custom') r = tryCustom(custom);
    else if (mode.startsWith('profile:')) { const p = D.profiles.find(x => x.name === mode.slice(8)); if (p) { const items = p.item ? qa(document, p.item) : []; const posts = fromItems(items, p, p.name); r = { name: mode, note: p.note, posts }; } }
    else if (mode === 'generic') r = tryGeneric();
    else if (mode === 'json') r = tryJsonFeed() || scriptJson(JSON_KEYS);
    else r = tryAdapters() || tryJsonFeed() || (custom && custom.item ? okOrNull(tryCustom(custom), 'saved profile') : null) || tryProfiles() || tryGeneric() || scriptJson(JSON_KEYS) || tryRememberedPick(custom);
    result = r || { name: 'none', note: 'no victim list found on this page', posts: [] };
    all = result.posts.map((p, i) => Object.assign({ idx: i }, p));
    return result;
  }
  function visibleList() { return all.filter(p => (!state.q || (p.title + ' ' + p.description).toLowerCase().includes(state.q)) && (!state.from || dateOf(p) >= state.from) && (!state.to || dateOf(p) <= state.to) && (!state.onlyNew || !done[key(p)])); }
  function render() {
    const L = panel.querySelector('.list'); L.innerHTML = '';
    const list = visibleList(); const groups = {}; list.forEach(p => (groups[dateOf(p)] = groups[dateOf(p)] || []).push(p));
    for (const d of Object.keys(groups).sort().reverse()) {
      const g = document.createElement('div'); g.className = 'grp'; const allSel = groups[d].every(p => sel.has(key(p)));
      g.innerHTML = `<input type="checkbox" ${allSel ? 'checked' : ''}> <b>${esc(d)}</b> <span style="color:#8b929e">${groups[d].length} victim(s)</span>`;
      g.querySelector('input').onchange = e => { groups[d].forEach(p => e.target.checked ? sel.add(key(p)) : sel.delete(key(p))); save(LS_SEL, [...sel]); render(); };
      L.appendChild(g);
      for (const p of groups[d]) {
        const r = document.createElement('div'); r.className = 'row';
        r.innerHTML = `<input type="checkbox" ${sel.has(key(p)) ? 'checked' : ''}><div style="flex:1"><div class="n">${p.pinned ? '💎 ' : ''}${esc(p.title)}${done[key(p)] ? `<span class="done">dumped ${done[key(p)]}</span>` : ''}</div><div class="m">${esc(p.timerLine || (p.el ? timerLine(p.el) : ''))}${p.dateText ? ' · ' + esc(p.dateText) : ''}${p.url ? ' · link' : ''} · ${esc((p.description || '').slice(0, 110))}</div></div>`;
        r.querySelector('input').onchange = e => { e.target.checked ? sel.add(key(p)) : sel.delete(key(p)); save(LS_SEL, [...sel]); counts(); };
        r.querySelector('.n').onmouseenter = () => { if (p.el) p.el.style.outline = '2px solid #e0a23c'; }; r.querySelector('.n').onmouseleave = () => { if (p.el) p.el.style.outline = ''; };
        L.appendChild(r);
      }
    }
    panel.querySelector('.src').innerHTML = `Source: <b>${esc(result.name)}</b> — ${esc(result.note || '')} · group from site list: <b>${esc(groupFromHost())}</b>`;
    counts();
  }
  function counts() { panel.querySelector('#dumper-count').textContent = `${visibleList().length} shown · ${all.length} total · ${[...sel].filter(k => all.some(p => key(p) === k)).length} selected`; panel.querySelector('#dumper-dump').textContent = `Dump selected (${[...sel].filter(k => all.some(p => key(p) === k)).length})`; }
  const status = t => { panel.querySelector('footer').textContent = t; };

  async function dump() {
    const chosen = all.filter(p => sel.has(key(p))); if (!chosen.length) { status('Nothing selected.'); return; }
    const btn = panel.querySelector('#dumper-dump'); btn.disabled = true;
    const group = panel.querySelector('#dumper-group').value.trim() || groupFromHost();
    const wantDetail = panel.querySelector('#dumper-detail').checked;
    const css = await pageCss(); const entries = []; let i = 0;
    for (const p of chosen) {
      i++; status(`Dumping ${i}/${chosen.length}: ${p.title}`);
      const el = p.el; const imgs = el ? [...el.querySelectorAll('img')].map(im => abs(im.getAttribute('src'))).filter(Boolean) : (p.logoUrl ? [p.logoUrl] : []);
      for (const u of imgs) await grab(u);
      const links = el ? [...el.querySelectorAll('a[href]')].map(a => ({ text: clean(a.textContent), href: abs(a.getAttribute('href')) })).filter(l => l.href && !/^(javascript:|mailto:)/.test(l.href)) : (p.mediaLinks || []).map(h => ({ text: 'media', href: h }));
      const tl = p.timerLine || (el ? timerLine(el) : '');
      const leakText = el ? blockText(el) : [p.title, p.description, tl].filter(Boolean).join('\n');
      const e = { title: p.title, url: p.url || null, publishedDate: parseDate(p.dateText) || null, dateText: p.dateText || null, timerLine: tl, description: p.description || '', descriptionHtml: p.descriptionHtml || null, leakText, links, mediaLinks: links.map(l => l.href).filter(h => !/\.onion/.test(h) || /\/(media|files?|download)/i.test(h)), iocs: extractIocs(leakText + ' ' + links.map(l => l.href).join(' '), links.map(l => l.href)), logoUrl: imgs[0] || null, images: imgs, pinned: !!p.pinned, cardHtml: el ? el.outerHTML.replace(/<script[\s\S]*?<\/script>/gi, '') : null, cardPng: el ? await cardPng(el) : null, extra: p.extra || null, raw: p.data || null };
      if (result.gentlemen && !e.cardPng) e.cardPng = null;
      if (wantDetail && e.url && (() => { try { return new URL(e.url).origin === location.origin && !FILE_RX.test(e.url); } catch (x) { return false; } })()) { e.detail = await detailPage(e.url); await new Promise(r => setTimeout(r, 250)); }
      entries.push(e);
    }
    const out = { tool: 'dumper 2.1.1', group, site: location.origin, page: location.href, host, profile: result.name, capturedAt: new Date().toISOString(), canvasTrusted: CANVAS_OK, count: entries.length, entries, assets, pageCss: css, pageTitle: document.title };
    const json = JSON.stringify(out); const name = `${group.replace(/[^A-Za-z0-9]+/g, '-').toLowerCase()}-dump-${new Date().toISOString().slice(0, 10)}-${entries.length}.json`;
    const blob = new Blob([json], { type: 'application/json' }); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; document.body.appendChild(a); a.click(); a.remove();
    const today = new Date().toISOString().slice(0, 10); chosen.forEach(p => done[key(p)] = today); save(LS_DONE, done); window.__dumperLastDump = out; btn.disabled = false;
    status(`Downloaded ${name} (${(json.length / 1048576).toFixed(1)} MB). ${CANVAS_OK ? '' : 'Card PNGs skipped (canvas protected) — Claude renders them from cardHtml + pageCss. '}If no download started: copy(JSON.stringify(window.__dumperLastDump))`);
    render();
  }

  async function dumpWholePage() {
    const btn = panel.querySelector('#dumper-whole'); btn.disabled = true; status('Dumping the whole page…');
    const group = panel.querySelector('#dumper-group').value.trim() || groupFromHost();
    const css = await pageCss();
    const imgs = [...document.images].map(im => abs(im.getAttribute('src'))).filter(Boolean).slice(0, 200); for (const u of imgs) await grab(u);
    const links = [...document.querySelectorAll('a[href]')].map(a => ({ text: clean(a.textContent), href: abs(a.getAttribute('href')) })).filter(l => l.href && !/^(javascript:|mailto:)/.test(l.href));
    const main = document.querySelector('main, #content, .content, article') || document.body;
    const text = blockText(document.body);
    const details = {}; const wantDetail = panel.querySelector('#dumper-detail').checked;
    if (wantDetail) { const same = [...new Set(links.map(l => l.href).filter(h => { try { const u = new URL(h); return u.origin === location.origin && u.pathname !== location.pathname && !FILE_RX.test(h) && !/#/.test(h); } catch (e) { return false; } }))].slice(0, 60); let i = 0; for (const h of same) { i++; status(`Fetching page ${i}/${same.length}…`); details[h] = await detailPage(h); await new Promise(r => setTimeout(r, 250)); } }
    const clone = document.documentElement.cloneNode(true); clone.querySelectorAll('script, #dumper, #dumper-toggle-btn, style').forEach(n => n.remove());
    const out = { tool: 'dumper 2.1.1', mode: 'wholepage', group, site: location.origin, page: location.href, host, profile: result ? result.name : 'none', capturedAt: new Date().toISOString(), canvasTrusted: CANVAS_OK, count: 0, entries: [], pageTitle: document.title, pageText: text, mainText: blockText(main), pageHtml: clone.outerHTML, pageCss: css, links, images: imgs, assets, details, iocs: extractIocs(text + ' ' + links.map(l => l.href).join(' '), links.map(l => l.href)) };
    const json = JSON.stringify(out); const name = `${group.replace(/[^A-Za-z0-9]+/g, '-').toLowerCase()}-page-${new Date().toISOString().slice(0, 10)}.json`;
    const blob = new Blob([json], { type: 'application/json' }); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; document.body.appendChild(a); a.click(); a.remove();
    window.__dumperLastDump = out; btn.disabled = false;
    status(`Downloaded ${name} (${(json.length / 1048576).toFixed(1)} MB): full page text, HTML, CSS, ${imgs.length} image(s), ${links.length} link(s)${wantDetail ? ', ' + Object.keys(details).length + ' linked page(s)' : ''}. Claude extracts the victims from it.`);
  }
  function build() {
    const st = document.createElement('style'); st.textContent = css; document.head.appendChild(st);
    toggleBtn = document.createElement('button'); toggleBtn.id = 'dumper-toggle-btn'; toggleBtn.textContent = 'Dumper'; toggleBtn.onclick = () => window.__dumper.toggle(); document.body.appendChild(toggleBtn);
    panel = document.createElement('div'); panel.id = 'dumper';
    const profOpts = D.profiles.map(p => `<option value="profile:${esc(p.name)}">${esc(p.name)}</option>`).join('');
    panel.innerHTML = `
      <header><b>Dumper</b><span id="dumper-count" style="color:#8b929e;flex:1"></span><button id="dumper-close">✕</button></header>
      <div class="bar"><span style="color:#8b929e">Group</span><input type="text" id="dumper-group"><select id="dumper-mode" title="how victims are detected"><option value="auto">auto-detect</option><option value="json">JSON feed</option><option value="generic">generic cards</option><option value="custom">custom selectors</option>${profOpts}</select><button id="dumper-rescan" title="re-run detection">Rescan</button><button id="dumper-pick" title="click one victim card on the page; all blocks shaped like it become the list">Pick a card</button><button id="dumper-whole" title="no list found? dump the entire page (text, HTML, CSS, images, linked pages) for Claude">Dump whole page</button></div>
      <div class="custom" id="dumper-custom"><input type="text" id="c-item" placeholder="item selector (one per victim)"><input type="text" id="c-title" placeholder="title selector"><input type="text" id="c-link" placeholder="link selector"><input type="text" id="c-date" placeholder="date selector"><input type="text" id="c-desc" placeholder="description selector"><button id="c-apply">Apply</button></div>
      <div class="bar" style="background:#171a22"><span style="color:#8b929e">AI</span><button id="dumper-ai-page" title="send the trimmed page HTML to Gemini and get a selector profile back">Scan page (AI)</button><button id="dumper-ai-card" title="after Pick a card: ask Gemini for the field selectors of that card">Scan card (AI)</button><button id="dumper-ai-fix" title="titles look wrong? ask Gemini to correct the selectors">Fix (AI)</button><button id="dumper-ai-save" disabled>Save profile</button><button id="dumper-ai-copy" disabled>Copy profile JSON</button></div>
      <pre id="dumper-ai-out" style="margin:0;padding:4px 12px;color:#8b929e;font:11px ui-monospace,monospace;white-space:pre-wrap;max-height:90px;overflow:auto"></pre>
      <div class="src"></div>
      <div class="bar"><input type="text" id="dumper-q" placeholder="search"><input type="date" id="dumper-from"><input type="date" id="dumper-to"><label class="chk"><input type="checkbox" id="dumper-new"> only not yet dumped</label><label class="chk"><input type="checkbox" id="dumper-detail" checked> fetch each victim's page</label></div>
      <div class="bar"><button id="dumper-selvis">Select all shown</button><button id="dumper-clear">Clear</button><button id="dumper-today">Select today</button><button id="dumper-names">Copy names</button><button id="dumper-undone" class="warn">Reset dumped marks</button><button id="dumper-dump" class="pri">Dump selected (0)</button></div>
      <div class="list"></div><footer>Tick victims (or a whole date), then Dump. The JSON goes to Downloads — send it to Claude.</footer>`;
    document.body.appendChild(panel);
    const $ = id => panel.querySelector('#' + id);
    $('dumper-group').value = groupFromHost();
    $('dumper-close').onclick = () => window.__dumper.toggle();
    $('dumper-mode').onchange = e => { state.mode = e.target.value; $('dumper-custom').classList.toggle('show', state.mode === 'custom'); if (state.mode !== 'custom') { extract(state.mode); render(); } };
    $('dumper-rescan').onclick = () => { if (result && result.name === 'picked') { status('Pick mode result kept. Change the mode box to re-detect.'); return; } extract(state.mode); render(); status(`Rescanned: ${all.length} victim(s) via ${result.name}.`); };
    $('dumper-pick').onclick = startPick;
    $('dumper-ai-page').onclick = () => aiScan('page'); $('dumper-ai-card').onclick = () => aiScan('card'); $('dumper-ai-fix').onclick = () => aiScan('fix'); $('dumper-ai-save').onclick = aiSave; $('dumper-ai-copy').onclick = aiCopy;
    $('dumper-whole').onclick = dumpWholePage;
    const cst = (load(LS_CUSTOM, {}))[host] || {}; ['item', 'title', 'link', 'date', 'desc'].forEach(k => $('c-' + k).value = cst[k] || '');
    $('c-apply').onclick = () => { const spec = {}; ['item', 'title', 'link', 'date', 'desc'].forEach(k => spec[k] = $('c-' + k).value.trim()); const c = load(LS_CUSTOM, {}); c[host] = spec; save(LS_CUSTOM, c); state.mode = 'custom'; extract('custom'); render(); status(`Custom selectors: ${all.length} victim(s).`); };
    $('dumper-q').oninput = e => { state.q = e.target.value.toLowerCase(); render(); }; $('dumper-from').onchange = e => { state.from = e.target.value; render(); }; $('dumper-to').onchange = e => { state.to = e.target.value; render(); }; $('dumper-new').onchange = e => { state.onlyNew = e.target.checked; render(); };
    $('dumper-selvis').onclick = () => { visibleList().forEach(p => sel.add(key(p))); save(LS_SEL, [...sel]); render(); }; $('dumper-clear').onclick = () => { sel.clear(); save(LS_SEL, []); render(); };
    $('dumper-today').onclick = () => { const t = new Date().toISOString().slice(0, 10); all.filter(p => dateOf(p) === t).forEach(p => sel.add(key(p))); save(LS_SEL, [...sel]); render(); };
    $('dumper-names').onclick = () => { const names = all.filter(p => sel.has(key(p))).map(p => `${dateOf(p)}  ${p.title}`).join('\n'); navigator.clipboard.writeText(names).then(() => status('Names copied.'), () => { console.log(names); status('Clipboard blocked — names printed in the console.'); }); };
    $('dumper-undone').onclick = () => { if (confirm('Forget which victims were already dumped on this site?')) { Object.keys(done).filter(k => k.startsWith(host + '|')).forEach(k => delete done[k]); save(LS_DONE, done); render(); } };
    $('dumper-dump').onclick = dump;
    render();
    if (!CANVAS_OK) log('canvas reads are protected (Tor Browser) — card PNGs skipped; cards are rebuilt from cardHtml + pageCss.');
  }

  window.__dumper = { aiScan, result: () => result, toggle() { if (!panel) { extract('auto'); build(); return; } panel.style.display = panel.style.display === 'none' ? 'flex' : 'none'; }, rescan() { extract(state.mode); render(); } };
  document.addEventListener('dumper-toggle', () => window.__dumper.toggle());
  let tries = 0;
  const wait = setInterval(() => {
    extract('auto');
    if (all.length) { clearInterval(wait); build(); log('ready:', all.length, 'victims via', result.name); }
    else if (++tries > 15) { clearInterval(wait); result = { name: 'none', note: 'no victim list found — use "Pick a card", custom selectors, or "Dump whole page"', posts: [] }; all = []; build(); status('Nothing detected automatically. Click "Pick a card" and click one victim on the page, or "Dump whole page".'); log('no victim list detected after 15 s — panel opened for pick / custom / whole-page.'); }
  }, 1000);
})();
