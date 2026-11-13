// Background: toolbar click -> toggle panel; AI requests from the panel -> Gemini API.
// The API key, model and consent live in extension storage (Options page), never in the page.
const api = typeof browser !== 'undefined' ? browser : chrome;
function sendToggle(tabId) { return new Promise((res, rej) => { try { const p = api.tabs.sendMessage(tabId, { type: 'dumper-toggle' }, r => { const e = api.runtime.lastError; e ? rej(e) : res(r); }); if (p && p.then) p.then(res, rej); } catch (e) { rej(e); } }); }
api.action.onClicked.addListener(async tab => {
  if (!tab.id) return;
  try { await sendToggle(tab.id); return; } catch (e) {}
  // No content script on this page (not a .onion site): inject it now, then open the panel.
  try { await api.scripting.executeScript({ target: { tabId: tab.id }, files: ['content.js'] }); setTimeout(() => sendToggle(tab.id).catch(() => {}), 700); }
  catch (e) { console.warn('[dumper] cannot inject here:', e && e.message); }
});
const DEFAULT_MODEL = 'gemini-2.5-flash';
function getSettings() { return new Promise(res => { try { const p = api.storage.local.get(['geminiKey', 'geminiKeys', 'geminiModel', 'aiConsent', 'profiles', 'keyState'], v => res(v || {})); if (p && p.then) p.then(res); } catch (e) { res({}); } }); }
function setSettings(obj) { return new Promise(res => { try { const p = api.storage.local.set(obj, () => res(true)); if (p && p.then) p.then(() => res(true)); } catch (e) { res(false); } }); }
const PARK_MS = 10 * 60 * 1000;
function keyList(s) { const multi = (s.geminiKeys || '').split(/\r?\n|,|;/).map(k => k.trim()).filter(Boolean); return multi.length ? multi : (s.geminiKey ? [s.geminiKey.trim()] : []); }
const mask = k => k.length > 8 ? k.slice(0, 4) + '…' + k.slice(-4) : '****';
async function geminiOnce(prompt, key, model) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(key)}`;
  const body = { contents: [{ role: 'user', parts: [{ text: prompt }] }], generationConfig: { temperature: 0.1, responseMimeType: 'application/json' } };
  const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error((j.error && j.error.message) || ('HTTP ' + r.status)); e.status = r.status; throw e; }
  const text = (((j.candidates || [])[0] || {}).content || {}).parts?.map(p => p.text).join('') || '';
  if (!text) throw new Error('empty answer' + (j.promptFeedback ? ' (' + JSON.stringify(j.promptFeedback) + ')' : ''));
  return text;
}
// Round robin over all configured keys: start after the last key that worked; a 429 / quota answer parks the
// key for PARK_MS, a 401 / 403 marks it invalid; other errors move on to the next key; all failed -> error.
async function gemini(prompt, s) {
  const keys = keyList(s); if (!keys.length) throw new Error('no Gemini API key set (extension Options)');
  const model = s.geminiModel || DEFAULT_MODEL; const st = s.keyState || { idx: 0, parked: {}, invalid: {} }; const now = Date.now();
  const errors = []; let tried = 0;
  for (let n = 0; n < keys.length; n++) {
    const i = (st.idx + n) % keys.length, key = keys[i];
    if (st.invalid[key]) { errors.push(`${mask(key)}: invalid`); continue; }
    if (st.parked[key] && st.parked[key] > now) { errors.push(`${mask(key)}: parked ${Math.ceil((st.parked[key] - now) / 60000)} min`); continue; }
    tried++;
    try { const text = await geminiOnce(prompt, key, model); st.idx = (i + 1) % keys.length; await setSettings({ keyState: st }); return { text, model, key: mask(key), keyIndex: i + 1, keys: keys.length }; }
    catch (e) {
      if (e.status === 429 || /quota|rate ?limit|resource.?exhausted/i.test(e.message)) { st.parked[key] = now + PARK_MS; errors.push(`${mask(key)}: quota/rate limit, parked 10 min`); }
      else if (e.status === 401 || e.status === 403 || /api key not valid|permission denied/i.test(e.message)) { st.invalid[key] = true; errors.push(`${mask(key)}: invalid`); }
      else errors.push(`${mask(key)}: ${e.message}`);
    }
  }
  await setSettings({ keyState: st });
  throw new Error(`all ${keys.length} key(s) failed (${tried} tried) — ` + errors.join('; '));
}
async function handle(msg) {
  const s = await getSettings();
  if (msg.kind === 'status') { const keys = keyList(s); const st = s.keyState || { parked: {}, invalid: {} }; const now = Date.now(); return { configured: !!(keys.length && s.aiConsent), model: s.geminiModel || DEFAULT_MODEL, consent: !!s.aiConsent, keys: keys.length, usable: keys.filter(k => !st.invalid[k] && !(st.parked[k] > now)).length }; }
  if (msg.kind === 'generate') { if (!s.aiConsent) throw new Error('sending page HTML to Google is not enabled (extension Options)'); return gemini(msg.payload.prompt, s); }
  if (msg.kind === 'save-profile') { const profiles = s.profiles || {}; profiles[msg.payload.host] = msg.payload.profile; await setSettings({ profiles }); return { ok: true, count: Object.keys(profiles).length }; }
  if (msg.kind === 'get-profile') { return { profile: (s.profiles || {})[msg.host] || null }; }
  if (msg.kind === 'list-profiles') { return { profiles: s.profiles || {} }; }
  if (msg.kind === 'open-options') { try { const p = api.runtime.openOptionsPage(); if (p && p.catch) p.catch(() => {}); } catch (e) {} return { ok: true }; }
  if (msg.kind === 'reset-keys') { await setSettings({ keyState: { idx: 0, parked: {}, invalid: {} } }); return { ok: true }; }
  throw new Error('unknown request ' + msg.kind);
}
api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || msg.type !== 'dumper-ai') return false;
  handle(msg).then(r => sendResponse(r), e => sendResponse({ error: String(e && e.message || e) }));
  return true;   // async reply
});
