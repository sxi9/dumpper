const api = typeof browser !== 'undefined' ? browser : chrome;
const $ = id => document.getElementById(id);
function get(keys) { return new Promise(res => { const p = api.storage.local.get(keys, v => res(v || {})); if (p && p.then) p.then(res); }); }
function set(obj) { return new Promise(res => { const p = api.storage.local.set(obj, () => res()); if (p && p.then) p.then(res); }); }
async function load() {
  const s = await get(['geminiKey', 'geminiKeys', 'geminiModel', 'aiConsent', 'profiles', 'keyState']);
  $('keys').value = s.geminiKeys || s.geminiKey || '';
  const ks = s.keyState || { parked: {}, invalid: {} }; const keys = (s.geminiKeys || s.geminiKey || '').split(/\r?\n|,|;/).map(k => k.trim()).filter(Boolean); const now = Date.now();
  $('keystatus').textContent = keys.length ? keys.map((k, i) => `#${i + 1} ${k.slice(0, 4)}…${k.slice(-4)}: ${ks.invalid && ks.invalid[k] ? 'INVALID' : (ks.parked && ks.parked[k] > now) ? 'parked ' + Math.ceil((ks.parked[k] - now) / 60000) + ' min' : 'ok'}${ks.idx === i ? ' (next)' : ''}`).join(' · ') : 'no keys yet'; $('model').value = s.geminiModel || 'gemini-2.5-flash'; $('consent').checked = !!s.aiConsent;
  const p = s.profiles || {}; $('profiles').textContent = Object.keys(p).length ? JSON.stringify(p, null, 1) : '(none)';
}
$('save').onclick = async () => { await set({ geminiKeys: $('keys').value.trim(), geminiKey: '', geminiModel: $('model').value.trim() || 'gemini-2.5-flash', aiConsent: $('consent').checked }); $('msg').textContent = 'Saved.'; setTimeout(() => $('msg').textContent = '', 2000); load(); };
$('resetkeys').onclick = async () => { await set({ keyState: { idx: 0, parked: {}, invalid: {} } }); load(); };
$('clear').onclick = async () => { await set({ profiles: {} }); load(); };
load();
