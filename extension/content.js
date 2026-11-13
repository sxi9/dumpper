// Injects data.js + panel.js into the PAGE world (page globals are invisible to content scripts),
// relays the toolbar click, and bridges the panel's AI requests to the extension background
// (window.postMessage <-> runtime.sendMessage). The Gemini key never reaches the page.
(() => {
  if (window.__dumperContentLoaded) return; window.__dumperContentLoaded = true;
  const api = typeof browser !== 'undefined' ? browser : chrome;
  const inject = (file, next) => { const s = document.createElement('script'); s.src = api.runtime.getURL(file); s.onload = () => { s.remove(); next && next(); }; (document.head || document.documentElement).appendChild(s); };
  inject('data.js', () => inject('panel.js'));
  api.runtime.onMessage.addListener(msg => { if (msg && msg.type === 'dumper-toggle') document.dispatchEvent(new CustomEvent('dumper-toggle')); });
  window.addEventListener('message', e => {
    const m = e.data; if (e.source !== window || !m || m.dumper !== 'ai-request') return;
    const reply = r => window.postMessage(Object.assign({ dumper: 'ai-response', id: m.id }, r || { error: 'empty reply' }), '*');
    try {
      const p = api.runtime.sendMessage({ type: 'dumper-ai', kind: m.kind, payload: m.payload, host: location.hostname });
      if (p && p.then) p.then(reply, err => reply({ error: String(err) })); else reply({ error: 'runtime.sendMessage returned nothing' });
    } catch (err) { reply({ error: String(err) }); }
  });
})();
