// Injects panel.js into the PAGE world so it can read the site's own `companies` array
// (content scripts live in an isolated world and cannot see page globals), and relays the
// toolbar-button click to it as a DOM event.
(() => {
  const api = typeof browser !== 'undefined' ? browser : chrome;
  const inject = (file, next) => { const s = document.createElement('script'); s.src = api.runtime.getURL(file); s.onload = () => { s.remove(); next && next(); }; (document.head || document.documentElement).appendChild(s); };
  inject('data.js', () => inject('panel.js'));
  api.runtime.onMessage.addListener(msg => {
    if (msg && msg.type === 'dumper-toggle') document.dispatchEvent(new CustomEvent('dumper-toggle'));
  });
})();
