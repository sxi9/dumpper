// Toolbar button: clicking the (pinned) Dumper icon toggles the panel on the current tab.
// Works as a MV3 service worker (Chrome) and as a background script (Firefox/Tor).
const api = typeof browser !== 'undefined' ? browser : chrome;
api.action.onClicked.addListener(tab => {
  if (!tab.id) return;
  api.tabs.sendMessage(tab.id, { type: 'dumper-toggle' }).catch?.(() => {});
});
