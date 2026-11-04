# Dumpper

**Dumper** — a browser extension that dumps the victim list of any ransomware leak site you have open
into one JSON file (text in visual order, links, IOCs, card HTML + site CSS, images, a card picture),
grouped by date, with tick-to-select and "only not yet dumped" tracking. It works on the already
loaded page (after you solved the CAPTCHA) and never reloads or navigates.

| folder | what |
|---|---|
| `extension/` | the unpacked extension (Manifest V3; Chrome, Brave, Edge, Tor Browser / Firefox) — see `extension/README.md` |
| `scripts/build-dumper-data.py` | regenerates `extension/data.js` (101 site profiles + onion → group map) from a [sxi9/leakwatch](https://github.com/sxi9/leakwatch) checkout |
| `scripts/render-cards.py` | renders every card of a dump to PNG with Playwright (for Tor Browser dumps, where in-page canvas reads are noise) |

## Install
1. Download / clone this repo.
2. Chrome, Brave, Edge: `chrome://extensions` → Developer mode → **Load unpacked** → pick `extension/`. Pin it from the puzzle-piece menu.
3. Tor Browser / Firefox: `about:debugging#/runtime/this-firefox` → **Load Temporary Add-on** → `extension/manifest.json` (temporary add-ons vanish when the browser closes; load again next session).

## Use
Open a leak site, solve its CAPTCHA, wait for the cards. The **Dumper** panel opens by itself when it
finds victims (or click the toolbar icon). Check the *Source* line (which detector won), tick victims
or a whole date, **Dump selected** → `<group>-dump-<date>-<n>.json` in Downloads.

How victims are found, in order: JS data adapters (The Gentlemen `companies`, any global / `<script>`
JSON array of victim-like objects such as Leaknet `INIT_DATA`), the leakwatch site profiles
(fingerprint + item/title/link/date/description selectors), generic card heuristics, and finally
custom selectors you type in the panel (saved per site). Full details in `extension/README.md`.

## Update the site tables
```bash
python3 scripts/build-dumper-data.py /path/to/leakwatch
```
then reload the extension.

## Render cards from a dump
```bash
pip install playwright && playwright install chromium
python3 scripts/render-cards.py gentlemen-dump-2026-11-03-25.json out/cards
```
