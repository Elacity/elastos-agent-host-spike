# Documents surface (`docs-reader`)

The render-only page for the docs-viewer pages. It follows the Photos surface
(`examples/photo-viewer/surface`) and the checklist in `examples/capsule-kit/PATTERNS.md`, pattern 2.

| Path | What |
|---|---|
| `capsule.json` | `docs-reader`, role `viewer`, `web-projection`. No capabilities, no storage, no requirements. One read-risk interface for discoverability only |
| `browser/index.html` | The page. No inline script, style or handler |
| `browser/main.js` | `mountReader(window)`, nothing else |
| `browser/reader.js` | Everything the page does; it takes the window as `env`, so tests can drive it |
| `browser/reader.css` | Layout |
| `reader.test.mjs` | Node tests with a fake fetch and a fake document |
| `reader-browser-smoke.mjs` | The real page in real Chromium, framed in Home's sandbox, against a stand-in server |
| `fixtures/pages.json` | The pages the core writes for a test shelf (`src/tests.rs`, `the_surface_fixture_is_what_the_core_writes`), so both sides are held to one format |

## What the page can do

It holds one thing: the launch token Runtime put in its fragment (`#home_token=`). It sends that token in
`x-elastos-home-token` to one route and nowhere else:

- `GET /api/viewers/docs-reader/pages`

The core already parsed every document into blocks of text, so the page has no item route and no parser:
it draws six block kinds (heading, paragraph, list, code, quote, rule) and four span styles (plain, strong,
emphasis, code), each as an element whose text is set with `textContent`. A block of any other kind, or too
many blocks, spans or items, makes the document "not shown". It never builds a path, follows a link or loads
an image: a link and an image are already text. It uses no storage, sends no messages, and asks for no
capability.

## Not here

- **The Runtime route.** The seam that exists (`viewer_gateway.rs`, "Photos surface") serves `image-viewer`
  and its playlist only. There is no `docs-reader` route in Runtime, and adding one is a Runtime change, so
  this page has run only against the stand-in server. See `examples/capsule-kit/KIT-REPORT.md`.
- **Opening it from the Library.** The Library picks a viewer by a name table (`.md` and `.txt` open
  `documents`, the existing editor), not by what a viewer declares.

## Run

```bash
node --test examples/docs-viewer/surface/reader.test.mjs
node examples/docs-viewer/surface/reader-browser-smoke.mjs        # needs Playwright's Chromium
python3 -I examples/docs-viewer/falsify-surface.py
```
