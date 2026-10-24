# Archive surface (`archive-reader`)

The render-only page for the archive-viewer view. It follows the Documents
surface (`examples/docs-viewer/surface`) and the checklist in
`examples/capsule-kit/PATTERNS.md`, pattern 2.

| Path | What |
|---|---|
| `capsule.json` | `archive-reader`, role `viewer`, `web-projection`. No capabilities, no storage, no requirements. One read-risk interface for discoverability only |
| `browser/index.html` | The page. No inline script, style or handler |
| `browser/main.js` | `mountReader(window)`, nothing else |
| `browser/reader.js` | The listing rows, the view checks and the mount; it takes the window as `env`, so tests can drive it |
| `browser/docs-render.js` | The docs-model block renderer, shipped copy. Its one owner is `examples/capsule-kit/surface/docs-render.js`; the build copies it and `reader.test.mjs` pins the bytes |
| `browser/reader.css` | Layout |
| `reader.test.mjs` | Node tests with a fake fetch and a fake document |
| `reader-browser-smoke.mjs` | The real page in real Chromium, framed in Home's sandbox, against a stand-in server |
| `fixtures/view.json` | A view in the shape the core writes, so both sides are held to one format |

## What the page can do

It holds one thing: the launch token Runtime put in its fragment
(`#home_token=`). It sends that token in `x-elastos-home-token` to one route
and nowhere else:

- `GET /api/viewers/archive-reader/view`

The page draws two things. The listing rows are its own: `index`, `path`,
`kind`, both declared sizes, `method`, `status` and `reason`, all as text, with
only the table's own kind names selecting a label. The previews are the
documents model's typed blocks, drawn by the shared renderer it ships as
`./docs-render.js`; this page defines none of the block rules. A view, entry or
preview it cannot read is not drawn on a guess. A refused archive shows its
reason and nothing beside it.

It never builds a path or URI, never fetches an entry, follows no link, and
draws no image on Bus v1: an image entry is a listed row, and an image block
is not a block the documents model reads. It uses no storage, sends no
messages, and asks for no capability.

## Not here

- **The Runtime route.** The seam that exists (`viewer_gateway.rs`, "Photos
  surface") serves `image-viewer` and its playlist only. There is no
  `archive-reader` route in Runtime, and adding one is a Runtime change, so
  this page has run only against the stand-in server.
- **Opening it from Home.** The archive-viewer core names the archive in a
  request object, and Home binds a launch only for `image-viewer` today. The
  launch binding is M6.
- **Image previews and the Bus v2 page.** Both wait for the typed UI document
  (DESIGN, F34 and F18).

## Run

```bash
node --test examples/archive-viewer/surface/reader.test.mjs
node examples/archive-viewer/surface/reader-browser-smoke.mjs        # needs Playwright's Chromium
python3 -I examples/archive-viewer/falsify-surface.py
```
