# Archive surface (`archive-reader`)

The render-only page for the archive-viewer view. It follows the Documents
surface (`examples/docs-viewer/surface`) and `examples/capsule-kit/PATTERNS.md`,
pattern 2.

| Path | What |
|---|---|
| `capsule.json` | `archive-reader`, role `viewer`, `web-projection`. No capabilities, no storage, no requirements. One read-risk interface for discoverability only |
| `browser/index.html` | The page. No inline script, style or handler |
| `browser/main.js` | `mountReader(window)`, nothing else |
| `browser/reader.js` | Everything the page does; it takes the window as `env`, so tests can drive it |
| `browser/reader.css` | Layout |
| `reader.test.mjs` | Node tests with a fake fetch and a fake view |
| `reader-browser-smoke.mjs` | The real page in real Chromium, framed in Home's sandbox, against a stand-in server |
| `fixtures/view.json` | A sample `elastos.archive-viewer.view/v1` view (a hostile path, a directory, a nested archive, a blocked entry, an image-path file and one text preview), so both sides are held to one format |

## What the page can do

It holds one thing: the launch token Runtime put in its fragment
(`#home_token=`). It sends that token in `x-elastos-home-token` to one route and
nowhere else:

- `GET /api/viewers/archive-reader/view`

The core already listed every entry and turned each shown text entry into the
documents model's typed blocks, so the page has no item route and no archive
parser. It draws the listing (path, kind, declared sizes, method, status,
reason) and six block kinds (heading, paragraph, list, code, quote, rule) with
four span styles (plain, strong, emphasis, code), each as an element whose text
is set with `textContent`. An entry path is text, never markup and never a path.
An image entry is a listed row and no image is drawn on Bus v1 (DESIGN decision
4). It uses no storage, sends no messages, and asks for no capability.

## Run

```bash
node --test examples/archive-viewer/surface/reader.test.mjs
node examples/archive-viewer/surface/reader-browser-smoke.mjs        # needs Playwright's Chromium
python3 -I examples/archive-viewer/falsify-surface.py
```
