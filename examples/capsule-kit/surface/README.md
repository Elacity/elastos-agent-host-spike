# Page kit (kit item A5)

What a render-only page shares. The fakes and the stand-in do not ship: a page's closure is only its
`capsule.json` and its `browser/` folder. `docs-render.js` is the one owner of the docs-model renderer; a page
that draws the docs model ships a copy of it.

| File | What | Used by |
|---|---|---|
| `test-kit.mjs` | `element`, `fakeDocument(ids)`, `response`: the fakes node tests drive a page with | `photo-viewer/surface/photos.test.mjs`, `docs-viewer/surface/reader.test.mjs` |
| `stand-in.mjs` | `standIn`: a server with the headers Runtime sends for an app, the front door's preflight and the launch-token check, serving the page's routes; `inHome`: the page framed in Home's opaque sandbox in real Chromium | `photos-browser-smoke.mjs`, `reader-browser-smoke.mjs` |
| `docs-render.js` | The docs-model block renderer: `readBlock`, `drawBlock`, `readSpans`, `cut`, the style map (`STYLES`, `styleTag`) and the renderer bounds | `docs-viewer` ships a copy at `surface/browser/docs-render.js`; its build writes the copy, and its surface test pins it to these bytes |

## One owner, verified copies

The docs-model renderer has one owner: `docs-render.js`. Runtime serves a page from its own folder with
`script-src 'self'`, so a page cannot import another folder's file at runtime. The page's `build.sh` copies
`docs-render.js` into its `browser/` folder, and a named surface test (`the shipped renderer matches the kit
owner`) asserts the copy is byte-identical to the owner. Edit the owner and rebuild; a hand edit to a copy
fails the test. The archive viewer will reuse the owner instead of copying it by hand.

Page glue stays page-local: `launchToken`, the client with its one `fetch` call site, the document-list
framing and the page-only bounds are about 25 lines in each page. It is not shared, for two reasons:

- **A page ships its own files.** Runtime serves a page from its own folder with `script-src 'self'`, so a
  shared module would have to be copied into each `browser/` folder anyway.
- **Runtime's own test of the Photos page installs exactly four files** (`index.html`, `main.js`,
  `photos.js`, `photos.css`; `elastos-server` `gateway_tests/photos.rs`, `install_photos_surface`). A fifth
  file that `photos.js` imports would be missing there, and that test is Runtime code, which this slice does
  not change. The Photos page draws images, not docs-model blocks, so it does not gain `docs-render.js`.
