# Page kit (kit item A5)

What a render-only page shares. The fakes and the stand-in do not ship: a page's closure is only its
`capsule.json` and its `browser/` folder. `docs-render.js` is the one owner of the docs-model renderer; a page
that draws the docs model ships a copy of it.

| File | What | Used by |
|---|---|---|
| `test-kit.mjs` | `element`, `fakeDocument(ids)`, `response`: the fakes node tests drive a page with | `photo-viewer/surface/photos.test.mjs`, `docs-viewer/surface/reader.test.mjs` |
| `stand-in.mjs` | `standIn`: a server with the headers Runtime sends for an app, the front door's preflight and the launch-token check, serving the page's routes; `inHome`: the page framed in Home's opaque sandbox in real Chromium | `photos-browser-smoke.mjs`, `reader-browser-smoke.mjs` |
| `docs-render.js` | The docs-model block renderer: `readBlock`, `drawBlock`, `readSpans`, `cut`, the style map (`STYLES`, `styleTag`) and the renderer bounds | `docs-viewer` ships a copy at `surface/browser/docs-render.js`; its build writes the copy, and its surface test pins it to these bytes |
| `page-client.js` | The launch token reader and one-request client: `launchToken`, `TOKEN_HEADER`, `pageClient` | `docs-viewer` ships a copy at `surface/browser/page-client.js`; its build writes the copy, and its surface test pins it to these bytes |

## One owner, verified copies

The docs-model renderer has one owner: `docs-render.js`. Runtime serves a page from its own folder with
`script-src 'self'`, so a page cannot import another folder's file at runtime. The page's `build.sh` copies
`docs-render.js` into its `browser/` folder, and a named surface test (`the shipped renderer matches the kit
owner`) asserts the copy is byte-identical to the owner. Edit the owner and rebuild; a hand edit to a copy
fails the test. The archive viewer will reuse the owner instead of copying it by hand.

The launch client has one owner: `page-client.js`. The docs build copies it into
`surface/browser/page-client.js`, and `the shipped client matches the kit owner` compares the bytes.
The client imports `cut` from the sibling `docs-render.js`. The document list and page bounds stay in
the page. The archive build copies `page-client.js` to `surface/browser/page-client.js`, and
`the shipped client matches the kit owner` compares the bytes.

The Photos page keeps its client copy until Runtime's four-file gateway test allows a fifth file.
That test (`elastos-server` `gateway_tests/photos.rs`, `install_photos_surface`) installs `index.html`,
`main.js`, `photos.js` and `photos.css`. The Photos page draws images and keeps its own renderer.
