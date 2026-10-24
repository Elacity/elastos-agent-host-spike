# Page test kit (kit item A5)

What a render-only page's tests share. Neither file ships: a page's closure is only its `capsule.json` and
its `browser/` folder.

| File | What | Used by |
|---|---|---|
| `test-kit.mjs` | `element`, `fakeDocument(ids)`, `response`: the fakes node tests drive a page with | `photo-viewer/surface/photos.test.mjs`, `docs-viewer/surface/reader.test.mjs` |
| `stand-in.mjs` | `standIn`: a server with the headers Runtime sends for an app, the front door's preflight and the launch-token check, serving the page's routes; `inHome`: the page framed in Home's opaque sandbox in real Chromium | `photos-browser-smoke.mjs`, `reader-browser-smoke.mjs` |

## What stays in each page, and why

The page code itself (`launchToken`, the client with its one `fetch` call site, cutting strings) is about
25 lines in each page. It is not shared, for two reasons:

- **A page ships its own files.** Runtime serves a page from its own folder with `script-src 'self'`, so a
  shared module would have to be copied into each `browser/` folder anyway.
- **Runtime's own test of the Photos page installs exactly four files** (`index.html`, `main.js`,
  `photos.js`, `photos.css`; `elastos-server` `gateway_tests/photos.rs`, `install_photos_surface`). A fifth
  file that `photos.js` imports would be missing there, and that test is Runtime code, which this slice does
  not change.
