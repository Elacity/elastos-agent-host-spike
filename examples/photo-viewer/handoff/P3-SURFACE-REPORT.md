# P3 surface report: the render-only Photos page

Slice P3 code, part two: the `image-viewer` surface page (P3 design section 6, item 1). It sits on the seam
merged in #18 (`spike/photo-viewer` at `dee1aca6`). **It stops here for review.**

Branch `claude/photo-p3-surface`, from `spike/photo-viewer`. **No shipping Runtime change**: the page lives
in `examples/photo-viewer/surface/`, and the one Runtime-side file touched is the test module
`gateway_tests/photos.rs`.

## What changed

| File | Change |
|---|---|
| `examples/photo-viewer/surface/capsule.json` | `image-viewer`, role `viewer`, `web-projection`. No capabilities, storage or requirements. One read-risk interface, `playlist.show`, for discoverability only |
| `surface/browser/index.html`, `main.js`, `photos.css` | The page. No inline script, style or handler; `main.js` is `mountPhotos(window)` |
| `surface/browser/photos.js` | Everything the page does, taking the window as `env` |
| `surface/photos.test.mjs` | 12 node tests, fake fetch and fake document; added to `just verify` |
| `surface/photos-browser-smoke.mjs` | The real page in real Chromium, in Home's sandbox, with Runtime's app headers |
| `examples/photo-viewer/falsify-surface.py` | 13 falsifiers over the page's rules |
| `server/api/gateway_tests/photos.rs` (test only) | `runtime_serves_the_real_photos_surface_in_its_sandbox` |
| `surface/README.md`, `justfile` | How to run it; the node tests join `just verify` |

## The page

- **It holds one thing:** the launch token from `#home_token=`. Without one it shows "Open Photos from Home."
  and asks for nothing.
- **It makes two kinds of request**, each a `GET` with `x-elastos-home-token`, `credentials: "omit"`,
  `cache: "no-store"` and `redirect: "error"`:
  - `GET /api/viewers/image-viewer/playlist`, once;
  - `GET /api/viewers/image-viewer/playlist/item/<position>`, one per photo shown.
- **It never builds a path.** It keeps only `{order, mime, width, height, duration_ms}` of each item. The
  `uri` fields are dropped unread. A position must be a whole number of 0 or more, else the entry is listed
  as "could not be read". A repeated position is listed the same way.
- **Its own checks,** on top of the seam's:
  - the playlist schema `elastos.photo-viewer.playlist/v1`;
  - at most 64 items;
  - PNG, JPEG or WebP only;
  - each duration kept within the core's 1–60 s.
- **Text** from the playlist (a skipped item's message, a refusal) is shown with `textContent` only, cut to
  200 characters.
- **Images** come from `blob:` URLs, typed from the playlist, and are released when replaced. A slow answer
  for an earlier photo never replaces a later choice.
- **Controls:** previous, pause and next buttons; the left and right arrows and space.
- **Not sent:** Home chrome messages (`home:app-ready`, menus), by decision (review answer 2 below). The page
  never calls `postMessage`.

## What the browser path depends on, and where it is pinned

The page runs as an opaque origin, so every subresource and every fetch is cross-origin. The gateway test
installs the real files as `image-viewer` and pins what the browser needs:

| Needed | Pinned |
|---|---|
| The document's CSP: Runtime's sandbox, `script-src 'self' 'wasm-unsafe-eval'`, `connect-src` the Home origin, `object-src 'none'`, no `allow-same-origin` | the document response |
| Module scripts load by CORS: `access-control-allow-origin: null` on each file | every file |
| `cross-origin-embedder-policy: require-corp`, and `cross-origin-resource-policy: cross-origin` for the stylesheet, which loads no-cors | every file |
| The `x-elastos-home-token` header triggers a preflight; the front door answers it for both routes (204, `null`, the header allowed) | `OPTIONS` on both routes |
| The seam's answer is readable by the frame (`access-control-allow-origin: null`) | the playlist `GET` from origin `null` |
| Served bytes equal the files in `examples/` | every file |

The Chromium smoke found the CORP need. A first run, without that header on the stand-in server, had the
stylesheet blocked by COEP. Runtime does send it; the stand-in now does too, and the gateway test pins it.

## Tests run and results

`export RUST_TEST_THREADS=2`:

| Suite | Result |
|---|---|
| `node --test examples/photo-viewer/surface/photos.test.mjs` | 12 passed |
| `node examples/photo-viewer/surface/photos-browser-smoke.mjs` (Playwright Chromium 1194, headless) | ok |
| `cargo test -p elastos-server --lib gateway_tests::photos` | 25 passed (24 seam + the real-surface test) |
| `cargo fmt -p elastos-server -- --check`, `cargo clippy -p elastos-server --all-targets -- -D warnings` | clean (exit 0) |

In the Chromium smoke:
- both PNGs decode at their real sizes, from `blob:` URLs;
- the skipped item's `<img onerror=…>` message shows as text, adds no element and makes no request;
- `localStorage` throws, because the frame is opaque;
- the only API requests are the playlist, items 0 and 2, and their preflights; item 1, the skipped one, is
  never asked for;
- there are no console errors (no CSP violation, no blocked resource).

Bug found by the tests: a refusal whose body had no readable `error` showed an empty status instead of
"Photos could not read this (status)". Fixed before the first commit, and falsified.

## Falsifiers

`python3 -I examples/photo-viewer/falsify-surface.py`: **13 of 13 caught**. Each mutant is restored from
saved bytes; `git status` after the run was clean. `--check` confirms the anchors only.

| Falsifier | Caught by |
|---|---|
| a position that is not a whole number is asked for | `it never requests a path…` |
| a skipped message is shown as markup | `it shows skipped items as text…`, `the page has no way to hold or reach anything else` |
| a skipped message is not cut short | `it shows skipped items as text…` |
| requests carry cookies | `it makes no request other than the two routes…` |
| requests are made without a launch token | `without a launch token it asks for nothing` |
| a type the core does not allow is shown | `a playlist that is not one is refused` |
| the playlist schema is not checked | `a playlist that is not one is refused` |
| a playlist of any length is taken | `a playlist that is not one is refused` |
| a duration outside the core's bounds is kept | `each photo shows for its duration…` |
| pause does not stop the slideshow | `each photo shows for its duration…` |
| a slow earlier answer replaces a later choice | `a slow answer for an earlier choice does not replace a later one` |
| old photo URLs are never released | `it renders only playlist items…` |
| an unreadable refusal shows no text | `a refusal is shown as its text` |

Not falsified separately, and said plainly:

- **The position check inside `photosClient().item`.** `readPlaylist` already refuses every bad position,
  so removing the second check fails no test. It is kept as a backstop.
- **The static scan** (no `innerHTML`, storage, messaging, other network, inline script) is a test, not a
  falsifier. One falsifier (markup) trips it.
- **The seam** is unchanged since #18. Its 21 falsifiers were not re-run on this branch; the 24 seam tests
  were.

## Principles checked

- **3 (no ambient authority).** The page's only authority is the launch token Runtime minted for this frame;
  it asks for no capability and declares no storage.
- **10 (one path).** Two read routes, items by position only; no path ever leaves the page.
- **11 (fail closed, then explain).** Every refusal from the seam shows its reason; a playlist the page cannot
  read is refused as a whole, and an entry it cannot show is listed with why.
- **13 (objects vs capsules).** The images and playlist stay the person's objects; the page holds only blob
  URLs for what it shows.
- **16 (UI is not authority).** The page cannot widen what the token allows; Runtime's sandbox and CSP hold
  it there even if the page changed.
- **18 (isolated instances).** Each frame has its own token and its own opaque origin.

## Roadmap milestone

2.5 (first app, photo viewer): the core (P1–P2), the seam (#18), and now the surface. Installing
`image-viewer` into a real Home stays out of the spike (review answer 1 below). The Phase 2 binding of the
run output is not built.

## Review answers (Sasha, relaying the Cursor review; Codex PASS at `d7e4dd02`)

1. **Installing `image-viewer` into a real Home stays out of the spike.** A `components.json` entry is
   release setup work, and this is freeze week. The real install path is Phase 2: the signed bundle
   (roadmap 2.2), then the photo viewer on Bus v2 (2.5). No slice for it.
2. **The page does not send `home:app-ready`, and stays silent.** Home draws the title bar and close button
   itself. In `capsules/home/browser/home-shell-host.js`, `home:app-ready` only resets per-document state
   (the link prompt, the picker, the clipboard) and sends a navigation hint for five named apps.
   - The page never sent it, so nothing was removed.
   - It is already tested: `the page has no way to hold or reach anything else` in
     `surface/photos.test.mjs` fails if `postMessage` appears in `photos.js` or `main.js`.
   - In the Chromium smoke the page sends Home nothing.

## Next slice

None. The photo track has 7 of 7 slices built. Nothing new starts without Sasha.
