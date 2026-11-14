# Photos surface (`image-viewer`)

The render-only page for the photo-viewer playlist (P3 design, section 2). On the line it was built on,
Home showed it as **Photos**; on this branch nothing opens it from Home.

> **What is and is not on this branch.** The examples landed without the Runtime and Home changes of the
> line they were built on. The Photos seam (the Runtime routes `/api/viewers/image-viewer/...`, their test
> `gateway_tests/photos.rs` in `elastos-server`, and `scripts/home-photos-launch.test.mjs`) is **not here**,
> and Home has no Photos entry. Nothing below that names them can be run on this branch.

| Path | What |
|---|---|
| `capsule.json` | `image-viewer`, role `viewer`, `web-projection`. No capabilities, no storage, no requirements. One read-risk interface for discoverability only |
| `browser/index.html` | The page. No inline script, style or handler |
| `browser/main.js` | `mountPhotos(window)`, nothing else |
| `browser/photos.js` | Everything the page does; it takes the window as `env`, so tests can drive it |
| `browser/photos.css` | Layout |
| `photos.test.mjs` | Node tests with a fake fetch and a fake document |
| `photos-browser-smoke.mjs` | The real page in real Chromium, framed in Home's sandbox, against a stand-in server |

## What the page can do

It holds one thing: the launch token Home put in its fragment (`#home_token=`), a token bound to the one
content launch it was opened for (`elastos://launch/<id>`, 15 minutes at most). It sends that token in
`x-elastos-home-token` to the two reads of that launch and nowhere else (the gateway's `viewer_launch_output`
and `viewer_launch_content`, which ask the Runtime for the kept launch):

- `GET /api/viewers/image-viewer/launch/output/playlist.json`: the playlist the photo core wrote
- `GET /api/viewers/image-viewer/launch/content/<path>`: a picture of the launched set, by its path

A picture's path comes from the playlist's `uri`, and only a plain path under `elastos://launch/content/` is
asked for (each part URL-encoded); any other `uri` is listed as not in the set and never asked for. The token
reaches only that launch, so no path the page builds can name anything outside the set it was opened with.
Text from the playlist, such as a skipped item's message, is shown with `textContent`, at most 200
characters. Images are shown from `blob:` URLs, typed from the playlist (PNG, JPEG or WebP only), and
released when replaced. Keys: left and right arrows move, space pauses.

It uses no storage, sends no messages, makes no other request, and asks for no capability. Runtime's app
policy (an opaque sandbox, `script-src 'self'`, `connect-src` the Home origin only) holds it there anyway.

## Run

```bash
node --test examples/photo-viewer/surface/photos.test.mjs          # run by examples/photo-viewer/verify.sh
node examples/photo-viewer/surface/photos-browser-smoke.mjs        # needs Playwright's Chromium
python3 -I examples/photo-viewer/falsify-surface.py                # the page's rules, each broken once
```

**Not on this branch:** on the line this page was built on, the server test
`gateway_tests::photos::runtime_serves_the_real_photos_surface_in_its_sandbox` installed these files as
`image-viewer` and checked that Runtime serves them in its sandbox, that the front door answers the page's
preflight, and that the seam's answers are readable by the opaque frame. That test and the seam it tests
return with the seam, under its own change. Here the page is checked by its own tests, its falsifiers and
the browser smoke against the kit's stand-in server, which plays Runtime.

## Not here

- **Installing it in a real Home.** A viewer needs an entry in the data root's `components.json`
  (`capsule_inventory.rs` `installed_active_capsule_dir`). That is setup and release work, outside this
  slice.
- **Home chrome messages** (`home:app-ready`, menus) are not sent. Photos needs none to show, and sending
  none keeps the page to its two reads.
