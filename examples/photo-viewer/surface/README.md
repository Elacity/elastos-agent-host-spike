# Photos surface (`image-viewer`)

The render-only page for the photo-viewer playlist (P3 design, section 2). Home shows it as **Photos**.

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

It holds one thing: the launch token Runtime put in its fragment (`#home_token=`). It sends that token in
`x-elastos-home-token` to the two Photos routes and nowhere else:

- `GET /api/viewers/image-viewer/playlist`
- `GET /api/viewers/image-viewer/playlist/item/<position>`

An item is asked for by its position. The playlist's `uri` fields are dropped unread, so the page never
builds a path. Text from the playlist, such as a skipped item's message, is shown with `textContent`, at
most 200 characters. Images are shown from `blob:` URLs, typed from the playlist (PNG, JPEG or WebP only),
and released when replaced. Keys: left and right arrows move, space pauses.

It uses no storage, sends no messages, makes no other request, and asks for no capability. Runtime's app
policy (an opaque sandbox, `script-src 'self'`, `connect-src` the Home origin only) holds it there anyway.

## Run

```bash
node --test examples/photo-viewer/surface/photos.test.mjs          # also in `just verify`
node examples/photo-viewer/surface/photos-browser-smoke.mjs        # needs Playwright's Chromium
python3 -I examples/photo-viewer/falsify-surface.py                # the page's rules, each broken once
```

`cargo test -p elastos-server --lib gateway_tests::photos::runtime_serves_the_real_photos_surface_in_its_sandbox`
installs these files as `image-viewer` and checks that Runtime serves them in its sandbox. It also checks
that the front door answers the page's preflight and that the seam's answers are readable by the opaque
frame.

## Not here

- **Installing it in a real Home.** A viewer needs an entry in the data root's `components.json`
  (`capsule_inventory.rs` `installed_active_capsule_dir`). That is setup and release work, outside this
  slice.
- **Home chrome messages** (`home:app-ready`, menus) are not sent. Photos needs none to show, and sending
  none keeps the page to its two reads.
