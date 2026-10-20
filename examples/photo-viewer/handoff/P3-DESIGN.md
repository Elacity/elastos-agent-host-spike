# P3 design: a render-only surface for the photo viewer

Slice P3, **design only**. No code, and nothing outside this file changed. Every claim cites `file:line` on
this branch (`claude/photo-p3`, stacked on `claude/photo-p2b`). Paths under `elastos/crates/elastos-server/src/`
are shortened to `server/`.

Goal from the review: a display-only surface with no authority of its own, which reads only the playlist and
the images it names. In Phase 2 its input is the object the person opened.

## 1. What exists today

### 1.1 How a viewer frame is launched and what it holds

1. **Home asks, Runtime mints.** Home posts `POST /api/apps/home/launch` with a target and a query
   (`server/api/gateway.rs:1046`, handler `server/api/gateway_home_runtime.rs:3-145`). Runtime resolves the
   target, then mints a launch token (`gateway_home_runtime.rs:110-122`, `147-162`).
2. **What the token is.** Runtime signs it (`server/api/gateway_home_token.rs:281-323`, schema
   `elastos.home.launch-token/v4` at `:8`). It binds:
   - a `launch_context` of `{selected_resource, executable_actor, authority_actor}` (`:19-61`);
   - principal, session and grant (`:64-78`);
   - `non_delegatable: true` (`:306`);
   - a 12-hour expiry (`server/api/gateway.rs:262`).
   `selected_resource` is at most 256 characters (`gateway_home_token.rs:52`).
3. **What reaches the page.** The query (for a Library open: `objectUri`, `name`, `mime`, `contentCid`,
   `capsules/library/browser/src/actions.js:115-134`) is appended to the route **in plain text**. The token
   goes in the fragment as `#home_token=` (`gateway_home_runtime.rs:164-187`). Pages read it from
   `location.hash` (`capsules/library/browser/src/state.js:22`, `capsules/documents/browser/documents.js:7`).
4. **What the token names.** For a viewer it names a *capsule* (the viewer, or a content capsule bound to it),
   not a Library object. `require_home_viewer_launch_token_context` returns `selected_resource`
   (`gateway_home_token.rs:396-404`), and `require_viewer_library_launch_context` accepts it when it is the
   viewer itself or a content capsule bound to it (`server/api/viewer_gateway.rs:691-709`).
   - **The opened object's URI is not in the token.** That is the P0 question 3 finding, confirmed in review
     and tracked privately.

### 1.2 The frame boundary

- **Iframe sandbox.** Home frames apps in an opaque sandbox: `allow-downloads allow-forms allow-modals
  allow-pointer-lock allow-scripts`, no `allow-same-origin` (`capsules/home-gui/browser/shell-windows.js:381-406`).
- **CSP.** Runtime serves every non-Home app document with a CSP that adds its own `sandbox allow-scripts
  allow-forms allow-downloads`. It allows `default-src`, `connect-src`, `frame-src` and `form-action` only to
  the Home origin and its WebSocket, `img-src` to the Home origin plus `blob:` and `data:`, and sets
  `object-src 'none'` (`server/api/browser_capsules.rs`, `shell_content_security_policy`, called at `296-304`
  and `331-340`).
- **Isolation headers.** COOP `same-origin`, COEP `require-corp`, ACAO `null` (`browser_capsules.rs:21-25`,
  `309-330`).

So a surface can reach nothing but Home-origin APIs, and those APIs are what its launch token unlocks.

### 1.3 What a viewer can read today

`/api/viewers/:viewer/library-object?raw=1` (`server/api/gateway.rs:1212-1216`) returns the bytes of any
object whose extension maps to that viewer. The checks:

- the launch-token context check (`viewer_gateway.rs:630-640`);
- the extension table (`viewer_gateway.rs:613-628`, `server/library.rs:7086-7107`);
- `uri` comes from the query (`viewer_gateway.rs:173-192`, `545-576`).

Per-request audit exists (`viewer_gateway.rs:654-682`). The Library's own preview reads through its own
provider authority (`capsules/library/browser/src/preview.js:39-40`), not through a viewer.

### 1.4 How a Component gets run from Home

When a Home target is a shell-launchable, non-projection WASM capsule, the launch also runs it:

- Runtime posts the capsule path to the shell-only `POST /api/capsules` with a projection launch grant bound
  to the person (`gateway_home_runtime.rs:427-492`, `516-556`; route `server/api/server.rs:461-466`).
- That grant becomes the run's principal (`server/api/routes.rs:80-118`).

Home targets are browser capsules (`gateway_home_runtime.rs:294-319`, which needs `browser/index.html`,
`browser_capsules.rs:635-660`) and viewer-bound content capsules (`gateway_home_runtime.rs:321-351`). A pure
Component is therefore not a Home target. Component manifest validation (`elastos-common/src/manifest.rs:775-801`)
does not forbid a `browser/` directory or a `web` projection, which matters for question 3 below.

## 2. The surface

**`image-viewer`** is a web-projection capsule with role `viewer`. That name is already reserved by the
Library for `.png`/`.jpg`/`.jpeg`/`.gif` (`server/library.rs:7092-7097`, label `:7124`), so no Library table
edit is needed to make it appear. It is separate from the `photo-viewer` Component: one capsule, one role, one
execution (`examples/hello/README.md` "Adapt the shape").

| Declared | Value |
|---|---|
| `role`, `execution` | `viewer`, `web-projection` (`docs/CAPSULE_AUTHORING.md:123-135`) |
| `capabilities`, `permissions.storage` | **none** |
| `interfaces` | one read-risk method, `playlist.show`, discoverability only (`CAPSULE_AUTHORING.md:186-196`) |
| `entrypoint` | `browser/index.html` and one script, no dependencies |

What its page does:

- Reads `home_token` from the fragment, like other apps.
- Calls only the two read routes in section 3. With the token in a header, it fetches the playlist, then
  each image as bytes, makes a `blob:` URL (allowed by the CSP's `img-src`) and shows it in an `<img>` for
  `duration_ms`.
- Shows each `skipped` item with its `message` as text.
- Has keys for previous, next and pause.
- **It never builds a URI.** Requests name a playlist position (`order`), not a path.
- It has no write route, no capability request, no network beyond Home, and no storage (the opaque sandbox
  has none).

What it holds: only the launch token Runtime minted for this frame. The token is non-delegatable and expires;
the surface cannot widen it. This is the reading of "no authority of its own" I propose: everything it can do
comes from one Runtime-minted, per-launch token that unlocks only the two read routes, for one playlist, for
this person.

Image decoding happens in the browser, inside the sandboxed frame's renderer, not in Runtime. The Component
checked type, size and dimensions before anything reaches the frame. The browser applies EXIF orientation
itself (`image-orientation: from-image` is the default), so the guest does not need to.

## 3. The Runtime seam (shipping change: needs Sasha's yes)

This is the one new Runtime piece, as named in P0. It is two read-only routes next to the existing viewer
routes:

| Route | Returns |
|---|---|
| `GET /api/viewers/image-viewer/playlist` | The bound playlist bytes, at most 64 KiB, `no-store` |
| `GET /api/viewers/image-viewer/playlist/item/:order` | The bytes of item `order`, at most 64 MiB, `no-store`, `application/octet-stream` |

Each request is checked in this order. The first failure refuses with a reason and is audited:

1. Valid launch token, `executable_actor == image-viewer`, and the viewer is installed with role `viewer`
   (reuse `viewer_gateway.rs:630-640`).
2. **Which playlist.** The token's `selected_resource` names the playlist the frame was launched for. For the
   spike that is the fixed object `localhost://Users/self/.AppData/App/photo-viewer/playlist.json` (62
   characters, under the 256 limit), resolved against the token's principal. The surface never sends a path.
3. **Which item.** Runtime reads the playlist (Runtime-handled principal-root read,
   `server/resource_bridge.rs:458-569`). It looks up `items[]` by `order` and takes that entry's `uri`.
   Runtime reads only `items[].order` and `items[].uri`, not the rest of the app's schema. A `skipped` entry
   is not an item, so it cannot be fetched.
4. **Bounds.** The item `uri` must be under `localhost://Users/self/Pictures/`, the prefix the Component's
   manifest declares (`examples/photo-viewer/capsule.json`), and must be viewable by `image-viewer` (reuse
   `viewer_gateway.rs:613-628`).
5. Read the bytes with Runtime's principal-root read and cap them at 64 MiB.
6. Append an audit event: viewer, principal, playlist, order, uri, result (reuse `viewer_gateway.rs:654-682`).

**No write route.** Any method other than `GET` gets 405.

What the seam does **not** fix in the spike: who wrote the playlist. Any capsule whose storage bounds cover
`.AppData/App/photo-viewer/` could write that path. Phase 2 removes the fixed path (section 4). For the spike,
the item checks (Pictures prefix, viewer extension table) still bound what a forged playlist could show:
images the person's own viewer could already open.

### Spike flow (Bus v1, no other Runtime change)

1. The person, or `elastos run`, runs the `photo-viewer` Component. It writes the playlist at the fixed path
   (P1b).
2. The person opens **Photo viewer** in Home. Home launches `image-viewer` with
   `selected_resource = <playlist object>`. That needs Home to pass the playlist as the selected resource, a
   small Home change; or, simpler, the seam treats the fixed path as implied for `image-viewer`. Question 2.
3. The surface fetches the playlist and its items through the seam and plays them.

## 4. Phase 2: the input is the object the person opened (P16)

| Step | Who | What |
|---|---|---|
| 1 | Person | Opens an album object, or selects images, in the Library. |
| 2 | Library → Home | `home:open-target` with the object, as today (`actions.js:115-134`). |
| 3 | Runtime | Binds the **opened object** into the launch: `selected_resource` becomes the object, not the viewer name. This closes the P0 question 3 gap: the object travels in the signed token instead of the plain query. |
| 4 | Runtime | Runs the core Component for this launch, with that object as its input and a read grant for exactly that object and the images it lists. This needs Bus v2: a `run` input and output (roadmap 2.3), or a Runtime-provided per-launch input handle. |
| 5 | Component | Returns the playlist as its **run output**. No user-writable path is involved. |
| 6 | Runtime | Stores the output against the launch id, and mints the surface token with `selected_resource = launch:<id>/output`. |
| 7 | Seam | As in section 3, plus: each item must also be one the **input** object listed (the intersection). A compromised Component cannot widen what the surface shows beyond what the person opened. |
| 8 | Runtime | Closing the window ends the launch, and Runtime drops the output. The token cannot outlive it. |

Then, under roadmap 2.2:
- the `image-viewer` manifest names its core Component by **bundle CID** rather than by name;
- both are signed bundles;
- playlist entries can carry the Runtime-named CID of each image instead of a path.

## 5. Kit item: `scripts/` reproducible-build proposal (roadmap 2.4)

From review answer 3. Not done now; the recipe stays in `examples/photo-viewer/repro/`.

- **Move.** `repro/build-in-container.sh` becomes `scripts/build-component-capsule-repro.sh <capsule-dir>`.
  It is the same container, digest and platform, and runs the existing `scripts/build-component-capsule.sh`
  inside, so there is still one builder (P10).
- **Pins in one file.** `scripts/repro-image.env` holds the image digest, platform, Debian snapshot and
  `python3` version, so a bump is one reviewed diff.
- **Recorded hash.** Each component capsule records its expected artifact sha256 next to the source, for
  example a `repro.sha256` file, or `capsule.json` once signing names bundles by CID (2.2). A check script
  rebuilds and compares, and fails closed with both hashes and the section that differs (the
  `wasm_sections.py` comparison from the agent-host spike).
- **CI.** One job runs the check for the fixture `elastos/tests/fixtures/components/bus-v1` and every repo
  component capsule. Another machine type (macOS runner, `linux/amd64` emulated) runs it weekly, which is the
  two-machine check P2 could not finish.
- **Not in the kit:** native-host builds. A Mac-native hash is expected to differ (P2 report), and only the
  container hash names a capsule.

## 6. What P3 code would include, if approved

1. **`examples/photo-viewer/surface/`:** the `image-viewer` manifest and page, with node tests driving the
   page against a fake fetch. The tests cover:
   - it renders only playlist items;
   - it never requests a path;
   - it shows skipped items as text;
   - it makes no request other than the two routes.
2. **The seam in `server/api/viewer_gateway.rs`, behind Sasha's yes.** Tests with falsifiers cover:
   - no token, an expired token, a token for another viewer or another principal;
   - `order` missing or a skipped entry;
   - an item outside `Pictures/`, an item the viewer table refuses;
   - an oversize playlist, an oversize item;
   - `POST` returning 405;
   - an audit event for each refusal.
3. Nothing else: no Library table edit, no manifest schema change, no Bus change.

## Principles checked

- **3 (no ambient authority).** The surface declares no capability. Its one token is Runtime-minted,
  per-launch, non-delegatable, read-only, and unlocks two routes for one playlist.
- **4.** The surface knows Runtime routes only, no provider internals.
- **10 (one path).** One way for a surface to get image bytes: the playlist position. No path parameter, no
  second route.
- **11 (fail closed, then explain).** Each seam check refuses with a reason and an audit event.
- **13 (objects vs capsules).** Playlist and images are objects; `image-viewer` and `photo-viewer` are two
  capsules with one role each.
- **15 (trust travels with content).** Phase 2 names the core by CID and items by Runtime CIDs.
- **16 (UI is not authority).** The surface cannot launch, write or widen. Phase 2 binds the opened object in
  the signed token rather than the query.
- **18 (isolated instances).** The core is one bounded Component run per launch; the surface is one opaque
  frame.

## Roadmap milestone

2.5 (first app = photo/signage viewer). Phase 2 steps 3 to 6 are 2.3 (Bus v2 input/output). Naming by CID is
2.2. The kit item is 2.4.

## Questions for Sasha

1. **The seam.** May I build the two read routes in `server/api/viewer_gateway.rs` (section 3) for the
   spike? It is a shipping Runtime change.
2. **Binding the spike playlist.** Should Home pass the playlist object as `selected_resource` when it
   launches `image-viewer` (a small Home change), or should the seam imply the fixed path for `image-viewer`
   (no Home change, but a name-to-path rule in Runtime)? I lean to the Home change, because it is the same
   mechanism Phase 2 needs.
3. **Component plus browser directory.** A Component manifest may ship `browser/index.html`. That makes it
   both a Home frame and a Runtime-backed run from one open (sections 1.4 and 2). Is that intended? I do not
   use it; I keep two capsules.
4. **Surface name.** Use the reserved `image-viewer` name (no Library edit), or `photo-viewer-surface` with a
   Library table edit?
5. **Token lifetime.** The surface would carry the standard 12-hour token. Should a display-only surface get a
   shorter one, or one that ends when its window closes? Phase 2 step 8 wants the latter.

## Next slice

If question 1 is yes: P3 code as in section 6, with tests and falsifiers. P4 (signed bundle by CID, design
only) can go in parallel.
