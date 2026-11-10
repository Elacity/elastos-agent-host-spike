# P0 Map: viewer choice, Component launch and output, and a path to a render-only surface

Slice P0, no code. Base `spike/photo-viewer` 6fd0756 (develop 3beb8164 plus handoff). Every claim cites
`file:line` on that base. Paths under `elastos/crates/` are shortened to the crate name
(`elastos-server/src/library.rs` means `elastos/crates/elastos-server/src/library.rs`). A bare `component.rs`
means `elastos-compute/src/providers/component.rs` unless the same sentence names `elastos-server/src/component.rs`.

## 1. How a viewer is chosen for a Library object today

Short answer: by a hard-coded table from file extension to viewer **name**. `interfaces[].methods[].input_schema.accepts`
does not take part in the choice.

1. The Library server adds `viewer` and `viewers` to every object it returns (`elastos-server/src/library.rs:60-62`).
   For a file it calls `viewer_options_for_name(data_dir, &name)` (`library.rs:3030-3035`; also `library.rs:3534`,
   `library.rs:4206`).
2. `viewer_ids_for_name` maps lower-case extensions to fixed names (`library.rs:7086-7107`):
   archive families → `archive-manager`, `.md`/`.txt`/`.pdf` → `documents`, `.png`/`.jpg`/`.jpeg`/`.gif` →
   `image-viewer`, `.mp4` → `video-viewer`, `.gba` → `gba-emulator`, else none. `.webp` is not in the table.
3. `installed_viewer_option` keeps a name only if an installed, active capsule with that exact name and
   `role == viewer` is in `list_launchable_browser_capsules` (`library.rs:7109-7119`). Every option is marked
   `default: true` (`library.rs:7117`); labels are a second hard-coded table (`library.rs:7121-7130`).
4. "Launchable browser capsule" means shell-launchable role (`elastos-common/src/manifest.rs:1142-1144`,
   checked at `elastos-server/src/api/browser_capsules.rs:427`) **and** a `browser/index.html` on disk (or an
   `.html` data entrypoint) (`browser_capsules.rs:635-660`). A Component capsule with only a `.component.wasm`
   entrypoint can therefore never be offered as a Library viewer today.
5. No `image-viewer` or `video-viewer` capsule exists in `capsules/` (only references are `library.rs:7097`,
   `7099`, `7124`, `7125`). So images get no viewer and fall through to the Library's own inline preview.
6. Library client: on open, it tries archive, protected video, then `viewerOptions(object)[0]`, then inline preview,
   else "No installed app can open this item." (`capsules/library/browser/src/actions.js:85-97`). `viewerOptions`
   is just `object.viewers` (`capsules/library/browser/src/model.js:83-85`); images preview because `mime`
   starts with `image/` (`model.js:142`). Opening a viewer posts `home:open-target` with
   `{objectUri, uri, name, mime, contentCid?}` (`actions.js:115-134`, `capsules/library/browser/src/api.js:234-236`),
   or `home:open-uri` with `elastos://<cid>` for published objects (`actions.js:117-120`, `api.js:238-240`).
7. Where `accepts` is read: the contract audit, only for content-capsule binding checks
   (`elastos-server/src/api/gateway_capsule_catalog/contract_audit.rs:553-577`), and Marketplace, to show supported
   extensions (`capsules/marketplace/browser/marketplace.js:572-580`). Examples of declarations:
   `capsules/documents/capsule.json:30-38`, `capsules/archive-manager/capsule.json:30-37`,
   `capsules/gba-emulator/capsule.json:30-37`.
8. Content capsules are bound to a viewer by its **name** (`"viewer": "gba-emulator"`,
   `capsules/gba-emulator/capsule.json:37`; lookup `browser_capsules.rs:455-467`), not by CID.
9. What a viewer may then read: the viewer gateway re-checks that the object's `viewers` list (the same extension
   table) contains this viewer (`elastos-server/src/api/viewer_gateway.rs:613-628`, called at `443` and `554`),
   after a Home launch-token check (`viewer_gateway.rs:630-640`, `691-709`). A `raw=1` read returns the object
   bytes to any viewer that passes the check (`viewer_gateway.rs:173-192`, `545-570`); non-raw reads return
   metadata only unless the viewer is `documents` (`viewer_gateway.rs:473-475`). Route:
   `/api/viewers/:viewer/library-object` (`elastos-server/src/api/gateway.rs:1212-1216`). In the code I read, the
   `uri` comes from the query string (`viewer_gateway.rs:181`, `199`); I did not find it bound to the one object the
   user opened. See question 3.

## 2. How a Component capsule is launched and what it returns

### Contract

- WIT world `product-capsule-v1` imports `runtime`, `identity`, `capabilities`, `providers` and exports
  `lifecycle` (`elastos/wit/elastos-bus-v1.wit:90-96`).
- `lifecycle.run: func() -> result<_, bus-error>` (`elastos-bus-v1.wit:84-88`): **no input and no output value**.
  The only results are "ok" or a `bus-error` variant (`elastos-bus-v1.wit:50-57`).
- `providers.invoke` takes `{resource, operation, body: bytes, grant}` and returns `{status, body, audit}`
  (`elastos-bus-v1.wit:37-48`, `78-82`). `capabilities.request` returns a grant id
  (`elastos-bus-v1.wit:24-35`, `72-76`).

### Guest side

- `elastos-guest` generates the same world with `wit_bindgen` behind the `component-bindings` feature on wasm32
  (`elastos-guest/src/component.rs:8-15`, `elastos-guest/src/lib.rs:35-37`, `elastos-guest/Cargo.toml:17-20`).
  `elastos-guest/src/bus.rs:15-83` holds serde shapes that mirror the WIT records and build the Runtime bridge
  envelope. Its `CapsuleInfo::from_env` and `log!` macros (`lib.rs:63-133`) rely on env and stdout, which a
  Component does not get; they are not usable from a Component.
- The template and the example each generate their own bindings straight from the WIT and export
  `lifecycle::Guest::run` (`templates/capsules/component-app/src/lib.rs:1-16`, `examples/hello/src/lib.rs:7-44`).
  Neither uses `elastos-guest` as a dependency (`templates/capsules/component-app/Cargo.toml:10-11`,
  `examples/hello/Cargo.toml:11-12`). Both only read `runtime.info` and `identity.context` and return `Ok(())`.
- Manifest shape: `role: app`, `type: wasm`, `runtime_abi: elastos.component/v1`, `bus_contract: elastos:bus@v1`,
  `wit_world_sha256`, `execution: component`, `projections: ["facts"]`
  (`templates/capsules/component-app/capsule.json:7-14`, `examples/hello/capsule.json:7-14`).
- Build: `examples/hello/build.sh:1-6` calls `scripts/build-component-capsule.sh` (locked deps, isolated target,
  path remapping per `docs/CAPSULE_AUTHORING.md:235-243`).
- `examples/hello/README.md:72-74`: "The Component ABI has no stdout function." The visible result is printed by
  the host.

### Host side, step by step

1. CLI `elastos run <dir>`: a `type: wasm` manifest must be a Component (`elastos-server/src/run_cmd.rs:51-59`) and
   goes to `run_component_via_operator_runtime` (`run_cmd.rs:225-270`). That attaches to the operator Runtime
   (`run_cmd.rs:230`, `237`), builds a local `Runtime`, and installs a hostcall that forwards each Bus line over HTTP
   to the operator (`run_cmd.rs:243-260`, `handle_remote_request_with_audit_dir`). It prints only
   `"[run] Component capsule '<name>' exited"` (`run_cmd.rs:268`).
2. In-process paths: `serve` with a WASM capsule (`elastos-server/src/serve_cmd.rs:265-284`) and the shell-only
   `POST /api/capsules` (`elastos-server/src/api/server.rs:461-466` → `elastos-server/src/api/routes.rs:80-118`).
   The API answers only `{id, name, status: "completed"}` for a Component (`routes.rs:99-114`). In process, the
   hostcall is set in `Runtime::set_provider_registry` and calls `handle_component_resource_request` directly
   (`elastos-server/src/runtime.rs:105-135`).
3. `Runtime::run_local_with_principal` (`runtime.rs:237-329`): parse and validate manifest (`258-261`), reject
   escaping entrypoints (`263-270`), provider dependencies (`279`), **signature check** (`282`), Component import
   allowlist (`283`; allowlist `elastos-server/src/component.rs:6-12`, forbidden markers `component.rs:14-30`,
   walk `component.rs:50-115`), pick `ComponentProvider` (`runtime.rs:159-168`, `286`), load (`298`), record the
   manifest's authority bounds `capabilities` + `permissions.storage` for this instance (`runtime.rs:299-304`;
   `elastos-common/src/manifest.rs:424-429`), bind principal (`runtime.rs:305-311`), start (`317`), clear (`318-325`).
   `handle.args` is set (`runtime.rs:314`) but `ComponentProvider` never reads it (`load` returns empty args at
   `elastos-compute/src/providers/component.rs:180-184`; `start` at `187-221` does not use them).
4. `ComponentProvider` (`elastos-compute/src/providers/component.rs`): accepts only `elastos.component/v1`
   (`149-154`, `99-101`); compiles (`164-167`); id `component-<uuid>` (`168`). `start` runs one bounded activation on
   a blocking thread (`212-216`) and removes the instance afterwards (`218`): fuel 100,000,000 (`28`, `120-122`),
   128 MiB memory, 16 instances, 32 tables, 4 memories (`29`, `89-97`). It links only the Bus world (`124-126`) and
   calls `lifecycle.run` (`131-135`). There is no resident stop (`223-238`).
5. Bus calls cross one synchronous hostcall `Fn(line, capsule_id, principal_id) -> String`
   (`elastos-compute/src/providers/mod.rs:9-11`; `component.rs:305-325`). `identity.context` returns
   `session == capsule` == the activation id (`component.rs:338-347`). `capabilities.request` allows exactly one
   action (`component.rs:355-359`). `providers.invoke` requires a JSON body (`component.rs:294-303`, `389`) and
   returns the provider result re-encoded as JSON bytes plus the audit id (`component.rs:396-414`).
6. Runtime bridge (`elastos-server/src/resource_bridge.rs`): frames above 1 MiB are refused (`32`, `747-749`).
   `request_capability`: scheme check (`772-781`), system-backend refusal (`782-791`), current-user alias scoping
   (`792-805`), manifest bound (`830-839`), then a pending request that the shell grants or denies, polled every
   100 ms up to 300 times (`30-31`, `842-900`). `resource_invoke`: audit "requested" (`344-348`), manifest bound
   (`350-362`), token required (`364-375`) and validated against capsule, action and resource (`377-409`),
   principal-root `localhost://Users/...` read/write handled in Runtime (`411-423`, `571-581`), else dispatched to
   the provider registry (`425-455`). A `read` supports an offset/length window (`594-604`), useful for header-only
   magic-byte checks in P1.

### What "returns output" means today

A Component has exactly one way to get anything out: an **effect** through `providers.invoke` with a grant, which
Runtime bounds by the manifest, validates, and audits (point 6 above). The activation itself returns only success
or a `bus-error`, which Runtime turns into `"Component capsule denied: ..."` (`component.rs:135`). There is no
return value, no stdout, and no input argument.

## 3. Smallest path from Component output to a render-only surface

### Gaps on today's code

| Gap | Evidence |
|---|---|
| No input to the activation | `lifecycle.run` takes nothing (`elastos-bus-v1.wit:87`); args ignored (`component.rs:180-184`). |
| No output value | `result<_, bus-error>` (`elastos-bus-v1.wit:87`); API returns status only (`routes.rs:99-114`). |
| A Component cannot be a Library viewer | Needs `browser/index.html` (`browser_capsules.rs:649-657`) and a name in the extension table (`library.rs:7086-7107`). |
| A viewer cannot read a JSON result object | Viewer reads are gated by the extension table (`viewer_gateway.rs:613-628`); `.json` maps to no viewer (`library.rs:7104-7105`). |
| Nothing but the shell can launch a Component | `POST /api/capsules` is shell-only (`server.rs:461-466`). This is correct (P16) and should stay. |

### Recommended design (no Bus ABI change)

Hand input and output across the Bus as **principal-scoped objects**, and let Runtime, not the surface, launch the
Component and bind the result to one surface.

1. **Input.** The album is a principal-scoped object, e.g.
   `localhost://Users/self/.AppData/App/photo-viewer/album.json`, listing `elastos://object` URIs. The manifest
   declares that prefix in `permissions.storage` (bounds at `manifest.rs:424-429`, enforced at
   `resource_bridge.rs:253-270`, `830-839`, `350-362`).
2. **Run.** The Component requests `read` on the album and on each image, reads headers with an offset/length
   window (`resource_bridge.rs:594-604`), checks magic bytes, size and dimension caps, and fails closed with a
   `bus-error` on any refusal.
3. **Output.** It `write`s `playlist.json` (order, duration, width, height, object CID/hash) to the same
   principal-scoped prefix under a `write` grant. Runtime handles that path itself (`resource_bridge.rs:411-423`,
   `571-581`) and audits it (`344-348`).
4. **Surface.** A web-projection viewer with `browser/index.html` and no capabilities of its own. It reads only:
   (a) the one `playlist.json` that Runtime bound to its launch, and (b) raw bytes of the objects named in that
   playlist, through the existing raw viewer read (`viewer_gateway.rs:173-192`). It renders `<img>` from those
   bytes and nothing else: no writes, no capability requests, no network.

What this needs:

- **P1 needs no shipping change.** Host tests drive the Component with a fake hostcall that serves album and image
  bytes and captures the `write` line, the same pattern as `elastos-compute/src/providers/component.rs:438-486`. That proves the core: grant
  refusal, wrong type, oversize, truncated header.
- **P3 needs exactly one new Runtime seam**, and that is for Sasha to decide: a narrow viewer-gateway read that lets
  viewer X read only its own app-data result object (the playlist), plus the Library mapping for the image
  extensions (adding `.webp`). The `image-viewer` name is already reserved in `library.rs:7097` and `7124`, so
  naming the surface `image-viewer` would light up the existing table entry without editing it. Both touch
  shipping Runtime files (`viewer_gateway.rs`, `library.rs`), so P3 stays design-only until Sasha says yes.

### Options I considered and do not recommend now

- **Change the WIT** to `run: func(input: bytes) -> result<bytes, bus-error>`. Cleanest data flow, but it changes
  `elastos-bus-v1.wit`, its pinned hash (`templates/capsules/component-app/capsule.json:11`) and the Bus contract.
  That is roadmap 2.3 (Bus v2) work, not a Bus v1 spike.
- **Write the playlist as `.txt` or `.md`** so `documents` can read it. It passes today's gate
  (`library.rs:7090-7091`), but it lies about the type and adds a hidden alternate path (P10, P12).
- **Let the surface launch the Component.** That gives a UI launch authority (P16); `/api/capsules` is
  shell-only for good reason (`server.rs:461-466`).

## 4. Principles checked

- **3 (no ambient authority).** Bus-only imports are enforced at load (`elastos-server/src/component.rs:6-30`); no WASI/env/stdout. The design keeps every read and write under a grant and manifest bound.
- **10 (one path).** One output path, the audited principal-object write; the `.txt` workaround is rejected.
- **11 (fail closed).** Refusals return `bus-error` and Runtime surfaces them (`component.rs:135`).
- **13 (objects vs capsules).** Album and playlist are user objects; the Component and the surface are capsules.
- **15 (trust travels with content).** The playlist carries object CID/hash. Viewer binding by name (`gba-emulator/capsule.json:37`) is a known gap (roadmap 2.2).
- **16 (UI is not authority).** The surface holds no capability, cannot launch, and reads only what Runtime bound to it.
- **18 (isolated instances).** One bounded activation with fuel and memory limits (`component.rs:28-29`, `89-97`, `212-218`).

## 5. Roadmap milestone

2.5 (first app = photo/signage viewer), proven early on Bus v1. The input/output gap is evidence for 2.3 (Bus v2).
Name-based viewer binding (`library.rs:7086-7119`, `browser_capsules.rs:455-467`) is evidence for 2.2.

## 6. Questions for Sasha

1. Is "input and output as principal-scoped objects" acceptable on Bus v1, or do you want the WIT input/output
   change folded into the Bus v2 plan instead?
2. For P3, may the render-only surface use the reserved `image-viewer` name (`library.rs:7097`), or should it be a
   new `photo-viewer` viewer name (needs a `library.rs` table edit)?
3. Viewer gateway: in the code I read, `/api/viewers/:viewer/library-object?raw=1` takes `uri` from the query, and
   the only object check is the extension table (`viewer_gateway.rs:181`, `613-628`). Is a viewer meant to be able to
   read any object of its extension class, or only the one the user opened? If only the opened one, this looks like
   a finding to file separately, outside this spike.
4. KICKOFF says "host tests with fakes, like `examples/agent-host`", but that directory is not on this branch.
   Should P1 copy the fake-hostcall pattern from `elastos-compute/src/providers/component.rs:438-486`, or should I read it from the other spike
   branch (read only)?
5. Album source: should P1 take `elastos://object/...` URIs (object-provider, `capsules/object-provider/capsule.json:11`)
   or principal-root `localhost://Users/self/...` paths (handled in Runtime, `resource_bridge.rs:571-581`)?
   They take different grant paths.

## 7. Next slice

P1, core in WASM: a standalone Component under `examples/photo-viewer/` (outside the Cargo workspace, like
`examples/hello`) that reads an album and its images by grant, checks magic bytes (PNG, JPEG, WebP), size and
dimension caps, and writes a playlist. Host tests with a fake hostcall; refusals and falsifiers for no grant, wrong
type, oversize, and truncated header. Report the guest hash and import list.
