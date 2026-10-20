# P1 report: photo viewer core in WASM

Slice P1. Code in `examples/photo-viewer/` (see its `README.md`). No file under `elastos/`, `capsules/`,
`templates/` or `examples/agent-host/` changed. No shipping Runtime change.

Branch `claude/photo-p1`, stacked on `claude/photo-p0` (P0's draft PR is not merged yet, and both add a line
to `LOG.md`).

## What was built

- A Component guest that reads an album object by grant, then each image it names by its own grant, checks
  magic bytes (PNG, JPEG, WebP), object size, and frame dimensions, hashes the bytes (SHA-256), and writes one
  playlist object by a write grant. Any refusal stops the run before anything is written and returns a
  `bus-error` that names the item and the reason.
- The logic sits behind a two-call `Bus` trait (`src/bus.rs`). On wasm32 it is the `elastos:bus@v1` imports;
  in tests it is a fake Runtime (`src/fake.rs`) that mirrors the bridge's grant check
  (`elastos-server/src/resource_bridge.rs:364-409`), read window (`594-604`) and answer shape (`503-524`).
- A host harness (`host-test/`) that runs the built component inside the Runtime's own `ComponentProvider`
  (`elastos-compute/src/providers/component.rs`: Wasmtime 36, fuel and memory limits) with a fake bridge
  behind the real hostcall, plus a copy of the Runtime's import admission check
  (`elastos-server/src/component.rs:14-136`) and a fuel gate.
- `falsify.py`: breaks each refusal, requires its test to fail, restores the file.

## Decisions taken by default (P0 questions not yet answered)

| P0 question | Default taken | Why |
|---|---|---|
| 1. I/O as objects | Album and playlist at fixed paths under `localhost://Users/self/.AppData/App/photo-viewer/` | No Bus ABI change; `lifecycle.run` has no input or output (`elastos-bus-v1.wit:84-88`). |
| 4. Test pattern | Read `spike/agent-host` (read only); used the fake-hostcall pattern from `component.rs:438-486` | `examples/agent-host` keeps logic as plain Rust tested natively; it calls no provider, so P1 adds a Bus trait and a fake. |
| 5. Album URIs | `localhost://Users/self/Pictures/...`, not `elastos://object/...` | An `elastos://object` grant names only the operation: the capability resource is `elastos://object/read` for every object (`elastos-server/src/provider_resource.rs:82`, `332-335`, `394`). A `localhost` grant names the path (`provider_resource.rs:337-353`), so each image gets its own grant (P3). KICKOFF said `elastos://object`; this is the one place I departed from it. |

All three are constants in `src/lib.rs`; changing them does not touch the checks.

## Tests run and results

`export RUST_TEST_THREADS=2`, then `examples/photo-viewer/verify.sh` (passes end to end, about 60 s warm):

| Suite | Result |
|---|---|
| Guest tests (`cargo test --locked`), fake Runtime | 28 passed |
| Guest `cargo fmt --check`, `cargo clippy --all-targets -D warnings` | clean |
| Build with `scripts/build-component-capsule.sh` | ok |
| Host harness (`host-test`), component in `ComponentProvider` | 12 passed, 1 ignored (the fuel probe, a measurement) |
| Host `cargo fmt --check`, `cargo clippy --all-targets -D warnings` | clean |
| `falsify.py --runtime` | 13 of 13 caught |
| `node scripts/check-capsule-templates.mjs`, `check-elastos-bus-wit.mjs`, `check-first-party-wasi-gate.mjs` | PASS |
| `git diff --check` | clean |

Refusals covered, each in the guest suite and the main ones again through `ComponentProvider`:
no grant (album read, image read, playlist write, read grant used for write), wrong type (GIF, text, WAVE,
zeros; only the 32-byte header is read), truncated header (partial magic for each type; cut before the size
field for PNG, JPEG, WebP VP8X and VP8L), malformed header (zero width or height, no IHDR, JPEG scan before
frame), oversize (only the header and one byte past the limit are read; an exact fit plays), frame limits at
the boundary (8192 a side, 40,000,000 pixels), album body budget, bad album (16 shapes, including `..`,
another principal, `elastos://` URI, unknown fields, duration range), provider error answer (also one that
carries data), answers without byte content, and a read answer longer than asked.

## Falsifiers

Each one replaces one exact line, runs the named test, requires it to fail, and restores the saved bytes
(`sha256sum -c` of `src/*.rs` after the run: all OK; component hash back to the value below).

| Falsifier | Caught by |
|---|---|
| album read without a grant | `album_without_a_read_grant_is_denied_before_any_read` |
| image read without a grant | `image_without_a_read_grant_is_denied_before_any_read_of_it` |
| playlist write without a grant | `playlist_without_a_write_grant_is_denied_and_not_written` |
| wrong type accepted as PNG | `wrong_type_is_refused_and_the_body_is_not_read` |
| truncated magic treated as unknown | `truncated_magic_is_refused` |
| size checked only after reading the body | `oversize_is_refused_without_reading_the_body` |
| side limit removed | `dimension_limits_are_enforced_at_the_boundary` |
| album body budget not spent | `album_whose_images_exceed_the_body_budget_is_refused_at_the_item_that_crosses_it` |
| provider status ignored | `an_error_answer_that_also_carries_data_is_still_an_error` |
| unknown album fields allowed | `malformed_albums_are_refused_before_any_image_is_read` |
| `..` segments allowed | `malformed_albums_are_refused_before_any_image_is_read` |
| wrong type accepted, built into the component | `wrong_type_is_refused_through_the_runtime` (host-test) |
| image read without a grant, built into the component | `no_grant_is_denied_through_the_runtime` (host-test) |

The first run missed "provider status ignored": the old test's error answer had no `data`, so the status
check was never the only guard. I added the error-with-data test; it now catches it.

## Guest hash and import list

- `photo-viewer.component.wasm` sha256 `9cf6874985454b5be310a68ea28493d8b3cac6a7a914d5831c4500bb3d17bade`,
  221,286 bytes. Built here (Linux x86_64 cloud container, Rust 1.91.0 from `rust-toolchain.toml`) with
  `scripts/build-component-capsule.sh`; the same hash on every rebuild here. Cross-machine sameness is P2.
- Imports: `elastos:bus/types@1.0.0`, `elastos:bus/runtime@1.0.0`, `elastos:bus/capabilities@1.0.0`,
  `elastos:bus/providers@1.0.0`. No `identity` (not used), no WASI. Export: `elastos:bus/lifecycle@1.0.0`.
  Passes the copied Runtime admission check.
- Guest dependencies (`Cargo.lock`): `wit-bindgen 0.57.1`, `serde 1.0.229` (no derive), `serde_json 1.0.154`,
  `sha2 0.10.9` (no default features). No new proc-macro beyond `wit-bindgen`'s.

## Findings

1. **Fuel bounds what a guest can read on Bus v1.** Read content crosses the Bus as a JSON array of numbers.
   Measured in `host-test` (`fuel_probe`), with the same engine config and store limits as `ComponentProvider`:

   | Guest version | Fuel per image byte |
   |---|---|
   | First (`serde_json::Value` per byte, `opt-level = "s"`) | about 1,040 |
   | `opt-level = 3` | about 850 |
   | One-pass typed parse into `Vec<u8>` (current) | about 415 |

   `ComponentProvider` fixes 100,000,000 fuel per run (`component.rs:28`), so at most about 235 KiB of image
   bytes fit in one run. I did not measure SHA-256's share separately. The guest therefore caps one object at
   128 KiB and the whole album at 128 KiB of image bytes; `host-test` gates the worst albums (one 128 KiB
   image: 54.5%; 64 images of 2 KiB: 63.7% of the budget) and runs them in `ComponentProvider`. Real photos
   (2-10 MB) do not fit. See question 1.
2. **A trapped run loses its cause.** `ComponentProvider` formats the Wasmtime error with `{err}`
   (`component.rs:134`), which prints the backtrace context but not the root cause (for example "all fuel
   consumed"). A fuel-exhausted run reads as `Component lifecycle run failed: error while executing at wasm
   backtrace: ...`. That is P11 (explain the failure). I did not change it.
3. **`elastos://object` grants are not object-scoped** (decision 5 above). A component granted
   `elastos://object/read` can read any object the provider serves. I did not test this against a live
   Runtime.
4. **Read answer shape is verified only for Runtime-handled principal roots.** When a principal root is not
   protected, Runtime hands the read to the localhost provider (`resource_bridge.rs:485-487`). I matched that
   answer to the `content` byte array used elsewhere (`elastos-server/src/library.rs:2905-2907`), but cloud
   has no Home, so neither path ran against a live Runtime.

## Principles checked

- **3 (no ambient authority).** Bus-only imports, four of five interfaces. One grant per object and action;
  a read grant is not a write grant (tested). Manifest bounds are two prefixes. The fake refuses an invoke
  without the matching grant, and tests show the guest stops before invoking.
- **10 (one path).** One input path, one output path, one read contract. No fallback between URI schemes or
  answer encodings.
- **11 (fail closed, then explain).** Every refusal stops before the write and names the item, the resource
  and the limit. The fuel budget is enforced by the guest, so a large album gets a reason, not a trap.
  Finding 2 is the Runtime-side gap.
- **13 (objects vs capsules).** Album, images and playlist are the person's objects; the capsule is the
  component.
- **15 (trust travels with content).** Each playlist entry carries the SHA-256 and size of the exact bytes
  that were checked. Naming by CID is not there yet (finding 1, question 1).
- **16 (UI is not authority).** No surface exists yet; the playlist is data for P3, and the guest has no UI.
- **18 (isolated instances).** One bounded activation in `ComponentProvider`, inside its fuel and memory
  limits, with no resident state.

## Roadmap milestone

2.5 (first app = photo/signage viewer), proven on Bus v1. Finding 1 is evidence for 2.1 (Wasmtime 48 and
limits) and 2.3 (Bus v2: binary bodies). The grant-per-path choice and finding 3 feed 2.7 (confine providers).

## Questions for Sasha

1. **Real photo sizes.** Which way?
   - (a) Runtime gives a component an object's size and content hash, and the guest reads only header
     windows. This needs a shipping change: a Runtime-handled `stat` with a hash.
   - (b) Manifest-declared fuel under 2.1.
   - (c) Binary Bus bodies under 2.3.
   - (d) Keep the small caps for the spike.

   With (a) the guest stays the same and only `MAX_*` and the hash source change.
2. Is `localhost://Users/self/Pictures/...` with a grant per object right for album items, instead of
   KICKOFF's `elastos://object`? Should finding 3 be filed outside the spike?
3. Is the P0 default for I/O OK: album and playlist at fixed app-data paths?
4. May I fix finding 2? It is a one-line shipping change in `component.rs:134`, adding the root cause.
5. Should one bad item refuse the whole album (current: fail closed), or should the playlist skip it and
   list the reason?

## Next slice

P2, reproducible build: build `photo-viewer.component.wasm` in one pinned Linux container and get the same
sha256 on Mac and in cloud (today's value is above). P3 waits for answers to questions 1 and 3.
