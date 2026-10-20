# Photo viewer capsule (slice P1: core in WASM)

`photo-viewer` is an ElastOS Component (`elastos.component/v1`). It reads an
album of images by grant, checks each one, and writes a playlist for a
render-only surface. It has no display of its own, and it imports only the
`elastos:bus@v1` interfaces it uses (`types`, `runtime`, `capabilities`,
`providers`). It gets no WASI, files, sockets, clock or environment.

This directory stays outside the ElastOS Cargo workspace and all CI, setup,
release and deployment lists, like `examples/hello`.

## What one run does

The Component ABI has no input argument and no return value
(`elastos/wit/elastos-bus-v1.wit:84-88`), so input and output are
principal-scoped objects at fixed paths:

| Object | Path | Grant |
| --- | --- | --- |
| Album (input) | `localhost://Users/self/.AppData/App/photo-viewer/album.json` | `read` |
| Images | `localhost://Users/self/Pictures/...` (each item) | `read`, one per image |
| Playlist (output) | `localhost://Users/self/.AppData/App/photo-viewer/playlist.json` | `write` |

`capsule.json` bounds the guest to those two prefixes (`permissions.storage`).

1. Request `read` on the album, read it (at most 64 KiB), and parse it:
   schema `elastos.photo-viewer.album/v1`, 1 to 64 items, each a `uri` under
   `Pictures/` and an optional `duration_ms` from 1000 to 60000 (default 5000).
   Unknown fields are refused.
2. For each item, in order: request `read`; read 32 header bytes and name the
   type from its magic bytes (PNG, JPEG, WebP); check that byte 128 KiB does
   not exist; read the body in 32 KiB windows; read the frame dimensions
   (at most 8192 a side and 40,000,000 pixels); hash the bytes with SHA-256.
3. Request `write` on the playlist and write it once:

```json
{"album":"localhost://Users/self/.AppData/App/photo-viewer/album.json",
 "items":[{"bytes":2048,"duration_ms":5000,"height":480,"mime":"image/png",
           "order":0,"sha256":"a6a0…1b43","uri":"localhost://Users/self/Pictures/a.png","width":640}],
 "schema":"elastos.photo-viewer.playlist/v1"}
```

Any refusal stops the run before the playlist is written. `lifecycle.run`
then returns a `bus-error` that names the item and the reason: `denied` for a
missing grant, `invalid` for a bad album, wrong type, truncated or malformed
header, oversize object, too-large frame, or album body budget.

## Limits and why they are small

| Limit | Value |
| --- | --- |
| Object | 128 KiB |
| Image bytes per run (album body budget) | 128 KiB |
| Items | 64 |
| Album | 64 KiB |

Bus v1 carries read content as a JSON array of numbers, and the guest parses
and hashes it at about 415 fuel a byte. `ComponentProvider` gives every run a
fixed 100,000,000 fuel (`elastos-compute/src/providers/component.rs:28`), and
when that runs out it reports the trap without its cause
(`component.rs:134`). The body budget keeps the worst album at 64% of that fuel,
so the guest refuses with a reason rather than trapping. Real photos (2-10 MB)
do not fit; see `handoff/P1-REPORT.md`.

## Build

```bash
rustup target add wasm32-unknown-unknown
./build.sh
```

## Verify

```bash
./verify.sh
```

It checks the manifest against the WIT hash, runs the guest tests against a
fake Runtime (`src/fake.rs`, `src/tests.rs`), builds the component, runs it
inside the Runtime's own `ComponentProvider` with a fake bridge
(`host-test/`), checks its imports with a copy of the Runtime admission check,
gates the fuel of the worst albums, and runs every falsifier (`falsify.py`):
each refusal is broken, its test must fail, and the file is restored.

Measure fuel by object size:

```bash
(cd host-test && cargo test --locked -- --ignored --nocapture fuel_probe)
```

## Package shape

| Path | Owner |
| --- | --- |
| `capsule.json` | Identity, role, Component ABI, entrypoint, storage bounds |
| `src/lib.rs` | Run order, limits, refusals, playlist, WIT glue |
| `src/album.rs` | Album schema |
| `src/image.rs` | Magic bytes and frame dimensions |
| `src/bus.rs` | The two Bus calls behind a trait, and answer parsing |
| `src/fake.rs`, `src/tests.rs` | Fake Runtime and guest tests |
| `host-test/` | The component in `ComponentProvider`, admission check, fuel gate |
| `falsify.py` | Break each refusal and see its test fail |
