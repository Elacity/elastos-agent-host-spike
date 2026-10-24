# Photo viewer capsule (core in WASM)

`photo-viewer` is an ElastOS Component (`elastos.component/v1`). It reads an
album of images by grant, checks each image from its headers, and writes a
playlist for a render-only surface. It has no display of its own, and it
imports only the `elastos:bus@v1` interfaces it uses (`types`, `runtime`,
`capabilities`, `providers`). It gets no WASI, files, sockets, clock or
environment.

This directory stays outside the ElastOS Cargo workspace and all CI, setup,
release and deployment lists, like `examples/hello`.

## What one run does

The Component ABI has no input argument and no return value
(`elastos/wit/elastos-bus-v1.wit:84-88`), so for this spike input and output
are principal-scoped objects at fixed paths. In Phase 2 the input should be
the object the person opened, bound by Runtime to this launch (P16).

| Object | Path | Grant |
| --- | --- | --- |
| Album (input) | `localhost://Users/self/.AppData/App/photo-viewer/album.json` | `read` |
| Images | `localhost://Users/self/Pictures/...` (each item) | `read`, one per image |
| Playlist (output) | `localhost://Users/self/.AppData/App/photo-viewer/playlist.json` | `write` |

`capsule.json` bounds the guest to those two prefixes (`permissions.storage`).

1. Request `read` on the album, read it whole (at most 16 KiB), and parse it:
   schema `elastos.photo-viewer.album/v1`, 1 to 64 items, each a `uri` under
   `Pictures/` and an optional `duration_ms` from 1000 to 60000 (default 5000).
   Unknown fields are refused.
2. For each item, in order, with the offset/length read window only:
   request `read`; read 32 header bytes and name the type from its magic bytes
   (PNG, JPEG, WebP); read one byte at 64 MiB to tell an oversize object; read
   the frame dimensions (at most 8192 a side and 40,000,000 pixels). PNG and
   WebP dimensions are in the 32 header bytes. For JPEG the guest walks the
   marker segments, reading 4 bytes per marker and 5 bytes of the frame header,
   and skips segment payloads (EXIF, ICC) unread, up to 32 segments.
   Image bodies are never read or hashed; Runtime is to name the bytes by CID
   (roadmap 2.2).
3. Request `write` on the playlist and write it once, as a byte array with
   `append: false`:

```json
{"album":"localhost://Users/self/.AppData/App/photo-viewer/album.json",
 "items":[{"duration_ms":5000,"height":480,"mime":"image/png","order":0,
           "uri":"localhost://Users/self/Pictures/a.png","width":640}],
 "schema":"elastos.photo-viewer.playlist/v1",
 "skipped":[{"message":"not PNG, JPEG or WebP","order":1,"reason":"wrong_type",
             "uri":"localhost://Users/self/Pictures/note.png"}]}
```

Two kinds of failure:

| Kind | Examples | Effect |
| --- | --- | --- |
| Authority | no grant; a refused or failed call; a provider error; an answer of the wrong shape; an album that is too large or malformed | The run stops before anything is written. `lifecycle.run` returns a `bus-error` naming the resource and the reason. |
| Content | wrong type, truncated or malformed header, oversize, frame too large | The item is skipped. The playlist lists it under `skipped` with its `order`, `reason` and `message`; the rest play in album order. |

## Limits

| Limit | Value | Why |
| --- | --- | --- |
| Album | 16 KiB | Read whole: Bus v1 bytes are a JSON array of numbers, about 415 fuel a byte. |
| Items | 64 | |
| Object | 64 MiB | One byte past it is read; the body is not. |
| JPEG segments before the frame | 32 | Bounds the reads per item. |

`ComponentProvider` gives every run a fixed 100,000,000 fuel
(`elastos-compute/src/providers/component.rs:28`). Fuel no longer depends on
image size (one 64-byte PNG and one 12 MiB PNG both use 257,772). The worst
album within these limits uses 59.1% of the budget (64.9% before the kit's
cheaper write); `host-test` gates it at 80%.

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
fake Runtime (the kit's `fake`, `src/tests.rs`), builds the component, runs it
inside the Runtime's own `ComponentProvider` with a fake bridge
(`host-test/`), checks its imports with a copy of the Runtime admission check,
gates the fuel of the worst albums, and runs every falsifier (`falsify.py`):
each check is broken, the mutant must compile, its test must fail, and the
file is restored.

Both fakes check request bodies the way the localhost provider does
(`elastos/capsules/localhost-provider/src/main.rs:25-48`: unknown fields
refused, write `content` is a byte array, `append` is required), which is
stricter than Runtime's own principal-root path.

Measure fuel by album shape:

```bash
(cd host-test && cargo test --locked -- --ignored --nocapture fuel_probe)
```

## Package shape

| Path | Owner |
| --- | --- |
| `capsule.json` | Identity, role, Component ABI, entrypoint, storage bounds |
| `src/lib.rs` | Run order, limits, stop and skip rules, playlist, the `lifecycle.run` export |
| `src/album.rs` | Album schema |
| `src/tests.rs` | Guest tests |
| `../capsule-kit/guest/` (path dependency `capsule-kit-guest`) | The two Bus calls and answer parsing, the write, the refusals and reads, the URI check, the image header checks (magic bytes, PNG and WebP headers, ranged JPEG walk), the fake Runtime and the WIT glue, shared with the documents viewer |
| `host-test/` | The component in `ComponentProvider`, admission check, fuel gate |
| `falsify.py` | Break each check and see its test fail |
