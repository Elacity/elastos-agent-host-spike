# P1b report: headers only, and skip vs stop

Slice P1b, after the review of P0 and P1 (both PASS). It applies Sasha's answers 1, 2, 3 and 5. Answer 4 (the
`component.rs:134` fix) is its own PR next. Code in `examples/photo-viewer/`; no file outside it changed. No
shipping Runtime change.

Branch `claude/photo-p1b`, stacked on `claude/photo-p1`, which is stacked on `claude/photo-p0`.

## Answer 1: headers only, through the read window

### Does the unprotected localhost-provider path honor offset/length and stat?

When a principal root is not protected, Runtime hands the request to the provider registry
(`elastos-server/src/resource_bridge.rs:485-487`). `localhost` there is the native `localhost-provider`
(`elastos-server/src/server_infra.rs:769-808`), source `elastos/capsules/localhost-provider/src/main.rs`.

| Question | Answer | Evidence (`localhost-provider/src/main.rs`) |
|---|---|---|
| Is offset/length honored? | Yes, with the same results as Runtime's `apply_read_window`. | `403-476`. Plaintext roots seek and read once (`457-475`). Encrypted roots read and decrypt the whole file, then window it (`443-454`). Only `MyWebSite` and `Public` are plaintext (`elastos-common/src/localhost.rs:103-105`), so a `Pictures` window costs one full read and decrypt on the host per call. That is host time, not guest fuel. |
| Does the answer have the same shape? | Yes: `{"status":"ok","data":{"content":[bytes],"size":n}}`. | `92-100`, `783-807` |
| Is stat honored? | Yes, but its `size` is the size on disk: the encrypted envelope for encrypted roots, not the image. Runtime's protected-root path has no stat at all (it handles only `read` and `write`, `resource_bridge.rs:571-573`). | `602-630`, `740-750` |
| What does the provider accept? | `deny_unknown_fields`. `read` takes `path`, `token`, `encoding`, `offset`, `length`. `write` needs `content` as a byte array and an `append` with no default. | `25-48` |

What the guest does with that:

- **Size.** It never uses stat. One byte read at the 64 MiB limit tells an oversize object, with the same
  result on both paths.
- **Read length.** It always names a `length`. Without one the provider computes `file_size - offset` as a
  `u64` (`434`, `468`), which underflows when the offset is past the end.
- **Playlist write.** It is now a byte array with `append: false`. **P1's write would have failed on this
  path:** it sent `content` as a string with no `append`. That works on Runtime's protected-root path
  (`resource_bridge.rs:583-592`), but this provider refuses it. Both fakes now check bodies the way the
  provider does, and a falsifier puts the P1 shape back and is caught.
- **For Sasha, not filed (same handling as the private findings).** The plaintext read allocates
  `vec![0; length]` with a length the caller chooses (`432-437`, `466-471`). Any component with a read grant
  can make the provider allocate as much as it asks for. This guest asks for at most 32 bytes per read
  (8 KiB for the album).

### What changed in the guest

- **No body read, no hash.** The playlist has no `sha256` and no `bytes` field; Runtime is to name the bytes by
  CID (2.2). `sha2` is gone from both crates.
- **PNG and WebP** dimensions come from the 32 header bytes.
- **JPEG** is walked with ranged reads: 4 bytes per marker and 5 bytes of the frame header. Payloads such as
  EXIF and ICC are skipped unread, up to 32 segments. A 12 MiB JPEG with its frame header after 105 KB of
  EXIF and ICC plays after **49 bytes** read (host-test `a_photo_sized_jpeg_plays_from_its_headers`).
- **Caps.** Object 64 MiB, checked with one byte past it. The album body budget is gone. The album, the one
  object still read whole, drops from 64 KiB to 16 KiB because its bytes cost about 415 fuel each.
- **Fuel** (host-test `fuel_probe`, same engine config and limits as `ComponentProvider`):

  | Album | Fuel | Share of the 100M budget |
  |---|---|---|
  | One 64-byte PNG | 257,772 | 0.3% |
  | One 12 MiB PNG | 257,772 | 0.3% |
  | One JPEG walking 31 segments | 804,655 | 0.8% |
  | 64 PNGs | 8,458,699 | 8.5% |
  | 64 JPEGs, 31 segments each, album near its 16 KiB cap (worst case) | 64,893,683 | 64.9% |

  The gate is 80%.

## Answer 2: `localhost://Users/self/Pictures/...`, one grant per image

Kept as in P1. `each_object_is_read_with_the_grant_issued_for_it` checks the order of the requests.

## Answer 3: fixed paths for the spike

Kept. Noted in `README.md` and here: in Phase 2 the input should be the object the person opened, bound by
Runtime to this launch (P16). A fixed path the component reads on its own is not that.

## Answer 5: authority failures stop the run, content failures skip the item

| Kind | Failures | Effect | Tests |
|---|---|---|---|
| Authority | No grant (album, image, playlist; a read grant used for a write), a refused invoke, a provider error answer (also one carrying data), a missing object, an answer of the wrong shape, an album too large or malformed (16 shapes) | Stops before any write. `lifecycle.run` returns `denied`, `unavailable`, `internal` or `invalid`, naming the resource. Later items are not touched. | `album_without_a_read_grant_stops_before_any_read`, `image_without_a_read_grant_stops_the_run_and_is_not_skipped`, `a_provider_error_stops_the_run_and_is_not_skipped`, and 10 more; host-test `no_grant_stops_the_run_through_the_runtime`, `provider_error_stops_the_run_through_the_runtime`, `write_without_grant_is_denied_through_the_runtime` |
| Content | Wrong type, truncated header, malformed header (zero size, no IHDR, scan before frame, too many JPEG segments), oversize, frame too large | The item is skipped. The playlist lists it under `skipped` with `order`, `reason` (`wrong_type`, `truncated`, `malformed`, `oversize`, `dimensions`) and `message`. The rest play in album order. An album where every item is skipped still writes a playlist with no items. | `a_bad_item_is_skipped_and_the_rest_play_in_order`, `an_album_where_every_item_is_skipped_still_writes_a_playlist`, and 6 more; host-test `content_failures_are_skipped_and_listed_through_the_runtime` (all five reasons in one run) |

Two choices of mine within the rule:

- **Truncated and malformed headers skip the item.** You named wrong type, oversize and bad dimensions. These
  two are defects of the item's own bytes, so I treated them the same way.
- **"Budget" stops the run.** P1's only budget, the album body budget, is gone. The limits left that end a run
  (album size, item count) are album-level, so they stop it. The per-item JPEG segment cap is the item's
  content, so it skips.

## Tests run and results

`export RUST_TEST_THREADS=2`, then `examples/photo-viewer/verify.sh` (passes, about 32 s warm):

| Suite | Result |
|---|---|
| Guest tests, fake Runtime | 29 passed |
| Guest fmt `--check`, clippy `--all-targets -D warnings` | clean |
| Build, `scripts/build-component-capsule.sh` | ok |
| Host harness, component in `ComponentProvider` | 13 passed, 1 ignored (fuel probe) |
| Host fmt, clippy | clean |
| `falsify.py --runtime` | 18 of 18 caught |
| `git diff --check` | clean |

## Falsifiers

`falsify.py` now requires every mutant to **compile** before its test counts as failing. A mutant that does not
compile would also fail `cargo test` and prove nothing. P1's run did not have this check. I re-ran P1's
falsifiers with it in a throwaway worktree of `claude/photo-p1`: all compiled and all were caught.

Guest, 15:
- **Authority:** album, image and playlist without a grant; a provider error on a header read skipped instead
  of stopping; provider status ignored; unknown album fields; `..` segments.
- **Content:** a content failure stopping the run instead of skipping; wrong type accepted; truncated magic
  treated as unknown; size limit not checked; side limit removed; JPEG segment cap doubled; JPEG payloads read.
- **Body shape:** the playlist written as a string with no `append` (the P1 shape).

Rebuilt into the component and caught in `ComponentProvider`, 3: wrong type accepted, image read without a
grant, playlist written as a string. After the run every `src/*.rs` matches its saved hash, and the component
is rebuilt to the hash below.

## Guest hash and import list

- `photo-viewer.component.wasm` sha256 `add93842bb7253bdab18d27067d0976558913fda6bd354f772f04c5e9fc9dd22` (this
  cloud container, Linux x86_64, Rust 1.91.0). The same on every rebuild here.
- The reviewer's Mac built P1 to `e2a4c798…638a` (221,287 bytes); cloud built it to `9cf68749…` (221,286). P2
  works on that one-byte gap.
- Imports, unchanged: `elastos:bus/types@1.0.0`, `runtime@1.0.0`, `capabilities@1.0.0`, `providers@1.0.0`.
  Export `elastos:bus/lifecycle@1.0.0`. Passes the copied Runtime admission check.
- Guest dependencies: `wit-bindgen 0.57.1`, `serde 1.0.229` (no derive), `serde_json 1.0.154`.

## Principles checked

- **3:** one grant per object and action. Reads are a window, never the whole body. The guest cannot make
  the provider allocate more than 32 bytes per image read.
- **10:** one read contract for both Runtime paths (no stat, no `encoding` switch); one write shape both paths
  accept.
- **11:** authority failures stop with a named reason; content failures are listed with a reason; fuel cannot
  trap within the limits.
- **13:** album, images and playlist are user objects.
- **15:** content identity is left to Runtime CIDs (2.2), not a guest hash of bytes Runtime served.
- **16:** the fixed input path is spike-only; Phase 2 input is the opened object.
- **18:** one bounded activation; fuel no longer grows with image size.

## Roadmap milestone

2.5 on Bus v1. The provider findings (stat size, caller-chosen allocation, underflow) feed 2.7. Naming by CID
is 2.2.

## Questions for Sasha

1. The provider's caller-sized allocation and its missing-`length` underflow: should they go to you privately
   like the other findings, or be filed?
2. `skipped` keeps the URI of every skipped item. Is that fine for a render-only surface to see, or should it
   carry only `order` and `reason`?

## Next slice

The `component.rs:134` root-cause fix with its test, as its own small PR (answer 4). Then P2.
