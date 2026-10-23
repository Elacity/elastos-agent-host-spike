# Capsule kit: the guest crate

The task: replace the symlinks with a real Cargo crate in `examples/capsule-kit`, used by both viewers as a
path dependency; move into it the code each viewer still copied and the Bus tests; add the three pieces the
archive design needs from the kit (the counted reader, the text checks, the image header checks); give the
documents viewer its cheaper write back; let the photo core's hash change once, and rerun every photo
falsifier, the whole seam set and both container builds. Every falsify script uses the shared runner.

Branch `claude/photo-kit-crate`, from `claude/photo-kit-shared` `3ecb8ae9` (#32). Spike only: nothing changed
under `elastos/`, `capsules/` or `examples/agent-host/`, and nothing in the Runtime, Home or the Bus.

## Summary

- **No symlinks are left.** `examples/capsule-kit/guest` is the crate `capsule-kit-guest`. Both viewers depend on
  it by path; `examples/capsule-kit/v1-guest` is gone.
- **Moved into it:** the Bus calls and answer parser, the WIT glue, the fake Runtime (these were the links); the
  copies each viewer still had (`Refusal`, `grant`, `read_at`, `read_bounded`, the URI check); the Bus tests;
  and from the archive design: the counted reader (`read_counted`, M1), the text checks (M2) and the image header
  checks (M3).
- **One write, the cheaper one.** The kit's write is now the documents viewer's (each byte written straight as a
  number), used by both viewers. The documents viewer's worst shelf is back to **50.2%** (it was 62.2% on the
  shared heavier write, 51.6% before that); the photo viewer's worst album drops from 64.9% to **59.1%**.
- **The photo hash changed once**, as planned: `add93842…dd22` to `053b198d…9cfc` in the pinned container
  (see below for why). Native builds no longer match the container: the crate's absolute path reaches the bytes
  (see [Reproducible build](#reproducible-build)).
- **Every falsifier set passes** under the all-tests-must-fail rule, with nothing surviving, including the whole
  seam set (21/21).

## The crate

| Module | What | From |
|---|---|---|
| `bus` | The `Bus` trait, the read window, the write and its body, the one-pass answer parser | the links (A1); the write from the documents viewer |
| `read` | `Refusal` (`NoGrant`, `Call`, `InputTooLarge`, `Input`), `App` (name, input noun, input cap), `grant`, `read_at`, `read_bounded`, `read_counted`, `READ_CHUNK_BYTES` | both viewers' `lib.rs` (about 120 lines each); `read_counted` from the documents viewer (M1) |
| `uri` | `check_object_uri(uri, prefix)` | `album.rs` and `shelf.rs` |
| `text` | `check_head`, `check_whole` | the documents model (M2); `docs-model` re-exports it |
| `image` | `sniff`, `header_dimensions`, `jpeg_dimensions`, `HEADER_BYTES` | the photo viewer (M3) |
| `fake` (feature `fake`) | `FakeBus` | the links |
| `wit`, `component` (feature `wit`, wasm32) | the `product-capsule-v1` bindings, generated once; `WitBus`; `lifecycle_run(app, run)`, which checks the ABI and turns a refusal into the `bus-error`; the export macro | the links and both viewers' export blocks |

Features keep each user to what it needs: a Bus v1 component turns on `wit`, its tests `fake`; `docs-model`
(and through it the Bus v2 guest) takes the crate with no features, so it gets the text checks and no Bus v1
binding at all. The Bus v2 guest's tests (which check it imports only `elastos:bus/*@2.0.0`) still pass.

A viewer now says only what is its own: `pub const APP: App = App { name, input, max_input_bytes }`, its
limits, its input schema, its run order and checks, and a nine-line export:

```rust
impl capsule_kit_guest::wit::exports::elastos::bus::lifecycle::Guest for PhotoViewer {
    fn run() -> Result<(), capsule_kit_guest::wit::elastos::bus::types::BusError> {
        capsule_kit_guest::component::lifecycle_run(&APP, |bus| run(bus).map(|_| ()))
    }
}
capsule_kit_guest::wit::export_lifecycle!(PhotoViewer with_types_in capsule_kit_guest::wit);
```

The crate has its own tests (18), falsifiers (21) and `verify.sh` (fmt, clippy with each feature set, tests,
the runner's self-test, falsifiers). Both viewers' `verify.sh` run it first.

## The photo hash

| | sha256 | Worst album |
|---|---|---|
| Before (`3ecb8ae9`) | `add93842bb7253bdab18d27067d0976558913fda6bd354f772f04c5e9fc9dd22` | 64.9% |
| After, in the container | `053b198d14e0b2abf1a2d911f3513e2d5bc9280b7202af806f56c71b86529cfc` | 59.1% (measured on the native build, `5a284f2f…`) |

Why it changed: the guest's code now comes from another crate (every symbol's crate name and the link order
change, and that crate is hashed by its absolute path), the WIT bindings are generated in that crate, and the
playlist is written through the cheaper write,
which builds the same body text without a `serde_json::Value` per byte. The playlist bytes on the wire are the
same; the tests that check them did not change. Rerun after the change: every photo falsifier (17, with the
component rebuilt for each runtime one), the page set (13), the bundle set (60), the whole seam set (21), and
both container builds (below).

## Reproducible build

The container build is now the only reference, and the container recipe changed to keep it one:

| | Photo core | Documents core |
|---|---|---|
| Pinned container (twice the same for the photo core) | `053b198d14e0b2abf1a2d911f3513e2d5bc9280b7202af806f56c71b86529cfc` | `c946ad9e0959f8ef985e978d30d0543e0d2bb7b17883f621ef61167366a3a7cf` |
| Native, this checkout (`/home/user/...`) | `5a284f2f…a516` | `a479a911…066b` |

Two things came with the crate:

1. **The builder refused the container build at first.** The crate is a path dependency outside each viewer's
   workspace, so Cargo gives rustc its absolute path, and the remapped path (`/src/elastos-runtime/examples/
   capsule-kit/guest/src/…`) stays in panic locations. The container mounted the repository at that same
   `/src/elastos-runtime`, so the builder's check for the repository's own path found it. The kit's recipe now
   mounts at `/build/elastos-runtime` (`examples/capsule-kit/repro/build-in-container.sh`); the builder
   (`scripts/build-component-capsule.sh`, which releases use) is unchanged.
2. **The checkout path reaches the bytes.** Cargo hashes a path package outside the workspace root by its
   absolute path, and that hash reaches symbol names and so the code. Measured: the documents core built in the
   container at another mount (`/other/place`) gives `e04b964d…`, not `c946ad9e…`. So native builds now differ
   with the checkout path, and only the container, with its one mount point, gives the reference hash on every
   machine. Pattern 4 already names the container build as the one that counts; native Linux matched it before
   only because each core was its own workspace root.

To make native builds path-free again, the kit's crate and the viewers would have to share one Cargo workspace
(rooted at `examples/`, with one lock file). That changes the layout of every example folder, so it is a
question for Sasha, not part of this slice.

## Lines

Counted with `git diff --numstat 3ecb8ae9`, lock files left out.

| Area | Added | Removed |
|---|---|---|
| `examples/photo-viewer` | 56 | 544 |
| `examples/docs-viewer` | 51 | 412 |
| `examples/capsule-kit/v1-guest` (the linked files, now the crate) | 0 | 530 |
| `examples/capsule-kit/guest` (the crate: code, its tests, its falsifiers, `verify.sh`) | 1,731 | 0 |

The viewers lost 956 lines and gained 107. Of the crate's 1,731 lines, 1,070 are code (almost all of it was
in the links or in a viewer before; new are `App`, `lifecycle_run` and the module docs), 477 are its tests
(most moved from the viewers, plus new ones for the refusal mapping, the reads, the URI check and the write
answer), 152 its falsify script and `verify.sh`, and 32 its manifest. The repository grows by about 350 lines
in all, less than the 629 lines of the crate's tests, falsifiers and `verify.sh`.

## What is still copied, and why

Measured with a line match (`difflib`) between the two viewers; "not trivial" leaves out blank lines and
lone braces.

| Pair | Lines that match (not trivial) | What, and why it stays |
|---|---|---|
| `album.rs` / `shelf.rs` | 31 | The strict input-list parser: a JSON object with only `schema` and `items`, a fixed schema, a non-empty capped list, unknown item fields refused. The item fields differ (an album item has a duration). It could be a kit `parse_list(bytes, schema, cap, item)`; not asked for here, and the next app (archive) has a single URI, not a list |
| `lib.rs` | 45 | Module docs, the fixed-path comments, the run skeleton (grant, bounded read, parse, check each item, write), the export block. The checks between are each app's own |
| `tests.rs` | 60 | Test helpers (`granted`, `written`, `skipped`, `assert_nothing_written`) and the shape of the authority tests, each against its own run |
| `host-test/tests/component.rs` | 70 | App paths, names, fixtures and the fuel-gate wrapper around the kit harness (`v1-host-test`) |
| `verify.sh`, `build.sh`, `falsify.py` | 18, 5, 46 | Script skeletons: which crates, which tests, which artifact |

Also still per page: the about 25 lines of `launchToken`, the client and `cut` in each `surface/browser/*.js`,
because the Runtime's gateway test installs exactly four Photos page files (unchanged from #32).

## Counts

| | Before (`3ecb8ae9`) | Now |
|---|---|---|
| Kit guest crate | (links, no own tests) | 18 tests, 21/21 falsifiers |
| Photo core | 29 guest, 13 host, 18/18 | 24 guest, 13 host, 17/17 (5 tests and 1 falsifier moved to the kit) |
| Photo page | 12 tests, 13/13 | the same |
| Bundle tool | 47 tests, 60/60 | the same |
| Photo seam (`falsify-seam.py`, whole set) | 21/21 | 21/21 |
| Documents viewer | 71 Rust, 14 page, 57/57 | 66 Rust (11 model, 27 guest, 12 host, 7 bundle, 9 Bus v2), 14 page, 52/52 (36 + 16; 5 tests and 5 falsifiers moved to the kit) |
| Photo core hash | `add93842…dd22` | container `053b198d…9cfc`; native here `5a284f2f…a516` |
| Documents core hash | `8765e790…da40` | container `c946ad9e…a7cf`; native here `a479a911…066b` |
| Documents worst shelf | 62.2% | 50.2% |
| Photo worst album | 64.9% | 59.1% |

## For the Mac and Codex

- Run both `verify.sh` (each runs `capsule-kit/guest/verify.sh` first), the photo page and bundle checks, and
  the whole `falsify-seam.py`.
- Run both container builds: photo `053b198d…`, documents `c946ad9e…` (the native hashes differ by checkout path; see "Reproducible build").
- Check that `capsule-kit/guest` builds with the Mac's toolchain for `wasm32-unknown-unknown` with `--features
  wit`, and with no features (the Bus v2 guest uses it that way, on Rust 1.95.0).
