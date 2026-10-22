# Capsule kit: one shared source

The task: move the copies A1 to A8 (`KIT-REPORT.md`) into `examples/capsule-kit`, as one source that the photo
viewer and the documents viewer both use, so no copy can drift. Both `verify.sh` must pass with the same
counts, and the photo core's hash must not change. Also, two spike-tool gaps from the kit draft: a pack step
(item 3) and a refused repeated publisher (item 5).

Branch `claude/photo-kit-shared`, stacked on `claude/photo-kit` (`779f37a8`, the kit draft, #29). Spike only:
nothing changed under `elastos/`, `capsules/` or `examples/agent-host/`, and nothing in the Runtime, Home or
the Bus.

## Summary

- **Every kit item now has one source.** A1 to A5 moved into `capsule-kit`. A6 (the bundle tool) and A7 (the
  Bus v2 proof) were already the only copy, so the documents viewer now uses them directly instead of copying.
- **The photo core's hash did not change:** `add93842…dd22`, natively and in the pinned container.
- **The documents core's hash did change**, `56a577fb…3e3c` to `87e3f454…4e98`, because it now uses the
  photo viewer's write body (see [The write body](#the-write-body)). Its worst shelf went from 52.9% to 63.3%
  of the fuel; the gate is 80%.
- **Same counts in both viewers.** Photo viewer: 29 guest and 13 host tests, 18 of 18 falsifiers. Documents
  viewer: 67 Rust and 13 page tests, 52 of 52 falsifiers.
- **About 2,950 lines left the two viewers** and about 1,450 shared lines came in (lock files not counted).
- **Items 3 and 5 are done**, in the bundle tool only: `capsule-bundle pack`, and `publisher_listed_twice`.
- **Codex's fixes to #29 are merged in** (a merge commit, see [Merged with the #29 fixes](#merged-with-the-29-fixes)).
  The documents viewer now has 71 Rust and 14 page tests and 57 of 57 falsifiers; its core is `8765e790…`,
  worst shelf 62.2%. The photo core is still `add93842…`.

## What moved where

| Item | Now in `capsule-kit` | How each viewer uses it |
|---|---|---|
| A1 Bus v1 guest sources | `v1-guest/bus.rs`, `component.rs`, `fake.rs` | Relative symlinks in `src/` |
| A2 host-test harness | `v1-host-test/` (crate `capsule-v1-host-test`): `Bridge`, `run`, `admission`, `measure`, `imports_and_exports` | A dev-dependency of `host-test/` |
| A3 build scripts | `scripts/check-manifest.py`, `repro/build-in-container.sh <capsule-dir>` | `verify.sh` calls the check; `repro/build-in-container.sh` is a two-line wrapper |
| A4 mutation runner | `falsify/falsify_kit.py` | Each `falsify*.py` keeps its cases and imports the runner (seven scripts) |
| A5 page test kit | `surface/test-kit.mjs` (fake element, document, response), `surface/stand-in.mjs` (Runtime's app headers, the CORS preflight, Home's sandbox) | The page tests import the fakes; the Chromium smokes run on the stand-in |
| A6 pack and bundle test helpers | (stays in `examples/photo-viewer/bundle`) `pack`, `capsule_bundle::testing` | The docs bundle test packs and admits with the tool |
| A7 Bus v2 test support | (stays in `examples/bus2-proof`) `host/tests/common`, `guests/busy` | The docs Bus v2 tests include the proof's helpers and load its busy guest; the copies are gone |
| A8 checklist | `PATTERNS.md` | - |

## Why links, not a crate, for A1

The photo core's hash depends on more than its code. I tried three ways:

| Way | Photo hash |
|---|---|
| `#[path = "../../capsule-kit/v1-guest/bus.rs"]` | changed (`606e1587…`): the source path reaches symbol names and so the layout |
| Moving the read helpers out of `lib.rs` into a shared module | changed (`c5114d14…`): the code moved between modules |
| Relative symlinks in `src/`, and the `mod component` block moved to its own linked file | **unchanged** (`add93842…`) |

So the guest sources are linked files, and the parts of `lib.rs` that would move code between modules stay in
each app (below). A crate would change the hash for the same reasons. `v1-guest/README.md` has the details.

## The write body

The kit can hold only one `bus.rs`. The photo viewer's write builds a `serde_json::Value` per byte; the
documents viewer had a cheaper one that writes the numbers straight to bytes. Taking the cheaper one changes
the photo hash, so the kit keeps the photo one. The cost falls on the documents viewer: 52.9% to 63.3% for its
worst shelf, within the 80% gate, which still runs. `PATTERNS.md` now says this.

The cheaper write can come back with the next change that is allowed to move the photo hash. (After the
#29 fixes the figures are 51.6% with the cheaper write and 62.2% with the shared one.)

## What is still copied, and why

| What | Where | Lines | Why it stays |
|---|---|---|---|
| `Refusal`, `to_bus_failure`, `grant`, `read_at`, `read_bounded` | each `src/lib.rs` | about 120 | Moving them changes the photo hash (`c5114d14`) |
| The object URI check | `album.rs`, `shelf.rs` | about 20 | The same reason; the prefixes differ too |
| The guest tests of `bus.rs` itself (`OddAnswers` and others) | each `src/tests.rs` | about 85 | They test the linked file through each app's `lib.rs`; to be moved with `lib.rs` |
| `build.sh` | each viewer | 7 | Names the capsule; the work is in `scripts/build-component-capsule.sh` |
| Page code: `launchToken`, the client, `cut` | each `surface/browser/*.js` | about 25 | Runtime's gateway test installs exactly the four Photos page files, so a shared module would be a fifth file there. That test is Runtime code |
| Host-test glue: `capsule_dir`, `component_path`, `manifest`, `denied`, the `measure` wrapper | each `host-test/tests/component.rs` | small | App paths and names |
| The `verify.sh` skeleton and `capsule.json` | each viewer | - | App steps and identity |

A line match (`difflib`) over every pair that is left finds 1,296 of 3,884 lines in common. Most are blank
lines, braces, imports and the shape of tests, not logic.

## Lines

Counted with `git diff --numstat 779f37a8`, lock files left out.

| Area | Added | Removed |
|---|---|---|
| `examples/photo-viewer` (not the bundle tool) | 164 | 1,380 |
| `examples/docs-viewer` | 229 | 1,573 |
| `examples/capsule-kit` (new shared code and READMEs) | 1,448 | 0 |
| The bundle tool (items 3 and 5, new code and tests) | 461 | 33 |

Without the bundle tool's new features: 2,953 lines removed from the viewers, 1,841 added in all, so 1,112
fewer lines.

## Items 3 and 5 (bundle tool)

- **`capsule-bundle pack <source> <into> [--require name=cid]`** ships `capsule.json` and the entrypoint; for a
  web projection, every file of the entrypoint's folder (never the source root). It refuses a symlink or a
  special file, a missing entrypoint (`pack_entrypoint_missing`), an existing destination
  (`pack_destination_exists`) and a CID that is not one. `--require` replaces a requirement of the same name;
  with none, `capsule.json` is copied byte for byte. Five tests, one of them that the CID does not change when
  a test or fixture in the source does.
- **A policy that lists one DID twice is refused** (`publisher_listed_twice`), before the policy floor moves.
  One entry may still list several roles. A test in the tool and one in the docs bundle test.
- Bundle tool: 46 tests (was 40), 56 of 56 falsifiers (was 49).

## Counts

| | Before (#29) | Now |
|---|---|---|
| Photo core (`photo-viewer/verify.sh`) | 29 guest, 13 host, 18/18 falsifiers | the same |
| Photo core hash | `add93842…dd22` | the same, also in the container |
| Photo page | 12 tests, 13/13 falsifiers | the same |
| Photo seam (`falsify-seam.py`) | 21 falsifiers | 21 anchors checked; one case run here (each takes about 5 minutes); the full run is for the Mac |
| Bundle tool | 40 tests, 49/49 | 46 tests, 56/56 |
| Documents viewer (`docs-viewer/verify.sh`) | 67 Rust, 13 page, 52/52 | the same |
| Documents core hash | `56a577fb…3e3c` | `87e3f454…4e98`, the same in the container |
| Documents worst shelf | 52.9% | 63.3% (gate 80%) |

## Merged with the #29 fixes

`claude/photo-kit` gained Codex's five fixes (`4df2ef7c`, `ae79a57b`; see `KIT-REPORT.md`, "Review fixes").
They are merged into this branch with a merge commit, no rebase. The conflicts were all in the documents
viewer and the kit docs:

| File | Resolved as |
|---|---|
| `docs-viewer/surface/reader-browser-smoke.mjs` | This branch's smoke on the shared stand-in, with the three inherited style names and their check from #29. The favicon 204 went into `capsule-kit/surface/stand-in.mjs`, so the photo smoke has it too |
| `docs-viewer/falsify.py` | Both: #29's seven new and moved cases, this branch's write falsifier (`src/bus.rs` is the shared one) |
| `docs-viewer/host-test/tests/component.rs` | The new backtick shelf, with this branch's `bridge_with` |
| `docs-viewer/src/lib.rs`, `src/tests.rs` | Merged without a conflict: the fixes touch the run loop and the reads, this branch only moved the WIT glue out |
| `capsule-kit/PATTERNS.md` | This branch's write rule, then #29's whole-output rule |
| `docs-viewer/README.md`, `repro/README.md`, `photo-viewer/handoff/LOG.md` | Both, with the merged hash and fuel |

After the merge, in this container:

| | Now |
|---|---|
| Photo core | 29 guest, 13 host, 18/18 falsifiers; `add93842…dd22`, the same in the container |
| Photo page | 12 tests, 13/13 falsifiers; the smoke passes on the stand-in with the favicon 204 |
| Bundle tool | 46 tests, 56/56 falsifiers |
| Documents viewer | 71 Rust (13 model, 30 guest, 12 host, 7 bundle, 9 Bus v2), 14 page, 57/57 falsifiers |
| Documents core | `8765e790…da40`, the same in the container; closure CID `bafkreigk…ukr3a` |
| Documents worst shelf | 62.2% (8 ordinary documents; gate 80%); the new backtick shelf 45.7% |

The photo code did not change in the merge, so `falsify-seam.py` was not run again.

## For the Mac and Codex

- Run both `verify.sh`, `photo-viewer/surface` and bundle checks, and the whole `falsify-seam.py`.
- Run both repro scripts; the photo hash must be `add93842…`, the documents hash `8765e790…`.
- Check the links survive a checkout on macOS (`git config core.symlinks` is true by default there).

## Commits

`1eb9aee4` A1, `095dd0fb` A2, `16b3e3ad` A3, `4f8db46f` pack and the repeated publisher, `516b6de8` A6,
`b404cf3a` and `7452b3f5` A4, `25ef8213` A5, `4e923c43` A7, then this report.
