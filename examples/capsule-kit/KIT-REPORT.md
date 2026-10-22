# Capsule kit draft: what a second viewer needed

Input to roadmap 2.4 (the capsule kit). I wrote the photo patterns down as a checklist (`PATTERNS.md`).
Then I built a second viewer, for markdown and text documents, read-only, using only those patterns and the
tools the photo viewer and the Bus v2 proof left (`examples/docs-viewer`). This report says what I had to
copy, what I had to change, and what was missing. That is what the kit must contain.

Branch `claude/photo-kit`, from `spike/photo-viewer` `c7505711`. Spike only: no Runtime change, and nothing
changed under `elastos/`, `capsules/`, `examples/photo-viewer/` or `examples/bus2-proof/`.

## Summary

- **The patterns carry over.** The documents viewer meets all six, with 67 Rust tests, 13 page tests and
  52 falsifiers, all in one `verify.sh`.
- **Three patterns are not fully shown, and none of the three can be finished inside an app:**
  - pattern 2: the page has run only against a stand-in server, because Runtime's read route serves the photo
    viewer alone;
  - pattern 3: Runtime's own manifest type refuses the field that names a core by CID;
  - pattern 4: one machine has built it so far.
- **About 2,550 lines of about 5,240 are copies**, line for line, of photo viewer or Bus v2 proof files.
  The rest is the documents logic and its tests. The copies are what the kit should ship once.
- **Pattern 1 needed the most change.**
  - "Read headers only" does not fit text: you must read the whole body to know it is text.
  - Reading whole bodies on Bus v1 exposed costs the photo viewer never met: fuel per output byte, the bridge
    frame size, and parsers that hostile input can make slow.
  - Each needed a rule and a test the checklist did not have.

## What I built, pattern by pattern

| Pattern | What | Tests | Falsifiers | Status |
|---|---|---|---|---|
| 1. Grant-only reads with checks | `docs-viewer` core: a shelf by grant; for each document a head check, a size probe, a bounded body read, a whole-text check; markdown parsed in the sandbox into typed blocks; `pages.json` written once | 13 model, 26 guest, 12 in `ComponentProvider` | 24 guest, 4 in `ComponentProvider` | Met. Worst shelf 52.9% of the fuel (gate 80%) |
| 2. Render-only page with a launch token | `docs-reader` page: one route, draws six block kinds with `textContent` only, no parser | 13 node, 1 Chromium smoke | 15 | Met against a stand-in server only (missing 1) |
| 3. Signed bundle by CID with policy | Both capsules packed, named by CID, claimed, admitted; the page names its core by CID | 7 | 2 (the tool's own checks are falsified in the photo viewer) | Met in the tool; Runtime's manifest refuses `requires[].cid` (missing 4) |
| 4. Reproducible build | The photo viewer's pinned container, pointed at the docs core | 1 build | - | Same hash in container and native here; second machine pending |
| 5. Mutation tests | `falsify.py` (core, model, Runtime, bundle, Bus v2) and `falsify-surface.py` | - | 52 in all | Met |
| 6. Bus v2 slices and stop | A resident reader on the draft Bus v2, in the proof's stub host | 9 | 7 | Met; one frame cannot hold a document (missing 7) |

Build facts: core component sha256 `56a577fb…3e3c`. Closure CIDs: core `bafkreib4…lvjq`, page `bafkreig3…fjaku`.
Bus v1 imports: `types`, `runtime`, `capabilities`, `providers`. Bus v2 imports: `types`, `capabilities`,
`providers`, `ui`.

## What I had to copy

Measured as lines that match the source file, in order (blank lines and braces count too).

| Copied into `examples/docs-viewer/` | From | Same | What it is | Kit item |
|---|---|---|---|---|
| `src/bus.rs` | `photo-viewer/src/bus.rs` | 88% | The `Bus` trait, the read window, the write, the one-pass reply parser | A1 |
| `src/fake.rs` | `photo-viewer/src/fake.rs` | 99% (one message) | The fake Runtime that checks bodies as the localhost provider does | A1 |
| `src/lib.rs` | `photo-viewer/src/lib.rs` | 55% | `Refusal` and its `bus-error` mapping, `grant`, `read_at`, `read_bounded`, the WIT glue (`WitBus`, `run`, ABI check) | A1 |
| `src/shelf.rs` | `photo-viewer/src/album.rs` | 69% | The strict list parser and the object URI check | A1 |
| `host-test/tests/component.rs` | `photo-viewer/host-test/tests/component.rs` | 63% | The fake bridge, the `ComponentProvider` run, the admission check (itself a copy of private Runtime code), the fuel runner | A2 |
| `build.sh`, `verify.sh`, `repro/build-in-container.sh` | the photo viewer's | 100%, 55%, 96% | The builder call, the manifest check, the pinned container | A3 |
| `falsify.py`, `falsify-surface.py` | the photo viewer's | 28%, 59% | The mutation runner | A4 |
| `surface/browser/reader.js` | `photos.js` | 37% | `launchToken`, the one-call-site client, the refusal text, cutting strings, the mount skeleton | A5 |
| `surface/reader.test.mjs`, `reader-browser-smoke.mjs` | the Photos tests | 37%, 66% | The fake window and document; the stand-in server with Runtime's app headers and Home's sandbox | A5 |
| `bundle-test/tests/bundle.rs` | `photo-viewer/bundle/tests/admission.rs` | 28% | `World`, `unseal`, `refused`, claim and policy setup | A6 |
| `bus2/guests/busy`, `bus2/host-test/tests/common` | `bus2-proof` | 94%, 92% | The busy guest; `guest()` and the watchdog `within()` | A7 |
| `bus2/rust-toolchain.toml`, release profile | `bus2-proof` | 100% | Rust 1.95.0 for Wasmtime 48 | A7 |

Two copies are copies of copies. The admission check was copied from private Runtime code into the photo
host test, and now from there. The Runtime's app headers were copied by hand into the Photos smoke server,
and now from there. When Runtime changes, these copies drift without a test failing.

`elastos/crates/elastos-guest` already generates the Bus v1 bindings. It has no read window, no reply
parser and no fake, so neither viewer uses it.

## What I had to change

Things in the photo patterns, or in the copied code, that did not fit a documents viewer.

1. **"Headers only" became "head, size, then a bounded body".**
   - An image has a header that names its type and size. Text has none: only the whole body shows it is
     UTF-8 with no control bytes.
   - So the core reads 512 bytes and checks they are text. It reads one byte at 16 KiB to tell an oversize
     document. Only then does it read the rest, and check the whole.
   - Pattern 1 should say: read only what you need, and for formats that must be read whole, only after a head
     check and a size probe.
2. **A per-shelf budget, counting every full read.**
   - Eight documents of 16 KiB each would cost too much fuel on Bus v1, so a shelf may read 32 KiB in all.
   - My first version counted only documents that were shown. Documents read in full and then skipped (not
     text, too long) were free, so a shelf of eight still read 128 KiB.
   - A test found it, and every byte read in full now counts. The checklist had no budget item at all.
3. **The output has a cost and a cap.**
   - The copied write built a `serde_json::Value` for every output byte. One document with many spans then
     cost 211% of the fuel.
   - The photo playlist is small, so this never showed. The write and the pages are now written straight to
     bytes (51% for the same document).
   - Output is also capped at 64 KiB a shelf: the write sends each byte as a number of up to four characters,
     and 260 KB of pages would pass the Runtime's 1 MiB bridge frame.
   - Pattern 1 should cap and gate the output, not only the input.
4. **Parsers must be linear, and the fuel gate must include hostile input.**
   - My first markdown parser searched to the end of the paragraph for every opener that never closes (`*`,
     `` ` ``, `[`, `<`).
   - One 16 KiB document of them cost 16 to 27 times the whole fuel budget. The run traps, so a content
     failure became a stop.
   - Every closer is now found through an index built once. The gate includes documents of openers that never
     close: 33% and 39%.
   - A Runtime falsifier puts a linear scan back, and the gate catches it. The photo viewer's header checks
     were bounded by construction, so the checklist never asked for this.
5. **The page has no parser and one route.**
   - The core parses markdown in the sandbox into typed, text-only blocks. A link keeps its label and shows
     its target as text; an image becomes `[image: alt]`; HTML stays text.
   - So the page only draws six block kinds and four span styles, and needs no item route.
   - The existing `capsules/documents` app renders markdown to an HTML string and sets `innerHTML`; this page
     cannot. Pattern 2 should say: the page draws a typed document, and has no parser of its own.
6. **Stop and skip on Bus v2 needed a rule.**
   - A resident guest has no "write once at the end", so "skip and list" has no direct form.
   - The reader ends the run when a grant is refused or a read is denied. For a document it does not show, it
     draws a frame that says so and goes on.
   - Pattern 6 should say which failures end a resident run.
7. **Bus v2's `bus-error` has `conflict`**, which v1 does not. The v1 error mapping does not carry over as it is.
8. **The mutation runner** had to name the crate each test is in (core, model, host test, bundle test, Bus v2),
   and gained `--check` and name filters from the Bus v2 proof's runner.
9. **The Bus v2 part runs from its own folder.** rustup picks the toolchain from the current folder, not from
   `--manifest-path`, so `verify.sh` must `cd bus2`.

## What was missing

What no app can add for itself. Items 1, 2, 4 and 6 are Runtime or Home changes and need Sasha's yes.

**Decided after review:** items 3 and 5 are done in the spike tools (branch `claude/photo-kit-shared`, see
`SHARED-REPORT.md`). Items 1, 2, 4 and 6 wait for Anders, after 0.8.0; the Runtime, Home and Bus stay as they
are.

1. **A generic read route for a viewer.**
   - The seam serves `image-viewer` and the photo playlist only (`viewer_gateway.rs`, "Photos surface").
   - So `docs-reader` has run only against the stand-in server.
   - Needed: one read-only route that serves the one output object bound to this launch, for any viewer, with
     no per-app Runtime code. For example `GET /api/viewers/<viewer>/output`, with the output's CID in the
     signed launch token.
2. **A way to open the viewer.**
   - Home binds a selected resource only for `image-viewer`.
   - The Library picks a viewer by a name table, and `.md` and `.txt` open the existing `documents` editor.
   - Needed: the viewer chosen by what it declares it accepts, and the launch bound to the opened object.
3. **A pack step.**
   - `capsule-bundle` names a folder by CID, but has nothing that decides which files ship. The source folders
     hold source, tests, fixtures and build output.
   - I wrote `pack` in the test: the manifest and the entrypoint, or for a page the entrypoint's folder.
     (Now done: `capsule-bundle pack`, and the test uses it.)
   - Needed: `capsule-bundle pack`, with the list of shipped files declared, and a test that the CID does not
     change when a test or fixture does.
4. **The Runtime manifest cannot name a core by CID.**
   - `elastos_common::CapsuleManifest` refuses `requires[].cid`: "unknown field `cid`, expected `name` or
     `kind`". A test pins this.
   - Known from P4; still missing.
5. **A policy that lists one publisher twice is not refused.**
   - The tool reads the first entry for a DID and ignores the rest, silently. A test pins this. (Now done: a
     repeated DID is refused as `publisher_listed_twice`.)
   - So "this publisher ships the app `docs-viewer` and the viewer `docs-reader`" cannot be said exactly. The
     only form is roles `[app, viewer]` with names `[docs-viewer, docs-reader]`, which also lets it ship an
     app named `docs-reader`.
   - Needed: refuse a repeated DID, or names per role.
6. **The output is a fixed path.** Any capsule with a storage grant on it could write `pages.json`. This is the
   same known limit as the photo playlist; Phase 2 binds the run's output to the launch by CID.
7. **A typed UI document on Bus v2.**
   - `ui.present` takes 32 text or image nodes of at most 1,000 characters, 16 KiB in all.
   - A document therefore loses its block kinds (a heading is just text) and is cut to one frame. The frame
     says how many blocks did not fit.
   - Needed: the typed WIT document the Bus v2 report recommends, with the six block kinds and paging. The
     `docs-model` blocks are a ready candidate: the v1 pages and the v2 frame would then be one format.
8. **A shared schema between a core and its page.**
   - Nothing ties the core's output to what the page reads.
   - I added a fixture the core writes and a core test checks (`surface/fixtures/pages.json`), and the page
     tests read it.
   - Needed: output formats as schemas, or WIT types on Bus v2.
9. **A reproducible-build check.**
   - The expected hash is written by hand in a README, and only one machine has built it.
   - The P3 design's proposal still stands: one `scripts/` recipe that takes a capsule folder, pins in one
     file, and a check that rebuilds and compares.
10. **A Bus v1 guest crate.** Either `elastos-guest` gains the read window, the reply parser, the string write
    body and a fake, or the kit ships them.
11. **Bus v1 fuel sets small limits.**
    - A byte read costs about 415 fuel (measured for the photo viewer). A byte written costs roughly 200: my
      estimate from these runs, not measured alone.
    - So a document is at most 16 KiB and a shelf reads at most 32 KiB.
    - Bus v2 streams remove the JSON byte arrays. These limits should be measured again there, not carried
      over.

## What the kit (2.4) should contain

| # | Item | Replaces |
|---|---|---|
| A1 | A Bus v1 guest crate: the `Bus` trait, read window, bounded read, string write body, reply parser, `Refusal` with its `bus-error` mapping, strict list and URI parsing, the WIT glue, and `FakeBus` | the copies of `bus.rs`, `fake.rs`, half of `lib.rs`, `shelf.rs` |
| A2 | A host-test crate: the fake bridge, the `ComponentProvider` run, the fuel runner, and the admission check exported by Runtime instead of copied | the 63% copy of `component.rs` |
| A3 | `scripts/` for build, verify and the pinned container, each taking a capsule folder; pins in one file; a recorded hash and a check | `build.sh`, the manifest check in `verify.sh`, `repro/` |
| A4 | One mutation runner that reads a case list per app, knows crates, and has `--check` and filters | three `falsify*.py` runners |
| A5 | A page kit: `launchToken`, the client, `cut`, a typed-document renderer; the fake window for tests; the stand-in server with Runtime's app headers taken from Runtime | half of `reader.js`, the test fakes, the smoke server |
| A6 | `capsule-bundle pack` and test support (`World`, sealed stores) | `pack` and the helpers in `bundle.rs` |
| A7 | The Bus v2 host as test support: `guest()`, `within()`, a busy guest, the toolchain pin | the copies in `bus2/` |
| A8 | The checklist (`PATTERNS.md`), with the changes above: bounded body reads, read and output budgets, linear parsers with hostile inputs in the fuel gate, the page has no parser, the stop and skip rule for resident guests | - |
| R1 to R4 | Runtime and Home, with Sasha's yes: the generic viewer route bound to the launch (missing 1), the viewer chosen by what it accepts (2), `requires[].cid` in the manifest (4), a typed UI document in the Bus v2 WIT (7) | - |

## How to check it

```bash
examples/docs-viewer/verify.sh
```

It runs the following, and ends with `docs-viewer capsule verification: OK`:

- the manifest check;
- fmt, clippy and the tests of the core, the model, the `ComponentProvider` host test, the bundle test and
  the Bus v2 part;
- the page tests and the Chromium smoke;
- all 52 falsifiers.

In this container it passes: 67 Rust tests (13 model, 26 guest, 12 host, 7 bundle, 9 Bus v2), 13 node tests,
52 falsifiers.

Fuel of the worst shelves in `ComponentProvider` (100,000,000 a run, gate 80%):

| Shelf | Fuel |
|---|---|
| The longest shelf, documents with the most spans | 52.9% |
| 8 documents with the most spans | 50.4% |
| 8 ordinary documents | 49.5% |
| 8 documents of brackets that never close | 39.4% |
| 8 documents of openers that never close | 33.1% |
| Shown to the output cap, then read to the reading cap | 22.6% |
| 8 documents read in full and then skipped | 16.3% |

These figures were measured in this cloud container. They are not guarantees.

## Principles checked

- **3 (no ambient authority).**
  - The core imports only the Bus and asks for one grant per object.
  - The page holds only its launch token.
  - The Bus v2 reader asks for one read grant per message.
- **10 (one path).**
  - The core reads only through `providers.invoke`.
  - The page makes one request, with one call site.
  - The reader stops only when its events close.
- **11 (fail closed, then explain).**
  - Authority failures stop with a named reason.
  - Content failures are listed with a code and a message.
  - Every check has a falsifier.
- **13 (objects vs capsules).** Documents are the person's objects. The core and the page are two capsules,
  each with one role.
- **15 (content-addressed).** Each closure is named by its CID, and the page names its core by CID. Runtime
  cannot carry that CID yet (missing 4).
- **16 (UI is not authority).** The page has no parser, no capability and no request but one. Links and
  images reach it as text.
- **18 (isolated instances).** Each run has its own budgets. A busy Bus v2 guest does not starve the reader.

## Not done

- **The Mac:** neither `verify.sh` nor the container build has run on the Mac.
- **Real Runtime and Home:** no Runtime route, no Home launch and no Library open for `docs-reader`
  (missing 1 and 2).
- **Credentials:** the Bus v2 reader checks none. Personal documents need none; a published document would
  need the photo guest's pinned-key check.
