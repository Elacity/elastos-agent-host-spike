# Archive viewer: design (no code)

The next app from the capsule kit: wave B, roadmap 2.6 ("move apps one at a time"). It replaces what
`capsules/archive-manager` does for reading: list an archive's entries and show a text entry inside it (image
entries on Bus v2). It is read-only. It never extracts anything to disk; extraction becomes a Runtime operation
the person approves, outside this app.

Branch `claude/photo-archive-design`, from `spike/photo-viewer` `cf4eab03`. Design only: no code, no Runtime
change. The code comes after #32 merges and the kit's shared crate exists (see [Order of work](#order-of-work)).

## In one paragraph

A WASM core reads one archive object through `providers.invoke`, with a grant for that one object, using the
offset and length read window. It never reads the whole archive. For a ZIP it reads the end record, the
central directory and one bounded local-header prefix for every entry, checks them against each other, and
lists every entry with a status. It checks and shows
at most a few small text entries, each read through its local header, inflated through a fixed
window, and checked against its declared size and CRC. Every cap is counted before any early return. It writes
one bounded view object that a render-only page draws. Nothing is extracted, and a nested archive is listed,
not opened.

## Contents

1. [Rong's four layers](#rongs-four-layers)
2. [What it does and does not do](#what-it-does-and-does-not-do)
3. [The shape of the app](#the-shape-of-the-app)
4. [Formats](#formats)
5. [Crates](#crates)
6. [Hostile archives](#hostile-archives)
7. [Limits and the fuel budget](#limits-and-the-fuel-budget)
8. [What the kit gives, and what it is missing](#what-the-kit-gives-and-what-it-is-missing)
9. [Falsifier plan](#falsifier-plan)
10. [Order of work](#order-of-work)
11. [Notes for the next builder](#notes-for-the-next-builder)
12. [Decisions](#decisions)
13. [Ready-PR note: the old routes](#ready-pr-note-the-old-routes)

## Rong's four layers

The layers as `examples/capsule-kit/PATTERNS.md` gives them after Rong's answer (22 Oct 2026), and how this
app meets each one.

| Layer | How the archive viewer meets it |
|---|---|
| **Own RTOS** | All archive parsing runs inside a fuel-metered component. Today the Runtime parses archives in its own process (`elastos-server/src/library.rs`, `zip` and `tar` crates); this app moves that work into the sandbox, which is the reason the roadmap gives for this app ("archive parsing is a classic attack surface"). On Bus v1 the run has the fixed 100,000,000 fuel, and the worst archive within the caps must use at most 80% of it. On Bus v2 the guest runs under fuel slices and the epoch deadline. There is no file system, clock or socket for the parser to reach. Rong's POSIX-compatible WASM inside the capsule (Wasmer as a proof of concept) is an open engine question; this app stays on Wasmtime. |
| **Trap down** | Every byte of the archive comes through `providers.invoke` with a grant for that one archive object, asked for with one action (`read`). The only write is the app's own view object, under its own grant and storage prefix. There is no extract operation: the capsule has no grant on Documents or Library to write to, and asks for none. A content failure skips one entry; an authority failure stops the run with a `bus-error` that names the resource. |
| **Component Model** | The core imports only `elastos:bus` (`types`, `runtime`, `capabilities`, `providers`), and admission checks it. The archive crates were built for `wasm32-unknown-unknown` and checked to add no import at all ([Crates](#crates)). |
| **Double-checking** | The core trusts no part of the archive. The end record, the central directory, each local header and the bytes that come out of the decompressor are each checked against the others: sizes, offsets, names, methods and CRC. A declared size is shown as declared, never used to size a buffer or to skip a check. The page checks the view's schema; Runtime checks every grant. The entitlement token check (pattern 7) is not needed: this is a free first-party viewer (below). |

### Capability and entitlement

Rong separates two checks (PATTERNS, "Two checks"). For this app:

| Check | Here |
|---|---|
| **Capability** (what the capsule may touch here) | All of it: the read grant on the one archive, the write grant on its own view object, the page's launch token. The local ElastOS Runtime gives and checks each one. Still missing on the capability side: the launch binding, so the core cannot yet check which archive it was opened on (M6). |
| **Entitlement** (whether this user may use it) | None needed: the archive viewer is a free first-party viewer. If a vendor ever sold one, it would take pattern 7: a token from the user's wallet, signed by the vendor, a marketplace or a dKMS (never by the local ElastOS), checked by the Capsule Runtime inside the capsule against issuer keys sealed in its bundle. |

The bundle and the build follow the clean design house: the pinned container build and publisher signing
(PATTERNS 3 and 4).

## What it does and does not do

Does:
- list the entries of one ZIP archive: path, kind, declared sizes, method, and a status per entry (shown,
  listed, unsupported, encrypted, blocked) with a reason;
- show up to a few small text entries (UTF-8, the documents viewer's text checks), each checked whole before
  it is shown. Image entries are listed; image previews wait for Bus v2 and the typed UI document (decision 4);
- list a nested archive as an entry of kind `archive`.

Does not:
- extract an entry to disk, Library or any object other than its own view. Extraction stays, but not in this
  app: it writes to the person's storage, so it becomes a Runtime operation the person approves, which the
  capsule cannot reach (decision 1);
- decode a method other than stored (0) and deflate (8), or anything encrypted;
- open a nested archive (Bus v1), or one that is not stored (Bus v2);
- follow a symlink entry, or treat an entry name as a path anywhere.

## The shape of the app

Two capsules, as in the photo and documents viewers (principle 13):

| Capsule | Role | Runs as | Holds |
|---|---|---|---|
| `archive-viewer` | `app` | a WASM component | a read grant for the one archive; a write grant for its own view object |
| `archive-reader` | `viewer` | a render-only page | its launch token, nothing else |

**Input.** The Bus v1 Component ABI has no input, so, as for the documents shelf, the archive to open is named
in a principal-scoped request object at a fixed path (`.AppData/App/archive-viewer/open.json`, schema
`elastos.archive-viewer.open/v1`, one `uri` under `Users/self/`, and optionally the entry indexes to show).
The request's `uri` must also lie outside `.AppData/`: the prefix `localhost://Users/self/` alone would take
this app's own view object and another app's AppData, so an `.AppData/` request stops the run with a `bus-error`
that names the request, before any grant is asked for or any archive byte is read (F41).
Who writes it is a missing piece: Home binds a launch only for `image-viewer` today (kit, "What was missing" 2).

**Output.** One view object, `.AppData/App/archive-viewer/view.json` (schema `elastos.archive-viewer.view/v1`),
written once and whole, with sorted keys, capped as a whole (PATTERNS 1, "cap the whole output"):
- `archive`: the URI and its size;
- `entries`: index, path (text), kind, declared sizes, method, status, reason;
- `previews`: for each shown entry, the docs-model typed blocks of its text;
- `skipped`: entries the request named that could not be shown, with a reason code and message.

**Bus v1 run.** One run lists the archive and shows at most the requested entries (or, with none named, the
first few that can be shown), within the budget below.

**Bus v2 run.** A resident guest in the Bus v2 proof's host: it lists once, draws the listing with
`ui.present`, and shows an entry when a `user-input` event names it. It never holds more than one entry's
bytes. Image previews come here, once the typed UI document exists: today `ui.present` draws images by granted
handle only, and an image that comes out of an archive has no handle
([Missing](#what-the-kit-gives-and-what-it-is-missing), M5).

**The page.** It draws the listing and the previews with `textContent` only; text previews use the documents
viewer's block kinds. It never builds a path, never fetches an entry, shows `path` fields as text only, and
draws no image on Bus v1.

## Formats

| Order | Format | Why |
|---|---|---|
| 1 | **ZIP**, stored and deflate only | The central directory lists every entry without reading or inflating any of them, and each entry can be reached by offset: it fits the read window. It is also the most common format in Library and the one with the most known tricks. |
| 2 | **tar** (uncompressed) | No directory: listing walks a 512-byte header per entry. On Bus v1 each header costs about 212,000 fuel to read, so a run can list only about 64 entries. Worth doing after ZIP, with the same path and size rules. |
| 3 | **tar.gz, .gz** | No random access: listing means inflating from the start. Only with Bus v2 streams, and only up to a fixed decompressed total, with the listing marked as cut short. |
| - | 7z, rar, xz, bz2, zst | Listed by today's capsule as "unsupported family"; the same here. Each is a new decoder in the sandbox; none is needed for a first app. |

Within ZIP: no zip64 (refused as `unsupported` in the first version: a first app does not need archives over
4 GiB or 65,535 entries), no multi-disk archives, no encryption (traditional or AES, listed as `encrypted`).

## Crates

Each candidate was built in this container with Rust 1.91.0 for `wasm32-unknown-unknown` (`opt-level = "s"`,
LTO), from a small probe that calls its read path. The import section of every probe module was then read: none
has any import, so none would add a WASI or host import to the component. Sizes are of the probe module.

| Crate | Version | Licence | Dependencies (wasm32) | Imports | Probe size | Use |
|---|---|---|---|---|---|---|
| **rawzip** | 0.5.2 | MIT | none | none | 15.5 KB | **Chosen** for the ZIP structure. Zero dependencies, `#![forbid(unsafe_code)]`, `no_std` capable. It reads through a `ReaderAt` trait (read N bytes at an offset), which maps onto the Bus read window, and lets the caller bring the decompressor. It has CRC-32 built in. |
| **miniz_oxide** | 0.9.1 | MIT OR Zlib OR Apache-2.0 | adler2 (0BSD OR MIT OR Apache-2.0) | none | 26.4 KB | **Chosen** to inflate. Streaming inflate into a caller's fixed buffer, so the core counts every output byte and stops at its cap mid-stream. Pure Rust, `no_std` with `alloc`. The Runtime already uses it (through flate2). |
| zip | 9.0.5 | MIT | 13 crates (flate2, miniz_oxide, indexmap, hashbrown, typed-path, memchr, ...) | none | 137 KB | Not chosen: wants `Read + Seek` over the archive, builds the whole directory in memory, and ties in its decompressor, so a cap is outside it rather than in the loop. The Runtime uses 2.4.2 today. |
| flate2 | 1.1.10 | MIT OR Apache-2.0 | miniz_oxide, crc32fast, adler2, simd-adler32 | none | 66.4 KB | Not needed: a `Read` wrapper over miniz_oxide. Would be the gzip reader for format 3. |
| tar | 0.4.46 | MIT OR Apache-2.0 | filetime, cfg-if | none | 55.9 KB | For format 2, or a small ustar reader of our own (the format is a fixed 512-byte header). Decide when tar is built. |
| unicode-normalization | 0.1.26 | (MIT OR Apache-2.0) AND Unicode-3.0 | tinyvec (Zlib OR Apache-2.0 OR MIT) | none | 145.8 KB | **Not used** (decision 3). It would only serve a collision check, which belongs to the extraction operation. |

The builds and checks were throwaway probes in the scratchpad, not in this branch.

## Hostile archives

Each rule says what the core does. "Blocked" means the entry is listed with a reason and never read or shown;
"refused" means the whole archive is shown as not readable, with the reason, and no entry is listed as safe.

### Zip bombs

Measured here (Wasmtime 36, the Runtime's version): inflating text costs about 30 fuel per output byte, but
inflating a run of zeros costs only about 1.3, and a stored copy almost nothing. Wasmtime charges fuel per
instruction, so one bulk memory copy costs the same fuel whatever its length. **Fuel alone cannot stop a
bomb**; the caps below do, and they are counted in the inflate loop, not taken from the archive.

- **B1, preview size cap.** An entry is shown only if its declared uncompressed size is at most 16 KiB. The
  decompressor writes into a fixed 16 KiB window plus one byte: the first byte past
  the cap stops it, and the entry is skipped `oversize`.
- **B2, ratio cap.** Output may never pass 100 times the compressed bytes consumed so far (plus 1 KiB of slack
  for tiny entries). Checked after every inflate step; past it, the entry is skipped `ratio`. A declared ratio
  over 100 is not even read. Text compresses about 7:1 here; a 16 KiB run of zeros about 800:1.
- **B3, total inflate cap.** All entries shown in one run inflate at most 64 KiB in all, counted as it comes out,
  whether the entry is then shown or skipped (PATTERNS 1, "count before any early return").
- **B4, overlapping entries.** Two entries whose whole records overlap (one compressed stream reused by many
  directory records, the "non-recursive" bomb) refuse the archive. The directory alone cannot give a range:
  where the data starts depends on the local header's own name and extra lengths, which only that header
  holds. So the listing is accepted only after one bounded local-header check for every entry (B4a), before
  any entry is listed as safe: read the 30-byte fixed header at the directory's local offset (cap: 256 × 30
  bytes, 7,680 bytes in all, counted), check its signature, and take `name_len` and `extra_len` from it.
  Then `data = local_offset + 30 + name_len + extra_len` and `end = data + compressed_size`. Each entry owns
  the whole record `[local_offset, end)`: its local header, its extra field and its compressed data. Records
  sorted by `local_offset` must not overlap, `data` must not exceed `end`, and every `end` must not pass the
  directory offset. The payload `[data, end)` alone is not enough: a record that starts inside another
  entry's header or extra field overlaps it even when the two payloads are disjoint (F6c). The name bytes
  are not read here; only a shown entry reads them (L5), which must then agree with the lengths this check
  used. A local header that cannot be read inside the object refuses the archive. The directory's name and
  extra lengths never stand in for the local ones: two archives with identical directories and end records
  can still overlap when a local extra field grows (F6b).
- **B5, declared totals are display only.** The sum of declared sizes is shown as declared. It never sizes a
  buffer and never decides that something is safe. Listing a 2 GB archive costs the same as listing a small
  one, because no entry is inflated to list it.

### Path tricks

A name is shown as text, never used as a path. The rules decide its status:

- **P1, absolute names**: a leading `/` or `\`, a drive (`C:`), or `\\server` is blocked.
- **P2, `..`, `.` and empty segments** (`a//b`) are blocked. A trailing `/` is allowed only on a directory entry.
- **P3, a backslash** anywhere is blocked (it is a separator on Windows and a character elsewhere).
- **P4, characters**: NUL, any other control character, and the bidirectional controls (U+202A to U+202E,
  U+2066 to U+2069, which can make `txt.exe` read as `exe.txt`) are blocked. A name marked UTF-8 (flag bit 11)
  must be valid UTF-8; an unmarked name must be printable ASCII, else blocked.
- **P5, duplicates**: two entries with the same name after the P1 to P3 rules are both blocked `duplicate`:
  which one a reader sees depends on the reader.
- **P6, look-alike names** (names that differ only in case or in Unicode composition) are both listed, each
  under its own name, and each can be shown. Read-only means a look-alike cannot overwrite anything; the
  collision check belongs to the extraction operation (decision 3). No case folding and no
  `unicode-normalization` in the viewer.
- **P7, a file and a directory** of the same path (`a` and `a/b`) are both listed, for the same reason.
- **P8, size**: a name over 255 bytes or 32 segments is blocked; an archive over 256 entries is refused as
  `too_many_entries` (the directory cap, below, comes first).
- **P9, kinds**: only regular files and directories are listed as such; a symlink (Unix mode in the external
  attributes) or any other kind is blocked.

### Nested archives

- **N1, depth cap.** On Bus v1 the depth is 0: an entry that is an archive (by its first bytes, `PK\x03\x04`, or by
  name, `.zip`, `.tar`, `.gz`, ...) is listed as kind `archive`, never opened. Opening it would mean extracting it.
- **N2, Bus v2.** A nested ZIP may be opened only if it is stored (method 0), because then it is a byte range of
  the outer object and the same read window reaches it without extracting anything. The depth cap is 2, and
  each level has its own caps inside the outer run's caps.

### Slow decompression

- **S1, Bus v1.** The run has fixed fuel and a trap is an authority-looking stop, so a content failure must
  never trap (PATTERNS 1). B1 to B3 bound the inflate work; the fuel gate (below) runs the worst archive of each
  hostile class through the real `ComponentProvider` and requires at most 80%.
- **S2, Bus v2.** Inflate runs in slices that yield; a stop during an inflate ends the run as cancelled; the
  epoch backstop ends one that never yields (the Bus v2 proof's limits).
- **S3, memory.** The inflate state is about 43 KiB (43,296 bytes, measured natively: a 32 KiB dictionary plus
  tables) and the output window
  16 KiB; the core holds at most one entry's bytes at a time.

### A central directory that lies

- **L1, end record.** It is searched for only in the last 22 + 1,024 bytes (a comment over 1 KiB is refused,
  `comment_too_long`). Exactly one valid end record must be there, and its comment must run exactly to the end
  of the object; two candidates refuse the archive (`ambiguous_end`).
- **L2, directory bounds.** The directory's offset plus size must lie inside the object and end exactly where the
  end record begins. No gap, no overlap. Disk numbers must be 0.
- **L3, counts.** The number of records parsed must equal both counts in the end record.
- **L4, records.** Each directory record must have its signature, and its name, extra and comment lengths must
  fit inside the directory.
- **L5, local header.** Before an entry is shown, its local header is read: the signature, the name byte for byte,
  the method and the flags (except bit 3) must equal the directory's; without a data descriptor (bit 3), the local
  CRC and sizes must equal the directory's too. The local extra field must fit before the data, and the local
  name and extra lengths must equal the ones B4a used to place the range, else the entry is skipped.
- **L6, sizes from the bytes.** Inflating must end (`StreamEnd`) exactly within the declared compressed size, and
  produce exactly the declared uncompressed size: one byte more or less skips the entry `size_mismatch`.
- **L7, CRC.** The CRC-32 of the output must equal the directory's, else the entry is skipped `crc_mismatch`.
- **L8, stored entries.** For method 0 the compressed and uncompressed sizes must be equal.
- **L9, directories.** A directory entry must have size 0; one with bytes is listed `blocked` with reason
  `directory_with_data`, and its bytes are never read. A trailing `/` is its only name allowance (P2).

A refused archive (L1 to L4, B4, P8 count) is a content failure of the whole archive: the view is written with
the reason and no entries. Only an authority failure (no grant, a refused or failed call) stops the run without
writing.

## Limits and the fuel budget

Bus v1, one run, 100,000,000 fuel, gate 80%. Read costs about 415 fuel a byte (measured for the photo viewer);
write about 200 a byte (estimated for the documents viewer, and higher with the shared write path: the gate
decides); inflate 30 and CRC 8.3 a byte (measured here).

| Step | Cap | Estimated fuel |
|---|---|---|
| End record and comment | 22 + 1,024 bytes | 0.4 M |
| Central directory | 16 KiB, 256 entries | 6.8 M |
| Local header prefix of every entry (B4a) | 256 × 30 bytes | 3.2 M |
| Local headers of shown entries (L5) | 8 entries, at most 350 bytes each | 1.2 M |
| Compressed data of shown entries | 24 KiB in all, counted on every read | 10.2 M |
| Inflate | 64 KiB out in all (B3) | 2.0 M |
| CRC | 64 KiB | 0.5 M |
| Text checks, docs-model blocks | the shown entries | measure |
| View object | 64 KiB in all: listing at most 24 KiB, previews the rest | 13 to 26 M |
| **Total** | | **about 38 to 53 M**, under the 80 M gate with room for parsing |

This budget would leave room for at most one 16 KiB image a run, which is why images wait for Bus v2
(decision 4). Bus v2 streams remove the JSON byte arrays, so its caps are set again from measurements there,
not carried over.

## What the kit gives, and what it is missing

**Given by the kit** (`examples/capsule-kit`, after #32 and #35):

| Need | Kit item |
|---|---|
| The Bus calls, the read window, the write, the refusals and reads, the URI check, the fake Runtime, the WIT glue | A1 the guest crate `guest/` (`capsule-kit-guest`): `bus`, `read`, `uri`, `fake`, `component`, `wit` |
| The `ComponentProvider` run, admission import check, fuel gate | A2 `v1-host-test` (`Bridge`, `run`, `admission`, `measure`) |
| Manifest check, pinned container build | A3 `scripts/check-manifest.py`, `repro/build-in-container.sh` |
| One falsifier per rule, `--check` | A4 `falsify/falsify_kit.py` |
| Page tests and the Chromium smoke in Home's sandbox | A5 `surface/test-kit.mjs`, `surface/stand-in.mjs` |
| Both capsules packed, named by CID, admitted | A6 `capsule-bundle pack`, `capsule_bundle::testing` |
| Resident guest, stop, slices, epoch | A7 the Bus v2 proof's host and helpers |
| The rules this design follows | A8 `PATTERNS.md`, including the (review) rules |

**Missing for this app:**

| # | What | Why it matters here | Where it belongs |
|---|---|---|---|
| M1 | A counted positioned reader | rawzip reads through `ReaderAt`; every byte it reads must be counted against the budget before anything returns | **Done in #35:** `capsule_kit_guest::read_counted`. Still to write, in this app: the `ReaderAt` adapter over it (see [Notes](#notes-for-the-next-builder)) |
| M2 | The text checks as a kit item | text entries are checked exactly as documents are | **Done in #35:** `capsule_kit_guest::text` (`check_head`, `check_whole`). The typed blocks are still `docs-model` (markdown to blocks), not the kit |
| M3 | The image header checks as a kit item | image previews on Bus v2 need the same checks, on bytes from the decompressor instead of the object | **Done in #35:** `capsule_kit_guest::image` (`sniff`, `header_dimensions`, `jpeg_dimensions`, `HEADER_BYTES`); the dimension caps stay the photo viewer's constants |
| M4 | Hostile-archive fixtures: a builder for ZIPs that lie (wrong counts, overlapping ranges, local and directory names that differ) | none of the kit's fixtures are archives, and real tools refuse to write these | test support in this app, then the kit if a second format needs it |
| M5 | A way to present bytes the guest produced as an image on Bus v2 | `ui.present` takes images by granted handle only | the draft Bus v2 WIT (Anders) |
| M6 | The launch binding: which archive was opened, in the signed launch context, and the generic viewer route | the core reads a fixed request object today; the page has only the stand-in server | Runtime and Home (kit "missing" 1, 2 and 6); a capability check, not pattern 7 |
| M7 | Deleting the native listing and preview routes for `archive-manager`, and making extraction a Runtime operation the person approves | "Move" means the old version goes in the same change | the real move PR after 0.8.0 ([ready-PR note](#ready-pr-note-the-old-routes)) |

## Falsifier plan

One falsifier per limit and per rule: an exact text change in the source that must compile, and named tests
that must then fail (PATTERNS 5). Each test uses a fixture built to break exactly that rule. Runtime falsifiers
rebuild the component and run in `ComponentProvider`.

| # | Rule | Mutant | Test that must fail |
|---|---|---|---|
| F1 | B1 preview cap | the window grows to 64 KiB | `an_entry_over_the_preview_cap_is_skipped_after_one_byte_past_it` |
| F2 | B1 declared size | the declared size is not checked first | `an_entry_declared_over_the_cap_is_not_read` |
| F3 | B2 ratio | the streaming ratio check is removed (the declared-ratio check stays) | `a_bomb_entry_stops_at_the_ratio_cap` (in the component: a declared 10,000-byte entry with 100 compressed bytes, so the declared ratio is exactly 100 and F4's check passes and inflation starts. A crafted stream yields about 3,100 bytes from its first 20 bytes, past 100 × 20 + 1 KiB = 3,024, and its 100 bytes end at exactly 10,000. The test asserts status `ratio`, that the stop came mid-stream, and that the output count at the stop is at least 1 KiB, so it also proves inflation ran. Without the streaming check the entry inflates to 10,000 and lists, so both the status and the count fail) |
| F4 | B2 declared ratio | the declared ratio is not checked | `an_entry_declared_past_the_ratio_is_not_read` |
| F5 | B3 total inflate | output of skipped entries is not counted | `no_run_inflates_more_than_its_total` (sweep) |
| F6 | B4 overlap | the range check is removed | `entries_that_share_data_refuse_the_archive` |
| F6b | B4 local extra | the local extra length is ignored and the data start comes from the directory (`local_offset + 30 + name_len`) | `entries_that_overlap_only_after_the_local_extra_field_refuse_the_archive` (two archives with identical directories and end records; the first local extra grows from 0 to 64 bytes so its record covers the second) |
| F6c | B4 record boundary | the overlap check uses only the payload `[data, end)`, not the whole record `[local_offset, end)` | `entries_that_share_a_local_header_region_refuse_the_archive` (two records with `(local_offset, data, end)` of `(0, 95, 103)` and `(35, 66, 74)`: the second sits inside the first entry's extra field, and only the payloads are disjoint) |
| F7 | P1 absolute | `/` and drive names pass | `absolute_names_are_blocked` |
| F8 | P2 dot segments | `..` passes | `dot_and_empty_segments_are_blocked` |
| F9 | P3 backslash | backslash passes | `a_backslash_is_blocked` |
| F10 | P4 control and bidi | the bidi range is dropped | `control_and_bidi_characters_are_blocked` |
| F11 | P4 encoding | an unmarked non-ASCII name passes | `names_are_utf8_when_marked_and_ascii_otherwise` |
| F12 | P5 duplicates | duplicates keep the first | `duplicate_names_are_both_blocked` |
| F13 | P6 look-alikes | look-alikes are merged by a lower-cased key | `names_that_differ_only_in_case_are_both_listed` |
| F14 | P7 file and directory | the directory hides the file of its path | `a_file_and_a_directory_of_one_path_are_both_listed` |
| F15 | P8 name and count caps | the caps are doubled | `a_name_over_its_cap_is_blocked`, `too_many_entries_refuse_the_archive` |
| F16 | P9 kinds | the mode check is removed | `a_symlink_entry_is_blocked` |
| F17 | N1 depth | a nested ZIP is opened | `a_nested_archive_is_listed_not_opened` |
| F18 | N2 depth (Bus v2) | the depth cap is 3 | `nesting_past_two_is_not_opened` |
| F19 | L1 comment | the tail search reads 64 KiB | `a_comment_over_1_kib_refuses_the_archive_without_reading_it` |
| F20 | L1 ambiguous end | the last candidate wins | `two_end_records_refuse_the_archive` |
| F21 | L2 bounds | the gap check is removed | `a_directory_that_does_not_end_at_the_end_record_refuses_the_archive` |
| F22 | L3 counts | the count is taken from the end record | `a_count_that_differs_from_the_records_refuses_the_archive` |
| F23 | L4 record lengths | lengths are not bounded | `a_record_that_runs_past_the_directory_refuses_the_archive` |
| F24 | L5 local name | the name compare is removed | `a_local_name_that_differs_skips_the_entry` |
| F25 | L5 local method and sizes | the method compare is removed | `a_local_header_that_differs_skips_the_entry` |
| F26 | L6 size from bytes | output stops at the cap, not at the declared size | `an_entry_longer_or_shorter_than_declared_is_skipped` |
| F27 | L7 CRC | the CRC compare is removed | `a_crc_mismatch_skips_the_entry` |
| F28 | L8 stored sizes | the stored compare is removed | `a_stored_entry_with_two_sizes_is_skipped` |
| F29 | Method | method 12 is treated as stored | `other_methods_are_listed_unsupported` |
| F30 | Encryption | flag bit 0 is ignored | `encrypted_entries_are_listed_not_read` |
| F31 | Read budget | a read is not counted | `every_read_counts_toward_the_budget` (sweep, PATTERNS review rule) |
| F32 | Output cap | only previews are capped | `no_view_is_longer_than_its_cap` (sweep) |
| F33 | Text checks | the whole-text check is removed | `a_text_entry_that_is_not_text_is_skipped` |
| F34 | Images (Bus v2) | the header check is removed | `an_entry_named_png_that_is_not_one_is_not_drawn` |
| F35 | Grant | the archive read uses no grant (in the component) | `no_grant_stops_the_run_through_the_runtime` |
| F36 | Fuel | the counted reader asks for one byte per call and the inflate loop copies the window per output byte (measured fuel regressions; they change no rule and no output) | `worst_archives_stay_under_80_percent_of_the_runtime_fuel` (the gate records the highest measured fuel under the mutant and requires it above 80%) |
| F37 | Page | a path is drawn as markup | `an_entry_path_is_text` |
| F38 | Page (Bus v1) | an image entry is drawn | `the_page_draws_no_image_on_bus_v1` |
| F39 | Page | an inherited property name picks a kind | `a_kind_named_after_an_inherited_property_is_not_drawn` |
| F40 | L9 directory | a directory's size is not checked | `a_nonempty_directory_is_blocked_and_the_valid_entry_still_lists` (one archive with a nonempty directory and a valid text file: the directory is listed `blocked` with `directory_with_data`, and the text file keeps its listing and preview; the run writes a view, it does not refuse the archive) |
| F41 | Request URI | the `.AppData/` refusal is removed | `a_request_for_an_appdata_uri_is_refused` |
| F42 | ReaderAt authority | a denied read is folded into an `io::Error` and becomes a content skip | `a_denied_read_during_the_directory_read_stops_the_run` |
| F43 | B5 declared totals | the sum of declared sizes sizes a buffer | `a_declared_two_gigabyte_archive_is_listed_with_the_same_reads_as_a_small_one` |

F40 to F42 give the three rules the review named a mutant and a test: L9 is F40, the request's `.AppData/`
refusal is F41, and the `ReaderAt` adapter's authority rule is F42. F43 covers B5, the last rule that had no
row. Each mutant changes only its own rule, so each named test fails independently. F3 runs in the component
and asserts the ratio status and the output count, so it does not depend on the fuel gate. F36's mutant adds
fuel cost only and changes no rule: the gate's measured fuel must cross 80% under it. The Bus v2 limits (S2
and the resident guest's S3) are tested with that proof when its guest is built.

The fuel gate (F36) runs one archive per hostile class at its caps: the largest directory, the most names at
their longest, the most shown entries, a bomb at the ratio cap, a text entry of the worst inflate cost, and the
largest view. F3 is not the fuel proof.

## Order of work

1. #32 merges.
2. Done in #35: the kit's guest crate (`examples/capsule-kit/guest`), with the counted reader, the text checks
   and the image header checks (M1 to M3), and the one photo hash change.
3. Then this app, Bus v1 first, in `examples/archive-viewer`:
   - the core: request, end record, directory, listing, B4a and the statuses, all P and L rules, with tests and
     falsifiers F6, F6b, F6c, F7 to F25, F29 to F31 and F40 to F43;
   - text previews: inflate with B1 to B3, L6 to L8, the text checks; F1, F2, F4, F5, F26 to F28, F32, F33;
   - the host test in `ComponentProvider` and the fuel gate; F3 (ratio), F35 and F36;
   - the page and its smoke; F37 to F39;
   - the bundle and the container build;
   - then the Bus v2 guest in the proof's host, with N2 and F18; image previews (F34) once the typed UI
     document and M5 exist.
4. tar after ZIP is shown on both buses.

## Notes for the next builder

Written on 23 Oct 2026, when the Photo track moved to its own lane. Read with `examples/capsule-kit/CRATE-REPORT.md`
("Notes for the next builder" there holds the kit-wide traps).

### Start from the kit's crate

- Depend on `capsule-kit-guest` by path: `features = ["wit"]` in `[dependencies]`, `features = ["fake"]` in
  `[dev-dependencies]`. Copy the shape of `examples/docs-viewer/Cargo.toml` and `src/lib.rs`.
- Name the app once: `pub const APP: App = App { name: "archive-viewer", input: "request", max_input_bytes: … }`.
  `Refusal::message(&APP)` and `to_bus_failure(&APP)` take it.
- The export is nine lines: implement `capsule_kit_guest::wit::exports::elastos::bus::lifecycle::Guest`, call
  `capsule_kit_guest::component::lifecycle_run(&APP, |bus| run(bus).map(|_| ()))`, and export with
  `capsule_kit_guest::wit::export_lifecycle!(… with_types_in capsule_kit_guest::wit)`. The macro is in the
  `wit` module, not at the crate root.
- A Bus v2 guest takes the crate with `default-features = false` (text, image and URI checks only), so no Bus v1
  binding reaches it.

### Traps in this app's own code

- **The `ReaderAt` adapter.** rawzip's `ReaderAt::read_at(&self, …)` takes `&self` and returns
  `std::io::Result`. So the adapter needs interior mutability over the Bus and the budget (a `RefCell`), and:
  - it must never call `read_counted` with more than is left: `read_counted` asserts that, and a panic in the
    guest is a trap, which the Runtime sees as a stop. Clamp the ask to what is left, and when nothing is left
    return an error that the core turns into a content skip with its reason (a read budget spent), not a trap;
  - it must keep a `Refusal` (an authority failure) aside and return it after rawzip gives up. If the refusal
    is folded into an `io::Error`, a denied read becomes a skipped entry, which breaks the stop/skip rule.
    Test it: `a_denied_read_during_the_directory_read_stops_the_run` (F42).
- **rawzip's own checks are not the design's checks.** It parses; L1 to L9 and P1 to P9 are still this app's
  to write and test. I did not check what rawzip's `try_normalize` accepts; test P1 to P4 against this app's
  own rules, not against it.
- **The request's URI prefix.** `check_object_uri(uri, prefix)` takes one prefix. `localhost://Users/self/` alone
  would also take the app's own `.AppData/App/archive-viewer/view.json` and any other app's AppData. Refuse
  `.AppData/` explicitly (or take a fixed list of the person's folders) and test it:
  `a_request_for_an_appdata_uri_is_refused` (F41).
- **Fuel.** The kit's write is the cheap one now, but the view still costs about 200 fuel a byte on Bus v1.
  Measure the budget table in [Limits](#limits-and-the-fuel-budget) with the real gate before trusting it.
- **Fixtures (M4).** Real zip tools refuse to write archives that lie. Build them byte by byte in a test-only
  module (rawzip's writer can make the good ones), one fixture per rule, so each falsifier has exactly one test.

### Which falsifiers belong together

Build them in these groups; each group shares fixtures and a test helper, and lands in one slice:

| Group | Falsifiers | Shares |
|---|---|---|
| Directory and end record | F19 to F23 (L1 to L4), F6, F6b and F6c (B4 overlap) | the end-record and directory fixture builder; all refuse the whole archive |
| Names | F7 to F16 (P1 to P9) | one fixture with many names; a table test per rule |
| Entry status | F40 (L9) | one archive with a nonempty directory and a valid text file; the directory is blocked and the file still lists |
| Request | F41 | the request fixture with an `.AppData/` uri; the run stops before a grant |
| Methods and encryption | F29, F30 | a directory-only fixture; nothing is inflated |
| Local header and the bytes | F24, F25 (L5), F26 to F28 (L6 to L8) | an entry fixture whose local header or data is changed after the fact |
| Authority stops | F42 | the fake Runtime denies the directory read; the run stops and writes nothing |
| Bomb caps | F1 to F5 (B1 to B3) | the inflate loop; F5 is a sweep (many entries, every order), like the docs viewer's budget sweeps; F3 also runs in the component |
| Budgets | F31 (reads), F32 (the whole view), F43 (declared totals) | sweeps over shelves of mixed entries; they must also cover entries skipped after reading |
| Text | F33 | the kit's text checks through this app's run |
| Nesting | F17 (Bus v1), F18 (Bus v2) | a stored inner ZIP fixture |
| In the component | F3 (ratio), F35 (grant), F36 (fuel gate) | `--runtime`: the component is rebuilt for each case |
| Page | F37 to F39 (Bus v1); F38 becomes "no image drawn" | the kit's page test kit and stand-in |
| Bus v2 images | F34 | waits for M5 and the typed UI document (decision 4) |

### Gaps that stay open

- M4 (lying-archive fixtures) is this app's to build; M5 (image bytes on Bus v2), M6 (launch binding, generic
  viewer route) and M7 (old routes, extraction as a Runtime operation) are not the lane's: they need Anders,
  the Runtime or the real move PR.
- Pattern 7 (entitlement) does not apply: a free first-party viewer.
- Native builds differ by checkout path; record the pinned-container hash only (`CRATE-REPORT.md`,
  "Reproducible build"). A shared `examples/` workspace that would fix it is a proposed slice, not built.

## Decisions

Sasha, 22 Oct 2026, on #34:

1. **Extraction stays, but not in this app.** It writes to the person's storage, so it becomes a Runtime
   operation that the person approves, which the capsule cannot reach. The viewer stays read-only.
2. **The old routes** are deleted in the real move PR after 0.8.0, in the same change. In the spike they are a
   ready-PR note (below).
3. **Look-alike names: no `unicode-normalization` in the viewer.** Read-only means look-alikes cannot overwrite
   anything; the collision check belongs to the extraction operation. Both names are listed (P6, P7).
4. **Images on Bus v1: text first.** Image previews wait for Bus v2 and the typed UI document.

## Ready-PR note: the old routes

For the real move PR after 0.8.0, not for the spike. In one change:

- delete the native archive listing and preview in `elastos/crates/elastos-server/src/library.rs`
  (`archive_entries_for_object`, `archive_preview_entry_for_object` and the ZIP and tar listing and preview
  helpers), and the `archive-manager` branches of `viewer_gateway.rs` that serve them;
- keep extraction, as a Runtime operation the person approves (decision 1). It is not reachable from the
  viewer capsule. The collision check (case, Unicode composition, file and directory of one path) moves with
  it, because only extraction can overwrite;
- replace `capsules/archive-manager` with the two capsules here, named by CID;
- the old journeys are the gate: the Library open, listing and preview journeys pass on the new capsules, and
  the extraction journey passes on the Runtime operation.
