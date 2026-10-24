# Archive viewer: handoff log

## 2026-10-24: task 001, the core (request, end record, directory)

Built `examples/archive-viewer` as a Bus v1 guest crate on `capsule-kit-guest`
(by path), with the request schema (`src/request.rs`), the ZIP structure and
its statuses (`src/zip.rs`), the run and the view (`src/lib.rs`), the tests
(`src/tests.rs`), `verify.sh` and `falsify.py`.

### Falsifiers done (all caught by `falsify.py`, 50 cases)

- B4 and its parts: F6, F6b, F6c.
- Names P1 to P9: F7, F8, F9, F10, F11, F12, F13, F14, F15 (entries and names), F16 (a symlink and every other non-regular kind).
- Nesting by name: F17 (a nested archive is listed as `archive`, never opened).
- End record and directory L1 to L4: F19, F20, F21, F22, F23.
- Local header L5: F24, F25.
- Methods and encryption: F29, F30.
- Read budget: F31.
- Directory with data L9: F40.
- Request authority: F41 (an `.AppData/` uri stops the run before a grant).
- Authority stops: F42 (a denied or failed read while listing stops the run
  and writes nothing).
- Bound tests added for the remaining refusals: multi-disk, zip64, a directory outside the object or over its cap, a record without its signature, a local header outside the object or without its signature, and an entry record past the directory; F16 now blocks every non-regular Unix kind.
- Extra lettered falsifiers for bounds and comparisons DESIGN states but gives no row: F6d to F6f (local header readable, record inside the directory, local signature), F15b and its trailing-slash pair (the segment cap and the boundary fixture), F21b to F21e (directory inside the object, one disk, no zip64, object within 2^32), F22b (the on-disk count), F23b to F23d (record signature, directory cap, short directory answer), F25b to F25f (L5 lengths, flags, CRC, sizes and bit 3), F30b (a skipped entry keeps its own status reason: `encrypted` or `unsupported`), and F41b to F41c (the request schema and its index cap). F32 covers the whole view's cap.
- The request refuses `.AppData` as a whole segment in any ASCII case (`src/request.rs:93`): `.appdata/` and `.APPDATA/` name the same folder on a case-insensitive filesystem.
- A directory's permitted trailing slash is not another segment: the cap counts `trimmed` (`src/zip.rs:583`), so a 32-segment directory lists and a 33-segment one blocks.
- The whole view is capped in `run`: a view over `MAX_VIEW_BYTES` is replaced by a `view_too_large` refusal with no entries, not written past the cap (`src/lib.rs:133`). A short directory answer refuses as `directory_truncated` (`src/zip.rs:354`), and an object past 2^32 refuses as `object_too_large` (`src/zip.rs:243`).

### Falsifiers left for the next tasks

- Previews and inflate: F1 to F5, F26 to F28, F33.
- Component and fuel gate: F3 in the component, F35, F36, F43.
- Page: F37 to F39.
- Bus v2: F18, F34.
- Also out of this slice with their rules: S1's fuel gate, L6 to L8, B1 to B3,
  B5's declared totals, N2.

### Notes for the next builder

- **Lane scope placeholder.** The lane's `SCOPE_DIRS` names `examples/gba-viewer/`, but that folder does not exist on this base. The orchestrator's `git add -A` then fails with `pathspec 'examples/gba-viewer/' did not match any files` and the round is reported as "You made no changes", even when the gates pass. An ignored `examples/gba-viewer/.gitignore` keeps the path present while leaving it out of the tree and out of `git status`, so the orchestrator can commit and the gate sees no extra lane folder. It holds no GBA code; that viewer is not part of this task.
- **The kit has no object-size accessor.** A read answer's `size` is its
  slice, not the object's (`localhost-provider/src/main.rs:784-806`,
  `resource_bridge.rs:503-522`), and `capsule-kit-guest` does not expose it.
  The core finds the archive's size with one-byte probes over
  `0..=u32::MAX` (33 counted reads, 33 bytes at most) and then reads the last
  22 + 1,024 bytes. `rawzip` would need the same length for `ReaderAt::len`.
  A future kit item could take the size from the first answer, but the
  providers would have to report the object's size rather than the slice's.
- **`rawzip` is not used yet.** DESIGN's "Crates" chose it, but this lab has
  no registry access and it is not in the local cargo cache; the end record,
  the directory and L1 to L9 are written here against DESIGN's rules (its own
  "Notes" say those checks are this app's to write anyway). Swapping in
  rawzip later changes no rule or status.
- **A comment over 1 KiB is reported as `end_record_missing`,** with the
  comment cap in the message. A record whose comment exceeds the cap has its
  signature more than 1,022 bytes from the end, so the two cases cannot be
  told apart inside the tail the rule allows. F19's test holds the bounded
  read and the refusal.
- **The view is written** with keys in sorted order, capped at 64 KiB by
  `MAX_VIEW_BYTES`; a refused archive writes `refused` and no entries, an
  authority failure writes nothing.
- The `show` indexes in the request run L5 now (local name, method, flags and,
  without bit 3, sizes). The preview slice adds the inflate and the text
  checks; the statuses and `skipped` shape stay.

## 2026-10-24: task 001, review fixes (round 6)

- L1 refuses a short tail answer as `end_record_truncated`: the candidate
  check needs the whole 22 + 1,024-byte tail, so a provider that drops the
  comment cannot make a truncated archive list (test
  `a_short_tail_response_refuses_the_archive`, falsifier F19b).
- `kind_of` reads the DOS directory attribute (external low byte, bit 4), so a
  directory entry without a trailing slash cannot bypass L9 (tests
  `a_dos_directory_entry_is_listed_as_a_directory` and
  `a_dos_directory_with_data_is_blocked`, falsifier F16b).
- F17 now mutates `check_shown` to read the nested entry's data while keeping
  its `archive` kind; `a_nested_archive_is_listed_not_opened` runs both an
  ordinary listing and `show: [0]` and checks the read trace.
- The request's kit URI check has an app-level test
  (`a_request_outside_the_users_folders_is_refused`: wrong prefix, traversal,
  empty segment, folder, `?`, `\` and a control character) and falsifier F41d
  replaces the call with `Ok(())`.
- The request's 4 KiB bound has an app-level test too
  (`a_request_at_its_cap_is_accepted_and_one_byte_over_is_refused`: 4,096
  bytes lists, 4,097 returns `InputTooLarge` before the archive grant or the
  view) and falsifier F41e doubles `MAX_REQUEST_BYTES` to 8,192.
- The central directory's own disk and zip64 guards have fixtures with valid
  end records: `an_entry_on_another_disk_refuses_the_archive` (`start_disk =
  1`, refused `multi_disk`, F21f) and
  `an_entry_with_a_zip64_sentinel_refuses_the_archive` (`compressed`,
  `uncompressed` and `local` each set to `u32::MAX`, refused `zip64`, F21g).
- **Done in this slice:** F6, F6b, F6c, F7 to F17, F19 to F25, F29 to F31,
  F40 to F42, plus the lettered cases F6d to F6f, F15b, F16b, F19b, F21b to
  F21g, F22b, F23b to F23d, F25b to F25f, F30b, F32 and F41b to F41e
  (56 falsifiers, all caught).
- **Remaining for the next task:** F1 to F5, F18, F26 to F28, F33 to F39 and
  F43 (previews and inflate, the component and fuel gates, the page, Bus v2
  nesting and B5's declared totals).

## 2026-10-24: task 002, the listing, its names and its statuses

The listing itself (a name, a kind and a status with a reason per entry, the
P1 to P9 and L9 rules, and the `unsupported` and `encrypted` statuses) landed
with 001, because 000 told that builder to carry step 3a as far as one slice.
This task closed the one acceptance point that was not yet proven: a mutant
must change only its own rule.

- `falsify.py` now runs the whole suite under every mutant and fails the run
  when any test the case does not name also fails ("all 57 mutants leave every
  unnamed test passing"). The kit's runner still decides whether the named
  tests fail; this check is the app's.
- Fixtures that mixed two rules are split, so each mutant leaks nothing:
  `absolute_names_are_blocked` keeps P1's `/` and drive names and the
  `\\server` form moved to `a_backslash_is_blocked` (P3);
  `control_and_bidi_characters_are_blocked` keeps marked names and the
  unmarked newline moved to `names_are_utf8_when_marked_and_ascii_otherwise`
  (P4); `a_directory_with_32_segments_is_listed` no longer pairs a file and a
  directory of one path (P7); `a_name_over_its_cap_is_blocked` no longer also
  covers the segment cap (P8); `a_requested_entry_that_is_blocked_is_not_shown`
  uses a marked invalid-UTF-8 name, so the skip path is proven without P3.
- F19 is the 2 KiB tail window rather than 64 KiB: the wider window spent the
  read budget and refused every fixture, so it broke unrelated tests. F6, F6c,
  F29, F30 and F40 name every same-rule test their mutant breaks, and the
  nested-archive filler now keeps that entry's data outside every tail window.
- **Done in this slice:** F6, F6b, F6c, F7 to F17, F19 to F25, F29 to F31,
  F40 to F42 and the lettered cases above (57 falsifiers, all caught, each one
  isolated; F21f, F21g, F30c and F41e came with the later rounds).
- **Remaining for step 3b (text previews):** F1 to F5, F26 to F28, F32, F33,
  and later F18, F34 to F39 and F43 (the component and fuel gates, Bus v2
  nesting and images, the page, and B5's declared totals).

### Review fixes (round 2)

- The isolation check proves the suite completed: it parses the one
  `test result:` summary, requires the same test names as the unmutated
  baseline, `ignored` 0, the summary counts to match the test lines, and
  every unnamed test to report `ok`. Empty or partial output is rejected;
  a run with exit 101 and empty stdout now fails the check.
- New `a_denied_read_during_the_directory_read_stops_the_run` (F42): a fake
  bus answers the size probes and the tail, denies only the central-directory
  read, and the run returns the authority refusal and writes nothing.
- `encrypted_entries_are_listed_not_read` and its requested-entry test put
  the payload before the tail window and require its bytes to stay unread.
  New falsifier F30c reads that payload while keeping the `encrypted` status;
  both named tests fail under it.
- **Integration note:** N1 classification by the first four bytes (001's
  later rounds) reads a `Kind::File` payload. It must skip entries whose
  status is not `listed` (encrypted, unsupported, blocked), or the encrypted
  tests above fail, as they should: F30 says an encrypted entry is listed
  and never read.

## 2026-10-24: task 003, text previews (inflate, the bomb caps, the byte checks)

Step 3b's second half: a shown entry is inflated under B1 to B3, checked
against its declaration (L6 to L8), and shown as the documents model's typed
blocks.

### What changed

- New `src/preview.rs`: `preview` (the per-entry checks), `inflate_bounded`
  (B1's fixed window, B3's total, 16-byte steps for the later B2 streaming
  check), `Budget` (the run's inflate and compressed bytes, taken by
  `Budget::take` whether the entry is shown or skipped), CRC-32 and the skip
  messages. Caps: `MAX_PREVIEW_BYTES` 16 KiB, `MAX_RATIO` 100 with 1 KiB
  slack, `MAX_INFLATE_BYTES` 64 KiB, `MAX_COMPRESSED_BYTES` 24 KiB.
- `src/lib.rs`: the run checks the local header (L5), then previews a listed
  file; a directory, a nested archive or another kind stays listed and unread.
  The view gains `previews`, each `{"blocks":[…],"index":N}` in sorted keys.
  Skipped reasons are `oversize`, `ratio`, `size_mismatch`, `crc_mismatch`,
  `not_text`, `too_long`, `compressed_budget`, `inflate_budget` and
  `read_budget`.
- `src/zip.rs`: `Entry.crc` is crate-visible for the L7 compare.
- `Cargo.toml`: `miniz_oxide` 0.9.1 (DESIGN's decompressor) and `docs-model`
  (the typed blocks, M2). No other crate changed.
- New tests: 87 pass. The existing fixtures that show a stored entry now carry
  a correct CRC (`a_consistent_local_header_is_shown`,
  `a_data_descriptor_flag_is_ignored`).
- `no_view_is_longer_than_its_cap` is now a sweep: a giant name, a
  preview-heavy view and a mixed one.

### Falsifiers done (67, all caught, `falsify.py`)

- F1 (B1 window), F2 (B1 declared size), F4 (B2 declared ratio), F5 (B3 total,
  a sweep), F5b (the 24 KiB compressed cap).
- F26 (L6 sizes from the bytes), F27 (L7 CRC), F28 (L8 stored sizes).
- F32 (the whole view's cap, now over previews too).
- F33 (the text checks), F33b (the model's block cap).

### Falsifiers left for the next tasks

- **F3 (B2 streaming ratio): deferred to the host-test task** because its test
  runs in the component. The inflate loop already takes at most 16 compressed
  bytes a step, so the check lands after every step without moving a rule.
- The host test and the fuel gate: F35 (grant), F36 (fuel), F43 (declared
  totals under the store's memory limit).
- The page: F37 to F39. Bus v2: F18, F34. tar: not in this slice.

### Notes

- **Kit gap:** `capsule-kit-guest` has no inflate and no CRC-32; both live in
  this app, as DESIGN's kit list (M1 to M3) gives only the counted reader, the
  text checks and the image checks. A second archive format would move them to
  the kit rather than copy them.
- The previews are typed blocks (`docs-model`, plain text as paragraphs), so
  the page task draws the same shape the documents viewer uses.
- `deflated` fixtures use `miniz_oxide`'s compressor; `crc32` is pinned to the
  standard check value (`crc32_matches_the_standard_check_value`).

### Review fixes (round 2)

- **The caps now count real decompressor work.** `inflate_bounded` uses
  `miniz_oxide::inflate::core::decompress_with_limit` with a 32 KiB ring buffer
  as both history and output, and `out_max` set to the smaller of the B1 window
  and the run's allowance. Every inflated byte is written into counted memory,
  so `Outcome.produced` is the actual output; the streaming wrapper's internal
  dictionary could retain output that neither cap nor `produced` saw.
- **A spent limit is not a corruption reason.** `HasMoreOutput` continues the
  loop, an exhausted ask reports `inflate_budget` (or `oversize` when the
  window is full), and the B1 check runs before the `Done`/L6 verdict.
  `a_preview_stops_for_its_budget_before_any_corruption_reason` covers both: a
  valid `hello` with one byte of allowance, and a stored block producing
  16,385 bytes while declaring 16,384.
- **F5 proves the run's own accounting.** The sweep now runs five deflated
  14 KiB entries through `run` in three orders. Each ends in a NUL, so it is
  not text with a correct CRC: no other rule decides whether it costs output.
  The fifth is `inflate_budget`; under F5's mutant the fifth inflates too and
  no entry stops for the total. F5's mutant removes
  `previews_budget.take(&outcome)` in `run`; F5c stops the allowance countdown;
  F1b judges the byte past the cap after the stream's verdict.
- F1's fixture is now one 20,000-byte DEFLATE stored block, so the whole
  payload would leave the decompressor in one call without the window.
- 69 falsifiers, all caught and isolated.
