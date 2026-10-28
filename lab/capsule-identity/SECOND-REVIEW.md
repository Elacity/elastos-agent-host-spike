# Second review of three one-reviewer merges

- PR #234 (task 019), merge d44f2d30d: Verdict: PASS (runner at the base: `summary: 10 CAUGHT of 10`)
- PR #244 (task 020), merge f26d5d036: Verdict: PASS (runner at the base: `summary: 6 CAUGHT of 6`)
- PR #247 (task 021), merge 6fe61d88e: Verdict: FOLLOWUP (citations: 69 checked, 69 match)
- FOLLOWUP: lab/capsule-identity/GAP-REPORT.md:848 says the lab "sits in no admission or launch path", but since task 032 (PR #587, merge 58fe29b8a) README says only "no Runtime admission or launch path" and that the lab's stand-in launcher, in test code, calls it; hand check: `sed -n 845,849p lab/capsule-identity/GAP-REPORT.md` against `sed -n 14,17p lab/capsule-identity/README.md`, and `git show 58fe29b8a^1:lab/capsule-identity/README.md | sed -n 16p` (the old wording) against `git show 58fe29b8a:lab/capsule-identity/README.md | sed -n 16p`. Closed by task 038.

Why: Flint's 27 Oct 12:06 note (Sasha's "nothing idle", to reopen and close S1 after
Rong's review rong-20261027-1010) asks the claude and cursor pair to re-read three merges
of this lane that had Codex as their only reviewer. cx-wasm-audit declined the ask at
12:15 and routed it here. The three are lab PRs #234 (task 019), #244 (task 020) and
#247 (task 021).

Base commit of this review: `4390c59002bdc8738cc7f031b64dcb695ec187fa` (`4390c5900`).
Each merge is judged as merged, with `git show <merge>:<path>`. Then each promise says
"still true at 4390c5900", or which later merge changed it (from
`git log --oneline --first-parent <merge>..HEAD -- <file>`). This file fixes nothing; each
`FOLLOWUP:` line is for the planner to turn into a later task. A claim of the kind README's
"Claim scope" keeps out of every lane doc is written here only as "an equality claim".

## PR #234 (task 019), merge d44f2d30d

Verdict: PASS

Lane diff: `git diff d44f2d30d^1 d44f2d30d -- lab/capsule-identity/` (5 files, +548 -20):
`LOG.md`, `README.md`, `falsifiers.json`, `tests/common/mod.rs` and the new
`tests/cross_implementation.rs`. Later merges that touch these files:
`tests/cross_implementation.rs` by 020 (f26d5d036) and 024 (a484fe001);
`tests/common/mod.rs` by 020, 025, 023, 028, 029, 031 and 032; README and LOG by 020 and
nearly every task after it; `src/lib.rs` by 023 (3818e38ca) only.

- Promise 1 (the test runs README's block and checks 11 pins three ways). At the merge,
  `readme_python_block` (`tests/common/mod.rs:582`) cuts README's "## The encoding"
  section (`:576`) at the next `\n## ` and takes its one ```` ```python ```` block as
  committed (README `:94`). `readme_python_lab_cids` (`:626`) appends
  `README_PYTHON_DRIVER` (`:612`) and runs one `run_python` per bundle; `run_python_with`
  (`:651`) passes `-I` (`:654`) and runs in a fresh temp folder (`:657`).
  `readme_python_recomputes_every_lab_cid_pin` (`tests/cross_implementation.rs:106`)
  compares `(python, encode_entries(..).to_string())` with `(pin, pin)` for each bundle
  (`:161`) and asserts `checked == PINNED_BUNDLES`, which is 11 (`:13`, `:172`). The
  bundle list is the seven fixtures, the recipe and three bundles built in memory, and
  `:64` asserts that every committed fixture but wc001-core is in it. Still true at
  4390c5900: the same test at `tests/cross_implementation.rs:127`, the count at `:22`
  and `:193`, the fixture list check at `:80`; the extractor is now
  `python_block_under` (`tests/common/mod.rs:611`, task 020) over
  `fenced_block_under` (`:630`, task 025), with the same refusals. The run below gives
  `test result: ok` for this test.
- Promise 2 (the driver holds no rule; README's block is the only Python copy). At the
  merge, the test asserts the driver holds none of `hashlib`, `sha256`, `varint`,
  `base64`, `B32`, the base32 alphabet, `def ` or `lambda` (`tests/cross_implementation.rs:139`
  onward) and calls `lab_cid(` once (`:153`). The driver text
  (`tests/common/mod.rs:612-620`) imports only `json`, `os` and `sys`, reads JSON, checks `-I` and an empty folder, and
  prints. Still true at 4390c5900 (`tests/cross_implementation.rs:160`, driver at
  `tests/common/mod.rs:655`). A search of the lane at the base (`def lab_cid`, `B32 = `,
  `def varint`, `hashlib.sha256`, outside `target/`) finds the naming rule only in
  README `:98-142`; the two other `hashlib.sha256` lines (README `:748`, `:942`) are 020's
  digest blocks, and GAP-REPORT `:660` quotes `:942`'s text at an old commit.
- Promise 3 (it never skips; each bad answer has its own reason). At the merge,
  `run_python_with` refuses a program that cannot start (`tests/common/mod.rs:662`), a
  non-zero exit, checked before the output is read (`:670`), no line (`:685`) and more
  than one line (`:687`). The test asserts each reason by its prefix: exit 1 after a
  valid CID (`tests/cross_implementation.rs:113`), empty output (`:118`), two lines
  (`:125`) and a program that does not exist (`:131`). The driver itself exits with its
  reason when it is not under `-I` (`tests/common/mod.rs:614`) or its folder is not
  empty (`:616`). Still true at 4390c5900 (`tests/common/mod.rs:771`, `:779`, `:794`,
  `:796`; driver checks `:657`, `:659`; asserts `tests/cross_implementation.rs:134`,
  `:139`, `:146`, `:152`). README `:202-203` at the merge also claimed that "two blocks
  or an unclosed block" is refused; the code held it but no test did. 020's review found
  that, and task 024 (a484fe001) added both cases to `assert_bad_block_refused`
  (`tests/cross_implementation.rs:201`) with F-CI24d and F-CI24e, so it is closed.
- Promise 4 (F-CI19a to F-CI19j, each editing only `src/lib.rs` or `tests/common/mod.rs`).
  At the merge, `falsifiers.json` holds 191 entries; F-CI19b edits `src/lib.rs`
  (`const RAW_CODEC: u8 = 0x55;`), and the other nine edit `tests/common/mod.rs`. Each
  names `readme_python_recomputes_every_lab_cid_pin`. The spec check's additions are
  there: F-CI19e (exit status), F-CI19f (empty), F-CI19g (several lines), F-CI19i (no
  `-I`) and F-CI19j (the lane folder). At 4390c5900 all ten are in the list; F-CI19d was
  changed once, by 020 (f26d5d036), to also name 020's two tests, and none was changed
  after. Each anchor is still in its file (`RAW_CODEC` at `src/lib.rs:223`). Runner
  result at 4390c5900: `summary: 10 CAUGHT of 10` (raw lines below).
- Promise 5 (README no longer calls the check uncommitted; one LOG line; no
  `Cargo.toml`/`Cargo.lock` change). At the merge, `git show d44f2d30d:lab/capsule-identity/README.md | grep -n uncommitted`
  prints nothing (the parent has it at `:154` and `:1113`). One LOG line is added
  (`LOG.md:17`, "ci-19 (task 019, ..."). `git diff --stat d44f2d30d^1 d44f2d30d --
  lab/capsule-identity/Cargo.toml lab/capsule-identity/Cargo.lock lab/capsule-identity/src`
  prints nothing. The LOG line's counts hold at the merge: 115 `#[test]` lines (114 in
  the parent) and 191 list entries; "Python 3.9.6" is this Mac's `python3 --version`.
  Still true at 4390c5900: README holds no "uncommitted" (only LOG's older 018 line,
  which was true when written, says it), and the ci-19 line is `LOG.md:17`.

Principles check:

1. Named by hash: yes. Every bundle is checked by its printed CID against its pin, never
   by a name (`tests/cross_implementation.rs:161-172` at d44f2d30d).
2. No ambient authority: not affected. Test code only; Python runs with `-I` in an empty
   temp folder and gets the bundle bytes on stdin (`tests/common/mod.rs:654-657` at
   d44f2d30d). No capsule, Home or UI code changes.
3. One path: yes. README's block is the one Python copy and the driver is checked to hold
   no rule (`tests/cross_implementation.rs:139-153` at d44f2d30d); the Rust side calls
   the one encoder `encode_entries` (`:161`).
4. Trusted core: not affected. The diff is under `lab/capsule-identity/` only, with no
   `src/lib.rs` change (`git diff --stat d44f2d30d^1 d44f2d30d`).
5. Fails closed: yes. Each bad run is an `Err` with its reason, never a skip
   (`tests/common/mod.rs:662`, `:670`, `:685`, `:687` at d44f2d30d).
6. Self-contained: not affected. No capsule code; the change tests the lab encoder
   (`tests/cross_implementation.rs:1-5` at d44f2d30d).
7. Tests prove it: yes. One named test, ten falsifiers, run at the base: `summary: 10 CAUGHT of 10`.
8. Separate decisions: yes. The check compares identity values only and holds no
   admission or budget step (`tests/cross_implementation.rs:158-172` at d44f2d30d;
   README `:15` at 4390c5900: "It never answers \"may this run?\"").

## PR #244 (task 020), merge f26d5d036

Verdict: PASS

Lane diff: `git diff f26d5d036^1 f26d5d036 -- lab/capsule-identity/` (6 files, +488 -39):
`LOG.md`, `README.md`, `falsifiers.json`, `tests/common/mod.rs`,
`tests/cross_implementation.rs` and `tests/name_signature.rs` (-5). Later merges that
touch them are the same as for #234, without 019 and 020; `tests/name_signature.rs` has
no later change.

- Promise 1 (README's two blocks define the functions; the placeholder DID line is gone;
  the text stays true). At the merge, the name block defines `name_digest(name)` (README
  `:637`) and the record block `record_payload(cid, did)` and `record_digest(cid, did)`
  (`:821`, `:825`). The parent's `did = "<the signer's did:key>"` (`f26d5d036^1`, README
  `:780`) and `name = b"..."` (`:608`) lines are gone. The text around them says what
  each function returns, and that holds: by hand, `python3 -I` over
  `domain || 0x00 || content-sample's pin` prints
  `e04c241b58d424a79e9c4308dc611216890d528ee098646acef7a836dbf4fbb9`, the value README
  states (`:631`) and `CONTENT_SAMPLE_NAME_DIGEST` holds. The bytes they hash are the
  parent's: same domains, separator and payload layout. Still true at 4390c5900 (README
  `:741`, `:747`, `:936`, `:940`; neither placeholder line is in README).
- Promise 2 (the name digest test, 7 pins). At the merge,
  `readme_python_matches_the_name_signature_digest` (`tests/cross_implementation.rs:223`)
  runs the block under "## Test-key publisher signature (lab proposal)"
  (`tests/common/mod.rs:588`) with `NAME_DIGEST_DRIVER` (`:667`) on the seven pins from
  `pinned_fixtures`, and asserts Python equals `hex::encode(name_signature_message(pin))`,
  content-sample's equals `CONTENT_SAMPLE_NAME_DIGEST` (`:260`), and `checked == 7`
  (`:25`, `:264`). Still true at 4390c5900 (`tests/cross_implementation.rs:238`, `:275`,
  `:279`).
- Promise 3 (the record test, byte for byte, DID as data, no key byte out). At the merge,
  `readme_python_matches_the_package_record_bytes` (`tests/cross_implementation.rs:269`)
  signs content-sample and web-app with `fresh_signing_key`, sends only
  `{"cid", "did"}` JSON (`RECORD_DRIVER` at `tests/common/mod.rs:693`,
  `readme_python_records` at `:702`), asserts the payload byte for byte (`tests/cross_implementation.rs:343`), the
  digest equal to `domain_separated_digest(PACKAGE_RECORD_DOMAIN, ..)` (`:346`), the
  record's signature valid over Python's digest (`:356`) and `checked == 2` (`:29`,
  `:360`). Still true at 4390c5900 (`:284`, `:358`, `:371`, `:375`).
- Promise 4 (never skips; F-CI20a to F-CI20c plus the spec check's; no Python Ed25519; no
  new crate). At the merge, both tests assert a missing section and a section with no
  block by their exact text (`assert_missing_block_refused`,
  `tests/cross_implementation.rs:200`) and an undefined function by Python's NameError
  (`assert_undefined`, `:214`); the record test also refuses a one-word answer
  (`tests/common/mod.rs:723`). The list has F-CI20a (`src/lib.rs`, the separator), F-CI20b
  (`src/lib.rs`, key order), F-CI20c (only the record block's `package-record/v1`, the
  schema keeps `/v1`), and the spec check's F-CI20d (the name block's domain), F-CI20e and
  F-CI20f (each block missing with no answers). No block or driver imports an Ed25519
  module: the signature check is `ed25519_dalek` in Rust (`:356`).
  `git diff --stat f26d5d036^1 f26d5d036 -- lab/capsule-identity/Cargo.toml
  lab/capsule-identity/Cargo.lock lab/capsule-identity/src` prints nothing. Still true at
  4390c5900: all six ids are in the list, unchanged since the merge; task 024 renamed the
  helper to `assert_bad_block_refused` (`tests/cross_implementation.rs:201`) and added
  two cases. Runner result at 4390c5900: `summary: 6 CAUGHT of 6` (raw lines below).
- Promise 5 (the 5 lines removed from `tests/name_signature.rs`). They were the doc
  comment, the definition and the value of `CONTENT_SAMPLE_NAME_DIGEST`, and the blank
  line after it (`f26d5d036^1`, `tests/name_signature.rs:15-19`). The constant moved to
  `tests/common/mod.rs:61` with the same value, and `tests/name_signature.rs:53` at the
  merge still asserts it in `signed_message_is_the_domain_separated_lab_cid` (through
  `use common::*`, `:13`). No rule lost its test. Still true at 4390c5900
  (`tests/common/mod.rs:68`, `tests/name_signature.rs:53`). The LOG line
  (`LOG.md:18`) counts hold at the merge: 117 `#[test]` lines and 197 list entries.

Principles check:

1. Named by hash: yes. The record test asserts each signed record's `cid` is the bundle's
   pin (`tests/cross_implementation.rs:320` at f26d5d036); the name test digests the
   printed CIDs only (`:249-253`).
2. No ambient authority: not affected. Test code only; Python gets a CID and a DID as
   data, and no key byte (`tests/common/mod.rs:693-702` at f26d5d036).
3. One path: yes. Both blocks run through 019's one `run_python` and one extractor
   (`tests/common/mod.rs:604`, `:681`, `:710` at f26d5d036); each driver is checked to
   hold no hash, domain or function (`tests/cross_implementation.rs:231-244`, `:288-306`).
4. Trusted core: not affected. No `src/lib.rs`, `elastos/` or dependency change
   (`git diff --stat f26d5d036^1 f26d5d036`).
5. Fails closed: yes. A missing section, a missing block, an undefined function and a
   one-word answer are each refused with an asserted reason
   (`tests/cross_implementation.rs:200-221` at f26d5d036, `tests/common/mod.rs:723`).
6. Self-contained: not affected. No capsule code (`tests/cross_implementation.rs:6-10`
   at f26d5d036).
7. Tests prove it: yes. Two named tests, six new falsifiers and the widened F-CI19d, run
   at the base: `summary: 6 CAUGHT of 6` (F-CI19d is CAUGHT in the F-CI19 run).
8. Separate decisions: yes. The record binds a CID and a signer only, and the test checks
   bytes and a signature, never a grant (`tests/cross_implementation.rs:310-360` at
   f26d5d036).

## PR #247 (task 021), merge 6fe61d88e

Verdict: FOLLOWUP

Lane diff: `git diff 6fe61d88e^1 6fe61d88e -- lab/capsule-identity/` (`GAP-REPORT.md` only,
+236 -12). The one later merge that touches it is 026 (2b2e294e9), which adds its own
revision, its own section and one sentence; of the 236 lines 021 added, 235 are at the
base word for word, and 026 extended the 236th (`:636-638` at the base, "except in \"B1
and B2 (Anders, 26 Oct)\"").

- Promise 1 (the revision header). At the merge, `GAP-REPORT.md:14-26` is "Revision
  (task 021, 2026-10-26)", with the lab commit read `01f6add1f...` and the
  `git diff --quiet c641bcff2... 01f6add1f... -- <file>` result: all 17 files under
  `elastos/` or `scripts/` unchanged. Checked by a run: for each file in the table
  (`:31-49` at the merge), `git diff --quiet c641bcff2 01f6add1f -- <file>` exits 0,
  17 of 17. The same holds from `c641bcff2` to 4390c5900, 17 of 17. `PRINCIPLES.md`,
  `components.json` and the four cited `docs/` files are unchanged too, as the header
  says. Still true at 4390c5900 (`:14`).
- Promise 2 (the section on Anders's answers). At the merge, "## Anders's answers and the
  lab prototypes" is `:615`, with Q2 (`:628`), Q3 (`:661`), Q4 (`:690`), Q6 (`:710`), Q7
  (`:724`) and Q10 (`:739`). Each has the answer as quoted, its lab tasks, a README line,
  named tests at `path:line` and a "Not shown" line. Q3's says no Kubo computed any pin
  (`:679`). Still true at 4390c5900 (`:628`, `:642`, `:675`, `:704`, `:724`, `:738`,
  `:753`).
- Promise 3 (the questions with no answer). At the merge, `:762`: "Q1, Q5, Q8 and Q9: no
  answer relayed to this lane." Still true at 4390c5900 (`:836`).
- Promise 4 (the lab "Not shown" on launch by name, citing b3). At the merge, `:807-811`
  says the Runtime still launches a capsule by name and quotes b3,
  `elastos/crates/elastos-server/src/runtime.rs:366` at `c641bcff2` (b3 itself is `:321`).
  Still true at 4390c5900 (`:883-887`, b3 at `:334`).
- Promise 5 (the lab section rewritten for the UnixFS value). At the merge, `:764-811`
  describes the `bafybei...` UnixFS root, the single-block subset, the refusals over
  262144 bytes, the old framed value only "at `c641bcff2`", and records outside the
  bundle. This review's FOLLOWUP is on this section at the base: its sentence that the lab
  "sits in no admission or launch path" (`:848-849` at 4390c5900, `:772-773` at the
  merge) held at the merge and at `01f6add1f`, but task 032 (58fe29b8a) narrowed README's
  sentence to "no Runtime admission or launch path" and added that the lab's stand-in
  launcher, in test code, calls the library (README `:14-17` at 4390c5900). The quoted
  citation is still right at its recorded commit; the report's own sentence now says
  more than README does. Task 033 is building and edits `GAP-REPORT.md`; the planner can
  check whether it already covers this sentence. Added by task 038: 033 left the sentence in
  place (at its merge `f94d89ac6` it is `GAP-REPORT.md:872`, and this record's commit
  `2029a6c3c` was made on that tree), and task 038 fixed it.
- Promise 6 (citations counted "N found, N match"). At the merge, `:115-118` says 69 found,
  69 match. Checked by a run: every `` `path:line` `` followed by a quoted text in the
  lines 021 added was compared with line `line` of `git show <commit>:<path>`, at
  `01f6add1f`, or at `c641bcff2` for the two the report names (`src/lib.rs:73` and
  `runtime.rs:366`). Result: 69 checked, 69 match (each quote is found in its line). The
  other 5 `path:line` mentions in the added lines carry no quote: they name the dropped
  or recounted citations of 008.
- Promise 7 (no security weakness described). The diff adds no text to the "security
  finding, details for Sasha" line (`:613` at the merge, unchanged context), and no added
  line describes a weakness. Still true at 4390c5900 (`:626`).

The six "Not shown" lines and the lab one, at 4390c5900: Q2 present (`:666`), Q3 present
(`:691`), Q4 present (`:716`), Q6 present (`:732`), Q7 present (`:748`), Q10 present
(`:760`), and the lab "Not shown" on launch by name present (`:883`).

FOLLOWUP: lab/capsule-identity/GAP-REPORT.md:848 says the lab "sits in no admission or launch path", but since task 032 (PR #587, merge 58fe29b8a) README says only "no Runtime admission or launch path" and that the lab's stand-in launcher, in test code, calls it; hand check: `sed -n 845,849p lab/capsule-identity/GAP-REPORT.md` against `sed -n 14,17p lab/capsule-identity/README.md`, and `git show 58fe29b8a^1:lab/capsule-identity/README.md | sed -n 16p` (the old wording) against `git show 58fe29b8a:lab/capsule-identity/README.md | sed -n 16p`.

Principles check:

1. Named by hash: yes. Q2 and Q3 describe the bundle's name as its CIDv1 SHA-256 root,
   and the record binds a CID, never a name (`GAP-REPORT.md:628`, `:661` and `:621-622`
   at 6fe61d88e).
2. No ambient authority: not affected. A document; it grants nothing
   (`GAP-REPORT.md:751-757` at 6fe61d88e, "Admission stays the Runtime's").
3. One path: not affected. It adds no rule or code; it cites the lab's one encoder and
   one record builder (`GAP-REPORT.md:641-650` at 6fe61d88e).
4. Trusted core: not affected. Only `GAP-REPORT.md` changes (`git diff --stat
   6fe61d88e^1 6fe61d88e`); the Runtime citations stay at `c641bcff2` (`:14-26`).
5. Fails closed: not affected. No refusal is added (doc only, `:615-811`).
6. Self-contained: not affected. No capsule code (doc only, `:615-811`).
7. Tests prove it: not affected for code; its citations are checked by a run here, 69 of
   69, and its 17-file claim 17 of 17 (`GAP-REPORT.md:115-118`, `:14-26` at 6fe61d88e).
8. Separate decisions: yes. Identity (Q2, Q3), the record's signer (Q6) and admission
   ("Admission stays the Runtime's", `GAP-REPORT.md:751`) are kept apart, and Q6's "Not
   shown" says no publisher policy is built (`:718`).

## Commands and raw results

All run at 4390c5900 on this Mac (Python 3.9.6, rustc 1.91.0), holding the build lease
(`.git/local-ai-heavy-build.lock`, taken after a 2100 s wait), with `RUST_TEST_THREADS=2
CARGO_INCREMENTAL=0`. After the runner, `git status --short` showed only this file.

`python3 -I examples/agent-host/falsify.py --from lab/capsule-identity/falsifiers.json F-CI19`
(exit 0):

```
baseline: 3 named tests pass without an edit, 0 do not
F-CI19a CAUGHT   README's rule drifts: the extracted Python's raw-leaf codec 0x55 becomes 0x70 before it runs
F-CI19b CAUGHT   the Rust encoder's raw-leaf codec becomes 0x56, so Rust and README's Python disagree
F-CI19c CAUGHT   the README block is not found and the run returns no answers, so the check covers no bundle
F-CI19d CAUGHT   the interpreter is a program that does not exist: the test must fail, not skip
F-CI19e CAUGHT   the exit status is not checked: a valid CID followed by exit 1 is taken
F-CI19f CAUGHT   a run that prints nothing gives an empty answer instead of a refusal
F-CI19g CAUGHT   a run that prints more than one line gives its first line instead of a refusal
F-CI19h CAUGHT   the driver imports hashlib, a second home for the rule's hash
F-CI19i CAUGHT   python3 runs without -I, so the folder and the environment can change what it imports
F-CI19j CAUGHT   python3 runs from the lane folder, not a fresh empty temp folder
summary: 10 CAUGHT of 10
```

`python3 -I examples/agent-host/falsify.py --from lab/capsule-identity/falsifiers.json F-CI20`
(exit 0):

```
baseline: 2 named tests pass without an edit, 0 do not
F-CI20a CAUGHT   the Rust digest's separator byte becomes 0x01, so Rust and README's two digest blocks disagree
F-CI20b CAUGHT   package_record_payload writes schema before cid, so its bytes are not README's record_payload
F-CI20c CAUGHT   README's record domain drifts: the extracted block's package-record/v1 becomes /v2 before it runs (the schema stays /v1)
F-CI20d CAUGHT   README's name domain drifts: the extracted block's name-signature/v1 becomes /v2 before it runs
F-CI20e CAUGHT   the name-signature block is not found and the run returns no answers, so the check covers no name
F-CI20f CAUGHT   the package-record block is not found and the run returns no answers, so the check covers no record
summary: 6 CAUGHT of 6
```

No F-CI19 or F-CI20 id is gone from the list at the base.

`RUST_TEST_THREADS=2 cargo test --locked --offline --manifest-path lab/capsule-identity/Cargo.toml --test cross_implementation`
(exit 0):

```
test readme_python_matches_the_package_record_bytes ... ok
test readme_python_matches_the_name_signature_digest ... ok
test readme_python_recomputes_every_lab_cid_pin ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.90s
```

021's citations: for each `` `path:line` `` with a quoted text on a line 021's diff adds,
`git show <commit>:<path>` at that line must hold the quote (commit `01f6add1f`, or
`c641bcff2` for `lab/capsule-identity/src/lib.rs:73` and
`elastos/crates/elastos-server/src/runtime.rs:366`): `69 checked, 69 match`. The 17
files: `git diff --quiet c641bcff2 01f6add1f -- <file>` exits 0 for 17 of 17.
