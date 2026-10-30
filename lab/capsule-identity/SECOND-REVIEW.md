# Second review of three one-reviewer merges

- PR #234 (task 019), merge d44f2d30d: Verdict: PASS (runner at the base: `summary: 10 CAUGHT of 10`)
- PR #244 (task 020), merge f26d5d036: Verdict: PASS (runner at the base: `summary: 6 CAUGHT of 6`)
- PR #247 (task 021), merge 6fe61d88e: Verdict: FOLLOWUP (citations: 69 checked, 69 match)
- FOLLOWUP: lab/capsule-identity/GAP-REPORT.md:848 says the lab "sits in no admission or launch path", but since task 032 (PR #587, merge 58fe29b8a) README says only "no Runtime admission or launch path" and that the lab's stand-in launcher, in test code, calls it; hand check: `sed -n 845,849p lab/capsule-identity/GAP-REPORT.md` against `sed -n 14,17p lab/capsule-identity/README.md`, and `git show 58fe29b8a^1:lab/capsule-identity/README.md | sed -n 16p` (the old wording) against `git show 58fe29b8a:lab/capsule-identity/README.md | sed -n 16p`. Closed by task 038.
- PR #657 (task 033), merge f94d89ac6: Verdict: PASS (added by task 039; runner at c6e2d58d5: `summary: 3 CAUGHT of 3`; citations: 13 checked, 13 match)
- PR #730 (task 035), merge 1503ac6f4: Verdict: FOLLOWUP, and PR #757 (task 036), merge b7c613a10: Verdict: PASS (added by task 041; runner at 9bd839491: F-CI35 `summary: 3 CAUGHT of 3`, F-CI36 `summary: 2 CAUGHT of 2`)
- PR #782 (task 037), head dd84ef2fe: Verdict: PASS, and PR #842 (task 044), head 1421a5ec6: Verdict: FOLLOWUP (added by task 046; runner at c59703a06: F-CI37 `summary: 3 CAUGHT of 3`, F-CI44 `summary: 3 CAUGHT of 3`, F-CI35 `summary: 3 CAUGHT of 3`)

Scope correction (29 Oct, task 059): tasks 037 through 049 (PRs #782 through #894) landed on one reviewer, so B1
and naming credit stay uncredited until a second reviewer of another family passes. This migration does not itself
clear that hold. Acceptance of the current candidate requires two independent non-author review verdicts, each
naming its reviewer identity and the tested head; an unavailable reviewer remains a pending gate.

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

## PR #657 (task 033), merge f94d89ac6

Added by task 039, on 2026-10-27. Rong (principles) asked on 27 Oct, per Sasha's 25 Oct
direction, for a second review of #657 before any B1 credit, because Flint's M1 B1 note
sets the bar at two independent reviews. #657 had one reviewer only: Cursor, PASS in round
2 (round 1 failed the test gate, not a review). So it was the one B1 stand-in merge below
the bar; #587 (task 032) already had Claude and Cursor.

Base commit of this section: `c6e2d58d5e298e3fa7d07908841ce4ca0a64f6f2` (`c6e2d58d5`). The
merge is judged as merged, with `git show f94d89ac6:<path>` (written "M:line" below). Then
each promise says "still true at c6e2d58d5" (written "B:line"), or which later change moved
it, from `git log --oneline --first-parent f94d89ac6..HEAD -- <file>`: 035 (PR #730,
`1503ac6f4`), 036 (PR #757, `b7c613a10`), 037 (`dd84ef2fe`, PR #782, done in the batch and
still open) and 038 (`c6e2d58d5`, `GAP-REPORT.md` only). This section fixes nothing.

Verdict: PASS

Lane diff: `git diff f94d89ac6^1 f94d89ac6 -- lab/capsule-identity/` (6 files, +292 -11):
`GAP-REPORT.md`, `LOG.md`, `README.md`, `falsifiers.json`, `tests/common/mod.rs` and
`tests/stand_in.rs`.

Known, queued as 037 (not new findings): Cursor's two round-2 FOLLOWUPs on #657, "seeds one
grant, so a view that returns only the first held grant (`take(1)` ...) still passes", and
"The `StandInRuntime` doc still says 'Its two methods'" (M:1370 in `tests/common/mod.rs`).
At c6e2d58d5 both are changed by 037: the doc lists each method (B:1369-1376), and
`standin_grant_view_lists_every_held_grant_of_every_session` (`tests/stand_in.rs` B:439)
holds three grants over two sessions with F-CI37a-c.

New FOLLOWUP lines: none.

- Promise 1 (the view, the seed, no grant from a launch, 032's keys). At the merge,
  `tests/common/mod.rs` holds `get_capability_list_all_sessions_live` (M:1479-1482),
  answering `{"scope": "all_sessions_live", "capabilities": [...]}` from `self.grants`, and
  `seed_grant(session_id, resource, action, duration)` (M:1489), whose doc starts "Lab test
  seam, not a route" (M:1484). Checked: `self.grants.push` occurs once, in `seed_grant`
  (M:1491); `post_capsules` (M:1448-1451) and `launch` (M:1549-1563) touch only
  `instances`, so a launch adds no grant. The answer keys are `id`, `name`, `status`,
  `session_id` (M:1556-1561) and the list keys add `cause` (M:1461-1467), with no grant or
  token key; `tests/stand_in.rs` M:275-279 and M:290-294 assert both key sets exactly.
  Still true at c6e2d58d5: view B:1492-1494, seed B:1497-1502, one push B:1504, keys
  asserted B:333-337 and B:348-352. Changed by 035: `launch` also stores the instance's
  asks (B:1591-1607) and its answer keys are the same four; by 036: the record check moved
  into `check_records` and any accepted record launches; neither adds a grant.
- Promise 2 (`standin_valid_signature_alone_yields_no_grant`). At the merge
  (`tests/stand_in.rs` M:309), it asserts the `agent-host` manifest asks for a capability
  (M:314-318), launches the signed bundle by CID, asserts no view entry for that session and
  an empty view (M:323-331), then launches again, asserts a second session id and two
  listed instances, and an empty view (M:333-341). Every view read goes through
  `grant_view`, which asserts the keys `capabilities` and `scope` and the value
  `all_sessions_live` (M:301-306). Still true at c6e2d58d5 (B:367-400, `grant_view`
  B:359-364). The run below gives `ok` for it.
- Promise 3 (`standin_grant_view_lists_a_seeded_grant`). At the merge (M:345), it seeds one
  grant for the launched session, asserts one entry (M:354), the six keys (M:356-366), the
  seeded `session_id`, `resource`, `action` and `duration`, a non-empty `request_id`, a
  number `granted_at`, and that the instance list is unchanged (M:377). Still true at
  c6e2d58d5 (B:403-436). Its one-grant limit is 037's known FOLLOWUP above.
- Promise 4 (F-CI33a, F-CI33b, F-CI33c, each in `tests/common/mod.rs`, each CAUGHT). At the
  merge, the three entries edit only `../../lab/capsule-identity/tests/common/mod.rs`:
  F-CI33a on `Ok(self.launch(name))` (M:1450), seeding one grant per manifest
  `capabilities` entry; F-CI33b `take(0)` on the view's line (M:1480); F-CI33c drops
  `"scope"` (M:1481). At c6e2d58d5 the three ids are in the list; F-CI33a was changed by
  035 (anchor `Ok(self.launch(name, asks))`, B:1463) and by 036 (its planted code names
  `elastos_common::CapsuleManifest` and `capsule_identity::MANIFEST_FILE` by path), with the
  same bug and test, as README B:1737-1743 and B:1756-1757 say; F-CI33b and F-CI33c are
  unchanged. Runner result at c6e2d58d5: `summary: 3 CAUGHT of 3` (raw lines below).
- Promise 5 (README's stand-in section). At the merge, README M:1340-1359 states the rule,
  the view's answer, the seed as "a lab test seam, not a route" and both tests; the
  interface rows are M:1375 (the view, citing #309 `01-live-grant-view.md:11` and `:83` at
  `513988ebd`, and `capability.rs:411-423`) and M:1376 (the seed); the rule rows M:1387-1389
  name the tests and F-CI33a-c; "Not shown" holds "No shell approval is modelled; a grant
  exists only through the test seam `seed_grant`" (M:1399-1401). Each citation in the row
  was checked with `git show` (list below). Still true at c6e2d58d5: paragraph B:1367-1386
  and rows B:1402-1403, word for word; B:1416 and B:1418 as at the merge; B:1417 widened by
  037 to name its test and F-CI37a-c; "Not shown" B:1428.
- Promise 6 (GAP-REPORT's dated paragraph). At the merge, the revision line is
  `GAP-REPORT.md` M:34-37 and the paragraph "B1 through a lab stand-in (27 Oct, tasks 032
  and 033)" is M:838-856, right after "B1 and B2 (Anders, 26 Oct)" (M:778, no heading
  between), with its "Not shown" at M:853-856. Each of its citations was checked (list
  below). Still true at c6e2d58d5: B:34-37 and B:845-863, word for word (`diff` of the two
  ranges prints nothing). 036 changed the record check to "any accepted record", and the
  paragraph's steps (f) and (g) still describe it.
- Promise 7 (`about`, README count, no `src/lib.rs`, `Cargo.toml` or `Cargo.lock` change).
  At the merge, `about` ends "031, 032 and 033" (033 after 032, in list order), the list
  holds 254 entries (`grep -c '"id": "F-CI'`) and README M:1559 says 254. `git diff --stat
  f94d89ac6^1 f94d89ac6 -- lab/capsule-identity/src lab/capsule-identity/Cargo.toml
  lab/capsule-identity/Cargo.lock` prints nothing. At c6e2d58d5 `about` names "032, 033,
  035, 036 and 037", README B:1628 says 262, and the list holds 262 entries (`git show
  c6e2d58d5:lab/capsule-identity/falsifiers.json | grep -c '"id": "F-CI'` prints 262); this
  review did not run `tests/inventory.rs` at c6e2d58d5; `src/lib.rs` was changed later by
  036 only. The LOG line (M:28, unchanged at B:28) says the whole list gave 254 CAUGHT of
  254 in two runs; this review did not rerun the whole list, only F-CI33.
Corrected by task 042, on 2026-10-27: the earlier text said `tests/inventory.rs` passed in the run below; that run was `--test stand_in` only (Cursor's FOLLOWUP on 039).

033's citations, each read with `git show` at its recorded commit: 13 checked, 13 match.
README's view row: `lab/runtime-asks/01-live-grant-view.md:11` at `513988ebd` ("A shell
session can read the live grants of every session"), `:83` ("`\"scope\":
\"all_sessions_live\"` to the response, and add the session id to"), and
`elastos/crates/elastos-server/src/api/handlers/capability.rs:411-423` (`CapabilityOutput`
with the five keys, `ListCapabilitiesOutput` with `capabilities`; the same at `513988ebd`,
f94d89ac6 and c6e2d58d5). GAP-REPORT's paragraph: its lab base `693c3681d` is the parent of
033's one commit `f767631f1`; its place after "B1 and B2 (Anders, 26 Oct)"; `StandInRuntime`
in `tests/common/mod.rs` (M:1386); README "Lab stand-in launcher (M1 check B1)" (M:1303);
RA-1's route (`01-live-grant-view.md:83`); the two tests (`tests/stand_in.rs` M:309,
M:345); `seed_grant` as the one seam (M:1489, one push); the README section's launch request
citation `routes.rs:65-66` (README M:1394; `LaunchRequest {` and `path: String,` at
f94d89ac6 and c6e2d58d5); and "asks for one grant in `capabilities`" (the `agent-host`
fixture's `capabilities` has one entry). The tests it names do not exist at `693c3681d`,
as expected: 033 added them, and the revision line says it names tests, not lines.

Principles check:

1. Named by hash: yes. A launch names its bundle only by its lab CID and recomputes it
   before any grant view is read (`tests/common/mod.rs:1507-1522` at f94d89ac6).
2. No ambient authority: yes. A launch gives no grant; the one way a grant exists is the
   test seam (`tests/common/mod.rs:1489-1491` at f94d89ac6); no capsule, Home or UI code
   changes.
3. One path: yes. One view over one `grants` list, one entry builder (`Grant::entry`,
   `tests/common/mod.rs:1414` at f94d89ac6); the stand-in still calls the library's
   checks, not copies (`:1514-1521`).
4. Trusted core: not affected. No `elastos/`, `src/lib.rs`, `Cargo.toml` or `Cargo.lock`
   change (`git diff --stat f94d89ac6^1 f94d89ac6`); the code is test code
   (`tests/common/mod.rs:1367` at f94d89ac6).
5. Fails closed: not affected. 033 adds no refusal; the view holds nothing unless a test
   seeds it (`tests/common/mod.rs:1439` at f94d89ac6, `grants: Vec::new()`).
6. Self-contained: not affected. No capsule code; the stand-in runs nothing
   (`tests/common/mod.rs:1367-1368` at f94d89ac6).
7. Tests prove it: yes. Two named tests (`tests/stand_in.rs:309`, `:345` at f94d89ac6) and
   three falsifiers, run at the base: `summary: 3 CAUGHT of 3`.
8. Separate decisions: yes. A verified publisher record (identity) admits a launch in the
   stand-in, and the grant view (allowance) stays empty after it
   (`tests/stand_in.rs:323-341` at f94d89ac6).

Commands and raw results for this section, all at c6e2d58d5 on this Mac (Python 3.9.6,
rustc 1.91.0), holding the build lease (`.git/local-ai-heavy-build.lock`, free, taken
after 0 s), with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. After the runner,
`git status --short` printed nothing.

`python3 -I examples/agent-host/falsify.py --from lab/capsule-identity/falsifiers.json F-CI33`
(exit 0):

```
baseline: 2 named tests pass without an edit, 0 do not
F-CI33a CAUGHT                            10s  a launch gives the instance one grant for each capabilities entry of its manifest, so a valid signature alone yields a grant
F-CI33b CAUGHT                             8s  the grant view answers no entries whatever is held, so it is a constant
F-CI33c CAUGHT                             9s  the grant view drops the all_sessions_live scope marker
summary: 3 CAUGHT of 3
```

`RUST_TEST_THREADS=2 cargo test --locked --offline --manifest-path lab/capsule-identity/Cargo.toml --test stand_in`
(exit 0):

```
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```

Added by task 042, at `c19e7cf06` (not c6e2d58d5; the list and README are the same there,
`git diff --quiet c6e2d58d5 c19e7cf06 -- lab/capsule-identity/falsifiers.json
lab/capsule-identity/README.md` exits 0):
`RUST_TEST_THREADS=2 cargo test --locked --offline --manifest-path lab/capsule-identity/Cargo.toml --test inventory`
(exit 0):

```
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

#657 now has two reviews, Cursor's merge review and this record, so both B1 stand-in merges,
#587 and #657, have two; the Runtime did nothing here: no Runtime code ran, launched, checked,
refused or granted anything.

## PR #730 (task 035), merge 1503ac6f4

Added by task 041, on 2026-10-27. Flint's URGENT M1 note of 27 Oct 11:10 sets one bar for
each M1 check through the lab stand-in: a full journey, a refusal with a reason plus a CAUGHT
falsifier, a planted stub that returns Ok without doing the work must FAIL, and two
independent reviews. #730 had one reviewer only: Cursor, PASS in round 3 (round 2 failed the
test gate because of an orphaned runner, not a review). #757 (next section) had one reviewer
only too: Cursor, PASS in round 1. Task 039 covered #657; this task covers these two.

Base commit of this section and the next: `9bd83949183e18ee4f343ef830af0e7467e78b3c`
(`9bd839491`). Each merge is judged as merged, with `git show <merge>:<path>` (written
"M:line" below). Then each promise says "still true at 9bd839491" (written "B:line"), or
which later change moved it, from `git log --oneline --first-parent <merge>..HEAD -- <file>`:
036 (PR #757, `b7c613a10`), 037 (`dd84ef2fe`, PR #782, done in the batch and still open),
038 (`c6e2d58d5`, `GAP-REPORT.md` only) and 039 (`9bd839491`, this file only). This section
fixes nothing.

Verdict: FOLLOWUP

Lane diff: `git diff 1503ac6f4^1 1503ac6f4 -- lab/capsule-identity/` (6 files, +283 -20):
`GAP-REPORT.md`, `LOG.md`, `README.md`, `falsifiers.json`, `tests/common/mod.rs` and
`tests/stand_in.rs`.

- Promise 1 (`Instance.asks`, set once at launch from the checked bundle; `asks_of`; keys
  kept). At the merge, `tests/common/mod.rs` has `asks: Option<Vec<u8>>` in `Instance`
  (M:1407), set only in `launch` (M:1572, M:1578) from `post_capsules`'s
  `let (name, asks) = self.checked_launch(body)...` (M:1458-1459). `checked_launch` answers
  `signed_asks(&checked)` (M:1544) on the `CheckedBundle` of the one walk (M:1536), after
  every check; `signed_asks` (M:1614-1620) takes the content of the `asks.json` entry from
  `entries()`, or `None`. Checked: no `fs::read` in `StandInRuntime` (M:1391-1620; the
  file's `fs::read` lines all come before M:1100), so nothing reads the folder again.
  `asks_of` (M:1515-1519) has the doc "Lab test seam, not a route" (M:1510) and answers
  `None` for an unknown session (`find` then `and_then`). The answer keys are asserted in
  `tests/stand_in.rs` M:468; the body stays `{"cid"}` (`launch_body`, M:65). Still true at
  9bd839491: B:1411, B:1591, B:1597, B:1461-1463, B:1544, B:1541, B:1620-1625, B:1519-1523
  and the doc B:1514; 036 changed only the name half of the answer (B:1544), and 037 only
  the `StandInRuntime` doc, which now lists `asks_of` as a lab test seam (B:1376).
- Promise 2 (`standin_hands_an_instance_only_its_signed_asks_bytes`). At the merge
  (`tests/stand_in.rs` M:392), it compares `asks_of` with the committed
  `fixtures/agent-host/asks.json`, changes one byte on disk (`change_stored_asks`, M:383),
  asserts `asks_of` still answers the signed bytes (M:411), a second launch refused with
  the name compare's own text, built from `check_name` and naming both CIDs (M:426), one
  listed instance (M:428) and an empty grant view (M:429). Still true at 9bd839491: the
  test and its helper are the same text at B:513-561 (`diff` of the two ranges prints
  nothing). The run below gives `ok` for it. This review's FOLLOWUP is on what the test can
  catch: see the GAP-REPORT bullet below.
- Promise 3 (`standin_gives_each_session_its_own_asks`). At the merge (M:433), `agent-host`
  and a signed `web-app` with no `asks.json` (asserted by its entries) are launched in both
  orders with fresh keys; `agent-host`'s session answers its bytes, `web-app`'s `None`
  (M:487), an unknown session `None` (M:492), two instances, an empty view (M:495). Still
  true at 9bd839491 (B:563, same text).
- Promise 4 (F-CI35a, F-CI35b, F-CI35c, each CAUGHT). At the merge, each edits only
  `../../lab/capsule-identity/tests/common/mod.rs`: F-CI35a turns `asks_of` into a read of
  `asks.json` from the stored folder at call time (anchor M:1519), F-CI35b answers the first
  instance (M:1518), F-CI35c answers `Some(Vec::new())` (M:1619). The three entries are the
  same at b7c613a10 and at 9bd839491, and their anchors are B:1523, B:1522 and B:1625.
  Runner result at 9bd839491: `summary: 3 CAUGHT of 3` (raw lines below).
- Promise 5 (README part "Asks come only from the signed bytes (M1 check B2, no-schema
  part)"). At the merge, the heading is README M:1408, the rule M:1410-1419 ("Nothing reads
  the folder again", M:1415), the three rule rows M:1434-1436 and "Not shown" M:1438-1445;
  the interface row "asks read `asks_of`" is M:1377. Its outside claim, "#309 has no asks
  field on any route (RA-1 to RA-7)", was checked with `git grep -i` at `513988ebd` over
  `lab/runtime-asks/`: no `asks.json`, no `"asks"` key and no asks field in any of the
  seven files. The text 035 added holds no `path:line` citation (0 checked). Still true at
  9bd839491: heading B:1436, row B:1404, rules B:1462-1464, "Not shown" B:1466-1473; 036
  (b7c613a10) changed one sentence of the rule to name `CheckedBundle::manifest_name()` for
  the name (B:1439-1442), with no change to what it says about the asks.
- Promise 6 (one dated B2 sentence in GAP-REPORT's B1 and B2 section). At the merge, it is
  `GAP-REPORT.md` M:837-843, the last paragraph of "B1 and B2 (Anders, 26 Oct)" (M:778),
  with its "not shown". Its references, each checked with `git show 1503ac6f4`: the stand-in
  is the next section (M:845, "B1 through a lab stand-in"); both tests exist
  (`tests/stand_in.rs` M:392, M:433); README's section heading is M:1408 word for word;
  `lab/bus-v2-proposal/` exists (`git ls-tree`); "no grant from an ask" holds (M:429,
  M:495); "a stub that reads the folder again fails" does not hold in general: 7 checked,
  6 match. By hand at 9bd839491: with `checked_launch` answering
  `fs::read(folder.join(ASKS_FILE)).ok()` in place of `signed_asks(&checked)` (a second read
  of the folder, made at launch), both named tests still pass (`test result: ok. 2 passed`),
  and the file was put back (same sha256, `git status --short` empty). Only a re-read at
  call time, F-CI35a, fails. Still true at 9bd839491: B:837-843, word for word.
- Promise 7 (`about`, count, no `src/lib.rs`, `Cargo.toml` or `Cargo.lock` change). At the
  merge, `about` ends "032, 033 and 035)", the list holds 257 entries
  (`grep -c '"id": "F-CI'`), README M:1600 says 257, and `git diff --stat 1503ac6f4^1
  1503ac6f4 -- lab/capsule-identity/src lab/capsule-identity/Cargo.toml
  lab/capsule-identity/Cargo.lock` prints nothing. The LOG line is M:29 (B:29, unchanged).
  At 9bd839491 `about` ends "036 and 037)", the list holds 262 and README B:1628 says 262;
  `git show 9bd839491:lab/capsule-identity/falsifiers.json | grep -c '"id": "F-CI'` prints
  262, so the list holds 262 entries at 9bd839491. This section's run below did not include
  `tests/inventory.rs`. Task 042's `--test inventory` run at `c19e7cf06` (the #657 section's
  "Added by task 042" block) covers it, because `git diff --stat 9bd839491 c19e7cf06 --
  lab/capsule-identity/falsifiers.json lab/capsule-identity/README.md
  lab/capsule-identity/tests lab/capsule-identity/src` prints nothing. The LOG line's whole-list result (257
  of 257) was not rerun here, only F-CI35.
Corrected by task 045, on 2026-10-28: the earlier text said `tests/inventory.rs` passed in the full run below; that run was `--test stand_in --test checked_bundle --test not_admission` only (Cursor's FOLLOWUP on 042).

FOLLOWUP: lab/capsule-identity/GAP-REPORT.md:839 says "a stub that reads the folder again fails", but only a re-read when `asks_of` is called (F-CI35a) fails; a stub that reads `asks.json` from the stored folder again at launch passes both named tests, because no test changes the folder between the walk and the launch; hand check: in `lab/capsule-identity/tests/common/mod.rs:1544` replace `signed_asks(&checked)` with `fs::read(folder.join(ASKS_FILE)).ok()`, run `RUST_TEST_THREADS=2 cargo test --locked --offline --manifest-path lab/capsule-identity/Cargo.toml --test stand_in -- standin_hands_an_instance_only_its_signed_asks_bytes standin_gives_each_session_its_own_asks` (`test result: ok. 2 passed`), then put the file back.
Answered by task 044, on 2026-10-28: `standin_takes_the_asks_from_the_walk_not_the_folder` changes the stored `asks.json` between the walk and the launch, and F-CI44a (this stub) is CAUGHT by it. The line's `GAP-REPORT.md:839` is at this section's base `9bd839491`; at task 044's base `6664cc655`, `grep -n "a stub that reads the folder again fails" lab/capsule-identity/GAP-REPORT.md` finds the sentence at `:849`.

Principles check:

1. Named by hash: yes. The asks come from the bundle whose lab CID was recomputed and
   compared with the requested CID before the record check (`tests/common/mod.rs:1536-1544`
   at 1503ac6f4).
2. No ambient authority: yes. Asks are bytes in a record and give no grant; the view stays
   empty after the launch (`tests/stand_in.rs:429`, `:495` at 1503ac6f4); no capsule, Home
   or UI code changes.
3. One path: yes. The asks come from `entries()` of the one walk, with no second read
   (`tests/common/mod.rs:1614-1620` at 1503ac6f4); the limit of the tests on this rule is
   the FOLLOWUP above, not a second path in the code.
4. Trusted core: not affected. No `elastos/`, `src/lib.rs`, `Cargo.toml` or `Cargo.lock`
   change (`git diff --stat 1503ac6f4^1 1503ac6f4`); the code is test code
   (`tests/common/mod.rs:1391` at 1503ac6f4).
5. Fails closed: not affected. 035 adds no refusal; an unknown session or a bundle with no
   `asks.json` answers `None` (`tests/common/mod.rs:1515-1519` at 1503ac6f4).
6. Self-contained: not affected. No capsule code; the stand-in runs nothing
   (`tests/common/mod.rs:1391` at 1503ac6f4).
7. Tests prove it: yes. Two named tests (`tests/stand_in.rs:392`, `:433` at 1503ac6f4) and
   three falsifiers, run at the base: `summary: 3 CAUGHT of 3`; one stub they cannot catch
   is the FOLLOWUP above.
8. Separate decisions: yes. What the bundle asks for (identity data in the signed bytes) is
   kept apart from a grant (allowance): a launch with asks leaves the grant view empty
   (`tests/stand_in.rs:429` at 1503ac6f4).

Commands and raw results for this section and the next, all at 9bd839491 on this Mac
(Python 3.9.6, rustc 1.91.0), holding the build lease (`.git/local-ai-heavy-build.lock`,
free: its recorded holder had exited; taken after 0 s), with `RUST_TEST_THREADS=2
CARGO_INCREMENTAL=0`. After the runner and the hand check, `git status --short` printed
nothing.

`python3 -I examples/agent-host/falsify.py --from lab/capsule-identity/falsifiers.json F-CI35`
(exit 0):

```
baseline: 2 named tests pass without an edit, 0 do not
F-CI35a CAUGHT                            11s  the planted accept-anything stub: asks_of reads asks.json from the stored folder at call time, so a change on disk after launch reaches the instance
F-CI35b CAUGHT                            14s  asks_of ignores the session and answers the first instance's asks
F-CI35c CAUGHT                            27s  a bundle with no asks.json is handed Some(Vec::new()), not None
summary: 3 CAUGHT of 3
```

`RUST_TEST_THREADS=2 cargo test --locked --offline --manifest-path lab/capsule-identity/Cargo.toml --test stand_in --test checked_bundle --test not_admission`
(exit 0):

```
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```

(in that order: `checked_bundle`, `not_admission`, `stand_in`).

#730 now has two reviews, Cursor's merge review and this record, with one FOLLOWUP for a
later task; the Runtime did nothing here: no Runtime code ran, launched, checked, refused,
granted or handed out any asks.

## PR #757 (task 036), merge b7c613a10

Added by task 041, on 2026-10-27, under the bar, base and form of the section above.
`src/lib.rs`, `tests/checked_bundle.rs`, `tests/not_admission.rs` and
`tests/variant_binding.rs` have no change after the merge, so for them M:line is also
B:line. `tests/common/mod.rs`, `tests/stand_in.rs`, README, LOG and `falsifiers.json` were
changed after it by 037 (`dd84ef2fe`) only.

Verdict: PASS

Lane diff: `git diff b7c613a10^1 b7c613a10 -- lab/capsule-identity/` (9 files, +273 -86):
`LOG.md`, `README.md`, `falsifiers.json`, `src/lib.rs`, `tests/checked_bundle.rs`,
`tests/common/mod.rs`, `tests/not_admission.rs`, `tests/stand_in.rs` and
`tests/variant_binding.rs`.

New FOLLOWUP lines: none.

- Promise 1 (`check_manifest` hands back the `name`; `manifest_name()`; nothing else
  changes; the export inventory allows only this accessor). At the merge, `check_manifest`
  (`src/lib.rs` M:1163) makes the one `CapsuleManifest` parse (M:1164) and returns
  `Ok((wasm, manifest.name))` (M:1168); the seam reads `let (wasm, name) =
  check_manifest(...)` (M:637) and builds `CheckedBundle` with `name` (M:640-645), a
  private field (M:295); `manifest_name` (M:679-681) answers `&self.name`. The library's
  diff has four hunks only (the doc and struct, the seam, the accessor, `check_manifest`):
  `lab_cid` (M:592), `LabCid` (M:240), `encode_entries` (M:809) and every `Refusal` text
  are untouched. `git grep CapsuleManifest` at the merge finds one parse in `src/` (M:1164);
  the tests' other parses read committed fixtures as their own expectations. 007's
  inventory (`tests/not_admission.rs` M:111) is 25 names with `manifest_name` added, and
  `the_harness_exports_only_identity_checks` (M:317) reports any extra `pub fn` not in that
  list (M:324-331), so an admit, grant or launch export is still refused; the forms
  `pub async fn admit`, `pub const fn grant`, `pub unsafe fn launch` are read as exports
  (M:249-251). Still true at 9bd839491 (no later change). The run below gives
  `test result: ok. 4 passed` for `not_admission`.
- Promise 2 (the stand-in reads the name only through `manifest_name()`). At the merge,
  `tests/common/mod.rs` no longer imports `CapsuleManifest` or `MANIFEST_FILE` (M:27-31),
  the helper `manifest_name` is gone, and `checked_launch` answers
  `checked.manifest_name().to_owned()` (M:1539). Still true at 9bd839491 (B:1544; 037
  changed only the doc above `StandInRuntime` and added a `BTreeSet` import to
  `tests/stand_in.rs`).
- Promise 3 (`checked_bundle_hands_out_the_manifest_name` uses names the test states). At
  the merge (`tests/checked_bundle.rs` M:315), the eight names are literals, the test
  asserts the list covers `FIXTURES` once, and compares each with `manifest_name()`
  (M:336). Each literal was checked against `"name"` in the committed
  `fixtures/<name>/capsule.json`: 8 checked, 8 match. Still true at 9bd839491.
- Promise 4 (the record rule and `standin_launch_does_not_depend_on_record_order`). At the
  merge, `check_records` (`tests/common/mod.rs` M:1547-1559) runs
  `verify_checked_package_record` on every record whose `cid` is the requested CID
  (M:1549), returns `Ok(())` at the first pass, else keeps the first refusal (M:1552) and
  answers it, else "unsigned:" (M:1555-1558). The test (`tests/stand_in.rs` M:272)
  launches from `[unaccepted, accepted]` and the reverse, each with one listed instance
  (M:299), then refuses two unaccepted signers with the first one's exact "not in the
  accepted list" text (M:314) and no instance (`assert_refused`, M:80-87, M:318-323).
  Still true at 9bd839491: `check_records` B:1552-1563, the test B:273, same text.
- Promise 5 (F-CI36a and F-CI36b, each CAUGHT). At the merge, F-CI36a makes
  `manifest_name` answer `""` (`src/lib.rs` M:680) and names
  `checked_bundle_hands_out_the_manifest_name` and
  `standin_launches_a_signed_bundle_by_its_cid`; F-CI36b adds `.take(1)` to the record
  filter (`tests/common/mod.rs` M:1549, B:1554). Both entries are the same at 9bd839491.
  The 17 older entries 036 changed (F-CI1f, 1g, 1k, 1l, 3a, 3b, 3i, 9a, 9b, 9c, 9d, 9e,
  9j, 12a, 32c, 32d and 33a, compared entry by entry between `b7c613a10^1` and the merge)
  keep their titles and tests, and no entry is gone, as LOG says. Runner result at
  9bd839491: `summary: 2 CAUGHT of 2` (raw lines below).
- Promise 6 (README: the accessor, the record rule, the rewrap, count and `about`). At the
  merge, README M:498-502 and the API row M:524 name the accessor, the rule row M:543
  names its test and F-CI36a, the export list M:844 and the stand-in note M:1317 name it;
  the record rule is the (g) row M:1340, the paragraph "Several records for one CID"
  M:1342-1352, the answer's `name` M:1356 and the rule row M:1412. The rewrap: the words of
  `b7c613a10^1` README `:16-19` and of the merge's `:16-20` are the same list (compared
  word by word), and the new lines are 74, 78, 76, 77 and 46 columns. The count is M:1628
  (259, and the list holds 259) and `about` ends "033, 035 and 036)". The text 036 added
  to README holds no `path:line` citation (0 checked); its LOG line (M:30) holds five,
  each checked with `git show`: `tests/checked_bundle.rs:336` and `tests/stand_in.rs:114`
  and `:296` at the merge are the asserts LOG says fail, and README `:16-19` at
  `b7c613a10^1` and `:16-20` at the merge are the sentence it says was rewrapped: 5
  checked, 5 match. Still true at 9bd839491: all of these lines are at the same numbers;
  037 changed the count (B:1628, 262) and `about`, and the "Task 036's" note is B:1744.
  The LOG line's whole-list result (259 of 259) was not rerun here, only F-CI36.
- Promise 7 (no `Cargo.toml`/`Cargo.lock` change; no assertion weakened). `git diff --stat
  b7c613a10^1 b7c613a10 -- lab/capsule-identity/Cargo.toml lab/capsule-identity/Cargo.lock`
  prints nothing. The changed assertions: `IDENTITY_FUNCTIONS` grows from 24 to 25
  (`tests/not_admission.rs` M:111), and `wasm_type_comes_from_the_one_manifest_check`
  (`tests/variant_binding.rs` M:1168) still asserts each seam text once (M:1204), now
  `let (wasm, name) = check_manifest(` (M:1201) and the struct literal with `name`. No
  assertion was removed, and no expected value was loosened. Still true at 9bd839491.

Principles check:

1. Named by hash: yes. A launch still finds its bundle and its records by the lab CID only;
   records are filtered by `record.cid == cid` (`tests/common/mod.rs:1549` at b7c613a10),
   and the manifest `name` is only the answer's display field (`:1539`).
2. No ambient authority: yes. The accessor answers a `&str` and grants nothing, and the
   export inventory still allows identity checks only (`tests/not_admission.rs:111`,
   `:317` at b7c613a10); no capsule, Home or UI code changes.
3. One path: yes. One manifest parse gives both the WASM flag and the name
   (`src/lib.rs:1163-1168` at b7c613a10), and the stand-in's second parse is gone
   (`tests/common/mod.rs:27-31`, `:1539`).
4. Trusted core: not affected. `src/lib.rs` is the lab library, not the Runtime; no
   `elastos/`, `capsules/`, `examples/`, `Cargo.toml` or `Cargo.lock` change
   (`git diff --stat b7c613a10^1 b7c613a10`).
5. Fails closed: yes. When no record for the CID passes, the launch is refused with the
   first record's own reason, or "unsigned:" when none binds it, and nothing is listed
   (`tests/common/mod.rs:1555-1558` at b7c613a10; `tests/stand_in.rs:318-323`).
6. Self-contained: not affected. No capsule code; the stand-in runs nothing
   (`tests/common/mod.rs:1390` at b7c613a10).
7. Tests prove it: yes. Two new named tests (`tests/checked_bundle.rs:315`,
   `tests/stand_in.rs:272` at b7c613a10) and two falsifiers, run at the base:
   `summary: 2 CAUGHT of 2`.
8. Separate decisions: yes. The name is identity data, "never a decision: it is no trust,
   admission or launch value" (`src/lib.rs:286-289` at b7c613a10); the record check
   decides the stand-in's launch, and the grant view is still separate (no change to it).

`python3 -I examples/agent-host/falsify.py --from lab/capsule-identity/falsifiers.json F-CI36`
(exit 0; the same lease and base as above):

```
baseline: 3 named tests pass without an edit, 0 do not
F-CI36a CAUGHT                            20s  manifest_name() answers an empty string, not the name the one manifest check read
F-CI36b CAUGHT                            14s  the stand-in checks only the first package record for the CID, so the launch depends on the records' order
summary: 2 CAUGHT of 2
```

The three `test result:` lines of `--test stand_in --test checked_bundle --test
not_admission` are in the section above (one run for both sections).

#757 now has two reviews, Cursor's merge review and this record. With task 039, every merged
B1 stand-in change has two: #587 (Claude and Cursor), #657 (Cursor and task 039's record)
and #757 (Cursor and this record). The Runtime did nothing here: no Runtime code ran,
launched, checked, refused or granted anything.

## PR #782 (task 037), head dd84ef2fe

Added by task 046, on 2026-10-28. Flint's URGENT M1 note of 27 Oct 11:10 sets one bar for
each M1 check through the lab stand-in: a full journey, a refusal with a reason plus a CAUGHT
falsifier, a planted stub that returns Ok without doing the work must FAIL, and two
independent reviews. #782 and #842 (next section) each had one reviewer only: the lane's
review step ran Cursor alone on them (both PASS in round 1), as on #730 and #757, so neither
had the second review the bar asks for; this record is that review. Both PRs were still open
in the batch (not merged) when this was written, so each is judged at its head, with
`git show <head>:<path>` (written "H:line" below).

Base commit of this section and the next: `c59703a06144ebeafd599d0b9c3d99616d804b3f`
(`c59703a06`), the lane tip, which holds both heads (`git merge-base --is-ancestor` passes
for each). Each promise then says "still true at c59703a06" (written "B:line"), or which
later commit changed it, from `git log --oneline <head>..HEAD -- <file>`. After dd84ef2fe,
`tests/common/mod.rs`, `tests/stand_in.rs`, README, LOG and `falsifiers.json` were changed
by 044 (`1421a5ec6`) only, and `src/lib.rs`, `Cargo.toml` and `Cargo.lock` by nothing. This
section fixes nothing.

Verdict: PASS

Lane diff: `git diff dd84ef2fe^1 dd84ef2fe -- lab/capsule-identity/` (5 files, +157 -19):
`LOG.md`, `README.md`, `falsifiers.json`, `tests/common/mod.rs` and `tests/stand_in.rs`. The
parent is `b7c613a10` (#757's merge).

New FOLLOWUP lines: none.

- Promise 1 (`standin_grant_view_lists_every_held_grant_of_every_session`). At the head
  (`tests/stand_in.rs` H:439), the signed `agent-host` bundle is launched twice (H:442-443)
  and the two session ids must differ (H:446); three grants are seeded, one for A and two
  for B, with three different `(resource, action)` pairs (H:449-468, seeded at H:470); the
  view must hold exactly 3 entries ("every held grant is listed", H:474); the sorted
  `(session_id, resource, action, duration)` tuples must equal the sorted seeded list
  (H:490); each session must appear (H:492); the three `request_id` values must differ
  ("three different request ids", H:503-505); the instance list stays at 2 (H:509).
  Resource, action and duration are the test's literals; the two session ids are the launch
  answers' values, which the test holds before it seeds and never reads from the view.
  033's two tests (`standin_valid_signature_alone_yields_no_grant` H:367,
  `standin_grant_view_lists_a_seeded_grant` H:403) are unchanged: the diff removes no line
  of `tests/stand_in.rs` (`grep -c '^-[^-]'` prints 0). Still true at c59703a06: the test is
  the same text at B:438-511 (`diff` of the two ranges prints nothing); 044 added its own
  test after it. The run below gives `ok` for it.
- Promise 2 (F-CI37a, F-CI37b, F-CI37c, each CAUGHT). At the head, each edits only
  `../../lab/capsule-identity/tests/common/mod.rs` and names only the new test. F-CI37a
  adds `.take(1)` and F-CI37b a filter to the first held grant's session, both on the view's
  line `self.grants.iter().map(Grant::entry).collect();` (H:1493), which is F-CI33b's anchor
  too (same `old` text); F-CI37c makes `seed_grant` give every grant `grant-1`, on
  `request_id: format!("grant-{number}"),` (H:1505), a line task 033 added (`git log -S`
  finds `f767631f1`). Each anchor is found once at the head (`grep -c -F` prints 1 each).
  F-CI37b leaves session A's one grant, so it fails at "every held grant is listed"; F-CI37c
  fails only at "three different request ids", the reason its title names. Still true at
  c59703a06: the three entries are unchanged (`git diff dd84ef2fe HEAD --
  lab/capsule-identity/falsifiers.json` has no F-CI37 line, F-CI37a at B:4306), and the
  anchors are B:1498 and B:1510, each found once. Runner result at c59703a06:
  `summary: 3 CAUGHT of 3` (raw lines below).
- Promise 3 (the `StandInRuntime` doc names every public method, no count word, no code
  change). At the head, the doc (`tests/common/mod.rs` H:1366-1394) names `new` (H:1369),
  `post_capsules` and `get_capsules` by RA-6's routes, the grant view by RA-1's route, and
  `seed_grant` and `asks_of` as "Lab test seam, not a route" (H:1375-1376). The impl block
  (H:1439-1608) has 6 `pub fn` (`new` H:1442, `post_capsules` H:1461, `get_capsules`
  H:1469, the view H:1492, `seed_grant` H:1502, `asks_of` H:1519): 6 checked, 6 named. The
  doc's number words ("one of two states", "one new instance", "one request field") count
  launch states and fields, not methods; "Its two methods" is gone. With `///` lines
  removed, `diff` of the parent's and the head's `tests/common/mod.rs` prints nothing, so
  no code line changed. Changed by 044 (`1421a5ec6`), and still true at c59703a06: 044
  added `set_after_walk` (B:1536) and its doc line (B:1377); the impl block (B:1443-1627)
  has 7 `pub fn`, each named in B:1366-1397.
- Promise 4 (README row, count, `about`). At the head, the row (README H:1417) says "lists
  every held grant of every session" and names both tests, F-CI33b and F-CI37a-c; the
  count is H:1628 (262, and `grep -c '"id": "F-CI'` on the list prints 262); the
  Falsifiers list names F-CI37a to F-CI37c (H:1666-1667), the anchor note is H:1758-1762
  and the runner record H:1898-1900; `about` ends "036 and 037)", 037 last, in list order.
  The LOG line is H:31. The text 037 added to README and LOG holds no `path:line` citation
  (0 checked); its two anchor claims were checked instead (Promise 2): 2 checked, 2 match.
  Still true at c59703a06: the row is B:1417, same text; 044 changed the count (B:1640,
  265, and the list holds 265) and `about` (ends "037 and 044)"); the note is B:1772 and
  the record B:1917-1919. The `--test inventory` run below checks count and `about` at
  c59703a06. The LOG line's whole-list result (262 of 262) was not rerun here, only F-CI37.
- Promise 5 (no `src/lib.rs`, `Cargo.toml` or `Cargo.lock` change; no assertion weakened).
  `git diff --stat dd84ef2fe^1 dd84ef2fe -- lab/capsule-identity/src
  lab/capsule-identity/Cargo.toml lab/capsule-identity/Cargo.lock` prints nothing; the diff
  removes no test line, and in `tests/common/mod.rs` only `///` lines. Still true at
  c59703a06: `git log dd84ef2fe..HEAD` on those three paths prints nothing.

Principles check:

1. Named by hash: not affected. 037 changes no launch or lookup; both sessions come from
   launches of the signed bundle by its lab CID (`tests/stand_in.rs:442-443` at dd84ef2fe).
2. No ambient authority: yes. A grant exists only through the test seam `seed_grant`
   (`tests/common/mod.rs:1497-1502` at dd84ef2fe), and the view lists only held grants
   (`:1493`); no capsule, Home or UI code changes.
3. One path: yes. One view method (`tests/common/mod.rs:1492-1494` at dd84ef2fe), now
   tested past one grant; no second view or second grant store.
4. Trusted core: not affected. Test code only; no `elastos/`, `src/lib.rs`, `Cargo.toml` or
   `Cargo.lock` change (`git diff --stat dd84ef2fe^1 dd84ef2fe`).
5. Fails closed: not affected. 037 adds no refusal; its `tests/common/mod.rs` change is doc
   only (`:1366-1394` at dd84ef2fe).
6. Self-contained: not affected. No capsule code; the stand-in runs nothing
   (`tests/common/mod.rs:1367` at dd84ef2fe).
7. Tests prove it: yes. One named test (`tests/stand_in.rs:439` at dd84ef2fe) and three
   falsifiers, run at the base: `summary: 3 CAUGHT of 3`.
8. Separate decisions: yes. Launching (admission) adds no grant (allowance): seeding is not
   a launch and launching is not a grant (`tests/stand_in.rs:509` at dd84ef2fe; 033's
   `standin_valid_signature_alone_yields_no_grant`, `:367`, unchanged).

Commands and raw results for this section and the next, all at c59703a06 on this Mac
(Python 3.9.6, rustc 1.91.0), with the build lease free (`.git/local-ai-heavy-build.lock`
had no holder in `lsof`), with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`. The three runner
calls ran one after another, then the cargo run; after them `git status --short` printed
nothing.

`python3 -I examples/agent-host/falsify.py --from lab/capsule-identity/falsifiers.json F-CI37`
(exit 0):

```
baseline: 1 named tests pass without an edit, 0 do not
F-CI37a CAUGHT                             7s  the grant view lists only the first held grant
F-CI37b CAUGHT                             8s  the grant view lists only the grants of the first held grant's session, the caller's-own-session shape
F-CI37c CAUGHT                             7s  seed_grant gives every grant the same request_id
summary: 3 CAUGHT of 3
```

`RUST_TEST_THREADS=2 cargo test --locked --offline --manifest-path lab/capsule-identity/Cargo.toml --test stand_in --test inventory`
(exit 0):

```
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```

(in that order: `inventory`, with `the_falsifier_inventory_matches_the_list` among its 3;
`stand_in`, with `standin_grant_view_lists_every_held_grant_of_every_session` and
`standin_takes_the_asks_from_the_walk_not_the_folder` among its 10).

#782 now has two reviews, Cursor's review and this record, with no FOLLOWUP. The Runtime did
nothing here: no Runtime code ran, launched, checked, refused or granted anything.

## PR #842 (task 044), head 1421a5ec6

Added by task 046, on 2026-10-28, under the bar, base and form of the section above.
Nothing in `lab/capsule-identity/` changed after 1421a5ec6 except `SECOND-REVIEW.md` (045,
`c59703a06`, which added lines above 044's line in the #730 section), so for every other
file H:line is also B:line.

Verdict: FOLLOWUP

Lane diff: `git diff 1421a5ec6^1 1421a5ec6 -- lab/capsule-identity/` (7 files, +140 -8):
`GAP-REPORT.md`, `LOG.md`, `README.md`, `SECOND-REVIEW.md`, `falsifiers.json`,
`tests/common/mod.rs` and `tests/stand_in.rs`. The parent is `6664cc655` (043).

- Promise 1 (one hook, one public seam, called once right after the walk and before (e);
  no hook, no change; `post_capsules` the one launch path; the struct doc). At the head,
  `StandInRuntime` holds `after_walk: Option<fn(&Path)>` (`tests/common/mod.rs` H:1404),
  `None` in `new` (H:1457); `set_after_walk` (H:1536-1538) is the one public method that
  sets it, documented "Lab test seam, not a route" (H:1531). `checked_launch` calls the
  hook once, on the stored `folder`, at H:1558-1560, right after
  `let checked = checked_bundle(folder)` (H:1557) and before `checked.check_name(&cid)`
  (H:1561, check (e)); with `None`, the `if let` calls nothing. `checked_launch` has one
  caller, `post_capsules` (H:1467), so the launch path is still one. The struct doc names
  the method (H:1377, H:1395-1397) with no count word. Still true at c59703a06 (same
  lines). The 9 older `stand_in` tests run with no hook and give `ok` below.
- Promise 2 (`standin_takes_the_asks_from_the_walk_not_the_folder`). At the head
  (`tests/stand_in.rs` H:568), the hook is `change_stored_asks_after_the_walk` (H:563,
  one byte of the stored `asks.json`); the launch must answer `launched` (H:576-577); the
  stored file must differ from the fixture bytes the test reads itself (H:571, H:582-586,
  "the hook must have changed the stored asks.json"); `asks_of` must equal those fixture
  bytes (H:589-593, "a change on disk between the walk and the launch must not reach the
  instance"); one instance and an empty grant view (H:594-595). 035's two tests
  (H:522, H:599) are unchanged: the diff removes no line of `tests/stand_in.rs`. Not a
  finding: the hook is the statement right after the walk (H:1557-1558), so only a folder
  read written in between those two lines would escape it; the stub the M1 bar names, a
  read of the folder in place of the walk's bytes at launch, is F-CI44a and is CAUGHT.
  Still true at c59703a06 (same lines). The run below gives `ok` for it.
- Promise 3 (F-CI44a, F-CI44b, F-CI44c, each CAUGHT; F-CI35a still CAUGHT). At the head,
  each edits only `../../lab/capsule-identity/tests/common/mod.rs` and names only the new
  test: F-CI44a puts `fs::read(folder.join(ASKS_FILE)).ok()` in place of
  `signed_asks(&checked)` on the answer line (H:1563), F-CI44b deletes `hook(folder);`
  (H:1559), F-CI44c moves the hook above the walk (anchor H:1557-1560). Each anchor is found
  once (`grep -c -F` prints 1 for the answer line and for the hook call). The F-CI35
  entries are unchanged by 044 (the `falsifiers.json` diff only adds F-CI44 and 044 in
  `about`). Still true at c59703a06 (same lines; F-CI44a starts at B:4354). Runner results
  at c59703a06: F-CI44 `summary: 3 CAUGHT of 3`, F-CI35 `summary: 3 CAUGHT of 3` (raw lines
  below).
- Promise 4 (README: how "Nothing reads the folder again" is shown, the row, count 265,
  `about`). At the head, README H:1443-1447 says the hook is called once on the stored
  folder, right after the one walk and before (e); H:1463-1469 describes the new test;
  the row H:1476 names it and F-CI44a-c; the count is H:1640 (265, and the list holds 265);
  the Falsifiers list H:1679-1681, the anchor note H:1777-1781 and the runner record
  H:1919-1922 name 044; `about` ends "037 and 044)", 044 last. Still true at c59703a06
  (same lines); the `--test inventory` run below checks count and `about`. The LOG line's
  whole-list result (265 of 265) was not rerun here, only F-CI44 and F-CI35.
- Promise 5 (one dated GAP-REPORT sentence after 035's B2 paragraph; that paragraph
  unchanged). At the head, it is `GAP-REPORT.md` H:854-858, dated "28 Oct, task 044", right
  after the 035 paragraph (H:847-853); the diff adds 5 lines and removes none. What it says
  holds: before 044 only F-CI35a was caught for B2 re-reads (041's FOLLOWUP, the #730
  section), and F-CI44a is now CAUGHT by the named test. Still true at c59703a06 (same
  lines). Its date disagrees with the LOG line: the FOLLOWUP below.
- Promise 6 (one "Answered by task 044" line after the #730 `FOLLOWUP:`, nothing else in
  this file). At the head, the diff of `SECOND-REVIEW.md` is one added line (H:590, right
  after the `FOLLOWUP:` at H:589). Changed by 045 (`c59703a06`) in place only: 045 added
  lines above it, so the line is B:596, same text (`git diff 1421a5ec6 HEAD` has no line
  with "Answered by task 044").
- Promise 7 (no `src/lib.rs`, `Cargo.toml` or `Cargo.lock` change; no assertion weakened).
  `git diff --stat 1421a5ec6^1 1421a5ec6` on those three paths prints nothing; the diff
  removes no test line, and in `tests/common/mod.rs` only three doc lines, each rewritten
  with more text (H:1377, H:1395, H:1547). Still true at c59703a06 (no later change).

Citations: the text 044 added to README, LOG, GAP-REPORT and SECOND-REVIEW holds 4
`path:line` citations, each checked with `git show`: `GAP-REPORT.md:839` at `9bd839491`
and `:849` at `6664cc655`, in the `SECOND-REVIEW.md` line (H:590) and again in the LOG line
(H:32); `sed -n` on each prints "does not reach it and a stub that reads the folder again
fails". 4 checked, 4 match.

Cursor's LOG date finding, checked by its reproduction command at c59703a06, `grep -n
"task 044" lab/capsule-identity/LOG.md lab/capsule-identity/GAP-REPORT.md`: it prints two
lines, `LOG.md:32` (which says GAP-REPORT got 'one dated "27 Oct, task 044" sentence') and
`GAP-REPORT.md:854` (which starts "28 Oct, task 044:"). 044's commit `1421a5ec6` is dated
28 Oct 01:18 +0700. The finding holds; it is not fixed here.

FOLLOWUP: lab/capsule-identity/LOG.md:32 says GAP-REPORT gained one dated "27 Oct, task 044" sentence, but that sentence (lab/capsule-identity/GAP-REPORT.md:854) is dated "28 Oct, task 044", as is 044's commit 1421a5ec6 (28 Oct 01:18 +0700); hand check: `grep -n "task 044" lab/capsule-identity/LOG.md lab/capsule-identity/GAP-REPORT.md | grep -o '[0-9][0-9] Oct, task 044'` prints `27 Oct, task 044` then `28 Oct, task 044`.

Principles check:

1. Named by hash: yes. The instance is handed the bytes of the one walk whose lab CID was
   compared with the requested CID (`tests/common/mod.rs:1557`, `:1561`, `:1563` at
   1421a5ec6).
2. No ambient authority: not affected. The hook is a test-only seam that grants nothing;
   the grant view stays empty after the launch (`tests/stand_in.rs:595` at 1421a5ec6); no
   capsule, Home or UI code changes.
3. One path: yes. `post_capsules` stays the one caller of `checked_launch`
   (`tests/common/mod.rs:1467` at 1421a5ec6), and the hook runs inside it (`:1558-1560`);
   the asks still come only from `signed_asks(&checked)` (`:1563`).
4. Trusted core: not affected. Test code only; no `elastos/`, `src/lib.rs`, `Cargo.toml` or
   `Cargo.lock` change (`git diff --stat 1421a5ec6^1 1421a5ec6`).
5. Fails closed: not affected. 044 adds no refusal; with the hook before the walk
   (F-CI44c), the existing check (e) refuses (`tests/common/mod.rs:1561` at 1421a5ec6).
6. Self-contained: not affected. No capsule code; the stand-in runs nothing
   (`tests/common/mod.rs:1367` at 1421a5ec6).
7. Tests prove it: yes. One named test (`tests/stand_in.rs:568` at 1421a5ec6) and three
   falsifiers, run at the base: `summary: 3 CAUGHT of 3`; F-CI35 still 3 of 3.
8. Separate decisions: yes. The asks are identity data from the signed bytes and give no
   grant: after the launch the grant view is empty (`tests/stand_in.rs:595` at 1421a5ec6).

`python3 -I examples/agent-host/falsify.py --from lab/capsule-identity/falsifiers.json F-CI44`
(exit 0; the same lease and base as above):

```
baseline: 1 named tests pass without an edit, 0 do not
F-CI44a CAUGHT                             7s  the 041 review's stub: checked_launch reads asks.json from the stored folder at launch, after the walk, instead of taking it from the checked entries
F-CI44b CAUGHT                             8s  the after-walk hook is never called, so the test's change on disk never happens
F-CI44c CAUGHT                             6s  the after-walk hook runs before the walk, so the changed bytes are walked and the name compare (e) refuses the launch
summary: 3 CAUGHT of 3
```

`python3 -I examples/agent-host/falsify.py --from lab/capsule-identity/falsifiers.json F-CI35`
(exit 0):

```
baseline: 2 named tests pass without an edit, 0 do not
F-CI35a CAUGHT                             4s  the planted accept-anything stub: asks_of reads asks.json from the stored folder at call time, so a change on disk after launch reaches the instance
F-CI35b CAUGHT                             4s  asks_of ignores the session and answers the first instance's asks
F-CI35c CAUGHT                             4s  a bundle with no asks.json is handed Some(Vec::new()), not None
summary: 3 CAUGHT of 3
```

The two `test result:` lines of `--test stand_in --test inventory` are in the section above
(one run for both sections).

#842 now has two reviews, Cursor's review and this record, with one FOLLOWUP for a later
task (the LOG date). Every stand-in change the B1 and B2 evidence rests on now has two:
#587 (Claude and Cursor at merge; no section here), #657 (Cursor and "PR #657 (task 033),
merge f94d89ac6"), #730 (Cursor and "PR #730 (task 035), merge 1503ac6f4"), #757 (Cursor
and "PR #757 (task 036), merge b7c613a10"), #782 (Cursor and "PR #782 (task 037), head
dd84ef2fe") and #842 (Cursor and this section). The Runtime did nothing here: no Runtime
code ran, launched, checked, refused, granted or handed out any asks.
