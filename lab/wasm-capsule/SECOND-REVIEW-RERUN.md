# Second review, run again by an independent reader

Rong (27 Oct, per Sasha's 25 Oct direction) asked for the second reviews in
`SECOND-REVIEW.md` to be run again by an independent second reviewer, because
each of lab PRs #608 and #621, which hold them, had one reviewer.

- Task 058 re-runs #608's part: lab PR #231 (task 024) and lab PR #235 (task
  025).
- Task 059 re-runs #621's part: lab PRs #238, #240, #241 and #245, in this same
  file.

Task 058's base, from `git rev-parse HEAD` before the first edit:
`8b291d65dccd1d363771c6399c3aada1b1ce7b49` (written `8b291d65d` below).

How this was done. Both PR sections were written from the merges
(`git show <merge>:<path>`, `git diff`) and from runs at the base, before
`SECOND-REVIEW.md` was opened. Only then was it read, for the comparison
section. Every run below was made from the repo root at the base, on this Mac.
`$S` is a new scratch folder outside the repo (`mktemp -d /tmp/rerun058.XXXXXX`);
nothing under `lab/` was changed by a run (`git status --short` empty after
them). The `tools/bundle` build and the canonical runner ran while holding the
shared build lease (taken after a 20 s wait).

A line `file:line` with no commit is at the base. A line `<commit>:file:line`
was read with `git show <commit>:lab/wasm-capsule/<file>`. Paths are under
`lab/wasm-capsule/` unless they say otherwise.

## PR #231 (task 024), merge f1f627250

Verdict: PASS

Lane diff `git diff f1f627250^1 f1f627250 -- lab/wasm-capsule/`: 7 files, +220
-52 (`ADOPTION.md`, `LOG.md`, `README.md`, `tests/bundle.rs`,
`tests/common/mod.rs`, `tests/lab_cid.rs`, `tests/run.rs`).

- Promise 1, the pins were recomputed outside the lab code, after the script
  first reproduced cc-capsule-identity's `content-sample` pin, and a pin was set
  only where it equals `bundle_identity`. Evidence at the merge: the script is
  `f1f627250:LOG.md:230-315` (84 lines between the fences, standard library
  only: it imports `hashlib`, `os`, `stat`, `sys` and no lab code); its checks
  and runs are `f1f627250:LOG.md:316-329`. Run at `8b291d65d`: the 84 lines
  copied out of LOG (the same at the merge and at the base, `diff` empty),
  `sed -n '231,314p'` with the two-space indent removed, into
  `$S/outside_cid.py` (sha256 `f2dd94a5f15cbd0c309ce30fe8f56a0d9128f36b5d1cb32a7180b65ff3a77bc5`).
  It ran as written, so LOG's text is complete enough to run.
  - `python3 -I $S/outside_cid.py lab/capsule-identity/fixtures/content-sample`
    printed `bafybeieahlroxjdalpmglh227eikmodrjhrlelvzlhylvyt3s65ackiybi`, that
    lane's committed pin (`lab/capsule-identity/tests/common/mod.rs:39`).
  - A copy with byte 1 of `sample.example` changed (`cmp -l`: `1 145 130`):
    `python3 -I $S/outside_cid.py $S/content-sample-changed` printed
    `bafybeihe2nuwvsnlpuwclyyvcxa6b254k6azmm7t3vixhodnpb5m365gva`, a different
    value (the same one LOG records).
  - Bundle (i), as `this_capsule_bundle` (`tests/lab_cid.rs:24-30`) builds it:
    `$S/module-bundle/` = `capsule/capsule.json` (277 bytes) as `capsule.json`
    and the 8 bytes `00 61 73 6d 01 00 00 00` as `capsule.wasm`.
    `python3 -I $S/outside_cid.py $S/module-bundle` printed
    `bafybeihtyzfql54i7irft23lg2mk44toqdww53ryuhs2psrknfjw4qhpcy`, and
    `lab/wasm-capsule/tools/bundle --name $S/module-bundle` (`bundle_identity`)
    printed the same. Both equal `MODULE_BUNDLE_LAB_CID`
    (`tests/common/mod.rs:20-21`).
  - Bundle (ii): `lab/wasm-capsule/tools/bundle $S/reference-out` exited 0 and
    printed `bafybeiebyzg55l4s6kb6daroty4prlkximwp6uvo32ovacfzdx7cahywqm`; its
    `bundle/capsule.wasm` is 180 bytes, `shasum -a 256`
    `2002429e73ee1a5e983df008f5b53728882646f109d55a9d1a93e831690631e1`
    (= `PINNED_ARTIFACT_SHA256`, `tests/common/mod.rs:30-31`).
    `python3 -I $S/outside_cid.py $S/reference-out/bundle` and
    `tools/bundle --name $S/reference-out/bundle` both printed
    `bafybeiebyzg55l4s6kb6daroty4prlkximwp6uvo32ovacfzdx7cahywqm`, which equals
    `REFERENCE_LAB_CID` (`tests/bundle.rs:37`).

  Still true at `8b291d65d`: both pins equal the outside script's output and
  `bundle_identity`'s. Changed by `3df3dcb83` (PR #306, task 032): bundle (ii)'s
  pin, `bafybeib34owcqffbwkntlhvbjngcj7eyeqqxx7aoefehqt2dqm2yu5jwse` at
  `f1f627250:tests/bundle.rs:40`, became `bafybeiebyzg...` when `capsule.wasm`
  gained its memory maximum (the 178-byte `6dd9af1a...` module no longer
  builds at the base). That old value was not re-run here; it is pinned
  nowhere at the base except as history (`README.md:347`, `ADOPTION.md:209`).
- Promise 2, the script named both lane bundles. Evidence at the merge:
  `f1f627250:LOG.md:321-325` (bundle (i), `capsule/capsule.json` beside the
  8-byte module as `capsule.wasm`) and `f1f627250:LOG.md:325-329` (bundle (ii),
  `tools/bundle target/recompute-024/reference-out`, with its module's sha256).
  Still true at `8b291d65d`: the LOG entry is unchanged at the same lines, and
  the run above named both bundles again.
- Promise 3, one module-bundle pin. Evidence at the merge: the only definition
  is `f1f627250:tests/common/mod.rs:18-19`; it is imported at
  `f1f627250:tests/lab_cid.rs:13` and `f1f627250:tests/bundle.rs:14`, and
  asserted at `f1f627250:tests/lab_cid.rs:74` and `f1f627250:tests/bundle.rs:223`.
  The diff removes both old copies (`PINNED_LAB_CID` in `tests/lab_cid.rs`,
  `MODULE_BUNDLE_LAB_CID` in `tests/bundle.rs`). Still true at `8b291d65d`:
  defined once at `tests/common/mod.rs:20-21`, asserted at
  `tests/lab_cid.rs:74` and `tests/bundle.rs:220`; `grep -rn
  --exclude-dir=target bafybeihtyzfql54 lab/wasm-capsule/` finds the value in
  Rust only at `tests/common/mod.rs:21` (the rest are README, ADOPTION, LOG and
  `SECOND-REVIEW.md`). The lines moved under `a5b4e8a10` (`pub mod grants`) and
  `3df3dcb83` (which put `PINNED_ARTIFACT_SHA256` beside it, also as one pin).
- Promise 4, `tests/run.rs` parses the printed name. Evidence at the merge:
  `f1f627250:tests/run.rs:24` imports `LabCid`; `f1f627250:tests/run.rs:1402-1410`
  parses the name with `LabCid`'s `FromStr` and asserts it prints back the same
  string; the diff removes `assert!(cid.starts_with("lab-cid:sha256:"), ...)`.
  Still true at `8b291d65d`: `tests/run.rs:32` and `:1895-1903`; no
  `starts_with("bafy` or `starts_with("lab-cid` is left in `tests/` or
  `tools/src/` (`grep -rn`, empty).
- Promise 5, README and ADOPTION describe the 59-character CIDv1 `bafybei...`
  UnixFS root. Evidence at the merge: `f1f627250:README.md:133-137`, `:182` and
  `:316` (both pins), `:165` (tests read a printed name only through
  `str::parse::<capsule_identity::LabCid>`); `f1f627250:ADOPTION.md:115-117` and
  `:170-183`. Still true at `8b291d65d`: `README.md:153`, `:183`, `:200`,
  `:339`; `ADOPTION.md:140`, `:195-209`. Changed by `3df3dcb83`: the
  `tools/bundle` pin text now gives the new value and names the old one.
- Promise 6, no new `falsifiers.json` entry and no new dependency. Evidence at
  the merge: the lane diff's file list has no `falsifiers.json`, `Cargo.toml`,
  `Cargo.lock` or `tools/` file; the `LabCid` import needs none, because
  `capsule-identity` was already a path dependency of the root package
  (`f1f627250^1:Cargo.toml:42`). Still true for this merge; at the base,
  `Cargo.lock` was later changed only by `614b85df8` (PR #700, cx-wasm-audit
  029, 5 lines removed), which is not this lane's work.

## PR #235 (task 025), merge a5b4e8a10

Verdict: PASS

Lane diff `git diff a5b4e8a10^1 a5b4e8a10 -- lab/wasm-capsule/`: 10 files,
+1366 -91. The carried commit is `5f3d23418` (task 020, base `36fa6d89c`).

- Promise 1, every lane change of `5f3d23418` is on the branch, merged with the
  base's changes. `git diff 5f3d23418 a5b4e8a10 -- lab/wasm-capsule/`: 8 files,
  +238 -55. Each hunk accounted for:
  - Base change (task 024): `ADOPTION.md`, `README.md`, `tests/bundle.rs`,
    `tests/common/mod.rs`, `tests/lab_cid.rs`, `tests/run.rs`. For each file, the
    sequence of `+`/`-` lines equals that of `git diff 36fa6d89c a5b4e8a10^1`
    (compared by `shasum`). That base diff is exactly #231's lane diff:
    `git diff 36fa6d89c f1f627250^1 -- lab/wasm-capsule/` and
    `git diff f1f627250 a5b4e8a10^1 -- lab/wasm-capsule/` are both empty.
  - `LOG.md`: the base's 121 added lines (024's entry), then the merge's own 40:
    26 are task 020's entry, line for line the 26 lines `5f3d23418` added
    (`diff` empty), and 14 are 025's own entry (`a5b4e8a10:LOG.md:372-385`).
  - `tools/src/verify.rs`: one hunk, 025's own addition (the module doc, promise
    2).
  - Carried byte for byte (`git diff --quiet 5f3d23418 a5b4e8a10` exit 0):
    `falsifiers.json`, `tests/common/grants.rs`, `tests/verify.rs`,
    `tools/src/run.rs`.
  - The other way: for each of the 10 lane files `5f3d23418` changed, its `+`/`-`
    lines in `git diff 36fa6d89c 5f3d23418` equal those in
    `git diff a5b4e8a10^1 a5b4e8a10`, except `LOG.md` and `tools/src/verify.rs`,
    which differ only by 025's own lines above. No lane change of `5f3d23418` is
    missing.

  Still true at `8b291d65d` in the sense that nothing was dropped at the merge;
  the files were changed later by many merges (for example `tools/src/verify.rs`
  by `b8c1dcedb`, PR #279, task 031).
- Promise 2, the module doc says the verifier "reads no bundle file by path".
  Evidence at the merge: `a5b4e8a10:tools/src/verify.rs:26-29` ("It reads no
  bundle file by path ... The one file it reads by a path is the lab grants
  file"). The code bears it out: the only `fs::read` in `tools/src/verify.rs` is
  in `read_grants` (`a5b4e8a10:tools/src/verify.rs:337`), and the tools crate has
  no other `fs::read`, `File::open` or `read_to` in `verify.rs`, `run.rs`,
  `receipt.rs`, `bundle.rs` or `lib.rs`. Still true at `8b291d65d`:
  `tools/src/verify.rs:33-36`, the one `fs::read` at `:455`.
- Promise 3, the named tests. Evidence at the merge, all in `tests/run.rs`:
  `zero_grants_zero_imports_runs` (`a5b4e8a10:tests/run.rs:1863`),
  `declared_not_granted_import_refuses_instantiation_by_name` (`:1936`),
  `valid_signature_with_empty_grants_file_links_nothing` (`:1960`), Rong's
  rename `grant_for_an_import_the_module_does_not_have_links_nothing_and_is_reported`
  (`:1974`) and `granted_import_is_linked` (`:1990`). Read: each signs a fresh
  bundle, reads a grants file outside it with `read_grants` and runs `run` on
  counting stand-ins; the refusal test asserts the exact refusal value and text
  `undeclared import env.f`, no run folder and zero engine starts; the
  unused-grant test asserts `linked() == []` and `unused_grants() == [env.f]`.
  "Linked" means the verifier's reported list: the stand-ins host nothing, and
  README says so (`a5b4e8a10:README.md:719`, "Allowed through, not hosted
  (wc-009b)"). Each named test can fail for its reason: the runner run below
  catches F-WC9-LINK-ALL with the refusal test, F-WC9-GRANT-INJECT with the
  unused-grant test, and F-WC9-RUN-DROPS-GRANTS with `granted_import_is_linked`.
  Still true at `8b291d65d`: `tests/run.rs:2376`, `:2450`, `:2474`, `:2488`,
  `:2504`, all passing in `cargo test --locked`. Changed by `b8c1dcedb` (PR
  #279, task 031: each written grant has a right, `("env", "f", "call")`) and
  `ad885d9d2` (PR #381, task 039: `granted_import_is_linked` reads each
  engine's module from the stand-in's record, because the run folder is now
  removed); the assertions the promise names are the same.
- Promise 4, the 17 `F-WC9-*` entries and the four re-anchored entries are
  caught by the canonical runner. Evidence at the merge: the 17 entries added
  and the five changed (F-WC5a, F-WC5-VERIFY-TWICE, F-WC5-QUERY-BEFORE-VERIFY,
  F-WC4-SEALED-NEW, and F-WC-README-COUNT's count) are what `a5b4e8a10:falsifiers.json`
  adds and changes against its first parent, and it equals
  `5f3d23418:falsifiers.json`. 025's own run (`a5b4e8a10:LOG.md:380-383`,
  "summary: 21 CAUGHT of 21") named `F-WC9`, three of the four re-anchored
  entries and F-WC-README-COUNT, not F-WC4-SEALED-NEW; the merge's evidence for
  F-WC4-SEALED-NEW was task 020's run at `5f3d23418`
  (`a5b4e8a10:LOG.md:361-365`, "93 CAUGHT of 94", the one BUILD FAILED being
  F-WC5a, then re-run alone). Run at `8b291d65d`: every `F-WC9-*` id in the list
  (all 18 edit only `../../lab/wasm-capsule/` files; none was removed; the
  18th, F-WC9-RUN-DROPS-GRANTS, came with `a541cd7ba`, PR #269, task 029) and the
  four re-anchored entries:

  ```
  python3 -I examples/agent-host/falsify.py --from lab/wasm-capsule/falsifiers.json \
    F-WC9-LINK-ALL F-WC9-GRANT-INJECT F-WC9-GRANTS-LABEL F-WC9-GRANTS-CAUSE \
    F-WC9-GRANTS-NOT-JSON F-WC9-GRANTS-NOT-OBJECT F-WC9-GRANTS-UNKNOWN-KEY \
    F-WC9-GRANTS-MISSING-KEY F-WC9-GRANTS-SCHEMA F-WC9-GRANTS-IMPORTS-NOT-LIST \
    F-WC9-GRANTS-ENTRY-EXTRA-KEY F-WC9-GRANTS-ENTRY-NOT-STRING F-WC9-GRANTS-DUPLICATE \
    F-WC9-UNUSED-KEEPS-USED F-WC9-UNUSED-REORDER F-WC9-GRANTS-READ-TWICE \
    F-WC9-GRANTS-PARSE-TWICE F-WC9-RUN-DROPS-GRANTS \
    F-WC5a F-WC5-VERIFY-TWICE F-WC5-QUERY-BEFORE-VERIFY F-WC4-SEALED-NEW
  baseline: 10 named tests pass without an edit, 0 do not
  summary: 22 CAUGHT of 22
  ```

  Exit 0, every line `CAUGHT`. Still true at `8b291d65d`.
- Promise 5, README keeps the link rule in Rong's words, the grants file
  format, the exact label and the hand-proven labels. Evidence at the merge:
  `a5b4e8a10:README.md:656-668` (the rule, quoted: "link an import only if it is
  in the signed module AND in the lab grants file; the grants file stays outside
  the bundle, labelled 'lab stand-in, not admission'"), `:675-680` (the format,
  schema `wc-009.lab-grants/v1`), `:682-684` (the label, exactly "lab stand-in,
  not admission"), and `:1350-1354` (the `&[]` plant in `run.rs` "is
  hand-proven, pending R1 ... outside every count above"). Still true at
  `8b291d65d` for the rule (`README.md:899-912`) and the label (`:922`, `:941`).
  Changed by `b8c1dcedb` (PR #279, task 031): the format is now
  `wc-009.lab-grants/v2`, with a `right` per import (`README.md:922`). Changed by
  `a541cd7ba` (PR #269, task 029): the `run.rs` plant is now the runner entry
  F-WC9-RUN-DROPS-GRANTS (`README.md:2963`), runner-caught (run above), so its
  hand-proven label is gone on purpose.
- Promise 6, no new dependency. Evidence at the merge: the lane diff's file list
  has no `tools/Cargo.toml`, `Cargo.toml` or `Cargo.lock`. Still true for this
  merge; at the base, `Cargo.lock` was later changed only by `614b85df8` (PR
  #700, cx-wasm-audit 029).
- The one-path rule (P10). Evidence at the merge: the verifier's one
  `audit(module, granted)` call is `a5b4e8a10:tools/src/verify.rs:182`, and
  `run` passes `input.granted` unchanged to its one `verify_bundle` call
  (`a5b4e8a10:tools/src/run.rs:543`); no other `audit(` call is in `tools/src/`.
  The unused grants are worked out from the audit's own list, with no second
  import read. Still true at `8b291d65d`: `tools/src/verify.rs:262` and
  `tools/src/run.rs:1284`; task 031's type check (`tools/src/verify.rs:263-271`)
  reads the audit's returned list, and `wasm_capsule_audit::memories`
  (`tools/src/run.rs:658`, task 033) reads memory limits, not imports.

## Comparison with SECOND-REVIEW.md (PR #608)

`SECOND-REVIEW.md` was opened only after the two sections above were written.
Its base for these two PRs is `dc78bca5b` (its intro, `SECOND-REVIEW.md:14-26`);
this file's is `8b291d65d`, so its base-side line numbers are compared at
`dc78bca5b` (`git show dc78bca5b:<path>`), not at this base. Each of its cites
below was read with `git show`; none was copied into the sections above.

### PR #231 (task 024)

This re-run: PASS. `SECOND-REVIEW.md:37` (`## Verdicts`): PASS. Agree.

- Promise 1: same. Both copied LOG's 84 lines with the same `sed` and got the
  same script sha256 (`f2dd94a5...`, `SECOND-REVIEW.md:106-108`), reproduced
  the `content-sample` pin, and found both pins equal to the script and to
  `bundle_identity` (`SECOND-REVIEW.md:111-143`). The only change in method:
  it showed the script reacts to its input by changing the module bundle's
  last byte (`SECOND-REVIEW.md:148-151`); this re-run changed byte 1 of a
  `content-sample` copy, as task 024's LOG did. Both name `3df3dcb83` (task 032)
  for the second pin's new value.
- Promise 2: same.
- Promise 3: same. Its base cites `tests/bundle.rs:220` and `:516`
  (`SECOND-REVIEW.md:76-78`) are right at `dc78bca5b`; at `8b291d65d` they are
  `:220` and `:520` (lines moved by later merges, no change to the rule).
- Promise 4: same.
- Promise 5: same. Its `dc78bca5b` cites (`SECOND-REVIEW.md:92-94`) differ from
  this file's only by line moves to `8b291d65d`.
- Promise 6: same. It says no later merge can change a fact about the merge;
  this file adds that `Cargo.lock` was later changed by `614b85df8` (PR #700,
  cx-wasm-audit 029), which is after its base (`git merge-base --is-ancestor
  614b85df8 dc78bca5b` exits 1), so both statements are true.

### PR #235 (task 025)

This re-run: PASS. `SECOND-REVIEW.md:38` (`## Verdicts`): PASS. Agree.

- Promise 1: same. Both compare each file's `+`/`-` lines by `shasum`
  against `git diff 36fa6d89c a5b4e8a10^1` and find the four untouched files
  identical. Checked its facts: `git diff 5f3d23418 a5b4e8a10 --
  lab/wasm-capsule/` has 20 hunks (`grep -c '^@@'`), the `tests/run.rs` hunks
  start at `-26` and `-1417` and the `LOG.md` ones at `-222` and `-248`, the only
  lane commit in `36fa6d89c..a5b4e8a10^1` is `416062dfe`, and the four blob ids
  it gives (`SECOND-REVIEW.md:180-183`) are those of `git rev-parse
  5f3d23418:<path>` and `a5b4e8a10:<path>`. This file adds the reverse check
  (each of `5f3d23418`'s lane changes found in the merge's own diff).
- Promise 2: same.
- Promise 3: same. Its `dc78bca5b` lines (`SECOND-REVIEW.md:210`, `:2370` to
  `:2498`) are right there; its notes on tasks 031 and 039
  (`SECOND-REVIEW.md:211-215`) hold at `8b291d65d` (`tests/run.rs:2492`,
  `:2508`, `:2513-2524`).
- Promise 4: same. Both note that the merge's own run (`a5b4e8a10:LOG.md:380-383`)
  named F-WC-README-COUNT, not F-WC4-SEALED-NEW, and both ran the same 22 ids
  with the same result, "summary: 22 CAUGHT of 22" (`SECOND-REVIEW.md:305-317`
  at `dc78bca5b`, `:337-343` at `720cdde57`, `:367-373` at `73f5fc35f`; this
  file at `8b291d65d`). Its other facts were checked and hold: task 020's LOG
  lines (`5f3d23418:LOG.md:238-244`), task 027's 13-id run
  (`dc78bca5b:LOG.md:501-505`, which names F-WC4-SEALED-NEW), `a5b4e8a10` an
  ancestor of both `f92fe8597` and `c5f50b08a`, no runner run added to LOG by
  `3a4d2812a` (#238) or `6333a87dd` (#240), eight ids in `bf752df1a`'s (#245) run,
  none of them F-WC4-SEALED-NEW, `720cdde57` = PR #621's merge, `67309348b`'s
  parent `9c382b0c6`, and 184, 185 and 188 entries at `720cdde57`, `9c382b0c6`
  and `73f5fc35f`.
- Promise 5: same. Its `dc78bca5b` and `286b983b6` cites
  (`SECOND-REVIEW.md:274-281`) were read there and hold.
- Promise 6: same; as for #231, `614b85df8` changed `Cargo.lock` after its base.
- The one-path rule: same. Its `git grep -n "audit(" a5b4e8a10 --
  lab/wasm-capsule/tools/src` finds only `verify.rs:182`, as it says
  (`SECOND-REVIEW.md:289-291`), and `grants_not_imported` is at
  `a5b4e8a10:tools/src/verify.rs:191-200`.

No finding in either PR, and no claim in `SECOND-REVIEW.md`'s PR #231 and PR
#235 sections or in their two `## Verdicts` lines that a check here shows false.
So this file has no `FOLLOWUP:` line for task 058.
