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
Task 059's base, from `git rev-parse HEAD` before its first edit: `ca39ee60f4c5296eba39bc5015abf3093b7075c2` (written `ca39ee60f` in its sections).

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

## PR #238 (task 021), merge 3a4d2812a

Verdict: FOLLOWUP

How task 059 made its four sections. They were written from the merges
(`git show <merge>:<path>`, `git diff <merge>^1 <merge> -- lab/wasm-capsule/`)
and from runs at `ca39ee60f`, before `SECOND-REVIEW.md` was opened. `$T` is a
new scratch folder outside the repo (`mktemp -d /tmp/rerun059.XXXXXX`). The
probe `.wat` files were written there from README's own text. Engines:
`/opt/homebrew/bin/wasmtime --version` = `wasmtime 45.0.1 (83166ba31
2026-06-05)` and `/opt/homebrew/bin/wasmer --version` = `wasmer 7.5.0`. Each
engine ran as its own process from a shell; there was no engine inside an
engine and no VM. The canonical runner, the capsule build and the hand plant
under #241 each ran holding the shared build lease. `git status --short` was
empty after every run. A section's verdict says what is still open at
`ca39ee60f`; a promise broken at the merge and fixed later is named with the
merge that fixed it.

Lane diff: 2 files, +137 (`README.md` +119, `LOG.md` +18). The section is
`3a4d2812a:README.md:731-849`; the LOG entry is `3a4d2812a:LOG.md:386-403`.

- Promise 1, a README section "## Memory cap discovery (wc-010a)" and one LOG
  entry, naming both engine versions. Evidence at the merge:
  `3a4d2812a:README.md:731` (the heading) and `:736-738` (both `--version`
  lines); one LOG entry, `3a4d2812a:LOG.md:386-403`, with both versions at
  `:387`. Still true at `ca39ee60f`: the section is at `README.md:1019`, and
  LOG lines 386-403 are the same as at the merge (`diff` empty). Changed by
  `c5f50b08a` (PR #254, task 027): it added one note to the intro
  (`README.md:1023-1024`, "task 027: no longer so"). A `diff` of the section at
  the merge against `README.md:1019-1138` shows only that hunk.
- Promise 2, each engine's memory cap flag from `--help`, or none. Evidence at
  the merge: wasmtime `3a4d2812a:README.md:774-778` (the `-W help` lines for
  `max-memory-size=N` and `trap-on-grow-failure`); wasmer `:801-811` (the words
  searched, "`wasmer --help` matched none", and the list of what
  `wasmer run --help` matched). Re-run at `ca39ee60f`:
  - `wasmtime -W help | grep -n 'max-memory-size\|trap-on-grow-failure'`:
    exit 0, lines 13 and 18, word for word the two lines README quotes.
  - `wasmer run --help` and `wasmer --help`: both exit 0.
    `grep -i -E 'memory|grow|trap|limit|pages|max|heap|size|resource|rlimit|bytes'`
    finds nothing in `wasmer --help`, as README says. In `wasmer run --help`
    it finds the lines README lists (91-124, the four memory feature switches;
    200, the CPU back-off "maximum"; 220-223, `--with-compact-on-growth`;
    256-257, `--stack-size`). It also finds two lines README does not list:
    241, `--skip-journal-stdio` ("... to bootstrap a module", `trap` inside a
    word), and 266, under `--COREDUMP_PATH <COREDUMP_PATH>`, "Generate a
    coredump at this path if a WebAssembly trap occurs" (`grep -w trap` finds
    this one too). Neither is a memory cap, so "SKIPPED" holds. But README's
    "matched only lines about other things", followed by its list, leaves out
    a line the search word `trap` finds. FOLLOWUP below.
- Promise 3, probe runs: grow within the cap, past it with the flag, and past
  it without. Evidence at the merge: `3a4d2812a:README.md:786-794` (seven
  wasmtime rows) and `:814-818` (three wasmer rows), each with its full
  command. Re-run in `$T/wc010a/`, each command exactly as written:

  ```
  wasmtime run -W max-memory-size=67108864 --invoke grow grow.wat 1023   exit 0, stdout 1
  wasmtime run -W max-memory-size=67108864 --invoke grow grow.wat 1024   exit 0, stdout -1
  wasmtime run -W max-memory-size=67108864,trap-on-grow-failure=y --invoke grow grow.wat 1024
                                    exit 1, last stderr: 2: forcing trap when growing memory to 67174400 bytes
  wasmtime run -W max-memory-size=67108864,trap-on-grow-failure=y --invoke grow grow.wat 1023   exit 0, stdout 1
  wasmtime run --invoke grow grow.wat 1024                               exit 0, stdout 1
  wasmtime run -W max-memory-size=67108864 --invoke size big-min.wat
                                    exit 1, last stderr: 1: memory minimum size of 1025 pages exceeds memory limits
  wasmtime run --invoke size big-min.wat                                 exit 0, stdout 1025
  wasmer run --invoke grow grow.wat 1024                                 exit 0, stdout 1, stderr empty
  wasmer run --invoke grow grow.wat 65535                                exit 0, stdout 1, stderr empty
  wasmer run --invoke size big-min.wat                                   exit 0, stdout 1025, stderr empty
  ```

  All ten equal README's exit codes and stdouts. Still true at `ca39ee60f`.
- Promise 4, one answer line per engine. Evidence at the merge:
  `3a4d2812a:README.md:822-826` (wasmtime: "grow returns -1", "trap" with
  `trap-on-grow-failure=y`, "start refused" for a minimum above the cap) and
  `:827-829` (wasmer: "SKIPPED"). Every word is borne out by the runs above.
  Still true at `ca39ee60f` (`README.md:1111-1121`). Later merges built on it
  and did not change it: `4a6a61896` (PR #273, task 030) found that both
  engines apply a module's own maximum with no flag. That does not contradict
  021, whose `grow.wat` declares no maximum.
- Promise 5, the `/usr/bin/time -l` line, labelled as process resident memory.
  Evidence at the merge: `3a4d2812a:README.md:835-849` ("the engine process's
  resident memory, not the capsule's linear memory"). Re-run of the two
  commands at `:839` and `:842`: wasmtime printed `1` and
  `14745600  maximum resident set size` (`5587400  peak memory footprint`);
  wasmer printed `1` and `19333120  maximum resident set size`
  (`5489096  peak memory footprint`). These are a few pages off README's
  14696448 and 19218432, as two measurements may be. Both are still far below
  the 64 MB each run grew to, so the label and its reason hold. Still true at
  `ca39ee60f` (`README.md:1124-1138`).
- Promise 6, the `manifest.rs` lines for the declared 64 MB, cited at 021's
  base. Evidence at the merge: `3a4d2812a:README.md:742-751` cites lines
  102-103, 1167-1169 and 1188-1190 at `a5b4e8a10`.
  `git show a5b4e8a10:elastos/crates/elastos-common/src/manifest.rs` has
  `#[serde(default)]` / `pub resources: ResourceLimits,` at 102-103,
  `pub struct ResourceLimits {` / `#[serde(default = "default_memory")]` /
  `pub memory_mb: u32,` at 1167-1169, and `fn default_memory() -> u32 {` /
  `64` / `}` at 1188-1190. The same lines hold at `3a4d2812a^1` and at
  `ca39ee60f`. `capsule/capsule.json` has no `resources` key at the merge or at
  the base (`grep -c resources` prints 0 / `grep -n` exits 1).
- Promise 7, only README and LOG changed. Evidence: the lane diff's file list
  above. True for the merge.

FOLLOWUP: README.md:1093-1098 says `wasmer run --help` "matched only lines about other things" and lists them, but leaves out the `--COREDUMP_PATH` line "Generate a coredump at this path if a WebAssembly trap occurs" (and `--skip-journal-stdio`'s "bootstrap"), which its own search word `trap` matches; hand check: `/opt/homebrew/bin/wasmer run --help | grep -n -i trap` prints lines 241 and 266, and neither flag is in README's list.

## PR #240 (task 022), merge 6333a87dd

Verdict: FOLLOWUP

Lane diff: 2 files, +161 (`README.md` +143, `LOG.md` +18). The section is
`6333a87dd:README.md:850-992`; the LOG entry is `6333a87dd:LOG.md:404-421`.
Probe modules `main.wat`, `host.wat`, `host-wasi.wat` and `host-unknown.wat`
were written in `$T/wc009b0/` from README's text; `<D>` below is that folder.

- Promise 1, a README section "## Granted import hosting discovery
  (wc-009b0)" and one LOG entry. Evidence at the merge:
  `6333a87dd:README.md:850` and `6333a87dd:LOG.md:404-421`. Still true at
  `ca39ee60f`: the section is at `README.md:1402`, and LOG lines 404-421 are
  the same (`diff` empty). Changed by `bf752df1a` (PR #245, task 026), and by
  no other merge: a `diff` of the section at the merge against
  `README.md:1402-1549` shows only 026's hunks (the discovery ruling, complete
  commands in both tables, and the narrowed conclusion; see #245).
- Promise 2, for each engine, a way to supply `env.f` from a zero-import host
  module, or none. Evidence at the merge: wasmtime
  `6333a87dd:README.md:899-903` (`--preload <NAME=MODULE_PATH>`, "Load the
  given WebAssembly module before the main module"); wasmer `:942-967`.
  Re-run at `ca39ee60f`:
  - `wasmtime run --help`: exit 0; lines 91-92 are the two lines README quotes.
  - `wasmer --help` (exit 0): no line has `preload`, `import`, `link`,
    `module` or `host`, as README says. `wasmer run --help` (exit 0): no
    `preload`; `import` matches only lines 249 and 269, the two README quotes;
    `--enable-module-linking` (117-118) and `--use <USE>` (158-159) read as
    README quotes them. README sums up the other `module`, `host`, `use` and
    `env` lines as "compile threads, folders and the CWD, network, journals,
    the cache, the webc entrypoint, and `--env`". The same search also finds
    `--env-file <PATH>` (150-151, "Load environment variables from a dotenv
    file") and `--forward-host-env` (153-154, "Forward all host env variables
    to guest"). Neither supplies an import, so "SKIPPED" holds. But the summary
    names `--env` as the one ambient flag and leaves out the flag that
    forwards the whole host environment. FOLLOWUP below.
- Promise 3, one answer line per engine. Evidence at the merge:
  `6333a87dd:README.md:980-983` (wasmtime "hosts by flag
  `--preload env=<path>`") and `:984-987` (wasmer "SKIPPED"). Re-run of every
  table row, with the complete commands at `README.md:1470-1474` and
  `:1526-1528` (`env -i`, absolute paths, `< /dev/null`):

  ```
  wasmtime run --preload env=<D>/host.wat --invoke digest <D>/main.wat 1592590337          exit 0, stdout 1592590338
  wasmtime run --invoke digest <D>/main.wat 1592590337
        exit 1, first: Error: failed to run main module `<D>/main.wat`; last: 1: unknown import: `env::f` has not been defined
  wasmtime run --preload other=<D>/host.wat --invoke digest <D>/main.wat 1592590337        exit 1, stderr = the row above (diff empty)
  wasmtime run --preload env=<D>/host-wasi.wat --invoke digest <D>/main.wat 1592590337     exit 0, stdout 1592590338
  wasmtime run --preload env=<D>/host-unknown.wat --invoke digest <D>/main.wat 1592590337
        exit 1, first: Error: failed to process preload `env` at `<D>/host-unknown.wat`; last: unknown import: `nope::g` has not been defined
  wasmer run --invoke digest <D>/main.wat 1592590337
        exit 1: error: Unable to instantiate the WebAssembly module
                ╰─▶ 1: Error while importing "env"."f": unknown import. Expected Function(FunctionType { params: [I32], results: [I32] })
  wasmer run --use <D>/host.wat --offline --invoke digest <D>/main.wat 1592590337           exit 1, stderr = the row above (diff empty)
  wasmer run --enable-module-linking --invoke digest <D>/main.wat 1592590337
        exit 1: error: No backends support the required features for the Wasm module. Feel free to open an issue at https://github.com/wasmerio/wasmer/issues
  ```

  All eight equal README's exit codes, stdouts and stderr lines, so both
  answers hold at `ca39ee60f` (`README.md:1537-1544`). At the merge, though,
  the tables (`6333a87dd:README.md:913-917`, `:969-971`) gave only the flag,
  and the intro (`:864-866`) gave the runner's shape "plus only the flag under
  test" without saying where the flag goes. Placed after the module path,
  `env -i wasmtime run --invoke digest <D>/main.wat 1592590337 --preload env=<D>/host.wat < /dev/null`
  exits 1 with (ii)'s refusal, because wasmtime reads it as a guest argument.
  So at the merge the probes were not given well enough to re-run. Changed by
  `bf752df1a` (PR #245, task 026), which gives each complete command; those
  are the ones run above. Nothing is left open at the base for this.
- Promise 4, for a found flag, whether it changes what a zero-import module
  sees, by a real run with and without it. Evidence at the merge:
  `6333a87dd:README.md:932-938` (the `tools/build` capsule, sha256
  `6dd9af1a...`, printed `230101071268130872` both ways). Re-run at
  `ca39ee60f`: `lab/wasm-capsule/tools/build $T/build` exited 0, and its
  180-byte `capsule.wasm` has sha256
  `2002429e73ee1a5e983df008f5b53728882646f109d55a9d1a93e831690631e1`
  (= `PINNED_ARTIFACT_SHA256`, `tests/common/mod.rs:30-31`).
  `env -i /opt/homebrew/bin/wasmtime run --invoke digest $T/build/capsule.wasm 1592590337 < /dev/null`
  and the same with `--preload env=$T/wc009b0/host.wat` each exited 0 with
  stdout `230101071268130872` and two warning lines on stderr. So the result
  also holds for today's capsule. Changed by `3df3dcb83` (PR #306, task 032):
  the capsule gained its memory maximum, so `README.md:1490-1492`'s "the pinned
  value" for `6dd9af1a...` holds only at the section's own stated base,
  `3a4d2812a`. Changed by `bf752df1a`: the conclusion is narrowed to this one
  comparison (`README.md:1495`).
- Promise 5, only README and LOG changed. Evidence: the lane diff's file list
  above. True for the merge.

FOLLOWUP: README.md:1507-1510 sums up `wasmer run --help`'s `module`, `host`, `use` and `env` matches and names `--env` as the ambient one, but leaves out `--forward-host-env` ("Forward all host env variables to guest") and `--env-file`, which its own search words `host` and `env` match; hand check: `/opt/homebrew/bin/wasmer run --help | grep -n -i -e '--forward-host-env' -e '--env-file'` prints lines 150 and 153, and neither flag is in README's summary.

## PR #241 (task 023), merge 33cbed8c5

Verdict: PASS

Lane diff: 4 files, +80 -1 (`LOG.md` +21, `README.md` +11,
`falsifiers.json` one line changed, `tests/docs.rs` +47).

- Promise 1, the `falsifiers.json` `"about"` states no evidence status.
  Evidence at the merge: the only `falsifiers.json` hunk is `@@ -1,5 +1,5 @@`,
  line 2 (`33cbed8c5:falsifiers.json:2`). It drops "The canonical runner
  falsify.py now has ... until R1 lands." and "(R1 is done: the canonical
  runner's lab command runs these)", and adds "Each entry's evidence label, and
  the count of each kind of evidence, are kept in one place, README.md \"##
  Falsifiers\"; this text says only what each falsifier plants." No entry
  changed. Still true at `ca39ee60f`: line 2 was changed by later merges
  (`git log -L2,2:lab/wasm-capsule/falsifiers.json --no-patch ca39ee60f`
  lists 27 commits in all). A `python3 -I` whole-word,
  case-ignored check of `pending`, `hand-proven`, `runner-caught`, `R1` and
  `R2` on it finds none, and it still names `README.md` and `## Falsifiers`.
- Promise 2, the new test `falsifiers_about_states_no_evidence_status`, with a
  falsifier proven by hand. Evidence at the merge:
  `33cbed8c5:tests/docs.rs:56` (the test; its words at `:19`, its three
  `assert!` at `:66`, `:71` and `:75`). LOG shows the hand-proven failing
  assertions: `33cbed8c5:LOG.md:430-442` gives eight plants, each followed by
  `cargo test --locked --test docs falsifiers_about_states_no_evidence_status`
  FAILED with its panic quoted (`tests/docs.rs:66:5 ... found ["pending",
  "hand-proven", "R1"]`, `:71:5` for `README.md` lost, `:75:5` for `## Falsifiers`
  lost), then reverted with the sha256 checked. Those three lines are the
  test's three `assert!` lines at the merge. Still true at `ca39ee60f`: the
  test is at `tests/docs.rs:345`, its words at `:46`, and it passes in
  `cargo test --locked`. Run at `ca39ee60f` (lease held, after a 300 s wait):
  "this text says only what each falsifier plants." (found once) gained
  " These are hand-proven, pending R1.". The named test then exited 101 at
  `tests/docs.rs:355:5`: `falsifiers.json "about" states evidence status, which
  README.md "## Falsifiers" alone holds: found ["pending", "hand-proven",
  "R1"]`. After the restore, `falsifiers.json`'s sha256 was again
  `7887fb2d74ffe4acf12353d344e42b36331ac1690c1511794490e2cd53e65a21`. These
  plants still have no runner entry: `falsifiers.json` is the runner's own
  input, not a recovery target (`README.md:2836-2842`).
- Promise 3, one README sentence saying "## Falsifiers" is the one place for
  evidence labels and counts. Evidence at the merge:
  `33cbed8c5:README.md:1292-1294`. Still true at `ca39ee60f`
  (`README.md:2488-2490`), still the first paragraph of "## Falsifiers".

## PR #245 (task 026), merge bf752df1a

Verdict: PASS

Lane diff: 6 files, +443 -34 (`ADOPTION.md`, `LOG.md`, `README.md`,
`falsifiers.json` +128, `tests/docs.rs` +181, `tools/src/run.rs`). The first
parent `f26d5d036` already holds `2221f8fbe` (PR #242, provider 026), which
merged after 026's own base `33cbed8c5`.

- Promise 1, README holds Rong's engine sentence once, and ADOPTION once.
  Evidence at the merge: `bf752df1a:README.md:62-63`, inside "## Layout"
  (`:26`), the first section that names both engines; `bf752df1a:ADOPTION.md:75`.
  `grep -F -c` of the exact sentence prints 1 for each file. `tools/src/run.rs`
  changed only in two doc comments (`bf752df1a:tools/src/run.rs:69-73` and
  `:99`), each now "test-only, not endorsed". Still true at `ca39ee60f`:
  `README.md:64-65` and `ADOPTION.md:94`, 1 each. (`ADOPTION.md:86`, from
  `dc80a2935`, task 038, says "Both engines stay test-only and not endorsed;
  the choice is Anders's." That is a second wording, not the exact sentence,
  and it says "not endorsed", so the test's line check passes.)
- Promise 2, 022's section holds the discovery ruling once, before the
  per-engine answers. Evidence at the merge: `bf752df1a:README.md:871-872`,
  inside the section at `:853`, before the first answer line `:905`
  (`### wasmtime 45.0.1: FOUND, ...`); `bf752df1a:ADOPTION.md:283`, on one
  line. `grep -F -c` prints 1 for each file. Still true at `ca39ee60f`:
  `README.md:1420-1421` (section `:1402`, first answer line `:1454`) and
  `ADOPTION.md:304`, 1 each.
- Promise 3, the tests `engines_are_labelled_test_only_not_endorsed` and
  `hosting_discovery_is_not_the_import_path`. Evidence at the merge:
  `bf752df1a:tests/docs.rs:149` and `:196`. Still true at `ca39ee60f`:
  `tests/docs.rs:257` and `:304`, both passing in `cargo test --locked`.
- Promise 4, falsifiers in `falsifiers.json`, each anchored in `README.md` and
  found there exactly once, including F-WC-ENGINE-ENDORSED and
  F-WC9B0-IMPORT-PATH. Evidence at the merge: seven entries,
  `bf752df1a:falsifiers.json:2270-2391`, every edit's `file` is
  `../../lab/wasm-capsule/README.md`. F-WC-README-COUNT was re-anchored to
  146 (`:1990-1991`). The merge's own run, `bf752df1a:LOG.md:463`:
  "summary: 8 CAUGHT of 8". The runner refuses an `old` text not found exactly
  once (`examples/agent-host/falsify.py:14`, `:514`). All seven are still in
  the list at `ca39ee60f` (189 entries). Run there, with the two `run.rs`
  entries task 052 added for 026's plants (promise 6):

  ```
  python3 -I examples/agent-host/falsify.py --from lab/wasm-capsule/falsifiers.json \
    F-WC-ENGINE-ENDORSED F-WC-ENGINE-MOVED F-WC-ENGINE-TWICE F-WC-ENDORSE-LINE \
    F-WC9B0-IMPORT-PATH F-WC9B0-AFTER-ANSWERS F-WC9B0-TWICE F-WC-README-COUNT \
    F-WC-ENGINE-RUN-MODULE-DOC F-WC-ENGINE-RUN-ENUM-DOC
  baseline: 3 named tests pass without an edit, 0 do not
  summary: 10 CAUGHT of 10
  ```

  Exit 0, every line `CAUGHT`, no `*.falsify-original` left.
- Promise 5, two of 022's PASS follow-ups folded into 022's section. Evidence
  at the merge: complete commands in both tables
  (`bf752df1a:README.md:919-925`, `:975-979`), and the conclusion narrowed to
  "this capsule's output for `1592590337` was unchanged; this one comparison
  says nothing about any other effect of a preloaded module" (`:946`). Still
  true at `ca39ee60f` (`README.md:1468-1474`, `:1524-1528`, `:1495`). The
  commands were run exactly as written (#240, promise 3) and matched.
- Promise 6, the five planted bugs outside `README.md`, labelled
  hand-proven, pending R1, because "`ADOPTION.md` and `tools/src/run.rs` are
  not recovery targets" (`bf752df1a:README.md:1676-1690`;
  `bf752df1a:LOG.md:471-478`). At the merge this reason was false for
  `run.rs`: `bf752df1a:examples/agent-host/falsify.py:336` lists
  `lab/wasm-capsule/tools/src/run.rs` (from `2221f8fbe`). It was true at 026's
  own base (`33cbed8c5:examples/agent-host/falsify.py:307-322` has no
  `run.rs`). Changed by `c305ca5a2` (PR #668, task 052): both `run.rs` plants
  are runner entries, and `README.md:2867-2868` and `:3320-3333` say why. Also
  changed by `af3b1a44b` (PR #696, task 055): F-WC-ENGINE-RUN-MODULE-DOC's
  `new` is byte for byte `bf752df1a^1:tools/src/run.rs:70-73`, and
  F-WC-ENGINE-RUN-ENUM-DOC's `new` is `:99`. Both are caught in the run
  above. `ADOPTION.md` is still not a target at `ca39ee60f`: it is in no
  `PROVIDER_TARGETS` line (`falsify.py:343-363`), and its one mention
  (`falsify.py:2235`) is in a self-test's list of foreign files. So the three
  ADOPTION plants stay hand-proven (`README.md:2868-2880`). Nothing is left
  open at the base.

## Comparison with SECOND-REVIEW.md (PR #621)

`SECOND-REVIEW.md` was opened only after the four sections above were
written. Its base for these four PRs is `43b4af944` (`SECOND-REVIEW.md:28-30`);
this file's is `ca39ee60f`, so its base-side cites were read at `43b4af944`
with `git show`, not at this base. Every cite of it named below was read that
way and holds unless this says otherwise; none was copied into the sections
above.

### PR #238 (task 021)

This re-run: FOLLOWUP. `SECOND-REVIEW.md:39` (`## Verdicts`): PASS. Differs.

- Promise 1: same. Its `43b4af944` cites (`README.md:1007`; the task 027 note
  at `:1011-1012`) hold there.
- Promise 2: differs: what and why. Both runs found the same two
  `wasmer run --help` lines that README does not list
  (`SECOND-REVIEW.md:399-401`), and both found that neither is a memory cap.
  It counted that as no finding. This re-run counts README's "matched only
  lines about other things", followed by a list without the `trap` line, as a
  wrong statement of what the search found, so a FOLLOWUP (the #238 section).
  Its text is true; the verdicts differ by that judgement only.
- Promise 3: same. It ran seven of the ten rows (`SECOND-REVIEW.md:454-469`;
  not (i-t), wasmtime's "start, no flag" or wasmer's 65535 row); this re-run
  ran all ten. The results are the same.
- Promise 4: same. Both name `c5f50b08a` (task 027) and `4a6a61896` (task
  030) as building on 021 without contradicting it; its `README.md:1310-1329`
  at `43b4af944` is 030's answer section.
- Promise 5: same. wasmtime's resident size was 14745600 in both runs; wasmer's
  was 19316736 there and 19333120 here.
- Promise 6: same.
- Promise 7: same.

### PR #240 (task 022)

This re-run: FOLLOWUP. `SECOND-REVIEW.md:40` (`## Verdicts`): PASS. Differs.

- Promise 1: same.
- Promise 2: differs: what and why. It checked `preload` and `import` in
  `wasmer run --help` and five words in `wasmer --help`
  (`SECOND-REVIEW.md:497-502`), but not README's summary of the `module`,
  `host`, `use` and `env` lines. This re-run found that summary leaves out
  `--forward-host-env` and `--env-file`, so a FOLLOWUP (the #240 section).
- Promise 3 (its promise 3 and its "probe commands" bullet): the answers are
  the same, and both ran the eight complete commands at their bases with the
  same results. Differs on the commands at the merge.
  `SECOND-REVIEW.md:524-528` says the flag-only tables, with the runner's shape
  at `6333a87dd:README.md:864-866`, "was enough to re-run them (flag after
  `run`)". The merge's text never says "after `run`". It says the runner's
  shape "plus only the flag under test", and with the flag appended after the
  module path, row (i) exits 1 with row (ii)'s refusal (#240, promise 3). Task
  026's own LOG says the same (`bf752df1a:LOG.md:452-453`, "022 recorded flags
  only, not their place in argv"). FOLLOWUP below.
- Promise 4: same. Both ran today's `2002429e...` capsule with and without
  `--preload` and got `230101071268130872` both ways. Its pin cites for the
  merge (`6333a87dd:tests/bundle.rs:32`, `6333a87dd:tests/verify.rs:52`) hold.
- Promise 5: same.

### PR #241 (task 023)

This re-run: PASS. `SECOND-REVIEW.md:41` (`## Verdicts`): PASS. Agree.

- Promise 1: same. It searched the `"about"` text at `43b4af944` for
  `caught`, `proven`, `by hand`, `pending`, `R1`, `R2` and `evidence`; this
  re-run searched for the test's five whole words at `ca39ee60f`. Both found no
  status.
- Promise 2 (its promises 2 and 3): same. Both read LOG's eight hand proofs at
  the merge (it cites the whole entry, `LOG.md:422-442`; this file
  `:430-442`), and both re-proved one at their base. It planted
  " These are pending." (failed at `tests/docs.rs:334:5` at `43b4af944`,
  `found ["pending"]`); this re-run planted " These are hand-proven, pending
  R1." (failed at `:355:5`, three words found). Its `PROVIDER_TARGETS` cites
  (`33cbed8c5:examples/agent-host/falsify.py:291-325`, `43b4af944:...:323-383`)
  hold.
- Promise 3 (its promise 4): same. Its `README.md:2456-2458` and `:2800-2806`
  at `43b4af944` hold.

### PR #245 (task 026)

This re-run: PASS. `SECOND-REVIEW.md:42` (`## Verdicts`): FOLLOWUP. Differs, by
base only.

- Promises 1 to 3: same. Its `43b4af944` cites (`README.md:63`,
  `ADOPTION.md:92`, `tools/src/run.rs:169` and `:300`, `tests/docs.rs:236`,
  `:283`, `:39` and `:44`, `README.md:1409`, `ADOPTION.md:302`) hold there;
  later merges moved the lines.
- Promise 4: same. It ran the seven ids ("summary: 7 CAUGHT of 7",
  `SECOND-REVIEW.md:691-696`) and left out F-WC-README-COUNT on purpose. This
  re-run ran the seven, F-WC-README-COUNT and the two `run.rs` entries
  ("summary: 10 CAUGHT of 10").
- Promise 5: same.
- Promise 6: same fact. Both found that the reason "`tools/src/run.rs` is not
  a recovery target" was false at the merge (`SECOND-REVIEW.md:702-713`). Its
  FOLLOWUP (`SECOND-REVIEW.md:43` and `:715`) is fixed by 052, and this base
  bears that out. `c305ca5a2` (PR #668, task 052) added both entries, so its
  own hand check `grep -c F-WC-ENGINE-RUN lab/wasm-capsule/falsifiers.json`
  now prints `2` (it printed `0` at `43b4af944`). README's sentence is
  replaced by `README.md:2867-2868` ("runner-caught since task 052"), and the
  run above catches both. `af3b1a44b` (task 055) made the module-doc plant
  equal the base's wording. The line its FOLLOWUP names, `README.md:2832`, now
  holds another sentence (task 020's `&[]` plant) because the text moved. So
  the FOLLOWUP it records is closed, and this file has none for #245.

FOLLOWUP: SECOND-REVIEW.md:527-528 says the flag-only probe tables of `6333a87dd`, with the runner's shape at `6333a87dd:README.md:864-866`, "was enough to re-run them (flag after `run`)", but that text never says where the flag goes ("plus only the flag under test"); hand check: with README's `main.wat` and `host.wat` in a scratch `<D>`, `env -i /opt/homebrew/bin/wasmtime run --invoke digest <D>/main.wat 1592590337 --preload env=<D>/host.wat < /dev/null` (the flag appended) exits 1 with "unknown import: `env::f` has not been defined", not row (i)'s `1592590338`.

Task 059's three `FOLLOWUP:` lines are the one in the #238 section, the one in
the #240 section and the one above. No claim in `SECOND-REVIEW.md`'s #238,
#241 or #245 sections, or in their `## Verdicts` lines, was shown false by a
check here.
