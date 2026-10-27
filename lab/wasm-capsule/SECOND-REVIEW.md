# Second review of six one-reviewer merges

Why: Rong (27 Oct, per Sasha's 25 Oct direction) asked the claude and cursor
pair to re-read six of this lane's merges that had Codex as their only
reviewer, and to record PASS or a follow-up task for each.

The six PRs and which task covers them:

- Task 047 (the two sections below): lab PR #231 (task 024) and lab PR #235
  (task 025), the two code merges.
- Task 048: lab PRs #238 (task 021), #240 (task 022), #241 (task 023) and
  #245 (task 026).

Base commit of this review: `dc78bca5b5817a33861073fd8614279b5c051eb3`
(`dc78bca5b`). Each merge is judged as merged (`git show <merge>:<path>`).
Then each promise says "still true at dc78bca5b", or which later merge changed
it. This file fixes nothing; each `FOLLOWUP:` line would become a later task.
Task 007's old name rule is written here as "the retired label".

## PR #231 (task 024), merge f1f627250

Verdict: PASS

Lane diff: `git diff f1f627250^1 f1f627250 -- lab/wasm-capsule/` (7 files,
+220 -52). The promises, as task 047 quotes them from task 024:

- Promise 1: one `python3 -I` script, written from cc-capsule-identity's README
  rules, recomputed each pin outside the lab code. It first reproduced that
  lane's content-sample pin, and a pin was set only when it equalled
  `bundle_identity`. At the merge: the script is at `LOG.md:230-315` (fenced,
  84 lines), its checks at `LOG.md:316-332`, the pins at
  `tests/common/mod.rs:18-19` and `tests/bundle.rs:40`. Checked by a run, not
  by reading (commands below). LOG's text runs as it is. Its output equals both
  pins at the base. Still true at dc78bca5b for `MODULE_BUNDLE_LAB_CID`
  (`tests/common/mod.rs:20-21`, same value). `REFERENCE_LAB_CID` was changed
  by task 032 (PR #306, merge `3df3dcb83`, commit `95141b3e6`) when
  `capsule.wasm` gained its memory maximum. It is now at `tests/bundle.rs:37`,
  and the same script gives the new value too.
- Promise 2: the script named both lane bundles. At the merge,
  `LOG.md:321-325` names bundle (i), `capsule/capsule.json` beside the 8 bytes
  `00 61 73 6d 01 00 00 00` as `capsule.wasm`. `LOG.md:325-329` names bundle
  (ii), the bundle `tools/bundle` built, whose `capsule.wasm` sha256 equals
  `PINNED_ARTIFACT_SHA256`. Still true at dc78bca5b: this review ran the script
  on both bundles (below).
- Promise 3: one pin per value. At the merge, `MODULE_BUNDLE_LAB_CID` is one
  `pub const` at `tests/common/mod.rs:18`. It is imported by
  `tests/lab_cid.rs:13` and `tests/bundle.rs:14`, and asserted at
  `tests/lab_cid.rs:74` and `tests/bundle.rs:223`. The diff removes the old
  copies from both test files. `REFERENCE_LAB_CID` is one const at
  `tests/bundle.rs:40`, asserted at `:519`. Still true at dc78bca5b:
  `tests/common/mod.rs:20` is used at `tests/lab_cid.rs:74` and
  `tests/bundle.rs:220`, and `REFERENCE_LAB_CID` is at `tests/bundle.rs:37`,
  used at `:516`. A search for `bafybei` in `tests/` and `tools/src/` at the
  base finds only those two consts.
- Promise 4: `tests/run.rs` parses the printed name and has no hand prefix
  check. At the merge, `tests/run.rs:24` imports `LabCid`. `tests/run.rs:1403-1410`
  parses the name with `str::parse::<LabCid>` and asserts that it prints back
  the same string. `git grep -n 'starts_with("baf\|starts_with("lab-cid'` on
  `tests/` and `tools/src/` finds nothing at the merge or at the base. Still
  true at dc78bca5b: `tests/run.rs:32` and `:1896-1903`.
- Promise 5: README and ADOPTION describe the lab CID as cc-capsule-identity's
  59-character CIDv1 `bafybei...` UnixFS root. At the merge:
  `README.md:134-137` ("printed as 59 characters that start `bafybei`"),
  `README.md:175-192` (the module-bundle pin and how it was recomputed),
  `README.md:316-322` (the reference pin), and `ADOPTION.md:115-117` and
  `:170-182` ("the 59-character CIDv1 SHA-256 UnixFS directory root"). Still
  true at dc78bca5b: `README.md:150-151`, `:191-208`, `ADOPTION.md:138-139` and
  `:192-207`. Task 032 (PR #306) updated the reference value in README
  (`:328-341`) and ADOPTION (`:204-207`), and both name the old value.
- Promise 6: no new `falsifiers.json` entry and no new dependency. At the
  merge, `git diff --stat f1f627250^1 f1f627250 -- lab/wasm-capsule/` lists 7
  files. None is `falsifiers.json`, `Cargo.toml`, `tools/Cargo.toml` or
  `Cargo.lock`. This is a fact about the merge, so no later merge can change
  it.

The run for promise 1. It used a scratch folder outside the repo,
`S=/tmp/r047.mXsCRd`. Nothing under `lab/` changed, and the script is not
committed. From the repo root:

```
$ sed -n '231,314p' lab/wasm-capsule/LOG.md | sed 's/^  //' > $S/outside_cid.py
$ shasum -a 256 $S/outside_cid.py
f2dd94a5f15cbd0c309ce30fe8f56a0d9128f36b5d1cb32a7180b65ff3a77bc5  /tmp/r047.mXsCRd/outside_cid.py
$ python3 --version
Python 3.9.6
$ python3 -I $S/outside_cid.py lab/capsule-identity/fixtures/content-sample
bafybeieahlroxjdalpmglh227eikmodrjhrlelvzlhylvyt3s65ackiybi
```

That is cc-capsule-identity's committed pin
(`lab/capsule-identity/tests/common/mod.rs:39`,
`lab/capsule-identity/README.md:289`). Bundle (i) is built the way
`this_capsule_bundle` (`tests/lab_cid.rs:24-30`) builds it.
`CAPSULE_MANIFEST` is `include_bytes!("../../capsule/capsule.json")`
(`tools/src/lib.rs:42`). From `lab/wasm-capsule/`:

```
$ mkdir -p $S/module-bundle && cp capsule/capsule.json $S/module-bundle/capsule.json
$ printf '\000asm\001\000\000\000' > $S/module-bundle/capsule.wasm   # xxd: 0061 736d 0100 0000
$ python3 -I $S/outside_cid.py $S/module-bundle
bafybeihtyzfql54i7irft23lg2mk44toqdww53ryuhs2psrknfjw4qhpcy
$ tools/bundle --name $S/module-bundle
bafybeihtyzfql54i7irft23lg2mk44toqdww53ryuhs2psrknfjw4qhpcy
```

This equals `MODULE_BUNDLE_LAB_CID` at dc78bca5b. Bundle (ii) is built the way
`tools_bundle_builds_a_new_bundle_and_prints_its_lab_cid` builds it:

```
$ tools/bundle $S/reference-out
built /tmp/r047.mXsCRd/reference-out/capsule.wasm 2002429e73ee1a5e983df008f5b53728882646f109d55a9d1a93e831690631e1
bafybeiebyzg55l4s6kb6daroty4prlkximwp6uvo32ovacfzdx7cahywqm
$ shasum -a 256 $S/reference-out/bundle/capsule.wasm   # 180 bytes; capsule.json cmp-equal to capsule/capsule.json
2002429e73ee1a5e983df008f5b53728882646f109d55a9d1a93e831690631e1  /tmp/r047.mXsCRd/reference-out/bundle/capsule.wasm
$ python3 -I $S/outside_cid.py $S/reference-out/bundle
bafybeiebyzg55l4s6kb6daroty4prlkximwp6uvo32ovacfzdx7cahywqm
$ tools/bundle --name $S/reference-out/bundle
bafybeiebyzg55l4s6kb6daroty4prlkximwp6uvo32ovacfzdx7cahywqm
```

The name equals `REFERENCE_LAB_CID` (`tests/bundle.rs:37`), and the module's
sha256 equals `PINNED_ARTIFACT_SHA256` (`tests/common/mod.rs:30-31`), at
dc78bca5b. The script does react to its input: with the module bundle's last
byte changed from `00` to `01` (`cmp -l`: `8 0 1`), it prints
`bafybeihqgrrppvccqgikj6tpjx6ntrhxqccrizqmi52cfjuslfdzu7szoq`, a different
value. Every command above exited 0.

No finding. Every promise held at the merge, and both pins still equal an
outside recomputation at the base.

## PR #235 (task 025), merge a5b4e8a10

Verdict: PASS

Lane diff: `git diff a5b4e8a10^1 a5b4e8a10 -- lab/wasm-capsule/` (10 files,
+1366 -91). It carries task 020's reviewed commit `5f3d23418` (base
`36fa6d89c`). The promises, as task 047 quotes them from task 025:

- Promise 1: every lane change of `5f3d23418` is on the branch, merged with the
  base's changes. Checked with `git diff 5f3d23418 a5b4e8a10 --
  lab/wasm-capsule/`: 8 files, 20 hunks. The only lane change on the base side
  is task 024 (`git log --oneline 36fa6d89c..a5b4e8a10^1 -- lab/wasm-capsule/`
  lists only `416062dfe`, merged as #231). Each hunk is accounted for:
  - Base change (task 024), 18 hunks: `ADOPTION.md` (3: `-117`, `-171`,
    `-202`), `LOG.md` (1: `-222`, 024's entry), `README.md` (6: `-131`, `-153`,
    `-168`, `-302`, `-571`, `-583`), `tests/bundle.rs` (2: `-11`, `-26`),
    `tests/common/mod.rs` (1: `-8`), `tests/lab_cid.rs` (3: `-10`, `-19`,
    `-75`) and `tests/run.rs` (2: `-26`, `-1417`). For six of these files, the
    added and removed lines of `git diff 5f3d23418 a5b4e8a10` are the same as
    those of `git diff 36fa6d89c a5b4e8a10^1` (same `shasum` of the `^[-+]`
    lines). For `LOG.md` they are the same except for 025's own entry. So each
    file differs from `5f3d23418` by exactly 024's change, and 020's lines in
    those files are kept.
  - Carried change: no hunk, because each of 020's changes is on both sides.
    The four 020 files missing from the diff have the same blob at `5f3d23418`
    and at `a5b4e8a10`: `tools/src/run.rs` `4a381399d05c`,
    `tests/common/grants.rs` `fda8e015a2a7`, `tests/verify.rs` `e282d941c4da`
    and `falsifiers.json` `28d90266d77a`. `git diff --name-only 36fa6d89c
    5f3d23418 -- lab/wasm-capsule/` lists 10 files, and each one is accounted
    for here, above, or below (`tools/src/verify.rs`).
  - 025's own additions, 2 hunks: `tools/src/verify.rs` `-23` (promise 2) and
    `LOG.md` `-248`. The second is 025's LOG entry, at the merge
    `LOG.md:372-385`. It comes after 020's entry at `LOG.md:346-371` and 024's
    at `LOG.md:225-345`.

  No lane change of `5f3d23418` is missing. Still true at dc78bca5b. Later
  merges changed these files on purpose (below), and none of them removed
  020's rule.
- Promise 2: `tools/src/verify.rs`'s module doc says the verifier "reads no
  bundle file by path". At the merge, `tools/src/verify.rs:26-29` says: "It
  reads no bundle file by path: ... The one file it reads by a path is the lab
  grants file (see wc-009a below)." Still true at dc78bca5b:
  `tools/src/verify.rs:33-36`.
- Promise 3: the five named tests. At the merge, in `tests/run.rs`:
  - `zero_grants_zero_imports_runs` at `:1863`.
  - `declared_not_granted_import_refuses_instantiation_by_name` at `:1936`. It
    asserts `undeclared import env.f`, no run folder and zero engine starts.
  - `valid_signature_with_empty_grants_file_links_nothing` at `:1960`.
  - `grant_for_an_import_the_module_does_not_have_links_nothing_and_is_reported`
    at `:1974`, Rong's rename. It asserts `linked() == []` and
    `unused_grants() == [env.f]`.
  - `granted_import_is_linked` at `:1990`. It asserts `linked() == [env.f]` and
    that each engine got the verified importing module.

  Still true at dc78bca5b, at `tests/run.rs:2370`, `:2444`, `:2468`, `:2482`
  and `:2498`. Two later merges changed them. Task 031 (PR #279, merge
  `b8c1dcedb`) gave each written grant a right (`("env", "f", "call")`). Since
  task 039 (PR #381, merge `ad885d9d2`), `granted_import_is_linked` reads each
  engine's module from its record, because the run folder is now removed.
  Otherwise the assertions are the same.
- Promise 4: the canonical runner catches each of the 17 `F-WC9-*` entries and
  the four re-anchored entries. At the merge, `falsifiers.json` holds 139
  entries. 17 of them are `F-WC9-*`, and every one of their edits is in
  `tools/src/verify.rs`. `LOG.md:381-383` records "summary: 21 CAUGHT of 21".
  Re-run at dc78bca5b (below): "summary: 22 CAUGHT of 22", exit 0. That covers
  all 18 `F-WC9-*` ids now in the list and the four re-anchored entries
  (F-WC5a, F-WC5-VERIFY-TWICE, F-WC5-QUERY-BEFORE-VERIFY, F-WC4-SEALED-NEW).
  Still true at dc78bca5b.
- Promise 5: README keeps the link rule in Rong's words, the grants file
  format, the exact label and the hand-proven labels. At the merge,
  `README.md:662-668` quotes Rong: "link an import only if it is in the signed
  module AND in the lab grants file; the grants file stays outside the bundle,
  labelled 'lab stand-in, not admission'". `README.md:678-680` gives the format
  (`wc-009.lab-grants/v1`), and `README.md:682-683` says the label is exactly
  "lab stand-in, not admission". `README.md:1350-1354` labels the `&[]` bug in
  `run` "hand-proven, pending R1 (LOG.md, task 020), outside every count
  above", and `README.md:1315-1317` keeps the 17 as runner-caught. Still true
  at dc78bca5b for the rule and the label (`README.md:896-898`, `:910`,
  `:929`). Two later merges changed the rest on purpose. Task 031 (PR #279)
  made the format `wc-009.lab-grants/v2`, with a `right` per grant
  (`README.md:910`). Task 029 (PR #269, merge `a541cd7ba`) added the runner
  entry F-WC9-RUN-DROPS-GRANTS for the `&[]` bug and relabelled it runner-caught
  (`README.md:2780-2783`, `:2912-2915`). The runner run below confirms that
  entry.
- Promise 6: no new dependency, and `tools/Cargo.toml`, `Cargo.toml` and
  `Cargo.lock` unchanged. `git diff --stat a5b4e8a10^1 a5b4e8a10 --
  lab/wasm-capsule/tools/Cargo.toml lab/wasm-capsule/Cargo.toml
  lab/wasm-capsule/Cargo.lock` prints nothing. Still true at dc78bca5b: `git
  log --oneline a5b4e8a10..dc78bca5b` on those three files prints nothing.
- The one-path rule (P10). At the merge, the grants reach the one `audit` call.
  `tools/src/run.rs:543` passes `input.granted` to the one `verify_bundle`
  call. `tools/src/verify.rs:182` is the only `audit(module, granted)` call in
  `tools/src/` (`git grep -n "audit(" a5b4e8a10 -- lab/wasm-capsule/tools/src`
  finds only it). The unused grants are worked out from the audit's own list
  (`grants_not_imported`, `tools/src/verify.rs:191-200`), with no second import
  read. Still true at dc78bca5b: `tools/src/run.rs:1284` and
  `tools/src/verify.rs:262`. Task 033's `memories` call (`tools/src/run.rs:658`)
  reads memory limits, not imports, through the same audit crate.

The runner run for promise 4, from the repo root at dc78bca5b. It covers every
`F-WC9-*` id now in the list. That is 18 ids: the 17 above, plus
F-WC9-RUN-DROPS-GRANTS from task 029. No `F-WC9-*` id was removed. It also
covers the four re-anchored entries. Every edit of these 22 entries names a file
under `lab/wasm-capsule/`: `tools/src/verify.rs`, or `tools/src/run.rs` for
F-WC9-RUN-DROPS-GRANTS, F-WC5a, F-WC5-VERIFY-TWICE and
F-WC5-QUERY-BEFORE-VERIFY.

```
$ RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 python3 -I examples/agent-host/falsify.py \
    --from lab/wasm-capsule/falsifiers.json F-WC9-LINK-ALL F-WC9-GRANT-INJECT \
    F-WC9-GRANTS-LABEL F-WC9-GRANTS-CAUSE F-WC9-GRANTS-NOT-JSON F-WC9-GRANTS-NOT-OBJECT \
    F-WC9-GRANTS-UNKNOWN-KEY F-WC9-GRANTS-MISSING-KEY F-WC9-GRANTS-SCHEMA \
    F-WC9-GRANTS-IMPORTS-NOT-LIST F-WC9-GRANTS-ENTRY-EXTRA-KEY F-WC9-GRANTS-ENTRY-NOT-STRING \
    F-WC9-GRANTS-DUPLICATE F-WC9-UNUSED-KEEPS-USED F-WC9-UNUSED-REORDER \
    F-WC9-GRANTS-READ-TWICE F-WC9-GRANTS-PARSE-TWICE F-WC9-RUN-DROPS-GRANTS \
    F-WC5a F-WC5-VERIFY-TWICE F-WC5-QUERY-BEFORE-VERIFY F-WC4-SEALED-NEW
baseline: 10 named tests pass without an edit, 0 do not
summary: 22 CAUGHT of 22
exit 0
```

Each of the 22 entries printed CAUGHT. After the run, `git status --short`
printed nothing, and no `*.falsify-original` backup was left in the lane.

No finding. Every promise held at the merge. The later changes to the format,
the test grants and one label were made on purpose by tasks 029, 031 and 039,
and none of them broke 025's promises.
