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

Task 048's four sections (after 047's two) use base commit
`43b4af9441fa6a0a3a5d379721633c158bcc8c1d` (`43b4af944`, the merge of 047's
PR #608). In those sections, "still true at 43b4af944" is said of that base.

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

## PR #238 (task 021), merge 3a4d2812a

Verdict: PASS

Lane diff: `git diff 3a4d2812a^1 3a4d2812a -- lab/wasm-capsule/` (2 files,
+137 -0). The promises, as task 048 quotes them from task 021:

- Promise 1: README section "## Memory cap discovery (wc-010a)" and one LOG
  entry, naming both engine versions. At the merge: `README.md:731` (heading),
  `README.md:735-738` (`wasmtime 45.0.1 (83166ba31 2026-06-05)` and
  `wasmer 7.5.0`, each from `--version`), and one entry at `LOG.md:386-403`
  naming both. Checked: both `--version` lines re-run (below) print the same
  text. Still true at 43b4af944: `README.md:1007`, `LOG.md:386`.
- Promise 2: for each engine, its memory cap flag from `--help`, or none. At
  the merge: wasmtime's two `-W help` lines at `README.md:776-779`; wasmer's
  search at `README.md:801-811`. Checked by a run: `wasmtime -W help` prints
  the same two lines (lines 13 and 18 of its output). `wasmer run --help` and
  `wasmer --help` both exit 0; the eleven words of `README.md:802-803` match
  nothing in `wasmer --help` (count 0), and in `wasmer run --help` only the
  lines the README lists (the four Wasm feature switches, the CPU back-off
  "maximum amount of time", `--with-compact-on-growth` and `--stack-size`),
  plus two lines it does not quote: "Skip writes to stdout and stderr ..."
  (journal replay) and "Generate a coredump at this path if a WebAssembly trap
  occurs". Neither is a memory cap. Still true at 43b4af944 (`README.md:1049`,
  `:1076`).
- Promise 3: probe runs within the cap, past it with the flag, and past it
  without. At the merge: the probe modules at `README.md:753-770`, the
  wasmtime table at `README.md:786-794` and the wasmer table at
  `README.md:814-818`, each row with its full command (run from the probe
  folder). Checked by a run of seven rows (below): every exit code and stdout
  matches. Still true at 43b4af944 (`README.md:1063-1071`, `:1091-1095`).
- Promise 4: a one-line answer per engine. At the merge, `README.md:822-826`
  (wasmtime "grow returns -1", "trap" with `trap-on-grow-failure=y`, "start
  refused" for an above-cap minimum) and `README.md:827-829` (wasmer
  "SKIPPED"). Checked: the runs below give each answer. Still true at
  43b4af944 (`README.md:1099-1106`). Later merges built on it and did not
  contradict it: task 027 (PR #254, merge `c5f50b08a`) gives wasmtime the cap,
  and added the note at `README.md:1011-1012` that `run.rs` now passes a
  flag. Task 030 (PR #273, merge `4a6a61896`) found that both engines apply a
  module's own maximum with no flag (`README.md:1310-1329`). That is a
  separate question from 021's, which was about a CLI cap flag: wasmer still
  has none.
- Promise 5: the `/usr/bin/time -l` line, labelled as process resident memory.
  At the merge, `README.md:835-848` ("This is the **engine process's resident
  memory**, not the capsule's linear memory"). Checked by a run: wasmtime
  printed `14745600  maximum resident set size`, wasmer `19316736`, both
  below 64 MB as the README says (021 measured 14696448 and 19218432; RSS
  varies by run, and the README gives it only as an example). Still true at
  43b4af944 (`README.md:1112-1125`).
- Promise 6: the `manifest.rs` lines for the declared 64 MB size, cited at its
  base. At the merge, `README.md:742-751` cites
  `elastos/crates/elastos-common/src/manifest.rs` at `a5b4e8a10`: lines 102-103
  (`#[serde(default)] pub resources: ResourceLimits`), 1167-1169 (`pub struct
  ResourceLimits {`, `#[serde(default = "default_memory")]`, `pub memory_mb:
  u32`) and 1188-1190 (`fn default_memory() -> u32 { 64 }`). Checked with
  `git show a5b4e8a10:elastos/crates/elastos-common/src/manifest.rs`: those
  lines hold that text. Still true at 43b4af944: the same lines, and `git log
  3a4d2812a..43b4af944 -- elastos/crates/elastos-common/src/manifest.rs`
  prints nothing. `grep -n resources lab/wasm-capsule/capsule/capsule.json`
  still prints nothing, exit 1.
- Promise 7: only README and LOG changed. `git diff --stat` above lists only
  `LOG.md` and `README.md`. A fact about the merge.

The run, in a scratch folder outside the repo, `S=/tmp/r048.ysgdPW`. The two
probe modules are written from `README.md:757-763` (`grow.wat`) and
`README.md:769` (`big-min.wat`) as given; the engines took the `.wat`
files directly. From `$S`, engine paths `/opt/homebrew/bin/...`:

```
$ wasmtime --version
wasmtime 45.0.1 (83166ba31 2026-06-05)
$ wasmer --version
wasmer 7.5.0
$ wasmtime -W help | grep -n 'max-memory-size\|trap-on-grow-failure'
13:  -W                         max-memory-size=N -- Maximum size, in bytes, that a linear memory is allowed to reach.
18:  -W                trap-on-grow-failure[=y|n] -- Force a trap to be raised on `memory.grow` and `table.grow` failure instead of returning -1 from these instructions.
$ wasmtime run -W max-memory-size=67108864 --invoke grow grow.wat 1023
1                                                   exit 0
$ wasmtime run -W max-memory-size=67108864 --invoke grow grow.wat 1024
-1                                                  exit 0
$ wasmtime run -W max-memory-size=67108864,trap-on-grow-failure=y --invoke grow grow.wat 1024
(no stdout)                                         exit 1
stderr, last line:     2: forcing trap when growing memory to 67174400 bytes
$ wasmtime run --invoke grow grow.wat 1024
1                                                   exit 0
$ wasmtime run -W max-memory-size=67108864 --invoke size big-min.wat
(no stdout)                                         exit 1
stderr, last line:     1: memory minimum size of 1025 pages exceeds memory limits
$ wasmer run --invoke grow grow.wat 1024
1                                                   exit 0
$ wasmer run --invoke size big-min.wat
1025                                                exit 0
$ /usr/bin/time -l wasmtime run -W max-memory-size=67108864 --invoke grow grow.wat 1023
            14745600  maximum resident set size
$ /usr/bin/time -l wasmer run --invoke grow grow.wat 1023
            19316736  maximum resident set size
```

Each wasmtime run that got as far as `--invoke` printed the CLI's `--invoke`
warnings on stderr first, as `README.md:782-784` says. No answer line is
contradicted.

No finding. Every promise held at the merge, and still holds at 43b4af944.

## PR #240 (task 022), merge 6333a87dd

Verdict: PASS

Lane diff: `git diff 6333a87dd^1 6333a87dd -- lab/wasm-capsule/` (2 files,
+161 -0). The promises, as task 048 quotes them from task 022:

- Promise 1: README section "## Granted import hosting discovery (wc-009b0)"
  and one LOG entry. At the merge: `README.md:850` and `LOG.md:404-421`, both
  naming `wasmtime 45.0.1 (83166ba31 2026-06-05)` and `wasmer 7.5.0`. Still
  true at 43b4af944: `README.md:1390`, `LOG.md:404`.
- Promise 2: for each engine, a way to supply `env.f` from a zero-import host
  module, or none. At the merge: wasmtime's `--preload <NAME=MODULE_PATH>`
  from `wasmtime run --help` at `README.md:901-904`; wasmer's search at
  `README.md:942-954` and the two near lines it tried at `README.md:956-961`.
  Checked by a run: `wasmtime run --help` prints `--preload <NAME=MODULE_PATH>`
  and "Load the given WebAssembly module before the main module" (its lines 91
  and 92). In `wasmer run --help`, `preload` matches nothing and `import`
  matches only the two lines the README quotes (its lines 249 and 269);
  `wasmer --help` matches none of `preload`, `import`, `link`, `module` or
  `host` (count 0). Still true at 43b4af944 (`README.md:1442`, `:1485`).
- Promise 3: a one-line answer per engine. At the merge, `README.md:980-983`
  ("hosts by flag `--preload env=<path>`") and `README.md:984-986` ("SKIPPED:
  ..."). Checked: the runs below give both answers. Still true at 43b4af944
  (`README.md:1525-1531`).
- Promise 4: for a found flag, whether it changes what a zero-import module
  sees, by a real run with and without it. At the merge, `README.md:932-938`:
  the real capsule (sha256 `6dd9af1a...`, the pin then at
  `tests/bundle.rs:32` and `tests/verify.rs:52`) printed
  `230101071268130872` with and without `--preload env=<D>/host.wat`. The
  merge's conclusion, "so the preload changes nothing a zero-import module
  sees" (`README.md:938`), says more than one output shows. It was changed by
  task 026 (PR #245, merge `bf752df1a`), which narrowed it to "this
  capsule's output for `1592590337` was unchanged; this one comparison says
  nothing about any other effect of a preloaded module" (`README.md:1483` at
  43b4af944). Checked by a run on today's capsule (task 032, PR #306, gave it
  a memory maximum, so its sha256 is now `2002429e...`, equal to
  `PINNED_ARTIFACT_SHA256`, `tests/common/mod.rs:30-31`): with and without the
  flag, exit 0 and `230101071268130872`, which is `FIXED_OUTPUT`
  (`capsule/src/lib.rs:20`, `0x0331_7BB4_875F_B038`).
- Promise 5: only README and LOG changed. `git diff --stat` above lists only
  `LOG.md` and `README.md`. A fact about the merge.
- The probe commands. At the merge, each table row gave only the flag added
  (`README.md:911-917`, `:967-971`), and the runner's shape once, at
  `README.md:864-866` (`env -i`, stdin from `/dev/null`, `run --invoke digest
  <absolute module path> 1592590337`). That was enough to re-run them (flag
  after `run`), and every row gave the same result. Task 026 then wrote each
  complete command into the tables (`README.md:1456-1462` and `:1512-1516` at
  43b4af944); this review ran exactly those commands.

The run, in the same scratch folder, `D=$S/wc009b0`. The four probe modules
are written from `README.md:1411-1436` at 43b4af944 as given. Each command is
the table's, with `<D>` filled in and the engine path `/opt/homebrew/bin/...`:

```
$ env -i wasmtime run --preload env=$D/host.wat --invoke digest $D/main.wat 1592590337 < /dev/null
1592590338                                          exit 0
$ env -i wasmtime run --invoke digest $D/main.wat 1592590337 < /dev/null
(no stdout)                                         exit 1
    1: unknown import: `env::f` has not been defined
$ env -i wasmtime run --preload other=$D/host.wat --invoke digest $D/main.wat 1592590337 < /dev/null
(no stdout)                                         exit 1
    1: unknown import: `env::f` has not been defined
$ env -i wasmtime run --preload env=$D/host-wasi.wat --invoke digest $D/main.wat 1592590337 < /dev/null
1592590338                                          exit 0
$ env -i wasmtime run --preload env=$D/host-unknown.wat --invoke digest $D/main.wat 1592590337 < /dev/null
(no stdout)                                         exit 1
Error: failed to process preload `env` at `/tmp/r048.ysgdPW/wc009b0/host-unknown.wat`
    unknown import: `nope::g` has not been defined
$ env -i wasmer run --invoke digest $D/main.wat 1592590337 < /dev/null
(no stdout)                                         exit 1
╰─▶ 1: Error while importing "env"."f": unknown import. Expected Function(FunctionType { params: [I32], results: [I32] })
$ env -i wasmer run --use $D/host.wat --offline --invoke digest $D/main.wat 1592590337 < /dev/null
(no stdout)                                         exit 1
╰─▶ 1: Error while importing "env"."f": unknown import. Expected Function(FunctionType { params: [I32], results: [I32] })
$ env -i wasmer run --enable-module-linking --invoke digest $D/main.wat 1592590337 < /dev/null
(no stdout)                                         exit 1
error: No backends support the required features for the Wasm module. Feel free to open an issue at https://github.com/wasmerio/wasmer/issues
$ lab/wasm-capsule/tools/build $S/build      # from the repo root
built /tmp/r048.ysgdPW/build/capsule.wasm 2002429e73ee1a5e983df008f5b53728882646f109d55a9d1a93e831690631e1
$ env -i wasmtime run --invoke digest $S/build/capsule.wasm 1592590337 < /dev/null
230101071268130872                                  exit 0
$ env -i wasmtime run --preload env=$D/host.wat --invoke digest $S/build/capsule.wasm 1592590337 < /dev/null
230101071268130872                                  exit 0
```

(iv) is borne out: wasmtime linked `host-wasi.wat`'s
`wasi_snapshot_preview1` import with no WASI flag, and (iv-c) shows an import
it cannot answer is refused. `git grep -n preload 43b4af944 --
lab/wasm-capsule/tools/src` prints nothing: no preload route reached the
runner, as Rong's later ruling asks.

No finding. Every promise held at the merge. The one overclaim
(`README.md:938` at the merge) and the flag-only tables were fixed by task 026
before this review.

## PR #241 (task 023), merge 33cbed8c5

Verdict: PASS

Lane diff: `git diff 33cbed8c5^1 33cbed8c5 -- lab/wasm-capsule/` (4 files,
+80 -1). The promises, as task 048 quotes them from task 023:

- Promise 1: the `falsifiers.json` `"about"` states no evidence status. At the
  merge, `falsifiers.json:2` drops "(ask R1, pending), so these are
  hand-proven, pending R1 ..." and "(R1 is done: ...)", and says instead that
  each entry's evidence label and count are kept in README.md "## Falsifiers".
  The diff changes only line 2. Still true at 43b4af944: a case-ignoring
  search of the `"about"` text for `caught`, `proven`, `by hand`, `pending`,
  `R1`, `R2` and `evidence` finds only the pointer sentence, and the one
  F-WC5-BOTH-ARGS note ("caught only by the real-engine test; NOT RUN when an
  engine is missing ..."), which says what the runner would print, not a
  status.
- Promise 2: new test `falsifiers_about_states_no_evidence_status`. At the
  merge, `tests/docs.rs:56`, with its five words at `tests/docs.rs:19` and its
  three assertions at `:66`, `:71` and `:75`. Still true at 43b4af944:
  `tests/docs.rs:324`, words at `:36`.
- Promise 3: a falsifier proven by hand. LOG shows the failing assertions: at
  the merge, `LOG.md:422-442` lists eight planted bugs, each with the line it
  failed at and its message, for example "`tests/docs.rs:66:5`
  `falsifiers.json "about" states evidence status, which README.md "##
  Falsifiers" alone holds: found ["pending", "hand-proven", "R1"]`", then
  `:71:5` and `:75:5` for the two pointer checks. Those are the three
  assertion lines of the test at the merge. It also records the restore
  (`shasum -a 256` equal to the fixed file). `falsifiers.json` is the
  runner's input, not a recovery target, at the merge and at 43b4af944
  (`examples/agent-host/falsify.py:339-359` lists no `falsifiers.json`), so a
  hand proof is the only kind possible. This review re-proved one of the
  eight at 43b4af944 (below).
- Promise 4: one README sentence saying "## Falsifiers" is the one place for
  evidence labels and counts. At the merge, `README.md:1292-1294`, and the
  eight hand proofs are labelled outside every count at `README.md:1621-1627`.
  Still true at 43b4af944: `README.md:2456-2458` and `:2800-2806`.

The hand check at 43b4af944. It ran while this review held the build lease,
from a `python3 -I` script in the scratch folder (not committed). The script
appended " These are pending." after the one match of "this text says only
what each falsifier plants." in `falsifiers.json` (one match), ran the named
test, then wrote the original bytes back:

```
$ RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 cargo test --locked \
    --manifest-path lab/wasm-capsule/Cargo.toml --test docs falsifiers_about_states_no_evidence_status
test falsifiers_about_states_no_evidence_status ... FAILED
panicked at tests/docs.rs:334:5:
falsifiers.json "about" states evidence status, which README.md "## Falsifiers" alone holds: found ["pending"]
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 5 filtered out
exit 101
sha256 before = after = 03a4d82907e1e8d415229871149bf3881a0fd35ac199a2fcadc3d2f0f6e02af8
$ cargo test --locked --manifest-path lab/wasm-capsule/Cargo.toml --test docs   # restored
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

`tests/docs.rs:334` is the test's first assertion at 43b4af944, the same
check that failed at `:66` at the merge.

No finding. Every promise held at the merge, and still holds at 43b4af944.

## PR #245 (task 026), merge bf752df1a

Verdict: FOLLOWUP

Lane diff: `git diff bf752df1a^1 bf752df1a -- lab/wasm-capsule/` (6 files,
+443 -34). The promises, as task 048 quotes them from task 026:

- Promise 1: README holds Rong's engine sentence once ("Both engines, wasmtime
  and wasmer, are test-only and not endorsed. The engine choice is
  Anders's."). At the merge: `README.md:63`, in "## Layout" (`:26`), and once
  in ADOPTION at `ADOPTION.md:75`. Both engine doc comments in
  `tools/src/run.rs` say "test-only, not endorsed" (`:70`, `:99` above
  `pub enum Engine` at `:101`). Still true at 43b4af944: `README.md:63`,
  `ADOPTION.md:92`, `tools/src/run.rs:169` and `:300`; `grep -cF` of the
  sentence gives 1 in each of README and ADOPTION.
- Promise 2: 022's section holds the discovery ruling once, before the
  per-engine answers. At the merge, `README.md:872`, inside the section at
  `:853` and before its first answer line `### wasmtime ...` at `:905`; and
  once in ADOPTION at `ADOPTION.md:283`. Still true at 43b4af944:
  `README.md:1409` (section `:1390`, first answer line `:1442`) and
  `ADOPTION.md:302`.
- Promise 3: tests `engines_are_labelled_test_only_not_endorsed` and
  `hosting_discovery_is_not_the_import_path`. At the merge, `tests/docs.rs:149`
  and `:196`, with the two sentences as consts at `:29` and `:34`. Still true
  at 43b4af944: `tests/docs.rs:236` and `:283`, consts at `:39` and `:44`.
- Promise 4: falsifiers in `falsifiers.json`, each anchored in `README.md` and
  found there exactly once, including F-WC-ENGINE-ENDORSED and
  F-WC9B0-IMPORT-PATH. At the merge, seven new entries (146 in all), each
  editing only `../../lab/wasm-capsule/README.md`; `LOG.md:463` records
  "summary: 8 CAUGHT of 8" (with F-WC-README-COUNT). All seven are still in
  the list at 43b4af944 (184 entries), each still editing only `README.md`.
  Re-run by the canonical runner at 43b4af944 (below).
- Promise 5: two of 022's PASS follow-ups folded into the same README section.
  At the merge: the complete commands (`README.md:919-925` and `:975-979`, the
  column now "Complete command as run") and the narrowed conclusion
  (`README.md:946`). Still true at 43b4af944 (`README.md:1456-1462`,
  `:1512-1516`, `:1483`); this review ran those commands (PR #240 above).
- Promise 6: five more falsifiers, hand-proven, outside README's counts. LOG
  shows each failing assertion: `LOG.md:471-478` at the merge gives the line
  and message of each (`:152:9`, `:189:5`, `:173:5`, `:178:5`, `:229:5`,
  which are the test's assertion lines at the merge). The reason the README
  gives for two of them is wrong; see the FOLLOWUP below.

The runner run at 43b4af944, from the repo root, with the build lease held
(it was busy for 500 s first; the wait was bounded at 25 minutes). It covers
all seven of 026's ids; each edits only `README.md`. F-WC-README-COUNT, which
026 re-anchored, has been re-anchored by every later task that changed the
total, so it is not 026's any more and is not run here.

```
$ RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 python3 -I examples/agent-host/falsify.py \
    --from lab/wasm-capsule/falsifiers.json F-WC-ENGINE-ENDORSED F-WC-ENGINE-MOVED \
    F-WC-ENGINE-TWICE F-WC-ENDORSE-LINE F-WC9B0-IMPORT-PATH F-WC9B0-AFTER-ANSWERS F-WC9B0-TWICE
baseline: 2 named tests pass without an edit, 0 do not
summary: 7 CAUGHT of 7
exit 0
```

Each of the seven printed CAUGHT. After the run, `git status --short` showed
only this file, and no `*.falsify-original` backup was left in the lane.

The finding. `README.md:1676-1678` at the merge, and `README.md:2831-2833`
at 43b4af944, say "`ADOPTION.md` and `tools/src/run.rs` are not recovery
targets, so they have no `falsifiers.json` entry". For `ADOPTION.md` that is
true. For `tools/src/run.rs` it was already false when PR #245 merged:
provider 026 (PR #242, merge `2221f8fbe`) merged first and made it a target
(`examples/agent-host/falsify.py:336` at `bf752df1a^1` and at `bf752df1a`,
`:357` at 43b4af944). The same README says so for later tasks
(`README.md:3067`: "`tools/src/run.rs`, a recovery target"). 026 was built on
`33cbed8c5`, before #242, so its builder's statement was true on its own base,
but the merged text was not. So F-WC-ENGINE-RUN-MODULE-DOC and
F-WC-ENGINE-RUN-ENUM-DOC stay hand-proven with no runner entry, for a reason
that no longer holds.

FOLLOWUP: lab/wasm-capsule/README.md:2832 says `tools/src/run.rs` is not a recovery target, so F-WC-ENGINE-RUN-MODULE-DOC and F-WC-ENGINE-RUN-ENUM-DOC stay hand-proven with no `falsifiers.json` entry, but run.rs has been a target since provider PR #242 merged before #245 (README:3067 says so too) — hand check: `grep -n '"lab/wasm-capsule/tools/src/run.rs"' examples/agent-host/falsify.py` prints `357:`, and `grep -c F-WC-ENGINE-RUN lab/wasm-capsule/falsifiers.json` prints `0`.
