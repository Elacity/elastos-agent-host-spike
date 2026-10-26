# wasm-capsule lab — log

- wc-001: byte-identical build of a zero-import core-Wasm capsule exporting
  `digest(i32)->i64`; `tools/build` + receipt; named tests for reproducibility,
  receipt toolchain/hashes, digest value, and wasm shape; 7 falsifiers in
  `falsifiers.json` proved by break → named test fails → revert (falsify.py
  `lab` command pending R1). Reproducible on this one Mac only; sha256
  `6dd9af1a8d33d14f48514611663e3f5b262f91ef2729de4ec851441af9b22b13`.
- wc-000 (task 005): the cx-wasm-audit lane's `wasm-capsule-audit` crate joins
  the lab workspace (`members = ["audit"]`; nothing written in `audit/`).
  `Cargo.lock` re-resolved offline from the cargo cache (21 registry crates:
  `wasmparser` 0.258.0, `wat` 1.258.0 and their deps), sha256 `d3348a16…` →
  `039aee94…`.
  `LANE_SOURCE_ENTRIES` copies `audit` (without it
  `two_clean_builds_in_different_paths_are_byte_identical` fails); README,
  ADOPTION and comments corrected (P12). `cargo test -p wasm-capsule-audit
  --locked` green; `capsule.wasm` unchanged (`6dd9af1a…`). No new rule.
- wc-003a (task 007): the lab-name rule as a library, the new member crate
  `wasm-capsule-tools` (`tools/`; `sha2` =0.10.9 and `libc` =0.2.189, the
  Runtime's pins). It holds `read_bundle`, `canonical_closure`, an infallible
  in-process `lab_name` and `name_bundle`; each closure file is opened once by
  `open_regular` (`O_NOFOLLOW | O_NONBLOCK` from `libc`) and read from that
  handle. `Cargo.lock` re-resolved offline (21 → 31 registry crates, all new
  ones at the Runtime's versions), sha256 `039aee94…` → `7056522c…`. 16 named
  tests in `tests/lab_name.rs`; 20 falsifiers proved by break → named test
  fails → revert (falsify.py `lab` pending R1). Discovery re-checked: the name
  carried 007's lane-own label (PR #105), never a CID. Pinned vector re-computed with
  `printf | shasum -a 256`; `capsule.wasm` unchanged (`6dd9af1a…`).
- wc-003a round 2 (review fix): `open_regular(path)` builds its own read-only
  options (caller-chosen options had let it empty or create a file), and its
  handle check is `check_regular`, so a failed inspection is tested too. Tests
  `the_one_open_never_writes_truncates_or_creates_a_file` and
  `inspection_failure_reports_path_and_cause` (18 named tests); falsifiers
  F-WC3-WRITABLE, -TRUNCATE, -CREATE and -INSPECT-CAUSE (24 for wc-003a), all
  caught by hand (falsify.py `lab` pending R1).
- Task 010 (one lab identity rule, Rong's one-rule note): 007's lane-own name
  rule (PR #105) is retired. `tools/src/lab_name.rs`, `tests/lab_name.rs` (18
  tests) and the 24 wc-003a falsifiers are deleted. The tools crate now
  path-depends on `lab/capsule-identity/` and names a bundle only through
  `pub use capsule_identity::lab_cid as bundle_identity;`; `sha2` and `libc`
  are dropped. New `capsule/capsule.json` (an `elastos.capsule/v1` manifest,
  277 bytes, exposed as `CAPSULE_MANIFEST`); the root package dev-depends on
  `elastos-common` (read-only) and `serde_json` to read it with the Runtime's
  `CapsuleManifest`, and keeps no `[dependencies]`. `Cargo.lock` re-resolved
  offline (31 → 135 registry crates; new names at capsule-identity's locked
  versions, existing ones unchanged), sha256 `7056522c…` → `1e9608bc…`. The
  reproducibility copy is laid out as `<root>/lab/wasm-capsule` with links to
  `lab/capsule-identity` and `elastos`. Named tests in `tests/lab_cid.rs`:
  `lab_manifest_passes_runtime_validate`,
  `this_capsule_bundle_has_the_pinned_lab_cid` (pin recomputed with Python
  `hashlib` from capsule-identity's README encoding) and
  `the_lane_keeps_no_bundle_name_rule_of_its_own`. Falsifiers F-WC3-LABCID-SCHEMA,
  -ENTRYPOINT, -VERSION, -PIN, F-WC3-SECOND-RULE, F-WC3-SECOND-IMPORT and
  F-WC3-COPY-DEPS: hand-proven, pending R1 (runner-caught: none);
  F-WC1-SPACED-PATH still caught by hand with the new layout. `capsule.wasm`
  unchanged (`6dd9af1a…`). Finding C4: a copy of `lab/wasm-capsule/` alone no
  longer builds (cc-redteam's probe; its fix).
- wc-003c (task 009): `tools/bundle OUT_DIR` makes a new OUT_DIR (`create_dir`),
  runs `tools/build` by its path (its stdout to stderr), makes `bundle/`
  (`create_dir`) and `capsule.json` (`create_new`, `CAPSULE_MANIFEST`), moves
  the module in with `rename`, and prints `bundle_identity(OUT_DIR/bundle)`;
  `--name BUNDLE_DIR` prints an existing bundle's lab CID. Rules in
  `tools/src/bundle.rs` (`parse_args`, `run` with the build script's path as the
  test seam), a thin `bundle` binary and a bash wrapper; stand-in build scripts
  in `tests/bundle_builds/`. 8 named tests in `tests/bundle.rs`, one of which
  spawns the wrapper (its child cargo uses its own target and build folder
  under that test's temp dir). Reference lab CID on this Mac
  `lab-cid:sha256:9ca715378b264e54614d2a231ee4d8e58e6a145873c55291fd02066aaf57f930`
  (also recomputed with Python `hashlib`). 23 falsifiers (F-WC3-CMD-BYPASS,
  -REUSE-OUT, -FOLLOW-WRITE, -MODULE-COPY, five -ARGS-*, -ARGS-UTF8,
  -BUILD-CAUSE, -BUILD-STDOUT, -IO-PATH, -IO-MOVE-PATH, five -IO-CAUSE-*,
  -CMD-REASON, -CMD-STATUS, -CMD-STDOUT, -ARTIFACT-PIN): hand-proven, pending R1
  (runner-caught: none). `Cargo.lock` and `capsule.wasm` (`6dd9af1a…`)
  unchanged; both of 010's retirement greps give empty output, exit 1.
- wc-003c round 2: the wrapper test's child `CARGO_TARGET_DIR`/`CARGO_BUILD_BUILD_DIR`
  moved from the lane's `target/tools-bundle-test` to that test's own temp dir
  (`tools_bundle(child_target, args)`), so the test writes nothing in the checkout.
- wc-004 (task 004): `wasm_capsule_tools::verify` (`tools/src/verify.rs`), the one verify path as library calls:
  `verify_checked(checked, signature, accepted, granted)` refuses `None` as unsigned, then calls cc-capsule-identity's
  `verify_checked_signature` once, reads the manifest's `entrypoint` from the checked `capsule.json` with the Runtime's
  `CapsuleManifest`, and calls `wasm_capsule_audit::audit(module, granted)` once on the checked bytes;
  `verify_bundle` is `checked_bundle` then `verify_checked`. Returns a sealed `VerifiedBundle`
  (`cid()`/`entries()`/`imports()`). No command, no signature file (C2: in memory only); reads no file by path; ordinary
  callers grant nothing until wc-009. Tools crate path-depends on `audit`, `elastos-common`, `serde_json`; root
  dev-depends on `capsule-identity`, `wasm-capsule-audit`, `elastos-identity`, `ed25519-dalek`, `rand` (no new crate:
  135 registry crates). `*.seed` added to the lane `.gitignore`. 21 named tests in `tests/verify.rs` (the real
  `tools/build` capsule passes the audit); `the_lane_keeps_no_bundle_name_rule_of_its_own` now allows the verifier's
  identity imports and still refuses a second naming import. 21 falsifiers (F-WC4a to F-WC4g and 14 more): hand-proven,
  pending R1 (runner-caught: none); F-WC3-SECOND-IMPORT and -SECOND-RULE re-proved. `capsule.wasm` stays `6dd9af1a…`.
- wc-004 round 2: the key scan in `no_key_material_is_tracked_in_the_lane` no longer skips a listed file it cannot
  read. `scan_lane_file` checks the name before any read, and an unreadable listed file (for example a key file still
  in git's index but gone from the worktree) is a finding with its path and cause. The test plants an absent `.seed`
  (reported by name and as unreadable) and an absent plain file (reported as unreadable). New falsifiers
  F-WC4-SCAN-SKIP-MISSING and F-WC4-SCAN-NAME-AFTER-READ. Evidence, rustc 1.91.0 (f8297e351 2025-10-28):
  - `Cargo.lock` sha256 `1e9608bc2fe285c471b23e3bc35d40eb013a68deaab0a788385a8f4a697cbe89` at base `be952af5f`, then
    `747f66b02bc35c03ba463311fc4569f17a3837f27724ec8846bedae68639f39f`; `capsule.wasm` stays
    `6dd9af1a8d33d14f48514611663e3f5b262f91ef2729de4ec851441af9b22b13` (the pinned-sha256 tests pass).
  - `cargo test --locked --manifest-path lab/capsule-identity/Cargo.toml`: 67 passed, 0 failed.
    `cargo test -p wasm-capsule-audit --locked` (from `lab/wasm-capsule/`): 20 passed, 0 failed.
  - Both retirement greps (BACKLOG merge gate): empty output, exit 1.
  - Each wc-004 falsifier, planted alone, then the named tests run with `--exact`, then the files restored byte for
    byte (the `git diff` sha256 was the same before and after). Every named test failed at an assertion with no build
    error. The failing line is in `tests/verify.rs`:
    F-WC4a: `wasm_changed_after_signing_is_refused` (:149), `manifest_changed_after_signing_is_refused` (:125, "the
    verifier passed …, not a refusal") and `extra_file_after_signing_is_refused` (:125);
    F-WC4b: `unsigned_bundle_is_refused` (:125, passed, not a refusal);
    F-WC4c: `bundle_with_undeclared_import_is_refused_even_if_signed` (:125, passed, not a refusal);
    F-WC4d: `verifier_reads_no_bundle_file_by_path` (:616, "reaches a file by a path: fs::read");
    F-WC4e: `a_grant_reaches_the_audit_unchanged` (:120, "refused: undeclared import env.f");
    F-WC4f: `key_and_seed_files_are_ignored_by_git` (:857, check-ignore list differs);
    F-WC4g: `no_key_material_is_tracked_in_the_lane` (:839, "README.md:593: a PEM private-key line");
    F-WC4-SCAN-SKIP-MISSING: same test (:797, the `.seed` is reported only by name, not as unreadable);
    F-WC4-SCAN-NAME-AFTER-READ: same test (:796, the `.seed` is reported only as unreadable, not by name);
    F-WC4-ENTRY-SUBSTITUTE: `missing_entrypoint_is_refused` (:125, passed, not a refusal);
    F-WC4-ENTRY-HARDCODED: `verifier_uses_manifest_entrypoint` (:125, passed, not a refusal);
    F-WC4-WALK-REASON, -SIG-REASON, -AUDIT-REASON: `verifier_preserves_upstream_refusals` (:411 "no manifest", :440
    "a malformed DID", :460 "code in a custom section");
    F-WC4-ORDER-AUDIT-FIRST, -ORDER-UNSIGNED-FIRST: `verifier_preserves_check_order` (:495, :479);
    F-WC4-SEALED-FIELD, -SEALED-NEW, -SEALED-MUT: `verified_bundle_is_sealed` (:661 "a field is public", :675 and :675
    "the verifier's public functions");
    F-WC4-SECOND-SIG, -SECOND-AUDIT: `verifier_has_one_check_path` (:630, :635).
  - All 21: hand-proven, pending R1 (runner-caught: none). The `falsify.py --from` run is pending R1, not a PASS.
- wc-008 (task 011), base `f9d2b48f8160398e843e0d656d2771fefc4fef29`: FINDING `NO_ABI_FOR_BARE_CAPSULE`. None of the
  seven `CapsuleRuntimeAbi` values fits a bare core module, and both run paths (`run_cmd.rs:51-57`,
  `capsule_cmd.rs:267-273`) refuse a `wasm` capsule that is not a Component; ADOPTION.md has the table and both
  "Gaps for Anders". `capsule/capsule.json`, the pinned lab CID, `Cargo.lock` (`747f66b0…`) and `capsule.wasm`
  (`6dd9af1a…`) are unchanged. New `tests/runtime_abi.rs`: `bare_capsule_runtime_abi_is_recorded_as_skipped`
  (SKIPPED, `ignored`), `no_runtime_abi_names_a_bare_core_module` and `an_unknown_manifest_field_is_refused_by_name`.
  Falsifiers, each hand-proven, pending R1 (not in the runner-caught count): F-WC8-UNKNOWN-FIELD, F-WC8-NEAR-FIT,
  F-WC8-INVALID-BASELINE, F-WC8-NAME-WITHOUT-MANIFEST and the reused F-WC3-LABCID-PIN (counted once). A canonical
  runner run over these five said `summary: 5 CAUGHT of 5`, pending R1 (its recovery targets miss `capsule.json` and
  `tools/src/lib.rs`), not a PASS. Both retired-label greps still match the base's line 100 above (task 013's fix), so
  the merge is held until 013 lands.
- wc-003c (task 012): new falsifier F-WC3-CREATE-NEW (`write_new_file` opens `capsule.json` with
  `.create(true).truncate(true)` instead of `.create_new(true)`); no code or test change. Runner-caught: the canonical
  runner (`falsify.py --from lab/wasm-capsule/falsifiers.json F-WC3-CREATE-NEW`) said `summary: 1 CAUGHT of 1` and
  restored `tools/src/bundle.rs`. By hand, `bundle_io_refusals_keep_path_and_cause` panicked at
  `tests/bundle.rs:410:60` ("an entry is there: ()") with the bug in and passed after the revert.
- Task 017 (carry of 013), base `edc31fb23`: line 100 above no longer holds the retired name label, so both
  retirement greps give empty output, exit 1. `the_lane_keeps_no_bundle_name_rule_of_its_own` now checks that label in
  every git-listed lane file (docs, `falsifiers.json` and `audit/` included); the code names keep the docs exemption,
  and `lane_files` leaves out the runner's `*.falsify-original` backups. New falsifier F-WC3-RETIRED-LABEL-DOC.
  Runner-caught: `falsify.py --from lab/wasm-capsule/falsifiers.json F-WC3-RETIRED-LABEL-DOC F-WC3-SECOND-RULE
  F-WC3-SECOND-IMPORT` said CAUGHT for each and `summary: 3 CAUGHT of 3`, and restored `LOG.md` and
  `tools/src/lib.rs` byte for byte.
  Round 2: `lane_files` reads the listing with `git ls-files -z`, so git no longer quotes a name with a quote mark or
  tab and such a file is scanned, not skipped as missing. Hand-proven, pending R1: with an untracked `review"note.md`
  holding the label, the old line-split listing passed the test, and the `-z` listing failed it with
  `["review\"note.md:1: <label>"]` (label elided here). By hand on the falsifier's plant: the base `edc31fb23` test
  passed, this test failed with `["LOG.md:139: <label>"]`, and with a `LOG.md.falsify-original` copy beside it and only
  the docs label check off it passed (no false catch). `git hash-object LOG.md` was `5bc57325` before and after.
- wc-005a (task 014): `VerifiedBundle::entrypoint()` (the verifier keeps the index its one manifest read found;
  `entrypoint_module` became `entrypoint_index`) and `wasm_capsule_tools::run::run_engine` (`tools/src/run.rs`), a
  library function, no command. It refuses a relative engine path, then a work root that is not absolute, missing,
  not its own canonical path or not a folder; makes `<root>/<engine>` with mode `0o700` (an existing name refused);
  writes only `entrypoint()`'s in-memory bytes as `module.wasm` with `bundle::write_new_file`; starts the engine once
  as `run --invoke digest <absolute module> 1592590337` (006's discovered syntax, unchanged) with stdin null and an
  empty environment. No closure staging, no re-name, no seal. Spec-check FIX folded in: the isolation claim is scoped
  to the guest and the argv, the race limit covers folder swaps, and the tests `run_directory_is_private_and_new`,
  `runner_io_refusals_keep_path_and_cause`, `runner_uses_only_explicit_inputs`, `runner_reuses_shared_writer` and
  the one-manifest-parse check in `verifier_has_one_check_path` were added; F-WC4-SEALED-NEW and -SECOND-AUDIT
  re-anchored. 11 tests in `tests/run.rs` plus `verified_entrypoint_is_the_audited_module`. Real run:
  `wasmtime` and `wasmer` (Homebrew, `/opt/homebrew/bin`) each printed `230101071268130872` for `1592590337`.
  Falsifiers: 18 F-WC5 and F-WC4-ENTRYPOINT-ACCESSOR, -ENTRYPOINT-REPARSE; six wc-004 entries re-anchored. Canonical
  runner, `python3 -I examples/agent-host/falsify.py --from lab/wasm-capsule/falsifiers.json F-WC5 F-WC4`:
  "summary: 41 CAUGHT of 41", exit 0 (runner-caught; each named test passed unmutated first). `tools/src/run.rs` is
  not a runner recovery target (R2), so a killed run does not restore it.
- wc-005a round 2 (task 014, Codex FAIL, fail-closed): the work root's folder check used `Path::is_dir`, which turns
  every metadata error into "not a folder". Now `run::work_root_folder` takes `fs::metadata` of the canonical path,
  and a failed read is its own reason, `the work root's metadata cannot be read: <OS error>`, path kept;
  `runner_io_refusals_keep_path_and_cause` asserts it as an exact string and checks the runner calls that step on the
  canonical path's metadata with no second `is_dir`. FOLLOWUP done: new test `engine_stdin_is_null` (a stand-in
  checks `/dev/stdin -ef /dev/null`). New falsifiers F-WC5-IO-ROOT-METADATA, -IO-ROOT-IS-DIR, -STDIN-PIPED. Canonical
  runner, `... --from lab/wasm-capsule/falsifiers.json F-WC5 F-WC4`: "summary: 44 CAUGHT of 44", exit 0, no backup
  left (runner-caught; each named test passed unmutated first). `run.rs` is still not a recovery target (R2).
- wc-005b (task 015): `run::run(&RunInput)` in `tools/src/run.rs` calls `verify_bundle(..., &[])` once (a refusal is
  returned unchanged, nothing written, no engine started), then 014's `run_engine` for `wasmtime` and then `wasmer`
  (one after the other; `wasmer` is not started after `wasmtime` is refused, so equal failures get the first failure's
  own reason), and requires byte-identical stdout. Returns `TwoEngineRun` (private fields: `cid()`, `wasmtime()`,
  `wasmer()`); no receipt (016). Real engines on this Mac (`wasmtime` 45.0.1, `wasmer` 7.5.0): both printed
  `230101071268130872` for `1592590337`. Seven new tests in `tests/run.rs`; `runner_uses_only_explicit_inputs` now
  permits exactly one `verify_bundle(input.bundle, input.signature, input.accepted, &[])`. 11 new falsifiers. Canonical
  runner, `python3 -I examples/agent-host/falsify.py --from lab/wasm-capsule/falsifiers.json F-WC5 F-WC4`:
  "summary: 55 CAUGHT of 55", exit 0, no backup left (runner-caught; baseline: 34 named tests pass without an edit).
  Both retired-label merge-gate greps: empty, exit 1. `run.rs` is still not a recovery target (R2).
- wc-005c (task 016): `run` now asks each engine `--version` after `verify_bundle` and before any module run (one
  process each, by the same absolute path, through the new `engine_command`: empty environment, stdin null), keeps
  the first stdout line as printed, and refuses a query that does not start, exits nonzero or prints an empty first
  line, each with its own reason (`TwoEngineRefusal::Version`). `run_engine` returns an `EngineRun` (status and
  stdout); `TwoEngineRun` adds `version()`, `status()`, `stdout()`. New `tools/src/receipt.rs`: `render` (schema
  `wc-005.run-receipt/v1`) and `write_receipt` (through `bundle::write_new_file`, refusal unchanged). Real receipt on
  this Mac: `bundle: lab-cid:sha256:9ca715378b264e54614d2a231ee4d8e58e6a145873c55291fd02066aaf57f930`, `function:
  digest`, `argument: 1592590337`, `wasmtime_version: "wasmtime 45.0.1 (83166ba31 2026-06-05)"`, `wasmer_version:
  "wasmer 7.5.0"`, both `exit status: 0`, both stdouts `"230101071268130872\n"`. Claim scope unchanged from 015 (one
  core module, this Mac, both engines test-only, neither endorsed, not the Component ABI). Five new tests in
  `tests/run.rs`; 015's stand-ins answer `--version` apart from the module run, and the missing-program case moved
  to `version_query_failures_keep_their_cause`. 20 new falsifiers, four re-anchored. Canonical runner,
  `python3 -I examples/agent-host/falsify.py --from lab/wasm-capsule/falsifiers.json F-WC5`: "summary: 52 CAUGHT of
  52", exit 0, no backup left (runner-caught; baseline: 22 named tests pass without an edit). Both retired-label
  merge-gate greps: empty, exit 1. `run.rs` and `receipt.rs` are not recovery targets (R2).
- Task 018: new test `lane_files_reads_names_git_would_quote` in `tests/lab_cid.rs` (017's PASS FOLLOWUP). It runs
  `git init -q` in a `TempDir`, writes untracked `plain.md` and `review"note.md`, and asserts the existing
  `lane_files` returns both under their real names with their text; `lane_files` and the guard test are unchanged.
  `cargo test --locked --test lab_cid`: 4 passed. Hand falsifier (hand-proven, pending R2; not in runner-caught
  totals): drop `"-z",` and read with `.lines()` → the new test alone fails, 3 passed 1 failed, panic "assertion
  `left == right` failed: lane_files did not list every file under its real name / left: [("plain.md", "plain
  text\n")] / right: [("plain.md", "plain text\n"), ("review\"note.md", "quoted text\n")]"; reverted → passes.
  `git hash-object tests/lab_cid.rs` before the break and after the revert: `846d89a8f2ae8a2f5dfd7698df46370ceec903fa`
  both times. No `falsifiers.json` entry: `tests/lab_cid.rs` is not a runner recovery target (R2).
- Task 019: new test `run_engine_starts_its_engine_exactly_once` (`tests/run.rs`, 014's PASS FOLLOWUP): counting
  stand-ins append one line per start to `"$0.starts"` (no environment); one `run_engine` call per engine records
  exactly one module run and no `--version`, and one `run` call exactly one module run per engine (two in all) plus,
  counted apart, one `--version` each. New `tests/docs.rs`, `readme_falsifier_total_matches_falsifiers_json`: the
  README's "`falsifiers.json` holds N planted bugs" sentence, found exactly once, must equal the file's entry count.
  README "## Falsifiers" summary rewritten: 122 entries (120 at base `e8d1642b4` plus this task's two), per-task counts
  (wc-005a is 23, not 20; a wc-001 section added), runner-caught 58 apart from hand-proven 64, R1 done, and only
  `tools/src/run.rs` and `tools/src/receipt.rs` named as unrecovered (R2); no falsifier relabelled. No change to
  `tools/`, `Cargo.toml` or `Cargo.lock`. Falsifiers F-WC5-START-TWICE and F-WC-README-COUNT, canonical runner,
  `python3 -I examples/agent-host/falsify.py --from lab/wasm-capsule/falsifiers.json F-WC5-START-TWICE
  F-WC-README-COUNT`: "baseline: 2 named tests pass without an edit, 0 do not", "summary: 2 CAUGHT of 2"
  (runner-caught). By hand: "wasmtime: one run_engine call started the engine 2 times" (left 2, right 1) and "README
  says falsifiers.json holds 121 planted bugs, but it holds 122"; reverted, `git hash-object` unchanged. Both
  retired-label merge-gate greps (`git grep -n` on the lane, `grep -rn --exclude-dir=target` on the lane): empty,
  exit 1.
