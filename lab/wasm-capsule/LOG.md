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
- Task 024: adopt cc-capsule-identity 018's lab CID (the 59-character CIDv1 SHA-256 UnixFS directory root,
  `bafybei...`). Base `352e8de07`: `cargo test --locked --no-fail-fast` failed 4 tests, all lab CID form or pin:
  `tests/bundle.rs:224` and `:520`, `tests/lab_cid.rs:78`, `tests/run.rs:1402` (each `left` a `bafybei...` value).
  The outside recomputation, written from `lab/capsule-identity/README.md` ("The encoding") only, standard library
  only, kept at `target/recompute-024/outside_cid.py` and never committed:
  ```python
  """Print a bundle folder's lab CID, from cc-capsule-identity's README rules.

  Usage: python3 -I outside_cid.py BUNDLE_DIR
  Standard library only. Written from lab/capsule-identity/README.md,
  "## The encoding"; never from that lane's Rust code.
  """
  import hashlib
  import os
  import stat
  import sys

  CHUNK_LIMIT = 262144
  ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"


  def uvarint(value):
      out = bytearray()
      while value >= 0x80:
          out.append((value & 0x7F) | 0x80)
          value >>= 7
      out.append(value)
      return bytes(out)


  def pb_bytes(number, payload):
      return bytes([(number << 3) | 2]) + uvarint(len(payload)) + payload


  def block_cid(codec, block):
      return bytes([0x01, codec, 0x12, 0x20]) + hashlib.sha256(block).digest()


  def dir_node(children):
      links = b""
      tsize_sum = 0
      for name in sorted(children, key=lambda part: part.encode("utf-8")):
          child = children[name]
          if isinstance(child, dict):
              child_cid, child_tsize = dir_node(child)
          else:
              if len(child) > CHUNK_LIMIT:
                  sys.exit(f"refused: {name} is {len(child)} bytes, over {CHUNK_LIMIT}")
              child_cid, child_tsize = block_cid(0x55, child), len(child)
          link = pb_bytes(1, child_cid) + pb_bytes(2, name.encode("utf-8"))
          link += b"\x18" + uvarint(child_tsize)
          links += pb_bytes(2, link)
          tsize_sum += child_tsize
      block = links + pb_bytes(1, b"\x08\x01")
      if len(block) > CHUNK_LIMIT:
          sys.exit("refused: a directory block is over the limit")
      return block_cid(0x70, block), len(block) + tsize_sum


  def collect_files(root):
      tree = {}
      for parent, folders, files in os.walk(root):
          folders.sort()
          for name in folders + files:
              mode = os.lstat(os.path.join(parent, name)).st_mode
              if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                  sys.exit(f"refused: {name} is not a regular file or folder")
          rel = os.path.relpath(parent, root)
          node = tree
          if rel != ".":
              for part in rel.split(os.sep):
                  node = node.setdefault(part, {})
          for name in files:
              with open(os.path.join(parent, name), "rb") as handle:
                  node[name] = handle.read()
      return tree


  def base32_print(raw):
      bits = "".join(f"{byte:08b}" for byte in raw)
      bits += "0" * (-len(bits) % 5)
      return "b" + "".join(ALPHABET[int(bits[i:i + 5], 2)] for i in range(0, len(bits), 5))


  def main():
      root_cid, _ = dir_node(collect_files(sys.argv[1]))
      print(base32_print(root_cid))


  main()
  ```
  Checks before trusting it (from the repo root; S = `lab/wasm-capsule/target/recompute-024/outside_cid.py`):
  (a) `python3 -I $S lab/capsule-identity/fixtures/content-sample` printed
  `bafybeieahlroxjdalpmglh227eikmodrjhrlelvzlhylvyt3s65ackiybi`, that lane's committed pin; (b) a copy at
  `lab/wasm-capsule/target/recompute-024/content-sample-changed` with byte 1 of `sample.example` changed (`cmp -l`:
  `1 145 130`), `python3 -I $S lab/wasm-capsule/target/recompute-024/content-sample-changed` printed
  `bafybeihe2nuwvsnlpuwclyyvcxa6b254k6azmm7t3vixhodnpb5m365gva`, a different value. Bundle (i), from
  `lab/wasm-capsule/`: `target/recompute-024/module-bundle/` = `capsule/capsule.json` + the 8 bytes `00 61 73 6d 01
  00 00 00` as `capsule.wasm`; `python3 -I target/recompute-024/outside_cid.py target/recompute-024/module-bundle`
  printed `bafybeihtyzfql54i7irft23lg2mk44toqdww53ryuhs2psrknfjw4qhpcy`, and `tools/bundle --name
  target/recompute-024/module-bundle` (`bundle_identity`) printed the same. Bundle (ii): `tools/bundle
  target/recompute-024/reference-out` built and printed `bafybeib34owcqffbwkntlhvbjngcj7eyeqqxx7aoefehqt2dqm2yu5jwse`;
  `shasum -a 256` of its `bundle/capsule.wasm` is `6dd9af1a8d33d14f48514611663e3f5b262f91ef2729de4ec851441af9b22b13`
  (= `PINNED_ARTIFACT_SHA256`); the script on `target/recompute-024/reference-out/bundle` and `tools/bundle --name`
  on it both printed `bafybeib34owcqffbwkntlhvbjngcj7eyeqqxx7aoefehqt2dqm2yu5jwse`. Both agree, so both became pins
  (no mismatch finding). One module-bundle pin, `MODULE_BUNDLE_LAB_CID` in `tests/common/mod.rs`, used by
  `this_capsule_bundle_has_the_pinned_lab_cid` and `tools_bundle_name_mode_prints_the_lab_cid` (the copies in
  `tests/lab_cid.rs` and `tests/bundle.rs` removed); `REFERENCE_LAB_CID` holds bundle (ii)'s value.
  `receipt_records_observed_engine_versions` now parses the printed name with `capsule_identity::LabCid`'s `FromStr`
  and asserts it prints back the same string, in place of a hand prefix check. README ("The lab name",
  "tools/bundle", the receipt example) and ADOPTION (claim scope, the identity decision, proposal 1 and 2) describe
  the new form and pins; no UnixFS code in the lane. No change to `tools/`, `capsule/`, `Cargo.toml`, `Cargo.lock`
  or `falsifiers.json` (no new entry). Canonical runner, from the repo root, `python3 -I examples/agent-host/falsify.py
  --from lab/wasm-capsule/falsifiers.json F-WC3-LABCID-PIN F-WC5-RECEIPT-CID F-WC3-RETIRED-LABEL-DOC F-WC4g
  F-WC-README-COUNT` (the last three are anchored in files this task edits; each anchor found exactly once):
  "baseline: 5 named tests pass without an edit, 0 do not", "summary: 5 CAUGHT of 5", exit 0 (runner-caught). By
  hand (hand-proven, pending R1; not in runner-caught totals): the last character of `MODULE_BUNDLE_LAB_CID` `y` →
  `z`; `this_capsule_bundle_has_the_pinned_lab_cid` failed at `tests/lab_cid.rs:74` and
  `tools_bundle_name_mode_prints_the_lab_cid` at `tests/bundle.rs:223`, each "assertion `left == right` failed",
  left `...qhpcy`, right `...qhpcz`; restored from a copy, `git diff --no-index --exit-code` against that copy: exit
  0. `cargo test --locked` and both fmt checks green. Retired-label greps: both empty, exit 1.
- Task 020 (wc-009a, granted imports only, checked before any engine starts): `read_grants(path)` in
  `tools/src/verify.rs` is the one lab grants reader (JSON `wc-009.lab-grants/v1`, label exactly "lab stand-in, not
  admission"; one `fs::read`, one `serde_json::from_slice` into `Value`, checked by hand; ten refusals with their own
  text). `VerifiedBundle` gains `unused_grants()`, worked out once from the audit's list; `RunInput` gains `granted`,
  which `run` passes unchanged to its one `verify_bundle` call; `TwoEngineRun` gains `linked()` and
  `unused_grants()`. `IMPORTING_MODULE` and `env_f()` moved from `tests/verify.rs` into `tests/common/grants.rs`
  with the grants-file writer, so both test files share one copy. New tests: `grants_file_refusals_keep_their_reason`,
  `unused_grants_excludes_linked_and_preserves_file_order` (`tests/verify.rs`); `zero_grants_zero_imports_runs`,
  `zero_grants_zero_imports_runs_on_both_real_engines`, `declared_not_granted_import_refuses_instantiation_by_name`,
  `valid_signature_with_empty_grants_file_links_nothing`,
  `grant_for_an_import_the_module_does_not_have_links_nothing_and_is_reported`, `granted_import_is_linked`
  (`tests/run.rs`; one `--version` and one module start per engine on success, zero of both on refusal). Guards
  updated: `verifier_reads_no_bundle_file_by_path`, `verifier_has_one_check_path`, `verified_bundle_is_sealed`,
  `runner_uses_only_explicit_inputs`. 17 new falsifiers (F-WC9-*), all anchored in `tools/src/verify.rs`; F-WC5a,
  F-WC5-VERIFY-TWICE, F-WC5-QUERY-BEFORE-VERIFY and F-WC4-SEALED-NEW re-anchored; README total 139. Canonical runner,
  `python3 -I examples/agent-host/falsify.py --from lab/wasm-capsule/falsifiers.json F-WC9 F-WC4 F-WC5
  F-WC-README-COUNT`: "baseline: 44 named tests pass without an edit, 0 do not", "summary: 1 BUILD FAILED, 93 CAUGHT
  of 94" (F-WC5a's mutant no longer built: it removes the verified value that the new `linked` line reads). F-WC5a
  got a fourth edit (fill both lists empty), then `... --from lab/wasm-capsule/falsifiers.json F-WC5a`: "summary: 1
  CAUGHT of 1" (runner-caught). Hand-proven, pending R1 (not in `falsifiers.json`, since `tools/src/run.rs` is not a
  recovery target, R2; outside every count): `input.granted` → `&[]` in `run`'s verify call made
  `runner_uses_only_explicit_inputs` fail ("the runner does not verify its own inputs with the caller's grants",
  left 0) and `granted_import_is_linked` fail ("the two-engine runner refused: undeclared import env.f"); reverted,
  `git hash-object tools/src/run.rs` `4a381399d05c4fcb070c7815e666d1dc995a8f4d` before and after. No change to
  `tools/Cargo.toml` or `Cargo.lock`. Both retired-label merge-gate greps (`git grep -n` on the lane, `grep -rn
  --exclude-dir=target` on the lane): empty, exit 1.
- Task 025 (carry of wc-009a onto the UnixFS lab CID base): task 020's lane changes, commit `5f3d23418` (base
  `36fa6d89c`), applied on a base with 024. Identical to `5f3d23418` (blob ids equal): `tools/src/run.rs`,
  `tests/common/grants.rs`, `tests/verify.rs`, `falsifiers.json`. Merged with 024's changes, nothing of 020 dropped:
  `tests/run.rs` (024's `LabCid` import and parse check kept beside 020's imports and tests), `tests/common/mod.rs`
  (024's `MODULE_BUNDLE_LAB_CID` kept beside 020's `pub mod grants`), `README.md` and `ADOPTION.md` (024's lab CID
  text and pins kept; each differs from `5f3d23418` by exactly 024's own change), `LOG.md` (020's entry above,
  verbatim, after 024's). `tools/src/verify.rs` differs from `5f3d23418` only by 020's review follow-up (Codex,
  round 1 PASS): its module doc now says the verifier "reads no bundle file by path", and that the one file it reads
  by a path is the lab grants file. Canonical runner, from the repo root, `python3 -I examples/agent-host/falsify.py
  --from lab/wasm-capsule/falsifiers.json F-WC9 F-WC5a F-WC5-VERIFY-TWICE F-WC5-QUERY-BEFORE-VERIFY
  F-WC-README-COUNT` (each `old` anchor of all 139 entries found exactly once on this base): "baseline: 9 named
  tests pass without an edit, 0 do not", "summary: 21 CAUGHT of 21", exit 0 (runner-caught). No change to
  `tools/Cargo.toml`, `Cargo.toml` or `Cargo.lock`. `cargo test --locked` and both fmt checks green. Retired-label
  greps: both empty, exit 1.
- Task 021 (wc-010a, memory cap discovery, read-only): README "## Memory cap discovery (wc-010a)" records, at base
  `a5b4e8a105fca181469ce15b2b84c03b86f0266d`, `wasmtime 45.0.1 (83166ba31 2026-06-05)` and `wasmer 7.5.0` (each from
  `--version`, absolute Homebrew paths, each its own process). Declared size: `manifest.rs:102-103` (`resources`
  defaults), `:1167-1169` (`memory_mb: u32`, `default = "default_memory"`), `:1188-1190` (`64`); `capsule.json` has
  no `resources` key, so 64 MB, read as 67108864 bytes = 1024 pages. wasmtime FOUND: `-W max-memory-size=N` (bytes,
  `wasmtime -W help`); with it a grow to 1024 pages returned `1` (exit 0), a grow to 1025 pages returned `-1` (exit 0),
  with `trap-on-grow-failure=y` added it trapped (exit 1, "forcing trap when growing memory to 67174400 bytes"), and
  without the flag the same grow returned `1` (exit 0); a module with minimum 1025 pages was refused at start (exit
  1, "memory minimum size of 1025 pages exceeds memory limits"). wasmer SKIPPED: `wasmer run --help` and `wasmer
  --help` have no memory cap flag (words searched in README); without one, the grow past 64 MB returned `1` (exit
  0) and the 1025-page minimum started (exit 0, `1025`). Answer for wc-010b: wasmtime "grow returns -1" ("trap" with
  `-W trap-on-grow-failure=y`; above-cap minimum "start refused"), wasmer "SKIPPED"; the engines differ, so not
  "traps on both". `/usr/bin/time -l` prints "maximum resident set size" (engine process resident memory, not linear
  memory): 14696448 for wasmtime, 19218432 for wasmer. Probe `.wat` files only under git-ignored `target/wc010a/`;
  both engines took `.wat` directly. No rule, so no falsifier; the with/without-flag runs are the evidence. Only
  `README.md` and `LOG.md` changed. `cargo test --locked` (81 passed, 1 ignored, 0 failed) and both fmt checks
  green. Retired-label greps (`git grep -n 'lab-''sha256' -- lab/wasm-capsule/` and `grep -rn --exclude-dir=target
  'lab-''sha256' lab/wasm-capsule/`): both empty, exit 1.
- Task 022 (wc-009b0, granted import hosting discovery, read-only): README "## Granted import hosting discovery
  (wc-009b0)" records, at base `3a4d2812aa71fce5a92e6bf7b314aee9844c7293` with `wasmtime 45.0.1 (83166ba31
  2026-06-05)` and `wasmer 7.5.0` (each engine's `--version`), whether each CLI supplies `env.f` from a second
  module file. Probes in the runner's shape (`env -i`, stdin `/dev/null`, `run --invoke digest <abs module>
  1592590337` plus the flag under test). wasmtime FOUND: `--preload <NAME=MODULE_PATH>` ("Load the given
  WebAssembly module before the main module", `wasmtime run --help`); (i) `--preload env=host.wat` printed
  `1592590338` (exit 0); (ii) no flag: exit 1, "unknown import: `env::f` has not been defined"; (iii) `other=`: the
  same as (ii); (iv) `env=host-wasi.wat` printed `1592590338` (exit 0): wasmtime linked the supplied module's
  `wasi_snapshot_preview1` import with no WASI flag, and a non-WASI unknown import in the supplied module was
  refused ("failed to process preload `env`", "`nope::g` has not been defined"). The real capsule (sha256
  `6dd9af1a...`) printed `230101071268130872` with and without `--preload env=host.wat`. wasmer SKIPPED: no such flag
  in `wasmer run --help` or `wasmer --help` (words in README); `--use host.wat --offline` gave the (ii) refusal
  ("Error while importing \"env\".\"f\": unknown import"), `--enable-module-linking` "No backends support the
  required features". Answer for wc-009b: wasmtime hosts by flag `--preload env=<path>`, wasmer SKIPPED; the
  engines differ, so "same results on both engines" cannot be tested for a hosted granted import (both only refuse
  an unsupplied `env.f`, naming it). Probe `.wat` files only under git-ignored `target/wc009b0/`; both engines took
  `.wat` directly. No rule, so no falsifier; the with/without-flag runs are the evidence. Only `README.md` and
  `LOG.md` changed. Gates: `cargo test --locked` and both fmt checks green; both retired-label greps empty, exit 1.
- Task 023 (falsifier list intro leaves evidence labels to README), at base `6333a87dde2326dcd80f2837f6228b497c96f959`:
  `falsifiers.json`'s `"about"` loses its evidence sentence ("The canonical runner falsify.py now has ... until R1
  lands.") and the aside "(R1 is done: the canonical runner's lab command runs these)"; in their place one sentence
  says each entry's evidence label and the count of each kind are kept in README.md "## Falsifiers". Every entry is
  unchanged (parsed `"falsifiers"` list equal to the base's; the diff touches only line 2). New test
  `falsifiers_about_states_no_evidence_status` (`tests/docs.rs`, through `lane_file` and `serde_json`) fails naming
  any whole word `pending`, `hand-proven`, `runner-caught`, `R1` or `R2` (case ignored) in `"about"`, and fails
  with its own reason if `"about"` lacks `README.md` or `## Falsifiers`. README "## Falsifiers" gets one sentence
  naming it the one place for evidence labels and counts. Eight falsifiers, each hand-proven (`falsifiers.json` is
  the runner's own input and not a recovery target, so no entry and outside README's counts; the total stays 139):
  each planted with a one-match `python3 -I` replace, then `cargo test --locked --test docs
  falsifiers_about_states_no_evidence_status` FAILED, then reverted and `shasum -a 256 falsifiers.json` equal to the
  fixed file's `96b62630a50c86868cafe0fea44027095b07b57e29ed0ff5d3d4b0d4a0bed68d`. Base sentence "(ask R1, pending),
  so these are hand-proven, pending R1" put back → `tests/docs.rs:66:5` `falsifiers.json "about" states evidence
  status, which README.md "## Falsifiers" alone holds: found ["pending", "hand-proven", "R1"]`; " These are
  pending." → `found ["pending"]`; " These are hand-proven." → `found ["hand-proven"]`; " These are runner-caught." →
  `found ["runner-caught"]`; " (ask R1)" → `found ["R1"]`; " (ask R2)" → `found ["R2"]` (all at `:66:5`);
  `README.md` → `README` → `tests/docs.rs:71:5` `falsifiers.json "about" does not name README.md as the place for
  evidence labels`; `"## Falsifiers"` dropped → `tests/docs.rs:75:5` `falsifiers.json "about" does not name the README
  section "## Falsifiers"`. Gates: `cargo test --locked` (82 passed, 1 ignored, 0 failed) and both fmt checks green;
  retired-label greps: both empty, exit 1.
- Task 026 (Rong's two rulings, 26 Oct), at base `33cbed8c5c385ae7e94f603527757eb896166b42`. One exact engine
  sentence ("Both engines, wasmtime and wasmer, are test-only and not endorsed. The engine choice is Anders's.") once
  in README's "## Layout" (the first section that names both engines) and once in ADOPTION; README's three other
  wordings, ADOPTION's two and both `tools/src/run.rs` doc comments now say "not endorsed" (run.rs: comments only,
  "test-only, not endorsed"). One exact discovery-only sentence (Discovery only: no engine-specific host-function
  route ... (P10, P18).) in README's 022 section before its first per-engine answer line, and once on one line in
  ADOPTION (new paragraph "Hosting discovery (wc-009b0, task 022)"). New tests in `tests/docs.rs`, through
  `lane_file`: `engines_are_labelled_test_only_not_endorsed` and `hosting_discovery_is_not_the_import_path`. 022's
  two FOLLOWUPs: both run tables now give each complete command as run (`env -i`, the absolute engine path, every
  argument in order, `< /dev/null`, `<D>` kept). 022 recorded flags only, not their place in argv, so each flag sits
  after `run` and before `--invoke` (wasmtime reads anything after the module path as guest arguments). Each of the
  eight rows was re-run once with exactly its written command (WAT re-made from README's text under git-ignored
  `target/wc009b0/`): exits and stdouts equal to 022's (wasmtime (i) 0 `1592590338`, (ii) 1, (iii) 1, (iv) 0
  `1592590338`, (iv-c) 1; wasmer (ii) 1, `--use` 1, `--enable-module-linking` 1; all failing stdouts empty), and a
  `diff` of full stderr confirmed (iii) = (ii) and `--use` = (ii) word for word. No STOP; no finding changed.
  README:938's conclusion narrowed to "this capsule's output for `1592590337` was unchanged; this one comparison says
  nothing about any other effect of a preloaded module" (the old phrase's grep: empty, exit 1). Seven new runner
  entries, all anchored in `README.md`, plus F-WC-README-COUNT re-anchored to 146: canonical runner, from the repo
  root, `python3 -I examples/agent-host/falsify.py --from lab/wasm-capsule/falsifiers.json F-WC-ENGINE-ENDORSED
  F-WC-ENGINE-MOVED F-WC-ENGINE-TWICE F-WC-ENDORSE-LINE F-WC9B0-IMPORT-PATH F-WC9B0-AFTER-ANSWERS F-WC9B0-TWICE
  F-WC-README-COUNT`: "baseline: 3 named tests pass without an edit, 0 do not", "summary: 8 CAUGHT of 8", exit 0
  (runner-caught; all 146 entries' anchors found exactly once). Each assertion, quoted by running the named test
  inside the runner's own `falsify.Mutation`: ENGINE-ENDORSED `tests/docs.rs:152:9` "README.md holds the engine
  ruling 0 times, not once"; ENGINE-MOVED `:166:5` "README.md's engine ruling is not in "## Layout", the first
  section that names wasmtime and wasmer"; ENGINE-TWICE `:152:9` "... 2 times, not once"; ENDORSE-LINE `:189:5` "a
  line mentions endorsement without "not endorsed": [README.md:555: ...]"; F-WC9B0-IMPORT-PATH `:199:5` "README.md
  holds the discovery ruling 0 times, not once"; AFTER-ANSWERS `:222:5` "README.md's discovery ruling comes after
  the first per-engine answer line of ...: "### wasmtime 45.0.1: FOUND, ..."" ; F-WC9B0-TWICE `:199:5` "... 2 times,
  not once". Five more, each hand-proven, pending R1 (`ADOPTION.md` and `tools/src/run.rs` are not recovery
  targets: no `falsifiers.json` entry, outside README's counts), planted with the same `falsify.Mutation` and one
  exact replace, named test FAILED, then restored (`shasum -a 256` before = after: ADOPTION `f3728967...cd13d3f`,
  run.rs `4ba2fbb8...cd46c8`): F-WC-ENGINE-ADOPTION (ruling removed) `:152:9` "ADOPTION.md holds the engine ruling 0
  times, not once"; F-WC-ENDORSE-ADOPTION (base claim-scope wording back) `:189:5` "[ADOPTION.md:134: ...]";
  F-WC-ENGINE-RUN-MODULE-DOC `:173:5` "tools/src/run.rs's module doc has no line saying "test-only, not endorsed"";
  F-WC-ENGINE-RUN-ENUM-DOC `:178:5` "... doc comment on `pub enum Engine` does not say ..."; F-WC9B0-ADOPTION
  (ruling removed) `:229:5` "ADOPTION.md holds the discovery ruling on one line 0 times, not once". No change to
  `tools/Cargo.toml`, `Cargo.toml` or `Cargo.lock`. Gates: `cargo test --locked` (84 passed, 1 ignored, 0 failed)
  and both fmt checks green; retired-label greps: both empty, exit 1.
- 26 Oct, task 027 (wc-010b, base `f92fe85970ad0898be4f5247cf580b1f5eaf4bda`): the declared memory cap on wasmtime.
  `VerifiedBundle` keeps the manifest's `resources.memory_mb` from the verifier's one `CapsuleManifest` parse
  (`manifest_entrypoint` now returns the entrypoint and `memory_mb`; one new accessor `memory_mb()`). The runner
  (`tools/src/run.rs`) gives wasmtime's module run one more pair, `-W` and
  `max-memory-size=<memory_mb × 1048576>,trap-on-grow-failure=y` (u64, MB read as 2^20 bytes), on a new line between
  `.args(["run", ...])` and `.arg(module)`; wasmer's argv and both `--version` queries are unchanged. Hand check of
  that order first, from git-ignored `target/wc010b/` with 021's `grow.wat`:
  `/opt/homebrew/bin/wasmtime run --invoke grow -W max-memory-size=67108864,trap-on-grow-failure=y grow.wat 1024`
  exit 1, stdout empty, stderr the `--invoke` takes-arguments warning, then "Error: failed to run main module
  `grow.wat`", "0: failed to invoke `grow`", "1: error while executing at wasm backtrace: 0: 0x33 - <unknown>!<wasm
  function 0>", "2: forcing trap when growing memory to 67174400 bytes"; the same with `1023` exit 0, stdout `1`,
  stderr the two `--invoke` warnings. wasmtime accepts that order, so no anchored line moved. New tests (README
  "Named tests"): `declared_memory_cap_comes_from_the_manifest` (2 MB → `max-memory-size=2097152`, `u32::MAX` →
  `4503599626321920`), `capsule_grows_within_the_declared_cap_on_wasmtime`,
  `memory_grow_past_the_declared_cap_traps_on_wasmtime`, `built_capsule_runs_under_the_declared_cap_on_wasmtime`
  (a recording shell that `exec`s the real wasmtime shows the cap on its argv) and the `#[ignore]` SKIP
  `memory_cap_on_wasmer_is_skipped`; the grow modules are hand-written bytes. Updated: the argv test (new wasmtime
  argv; the module is the second-to-last argument), `verified_bundle_is_sealed` (the new field and accessor), and
  the three stand-ins that read the module as `$4` (now the second-to-last argument; no byte assertion changed).
  Six new entries and seven re-anchored, all anchored in `tools/src/run.rs`, `tools/src/verify.rs` or `README.md`
  (all recovery targets on this base): canonical runner, from the repo root, `python3 -I
  examples/agent-host/falsify.py --from lab/wasm-capsule/falsifiers.json F-WC10-CAP-IGNORED F-WC10-CAP-FIXED
  F-WC10-NO-TRAP F-WC10-CAP-OVERFLOW F-WC10-CAP-NOT-READ F-WC10-WASMER-FLAG F-WC5-START-TWICE F-WC5a
  F-WC5-BYPASS-RUN-ENGINE F-WC4-ORDER-AUDIT-FIRST F-WC4-ENTRYPOINT-REPARSE F-WC4-SEALED-NEW F-WC-README-COUNT`:
  "baseline: 11 named tests pass without an edit, 0 do not", "summary: 13 CAUGHT of 13", exit 0 (the six new ones
  runner-caught; all 152 entries' anchors found exactly once). Because `run.rs` and `verify.rs` changed, every other
  entry anchored there was re-run too (76 ids): 73 CAUGHT and 3 BUILD FAILED (F-WC4-ENTRYPOINT-REPARSE, F-WC5a,
  F-WC5-BYPASS-RUN-ENGINE, whose planted code used the old signatures); those three were re-anchored, same bug, and
  are in the 13 above. No hand-proven entry was added. No change to `tools/Cargo.toml`, `Cargo.toml`, `Cargo.lock`,
  `capsule.json`, `capsule/` or the lab CID pins. Gates: `cargo test --locked` (88 passed, 2 ignored, 0 failed) and
  both fmt checks green; retired-label greps: both empty, exit 1.
