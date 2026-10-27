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
- 26 Oct, task 027 round 2 (Codex FAIL, fail-closed): `max-memory-size` caps each linear memory on its own, and the
  verifier's import audit accepts a module with two memories, so a capsule declaring 2 MB with two 2 MB memories got
  4 MB. `tools/src/run.rs` `memory_cap_args` now gives wasmtime `-W
  max-memory-size=<bytes>,max-memories=1,trap-on-grow-failure=y` (still one pair; wasmer and `--version` unchanged).
  Hand check from git-ignored `target/wc010b-r2/`: the two-memory module (`(memory 32) (memory 32)`, `digest` returns
  `memory.size 0 + memory.size 1`) under `-W max-memory-size=2097152,trap-on-grow-failure=y` exit 0, stdout `64`;
  with `max-memories=1` added exit 1, stderr "0: failed to instantiate", "1: resource limit exceeded: memory count
  too high at 2"; 021's `grow.wat` with `max-memories=1` added: `1024` exit 1 with the same 67174400-byte trap line,
  `1023` exit 0, stdout `1`. New test `second_memory_cannot_double_the_declared_cap_on_wasmtime` (hand-written bytes,
  signed and verified bundle declaring `"memory_mb": 2`, `EngineFailed` with the count line); the three exact
  wasmtime argv strings now carry `max-memories=1`; helper `verified_bundle_declaring` shared with
  `declared_memory_cap_comes_from_the_manifest` (no assertion changed). New falsifier F-WC10-TWO-MEMORIES;
  F-WC10-NO-TRAP re-anchored to the new format line (same bug); F-WC10-CAP-IGNORED also names the new test;
  F-WC-README-COUNT re-anchored to 153. Canonical runner, from the repo root, `python3 -I examples/agent-host/falsify.py
  --from lab/wasm-capsule/falsifiers.json F-WC10-TWO-MEMORIES F-WC10-NO-TRAP F-WC10-CAP-IGNORED F-WC10-CAP-FIXED
  F-WC10-CAP-OVERFLOW F-WC10-WASMER-FLAG F-WC-README-COUNT`: "baseline: 5 named tests pass without an edit, 0 do
  not", "summary: 7 CAUGHT of 7", exit 0 (runner-caught; all 153 anchors found exactly once). Gates: `cargo test
  --locked` (89 passed, 2 ignored, 0 failed) and both fmt checks green; retired-label greps: both empty, exit 1.
- 26 Oct, task 028 (wc-010c): the run receipt records the declared memory cap per engine. `tools/src/run.rs`:
  `EngineRun` gains `memory_mb` and `memory_cap`; `start_engine` keeps its argv line for line and, after the run,
  reads the cap back from that process's own argv with `memory_cap_given` (the argument after `-W`, else none), so
  the receipt cannot say ENFORCED for an argv without the cap; `TwoEngineRun` gains `memory_mb()`,
  `memory_cap_bytes()` (the one `memory_cap_bytes` conversion, no second MB to bytes rule, no second manifest read)
  and `memory_cap(engine)`. `tools/src/receipt.rs`: `RECEIPT_SCHEMA` is `wc-005.run-receipt/v2`; after the v1 lines
  (every anchored line unchanged) `render` adds `memory_mb`, `memory_cap_bytes`, then `wasmtime_memory_cap` and
  `wasmer_memory_cap` from `memory_cap_line` (ENFORCED with the recorded argument exactly, or SKIPPED with wc-010a's
  reason). Real receipt on this Mac: `memory_mb: 64`, `memory_cap_bytes: 67108864`, `wasmtime_memory_cap: ENFORCED
  max-memory-size=67108864,max-memories=1,trap-on-grow-failure=y`, `wasmer_memory_cap: SKIPPED: no memory cap flag
  in wasmer run --help or wasmer --help (wc-010a)`. No peak memory line (waits for Flint). `tests/run.rs`: new
  `receipt_records_the_declared_memory_cap` and `receipt_cap_line_matches_the_argv_the_engine_got`;
  `receipt_records_observed_engine_versions` and `real_receipt_names_both_installed_engines` updated to v2;
  `recording` also writes each module run's argv to `<name>.argv` (its order log unchanged); 027's
  `verified_bundle_declaring` now calls the new `signed_bundle_declaring` (no assertion changed). New falsifiers
  F-WC10C-WASMER-ENFORCED and F-WC10C-CAP-FIXED; F-WC10-CAP-IGNORED also names the argv test; F-WC-README-COUNT
  re-anchored to 155. Canonical runner, from the repo root, `python3 -I examples/agent-host/falsify.py --from
  lab/wasm-capsule/falsifiers.json F-WC10C-WASMER-ENFORCED F-WC10C-CAP-FIXED F-WC10-CAP-IGNORED F-WC-README-COUNT`:
  "baseline: 7 named tests pass without an edit, 0 do not", "summary: 4 CAUGHT of 4", exit 0 (runner-caught).
  Because `run.rs` and `receipt.rs` changed, the other 58 entries anchored there were re-run: "baseline: 26 named
  tests pass without an edit, 0 do not", "summary: 58 CAUGHT of 58", exit 0. No hand-proven entry was added. No
  change to `tools/Cargo.toml`, `Cargo.toml`, `Cargo.lock`, `capsule.json`, `capsule/` or the lab CID pins.
  Gates: `cargo test --locked` (91 passed, 2 ignored, 0 failed) and both fmt checks green; retired-label greps: both
  empty, exit 1.
- 27 Oct, task 029: runner entries for the two bugs R2 held back (provider 026, PR #242, made `tests/lab_cid.rs` and
  `tools/src/run.rs` recovery targets). `falsifiers.json` gains F-WC3-LANE-FILES-QUOTED (task 018's bug: `lane_files`
  drops `"-z",` and splits by `lines()`; named test `lane_files_reads_names_git_would_quote`) and
  F-WC9-RUN-DROPS-GRANTS (task 020's bug: `run` passes `&[]` in place of `input.granted` to `verify_bundle`; named
  tests `runner_uses_only_explicit_inputs` and `granted_import_is_linked`); F-WC-README-COUNT re-anchored to 157; one
  `"about"` sentence for task 029. README: task 018's note and task 020's passage now say runner-caught under the new
  ids, the totals are 157 (two task 029) and 93 runner-caught, the recovery-target sentence says R2 is done, and a
  task 029 section lists both. No change to `tests/`, `tools/`, `capsule/`, `capsule.wasm`, `Cargo.toml` or
  `Cargo.lock`. Canonical runner, from the repo root, `python3 -I examples/agent-host/falsify.py --from
  lab/wasm-capsule/falsifiers.json F-WC3-LANE-FILES-QUOTED F-WC9-RUN-DROPS-GRANTS F-WC-README-COUNT`: "baseline: 4
  named tests pass without an edit, 0 do not", "summary: 3 CAUGHT of 3", exit 0 (runner-caught), no
  `*.falsify-original` backup left. Gates: `cargo test --locked` (91 passed, 2 ignored, 0 failed) and `cargo fmt
  --check` green. Retired-label greps from the repo root (`git grep -n 'lab-''sha256' -- lab/wasm-capsule/` and
  `grep -rn --exclude-dir=target 'lab-''sha256' lab/wasm-capsule/`): both empty, exit 1.
- 27 Oct, task 030 (wc-010d0): read-only discovery of whether each engine applies a module's own memory maximum with
  no flag, for the C0 refusal (Flint, 26 Oct 23:50). README gets "## Module memory maximum discovery (wc-010d0)"
  after "## Memory cap (wc-010b)"; nothing else changes (no `tests/`, `tools/`, `capsule/`, `falsifiers.json`,
  `Cargo.toml`, `Cargo.lock` or pin edit; no falsifier entry, so README's "## Falsifiers" totals are unchanged). Base
  `a541cd7ba8e656ddc07466b3fc533118c5771ac7`. A previous draft had left files in the git-ignored `target/wc010d/`; its
  removal was refused, so none of it was used and every probe, script and build is new, in `target/wc010d/r1/`.
  Commands, in order, from `lab/wasm-capsule/target/wc010d/r1/` (each module written with the Write tool, text as in
  README): `/opt/homebrew/bin/wasmtime --version` (exit 0, `wasmtime 45.0.1 (83166ba31 2026-06-05)`),
  `/opt/homebrew/bin/wasmer --version` (exit 0, `wasmer 7.5.0`); `/opt/homebrew/bin/wasmtime run --invoke grow
  grow-max.wat 1023` (0, `1`), `... 1024` (0, `-1`), `/opt/homebrew/bin/wasmtime run -W trap-on-grow-failure=y
  --invoke grow grow-max.wat 1023` (0, `1`), `... 1024` (1, "forcing trap when growing memory to 67174400 bytes"),
  `/opt/homebrew/bin/wasmtime run --invoke size bad-max.wat` (1, "size minimum must not be greater than maximum (at
  offset 0x16)"); `/opt/homebrew/bin/wasmer run --invoke grow grow-max.wat 1023` (0, `1`), `... 1024` (0, `-1`),
  `/opt/homebrew/bin/wasmer run --invoke size bad-max.wat` (1, the same validation line); the contrast
  `/opt/homebrew/bin/wasmtime run --invoke grow grow-nomax.wat 1024` (0, `1`) and `/opt/homebrew/bin/wasmer run
  --invoke grow grow-nomax.wat 1024` (0, `1`). From `lab/wasm-capsule/`: `tools/build target/wc010d/r1/today` (exit 0,
  `6dd9af1a8d33d14f48514611663e3f5b262f91ef2729de4ec851441af9b22b13`, the pin); then by hand, twice, with
  `LANE_DIR=$(pwd)`, `SYSROOT=$(rustc --print sysroot)`, `CH=${CARGO_HOME:-$HOME/.cargo}`, `us=$'\x1f'`:
  `SOURCE_DATE_EPOCH=1700000000 CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=$LANE_DIR/target/wc010d/r1/build-<v> RUSTC=rustc
  CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=${LANE_DIR}=/lab/wasm-capsule${us}--remap-path-prefix=${CH}=/cargo${us}--remap-path-prefix=${SYSROOT}=/rustc"
  cargo build --locked --manifest-path $LANE_DIR/Cargo.toml --package capsule --release --target
  wasm32-unknown-unknown`, `<v>` = `control`, and `<v>` = `max` with `${us}-C${us}link-arg=--max-memory=67108864`
  added to the flags; each exit 0, each `capsule.wasm` copied to `target/wc010d/r1/capsule-<v>.wasm`. `rustc
  --version` from the lane root: `rustc 1.91.0 (f8297e351 2025-10-28)`, the receipt's. Cargo reported the control
  build as a cached one (`Finished ... in 0.04s`, no `Compiling` line) and compiled the max build (`Compiling capsule
  v0.1.0`); its intermediate files are not in the scratch dirs (no `deps/`), as for `tools/build`, whose run also
  reported a cached build; no cargo config was read or changed. A third max build into `build-max2` gave the same
  sha256, `2002429e73ee1a5e983df008f5b53728882646f109d55a9d1a93e831690631e1`, but it too was cached, so it shows no
  reproducibility and is not claimed in README. `python3 -I target/wc010d/r1/memsec.py <module>` on
  `today/capsule.wasm` and `capsule-control.wasm` (each `sha256 6dd9af1a…  178 bytes`, `memory 0: minimum 16 pages,
  maximum none`) and `capsule-max.wasm` (`sha256 2002429e…  180 bytes`, `memory 0: minimum 16 pages, maximum 1024
  pages`), each exit 0. `env -i /opt/homebrew/bin/<engine> run --invoke digest <D>/<module> 1592590337 < /dev/null`
  for `wasmtime` and `wasmer` on `capsule-max.wasm` and `today/capsule.wasm`: all four exit 0, stdout
  `230101071268130872` (`FIXED_OUTPUT`); wasmtime's stderr the two `--invoke` warnings, wasmer's empty. The script,
  standard library only, at `target/wc010d/r1/memsec.py`, never committed:
  ```python
  """Print a core Wasm module's memory section and its sha256.

  Usage: python3 -I memsec.py MODULE.wasm
  Standard library only, written from the Wasm core spec's binary format
  (magic and version 1, then sections: id byte, LEB128 size, body; the memory
  section is id 5: a count, then per memory a limits flag byte, 0x00 = minimum
  only, 0x01 = minimum and maximum, each a LEB128 page count). It refuses any
  byte it does not read: a bad header, a truncated number, other limits flags,
  trailing bytes in the memory section, a section past the end.
  """
  import hashlib
  import sys


  def leb(data, pos):
      value = shift = 0
      while True:
          if pos >= len(data):
              sys.exit("refused: truncated LEB128")
          byte = data[pos]
          pos += 1
          value |= (byte & 0x7F) << shift
          shift += 7
          if not byte & 0x80:
              return value, pos


  def memories(data):
      if data[:8] != b"\x00asm\x01\x00\x00\x00":
          sys.exit("refused: not a core Wasm module, version 1")
      pos, found = 8, None
      while pos < len(data):
          section, (size, pos) = data[pos], leb(data, pos + 1)
          end = pos + size
          if end > len(data):
              sys.exit("refused: section runs past the end")
          if section == 5:
              if found is not None:
                  sys.exit("refused: two memory sections")
              count, cur = leb(data, pos)
              found = []
              for index in range(count):
                  flags = data[cur]
                  if flags not in (0x00, 0x01):
                      sys.exit(f"refused: memory {index} limits flags {flags:#04x}")
                  minimum, cur = leb(data, cur + 1)
                  maximum = None
                  if flags == 0x01:
                      maximum, cur = leb(data, cur)
                  found.append((minimum, maximum))
              if cur != end:
                  sys.exit("refused: trailing bytes in the memory section")
          pos = end
      return found


  def main(path):
      data = open(path, "rb").read()
      print(f"sha256 {hashlib.sha256(data).hexdigest()}  {len(data)} bytes")
      found = memories(data)
      if found is None:
          print("no memory section")
          return
      print(f"memory section: {len(found)} memory")
      for index, (minimum, maximum) in enumerate(found):
          shown = "none" if maximum is None else f"{maximum} pages"
          print(f"memory {index}: minimum {minimum} pages, maximum {shown}")


  main(sys.argv[1])
  ```
  The script's own check: its sha256 line for `today/capsule.wasm` equals `tools/build`'s receipt
  (`artifact_sha256`, from `shasum -a 256`), and the added maximum, 1024 as a 2-byte LEB128 (the limits flag byte
  only changes 0x00 to 0x01), is consistent with the 178 → 180 byte growth. Answers (README
  "### The answer for the C0 refusal"): (a) FOUND, (b) FOUND (returns -1, no trap flag), (c) FOUND, (d) NOT FOUND
  (maximum none), (e) FOUND. No engine was missing or failed to start, so nothing is SKIPPED. Gates, with
  `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`: `cargo test --locked` (91 passed, 2 ignored, 0 failed) and `cargo fmt
  --check` green. Retired-label greps from the repo root (`git grep -n 'lab-''sha256' -- lab/wasm-capsule/` and
  `grep -rn --exclude-dir=target 'lab-''sha256' lab/wasm-capsule/`): both empty, exit 1.
- 27 Oct, task 031 (M1 B4 lab half, typed lab operations; base `b75ffefdbe09b3ff1c7328450cb0db8baa0c71f0`):
  `tools/src/verify.rs` gets `pub const LAB_OPERATIONS` (type `LabOperation`: module, name, inputs, outputs, right,
  effect `Effect::None`/`Read`/`Write`), with one entry, `env.f`, inputs and outputs none, right `call`, effect
  `none`. The grants file is now `wc-009.lab-grants/v2`: each grant is exactly `module`, `name` and `right`
  (`EntryNotAPair` became `EntryNotATriple`, reworded for three keys; a v1 file is refused by the schema reason).
  `parse_grants` calls `check_right`, which refuses a grant whose right is not its operation's
  (`RightNotNeeded`: "the grant env.f names the right \"write\", but its typed lab operation needs \"call\""); a
  grant with no typed operation is read. `verify_checked` refuses a module import with no typed operation
  (`VerifyRefusal::UntypedImport`, "no typed lab operation for import env.g"). That check runs on the audit's own
  returned list, right after the one `audit` call, not before it: a check on the granted list before the audit
  would refuse the untyped unused grants of `unused_grants_excludes_linked_and_preserves_file_order` (z.last,
  a.first), and the tools crate may not read the module's imports itself (P10). No engine starts either way.
  Tests: `grant_naming_a_right_the_operation_does_not_need_is_refused` (`tests/verify.rs`),
  `module_import_with_no_typed_operation_is_refused` (`tests/run.rs`, counting stand-ins, zero `--version` and
  zero module starts; `env.g` with no grant is still `undeclared import env.g`), `readme_lists_each_typed_lab_operation`
  (`tests/docs.rs`). `tests/common/grants.rs`: `grants_file` takes (module, name, right), new `importing_env`. The
  wc-009a tests use the v2 form (`env.f` granted `call`); `grants_file_refusals_keep_their_reason` now has 21
  cases (a v1 file, an entry with no right, a number right). README: the wc-009a section shows v2 and the new
  refusals, new "### Typed lab operations (M1 B4 lab half)", the verify section has five checks, the named-test
  lists, totals 159 (two task 031) and 95 runner-caught. ADOPTION: gap 3 for Anders. `falsifiers.json`:
  F-WC-B4-UNTYPED-LINKED, F-WC-B4-RIGHT-IGNORED, F-WC-README-COUNT re-anchored to 159, one `"about"` sentence.
  `readme_lists_each_typed_lab_operation` checked by hand (README's `env.f` effect set to `read`: the test failed
  at its list comparison; reverted, it passed); it is a README guard, with no `falsifiers.json` entry. Canonical
  runner, from the repo root, `python3 -I examples/agent-host/falsify.py --from lab/wasm-capsule/falsifiers.json`
  with the two new ids, all 37 other entries that edit `tools/src/verify.rs` and F-WC-README-COUNT: "baseline: 22
  named tests pass without an edit, 0 do not", "summary: 40 CAUGHT of 40", exit 0, no `*.falsify-original` backup
  left. Gates, with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`: `cargo test --locked` (94 passed, 2 ignored, 0
  failed) and `cargo fmt --check` green. Retired-label greps from the repo root (`git grep -n 'lab-''sha256' --
  lab/wasm-capsule/` and `grep -rn --exclude-dir=target 'lab-''sha256' lab/wasm-capsule/`): both empty, exit 1.
- 27 Oct, task 032 (M1 C0 step ii, the capsule declares its 64 MB memory maximum; base
  `3639b0357f588c74a2a233cf6aa3c1e78bca99a0`, which holds 031): `tools/build` gets one new line after the
  `CARGO_ENCODED_RUSTFLAGS` export, appending `${us}-Clink-arg=--max-memory=67108864`, with a comment (64 = the
  declared `memory_mb`, the Runtime's `default_memory()`, `elastos/crates/elastos-common/src/manifest.rs:1188-1190`,
  × 2^20). `tests/common/wasm_shape.rs` now reports `imported_memory_count` and `memories` (the memory section, id
  5: minimum and maximum or none, in pages; flags other than 0x00/0x01, a short body, bytes after the last memory
  and a second memory section each fail closed with a reason starting `memory section: `). One
  `PINNED_ARTIFACT_SHA256` in `tests/common/mod.rs` (the copies in `tests/bundle.rs` and `tests/verify.rs`
  removed). Builds, from `lab/wasm-capsule/`: `tools/build target/recompute-032/build-a` (exit 0, `Compiling capsule
  v0.1.0`), `.../build-b` and `.../build-c` (exit 0, each reported a cached build, `Finished` with no `Compiling`
  line, as task 030 saw): each `capsule.wasm` 180 bytes, sha256
  `2002429e73ee1a5e983df008f5b53728882646f109d55a9d1a93e831690631e1` (the receipt's `artifact_sha256`, from
  `shasum -a 256`), `cmp` a b identical; `rustc 1.91.0 (f8297e351 2025-10-28)`. `python3 -I -c` with `hashlib.sha256`
  over build-a's and build-b's file: the same sha256 and 180 bytes for each. The paths-differ, clean-copy proof is
  `two_clean_builds_in_different_paths_are_byte_identical`, green in the gate. The two never-committed scripts
  were re-created byte for byte from this LOG's text (task 024's `outside_cid.py`, 84 lines, and task 030's
  `memsec.py`, 70 lines; LOG's two-space indent removed, nothing else) under `target/recompute-032/`. First check,
  from the repo root: `python3 -I lab/wasm-capsule/target/recompute-032/outside_cid.py
  lab/capsule-identity/fixtures/content-sample` printed `bafybeieahlroxjdalpmglh227eikmodrjhrlelvzlhylvyt3s65ackiybi`
  (exit 0), that lane's pin (`lab/capsule-identity/tests/common/mod.rs:32`). From `lab/wasm-capsule/`:
  `tools/bundle target/recompute-032/reference-out` (exit 0) printed
  `bafybeiebyzg55l4s6kb6daroty4prlkximwp6uvo32ovacfzdx7cahywqm`; its `bundle/capsule.json` equals
  `capsule/capsule.json` (`cmp`) and its `bundle/capsule.wasm` has sha256 `2002429e…` (`shasum -a 256` and
  `hashlib`, 180 bytes); `python3 -I target/recompute-032/outside_cid.py target/recompute-032/reference-out/bundle`
  printed `bafybeiebyzg55l4s6kb6daroty4prlkximwp6uvo32ovacfzdx7cahywqm` (exit 0) and `tools/bundle --name
  target/recompute-032/reference-out/bundle` printed the same (exit 0). All agree, so no mismatch finding.
  `python3 -I target/recompute-032/memsec.py target/recompute-032/reference-out/bundle/capsule.wasm` (exit 0):
  `sha256 2002429e…  180 bytes`, `memory section: 1 memory`, `memory 0: minimum 16 pages, maximum 1024 pages`. Pins:
  `PINNED_ARTIFACT_SHA256` `6dd9af1a8d33d14f48514611663e3f5b262f91ef2729de4ec851441af9b22b13` →
  `2002429e73ee1a5e983df008f5b53728882646f109d55a9d1a93e831690631e1`; `REFERENCE_LAB_CID`
  `bafybeib34owcqffbwkntlhvbjngcj7eyeqqxx7aoefehqt2dqm2yu5jwse` →
  `bafybeiebyzg55l4s6kb6daroty4prlkximwp6uvo32ovacfzdx7cahywqm`; `MODULE_BUNDLE_LAB_CID` unchanged
  (`bafybeihtyzfql54i7irft23lg2mk44toqdww53ryuhs2psrknfjw4qhpcy`, `capsule.json` unchanged). Tests:
  `reads_a_memory_maximum_from_a_crafted_module`, `reads_a_memory_with_no_maximum_from_a_crafted_module`,
  `fails_closed_on_a_truncated_memory_section` (`tests/wasm_shape.rs`) and
  `built_capsule_declares_the_manifest_memory_as_its_maximum` (`tests/run.rs`, through `built_capsule`,
  `verified_bundle` and `memory_mb()`). Finding (not fixed, out of scope: "nothing else in it changes"):
  `tools/build` exits 0 when a `set -u` error happens after its `trap ... EXIT` line, on this Mac's `/bin/bash`
  3.2.57: the EXIT trap's `rm -rf` status becomes the exit status. Seen by hand with F-WC1-SPACED-PATH's old single
  edit, which leaves the new line reading an unset `CARGO_ENCODED_RUSTFLAGS`: `bash tools/build
  target/recompute-032/spaced-out` printed `tools/build: line 61: CARGO_ENCODED_RUSTFLAGS: unbound variable`, exit 0,
  no `capsule.wasm` and no receipt (a two-line probe, `set -euo pipefail`, `trap "true" EXIT`, then an unbound
  expansion, also exits 0; with `false` in place of the expansion it exits 1); the named test then failed at
  `sha256_file` ("no sha256 tool"), not at the build. So F-WC1-SPACED-PATH is re-anchored with a second edit that
  turns the new line into `export RUSTFLAGS="${RUSTFLAGS} -Clink-arg=--max-memory=67108864"`, the same bug as
  before; by hand with both edits, `cargo test --locked --test reproducible` failed at `tests/common/build.rs:132`
  ("tools/build failed (exit status: 101)", rustc's "--remap-path-prefix must contain '=' between FROM and TO");
  `tools/build` restored byte for byte (`cmp`). Canonical runner, from the repo root, `python3 -I
  examples/agent-host/falsify.py --from lab/wasm-capsule/falsifiers.json` with F-WC1 (a prefix: every F-WC1*
  entry, so also F-WC1-*, F-WC10-*, F-WC10C-* and F-WC10D-*), every other entry that edits `tools/build` or names a
  test that holds a pin or builds the capsule (F-WC3-COPY-DEPS, -CMD-BYPASS, -REUSE-OUT, -ARGS-UNKNOWN,
  -BUILD-STDOUT, -CMD-REASON, -CMD-STATUS, -CMD-STDOUT, -ARTIFACT-PIN) and F-WC-README-COUNT: "baseline: 20 named
  tests pass without an edit, 0 do not", "summary: 29 CAUGHT, 1 NOT RUN of 30", "not as expected:
  F-WC1-SPACED-PATH" ("did not run: two_clean_builds_in_different_paths_are_byte_identical": the child cargo's
  `process didn't exit successfully` line is the runner's Cargo failure marker, so it stays hand-proven, as before),
  exit 0, no `*.falsify-original` backup left. F-WC10D-NO-MODULE-MAX and F-WC10D-MAX-WRONG CAUGHT (runner-caught);
  every existing `tools/build` anchor is found once (each entry ran). README: totals 161 (two task 032), 97
  runner-caught; new "### The capsule declares its maximum (task 032)"; pins in "Claim scope", "Reference lab CID
  on this Mac", the receipt sample's `bundle` line and the named-test lists. ADOPTION: the lab CID pin and one
  task 032 line. Consumer check, from the repo root: `cargo test --locked --manifest-path
  lab/capsule-identity/Cargo.toml` exit 0, 117 passed, 0 failed (`wc001_capsule_bundle_gets_a_stable_lab_cid` ok).
  Gates, with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`: `cargo test --locked` (98 passed, 2 ignored, 0 failed) and
  `cargo fmt --check` green. Retired-label greps from the repo root (`git grep -n 'lab-''sha256' -- lab/wasm-capsule/`
  and `grep -rn --exclude-dir=target 'lab-''sha256' lab/wasm-capsule/`): both empty, exit 1.
- 27 Oct, task 035 (`tools/build` keeps its failure status through the cleanup trap; base
  `e3f510722`): probes first, before any edit, all with `/bin/bash`, whose `--version` first line is `GNU bash,
  version 3.2.57(1)-release (arm64-apple-darwin25)` (PATH `bash` is `/opt/homebrew/bin/bash`, 5.3.15). 032's probe
  `/bin/bash -c 'set -euo pipefail; trap "true" EXIT; : "$WC_UNSET_PROBE"'` printed `/bin/bash: WC_UNSET_PROBE:
  unbound variable`, exit 0; with `false` in place of the expansion, exit 1. Today's shape (`D="$(mktemp -d)"; trap
  'rm -rf "$D"' EXIT; : "$WC_UNSET_PROBE"`): exit 0 (the same with `/opt/homebrew/bin/bash`: exit 1). The planned
  shape, `trap 'status=$?; exit "$status"' EXIT` then the expansion: exit 0, because the trap sees `$?` 0: `trap
  'echo "trap sees $?" >&2' EXIT` printed `trap sees 0`, exit 0. Nothing else in the trap tells the two exits
  apart: `$BASH_COMMAND` is the failing command, `${PIPESTATUS[*]}` is `0`, `$LINENO` and `${BASH_LINENO[*]}` are
  `0`, an ERR trap does not fire, and a script file (`/bin/bash <(printf ...)`) behaves as `-c` does; `trap "false"
  EXIT` makes even a clean `true` exit 1, so 3.2 exits with the trap's last status. So no one-line trap keeps the
  status. The shape chosen from the probe: arm the trap to fail, `trap 'status=$?; rm -rf "$D"; exit "$((status ==
  0 ? 1 : status))"' EXIT`, and re-arm `trap 'rm -rf "$D"' EXIT` as the last line. In a probe script per body, with
  `/bin/bash` and with `/opt/homebrew/bin/bash`: `: "$WC_UNSET_PROBE"` exit 1, `false` exit 1, `(exit 7)` exit 7,
  `true` exit 0, and `$D` removed every time. `tools/build` changes only its trap lines (plus their comments): line
  41 is the armed trap, the new last line the plain re-arm. Test `build_script_fails_closed_after_an_unbound_variable`
  (`tests/reproducible.rs`) copies `tools/build` to `<tmp>/lane/tools/build`, with `: "$WC_UNSET_PROBE"` after the
  one line starting with `trap ` before `cargo build` (the re-arm comes after it, so the spec's "starts with `trap
  `, found once" is checked before that line), and runs it through `spawn_build` (`tests/common/build.rs`), the one
  spawn function, which `run_build_with_env` now calls. The spec check's FIX: this test runs `SYSTEM_BASH`
  (`/bin/bash`); every other build keeps `PATH_BASH` (`bash`). Before the fix, `cargo test --locked --test
  reproducible build_script_fails_closed_after_an_unbound_variable` failed at `tests/reproducible.rs:116:5`
  ("tools/build exited exit status: 0 after an unbound variable past its cleanup trap:", with bash's `line 39:
  WC_UNSET_PROBE: unbound variable`); after it, ok. A real build after the fix, `TMPDIR=<empty> <bash> tools/build
  <out>`: exit 0, TMPDIR empty, receipt written and sha256 `2002429e73ee…` (the pin) with both bashes. Falsifier
  F-WC1-TRAP-STATUS (the trap goes back to `trap 'rm -rf "$TARGET_DIR"' EXIT`); by hand, planted then restored
  (`cmp` identical), the test fails at the same `tests/reproducible.rs:116:5` assertion. Canonical runner, from the
  repo root, `python3 -I examples/agent-host/falsify.py --from lab/wasm-capsule/falsifiers.json F-WC1
  F-WC3-COPY-DEPS F-WC3-CMD-BYPASS F-WC3-REUSE-OUT F-WC3-ARGS-UNKNOWN F-WC3-BUILD-STDOUT F-WC3-CMD-REASON
  F-WC3-CMD-STATUS F-WC3-CMD-STDOUT F-WC3-ARTIFACT-PIN F-WC-README-COUNT` (F-WC1 is a prefix: every F-WC1*,
  F-WC10*, F-WC10C* and F-WC10D* entry): "baseline: 21 named tests pass without an edit, 0 do not", "F-WC1-TRAP-STATUS
  CAUGHT", "F-WC-README-COUNT CAUGHT" (re-anchored to 162, the same bug as before), "summary: 30 CAUGHT, 1 NOT RUN
  of 31", "not as expected: F-WC1-SPACED-PATH" ("did not run: two_clean_builds_in_different_paths_are_byte_identical",
  the runner's Cargo failure marker, as task 032 recorded; it stays hand-proven), exit 1 (that NOT RUN; task 032's
  run of the same set exited 0), no `*.falsify-original` backup left. Every existing `tools/build` anchor ran, so
  each is still found once. README: one Build sentence, the named test, totals 162 (one task 035) and 98
  runner-caught, a task 035 section. Consumer check, from the repo root: `cargo test --locked --manifest-path
  lab/capsule-identity/Cargo.toml` exit 0, 123 passed, 0 failed (`wc001_capsule_bundle_gets_a_stable_lab_cid ...
  ok`). Gates in `lab/wasm-capsule/`, with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`: `cargo test --locked` (99
  passed, 2 ignored, 0 failed), `cargo fmt --check` and `cargo fmt -p wasm-capsule-tools -- --check` exit 0. No
  dependency, `Cargo.toml`, `Cargo.lock`, `tools/Cargo.toml`, `capsule/` or pin changed. Retired-label greps from the
  repo root (`git grep -n 'lab-''sha256' -- lab/wasm-capsule/` and `grep -rn --exclude-dir=target 'lab-''sha256'
  lab/wasm-capsule/`): both empty, exit 1.
- 27 Oct, task 036 (build cleanup test watches the folder the build really uses; base `aecdfb314`): the probe
  first, before any edit. With only `rm -rf "$TARGET_DIR"; ` taken out of the armed trap (`tools/build:41`), `cargo
  test --locked --test reproducible build_script_fails_closed_after_an_unbound_variable` still passed ("test result:
  ok. 1 passed"), and the build's `mktemp -d` folder stayed, empty, under `/var/folders/.../T/tmp.XXXXXXXXXX`, not
  in the test's TMPDIR: the gap 035's review found is real. Reverted (`git status --short` empty) and that leaked
  folder removed. Template probe: `mktemp -d "${TMPDIR:-/tmp}/wc-build.XXXXXX"` with `TMPDIR=<dir>/` made
  `<dir>//wc-build.1UsW63` and with TMPDIR unset `/tmp/wc-build.KbfXPF`; the double slash does not matter, so no
  strip. `tools/build` line 39 is now `TARGET_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wc-build.XXXXXX")"`, with a comment
  why (macOS `mktemp -d` alone ignores TMPDIR); nothing else changed but comments. `tests/reproducible.rs`: the
  status test first calls `require_system_bash_3_2` (`/bin/bash --version` must name ` version 3.2.`, else it
  fails "this test needs /bin/bash 3.2, where a `set -u` error reaches the EXIT trap with $? 0; found: ...", never a
  SKIP); its planted copy also prints `wc-probe target dir: $TARGET_DIR` before the unbound expansion, and the test
  asserts that folder's parent is its TMPDIR before its empty check. Hand check of the version guard (not a
  `falsifiers.json` entry; `tests/reproducible.rs` is not a recovery target): with ` version 5.3.` in place of `
  version 3.2.`, the test failed at `tests/reproducible.rs:103:5` with that message ("found: \"GNU bash, version
  3.2.57(1)-release (arm64-apple-darwin25)\""), restored. New test `finished_build_leaves_its_tmpdir_empty`: one
  real build of the lane through `run_build_with_env` with `TMPDIR` set to a new empty folder; the build succeeds
  and the folder is empty. Falsifiers, all three runner-caught: F-WC1-TRAP-CLEANUP (the armed trap drops `rm -rf
  "$TARGET_DIR"; `), F-WC1-CLEANUP-ON-SUCCESS (the last line becomes `trap ':' EXIT`) and F-WC1-TARGET-OUTSIDE-TMPDIR
  (the target dir by a bare `mktemp -d` again; not in the task's list, added because the TMPDIR template is a new
  rule and without it every test stayed green). Each planted by hand and restored: the status test failed at
  `tests/reproducible.rs:180:5` ("the cleanup trap left [\"wc-build.Utmfkv\"] in the build's TMPDIR"), the new test
  at `:204:5` ("a finished build left [\"wc-build.GNbiV6\"] in its TMPDIR"), and the status test at `:174:5` (the
  target dir's parent is not the TMPDIR). Canonical runner, from the repo root, `python3 -I
  examples/agent-host/falsify.py --from lab/wasm-capsule/falsifiers.json F-WC1-TRAP-CLEANUP F-WC1-CLEANUP-ON-SUCCESS
  F-WC1-TARGET-OUTSIDE-TMPDIR F-WC1-TRAP-STATUS F-WC-README-COUNT`: "baseline: 3 named tests pass without an edit, 0
  do not", each CAUGHT, "summary: 5 CAUGHT of 5". Then every `tools/build` anchor, `... F-WC1 F-WC3-COPY-DEPS
  F-WC3-ARTIFACT-PIN F-WC-README-COUNT` (F-WC1 is a prefix): "baseline: 18 named tests pass without an edit, 0 do
  not", "summary: 26 CAUGHT, 1 NOT RUN of 27", "not as expected: F-WC1-SPACED-PATH" (the runner's Cargo failure
  marker, as tasks 032 and 035 recorded; it stays hand-proven), no `*.falsify-original` backup left. So every
  `tools/build` anchor is still found once, and F-WC1-TRAP-STATUS (its anchor unchanged) is still CAUGHT.
  F-WC-README-COUNT re-anchored to 165, the same bug as before. README: one Build sentence, the status test's
  description and the new test, totals 165 (three task 036) and 101 runner-caught (the stray line break before "1),
  each" is gone), a task 036 section. Consumer check, `cargo test --locked --manifest-path
  lab/capsule-identity/Cargo.toml`: 123 passed, 0 failed. Gates in `lab/wasm-capsule/`, with `RUST_TEST_THREADS=2
  CARGO_INCREMENTAL=0`: `cargo test --locked` (100 passed, 2 ignored, 0 failed; the pinned `capsule.wasm` sha256,
  every lab CID pin and the reproducibility test hold with no edit), `cargo fmt --check` and `cargo fmt -p
  wasm-capsule-tools -- --check` exit 0. No dependency, `Cargo.toml`, `Cargo.lock`, `tools/Cargo.toml`, `capsule/` or
  pin changed. Retired-label greps from the repo root (`git grep -n 'lab-''sha256' -- lab/wasm-capsule/` and `grep
  -rn --exclude-dir=target 'lab-''sha256' lab/wasm-capsule/`): both empty, exit 1.
- 27 Oct, task 038 (C0 lab half: pinned engine versions and a rejected cap argument; base `d30172ddf`). Probes
  first, before any code edit, read-only, run from `/tmp`: `/opt/homebrew/bin/wasmtime --version` (exit 0, `wasmtime
  45.0.1 (83166ba31 2026-06-05)`) and `/opt/homebrew/bin/wasmer --version` (exit 0, `wasmer 7.5.0`), the same lines
  as LOG 575-576. An unknown `-W` key, `/opt/homebrew/bin/wasmtime run -W max-memory-sizeX=1
  /nonexistent/module.wasm`: exit 2, stderr (one line) `error: unknown -W / --wasm option: max-memory-sizeX`. A bad
  `-W` value, `/opt/homebrew/bin/wasmtime run -W max-memory-size=abc /nonexistent/module.wasm`: exit 2, stderr (one
  line) ``error: failed to parse -W option `max-memory-size=abc`: invalid digit found in string``. Contrast, no `-W`:
  `/opt/homebrew/bin/wasmtime run /nonexistent/module.wasm`: exit 1, first stderr line `Error: failed to open wasm
  module "/nonexistent/module.wasm"`. So the two probes share exit status 2 and a first stderr line that starts with
  `error: ` (lower case; the module failure starts `Error: `) and holds ` -W ` (the option's name, with a space on
  each side). Those are the measured values of the rule.
  Then the code. `tools/src/run.rs`: `pub const WASMTIME_VERSION = "45.0.1"` and `WASMER_VERSION = "7.5.0"` (each
  citing tasks 021 and 030), `Engine::pinned_version`, and `check_pinned`, called inside `query_version` on the first
  line once the empty-line check passes (split on single spaces: word 1 the engine's name, word 2 its pin exactly,
  any tail allowed). A refusal is `Reason::VersionNotPinned { engine, printed, pinned }`, text `<engine> --version
  printed "<line>", not the pinned version <engine> <pin>: no module run starts`, reaching `run`'s caller as
  `TwoEngineRefusal::Version`. `start_engine` refuses a start given a cap argument as `Reason::CapRejected { engine,
  argument, status, stderr }` (text `<engine> rejected the memory cap argument -W <argument> (exit status: <n>):
  <stderr>; the module is not run without its cap`) when `cap_rejected` holds: exit `CAP_REJECTED_STATUS` (2) and a
  first stderr line that starts with `CAP_REJECTED_PREFIX` (`error: `) and holds `CAP_REJECTED_OPTION` (` -W `), one
  `const` each, citing this LOG. Any other nonzero exit stays `EngineFailed`; there is no retry. `run_engine` still
  makes no `--version` query; both engines' argv are unchanged; no fuel flag. `tests/run.rs`: `stand_in_version`
  (used by `marked`, `recording` and `counting`) prints `<engine> <pinned const> (stand-in)`;
  `receipt_records_observed_engine_versions` uses pinned versions with made-up tails and checks the receipt never
  holds this Mac's quoted real lines; `version_queries_use_explicit_inputs` puts the pinned line before its report.
  New tests `run_refuses_an_unpinned_engine_version_before_any_module_run`,
  `run_accepts_the_pinned_version_with_any_tail` and `run_refuses_a_rejected_memory_cap_without_retrying_it`. Five
  new falsifiers, all runner-caught: F-WC5-VERSION-UNPINNED, F-WC10-CAP-REJECTED-RETRY, and three that each drop one
  part of the cap rule (F-WC10-CAP-REJECTED-UNNAMED, -ANY-STATUS, -UNCAPPED; not in the task's list, added because
  each part is a rule). By hand, each of the two named ones applied and restored (`cmp` equal): its test failed at
  `tests/run.rs:928:23`, "the two-engine runner passed, ..., not a refusal"; under the retry bug the passing run held
  `memory_caps: [None, None]`, the module run uncapped. Canonical runner, from the repo root, `python3 -I
  examples/agent-host/falsify.py --from lab/wasm-capsule/falsifiers.json F-WC5-VERSION-UNPINNED
  F-WC10-CAP-REJECTED-RETRY F-WC10-CAP-REJECTED-UNNAMED F-WC10-CAP-REJECTED-ANY-STATUS F-WC10-CAP-REJECTED-UNCAPPED
  F-WC5-HARDCODED-VERSIONS F-WC-README-COUNT`: "baseline: 4 named tests pass without an edit, 0 do not", "summary: 7
  CAUGHT of 7", exit 0. Then every entry that edits `tools/src/run.rs` or `tools/src/receipt.rs` (67 ids): "baseline:
  31 named tests pass without an edit, 0 do not", "summary: 67 CAUGHT of 67", exit 0, no `*.falsify-original` backup
  left; so every `run.rs` anchor is still found once and F-WC5-HARDCODED-VERSIONS is still caught. F-WC-README-COUNT
  re-anchored to 170, the same bug as before. README: the run, receipt and cap sections, the named tests, totals 170
  (five task 038) and 106 runner-caught, a task 038 section; ADOPTION gets one task 038 paragraph. Real engines:
  `real_receipt_names_both_installed_engines` and `built_capsule_runs_under_the_declared_cap_on_wasmtime` pass on
  `/opt/homebrew/bin` wasmtime 45.0.1 and wasmer 7.5.0, assertions unchanged. Gates in `lab/wasm-capsule/`, with
  `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`: `cargo test --locked` (103 passed, 2 ignored, 0 failed), `cargo fmt
  -- --check` and `cargo fmt -p wasm-capsule-tools -- --check` exit 0. No dependency, `Cargo.toml`, `Cargo.lock`,
  `tools/Cargo.toml`, `capsule/`, `tools/build`, lab CID or sha256 pin changed. Retired-label greps from the repo
  root (`git grep -n 'lab-''sha256' -- lab/wasm-capsule/` and `grep -rn --exclude-dir=target 'lab-''sha256'
  lab/wasm-capsule/`): both empty, exit 1.
- 27 Oct, task 039 (M1 A12 lab half, step 1 of 2: the run folder is removed after every engine start; base
  `dc80a2935`). `tools/src/run.rs`: `run_engine` is now steps 1 and 2, then `make_run_dir` (step 3, unchanged
  rule), `write_and_start` (steps 4 and 5, unchanged lines) and `finish_run`, which reads the outcome (the engine has
  exited, or never started) and then calls `remove_run_dir` on every outcome after the folder was made:
  `fs::remove_file` on `module.wasm` unless the writer refused to create it (`module_made`), then `fs::remove_dir`
  on the folder, never `remove_dir_all`, so an entry someone else put there stays and the removal fails. After a
  success a failed removal is refused with the new `Reason::RunDirNotRemoved(io::Error)`, text `the run folder cannot
  be removed after the engine exited: <OS error>`, at the path it stopped at; after a refusal the first refusal stays
  the answer and a failed removal is not reported (known limit, README). A killed runner leaves its folder (known
  limit; 040's census covers a killed engine, not a killed runner). `tests/run.rs`: one shared shell snippet,
  `RECORD_RUN_FOLDER` beside `MODULE_ARGUMENT`, records a stand-in's run folder during its run beside its own `$0`
  (outside the work root): the module copy, the folder's mode (`/usr/bin/stat -f %Lp`) and its entries; `CAT_MODULE`,
  `counting` and `recording` use it (no new stand-in helper). The tests that read the run folder after a run now read
  those records and also assert the folder is gone; the second-run case of `run_directory_is_private_and_new` now
  runs and makes a new `0o700` folder; the planted-folder case stays refused and the planted folder is not removed.
  New tests `run_engine_removes_its_run_folder_after_every_outcome` (both engines: success, `FAILING`, a missing
  absolute program), `run_leaves_an_empty_work_root` (two-engine pass, and wasmer failing) and
  `run_folder_that_cannot_be_removed_is_refused` (extra file: `Directory not empty (os error 66)` at the run
  folder, the extra file stays, the module file is gone; a folder at the module path: os error 1 at that path; extra
  file then a failure: the failure is the answer). Three new falsifiers, runner-caught: F-WC5-RUN-DIR-KEPT,
  F-WC5-RUN-DIR-KEPT-ON-FAILURE, F-WC5-REMOVAL-ERROR-DROPPED. F-WC5-DISK-REREAD's planted line now finds the bundle
  with `run_dir.with_file_name("bundle")` (the write moved into `write_and_start`, which has no work root), anchor
  unchanged, same bug; F-WC-README-COUNT re-anchored to 173. Before the edits every existing anchor in
  `falsifiers.json` was found exactly once, and still is. Canonical runner, from the repo root, `python3 -I
  examples/agent-host/falsify.py --from lab/wasm-capsule/falsifiers.json <63 ids>` (every entry that edits
  `tools/src/run.rs`, every entry naming a test whose body or stand-in helper changed, F-WC-README-COUNT, and the three
  new): "baseline: 37 named tests pass without an edit, 0 do not", "summary: 63 CAUGHT of 63", exit 0, no
  `*.falsify-original` backup left. Both engines were on PATH, so F-WC5-BOTH-ARGS ran. Real engines
  (`/opt/homebrew/bin` wasmtime 45.0.1, wasmer 7.5.0): `real_receipt_names_both_installed_engines`, the three wasmtime
  cap tests, `zero_grants_zero_imports_runs_on_both_real_engines` and the other real runs print PASS, assertions on
  output, status and receipt unchanged. README: the run section (step 6, which answer wins, the new reason), the
  test list, totals 173 (three task 039) and 109 runner-caught, a task 039 section; ADOPTION gets one task 039
  paragraph. Gates in `lab/wasm-capsule/`, with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`: `cargo test --locked`
  (106 passed, 2 ignored, 0 failed), `cargo fmt -- --check` and `cargo fmt -p wasm-capsule-tools -- --check` exit 0.
  No dependency, `Cargo.toml`, `Cargo.lock`, `tools/Cargo.toml`, `capsule/`, `tools/build`, engine argv, receipt
  text, lab CID or sha256 pin changed. Retired-label greps from the repo root (`git grep -n 'lab-''sha256' --
  lab/wasm-capsule/` and `grep -rn --exclude-dir=target 'lab-''sha256' lab/wasm-capsule/`): both empty, exit 1.
- 27 Oct, task 040 (M1 A12 lab half, step 2 of 2: cleanup census after normal, trapped and killed runs). Base
  `ad885d9d2`. `tests/run.rs` only, plus docs and `falsifiers.json`; no `tools/src/` change. New helpers: `real_wasmer`
  and `real_engines` beside `real_wasmtime` (SKIPPED, never PASS, when an engine is missing); one census,
  `census(work_root) -> Vec<String>` (P10), with `census_tool` (absolute path; a tool that does not start fails the
  test with its path), `live_processes` (`/usr/bin/pgrep -f <work root>`) and `live_argv` (`/bin/ps -o args= -p
  <pid>`); `digest_module` (hand-written bytes in `grow_module`'s style, no memory, no import; the root package has
  no `wat` dev-dependency, and none was added) with `TRAP_BODY` (`unreachable`) and `LOOP_BODY` (`loop br 0 end`);
  `argv_faults` for the live argv. Measured on this Mac: `/usr/sbin/lsof +D` exits 1 even when it lists an open file
  (the first self-test run read the test's own open handle as `census failed: ... (exit status: 1): stdout "COMMAND
  ... left.txt"`), so a listing with exit 0 or 1 is read as open files; exit 1 with nothing printed is still the only
  "none", and any stderr or other exit is a census failure. `/bin/sleep` refuses a path argument (`sleep: invalid
  time interval`), so the self-test's sleeper carries the work-root path as its `argv[0]`. Results (engines
  `/opt/homebrew/bin` wasmtime 45.0.1, wasmer 7.5.0): `census_reports_each_kind_of_leftover` PASS (one `entry:
  left.txt`, one `process: <pid> <work>/sleeper 30`, one `open file:` line naming the test process and the file;
  empty after cleanup); `normal_run_leaves_nothing_under_the_scratch_root` PASS (both print `FIXED_OUTPUT`, census
  empty); `trapped_run_leaves_nothing_under_the_scratch_root` PASS (wasmtime `exit status: 134`, ``wasm trap: wasm
  `unreachable` instruction executed``; wasmer `exit status: 1`, `error: RuntimeError: unreachable`; census empty on
  each); `killed_run_leaves_nothing_under_the_scratch_root` PASS (one engine process each, SIGKILL, signal 9, census
  empty on each; live argv `/opt/homebrew/bin/wasmtime run --invoke digest -W
  max-memory-size=67108864,max-memories=1,trap-on-grow-failure=y <work>/wasmtime/module.wasm 1592590337` and
  `/opt/homebrew/bin/wasmer run --invoke digest <work>/wasmer/module.wasm 1592590337`, no preopen, env or network
  flag). The census found no real leftover. New falsifier F-WC-A12-TEMP-LEAK (`run_engine` makes `<work
  root>/<engine>.scratch` before its run folder, never removed; anchor `let run_dir = make_run_dir(work_root,
  engine)?;`, found once, on a line no other entry anchors; every existing anchor unchanged); F-WC-README-COUNT
  re-anchored to 174. Canonical runner, from the repo root, `python3 -I examples/agent-host/falsify.py --from
  lab/wasm-capsule/falsifiers.json F-WC-A12-TEMP-LEAK F-WC-README-COUNT`: "baseline: 4 named tests pass without an
  edit, 0 do not", "summary: 2 CAUGHT of 2", exit 0, no `*.falsify-original` left. With the same mutation applied
  through `falsify.Mutation`, all three run tests failed at `assert_census_empty` ("the census found leftovers",
  `entry: wasmtime.scratch`, and for the normal run `entry: wasmer.scratch` too). README: new section "Cleanup census
  (M1 A12)", the four tests in "Named tests", totals 174 (one task 040) and 110 runner-caught, a task 040 section;
  ADOPTION one line. Gates in `lab/wasm-capsule/`, with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`: `cargo test
  --locked` (110 passed, 2 ignored, 0 failed), `cargo fmt -- --check` and `cargo fmt -p wasm-capsule-tools -- --check`
  exit 0. No dependency, `Cargo.toml`, `Cargo.lock`, `tools/Cargo.toml`, `tools/src/`, `capsule/`, `tools/build`, lab
  CID or sha256 pin changed. Retired-label greps from the repo root (`git grep -n 'lab-''sha256' --
  lab/wasm-capsule/` and `grep -rn --exclude-dir=target 'lab-''sha256' lab/wasm-capsule/`): both empty, exit 1.
- 27 Oct, task 041 (M1 A8 lab half: host secrets never reach either engine or the capsule output). Base
  `571741989`. `tests/run.rs` and `tests/common/grants.rs` only, plus docs and `falsifiers.json`; no `tools/src/`
  change. `tests/common/grants.rs`: the one module builder is now `importing(module, name)`; `importing_env` calls
  it and `IMPORTING_MODULE` stays byte for byte (`importing("env", "f") == IMPORTING_MODULE` is asserted). New in
  `tests/run.rs`: `HostSecretCase` (one case-folder layout for both halves), `host_secret_shim` (`#!/bin/sh`: writes
  `"$@"` one per line and `/usr/bin/env` into `records/<engine>.<version|run>.<argv|env>`, then `exec`s the real
  engine by its absolute path), and three tests. `host_secret_fixture_never_reaches_either_real_engine` (outer)
  builds the capsule, writes `<tmp>/home/keys/host-secret` holding `host-secret-marker <fresh test key's DID>`, and
  starts this test binary (`--exact host_secret_fixture_run_inside_the_child --ignored --nocapture`) with
  `HOME=<tmp>/home` and `WASM_CAPSULE_LAB_A8_CASE=<tmp>`; it passes only on child exit 0 and `test result: ok. 1
  passed;`. `host_secret_fixture_run_inside_the_child` (`#[ignore]`, fails at once on another `HOME`: run by hand
  it panicked "WASM_CAPSULE_LAB_A8_CASE is not set", and with the variable set under the real `HOME`, "HOME is not
  the fixture home"). `host_secret_probe_imports_are_refused_before_any_engine_starts`. Results (engines
  `/opt/homebrew/bin`, `wasmtime 45.0.1 (83166ba31 2026-06-05)`, `wasmer 7.5.0`): outer PASS (child PASS);
  recorded module run argv wasmtime `run --invoke digest -W
  max-memory-size=67108864,max-memories=1,trap-on-grow-failure=y <work>/wasmtime/module.wasm 1592590337`, wasmer
  `run --invoke digest <work>/wasmer/module.wasm 1592590337`; each `--version` argv `--version` alone; every
  recorded environment (both engines, both starts) `PWD=<lane dir>`, `SHLVL=1`, `_=/usr/bin/env`, the shim shell's
  own (`env -i /bin/sh -c /usr/bin/env` prints the same three), no `HOME`, no home folder, fixture path or marker;
  both stdouts `FIXED_OUTPUT` and a newline. Probe test PASS: `path_open`, `fd_read`, `fd_prestat_get`,
  `environ_get`, `environ_sizes_get` from `wasi_snapshot_preview1`, each refused with no grant as `undeclared import
  wasi_snapshot_preview1.<name>` (`Audit(Undeclared)`) and with a `call` grant as `no typed lab operation for import
  wasi_snapshot_preview1.<name>` (`UntypedImport`), no run folder, no `--version` and no module run. No leak found.
  New falsifier F-WC-A8-HOME-PREOPEN (`start_engine` adds `.arg(format!("--dir={}",
  std::env::var("HOME").unwrap_or_default()))` after the `memory_cap_args` line; that anchor is found once in
  `tools/src/run.rs`, which this task does not change, so every existing anchor is unchanged); F-WC-README-COUNT
  re-anchored to 175. Canonical runner, from the repo root, `python3 -I examples/agent-host/falsify.py --from
  lab/wasm-capsule/falsifiers.json F-WC-A8-HOME-PREOPEN F-WC-README-COUNT`: "baseline: 2 named tests pass without an
  edit, 0 do not", "F-WC-README-COUNT CAUGHT", "F-WC-A8-HOME-PREOPEN CAUGHT", "summary: 2 CAUGHT of 2", exit 0, no
  `*.falsify-original` left. With the same mutation applied through `falsify.Mutation`, the real wasmtime took the
  preopen and ran; the outer test failed at "the child host_secret_fixture_run_inside_the_child did not pass (exit
  status: 101)", and the child at its `argv_faults` assertion: "wasmtime: the module run's argv [..., "--dir=<tmp>/home",
  ...]: a preopen, env or network flag: --dir=<tmp>/home". README: new section "Host secrets denied (M1 A8 lab
  half)", the three tests in "Named tests", totals 175 (one task 041) and 111 runner-caught, a task 041 section;
  ADOPTION one line. Gates in `lab/wasm-capsule/`, with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`: `cargo test
  --locked` (112 passed, 3 ignored, 0 failed), `cargo fmt -- --check` and `cargo fmt -p wasm-capsule-tools -- --check`
  exit 0. No dependency, `Cargo.toml`, `Cargo.lock`, `tools/Cargo.toml`, `tools/src/`, `capsule/`, `tools/build`, lab
  CID or sha256 pin changed. Retired-label greps from the repo root (`git grep -n 'lab-''sha256' --
  lab/wasm-capsule/` and `grep -rn --exclude-dir=target 'lab-''sha256' lab/wasm-capsule/`): both empty, exit 1.
- 27 Oct, task 042 (three wrong claims from PASS reviews: 040's killed-run test, 039's claim sentence, 036's guard
  label). Base `ed88c8670`. `tests/run.rs`, `tools/src/run.rs` (module doc only), README, ADOPTION and LOG; no
  `falsifiers.json` change. (1) `tests/run.rs`: `census_tool` now returns an `Err` ("the census tool <path> did not
  start: ...") in place of a panic, so the census still fails the test with the path (`census failed: ...`) and the
  killed-run test can stop its engines first; new `PKILL` (`/usr/bin/pkill`) and `stop_run_engines`
  (`pkill -KILL -f <work root>` every 50 ms while the runner thread has not finished, at most 10 s; returns any
  `pkill` start error, exit other than 0 or 1, or a runner still running). In
  `killed_run_leaves_nothing_under_the_scratch_root`, a failed wait (pgrep error, no process in 10 s, run ended
  first) and a `/bin/kill` that does not start or fails each call it, then join the thread, then fail with the first
  reason; if the thread still runs, the join waits, so no detached thread is left. Passing path unchanged: run alone,
  both "live argv held no preopen" PASS lines and both census PASS lines, `ok. 1 passed`. Hand proof,
  hand-proven, pending R1 (`tests/run.rs` is not a recovery target, so no `falsifiers.json` entry), each followed by
  `/usr/bin/pgrep -f run40-killed`: with `PGREP` = `/nonexistent/pgrep`, the test failed at `tests/run.rs:3605:17`,
  "wasmtime: the census tool /nonexistent/pgrep did not start: No such file or directory (os error 2); then stopped
  its engines (problems: []) and joined the runner (it panicked: false)", in 0.08s; pgrep printed nothing, exit 1.
  With `PGREP` = `/usr/bin/false` (exit 1, nothing printed: the 10 s path), it failed after 10.09s, "wasmtime: no
  engine process showed up within 10 s, or the run ended first; then stopped its engines (problems: []) and joined
  the runner (it panicked: false)"; pgrep printed nothing, exit 1. Before the fix, on the base: `/usr/bin/false`
  failed at `tests/run.rs:3549:48` after 10.04s, and pgrep then exited 0 with one live engine, `/opt/homebrew/bin/wasmtime
  run --invoke digest -W max-memory-size=67108864,max-memories=1,trap-on-grow-failure=y
  <tmp>/wc001-run40-killed-71932-.../work-wasmtime/wasmtime/module.wasm 1592590337`, killed by hand with `/bin/kill
  -KILL` (pgrep then exit 1). `/nonexistent/pgrep` on the base panicked at `tests/run.rs:3223:33` with the same start
  error, but left no engine in ten tries (eight run alone, each "finished in 0.00s"; one with the whole `run` test
  binary): the test binary exited, or the panic's unwinding removed the temp root, before the detached thread started
  the engine. So that path leaked only by timing; the 10 s path leaked every time. Each `PGREP` edit restored byte
  for byte (`git diff --stat -- tests/run.rs` empty before the fix was written). (2) The claim sentence in
  `tools/src/run.rs`'s module doc, README's "**The claim.**" and ADOPTION's task 039 line now say a failed removal
  leaves that run folder (step 6), refused after a success; no code change in `tools/src/`. (3) Task 036's
  `/bin/bash` 3.2 guard is labelled hand-proven, pending R1 in README (named tests, a "Falsifiers" paragraph) and
  here; re-run now: with ` version 5.3.` in place of ` version 3.2.` in `require_system_bash_3_2`, the status test
  failed at `tests/reproducible.rs:103:5`, "this test needs /bin/bash 3.2, where a `set -u` error reaches the EXIT
  trap with $? 0; found: \"GNU bash, version 3.2.57(1)-release (arm64-apple-darwin25)\" (exit status: 0)";
  restored (`git diff --stat -- tests/reproducible.rs` empty), then `ok. 1 passed`. README's hand-proven total is 66
  (the 64 entries, plus this guard and task 042's stop, each once, outside the 175); runner-caught stays 111, total
  175. Every `falsifiers.json` anchor found exactly once (64 in `tools/src/run.rs`, none touched; `grep -c "nothing
  the runner made is left in" tools/src/run.rs` = 1). Gates in `lab/wasm-capsule/`, with `RUST_TEST_THREADS=2
  CARGO_INCREMENTAL=0`: `cargo test --locked` (112 passed, 3 ignored, 0 failed), `cargo fmt -- --check` and `cargo
  fmt -p wasm-capsule-tools -- --check` exit 0. No dependency, `Cargo.toml`, `Cargo.lock`, `capsule/`,
  `tools/build`, lab CID or sha256 pin changed. Retired-label greps from the repo root (`git grep -n 'lab-''sha256' --
  lab/wasm-capsule/` and `grep -rn --exclude-dir=target 'lab-''sha256' lab/wasm-capsule/`): both empty, exit 1.
- 27 Oct, task 043 (M1 A7 lab half: the runner stops an engine run at its wall-clock budget). Base `970abb4ca`.
  `tools/src/run.rs`: new `RunControl` (`RunControl::new(budget: Duration)`, `const fn`, no default) as `run_engine`'s
  last argument and a `RunInput::control` field; `check_budget` refuses a zero budget (`Reason::BudgetZero`, the work
  root as its path) first in `run_engine` and first in `run` (as `TwoEngineRefusal::Engine`, before verification and
  any `--version` query). `start_engine` spawns with the same argv, empty environment and null stdin, stdout and stderr
  piped, and calls `wait_within_budget`: one reader thread per pipe (`read_pipe`, `io::copy`), `try_wait` every
  `WAIT_POLL` (10 ms), the budget counted from just after the spawn. On overrun `stop_engine` sends SIGKILL
  (`Child::kill`) and reaps (`Child::wait`), both readers are joined, the output dropped, and the run refused
  `BudgetExceeded { engine, budget }`, "<engine> still ran at its run budget of <n> ms: the runner stopped it with
  SIGKILL"; `finish_run` removes the folder as on every outcome. New reasons with their OS cause: `EngineNotStopped`
  (a failed kill; the engine is then neither waited for nor its pipes read), `EngineNotWaited` (a failed `try_wait`,
  after which the engine is stopped too, or a failed reap) and `OutputNotRead`. These three have no test: there is no
  seam to make `kill`, `try_wait` or a pipe read fail. The engine argv is unchanged (no fuel or timeout flag); no
  expected argv in any test changed. To keep all 64 existing `run.rs` anchors found exactly once (each checked with a
  `str.count` = 1 loop over `falsifiers.json`), `run` and `write_and_start` bind the control into a local closure
  named `run_engine` / `start_engine`, so the anchored four-argument calls are unchanged; F-WC5a's and
  F-WC5-BYPASS-RUN-ENGINE's planted direct `start_engine` calls now pass `input.control` (anchors unchanged).
  `tests/run.rs`: every passing run passes `TEST_CONTROL` (`static`, 30 s); the killed-run test passes
  `KILLED_RUN_CONTROL` (120 s), so its own SIGKILL still reads `EngineFailed` with signal 9 (it passed). New tests:
  `looping_capsule_is_stopped_at_its_run_budget_on_both_engines` (real engines; wasmtime stopped after 505.5 ms, wasmer
  after 504.6 ms, census empty), `run_stops_wasmtime_at_its_budget_and_never_starts_wasmer` (passed with the real
  wasmtime, and with `PATH=$HOME/.cargo/bin:/usr/bin:/bin` so the stand-in `exec -a "$module" /bin/sleep 600` ran;
  `pgrep -f run43-` then found nothing), `zero_run_budget_is_refused_before_any_engine_starts`, and
  `engine_output_past_a_pipe_buffer_never_blocks_it` (128 KiB to stderr then stdout, shell builtins only). The two
  looping and the pipe test use `answer_within_watchdog` (budget + 20 s, then `stop_run_engines`, join, fail), since
  `falsify.py` gives `cargo test` no time limit. New falsifiers F-WC-A7-BUDGET-IGNORED (the line `Ok(None) if
  started.elapsed() >= control.budget() => {` becomes `Ok(None) if false => {`) and F-WC-A7-PIPE-BLOCKED (stdout is
  read to its end before the stderr reader starts); F-WC-README-COUNT re-anchored to 177. Canonical runner, from the
  repo root: `python3 -I examples/agent-host/falsify.py --from lab/wasm-capsule/falsifiers.json F-WC-A7-` gave
  "baseline: 2 named tests pass without an edit, 0 do not", "F-WC-A7-BUDGET-IGNORED CAUGHT", "F-WC-A7-PIPE-BLOCKED
  CAUGHT", "summary: 2 CAUGHT of 2"; then every entry that edits `tools/src/run.rs` plus F-WC-README-COUNT (63 ids)
  gave "baseline: 39 named tests pass without an edit, 0 do not", "summary: 63 CAUGHT of 63", exit 0, no
  `*.falsify-original` left. README: "Run one engine (wc-005a)" (signature, step 0, the reasons, "The run budget"
  with its limits: no budget on `--version`, wall-clock not CPU, partial output dropped, a killed runner leaves its
  engine), `RunInput` and step 0 in "Same output on two engines", the memory-cap section's "no fuel or time limit"
  sentence replaced, four named tests, totals 177 (two task 043) and 113 runner-caught, a task 043 section. ADOPTION:
  its "no fuel or time limit" sentence fixed, one task 043 line. Gates in `lab/wasm-capsule/`, with
  `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`: `cargo test --locked` (116 passed, 3 ignored, 0 failed), `cargo fmt --
  --check` and `cargo fmt -p wasm-capsule-tools -- --check` exit 0. No dependency, `Cargo.toml`, `Cargo.lock`,
  `tools/Cargo.toml`, `capsule/`, `tools/build`, lab CID or sha256 pin changed. Retired-label greps from the repo root
  (`git grep -n 'lab-''sha256' -- lab/wasm-capsule/` and `grep -rn --exclude-dir=target 'lab-''sha256'
  lab/wasm-capsule/`): both empty, exit 1.
