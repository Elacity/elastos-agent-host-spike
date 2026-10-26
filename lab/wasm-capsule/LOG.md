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
  - Both retired-label greps (Acceptance, the merge gate): empty output, exit 1.
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
- wc-005 (task 006): `wasm_capsule_tools::run::run` / `run_observed` (`tools/src/run.rs`), a library function, no
  command. It calls wc-004's `verify_bundle` once with no grants (a refusal starts no engine and makes no OUT_DIR),
  stages every verified `entries()` entry new into `OUT_DIR/staged/` from the checked bytes, checks the copy's lab CID
  with `bundle_identity` against the verified `cid()`, queries each engine's `--version`, runs the verified
  `entrypoint()` with `wasmtime run --invoke digest <module> 1592590337` and `wasmer run --invoke digest <module>
  1592590337` (two separate processes, no `--dir`/`--mapdir`/`--env`/`--net`), requires both to exit 0 with
  byte-identical stdout, and writes `OUT_DIR/receipt.txt` (`wc-005.run-receipt/v1`: lab CID, observed versions,
  function, argument, both exits and outputs). Engines are inputs by path, never the environment; one `Command::new`.
  Each step has its own refusal with path and cause. Spec-check FIX: `VerifiedBundle::entrypoint()` added (the
  verifier stores the audited entry's index), `verified_bundle_is_sealed` updated, `path_to_run` shared with
  `bundle.rs`. 11 named tests in `tests/run.rs` (stand-in engine scripts written into each test's temp dir; one test
  starts the real engines). Real run: `wasmtime 45.0.1 (83166ba31 2026-06-05)` and `wasmer 7.5.0`, argument
  `1592590337` (`FIXED_INPUT`), both stdout `"230101071268130872\n"` (`FIXED_OUTPUT`), exit 0. A behaviour proof on one
  core module on this Mac; both engines test-only, neither endorsed; not the Component ABI. Falsifiers: 18 new F-WC5
  (F-WC5a to F-WC5d and 14 more) and F-WC4-ENTRYPOINT-ACCESSOR; F-WC4-ENTRY-SUBSTITUTE, -ENTRY-HARDCODED,
  -ORDER-AUDIT-FIRST, -SEALED-NEW and -SECOND-AUDIT re-anchored (same bug). All 24 run by the canonical runner,
  `python3 -I examples/agent-host/falsify.py --from lab/wasm-capsule/falsifiers.json F-WC5 F-WC4-ENTRY-SUBSTITUTE
  F-WC4-ENTRY-HARDCODED F-WC4-ENTRYPOINT-ACCESSOR F-WC4-ORDER-AUDIT-FIRST F-WC4-SEALED-NEW F-WC4-SECOND-AUDIT`:
  "summary: 24 CAUGHT of 24", exit 0 (runner-caught). F-WC5a and F-WC5-ENGINE-ENV also checked by hand: each named
  test built and failed at its assertion (`tests/run.rs` "the runner ran lab-cid:…", "the runner reads the
  environment: env::"). `LOG.md`'s gate line reworded so both retired-label greps give empty output, exit 1.
