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
  identity imports and still refuses a second naming import. 19 falsifiers (F-WC4a to F-WC4g and 12 more): hand-proven,
  pending R1 (runner-caught: none); F-WC3-SECOND-IMPORT and -SECOND-RULE re-proved. `capsule.wasm` stays `6dd9af1a…`.
