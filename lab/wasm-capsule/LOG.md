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
  is `lab-sha256:<hex>`, never a CID. Pinned vector re-computed with
  `printf | shasum -a 256`; `capsule.wasm` unchanged (`6dd9af1a…`).
- wc-003a round 2 (review fix): `open_regular(path)` builds its own read-only
  options (caller-chosen options had let it empty or create a file), and its
  handle check is `check_regular`, so a failed inspection is tested too. Tests
  `the_one_open_never_writes_truncates_or_creates_a_file` and
  `inspection_failure_reports_path_and_cause` (18 named tests); falsifiers
  F-WC3-WRITABLE, -TRUNCATE, -CREATE and -INSPECT-CAUSE (24 for wc-003a), all
  caught by hand (falsify.py `lab` pending R1).
