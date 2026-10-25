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
