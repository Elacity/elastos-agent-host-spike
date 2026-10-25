# wasm-capsule lab — log

- wc-001: byte-identical build of a zero-import core-Wasm capsule exporting
  `digest(i32)->i64`; `tools/build` + receipt; named tests for reproducibility,
  receipt toolchain/hashes, digest value, and wasm shape; 7 falsifiers in
  `falsifiers.json` proved by break → named test fails → revert (falsify.py
  `lab` command pending R1). Reproducible on this one Mac only; sha256
  `6dd9af1a8d33d14f48514611663e3f5b262f91ef2729de4ec851441af9b22b13`.
- wc-003: `tools/bundle` (the `bundle` binary) builds via `tools/build`, writes
  `bundle/` = `capsule.json` (lab manifest `wc-003.lab-manifest/v1`) +
  `capsule.wasm`, and names it `lab-sha256:<hex>` over a canonical closure (a
  tag, then sorted length-framed paths and exact bytes; no mtime or mode)
  through one rule, `tools/lab_name.rs`; extra, missing and symlinked files are
  refused with path and reason. Discovery: the Runtime's CID is Kubo v0.40.1's
  UnixFS root via the ipfs-provider, not reproducible lab-side, so the name is a
  lab name, never a CID (ADOPTION.md). 9 named tests; 12 falsifiers proved by
  break → named test fails → revert (falsify.py `lab` pending R1). This Mac:
  `lab-sha256:11ae0c0cd21c120c216aef1f15ef4178e30371a46e51b26ec95849b43bc8cbcc`.
