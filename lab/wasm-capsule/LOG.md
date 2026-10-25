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
- wc-003 round 2 (review: writes through output links; read-after-check race):
  one check, `open_regular` (O_NOFOLLOW|O_NONBLOCK, then the handle's own
  type), now covers every read and write of a capsule file; the reader reads
  the handle it checked, behind a test seam; the build mode creates
  `OUT_DIR/bundle` and its files new; `tools/build` replaces its two outputs
  instead of writing through them. 4 new named tests, 5 new falsifiers
  (F-WC3-FIFO, -NOT-REGULAR, -REREAD, -REUSE-BUNDLE, -BUILD-LINK); F-WC3b,
  -MODE, -MISSING, -SYMLINK and -BYPASS re-pointed at the new code; all 26
  proved by break → named test fails → revert.
