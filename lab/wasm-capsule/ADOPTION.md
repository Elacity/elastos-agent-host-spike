# Adoption notes (for Anders, after 0.8.0)

This lane is falsifiable lab tooling, not a second Runtime. It claims no
Agent-Host grade row (Rong spec, section 3). wc-001 gives a reproducible
zero-import core-Wasm capsule and a receipt; wc-002..005 build on it.

## What you can take

- `tools/build` — a pinned, reproducible build of a core-Wasm capsule, with a
  receipt that binds the artifact to the exact toolchain, lockfile and inputs
  (PRINCIPLES P13). The knobs (one codegen unit, LTO, strip, `panic = "abort"`,
  fixed `SOURCE_DATE_EPOCH`, isolated target dir, `--remap-path-prefix`) are the
  reproducible-build recipe.
- `tests/common/wasm_shape.rs` — a tiny dependency-free reader that checks an
  artifact is core Wasm, imports nothing, and has an expected export signature.
  It is NOT a validator; wc-002 grows it into the static import audit.

## Requirements (what the claim rests on)

- rustc **1.91.0** with the `wasm32-unknown-unknown` target (pinned in
  `rust-toolchain.toml`). The receipt records the exact version.
- `bash`, and a sha256 tool: `sha256sum` or `shasum -a 256` (both present on the
  Mac). `tools/build` and the tests prefer `sha256sum`, then `shasum`.
- No network: the lane has no external crates, so `cargo build --locked` builds
  from clean caches offline. Keep it that way — a dependency would put the
  lockfile on the network and widen the surface.

## Claim scope — do not overstate

- Reproducible on **this one Mac**, across paths and clean caches only.
  Cross-machine reproduction is **unverified**: symbol hashes depend on the
  build machine. Do not call a cross-machine match proven without a test.
- The capsule is a **core** module, not a Component. It declares no
  `elastos:bus` world and uses no `wit-bindgen`. Do not call its name a CID
  unless the Runtime's content-identity rule is reproduced exactly lab-side
  (wc-003 does the hash-naming; wc-004 the signature).
- `digest` is a placeholder pure function to anchor identity and portability
  work. It is not a product capability.

## Not yet wired

The canonical falsifier runner (`examples/agent-host/falsify.py`) has no `lab`
command or recovery target for this workspace (ask **R1**, owned by the
model-provider lane). Until that one-line addition lands, run the lane's
falsifiers by hand (break → named test fails → revert); do not add a second
runner or edit `falsify.py`.
