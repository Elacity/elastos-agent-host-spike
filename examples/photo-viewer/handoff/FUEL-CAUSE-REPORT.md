# Fix report: a trapped Component run keeps its cause

Answer 4 of the P0/P1 review: fix `elastos-compute/src/providers/component.rs:134` so the root cause reaches
the caller, with a test that a fuel cause does. It is its own small PR, branched from `spike/photo-viewer` and
independent of the photo-viewer stack. Sasha approved this shipping Runtime change; it is the only one.

## Change

`elastos/crates/elastos-compute/src/providers/component.rs`, one call site plus one helper:

- Before: `format!("Component lifecycle run failed: {err}")`. A Wasmtime trap's `Display` is only the outer
  context, `error while executing at wasm backtrace: ...`. The cause, `wasm trap: all fuel consumed by
  WebAssembly`, sits in the root of the chain and was dropped.
- After: `lifecycle_run_failure(&err)` leads with `err.root_cause()` and keeps the backtrace on the next lines.
  When the error has no context (cause equals outer), it prints once.

The message for a fuel-exhausted run is now:

```
Compute error: Component lifecycle run failed: wasm trap: all fuel consumed by WebAssembly
error while executing at wasm backtrace:
    0:     0xca - m!<wasm function 0>
```

Instantiation and linking errors (`component.rs:126`, `129`) are unchanged; the review asked for line 134 only.
No code in the repository matches the old text, so no caller depends on it (searched `.rs`, `.py`, `.mjs`,
`.sh`, `.md`).

## Test

`providers::component::tests::fuel_exhaustion_reaches_the_caller_with_its_cause`, in the crate's test module.

- The input is a Bus v1 component written in WAT inside the test: it imports `elastos:bus/types` for
  `bus-error` and exports `elastos:bus/lifecycle` whose `run` spins forever.
- It is loaded and started through the real `ComponentProvider` (`load`, then `start`) at the production
  fuel of 100,000,000.
- It asserts that the first line of the caller's error names the cause, and that the backtrace is still in
  the message.

## Tests run and results

`export RUST_TEST_THREADS=2`:

| Check | Result |
|---|---|
| The new test on the old code (reproduction) | failed, error shows only the backtrace |
| `cargo test -p elastos-compute` with the fix | 5 passed |
| `cargo fmt -p elastos-compute -- --check`, `cargo clippy -p elastos-compute --all-targets -D warnings` | clean |
| Falsifier: old `format!` put back, test run, file restored from saved bytes | failed, then passed after restore |
| `cargo test -p elastos-server component_conformance_exercises_bus_authorization_dispatch_and_audit` (the Runtime's Component path end to end) | 1 passed |

## Principles checked

- **11 (fail closed, then explain).** A fuel-exhausted run now explains itself. That is what lets a guest
  rely on the Runtime trap as a last resort.
- **12 (docs, code and tests agree).** `docs/CAPSULE_AUTHORING.md:202-209` documents the fixed fuel. It now
  shows up when the fuel runs out.
- **3, 10, 13, 15, 16, 18:** not affected. Error text only; no authority, path, identity or isolation change.

## Roadmap milestone

2.1 (Wasmtime and limits): a limit a component hits must be visible to whoever runs it.

## Questions for Sasha

None.

## Next slice

P2, reproducible build. The reviewer's Mac built P1 to `e2a4c798…638a` (221,287 bytes); cloud built it to
`9cf68749…` (221,286). P2 builds the current guest in one pinned Linux container and compares.
