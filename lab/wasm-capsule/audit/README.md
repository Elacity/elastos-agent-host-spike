# Static import audit

`wasm-capsule-audit` is a static lab pre-check that lists core Wasm imports and
refuses undeclared imports by module and name. [API v1](INTERFACE.md) defines
the public types, validation rules and exact refusal strings.

The crate never executes or instantiates a module. It makes no admission,
launch or trust decision, and no admission or launch path calls it. The Runtime
owns enforcement. This lab work claims no grade row or installed-product proof.

## Checks

Run from the repository root, using the lab workspace's committed lockfile:

```sh
export RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true
export CARGO_BUILD_JOBS=2
export CARGO_TARGET_DIR="$PWD/lab/wasm-capsule/audit/target"
export CARGO_BUILD_BUILD_DIR="$CARGO_TARGET_DIR/build"
cargo fmt --manifest-path lab/wasm-capsule/audit/Cargo.toml -- --check
cargo test --locked --manifest-path lab/wasm-capsule/audit/Cargo.toml
```

The eight `core_imports` tests cover default features, named refusals, exact
declarations, malformed bytes, custom payloads, compact import groups and API
v1. The two retained `skeleton` tests pin the manifest and workspace boundary.
Fixtures are built in the tests with the pinned `wat` or raw bytes.

## Falsifiers

[falsifiers.json](falsifiers.json) is the crate's one falsifier file. Its paths
are relative to `examples/agent-host/`. Each `old` text occurs exactly once.
The canonical `examples/agent-host/falsify.py` runner awaits R1 support for
`"command": "lab"`; its current loader refuses that command. Until R1 is fixed,
apply and verify each entry by hand in this workspace.

| ID | Planted change | Required failing test |
| --- | --- | --- |
| F-CWA0a | Remove the exact `wasmparser` pin | `manifest_pins_only_wasmparser_and_wat_exactly` |
| F-CWA0b | Move `wat` into caller dependencies | `manifest_pins_only_wasmparser_and_wat_exactly` |
| F-CWA0c | Add a nested workspace | `cargo test --locked --manifest-path lab/wasm-capsule/audit/Cargo.toml --no-run` must fail before tests |
| F-CWA0e | Add a second public audit entry point | `public_api_is_v1` |
| F-CWA1a | Skip modules whose names start with `wasi` | `undeclared_wasi_import_is_refused_by_name`, `clock_random_and_socket_imports_are_refused` |
| F-CWA1b | Compare import counts instead of names | `declared_import_passes_and_only_that_one` |
| F-CWA1c | Return imports collected so far on invalid bytes | `malformed_module_is_refused` |
| F-CWA1d | Skip the custom-section code check | `custom_section_carrying_code_is_refused` |
| F-CWA1e | Change only the code's Malformed Display string | `public_api_is_v1`, `malformed_module_is_refused` |
| F-CWA1f | Validate with `WasmFeatures::WASM1` | `zero_import_module_passes` |
| F-CWA1g | Read single imports and skip compact groups | `compact_import_groups_are_listed_and_refused_by_name` |
| F-CWA1h | Return declarations instead of imports read | `compact_import_groups_are_listed_and_refused_by_name` |

Start with passing checks. Save the original bytes of the edited file and its
SHA-256, then apply one entry's exact edits. With the check environment above,
run each named test separately:

```sh
cargo test --locked --manifest-path lab/wasm-capsule/audit/Cargo.toml \
  --test core_imports -- --exact public_api_is_v1
```

Replace the test name with the entry's name. Use `--test skeleton` for F-CWA0a
and F-CWA0b. A caught entry requires every named test to run and fail at its
assertion; a build error or zero matching tests does not count. F-CWA0c instead
uses the `--no-run` command in the table and expects Cargo failure. Restore the
original bytes, check the SHA-256, and confirm that `audit/Cargo.lock` is absent
before the next entry. Finish by running both clean checks again. Keep the
workspace manifest and lockfile unchanged throughout.

The cwa-001 in-tree run caught all 11 `caught` entries: all 13 named test runs
built and failed. F-CWA1b failed on the equal-count, different-name case.
F-CWA0c failed because the nested workspace needed its own lockfile and
`--locked` refused to create it. Each edited file restored to its original
SHA-256, and the clean suite passed all 10 tests.
