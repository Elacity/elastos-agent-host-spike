# Static import audit

`wasm-capsule-audit` is a static lab pre-check. `audit` lists core Wasm imports
and refuses undeclared imports by module and name. `audit_component` lists the
outermost Component's imports and requires each full interface name and version
to match a declaration exactly. Both use one validation and parsing path, with
one custom-section check at every depth. [API v1](INTERFACE.md) defines the
public types, validation rules and exact refusal strings; `AUDIT_API` stays 1.

The crate never executes or instantiates a module. It makes no admission,
launch or trust decision, and no admission or launch path calls it. The Runtime
owns enforcement through its link-time refusal. This lab work claims no grade
row or installed-product proof.

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
The seven `component_imports` tests cover exact names and versions, section
order, unused declarations, core-module refusal, full Component validation,
internal imports, and custom payloads in Components and embedded modules.
Component fixtures are built in the tests with the pinned `wat`; malformed
fixtures also truncate or extend those bytes. Tests read no external WIT files.

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
| F-CWA2a | Ignore Component imports and inspect only embedded core modules | `component_importing_wasi_filesystem_is_refused_by_name` |
| F-CWA2b | Match only the package prefix | `a_different_version_of_a_declared_interface_is_refused` |
| F-CWA2c | Skip the Component encoding check | `core_module_bytes_are_not_accepted_as_a_component` |
| F-CWA2d | Check only outermost Component custom sections | `component_custom_section_carrying_code_is_refused` |
| F-CWA2e | Return declarations instead of interfaces read | `component_importing_only_a_declared_interface_passes` |
| F-CWA2f | Skip full Component validation | `invalid_component_bytes_are_refused` |
| F-CWA2g | Treat nested Component imports as outside authority | `embedded_imports_are_internal` |

Start with passing checks. Save the original bytes of the edited file and its
SHA-256, then apply one entry's exact edits. With the check environment above,
run each named test separately:

```sh
cargo test --locked --manifest-path lab/wasm-capsule/audit/Cargo.toml \
  --test core_imports -- --exact public_api_is_v1
```

Replace the test name with the entry's name. Use `--test skeleton` for F-CWA0a
and F-CWA0b, and `--test component_imports` for F-CWA2a through F-CWA2g:

```sh
cargo test --locked --manifest-path lab/wasm-capsule/audit/Cargo.toml \
  --test component_imports -- --exact component_importing_wasi_filesystem_is_refused_by_name
```

A caught entry requires every named test to run and fail at its
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

The cwa-002 in-tree run caught all 18 `caught` entries: all 20 named test runs
built and failed at assertions. F-CWA2a returned an empty import list;
F-CWA2b accepted the wrong version; F-CWA2c accepted a core module;
F-CWA2d accepted code in an embedded module's custom section; F-CWA2e returned
an unused declaration; F-CWA2f accepted an invalid embedded function; and
F-CWA2g refused an internal nested import. F-CWA0c again failed before tests
because `--locked` refused the nested workspace's missing lockfile. Every
edited file restored byte-identical, checked by SHA-256. The clean format and
locked-test checks passed all 17 tests offline with `RUST_TEST_THREADS=2` and
`CARGO_INCREMENTAL=0`. The audit manifest and workspace files stayed unchanged.
