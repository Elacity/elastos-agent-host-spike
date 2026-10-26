# Static import audit

`wasm-capsule-audit` is a static lab pre-check. `audit` lists core Wasm imports
and refuses undeclared imports by module and name. `audit_component` lists the
outermost Component's imports and requires each full interface name and version
to match a declaration exactly. Both use one validation and parsing path, with
one custom-section check at every depth. It scans one run from the size's last
byte through the section content: the name's length, the name and the data.
A padded size can end in `00`; earlier size bytes are `0x80` or more and cannot
be part of the magic. Wasm magic `00 61 73 6D` at any offset returns
`CodeInCustomSection`; a section without that run passes, including padding
alone. This byte heuristic leaves compressed or encoded content undecoded.
[API v1](INTERFACE.md) defines the
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

The nine `core_imports` tests cover default features, named refusals, exact
declarations, malformed bytes, custom-section content, compact import groups,
refusal order and API v1. The two retained `skeleton` tests pin the manifest
and workspace boundary. The nine `component_imports` tests cover exact names
and versions (including same-major, pre-release and build-metadata versions;
a declared pre-release or build version does not match the release),
more than one import section, section order, unused declarations, core-module
refusal, full Component validation,
internal imports, import names with options, and custom-section content in
Components and embedded modules.
Custom-section cases cover code in the name and data, runs across their boundary,
and runs that start in the name's length byte or the size's last byte. Both entry
points refuse a whole module hidden from the size's last byte and accept the
same padded size with a plain name. The Component test runs both padded cases
inside an embedded core module too. Component cases also cover a module header
in the name at all four tested depths, plus plain names and data.
The API test pins the derives and `#[non_exhaustive]` lines in both the source
and API document. Both refusal-order tests require the header or encoding check
and full validation before custom-section checks, then the first undeclared
entry. Their fixtures check section order in the encoded bytes and exact refusal
variants and strings. Each wrong-encoding fixture validates and returns
`CodeInCustomSection` through the matching entry point before the other entry
point returns `Malformed` or `NotAComponent`.
Component fixtures are built in the tests with the pinned `wat`; malformed
fixtures also truncate, extend or splice those bytes. Tests read no external
WIT files.

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
| F-CWA1d | Skip the whole-content custom-section code check | `custom_section_carrying_code_is_refused` |
| F-CWA1e | Change only the code's Malformed Display string | `public_api_is_v1`, `malformed_module_is_refused` |
| F-CWA1f | Validate with `WasmFeatures::WASM1` | `zero_import_module_passes` |
| F-CWA1g | Read single imports and skip compact groups | `compact_import_groups_are_listed_and_refused_by_name` |
| F-CWA1h | Return declarations instead of imports read | `compact_import_groups_are_listed_and_refused_by_name` |
| F-CWA2a | Ignore Component imports and inspect only embedded core modules | `component_importing_wasi_filesystem_is_refused_by_name` |
| F-CWA2b | Match only the package prefix | `a_different_version_of_a_declared_interface_is_refused` |
| F-CWA2c | Skip the Component encoding check | `core_module_bytes_are_not_accepted_as_a_component` |
| F-CWA2d | Check whole custom-section content only at the outermost Component level | `component_custom_section_carrying_code_is_refused` |
| F-CWA2e | Return declarations instead of interfaces read | `component_importing_only_a_declared_interface_passes` |
| F-CWA2f | Skip full Component validation | `invalid_component_bytes_are_refused` |
| F-CWA2g | Treat nested Component imports as outside authority | `embedded_imports_are_internal` |
| F-CWA3a | Scan only custom-section data, skipping the name and its length | `custom_section_carrying_code_is_refused`, `component_custom_section_carrying_code_is_refused` |
| F-CWA3b | Scan the name and data separately, missing runs across fields | `custom_section_carrying_code_is_refused` |
| F-CWA4a | Remove `Eq` from `Refusal`'s source derive | `public_api_is_v1` |
| F-CWA4b | Remove `#[non_exhaustive]` from `Refusal` in the source | `public_api_is_v1` |
| F-CWA4c | Remove `#[non_exhaustive]` from the API document | `public_api_is_v1` |
| F-CWA4d | Reverse both loops to name the last undeclared entry | `audit_refusals_follow_the_documented_order`, `component_refusals_follow_the_documented_order` |
| F-CWA4e | Refuse undeclared entries during parsing, before later custom sections | `audit_refusals_follow_the_documented_order`, `component_refusals_follow_the_documented_order` |
| F-CWA4f | Run full validation after parsing and custom-section checks | `audit_refusals_follow_the_documented_order`, `component_refusals_follow_the_documented_order` |
| F-CWA4g | Skip the core header check | `malformed_module_is_refused` |
| F-CWA5a | Match the interface name and major version only | `a_different_version_of_a_declared_interface_is_refused` |
| F-CWA5b | Read only the first nonempty top-level import section | `component_importing_wasi_filesystem_is_refused_by_name`, `component_importing_only_a_declared_interface_passes` |
| F-CWA6a | Validate with every feature enabled, accepting import name options | `component_import_names_with_options_are_refused` |
| F-CWA7a | Skip the size's last byte in the custom-section scan | `custom_section_carrying_code_is_refused`, `component_custom_section_carrying_code_is_refused` |
| F-CWA7b | Refuse padding alone when a custom-section size ends in `00` | `custom_section_carrying_code_is_refused`, `component_custom_section_carrying_code_is_refused` |
| F-CWA8a | Run the encoding check after parsing and custom-section checks | `audit_refusals_follow_the_documented_order`, `component_refusals_follow_the_documented_order` |
| F-CWA8b | Remove `Eq` from `DeclaredImport`'s derive in the API document | `public_api_is_v1` |
| F-CWA9a | Match versions while ignoring build metadata | `a_different_version_of_a_declared_interface_is_refused` |
| F-CWA9b | Match versions while ignoring the pre-release | `a_different_version_of_a_declared_interface_is_refused` |
| F-CWA10a | Add only `cm-implements` to the default features, accepting the `implements` import | `component_import_names_with_options_are_refused` |
| F-CWA11a | Read the custom-section size's last byte only at depth 1 | `component_custom_section_carrying_code_is_refused` |
| F-CWA13a | Drop build metadata only from the declared interface | `a_different_version_of_a_declared_interface_is_refused` |
| F-CWA13b | Drop the pre-release only from the declared interface | `a_different_version_of_a_declared_interface_is_refused` |
| F-CWA14a | Match the module and name against separate declared entries | `declared_import_passes_and_only_that_one` |
| F-CWA15a | Match the name by a declared prefix while the module matches exactly | `declared_import_passes_and_only_that_one` |
| F-CWA15b | Match the module by a declared prefix while the name matches exactly | `declared_import_passes_and_only_that_one` |

Start with passing checks. Save the original bytes of the edited file and its
SHA-256, then apply one entry's exact edits. With the check environment above,
run each named test separately:

```sh
cargo test --locked --manifest-path lab/wasm-capsule/audit/Cargo.toml \
  --test core_imports -- --exact public_api_is_v1
```

Replace the test name with the entry's name. Use `--test skeleton` for F-CWA0a
and F-CWA0b, and `--test component_imports` for F-CWA2a through F-CWA2g and
the Component tests of F-CWA3a, F-CWA4d through F-CWA4f, F-CWA5a/F-CWA5b,
F-CWA6a, F-CWA7a/F-CWA7b, F-CWA8a (`component_refusals_follow_the_documented_order`),
F-CWA9a/F-CWA9b, F-CWA10a, F-CWA11a, and F-CWA13a/F-CWA13b:

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

The cwa-003 in-tree run caught all 20 `caught` entries: all 23 named test runs
built and failed at assertions. F-CWA3a failed both custom-section tests on
the module header in the name. F-CWA3b failed the core test on magic across
the name/data boundary. F-CWA1d and F-CWA2d kept their original bugs and were
caught again. F-CWA0c failed before tests because `--locked` refused the nested
workspace's missing lockfile. Every edited file restored byte-identical,
checked by SHA-256. The clean format and locked-test checks passed all 17 tests
offline with `RUST_TEST_THREADS=2` and `CARGO_INCREMENTAL=0`. The audit manifest,
workspace manifest and workspace lockfile stayed unchanged.

The cwa-004 in-tree run caught all 27 `caught` entries: all 33 named test runs
built and failed at assertions. F-CWA4a through F-CWA4c failed the API attribute
checks and named the affected file and expected line. F-CWA4d returned `c`
instead of `b` in both order tests; F-CWA4e returned an undeclared refusal
instead of `CodeInCustomSection`; F-CWA4f returned `CodeInCustomSection` instead
of `Malformed` or `NotAComponent`. F-CWA4g failed on the Component case in
`malformed_module_is_refused`. F-CWA0c failed before tests because `--locked`
refused the nested workspace's missing lockfile. Every edited file restored
byte-identical, checked by SHA-256. The clean format and locked-test checks
passed all 19 tests offline with `RUST_TEST_THREADS=2` and `CARGO_INCREMENTAL=0`.
The implementation, API document, audit manifest, workspace manifest and
workspace lockfile stayed unchanged.

The cwa-005 in-tree run caught all 29 `caught` entries: all 36 named test runs
built and failed at assertions. F-CWA5a accepted the newer minor version;
F-CWA5b missed the later filesystem import in both the refusal and result
checks. F-CWA0c failed before tests because `--locked` refused the nested
workspace's missing lockfile. Every edited file restored byte-identical,
checked by SHA-256. The clean format and locked-test checks passed all 19 tests
offline with `RUST_TEST_THREADS=2` and `CARGO_INCREMENTAL=0`. The implementation,
API document, audit manifest, workspace manifest and workspace lockfile stayed
unchanged.

The cwa-006 in-tree run caught all 30 `caught` entries: all 37 named test runs
built and failed at assertions. F-CWA6a accepted the version-suffix import as
`elastos:bus/runtime@1.0.0`, failing the new option-refusal test. With the default
validator, all three option cases returned `NotAComponent` and `not a component`,
and both plain-name controls returned exactly their declared import. F-CWA0c
failed before tests because `--locked` refused the nested workspace's missing
lockfile. Every edited file restored byte-identical, checked by SHA-256. The
clean format and locked-test checks passed all 20 tests offline with
`RUST_TEST_THREADS=2` and `CARGO_INCREMENTAL=0`. The implementation, API document,
audit manifest, workspace manifest and workspace lockfile stayed unchanged.

The cwa-007 in-tree run caught all 32 `caught` entries: all 41 required named
test runs built and failed at assertions. F-CWA7a accepted the module hidden
from the size's last byte in both custom-section tests; F-CWA7b refused their
plain-name controls on padding alone. F-CWA3a and F-CWA3b kept their original
bugs with updated anchors; F-CWA1d and F-CWA2d were caught unchanged. F-CWA0c
failed before tests because `--locked` refused the nested workspace's missing
lockfile. Every edited file restored byte-identical, checked by SHA-256. The
clean format and locked-test checks passed all 20 tests offline with
`RUST_TEST_THREADS=2` and `CARGO_INCREMENTAL=0`. The audit manifest, workspace
manifest and workspace lockfile stayed unchanged.

The cwa-009 in-tree run caught all 36 `caught` entries: all 46 required named
test runs built and failed at assertions. With only `elastos:bus/runtime@1.0.0`
declared, F-CWA9a accepted `elastos:bus/runtime@1.0.0+b1` and F-CWA9b accepted
`elastos:bus/runtime@1.0.0-rc.1`; each failed the exact-version refusal test.
The two-section fixture now uses one shared empty instance type, so the core
module is the only separator between its imports. Removing `(core module)` by
hand made both fixture callers fail at the section-count assertion: one section
instead of two. With the original anonymous types, removing that line had kept
two import sections. F-CWA5b again failed both the refusal and result checks on
the later filesystem import. F-CWA0c failed before tests because `--locked`
refused the nested workspace's missing lockfile. Every edited file, including
the fixture, restored byte-identical, checked by SHA-256. The clean format and
locked-test checks passed all 20 tests offline with `RUST_TEST_THREADS=2` and
`CARGO_INCREMENTAL=0`. The implementation, API document, audit manifest,
workspace manifest and workspace lockfile stayed unchanged.

The cwa-010 in-tree run caught F-CWA10a with the default features plus
`cm-implements` alone. `component_import_names_with_options_are_refused`
built and failed at case (b)'s option assertion: the message named
`(component (import "cache" (implements "wasi:filesystem/types@0.2.0") (instance)))`,
and the result was `Ok(["cache"])` instead of `Err(NotAComponent)`. Case (a),
`versionsuffix`, still returned `NotAComponent` and passed its checks first.
Case (c), `external-id`, is not reached: it needs the same feature as case (b),
where the test stops. The source restored byte-identical, checked by SHA-256.

The cwa-011 in-tree run caught F-CWA11a at `(ii) embedded core module:
hidden_name: padded size`: it returned `Ok([])` instead of
`Err(CodeInCustomSection)`. The top-level padded `hidden_name` case was still
refused under this change and passed its checks first, as did all earlier
custom-section cases. The clean test accepts the plain-name padded case in
both layouts and refuses the hidden module with v1's variant and string.
Including the 38 earlier entries, all 38 `caught` entries built and failed all
48 required named checks; F-CWA0c failed before tests because `--locked`
refused the nested workspace's missing lockfile. Every temporary edit restored
byte-identical, checked by SHA-256. The clean format and locked-test checks
passed all 20 tests offline with `RUST_TEST_THREADS=2` and `CARGO_INCREMENTAL=0`.
The implementation, API document, audit manifest, workspace manifest and
workspace lockfile stayed unchanged.

The cwa-012 in-tree run completed task 009's proof: its cwa-008 run left
F-CWA8a, F-CWA8b and the re-anchored F-CWA4f unrun. Applied alone, F-CWA8a
built and failed `audit_refusals_follow_the_documented_order` and
`component_refusals_follow_the_documented_order` at case (d): `audit` returned
`Err(CodeInCustomSection)` instead of `Err(Malformed)`, and `audit_component`
returned `Err(CodeInCustomSection)` instead of `Err(NotAComponent)`.
F-CWA8b built and failed `public_api_is_v1` with the assertion message
`INTERFACE.md: expected line #[derive(Debug, Clone, PartialEq, Eq)] at offset -1 from pub struct DeclaredImport {`.
F-CWA4f built and failed the same two refusal-order tests at case (c): `audit`
returned `Err(CodeInCustomSection)` instead of `Err(Malformed)`, and
`audit_component` returned `Err(CodeInCustomSection)` instead of
`Err(NotAComponent)`. All five named tests ran separately with `--exact`.
Every temporary edit restored byte-identical, checked by SHA-256;
`audit/Cargo.lock` stayed absent, and the implementation, API document, tests,
falsifier entries, audit manifest, workspace manifest and workspace lockfile
stayed unchanged. The final full sweep covered all 39 entries: all 38 `caught`
entries built and failed all 48 named test runs at assertions, and F-CWA0c
failed before tests because `--locked` refused the nested workspace's missing
lockfile. The clean format and locked-test checks passed before the first
mutation and after the sweep, with all 20 tests passing offline under
`RUST_TEST_THREADS=2` and `CARGO_INCREMENTAL=0`.

The cwa-013 in-tree run first applied F-CWA13a and F-CWA13b separately to the
base; each passed all 20 tests. With the two reverse pairs added,
`a_different_version_of_a_declared_interface_is_refused` built and failed at
its refusal assertion for each entry. F-CWA13a accepted
`elastos:bus/runtime@1.0.0` with only `elastos:bus/runtime@1.0.0+b1` declared
(pair (b)); pair (a)'s pre-release declaration still refused the release.
F-CWA13b accepted `elastos:bus/runtime@1.0.0` with only
`elastos:bus/runtime@1.0.0-rc.1` declared (pair (a)). Each returned
`Ok(["elastos:bus/runtime@1.0.0"])`. Temporary pair output confirmed that all
preceding pairs completed before each failure, then the source and test
restored byte-identical, checked by SHA-256. The clean test requires
`UndeclaredInterface` naming the release and the exact string
`undeclared interface elastos:bus/runtime@1.0.0` for both pairs.
The full sweep then covered all 41 entries with the test's final bytes:
all 40 `caught` entries built and failed all 50 named test runs at assertions,
and F-CWA0c failed before tests because `--locked` refused the nested
workspace's missing lockfile. Every temporary edit restored byte-identical,
checked by SHA-256, and `audit/Cargo.lock` stayed absent. The clean format and
locked-test checks passed before the mutations and after the sweep, with all
20 tests passing offline under `RUST_TEST_THREADS=2` and `CARGO_INCREMENTAL=0`.
The implementation, API document, audit manifest, workspace manifest and
workspace lockfile stayed unchanged.

The cwa-014 in-tree run first applied F-CWA14a to the base; all 20 tests
passed. With the crossed case added, `declared_import_passes_and_only_that_one`
built and failed at `assert_undeclared`'s `expect_err`, after the earlier cases
and the two-pair pass control passed. For the crossed import, `audit` returned
`Ok([DeclaredImport { module: "wasi_snapshot_preview1", name: "fd_write" }])`.
F-CWA1b built and failed the same test at the existing equal-count,
different-name case, returning
`Ok([DeclaredImport { module: "env", name: "second" }])` with only `env.first`
declared. Each temporary edit restored `src/lib.rs` byte-identical, checked
by SHA-256. All 47 edit anchors in the 42 entries occurred exactly once.
The clean format and locked-test checks passed before the first mutation
and after both catches, with all 20 tests passing offline under
`RUST_TEST_THREADS=2` and `CARGO_INCREMENTAL=0`. The implementation, API document,
other tests, audit manifest, workspace manifest and workspace lockfile stayed
unchanged, and `audit/Cargo.lock` stayed absent.

The cwa-015 in-tree run first applied F-CWA15a and F-CWA15b separately to the
base; all 20 tests passed under each before the new cases. With the exact-pair
pass control and both prefix cases added, each entry built and failed
`declared_import_passes_and_only_that_one` at `assert_undeclared`'s `expect_err`.
F-CWA15a failed at the name case: `audit` returned
`Ok([DeclaredImport { module: "wasi_snapshot_preview1", name: "fd_readdir" }])`.
F-CWA15b passed the name case's refusal checks, then failed at the module case:
`audit` returned
`Ok([DeclaredImport { module: "wasi:cli/environment@0.2.0-rc.1", name: "get-environment" }])`.
The earlier cases and the exact-pair pass control passed before each failure.
F-CWA1b still failed at the equal-count, different-name case, returning
`Ok([DeclaredImport { module: "env", name: "second" }])` with only `env.first`
declared. F-CWA14a still failed at the crossed case, returning
`Ok([DeclaredImport { module: "wasi_snapshot_preview1", name: "fd_write" }])`.
All four checked entries built and failed their named test at an assertion,
each run separately with `--exact`. Each temporary edit restored `src/lib.rs`
byte-identical, checked by SHA-256, and every falsifier's `old` text still
occurred exactly once. The clean format and locked-test checks passed before
the first mutation and after the catches, with all 20 tests passing offline
under `RUST_TEST_THREADS=2` and `CARGO_INCREMENTAL=0`. The implementation, API
document, other tests, audit manifest, workspace manifest and workspace lockfile
stayed unchanged, and `audit/Cargo.lock` stayed absent.
