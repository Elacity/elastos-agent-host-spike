# A6 / A12 evidence findings

Lab folder: `lab/a6-a12-evidence-fix/`. Head is this branch. Machine: Linux
x86_64, `rustc 1.91.0`. Every path, line number, and count below comes from a
command run in this session.

## Plain status

#343 now mints a real Runtime session token and calls real `validate`. It
also walks leftovers under `ELASTOS_TMP_ROOT` (default `/tmp/elastos`) after
creating a storage leftover, and it calls `ThrowawayHome::new` /
`census::cleanup`. That Linux journey is still not two resident capsule
instances inside one Runtime, so A6 and A12 stay in-flight.

## Did #323 or base already fix these?

No. Skip neither check.

- Draft PR #323 still lists **A6 pending routing** and **A12
  `/tmp/elastos/storage`** as **NEEDS RUNTIME**.
- The gap tests in this folder still pass: owner A6 rows do not present a
  token, and owner `census.rs` still does not name `/tmp/elastos/storage`.

## Wrong existing tests

| File | Lines | Why it is not the claimed evidence |
| --- | --- | --- |
| `lab/agent-conformance/src/census.rs` | 79, 100, 124 | Temp walk is the throwaway TMPDIR only. Line 124 never walks `/tmp/elastos/storage`. |
| `lab/agent-conformance/tests/runtime.rs` | 324, 340 | A leftover under `/tmp/elastos/storage` is not a failure. |
| `lab/agent-conformance/tests/effects.rs` | 657, 662 | Both call `exercise_read`. No `WrongCapsule` / `from_base64`. |
| `lab/agent-conformance/tests/common/grants.rs` | sibling deny | Fixture deny, not Runtime `validate` step 4. |
| `elastos/crates/elastos-server/src/api/handlers/capability.rs` | 119 | Every request still goes to pending. |
| `elastos/crates/elastos-runtime/src/capability/manager.rs` | 409–411 | Step 4 exists. This folder now calls it. Owner A6 journeys still do not. |
| `lab/agent-conformance/src/harness.rs` | 18 | Throwaway Homes require macOS. |

## Corrected checks

- **A6** `Session::mint_instance1` calls `CapabilityManager::grant`, then
  `from_base64` / `validate`. Owner use is `Ok`. Sibling use is
  `ValidationError::WrongCapsule { expected, got }` with those two fields
  compared. Prefix (`instance-1-evil`) and empty-capsule tokens are refused
  the same way. Commenting out Runtime step 4 is a plant, not a substring pin.
- **A12** roots are `ELASTOS_TMP_ROOT` (default `/tmp/elastos`) and
  `{root}/storage`. `create_runtime_storage_leftover` creates the storage
  tree a run would create. Symlink roots are resolved. Renamed trees are
  found by leftover-marker bytes. A clean missing root is PASS.
  `ThrowawayHome::new` + `census::cleanup` are invoked; Linux is NOT RUN.

## Linux vs resident instances

This crate builds one in-process `CapabilityManager` and two capsule ids
(`instance-1`, `instance-2`). That is the Runtime grant/validate path. It is
not two independent resident capsule instances inside one running Home.
Anders's A6/A12 bookability rule still needs that resident journey on a Mac.

## Verdicts

Command:

```
CARGO_TARGET_DIR="$PWD/lab/a6-a12-evidence-fix/target" \
RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 \
cargo test --locked --offline --manifest-path lab/a6-a12-evidence-fix/Cargo.toml --lib -- --nocapture
```

| Check | Verdict | Notes |
| --- | --- | --- |
| A6 owner token accepted | **PASS** | real `grant` + `validate` as instance-1 |
| A6 sibling token refused | **PASS** | `WrongCapsule { expected:instance-1 got:instance-2 }` |
| A6 prefix capsule id | **PASS** | instance-1 vs instance-1-evil |
| A6 empty token capsule | **PASS** | `from_base64("")` fails; empty grant is WrongCapsule |
| A6 F-A6-NO-TOKEN-CHECK | **CAUGHT** | plant comments out Runtime step 4 |
| A6 M-A6-PREFIX-BIND | **CAUGHT** | `starts_with` accepts instance-1-evil |
| A6 M-A6-EMPTY-TOKEN | **CAUGHT** | empty capsule skips the check |
| A6 M-A6-COMMENT-STEP4 | **CAUGHT** | sibling `validate` would succeed |
| A6 resident instances | **NOT RUN** | needs macOS throwaway Home + two live capsules |
| A12 lists storage root | **PASS** | honours `ELASTOS_TMP_ROOT` |
| A12 clean isolated root | **PASS** | leftovers:0; kills hardcoded FAIL |
| A12 planted file | **CAUGHT** | isolated `{root}/storage` leftover |
| A12 symlink root | **PASS** | resolved and scanned through |
| A12 renamed root | **PASS** | found by leftover marker |
| A12 M-A12-HARDCODE-FAIL | **CAUGHT** | clean PASS test fails |
| A12 M-A12-SYMLINK-ROOT | **CAUGHT** | nested leftover hidden |
| A12 M-A12-RENAME-ROOT | **CAUGHT** | bak tree hidden |
| A12 F-A12-DROP-ROOTS | **CAUGHT** | empty roots |
| A12 ELASTOS_TMP_ROOT | **PASS** | nothing written under `/tmp/elastos` |
| A12 in-root `census::cleanup` | **NOT RUN** | `ThrowawayHome::new` refused on Linux |
| Existing A6/A12 gap pins | **PASS** | owner files still have the #294 holes |

## Falsifiers

| Id | What it breaks | Named tests that FAILED |
| --- | --- | --- |
| F-A6-NO-TOKEN-CHECK | Runtime `if token.capsule != caller` becomes `if false &&` | `tests::a6_sibling_presenting_owner_token_is_refused` |
| M-A6-PREFIX-BIND | `!=` becomes `!caller.starts_with(token)` | `tests::a6_prefix_capsule_id_is_refused` |
| M-A6-EMPTY-TOKEN | skip the check when `token.capsule` is empty | `tests::a6_empty_token_capsule_is_refused` |
| M-A6-COMMENT-STEP4 | delete Runtime step 4 | `tests::a6_sibling_presenting_owner_token_is_refused` |
| F-A12-DROP-ROOTS | `runtime_owned_temp_roots` returns empty | `tests::a12_census_lists_runtime_storage`, `tests::a12_planted_storage_file_is_caught` |
| M-A12-HARDCODE-FAIL | census always returns FAIL | `tests::a12_clean_isolated_root_passes` |
| M-A12-SYMLINK-ROOT | do not scan through a symlink root | `tests::a12_symlink_root_is_scanned_through` |
| M-A12-RENAME-ROOT | do not scan rename siblings for the marker | `tests::a12_renamed_root_is_found_by_marker` |

## NOT RUN (macOS / resident instances)

```
cargo test --manifest-path lab/agent-conformance/Cargo.toml --test effects \
  two_instances_overlap_with_separate_grants -- --nocapture
cargo test --manifest-path lab/agent-conformance/Cargo.toml --test effects \
  instance_grant_does_not_authorise_sibling -- --nocapture
cargo test --manifest-path lab/agent-conformance/Cargo.toml --test runtime \
  cleanup_census_refuses_each_leftover -- --nocapture
```

A new A6 journey that presents instance-1's token as a second *resident*
instance still needs Anders's Runtime. This Linux crate does not start that
Home.
