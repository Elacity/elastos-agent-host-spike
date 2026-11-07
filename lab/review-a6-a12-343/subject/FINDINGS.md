# A6 / A12 evidence findings

Lab folder: `lab/a6-a12-evidence-fix/`. Base: `origin/spike/agent-host`
`9bb68053feea8426f33ade652f87f5ad47d03bb8`. Machine: Linux x86_64,
`rustc 1.91.0 (f8297e351 2025-10-28)`. Every path, line number, and count
below comes from a command run in this session.

## Did #323 or base already fix these?

No. Skip neither check.

- `gh pr view 323 --json title,state,body`: draft PR #323
  (`lab/redteam-fix: close lab-side M1 findings from #294`) is **OPEN**.
  Its table lists **A6 pending routing** and **A12 `/tmp/elastos/storage`**
  as **NEEDS RUNTIME**. It fixed s-expression contract checks, root-wide
  reads, and missing-tool tests as NOT RUN.
- `git log --oneline ce35224f..origin/spike/agent-host` is 6 commits
  (wasm-capsule 036, confine 078). None of them touch A6 or A12 evidence.
- The gap tests in this folder passed on that head, so the holes are still
  in the owner files.

## Wrong existing tests

Commands:

```
rg -n 'home\.temp\(\)|outside-root:BLOCKED|pub fn cleanup' lab/agent-conformance/src/census.rs
rg -n 'fn cleanup_census_refuses_each_leftover|home\.temp\(\)\.join\("planted"\)' lab/agent-conformance/tests/runtime.rs
rg -n 'fn two_instances_overlap_with_separate_grants|fn instance_grant_does_not_authorise_sibling' lab/agent-conformance/tests/effects.rs
rg -n 'WrongCapsule|from_base64|token\.capsule|caller_capsule' lab/agent-conformance/tests/common/grants.rs lab/agent-conformance/tests/effects.rs
rg -n 'For now, all requests go to pending' elastos/crates/elastos-server/src/api/handlers/capability.rs
rg -n 'if token\.capsule != caller_capsule_id' elastos/crates/elastos-runtime/src/capability/manager.rs
rg -n '"/tmp/elastos/storage"|PathBuf::from\("/tmp/elastos"\)' elastos/crates/elastos-server/src/run_cmd.rs elastos/crates/elastos-server/src/main.rs elastos/crates/elastos-server/src/share_cmd.rs elastos/crates/elastos-server/src/security_cmd.rs
rg -n 'create_dir_all' elastos/crates/elastos-storage/src/providers/local.rs
rg -n 'throwaway Homes require macOS' lab/agent-conformance/src/harness.rs
```

| File | Lines | Why it is not the claimed evidence |
| --- | --- | --- |
| `lab/agent-conformance/src/census.rs` | 79 (`cleanup`), 100 (`home.temp()`), 124 (`outside-root:BLOCKED(AC-006-STORAGE)`) | Temp walk is the throwaway TMPDIR only. Line 124 never walks `/tmp/elastos/storage`. |
| `lab/agent-conformance/tests/runtime.rs` | 324 `cleanup_census_refuses_each_leftover`, 340 `home.temp().join("planted")` | A leftover under `/tmp/elastos/storage` is not a failure. |
| `lab/agent-conformance/tests/effects.rs` | 657 `two_instances_overlap_with_separate_grants`, 662 `instance_grant_does_not_authorise_sibling` | Both call `exercise_read`. `rg` found **0** hits for `WrongCapsule`, `from_base64`, `token.capsule`, or `caller_capsule` in `effects.rs` or `grants.rs`. |
| `lab/agent-conformance/tests/common/grants.rs` | sibling deny path | Sibling refusal is the fixture deny, not Runtime `validate` step 4. |
| `elastos/crates/elastos-server/src/api/handlers/capability.rs` | 119 | `For now, all requests go to pending`. A live session grant does not change that answer. |
| `elastos/crates/elastos-runtime/src/capability/manager.rs` | 409–411 | The session-token check exists (`token.capsule != caller_capsule_id` → `wrong_capsule` / `WrongCapsule`). No A6 journey calls it. |
| `lab/agent-conformance/src/harness.rs` | 18 | `throwaway Homes require macOS`. Linux cannot run the owner journeys. |

Runtime-owned temp roots in production source (same `rg`):

| Path | Sites |
| --- | --- |
| `/tmp/elastos/storage` | `run_cmd.rs` 62, 70, 236; `main.rs` 123; `share_cmd.rs` 183 |
| `/tmp/elastos` | `security_cmd.rs` 26 |

`LocalFSProvider::new` (`elastos/crates/elastos-storage/src/providers/local.rs` 20) calls `create_dir_all` on that path.

## Corrected checks

- **A6** `tests::a6_owner_may_use_own_session_token` +
  `tests::a6_sibling_presenting_owner_token_is_refused`: owner use is
  accepted; sibling presentation is refused with
  `wrong_capsule expected:instance-1 got:instance-2`.
  `tests::a6_runtime_session_token_check_is_present` requires Runtime step 4
  in `manager.rs`. `tests::a6_absent_runtime_session_token_check_is_caught`
  deletes that `if` from a copy of the source and requires the pin to fail.
- **A12** `runtime_temp_census` walks `/tmp/elastos/storage` and
  `/tmp/elastos`. Existence of the path, an empty directory, or a file is a
  leftover. `cleanup_with_runtime_temps` merges a `census::cleanup` result
  with that walk. `tests::a12_planted_storage_file_is_caught` plants
  `/tmp/elastos/storage/a6-a12-evidence-fix-planted`.

## Status of A6 / A12

Unchanged: **in-flight, not counted**. Anders's rule needs a complete
resident-instance journey, a refusal with a reason, and a CAUGHT falsifier.
The resident-instance half stays out of scope. These rows do not raise the
M1 score.

## Verdicts

Command (this machine):

```
CARGO_TARGET_DIR="$PWD/lab/a6-a12-evidence-fix/target" \
RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 \
cargo test --locked --offline --manifest-path lab/a6-a12-evidence-fix/Cargo.toml --lib -- --nocapture
```

Result line: `test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.68s`.
`./lab/a6-a12-evidence-fix/run.sh` printed the same 16/0 result in 0.63s.

`cargo test --lib -- --list` printed `16 tests, 0 benchmarks`.

| Check | Verdict | Notes from that run |
| --- | --- | --- |
| A6 owner token accepted | **PASS** | `A6 journey: instance-1 may use its session token` |
| A6 sibling token refused with reason | **PASS** | `A6 refusal: wrong_capsule expected:instance-1 got:instance-2` |
| A6 Runtime step 4 present | **PASS** | `Runtime validate step 4 (session-token / capsule bind) is present` |
| A6 absent step 4 (source copy) | **CAUGHT** | `Runtime session-token check is absent` |
| A6 F-A6-NO-TOKEN-CHECK | **CAUGHT** | `CAUGHT F-A6-NO-TOKEN-CHECK by tests::a6_sibling_presenting_owner_token_is_refused` |
| A6 full harness journeys | **NOT RUN** | `throwaway Homes require macOS`; resident instances out of scope |
| A12 lists storage root | **PASS** | `A12 roots: ["/tmp/elastos/storage", "/tmp/elastos"]` |
| A12 planted file | **CAUGHT** | `FAIL leftovers:3 paths:["/tmp/elastos", "/tmp/elastos/storage", "/tmp/elastos/storage/a6-a12-evidence-fix-planted"]` |
| A12 empty root | **PASS** | empty dir is a leftover |
| A12 F-A12-DROP-ROOTS | **CAUGHT** | caught by `tests::a12_census_lists_runtime_storage` and `tests::a12_planted_storage_file_is_caught` |
| A12 wrap vs existing PASS | **PASS** | existing `root checks PASS` + `outside-root:BLOCKED` still fails the wrap when storage is planted |
| A12 in-root `census::cleanup` | **NOT RUN** | Linux; `ThrowawayHome` (`harness.rs` 18) |
| Existing A6/A12 gap pins | **PASS** | owner files still have the #294 holes |

After the suite, `ls /tmp/elastos` printed `No such file or directory` (the
planted file and the dirs this folder created were removed).

## Falsifiers

| Id | What it breaks | Named tests that FAILED |
| --- | --- | --- |
| F-A6-NO-TOKEN-CHECK | `if token_capsule != caller_capsule` becomes `if false && ...` | `tests::a6_sibling_presenting_owner_token_is_refused` |
| A6 source delete | removes `if token.capsule != caller_capsule_id` from a copy of `manager.rs` | `tests::a6_absent_runtime_session_token_check_is_caught` |
| F-A12-DROP-ROOTS | `RUNTIME_TEMP_ROOTS` becomes empty | `tests::a12_census_lists_runtime_storage`, `tests::a12_planted_storage_file_is_caught` |
| A12 planted file | writes `/tmp/elastos/storage/a6-a12-evidence-fix-planted` | `tests::a12_planted_storage_file_is_caught` (leftovers: **3**) |
