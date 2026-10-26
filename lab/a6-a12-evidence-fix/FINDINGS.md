# A6 / A12 evidence findings

Lab folder: `lab/a6-a12-evidence-fix/`. Base: `spike/agent-host`. This file
is updated after the commands in `run.sh`. Every path and line number below
comes from a command run in this session.

## Did #323 or base already fix these?

No. Skip neither check.

- Draft PR #323 (`lab/redteam-fix`) lists **A6 pending routing** and **A12
  `/tmp/elastos/storage`** as **NEEDS RUNTIME**. It fixed s-expression
  contract checks, root-wide reads, and missing-tool tests as NOT RUN.
- #323 is open and not merged. Current `origin/spike/agent-host` still has
  the #294 holes (commands below).

## Wrong existing tests

| File | Lines | Why it is not the claimed evidence |
| --- | --- | --- |
| `lab/agent-conformance/src/census.rs` | 99–103, 124 | Temp walk is `home.temp()` only. Line 124 prints `outside-root:BLOCKED(AC-006-STORAGE)` and never walks `/tmp/elastos/storage`. |
| `lab/agent-conformance/tests/runtime.rs` | `cleanup_census_refuses_each_leftover` (323–397), plant at 340 | Plants `home.temp().join("planted")`. A leftover under `/tmp/elastos/storage` is not a failure. |
| `lab/agent-conformance/tests/effects.rs` | 657–664 | `two_instances_overlap_with_separate_grants` and `instance_grant_does_not_authorise_sibling` call `exercise_read`. They never present a grant token. |
| `lab/agent-conformance/tests/common/grants.rs` | sibling deny path (see `Denied` / fixture deny) | Sibling refusal is the fixture's `POST /api/capability/deny`, not Runtime `validate` step 4. |
| `elastos/crates/elastos-server/src/api/handlers/capability.rs` | 119–141 | `request_capability` sends every request to pending. A live session grant does not change that answer. |
| `elastos/crates/elastos-runtime/src/capability/manager.rs` | 409–415 | The session-token check exists (`token.capsule != caller_capsule_id` → `WrongCapsule`). No A6 journey calls it. |

Runtime-owned temp roots found in production source (not test-only strings):

| Path | Sites |
| --- | --- |
| `/tmp/elastos/storage` | `run_cmd.rs` 62, 70, 236; `main.rs` 123 (`serve --storage-path` default); `share_cmd.rs` 183 |
| `/tmp/elastos` | `security_cmd.rs` 26 (data-dir fallback parent) |

`LocalFSProvider::new` (`elastos/crates/elastos-storage/src/providers/local.rs` 18–20) creates the storage directory.

## Corrected checks

- **A6** `a6_owner_may_use_own_session_token` + `a6_sibling_presenting_owner_token_is_refused`: owner use is accepted; sibling presentation is refused with `wrong_capsule expected:instance-1 got:instance-2`. `a6_runtime_session_token_check_is_present` requires Runtime step 4 in source. `a6_absent_runtime_session_token_check_is_caught` deletes that `if` from a copy of the source and requires the pin to fail.
- **A12** `runtime_temp_census` walks `/tmp/elastos/storage` and `/tmp/elastos`. Existence of the path, an empty directory, or a file is a leftover. `cleanup_with_runtime_temps` imports `agent_conformance::census::cleanup` and merges it with that walk. `a12_planted_storage_file_is_caught` plants `/tmp/elastos/storage/a6-a12-evidence-fix-planted`.

## Status of A6 / A12

Unchanged: **in-flight, not counted**. Anders's rule needs a complete
resident-instance journey, a refusal with a reason, and a CAUGHT falsifier.
The resident-instance half stays out of scope. The new rows do not raise the
M1 score.

## Verdicts

Filled after `run.sh`. Placeholder until that command runs.

| Check | Verdict | Notes |
| --- | --- | --- |
| A6 owner token accepted | (pending run) | |
| A6 sibling token refused with reason | (pending run) | |
| A6 Runtime step 4 present | (pending run) | |
| A6 absent step 4 CAUGHT | (pending run) | |
| A6 F-A6-NO-TOKEN-CHECK | (pending run) | |
| A6 full harness journeys | NOT RUN | throwaway Homes require macOS; resident instances out of scope |
| A12 lists storage root | (pending run) | |
| A12 planted file CAUGHT | (pending run) | |
| A12 F-A12-DROP-ROOTS | (pending run) | |
| A12 in-root `census::cleanup` | NOT RUN on Linux | `ThrowawayHome` (`harness.rs` 16–18) |

## Falsifiers

| Id | What it breaks | Named tests that must FAIL |
| --- | --- | --- |
| F-A6-NO-TOKEN-CHECK | `if token_capsule != caller_capsule` becomes `if false && ...` | `a6_sibling_presenting_owner_token_is_refused` |
| A6 source delete | removes `if token.capsule != caller_capsule_id` from a copy of `manager.rs` | `a6_absent_runtime_session_token_check_is_caught` |
| F-A12-DROP-ROOTS | `RUNTIME_TEMP_ROOTS` becomes empty | `a12_census_lists_runtime_storage`, `a12_planted_storage_file_is_caught` |
| A12 planted file | writes `/tmp/elastos/storage/a6-a12-evidence-fix-planted` | `a12_planted_storage_file_is_caught` |
