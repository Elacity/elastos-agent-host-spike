# Review of draft PR #343

Independent adversarial review of the A6 / A12 evidence-fix in draft PR
#343 (`cursor/a6-a12-evidence-fix-6e3b`). This folder only adds
`lab/review-a6-a12-343/`. It does not edit #343's branch, other `lab/`
folders, `BACKLOG.md`, `lane.env`, `scripts/`, or Runtime source.

- Target: #343 head `011d01f283a3f4ed4717383ecedf55622d451b4d`
  (live head; no later commit).
- Base of #343: `spike/agent-host` at `9bb68053feea8426f33ade652f87f5ad47d03bb8`.
- This review: `cursor/review-a6-a12-343-d684` from current
  `origin/spike/agent-host` `3fee89ff88d0d42f1c201e2ff2fa92923301190d`.
- Review PR: https://github.com/Elacity/elastos-agent-host-spike/pull/365
- Machine: Linux x86_64, `rustc 1.91.0 (f8297e351 2025-10-28)`,
  Python 3.12.3. No macOS.
- How to run: `lab/review-a6-a12-343/run.sh`.
  Cargo holds/weak stay green. Python FALSIFIED tests fail on this head.

Anders's rule, as given for this review: an M1 check counts only when its
complete journey, refusal evidence, and required reviews all pass. Every
#343 claim was treated as unverified until a command on this machine
showed it.

## Verdict

**A6 is not bookable. A12 is not bookable.**

#343's own 16 lib tests passed here, and its four named plants were
CAUGHT. That suite is a local string mock plus a walk of two fixed
`/tmp` names. It does not present a session token to Runtime `validate`,
and it does not call `census::cleanup` or `ThrowawayHome`. The owner A6
rows and the in-root A12 census stay NOT RUN on Linux. The macOS branch
in `in_root_census_on_this_host` is also an explicit NotRun.

#323 still lists A6 pending routing and A12 `/tmp/elastos/storage` as
NEEDS RUNTIME. This review does not close those rows.

## Commands run

Subject suite, worktree `/tmp/pr343` at `011d01f2`, no edits:

```
./lab/a6-a12-evidence-fix/run.sh
```

Result: `ok. 16 passed; 0 failed; 0 ignored` in 0.75s.
After the run: worktree clean; `ls /tmp/elastos` → No such file or
directory.

Review crate:

```
CARGO_TARGET_DIR=lab/review-a6-a12-343/target \
cargo test --offline --manifest-path lab/review-a6-a12-343/Cargo.toml --lib -- --nocapture
```

Result: `ok. 18 passed; 0 failed; 0 ignored` in 0.01s.

Review mutants and claim tests:

```
python3 -I -m unittest discover -s lab/review-a6-a12-343/py -v
```

Result: `Ran 17 tests in 2.706s` / `FAILED (failures=8)`.
9 HOLDS/WEAK tests passed. 8 FALSIFIED tests failed.

Not run here: agent-conformance A6/A12 journeys (`ThrowawayHome` needs
macOS). Compiling that crate pulls Runtime; this review did not do that.

## Per-claim table

| Claim | Verdict | Evidence |
| --- | --- | --- |
| 16 named lib tests pass | **HOLDS** | `--list` printed those 16 names; `run.sh` printed `16 passed` |
| F-A6-NO-TOKEN-CHECK (`if false &&`) is CAUGHT | **HOLDS** | subject plant + this review's re-run: sibling test FAILED |
| Delete `if token.capsule != caller_capsule_id` from a copy of `manager.rs` | **HOLDS** | `a6_absent_runtime_session_token_check_is_caught` and `holds::a6_runtime_step4_source_pin_and_delete_falsifier` |
| F-A12-DROP-ROOTS (empty `RUNTIME_TEMP_ROOTS`) is CAUGHT | **HOLDS** | subject plant + this review's re-run: list and plant tests FAILED |
| Planted `/tmp/elastos/storage/a6-a12-evidence-fix-planted` → `FAIL leftovers:3` | **HOLDS** | exact line from the subject run |
| Empty isolated dir is a leftover | **HOLDS** | `a12_empty_root_is_leftover` and `holds::a12_isolated_walk_sees_empty_dir_and_nested_file` |
| Child symlink is listed and not followed | **HOLDS** | `a12_symlink_root_is_leftover_and_not_followed` |
| Cited owner lines exist and say what FINDINGS.md says | **HOLDS** | `git show 011d01f2:<file>` at the cited lines; same lines on current `spike/agent-host` |
| Existing A6 rows have 0 `WrongCapsule` / `from_base64` / `token.capsule` / `caller_capsule` hits | **HOLDS** | `rg` on `effects.rs` and `grants.rs` |
| `capability.rs:119` still sends every request to pending | **HOLDS** | source pin; live grant does not change that path |
| `harness.rs:18` requires macOS | **HOLDS** | source pin; in-root census printed NOT RUN |
| Full A6/A12 harness journeys NOT RUN on Linux | **HOLDS** | honest skip; this host is not macOS |
| Sibling refusal reason is `wrong_capsule expected:instance-1 got:instance-2`, not a generic `denied` | **WEAK** | generic `denied` is CAUGHT; any error that contains those three substrings still passes; the mock builds that string itself |
| Instance-1 may use its session token | **WEAK** | the "token" is the string `"instance-1"`; no `CapabilityToken`, no `from_base64`, no `validate` |
| Runtime validate step 4 is present | **WEAK** | substring pin; commenting out the `if` still counts as present |
| Combined wrap fails when storage is planted | **WEAK** | wrap is `merge_host` plus a **hardcoded** existing PASS line; it does not call `census::cleanup` |
| Census includes `/tmp/elastos/storage` and `/tmp/elastos` | **WEAK** | the constant lists those names and `leftovers_under` can walk them; `a12_census_lists_runtime_storage` does not call the walk; a hardcoded FAIL survives the list+plant pair |
| Invokes existing census and `ThrowawayHome` by source and name | **FALSIFIED** | `include_str!` and two string constants; no `census::cleanup(` call; no `ThrowawayHome::new`; macOS path is still NotRun |
| Sibling capsule cannot use the owner's token/grant (M1 A6) | **FALSIFIED** | no token is presented; request path still goes to pending; fixture deny is still the owner refusal |
| Census cannot be fooled by a symlink-named root or a renamed dir | **FALSIFIED** | symlink root hides nested files; rename of the walked name hides the old tree |
| These checks make A6 or A12 bookable | **FALSIFIED** | see bookability below |

#343's FINDINGS.md table of "wrong existing tests" is itself **HOLDS**:
`census.rs` 79/100/124 walk the throwaway TMPDIR and label
`outside-root:BLOCKED(AC-006-STORAGE)`; `runtime.rs` 324/340 plants under
`home.temp()`; `effects.rs` 657/662 call `exercise_read` and never
present a token; `manager.rs` 409–411 is live Runtime code that no A6
journey calls.

## Surviving mutants

These were applied to a copy of the snapshot crate. The named #343 tests
still passed.

| Id | Change | Named tests | Result |
| --- | --- | --- | --- |
| M-A6-PREFIX-BIND | `!=` → `!caller.starts_with(token)` | owner + sibling | **SURVIVED**. Extra case `instance-1` / `instance-1-evil` is accepted. |
| M-A6-EMPTY-TOKEN | skip the check when the token string is empty | owner + sibling | **SURVIVED**. `("", "")` and `("", "instance-2")` are accepted. |
| M-A6-COMMENT-STEP4 | comment out the Runtime `if` in a source copy | `runtime_step4_present` | **SURVIVED**. The pin is a substring search. |
| M-A12-HARDCODE-FAIL | `runtime_temp_census` always returns the planted FAIL line | list + plant | **SURVIVED**. There is no clean-PASS test of `runtime_temp_census`. |
| M-A12-SYMLINK-ROOT | walk a symlink whose target holds a file | `leftovers_under` | **SURVIVED** as a hide: the file is absent from leftovers. |
| M-A12-RENAME-ROOT | rename the walked root, recreate the name empty | `leftovers_under` | **SURVIVED** as a hide: the bak tree is not listed. |

Caught controls (not survivors):

| Id | Result |
| --- | --- |
| F-A6-NO-TOKEN-CHECK | **CAUGHT** by `tests::a6_sibling_presenting_owner_token_is_refused` |
| F-A12-DROP-ROOTS | **CAUGHT** by list + plant |
| M-A6-GENERIC-DENIED | **CAUGHT** by the sibling test (reason must name `wrong_capsule`) |

A plant that only refuses the sibling and always returns the three
substrings also satisfies the sibling test. F-A6 does not require the
owner test in the same plant file.

## A6 bookability

**Not bookable.**

Needed for Anders's rule: two resident instances, instance-1 uses its
own session token through Runtime `validate`, instance-2 presents that
token and is refused with `wrong_capsule` (or the typed
`WrongCapsule { expected, got }`), and removing validate step 4 fails
that journey.

What #343 ran: `session_token_binds_caller("instance-1", "instance-2")`.
`capability.rs:119` still sends every request to pending. The owner A6
rows still refuse the sibling by fixture deny. Prefix and empty-token
mutants survive the named tests. Full journeys: NOT RUN.

## A12 bookability

**Not bookable.**

Needed: after a real Home / `run` journey, leftovers under
`/tmp/elastos/storage` (and the throwaway root) fail the owner census,
including when the name is a symlink or has been renamed, and the
in-root `census::cleanup` runs.

What #343 ran: a lab walk of two fixed paths, plus a wrap that feeds a
forged `root checks PASS; ... outside-root:BLOCKED(AC-006-STORAGE)`
string. `census.rs:124` still prints that block label and still does not
name `/tmp/elastos/storage`. `in_root_census_on_this_host` is NotRun on
Linux and on macOS. A hardcoded FAIL survives the list+plant pair.
Symlink roots and renamed roots hide files.

The walk of a real directory at `/tmp/elastos/storage` is real when that
path is an ordinary directory. That is not the owner A12 journey.

## What remains for a Mac run

1. `ThrowawayHome` A6 rows: `two_instances_overlap_with_separate_grants`
   and `instance_grant_does_not_authorise_sibling`. Expect fixture deny,
   not `WrongCapsule`, until a new journey presents instance-1's token
   as instance-2.
2. A new A6 journey that mints a real session token, calls Runtime
   `validate` as the sibling, and fails when step 4 is removed from the
   Runtime the journey actually loaded.
3. Owner `census::cleanup` after a real `run` that constructs
   `/tmp/elastos/storage` (`run_cmd.rs` 62, 70, 236;
   `LocalFSProvider::new` `create_dir_all`).
4. Prove leftovers behind a symlink-named storage root and after a
   rename of `/tmp/elastos`.
5. Resident instances. #343 leaves them out of scope. #323 still says
   NEEDS RUNTIME.

#343's own macOS branch will not do items 3–5: it returns NotRun with
"resident instances are out of scope on this task".

## Principles

- 3 No ambient authority: A6 still does not bind a token to a caller.
- 11 Fail closed, then explain: the mock can name `wrong_capsule`; the
  live request path still goes to pending.
- 12 Docs, code, tests, and operations must agree: FINDINGS.md's gap
  pins match the owner sources; the "invoke by name" wording does not
  match the code.

DeepSeek: none.
