# Adversarial review of PR #290 (M1 check A9)

Draft only. Do not merge. This folder does not edit `lab/owned-storage/`.

```text
Lane:         lab/review-a9-290
Branch / PR:  cursor/review-a9-290-1a8b  (this PR)
Reviewed:     Elacity/elastos-agent-host-spike#290
Head:         c0b16491076c30366a3504066499c9f5ad831ef2
Tree:         /tmp/pr-290-readonly (origin/cursor/owned-storage-a9-9b7c, read-only)
Base of #290: spike/agent-host at the #290 merge-base
This branch:  origin/spike/agent-host 3818e38ca91d2a3123ae25382a9643f195235baf
Machine:      Linux x86_64 cloud VM, rustc 1.91.0, no KVM, no elastos on PATH
```

## A9 wording used here

The tracker is not in this repository (`milestones.json` is absent). The
wording this review holds #290 to, as given for M1 check A9:

> another agent's files are denied

Anders's counting rule, as given for this review: a check counts only when
its whole journey as worded passes (not a lab half), with a refusal that
carries a reason, a CAUGHT falsifier, and both lane reviewers at merge.

#290's own body names the check as lab only: one agent cannot read or write
another agent's files. Tracker status for A9 is in-flight. A9 depends on A5
owned storage. Draft #309 lists RA-3 (`run` storage from Home) as the small
Runtime ask for A9. AC-006-STORAGE is the standing launcher blocker in
`lab/agent-conformance/GAPS.md`.

## How this review ran

`run.py` attaches a detached worktree at the reviewed SHA, runs #290's own
commands, then compiles `probe.rs` against that crate through a scratch
manifest under `/tmp/review-a9-290-crate`. The probe calls only public
`owned-storage` APIs plus host `fs` on the paths `host_root()` returns. It
does not start `elastos`. It does not create `/tmp/elastos/storage`.

Session results live in `last-run.json` after `python3 -I lab/review-a9-290/run.py`.
This session: fmt check clean; 8 tests passed, 0 ignored; clippy `-D warnings`
clean; probe 19 FINDING lines; `lib.rs` /
`launch.rs` SHA-256 unchanged
(`a3a1f920…d6481b`, `79b5a46d…a19864`); worktree clean;
`/tmp/elastos/storage` absent before and after.

## Findings

| ID | Claim | Verdict | Reproducer |
| --- | --- | --- | --- |
| api-read-write | Agent B cannot read or write A's files through the Store API | HOLDS | `Store::read` / `write` of the other grant's host path returns `Refuse::CrossAgent`. Bytes on disk stay `b-secret`. Official tests `agent_a_is_denied_b_directly` and `agent_a_reads_and_writes_its_own_storage` (other instance / other session) match. |
| api-traversal | A `..` path cannot walk from A into B | HOLDS | `../../../agent-b/session-b/2/secret.txt` returns `Refuse::Traversal`. Official `agent_a_is_denied_b_through_a_parent_path`. |
| api-symlink | A symlink that leaves the owned root is refused by the Store | HOLDS | `read("via-a")` / `write("via-b")` return `Refuse::Symlink`. Official `agent_a_is_denied_b_through_a_symlink`. |
| api-list-absent | Agent B cannot list A's files | WEAK | The crate has no `list`. A missing method is not a denial. The host walk in `host-list` lists the names. |
| api-rename-absent | Agent B cannot rename into A's files | WEAK | The crate has no `rename`. The host rename in `host-rename-into` moves the file. |
| host-list | From B's host root, B can list A's files | FALSIFIED | `read_dir(B/../../../agent-a/session-a/1)` returns `note.txt`. Same uid, mode `0755` siblings. |
| host-read | From B's host root, B can read A's bytes | FALSIFIED | `fs::read` of that sibling path returns `hello-a`. |
| host-write | From B's host root, B can write A's files | FALSIFIED | `fs::write(..., "planted-by-b.txt")` then `Store::read(&a, "planted-by-b.txt")` returns `from-b`. |
| host-rename-into | B can rename A's file into B's root | FALSIFIED | `fs::rename(A/note.txt, B/from-a.txt)`. `Store::read(&b, "from-a.txt")` returns `hello-a`. |
| host-hardlink | B can hard-link A's inode and read it through the Store | FALSIFIED | `hard_link(A/note.txt, B/hard.txt)`. `Store::read(&b, "hard.txt")` returns A's bytes. A later write of A's file is visible through B's name. The Store treats a hard link as a regular file inside B. |
| host-symlink | B can create a host symlink to A's file | FALSIFIED | `symlink(A/note.txt, B/via-a)` then `fs::read` returns `hello-a`. The Store refuses the same name (`api-symlink`). Denial is the fixture, not the host. |
| root-symlink-swap | Replacing A's directory with a symlink to B bypasses the Store | FALSIFIED | `remove_dir_all(A_root); symlink(B_root, A_root)`. `contained()` is lexical on the stored path, so `read(&a, "secret.txt")` returns B's bytes and `write` lands in B. |
| specific-reason | A lab denial carries a specific reason | HOLDS | Distinct strings: `cross-agent storage is refused`, `path traversal is refused`, `symlink leaves the owned root`, `shared temp directory is not agent storage`, `storage was removed`. |
| lab-shared-temp | The lab store still falls back to `/tmp/elastos/storage` | HOLDS (lab does not) | `Store::open("/tmp/elastos/storage")` is `Refuse::SharedTemp` and does not create the directory. Official `shared_temp_directory_is_refused`. |
| runtime-shared-temp | The Runtime still falls back to `/tmp/elastos/storage` | FALSIFIED | `run_cmd.rs` still has three `create_runtime("/tmp/elastos/storage")` calls (`:62`, `:70`, `:236`). `share_cmd.rs:183` is a fourth site #290's count of 3 does not include. `serve` default is the same path. |
| runtime-enforced | The denial is enforced by the Runtime | FALSIFIED | `real_runtime_journey()` is `RowState::Blocked`, `executed=false`, `read_refusal=None`. Object reads use the Home data directory, not `_storage` (`runtime.rs:42-44`). RA-3 / AC-006-STORAGE. |
| blocked-not-skip-pass | A skipped test is counted as a pass | HOLDS | #290 has no `#[ignore]`. The Runtime rows are BLOCKED inside a passing tripwire. That tripwire does not mark A9 ready. |
| grant-shape-a5 | A9's grant is the A5 owned-storage binding | WEAK | Field names match `grant_binding::Decision` (`identity`, `session`, `instance`, `owned_root`). The resource is `UsersAI/<id>/<session>/<instance>`. A5 stores `UsersAI/<agent>/<rest>` (example `UsersAI/agent-1/notes`). This crate does not call `lab/grant-binding`. A5's README says that crate counts toward no M1 check. |
| host-root-api | Isolation stays inside the fixture | WEAK | `host_root()` exists so tests can feed a foreign host path. It also hands a live directory to any caller. The OS does not confine that directory. |
| plant-share | The falsifier fails when the protection is removed | HOLDS | `plants/F-A9-share.txt` makes every instance use `yard/shared`. Official `planted_shared_root_is_caught` requires `agent_a_is_denied_b_directly`, `..._through_a_parent_path`, and `..._through_a_symlink` to print `FAILED`. Direct and symlink then see B's bytes. Parent-path still returns `Traversal` and fails only on `assert_ne!(A_root, B_root)`. |
| plant-fake-runtime | Marking Runtime rows Ready without a run is caught | HOLDS | `plants/F-A9-fake-runtime.txt` sets `RowState::Ready`. `real_runtime_rows_match_the_launcher` fails because the three literals remain and there is no captured refusal. |

Verdict words: **HOLDS** = the claim as worded stood on this head. **FALSIFIED**
= a concrete run broke the claim. **WEAK** = the crate never tests that
operation, or the proof is a tripwire / field-name match rather than the
journey.

## Bookability under Anders's rule

**A9 is not bookable.**

The wording is "another agent's files are denied". The product journey is two
agent instances on the Runtime. #290 is a lab store in one process. It does
not start a component. GitHub has no review objects on #290 (`reviews: []`).
The PR is draft.

What would be required to book A9, and is missing:

| Gate | Present on #290? |
| --- | --- |
| Whole journey as worded (two Runtime agents; B cannot read/list/write/rename/link A's files) | No. Lab `read`/`write` only. |
| Refusal that carries a reason | Lab yes. Runtime row empty. |
| CAUGHT falsifier | Lab plants yes. No Runtime plant that shows a live refusal disappear. |
| Both lane reviewers at merge | No reviews. Draft. |

## What is lab-only

- Per-instance directories under a private yard, named
  `UsersAI/<identity>/<session>/<instance>` on the grant and
  `<yard>/<identity>/<session>/<instance>` on the host.
- Store `read` / `write` refusals for a foreign host path, a `..` segment, an
  outbound symlink, and `/tmp/elastos/storage`, each with a reason.
- Cleanup and Drop remove the yard.
- Plants `F-A9-share` and `F-A9-fake-runtime`.
- The tripwire `real_runtime_rows_match_the_launcher`, which stays green
  while the three `run_cmd.rs` literals exist and the state stays `Blocked`.

`lab/grant-binding` (A5 reference model) is a separate crate. #290 copies
field names and does not bind a handle. Grant-binding's README says it
counts toward no M1 check.

## What needs the Runtime

Cite RA-3 (`lab/runtime-asks/03-launcher-storage-under-home.md` in #309) and
AC-006-STORAGE (`lab/agent-conformance/GAPS.md`).

1. **RA-3 (small, not sufficient for A9).** Replace the three
   `create_runtime("/tmp/elastos/storage")` calls in `run_cmd.rs` with
   `create_runtime(crate::default_data_dir().join("storage"))`, as
   `capsule_cmd.rs` already does. That is a per-Home directory, not a
   per-instance root. Two `run` clients of one Home still share it. #309
   states RA-3 does not make A9's read-refusal row pass. #290 says the same
   (`PROPOSED-LAUNCHER-CHANGE.md` lines 76-77; `launch.rs:59`).
2. **AC-006-STORAGE.** Same three literals, plus the known leftover
   `/tmp/elastos/storage` on the process-isolation lab half of A3, A6 and A9.
   `operator_storage_is_under_throwaway_home` stays ignored with
   `blocked: AC-006-STORAGE`. RA-3 is the ask that flips this blocker. It
   still does not prove "A reads B" is refused.
3. **The missing Runtime ask for A-read-B.** Object reads use
   `rooted_localhost_fs_path` under the Home data directory
   (`elastos-common/src/localhost.rs`). The bridge refuses an undeclared
   resource (`manifest_capability_denied`) and a `Users` root without a
   principal (`principal_context_required`). Those checks do not consult
   `/tmp/elastos/storage` and do not implement per-instance owned storage.
   A later proof is two component processes, each with its own Home
   (`HOME` on the Mac; `XDG_DATA_HOME` is not enough there, `GAPS.md:37`),
   a captured non-empty bridge reason, and B's bytes unchanged. #309 points
   at UsersAI principal binding / RA-5 for that half. A5's Runtime half is
   Anders's (`#464`, `#463`, `#181` in the grant-binding README).
4. **`share_cmd.rs:183`.** Fourth `create_runtime("/tmp/elastos/storage")`.
   RA-3 as written does not touch it.

## Fix list for #290

1. Do not book A9 from this PR. Keep the title and body as lab-only. The
   current body already says no live Runtime ran.
2. Split the one `RowState` so RA-3 can move
   `real_runtime_each_instance_has_its_own_storage_root` without implying
   `real_runtime_agent_a_read_of_b_is_refused` is ready. #309 already asks
   for this split.
3. Count `share_cmd.rs` in the tripwire, or say the tripwire is `run` only.
   A count of exactly 3 hides the fourth literal.
4. Add Store (or host-preopen) rows for list, rename, symlink create, and
   hard link, or write down that those operations are out of scope. Today's
   A9 wording includes another agent's files, not only `read`/`write`.
5. Stop treating a hard link inside the caller's root as a safe regular file
   if the inode was created from another root. Re-stat the root after
   `bind` if the host can replace it with a symlink (`contained` is lexical).
6. Align `owned_root` with A5 (`UsersAI/<agent>/<rest>`) or drop the claim
   that the fields match `grant_binding::Decision`. Call the grant-binding
   crate or say the store is unbound.
7. Tighten `host_root()`: tests can keep a private test-only path helper.
   A public host path is ambient authority (Principle 3).
8. Strengthen `F-A9-share` for the parent-path test. Today that test still
   refuses `..` and fails only because the two host roots are equal. A plant
   that removes the `..` check should be a separate file.
9. Do not flip either Runtime row to Ready without a captured refusal from
   a real component run. `F-A9-fake-runtime` already catches a silent flip.

## #290 suites rerun here

```text
export RUST_TEST_THREADS=2
cargo fmt --manifest-path lab/owned-storage/Cargo.toml -- --check
# clean

cargo test --locked --offline --manifest-path lab/owned-storage/Cargo.toml
# 8 passed; 0 failed; 0 ignored
# agent_a_reads_and_writes_its_own_storage
# agent_a_is_denied_b_directly
# agent_a_is_denied_b_through_a_parent_path
# agent_a_is_denied_b_through_a_symlink
# shared_temp_directory_is_refused
# cleanup_leaves_nothing_behind
# planted_shared_root_is_caught
# real_runtime_rows_match_the_launcher

cargo test --locked --offline --manifest-path lab/owned-storage/Cargo.toml -- --list
# 8 tests, 0 benchmarks. No ignored names.

cargo clippy --manifest-path lab/owned-storage/Cargo.toml --locked --offline --all-targets -- -D warnings
# Finished `dev` profile, no diagnostics

python3 -I lab/review-a9-290/run.py
# probe findings as in last-run.json; exit 0

python3 -I lab/review-a9-290/check.py
# REVIEW.md pins and last-run.json required verdicts hold
```

Independent plant replay (files restored; SHA-256 match after):

```text
F-A9-share / tests::agent_a_is_denied_b_directly
  test tests::agent_a_is_denied_b_directly ... FAILED

F-A9-share / tests::agent_a_is_denied_b_through_a_parent_path
  assertion `left != right` failed: agents share a storage root
  left:  .../shared
  right: .../shared
  test tests::agent_a_is_denied_b_through_a_parent_path ... FAILED

F-A9-share / tests::agent_a_is_denied_b_through_a_symlink
  test tests::agent_a_is_denied_b_through_a_symlink ... FAILED

F-A9-fake-runtime / launch::tests::real_runtime_rows_match_the_launcher
  ready while elastos run still calls create_runtime("/tmp/elastos/storage")
  test launch::tests::real_runtime_rows_match_the_launcher ... FAILED
```

The parent-path plant is CAUGHT by the equal-root assertion, not by a
successful `..` walk. Direct and symlink plants fail because the Store then
returns B's bytes.

## Not run here

- A live `elastos run` or `elastos serve`. `command -v elastos` is empty.
  The VM's global exec setup was left as found.
- Mac `HOME` vs `XDG_DATA_HOME` data-dir proof (`GAPS.md:37`).
- `lab/agent-conformance` ignored row `operator_storage_is_under_throwaway_home`.
- Lane reviews of #290 (none posted).

## Principles

- 3 No ambient authority: the lab API confines `read`/`write`; `host_root()`
  and same-uid sibling directories do not.
- 5 Small trusted core: this crate is a stand-in, not the trusted core.
- 7 One authority model: the grant name is `UsersAI/...`, unbound to A5.
- 10 One canonical path: `run` still uses a different storage literal than
  `capsule`.
- 11 Fail closed, then explain: lab refusals explain; Runtime rows stay
  BLOCKED instead of reporting a run that did not happen.
- 12 Docs, code, tests agree: README, plants, and BLOCKED rows agree this
  is not a Runtime proof. The PR title can still be read as closing A9.
- 18 Isolated execution: lab directories are separate; the host process is
  not.

DeepSeek: none.
