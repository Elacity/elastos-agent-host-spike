# Runtime asks for the blocked M1 checks

LAB DRAFT for Anders, for review after 0.8.0. This folder changes no Runtime
code and no file outside `lab/runtime-asks/`. It counts toward no M1 check.
Every check named here stays open.

Several M1 checks are blocked only on a Runtime capability. Three draft PRs and
the agent-conformance notes each record part of that list. This folder merges
them into seven asks. Each ask has its own file with the checks it unblocks,
today's file and line evidence, the smallest change, how it fits the capability
and grant model, the risks, and the acceptance test the lab already has.

## The ranked asks

Score is checks named divided by effort points (see "How the ranking works").

| Rank | Ask | Runtime change in one line | Effort | Checks named | Score | Flips a written row alone |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | [RA-1](01-live-grant-view.md) | The shell reads the live grants of every session | M (2) | A6, A10, A11, A12 (4) | 2.00 | Yes: `run_leaves_no_live_grant` (Mac) |
| 2 | [RA-2](02-settle-ended-requests.md) | The Runtime settles an ended requester's pending requests, and the shell reads who settled | M (2) | A10, A11 (2) | 1.00 | No. Needs RA-6. |
| 3 | [RA-3](03-launcher-storage-under-home.md) | `elastos run` takes its storage from the selected Home (three literals) | S (1) | A9 (1) | 1.00 | No. A9's read-refusal row has no ask. |
| 4 | [RA-4](04-protected-storage-bridge-entry.md) | The A15 host can reach the in-runtime protected storage bridge | S (1) | A15 (1) | 1.00 | No. The lab tests assert the gap. |
| 5 | [RA-5](05-usersai-principal-root-alias.md) | `UsersAI/self` resolves to the verified agent principal's root | M (2) | A15 (1) | 0.50 | No. The lab decides this gap in code. |
| 6 | [RA-6](06-resident-instances-core.md) | Resident component instances: world, launch, list, stop (RI-1 to RI-4) | 11 (L+M+S+L) | A3, A6, A10, A11, A12 (5) | 0.45 | A3 only, once fixture guests exist |
| 7 | [RA-7](07-pending-request-outlives-call.md) | A request can stay pending after the guest's call returns (RI-6) | L (4) | A11 (1) | 0.25 | No. Needs RA-2 and RA-6. |

Sources by ask: RA-1 is RI-7 (#293) and AC-021-GRANTS. RA-2 is RI-5 (#293) and
AC-027-ORPHAN. RA-3 is the launcher change in #290 and AC-006-STORAGE. RA-4 and
RA-5 come from #284. RA-6 is RI-1 to RI-4 (#293) and RT4. RA-7 is RI-6 (#293).

## How the ranking works

- **Counting rule.** A check counts for an ask when a lab names that ask as a
  missing Runtime capability for that check. The lab does this in an
  `#[ignore = "blocked: ..."]` reason, a BLOCKED row, or a BLOCKED row in its
  README. A recorded exception beside a passing journey does not count. A
  looser count that includes those exceptions (`GAPS.md` lists the client
  storage half of A3, A6 and A9 under AC-006-STORAGE, and no cross-session
  grant census under AC-021-GRANTS) would raise RA-1 and RA-3.
- **Effort.** My estimate from the code each ask touches, for Anders to correct.
  S (1): one function or literal edit in one crate, with no new state or
  contract. M (2): a new route, field or state, or edits across two crates.
  L (4): a change to the Bus WIT, the component execution model or the blocking
  call model. RA-6 is the sum of its four parts.
- **Ties.** RA-2, RA-3 and RA-4 all score 1.00. More checks goes first. Then the
  ask that stays away from the principal boundary goes first.
- **Sensitivity.** If M costs 3 and L costs 8, RA-1 stays first and ranks 5 to 7
  keep their order. RA-2 drops from rank 2 to rank 4 (scores 1.33, 1.00, 1.00,
  0.67). If Anders takes the deadline option for RA-7 (Option 2 in that file),
  RA-7 costs M and ties RA-5 at 0.50.

## What lands when

Read the ranking with the dependencies. Four resident checks need several asks
together.

| After these asks land | What can flip | Note |
| --- | --- | --- |
| RA-1 | `run_leaves_no_live_grant` (lab half of A10, A11, A12) | Needs the Mac harness. |
| RA-1 and RA-2 | Nothing new alone | The resident rows also need RA-6. Two agent-conformance journeys turn FAIL on purpose until re-measured. |
| RA-3 | Nothing alone | A9 row 1 becomes measurable once the lab splits its single row state. |
| RA-4 | Nothing alone | Three A15 lab rows become measurable. The lab writes the PASS assertions. |
| RA-5 | Nothing alone | The A15 notes step needs RA-4 and a lab probe. |
| RA-6 | A3 | With RA-1: A6 and A12. With RA-2: A10. Fixture guests must exist. |
| RA-7 | A11 | With RA-2 and RA-6. |

When RA-1, RA-2, RA-6 and RA-7 have landed, all five resident checks (A3, A6,
A10, A11, A12) can run. A15 needs RA-4 and RA-5. A9 needs RA-3 and one more
change that no PR names (see finding 2).

## Which written tests flip, and how

Each ask names its tests. They fall in four classes.

- **READY.** The body is written. The row flips when the Runtime ships the ask
  and the listed prerequisites exist.
- **TRIPWIRE.** The test asserts today's gap. It fails when the gap closes. The
  PASS assertion is still to write.
- **PLACEHOLDER.** The row is ignored and its body is a panic.
- **STATIC.** Lab code decides the grade. The lab never asks the Runtime.

| Ask | Test | Where | Class |
| --- | --- | --- | --- |
| RA-1 | `run_leaves_no_live_grant` | agent-conformance `tests/effects.rs` | READY (Mac) |
| RA-1 | `acceptance_a6_*`, `acceptance_a12_*` | #293 | READY, needs RA-6 and fixtures |
| RA-2 | `acceptance_a10_*`, `acceptance_a11_*` | #293 | READY, needs RA-6 (A11 also RA-7) and fixtures |
| RA-2 | `killed_worker_settlement_recorded_without_retry`, `no_policy_file_does_not_mean_allow` | agent-conformance | TRIPWIRE (PASS turns FAIL) |
| RA-3 | `real_runtime_rows_match_the_launcher` | #290 | TRIPWIRE |
| RA-3 | `operator_storage_is_under_throwaway_home` | agent-conformance | PLACEHOLDER |
| RA-4 | `public_bridge_blocks_journal_storage_before_token_checks`, `approved_plan_executes_with_the_approved_grants` | #284 | TRIPWIRE |
| RA-5 | The notes step of `approved_plan_executes_with_the_approved_grants` | #284 | STATIC |
| RA-6 | `acceptance_a3_two_resident_instances_in_one_runtime` | #293 | READY, needs fixtures |
| RA-6 | `parallel_capsules_complete_independently` | agent-conformance | PLACEHOLDER |
| RA-7 | `acceptance_a11_*` | #293 | READY, needs RA-2, RA-6 and a fixture |

Only RA-1 has a row that flips without other lab work. RA-3, RA-4 and RA-5 need
new lab assertions or a live probe first. RA-2, RA-6 and RA-7 need the resident
fixture guests, which are not written.

## Findings from reading the evidence

1. **The two labs call the live-grant view differently (RA-1).** agent-conformance
   calls the plain `GET /api/capability/list` and expects a `scope` marker. The
   resident harness calls it with `?scope=all_sessions_live`. A Runtime that
   returns the marked global view to a shell session on both calls satisfies
   both labs. Otherwise one lab changes one line.
2. **RA-3 does not make A9's read refusal pass.** #290 says so itself: its edit
   "does not by itself make agent A's read of B's file return a reason". The
   second A9 row has no ask in these PRs. The Mac data directory follows `HOME`,
   and the proposal's example uses `XDG_DATA_HOME`.
3. **Most "flips" need new lab code.** See the table above.
4. **Three pairs name one Runtime change twice.** RI-7 and AC-021-GRANTS, RI-5
   and AC-027-ORPHAN, and RI-1 to RI-4 and RT4 each describe the same
   behaviour. This folder lists each once.
5. **The `UsersAI` root layout is not fixed (RA-5).** The architecture doc
   leaves it open, the journal contract has the guest name `UsersAI/self`, and
   the labs name the agent in the path. The alias waits for that contract.
6. **A caller-named principal is refused at launch (RA-4, RA-5).** The launch
   route says `principal_id` is not launch authority. RA-4 Form A and RA-5 both
   need a principal that the Runtime verified.
7. **Some cited lines have moved.** These rows show the old and the current
   line for three citations in `GAPS.md`.

| Citation | Text on that line | What it shows |
| --- | --- | --- |
| `lab/agent-conformance/GAPS.md:780` | `run_cmd.rs:264` | `GAPS.md` cites line 264 for the end of `run_local`. |
| `elastos/crates/elastos-server/src/run_cmd.rs:265` | `.run_local(capsule_dir, capsule_args)` | It is line 265 now. |
| `lab/agent-conformance/GAPS.md:774` | `manager.rs:485` | `GAPS.md` cites line 485 for the use count. |
| `elastos/crates/elastos-runtime/src/capability/manager.rs:487` | `self.store.try_use_token(&token.id, max_uses)` | It is line 487 now. |
| `lab/agent-conformance/GAPS.md:783` | `capability.rs:433` | `GAPS.md` cites line 433 for the grant list. |
| `elastos/crates/elastos-server/src/api/handlers/capability.rs:434` | `list_session_granted(&session_id)` | It is line 434 now. |

## Sources and pins

All three PRs are drafts. The evidence rows read each file at the commit named
here. Runtime paths are read at the base commit.

| Source | Commit |
| --- | --- |
| Base: `spike/agent-host`, includes `elastos/` and `lab/agent-conformance/` | `a76268e7793097ebf38506902b68d824c0ce10cd` |
| #293, `lab/resident-instances/` (branch `cursor/resident-instances-harness-c6ae`) | `35697329be0aad89eb68d0adf78aa94d24751317` |
| #290, `lab/owned-storage/` (branch `cursor/owned-storage-a9-9b7c`) | `c0b16491076c30366a3504066499c9f5ad831ef2` |
| #284, `lab/intent-planner/` (branch `cursor/intent-planner-a15-10c1`) | `cb102ed13b9e93e7e99a820d63195cf931bee22a` |

## What was re-run

In a scratch worktree of the base commit outside this repo (removed
afterwards), each lab folder was copied from its PR head and run on the current
base:

- `lab/resident-instances`: `cargo test --locked`. Library 17, gates 4, journeys
  18 passed, acceptance 5 ignored. `blocker_evidence_still_holds` passes. The
  acceptance table prints five BLOCKED rows.
- `lab/owned-storage`: `cargo test --locked --offline`. 8 passed.
- `lab/intent-planner`: `cargo test --locked`. 13 passed. The planted approval
  bug is caught by its five named tests.

So each lab's own statement of its gap holds on `a76268e7`. Not re-run:
`lab/agent-conformance`, which needs macOS. No live operator ran. No Runtime
change was built.

## Limits

- No file in this repo defines the M1 checks. The labs name them in their own
  text. The check names A3 to A15 here come from those labs only.
- Effort numbers are my estimate from the code touched.
- Nothing here measures a changed Runtime. Every "smallest change" is a
  reading of today's code, not a run.
- Line numbers are pinned to the base above, which holds this repo's copy of
  `elastos/`. The resident-instances log records that the same pins hold on
  Elacity `develop` (`92aeea44` at the time) except two `resource_bridge.rs`
  lines. This folder did not re-check `develop`.
- The checker re-reads every row.

| Citation | Text on that line | What it shows |
| --- | --- | --- |
| `#293 lab/resident-instances/LOG.md:127` | `873 and 946` | The #293 log says only the `resource_bridge.rs` lines differ on `develop`, and gives 873 and 946 as the two lines there. |

## Out of scope

Other blockers in `lab/agent-conformance/GAPS.md`, named and not evaluated:
AC-002-ARGS (a typed launch selector and result), RT3 (a model-call grant),
AC-025-CID (launch by content id) and AC-005-REASON (the stop cause on stderr).
The "UsersAI binding" blocker overlaps RA-5 and is discussed in that file.

## Check the evidence

```bash
git fetch origin cursor/resident-instances-harness-c6ae cursor/owned-storage-a9-9b7c cursor/intent-planner-a15-10c1
python3 lab/runtime-asks/check-citations.py            # pinned base
python3 lab/runtime-asks/check-citations.py --at HEAD  # find lines that moved
```

The script reads every evidence row in these files and checks that the quoted
text sits on the named line. It exits 1 when a row fails and 2 when it finds no
rows or cannot read a source. To see it fail, change a line number in any
evidence row and run it again. It prints the row, the text it wanted and the
text it found.

## Files

- `01-live-grant-view.md` to `07-pending-request-outlives-call.md`: one file
  per ask, in rank order.
- `check-citations.py`: the evidence checker.

## Principles

3 (no ambient authority): RA-1 to RA-6 keep authority with a grant bound to one
requester. 7 (one authority model): the shell and the Runtime use the same
request record. 10 (one canonical path): each ask extends an existing route or
function. 11 (fail closed, then explain): RA-2 settles with a reason. 12 (docs,
code, tests agree): every cited line is checked by the script. 18 (isolated
execution): RA-6 gives each instance its own session and lifecycle.
