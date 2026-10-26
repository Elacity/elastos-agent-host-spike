# Independent adversarial review r2 of #284 (A15) at 4f17e482

Reviewer: Cursor Grok 4.6 (Grok family). #284 was authored by Claude. r1 was
PR #399 at `cb102ed1`. This is the second independent review.

Reviewed head: `4f17e482f9be239aa880a5da574429a49d46276e`  
Worktree: `/tmp/a15-review-r2/4f17e482` (detached at that commit)  
Review branch: `cursor/review-a15-284-r2-9ff1` from `origin/spike/agent-host` at `1d9b66562977c51bf6b2271e0ceb8543946c5683`  
Machine: Linux 6.12.94+ x86_64, rustc 1.91.0 (f8297e351 2025-10-28)  
Date: 26 Oct 2026

**Bookability for A15: still open. The journal write stays BLOCKED.**

The complete journey as worded is preview, explicit approval, then execute
exactly the approved plan, with a stored journal. The Host gate for the table
plan is stronger than at r1. The journal write still ends as
`principal_context_required`. The notes read still ends as a local
`runtime_gap` string. This review is FIX for new unpinned binds, not because
the r1 mutants survived.

This folder is the only change on this branch. #284's branch was left alone.
Nothing was merged. Elacity/elastos-runtime was left alone.

## Verdict

**VERDICT: FIX**

r1's surviving mutants are dead. The author's 19/0 count is real. The README
no longer claims work against a Runtime process. Those r1 items hold.

Two new plants still let `Host::execute` run a constructed plan that is
different from the approved one (N1 newline field split, N3 trimmed
principal). The author's suite stays green under both. That is the same class
of hole r1 called FIX for M3 and M8.

A15 stays open while the journal write is BLOCKED.

## Anders's counting rule, applied

A check counts when the complete journey as worded passes, each refusal
carries a reason plus a CAUGHT falsifier, and the required reviews exist.
Lab evidence for a Runtime-side property stays evidence. Rows that need the
Runtime stay BLOCKED.

| Journey part | What I saw | Counts? |
| --- | --- | --- |
| Preview | `preview()` lists both steps and records no grant. Lab. | Lab evidence |
| Explicit approval | `Host::review(..., Choice::Approve)` is a function argument. There is still no person channel, session id, or signed approval object. | Lab evidence |
| Execute exactly the approved plan | Table-plan reject, reorder, extra step, altered resource, other principal, spent grant, and a second `Host::new()` are pinned. Constructed plans with a colliding `canonical()` still execute under N1 and N3. The journal step records BLOCKED. Nothing is stored. | BLOCKED for the product journey. Lab Host-gate is incomplete for constructed plans. |
| Refusal + reason | The r1 refusals now have named reasons and per-guard plants. Cross-host prefix ids (`host-1` vs `host-10`) still read as `ForeignHost` in today's code, and the author's test only uses consecutive ids. A spent-before-execute path returns `Bridge` ("the bus bridge did not answer"). | Partial |
| CAUGHT falsifier | Author plants M1–M8, M6-host, F-A15-approval are CAUGHT. New plants N1, N3, N4, N6, N7, N10 survive the author's 18 Host/library tests. | Partial |
| Required reviews | r1 was FIX. This r2 is FIX. | Missing PASS |

**A15 is not bookable.**

## What I rebuilt and reran

Detached worktree only. First command was `cargo fetch --locked`.

```bash
export RUST_TEST_THREADS=2
cd /tmp/a15-review-r2/4f17e482
cargo fetch --locked --manifest-path lab/intent-planner/Cargo.toml
cargo fmt --manifest-path lab/intent-planner/Cargo.toml -- --check
cargo clippy --manifest-path lab/intent-planner/Cargo.toml --locked --offline --all-targets -- -D warnings
cargo test --locked --offline --manifest-path lab/intent-planner/Cargo.toml -- --nocapture
```

| Command | Exit | Result |
| --- | --- | --- |
| `cargo fetch --locked` | 0 | lock file resolved |
| `cargo fmt -- --check` | 0 | no diff |
| `cargo clippy ... -D warnings` | 0 | clean for `intent-planner` |
| `cargo test ... -- --nocapture` | 0 | `19 passed; 0 failed; 0 ignored` in 77.13s |

The in-crate plant runner printed one `FAILED` line per named test, then
restored `src/lib.rs`. SHA-256 of `lab/intent-planner/src/lib.rs` at the
reviewed head, and again after every restore:
`f09d572393060f2b56e6796b2a9ba2227a3d024867078f031efa2d000830bc64`.

`pgrep -a elastos` was empty after the suite. Clippy of `elastos-server`
printed two `AsyncFd::new` deprecation warnings. They are in the dependency.

## Author plants, rerun by me

I applied each plant file myself and ran the 18 non-plant tests (`--skip`
`model_planted_bugs_are_caught`). Named-test counts below are exact.

| Plant | Named tests FAILED | Suite | Grade |
| --- | --- | --- | --- |
| F-A15-approval | 5/5 (`approved_plan_records_blocked_in_process_bridge_effects`, `rejected_plan_executes_nothing`, `plan_altered_after_approval_is_refused`, `extra_step_injected_at_run_time_is_refused`, `approved_grant_runs_once`) | 11 failed / 7 passed | CAUGHT |
| M1 | 1/1 `rejected_plan_executes_nothing` | 1 / 17 | CAUGHT |
| M2 | 1/1 `plan_altered_after_approval_is_refused` | 2 / 16 (also `approval_for_one_principal_does_not_execute_for_another`) | CAUGHT |
| M3 | 1/1 `reordered_approved_steps_are_refused` | 1 / 17 | CAUGHT |
| M4 | 1/1 `approved_grant_runs_once` | 1 / 17 | CAUGHT |
| M5 | 1/1 `grant_lookup_uses_covers_for_the_exact_resource` | 1 / 17 | CAUGHT |
| M6 | 1/1 `execute_spends_the_allow_once_grant_at_the_lab_manager` | 1 / 17 | CAUGHT |
| M6-host | 1/1 `unused_review_does_not_run_on_a_second_host` | 1 / 17 | CAUGHT |
| M7 | 1/1 `blocked_journal_effect_comes_from_a_bus_round_trip` | 1 / 17 | CAUGHT |
| M8 | 1/1 `approval_for_one_principal_does_not_execute_for_another` | 1 / 17 | CAUGHT |

The author claim "all r1 mutants caught, 19/0" holds. F-A15-approval still
removes the whole of `approval_check` in one edit. The per-guard files now
pin the r1 holes one at a time.

## New mutants (reviewer-owned)

Ten plants, applied to `src/lib.rs` or `src/runtime_bridge.rs`, then the
author's 18 tests. Source restored to `f09d5723…` after each.

| Id | Guard removed | Author suite | Probe | Grade |
| --- | --- | --- | --- | --- |
| N1 | `push_field` drops the length prefix | 18/0 SURVIVED | `review_n1_newline_fields_do_not_collide`: approve `principal="a\nb"` / `intent="c"`, execute `principal="a"` / `intent="b\nc"` with the same journal step. Under N1, `execute` returned `Ok`. | **LIVE execute** |
| N2 | `canonical()` omits `step.resource` | 17/1 CAUGHT by `plan_altered_after_approval_is_refused` | — | CAUGHT |
| N3 | `push_field` trims whitespace | 18/0 SURVIVED | `review_n3_trailing_space_principal_is_a_different_plan`: approve `ada`, execute `ada `. Under N3, `expect_err` failed (`Ok`). | **LIVE execute** |
| N4 | `covers()` treats a resource as matching a prefix of the other | 18/0 SURVIVED | `review_n4_prefix_resource_does_not_cover`: parent `.../Agents/ada/tasks` vs child journal, same step id. Under N4, `covers` returned true. | **LIVE covers** |
| N5 | `covers()` matches only the last path segment and drops `step_id` | 17/1 CAUGHT by `grant_lookup_uses_covers_for_the_exact_resource` | — | CAUGHT |
| N6 | `invoke_journal` still runs; the reply is replaced with hardcoded BLOCKED | 18/0 SURVIVED | Fake bus reply `stored` / `probe-stored-journal`. Under N6, `approved_plan_records_blocked_in_process_bridge_effects` stayed `ok` (still records BLOCKED). Control without N6: that test FAILED. | **LIVE ignore-reply** |
| N7 | `host_id` bind uses `starts_with` | 18/0 SURVIVED | `review_n7_prefix_host_id_stays_foreign`: forced `host-1` vs `host-10`. Under N7 the `ForeignHost` assertion failed. | **LIVE host-id prefix** |
| N8 | mint with `max_uses: None` (grant cap omitted) | 15/3 CAUGHT by `execute_spends_the_allow_once_grant_at_the_lab_manager`, `lab_manager_denies_a_reused_single_use_grant`, `approved_plan_records_blocked_in_process_bridge_effects` | — | CAUGHT |
| N9 | `validate_journal_write` uses `grant.resource` (guest URI) instead of `scoped_journal` | 13/5 CAUGHT | — | CAUGHT |
| N10 | mark `used` before the bus call | 18/0 SURVIVED | `review_toctou_spend_before_execute_is_refused`: spend the token with `validate_journal_write`, then `execute` (gets `Bridge`), then `execute` again. Under N10 the retry became `GrantSpent`. | **LIVE used-list** |

`Plan.canonical()` still stores only plan fields. Grant scope, expiry, and
nonce never enter the binding. N8 shows a missing use-cap is caught at the
lab manager. There is no expiry or nonce field on `Grant` to omit.

Review replay after the minting `Host` is dropped is the same as a second
`Host::new()`. That path is already `ForeignHost` (`review_restart_drops_the_review`).
The Host keeps no disk. A process restart is a new Host.

`Host::execute` takes `&mut self`, so two threads cannot call it on one Host
through the public API. Two threads on the same `Grants` allow-once token
gave one `Ok` and one `use limit exceeded` (`review_concurrent_validate_of_allow_once`).
That is library evidence for the lab manager, not a Host lock.

Approving table-plan P and executing a reordered or space-padded P' is
refused today (`review_p_then_p_prime_same_canonical_is_refused`). The live
collisions are the newline split (N1) and the trimmed principal (N3).
`plan()` refuses a space in a principal. `Host::review` accepts any
constructed `Plan`.

## Rows: what counts

| Row | Where the call goes | Class | Counts as |
| --- | --- | --- | --- |
| Preview of the two-step plan | `preview()` | lab | Lab evidence |
| Notes step BLOCKED (`UsersAI`) | `runtime_gap()`, no bus | BLOCKED (STATIC), RA-5 | BLOCKED |
| Reject / altered resource / extra step / reorder / spent grant / other principal | `Host::approval_check` | lab Host-gate | Lab evidence |
| Review from another `Host::new()` | `host_id` inequality | lab Host-gate | Lab evidence for consecutive ids. Prefix ids (`host-1` / `host-10`) are unpinned. |
| Unapproved journal `missing_token` | in-process `handle_remote_request_with_audit_dir` | library | Library evidence |
| Altered resource / allow-once / second use | lab `CapabilityManager::validate` | library | Library evidence |
| Same checks on the public bus entry | in-process public function | BLOCKED, RA-4 | BLOCKED |
| Approved journal write stored | in-process public function | BLOCKED, RA-4 | BLOCKED |
| BLOCKED journal effect from a bus round trip | `execute` → `invoke_journal` + audit dir | library | Library evidence that a call happened. The recorded BLOCKED strings are not bound to the reply (N6). |
| Spawned `elastos` over the bus | absent | NEEDS RUNTIME | NEEDS RUNTIME |

The README's class column matches this table. The leftover stretch is the
phrase "bus round trip" on an in-process library call whose recorded effect
can ignore the reply.

## README and row-label check

Honest now, and kept:

- In-process `handle_remote_request_with_audit_dir`, "linked crate function
  in the test process".
- "A spawned `elastos` binary over the bus is NEEDS RUNTIME".
- UsersAI notes BLOCKED (RA-5). Stored journal BLOCKED (RA-4).
- `Grants::mint_journal_write` and `invoke_journal` stay callable and skip
  preview / `Host::execute`.

Stretch that remains:

- Test name `blocked_journal_effect_comes_from_a_bus_round_trip` and the row
  "BLOCKED journal effect from a bus round trip". M7 pins that
  `invoke_journal` ran (audit records). N6 shows the recorded BLOCKED
  strings can be hardcoded after that call. When I returned `stored` from
  `invoke_journal`, `approved_plan_records_blocked_in_process_bridge_effects`
  still passed under N6.
- README "covers for the exact resource and action". The code compares
  strings today. The author's `grant_lookup` pair (`ada` vs `bea`) shares
  no prefix, so a prefix `covers` survives.
- Code comment on `Plan::canonical`: "Each field is length-prefixed, so a
  later edit cannot keep the same binding by moving a separator." True in
  the source. The suite never constructs a colliding pair. Dropping the
  prefix (N1) or trimming (N3) leaves 18/0.
- F-A15-approval's first named test is
  `approved_plan_records_blocked_in_process_bridge_effects`. That is a
  success-path test, not a Host refusal. The four refusal names after it
  match the README.

The r1 overclaim "against the real Runtime" is gone.

## Principles

- 3 No ambient authority. The Host gate holds for the table plan. A
  constructed `Plan` with a colliding `canonical()` still executes under N1
  and N3. `mint` and `invoke_journal` stay callable without `review`.
- 7 One authority model. Approval is still a `Choice` enum.
- 10 One canonical path. README names `approval_check` and the in-process
  public entry. Direct `invoke_journal` is a second path, and the README
  says so.
- 11 Fail closed, then explain. Spend-then-execute returns `Bridge`. N10
  then marks `used`, so a retry becomes `GrantSpent` after an empty first
  run.
- 12 Docs, code, and tests agree on BLOCKED storage and on "in-process".
  They stretch on "bus round trip", on "exact" `covers`, and on the
  length-prefix comment.
- 16 UI is not authority. The preview records no grant.
- 18 Isolated instances. `Review` now carries `host_id`. The check is
  string equality. Prefix ids are unpinned.
- 19 Consequences, not transports. The public entry refusal is labeled
  BLOCKED. That part holds.

DeepSeek: none. I did not change Runtime source.

## Ranked fixes for #284

1. Pin `canonical()` against a newline field-boundary pair and a trimmed
   principal. `Host::review` should refuse a constructed plan the table
   would refuse, or the bind must treat those as `PlanAltered` with a
   plant (closes N1, N3).
2. Pin `covers()` with a parent-path grant and a child journal, same step
   id (closes N4).
3. Bind the recorded journal effect to `classify(actual_reply)`. A planted
   `stored` reply must fail the BLOCKED assertion (closes N6). Rename the
   test so it reads as an in-process library call.
4. Pin `host_id` with `host-1` vs `host-10` (closes N7).
5. Mark `used` only after a finished `execute` that recorded effects
   (closes N10). Keep spend-before-execute as `Bridge` or give it its own
   reason.
6. Keep RA-4 / RA-5 as the Runtime half. Until a stored journal is
   asserted, A15 stays open.

## Bookability sentence

A15 is a lab model of preview and a Host approval bind, plus honest BLOCKED
rows for UsersAI (RA-5) and protected storage (RA-4). The r1 mutants are
dead. Constructed-plan collisions and an ignored bus reply still survive
the author's tests. **Do not book A15. The journal write stays BLOCKED.**

## Next

#284 authors pin N1, N3, N4, N6, N7, and N10, or write those limits into
the README as lab limits. RA-4 and RA-5 stay with Anders after 0.8.0.
This review PR stays draft. Do not merge #284 on the strength of this file.
