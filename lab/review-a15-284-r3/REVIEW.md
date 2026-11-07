# Independent adversarial review r3 of #284 (A15) at d169f90

Reviewer: Cursor Grok 4.6 (Grok family). #284 was authored by Claude. r1 was
PR #399 at `cb102ed1`. r2 was PR #414 at `4f17e482`. This is the third
independent review. I read `lab/review-a15-284-r2/REVIEW.md` first.

Reviewed head: `d169f90d5f5dae2de52d40c8fb4f4ab908481124`  
Code commit: `9664738431c065a7c69cb07577ee6fc2eb898152`  
Worktree: `/tmp/a15-review-r3/d169f90` (detached at that commit)  
Review branch: `cursor/review-a15-284-r3-7c92` from `origin/spike/agent-host` at `4290f17050b7738e6571398795e4d77622b0aa6c`  
Machine: Linux 6.12.94+ x86_64, rustc 1.91.0 (f8297e351 2025-10-28)  
Date: 27 Oct 2026

**Bookability for A15: still open. The journal write stays BLOCKED.**

The r2 surviving mutants are dead. The author's 25/0 count is real. The six
named binds r2 asked for (N1, N3, N4, N6, N7, N10) now have tests, and I
replanted those files myself. Ten new plants still let a constructed plan
or a loosened bind through the Host gate. That is the same class of hole
r2 called FIX.

This folder is the only change on this branch. #284's branch was left alone.
Nothing was merged. Elacity/elastos-runtime was left alone.

## Verdict

**VERDICT: FIX**

Lab half only. The r2 plants are CAUGHT. The Host gate is still open for
constructed plans and for covers / reply / host-id shapes the suite never
builds.

A15 stays open while the journal write is BLOCKED (RA-4), UsersAI notes are
BLOCKED (RA-5), and a spawned `elastos` over the bus is NEEDS RUNTIME.

## Anders's counting rule, applied

A check counts when the complete journey as worded passes, each refusal
carries a reason plus a CAUGHT falsifier, and the required reviews exist.
Lab evidence for a Runtime-side property stays evidence. Rows that need the
Runtime stay BLOCKED.

| Journey part | What I saw | Counts? |
| --- | --- | --- |
| Preview | `preview()` lists both steps and records no grant. Lab. | Lab evidence |
| Explicit approval | `Host::review(..., Choice::Approve)` is a function argument. There is still no person channel, session id, or signed approval object. | Lab evidence |
| Execute exactly the approved plan | Table-plan reject, reorder of the steps slice, extra step, altered resource, other principal, spent grant, second `Host::new()`, newline split, trailing space, parent-path covers, `host-1`/`host-10`, and spend-after-success are pinned. Constructed plans with NFC/NFD, confusables, a truncated length prefix, or a sorted-step canonical still execute. Covers still folds `..`, a trailing slash, ASCII case, and percent-encoding. | BLOCKED for the product journey. Lab Host-gate is incomplete for constructed plans. |
| Refusal + reason | r2 refusals now have named reasons. Empty or NUL `host_id` skips `ForeignHost` and fails later as `Bridge`. A trailing or case-folded BLOCKED reply is accepted as success. | Partial |
| CAUGHT falsifier | Author plants F-A15-approval, M1–M8, M6-host, N1–N10 are CAUGHT. New plants R3-1 through R3-10 survive the author's 24 Host/library tests. | Partial |
| Required reviews | r1 was FIX. r2 was FIX. This r3 is FIX. | Missing PASS |

**A15 is not bookable.**

## What I rebuilt and reran

Detached worktree only. First command was `cargo fetch --locked`.

```bash
export RUST_TEST_THREADS=2
cd /tmp/a15-review-r3/d169f90
cargo fetch --locked --manifest-path lab/intent-planner/Cargo.toml
cargo fmt --manifest-path lab/intent-planner/Cargo.toml -- --check
cargo clippy --manifest-path lab/intent-planner/Cargo.toml --locked --offline --all-targets -- -D warnings
cargo test --locked --offline --manifest-path lab/intent-planner/Cargo.toml -- --nocapture --skip model_planted_bugs_are_caught
cargo test --locked --offline --manifest-path lab/intent-planner/Cargo.toml --lib model_planted_bugs_are_caught -- --exact --nocapture
```

| Command | Exit | Result |
| --- | --- | --- |
| `cargo fetch --locked` | 0 | lock file resolved |
| `cargo fmt -- --check` | 0 | no diff |
| `cargo clippy ... -D warnings` | 0 | clean for `intent-planner` |
| `cargo test ... --skip model_planted_bugs_are_caught` | 0 | `24 passed; 0 failed; 0 ignored` in 0.97s |
| `cargo test ... model_planted_bugs_are_caught` | 0 | `1 passed` in 87.83s; every named plant line printed `FAILED` |

Together that is the author's **25/0**. `pgrep -a elastos` was empty after
the suite. Clippy of `elastos-server` printed two `AsyncFd::new` deprecation
warnings. They are in the dependency.

SHA-256 of `lab/intent-planner/src/lib.rs` at the reviewed head, after the
author runner, and after every restore I made:
`dba94e5b1b456f878fc463565ff5f1d11b892df283acac1ed421fccb9445093b`.

SHA-256 of `lab/intent-planner/src/runtime_bridge.rs`:
`6b0d316cd0f25d4c4c4a3f4646c74b2272d2ab554c69f0f5195a86a4f8357494`.

## Author plants, rerun by me

I applied each plant file myself and ran the 24 non-plant tests (`--skip`
`model_planted_bugs_are_caught`). Named-test counts below are exact. Source
restored to `dba94e5b…` after every plant.

| Plant | Named tests FAILED | Suite | Grade |
| --- | --- | --- | --- |
| F-A15-approval | 5/5 (`approved_plan_records_blocked_in_process_bridge_effects`, `rejected_plan_executes_nothing`, `plan_altered_after_approval_is_refused`, `extra_step_injected_at_run_time_is_refused`, `approved_grant_runs_once`) | 8 failed / 16 passed | CAUGHT |
| M1 | 1/1 `rejected_plan_executes_nothing` | 1 / 23 | CAUGHT |
| M2 | 1/1 `plan_altered_after_approval_is_refused` | 4 / 20 | CAUGHT |
| M3 | 1/1 `reordered_approved_steps_are_refused` | 1 / 23 | CAUGHT |
| M4 | 1/1 `approved_grant_runs_once` | 1 / 23 | CAUGHT |
| M5 | 1/1 `grant_lookup_uses_covers_for_the_exact_resource` | 1 / 23 | CAUGHT |
| M6 | 1/1 `execute_spends_the_allow_once_grant_at_the_lab_manager` | 2 / 22 | CAUGHT |
| M6-host | 1/1 `unused_review_does_not_run_on_a_second_host` | 2 / 22 | CAUGHT |
| M7 | 1/1 `blocked_journal_effect_comes_from_an_in_process_library_call` | 3 / 21 | CAUGHT |
| M8 | 1/1 `approval_for_one_principal_does_not_execute_for_another` | 2 / 22 | CAUGHT |
| N1 | 1/1 `newline_fields_do_not_collide` | 1 / 23 | CAUGHT |
| N2 | 1/1 `plan_altered_after_approval_is_refused` | 1 / 23 | CAUGHT |
| N3 | 1/1 `trailing_space_principal_is_a_different_plan` | 1 / 23 | CAUGHT |
| N4 | 1/1 `prefix_resource_does_not_cover_a_child_journal` | 1 / 23 | CAUGHT |
| N5 | 1/1 `grant_lookup_uses_covers_for_the_exact_resource` | 1 / 23 | CAUGHT |
| N6 | 1/1 `approved_plan_refuses_a_stored_bus_reply` | 1 / 23 | CAUGHT |
| N7 | 1/1 `prefix_host_id_stays_foreign` | 1 / 23 | CAUGHT |
| N8 | 1/1 `execute_spends_the_allow_once_grant_at_the_lab_manager` | 4 / 20 | CAUGHT |
| N9 | 1/1 `execute_spends_the_allow_once_grant_at_the_lab_manager` | 7 / 17 | CAUGHT |
| N10 | 1/1 `failed_execute_does_not_spend_the_grant` | 2 / 22 | CAUGHT |

The author claim "all 20 plants CAUGHT, 25/0, lib.rs sha `dba94e5b…`" holds.
The r2 holes are pinned in code, not only in docs.

## New mutants (reviewer-owned)

Twelve plants, applied to `src/lib.rs` or `src/runtime_bridge.rs`, then the
author's 24 tests. Source restored to `dba94e5b…` after each. Each surviving
plant has a probe that fails under the mutant and passes on the clean tree.

| Id | Guard removed | Author suite | Probe | Grade |
| --- | --- | --- | --- | --- |
| R3-1 | `push_field` maps NFD `e\u{0301}` to NFC `é` | 24/0 SURVIVED | Approve principal `café` (U+00E9), execute `cafe\u{0301}`. Under the plant, `execute` returned `Ok`. Clean tree: `PlanAltered`. | **LIVE execute** |
| R3-2 | `push_field` maps Cyrillic `а` (U+0430) to Latin `a` | 24/0 SURVIVED | Approve `ada`, execute `\u{0430}da`. Under the plant, `execute` returned `Ok`. Clean tree: `PlanAltered`. | **LIVE execute** |
| R3-3 | length prefix kept as `min(255)` and the field is truncated | 24/0 SURVIVED | Principals of 255 `a` + `b` vs 255 `a` + `c`. Canonical bytes collided. Follow-up `r3_truncated_execute`: `execute` returned `Ok` and recorded one effect. Clean tree: canonical bytes differ. | **LIVE execute** |
| R3-4 | `covers` normalises `.` and `..` path components | 24/0 SURVIVED | Grant for `.../journal` covered `.../journal/foo/..`. Clean tree: covers is false. | **LIVE covers** |
| R3-5 | `covers` strips a trailing `/` | 24/0 SURVIVED | Grant for `.../journal` covered `.../journal/`. Clean tree: covers is false. | **LIVE covers** |
| R3-6 | `covers` is ASCII case-insensitive | 24/0 SURVIVED | Grant for `.../Agents/ada/...` covered `.../Agents/Ada/...`. Clean tree: covers is false. | **LIVE covers** |
| R3-7 | `classify` trims, case-folds, and prefix-matches the BLOCKED text | 24/0 SURVIVED | Forced reply `principal_context_required ` plus the gap text plus ` trailing`. Under the plant, `execute` returned `Ok`. Clean tree: `Bridge`. | **LIVE ignore-reply** |
| R3-8 | `host_id` strips NUL and skips an empty id | 24/0 SURVIVED | `host-1\0` vs `host-1`, and empty vs `host-99`. Both skipped `ForeignHost` and failed later as `Bridge` (foreign manager). The journal invoke runs before that fail. Clean tree: `ForeignHost`. | **LIVE host-id bind** |
| R3-9 | `canonical()` sorts steps by resource before binding | 24/0 SURVIVED | Approve the table plan `[notes, journal]`, execute the swapped plan object. Under the plant, `execute` returned `Ok`. M3 still passes because it only swaps the steps slice. Clean tree: `PlanAltered`. | **LIVE execute** |
| R3-10 | `covers` percent-decodes both sides | 24/0 SURVIVED | Grant for `.../journal` covered `.../journa%6c`. Clean tree: covers is false. Guest URIs have no filesystem symlink; this is the matching plant. | **LIVE covers** |
| R3-11 | mark `used` before `validate_journal_write` | 23/1 CAUGHT by `failed_execute_does_not_spend_the_grant` (retry became `GrantSpent`, expected `Bridge`) | — | CAUGHT |
| R3-12 | `new_host_id` always returns `host-1` | 23/1 CAUGHT by `unused_review_does_not_run_on_a_second_host` (`Bridge` instead of `ForeignHost`) | — | CAUGHT |

`Host::review` still accepts any constructed `Plan`. `plan()` refuses a
space, an uppercase letter, and an empty name. The live collisions above
go through `review`, not through `plan()`.

### Concurrent execute and crash-between-spend

`Host::execute` takes `&mut self`. Two threads cannot call it on one Host
through the public API.

Two threads on the same `Grants` allow-once token gave one `Ok` and one
`use limit exceeded` (`r3_concurrent_validate_of_allow_once`). That is
library evidence for the lab manager, not a Host lock.

A Review replay after the minting `Host` is dropped is `ForeignHost`
(`r3_grant_replay_across_second_host_is_foreign`). A constant host id
(R3-12) is CAUGHT. An empty or NUL id (R3-8) is not.

Spend-then-execute, then retry, stays `Bridge` on the clean tree. Marking
`used` before validate (R3-11) turns that retry into `GrantSpent` and is
CAUGHT. The current order is validate, then record effects, then mark
`used`. A crash after validate and before `used` is the path
`failed_execute_does_not_spend_the_grant` already pins as `Bridge`.

## Rows: what counts

| Row | Where the call goes | Class | Counts as |
| --- | --- | --- | --- |
| Preview of the two-step plan | `preview()` | lab | Lab evidence |
| Notes step BLOCKED (`UsersAI`) | `runtime_gap()`, no bus | BLOCKED (STATIC), RA-5 | BLOCKED |
| Reject / altered resource / extra step / reorder of the steps slice / spent grant / other principal / newline split / trailing space | `Host::approval_check` | lab Host-gate | Lab evidence for the table plan. Constructed-plan collisions (R3-1, R3-2, R3-3, R3-9) are unpinned. |
| Review from another `Host::new()` | `host_id` inequality | lab Host-gate | Lab evidence for consecutive ids and for `host-1`/`host-10`. Empty and NUL ids are unpinned. |
| Unapproved journal `missing_token` | in-process `handle_remote_request_with_audit_dir` | library | Library evidence |
| Altered resource / allow-once / second use | lab `CapabilityManager::validate` | library | Library evidence |
| Same checks on the public bus entry | in-process public function | BLOCKED, RA-4 | BLOCKED |
| Approved journal write stored | in-process public function | BLOCKED, RA-4 | BLOCKED |
| BLOCKED journal effect from an in-process library call | `execute` → `invoke_journal` + audit dir | library | Library evidence that a call happened. Exact BLOCKED bytes are pinned against `stored`. Trailing or case-folded BLOCKED text is unpinned (R3-7). |
| Spawned `elastos` over the bus | absent | NEEDS RUNTIME | NEEDS RUNTIME |

The README's class column matches this table. The leftover stretch is
"exact path components" and "exact bytes" for shapes the suite never
builds, and "the review was minted by another host" for an empty or NUL
id.

## README and row-label check

Honest now, and kept:

- In-process `handle_remote_request_with_audit_dir`, "linked crate function
  in the test process".
- "A spawned `elastos` binary over the bus is NEEDS RUNTIME".
- UsersAI notes BLOCKED (RA-5). Stored journal BLOCKED (RA-4).
- `Grants::mint_journal_write` and `invoke_journal` stay callable and skip
  preview / `Host::execute`.
- The r2 binds (newline split, trailing space, parent path, `host-1` vs
  `host-10`, `stored` reply, spend after success) are named in the README
  and pinned by tests.

Stretch that remains:

- README "covers by exact path components". The code compares split `/`
  parts today. The suite never builds `..`, a trailing slash, ASCII case,
  or `%6c`. Those four plants survive.
- README "length-prefixed canonical bytes (including the principal,
  compared as exact bytes)". True for the ASCII pairs the suite builds.
  NFC/NFD, a Cyrillic confusable, a 255-byte truncated field, and a
  sorted step list keep the same binding. `Host::review` accepts those
  constructed plans.
- F-A15-approval's first named test is still
  `approved_plan_records_blocked_in_process_bridge_effects`. That is a
  success-path test. The four refusal names after it match the README.

The r1 overclaim "against the real Runtime" stays gone. The r2 overclaim
on prefix `covers` and prefix `host_id` is gone.

## Principles

- 3 No ambient authority. The Host gate holds for the table plan and for
  the r2 constructed pairs. A constructed `Plan` with colliding
  `canonical()` still executes under R3-1, R3-2, R3-3, and R3-9.
  `mint` and `invoke_journal` stay callable without `review`.
- 7 One authority model. Approval is still a `Choice` enum.
- 10 One canonical path. README names `approval_check` and the in-process
  public entry. Direct `invoke_journal` is a second path, and the README
  says so.
- 11 Fail closed, then explain. Spend-then-execute returns `Bridge`.
  R3-11 then marks `used` first, so a retry becomes `GrantSpent`. That
  plant is CAUGHT. Empty or NUL `host_id` fails closed as `Bridge` after
  the journal invoke has already run.
- 12 Docs, code, and tests agree on BLOCKED storage and on "in-process".
  They stretch on "exact" covers and on "exact bytes" for Unicode,
  truncation, and a reordered plan object.
- 16 UI is not authority. The preview records no grant.
- 18 Isolated instances. `Review` carries `host_id`. Consecutive ids and
  `host-1`/`host-10` are pinned. Empty and NUL ids are not.
- 19 Consequences, not transports. The public entry refusal is labeled
  BLOCKED. That part holds.

DeepSeek: none. I did not change Runtime source.

## Ranked fixes for #284

1. Bind the ordered step list into `canonical()` so that approve
   `[notes, journal]` and execute the swapped plan object is
   `PlanAltered` (closes R3-9). M3 only swaps the steps slice.
2. Refuse at `Host::review` a constructed plan `plan()` would refuse, or
   pin `canonical()` against NFC/NFD, a Cyrillic confusable, and a
   255-byte truncated field (closes R3-1, R3-2, R3-3).
3. Pin `covers()` with `..`, a trailing slash, ASCII case, and
   percent-encoding (closes R3-4, R3-5, R3-6, R3-10).
4. Keep `classify` on exact code and message bytes. A trailing space, a
   case change, or extra text must be `Bridge` (closes R3-7).
5. Treat empty and NUL `host_id` as `ForeignHost` before any bus call
   (closes R3-8).
6. Keep RA-4 / RA-5 as the Runtime half. Until a stored journal is
   asserted, A15 stays open.

## Bookability sentence

A15 is a lab model of preview and a Host approval bind, plus honest BLOCKED
rows for UsersAI (RA-5) and protected storage (RA-4). The r2 mutants are
dead. Constructed-plan collisions, folded covers, a flexible BLOCKED
reply, and an empty or NUL host id still survive the author's tests.
**Do not book A15. The journal write stays BLOCKED.**

## Next

#284 authors pin R3-1, R3-2, R3-3, R3-4, R3-5, R3-6, R3-7, R3-8, R3-9,
and R3-10, or write those limits into the README as lab limits. RA-4 and
RA-5 stay with Anders after 0.8.0. This review PR stays draft. Do not
merge #284 on the strength of this file.
