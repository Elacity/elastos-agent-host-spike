# OMP idea 2: child limits (design draft, no code)

Written 21 Oct 2026. **Draft for review. Ideas only; no omp or DeepSeek code.** Building starts only after Codex
passes PR #24 (idea 1), and after Sasha answers the questions at the end.

Source: OMP.md section 3 and reports/OMP-AUDIT.md row 2 (omp at `2220e58`):
- depth 2, after which the child loses the `task` tool (`src/task/settings.ts:328-344`);
- a soft request budget, then a forced stop (`executor.ts:1576-1583`);
- results over 5000 characters become an `agent://` artifact (`result-summary.ts:1-16`);
- cancel stops new siblings and lets started ones clean up (`parallel.ts`).

Sasha's rule for the budget (20 Oct): **both model requests and wall time; stop at whichever runs out first, and
record which one.**

## What the guest has today (spike/agent-host f5396709c, `examples/agent-host/src/lib.rs`)

- `propose_child`: a Child step whose resource sits strictly under the parent step's resource. No grant is copied.
- `authorize_child`: the child needs its own grant; the parent's grant string is refused.
- `open_child_host`: a second journal with the system head and one Run step. It copies nothing else. It is not a
  second component; that waits for Bus v2.
- `grant_child_host`, and `record_child_result` (one result line, no grant string in it).
- `spill_pointer` (a long result stored as a pointer to a read object) and `cancel` (only from Prepared).

There is no depth limit, no budget, no stop reason, and no result cap for children.

## Rules (proposed)

**R1. Depth.**
- A step's depth is the number of Child links up its `parent_id` chain. A child host journal starts at its parent's
  depth plus one, and records that depth when it is opened.
- `CHILD_DEPTH_LIMIT = 2`, as in omp. A proposal that would go past it is refused with "depth limit", and no step
  is made. A child at the limit cannot propose a child at all.

**R2. Budget.**
- Every child is proposed with a budget: `requests` (model requests) and `seconds` (wall time). Both are required.
  A child with no budget is refused ("no budget"); there is no unlimited default (fail closed, PRINCIPLES 11).
- A child's budget may not be larger than its parent's remaining budget, the same way its resource must be narrower
  (3, 7). The top task's budget comes from the person or the shell, never from the model.

**R3. Stop at whichever runs out first, and record which.**
- **Requests:** the guest counts the model steps the child dispatches. When the count reaches the budget, the next
  model proposal is refused before anything is asked, and the child stops with reason `requests`.
- **Time:** the guest has no clock (its imports are capabilities, identity, providers, runtime and types), so it
  cannot measure time and does not pretend to.
  - Time is enforced by the Runtime: the child's grants expire (R6). When a call is refused because a grant has
    expired, the child stops with reason `time`.
  - Until R6 exists, the code that runs the child reports time through the same stop function (in tests, the test
    itself).
- **Which:** the first reason recorded is kept, and a later one does not replace it. The requests check runs before
  each ask and the time refusal comes from an ask, so the order is well defined.
- Reasons: `requests`, `time`, `cancelled`. A crash keeps today's states (not started, or settlement unknown).
- The parent's result line for the child names the reason and what was used, for example
  `child 7 stopped: requests (8 of 8 requests)`.

**R4. Result cap.**
- A child result longer than `CHILD_RESULT_CAP` (4,000 bytes, like `RUN_LOG_BUDGET`) is not stored inline.
- It must be a spill pointer to an object under the child's resource, read and current (today's `spill_pointer`
  rules).
- Over the cap with no pointer is refused. It is never cut silently.

**R5. Cancel.**
- When a parent is cancelled or denied:
  - new children of it are refused ("parent stopped");
  - its children that are still Prepared become Cancelled (reason `cancelled`);
  - children already dispatched are left to settle, and their results are still recorded. No state is rewritten.

**R6. Runtime layer (existing primitives; wiring them is after 0.8.0, Anders decides).**
- A capability token already has `max_uses` (refused with `UseLimitExceeded`), `expiry` (refused with
  `TokenExpired`) and `delegatable` (`elastos-runtime/src/capability/token.rs`, `manager.rs`).
- A child's model grant would carry `max_uses = requests`, every child grant `expiry = now + seconds`, and a child at
  the depth limit `delegatable = false`.
- The grant handler today offers only "once" and "session" (`api/handlers/capability.rs`, `grant_request`); this
  would add budget fields there.
- The bridge and `elastos-compute` would map `token_expired` and `use_limit_exceeded` to the guest's `time` and
  `requests` (like PR #19).
- Then the Runtime enforces the limits, and the guest's own count is a second check.

## Where it is stored (no journal format change, if option A is chosen)

- **Option A (proposed).**
  - A Child step's `argv` holds its budget as words: `requests=<n>`, `seconds=<n>`. Decode refuses any other word on
    a Child step, as PR #24 does for read rows.
  - A child host journal records `child depth=<d> requests=<n> seconds=<n>` in one node right after the system
    head, written by `open_child_host`.
  - The stop reason is the parent's result line plus one node in the child journal.
  - Everything round-trips in format 1.
- **Option B.** Journal format 2, with typed fields on the step for depth, budget and stop reason. Clearer bytes,
  but USERSAI-JOURNAL.md, the decoder and every stored journal must move.

## Tests and falsifiers

| Test | Falsifier |
| --- | --- |
| `a_child_at_the_depth_limit_cannot_propose_a_child` (also inside a child host journal) | raise the limit |
| `a_child_without_a_budget_is_refused` | default to unlimited |
| `a_child_budget_larger_than_the_parent_remaining_is_refused` | skip the parent check |
| `a_child_over_its_request_budget_stops_with_requests` (nothing asked after the limit) | ignore the count |
| `a_time_refusal_stops_the_child_with_time` | record it as an error |
| `the_first_stop_reason_is_kept` (requests, then time) | let the later reason overwrite |
| `a_long_child_result_is_a_spill_pointer` and `a_long_inline_child_result_is_refused` | store it inline, or cut it |
| `cancelling_a_parent_starts_no_new_child` (prepared children cancelled; a dispatched one keeps its result) | start one anyway, or rewrite the dispatched one |
| `a_child_budget_round_trips_in_format_1` (option A) | drop the words on encode |
| `an_unknown_word_on_a_child_step_does_not_decode` (option A) | accept it |

The Runtime layer (R6) gets its own tests when it is built: an expired child grant is refused, a use-limited model
grant refuses the n+1th call, and a non-delegatable grant cannot be delegated.

## Not taken from omp

- Children with `approvalMode: "yolo"`, child tools not narrowed to the parent's, and in-process children that
  share the parent's authority (3, 7, 18).
- No wall-clock limit by default: ours requires one.
- A soft budget with a grace period: ours refuses before the next ask.
- Concurrency (omp allows 32): children in one guest are proposed one at a time today; concurrency waits for
  separate component instances (Bus v2).

## Questions for Sasha

1. `CHILD_DEPTH_LIMIT = 2` (as omp)? `CHILD_RESULT_CAP = 4,000` bytes?
2. What counts as a model request: only hosted model steps, or local model calls too?
3. Default budget for the top task: none (the person must set one), or a stated default?
4. Option A (no format change) or option B (format 2)?
5. Should R6 (Runtime budget fields on grants) be written as its own design note for Anders now, like
   EDIT-PROVIDER.md?
