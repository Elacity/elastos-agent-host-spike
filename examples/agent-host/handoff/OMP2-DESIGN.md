# OMP idea 2: child limits (design draft, no code)

Written 21 Oct 2026, revised the same day with Sasha's answers. **Draft for review. Ideas only; no omp or DeepSeek
code.** Building starts only after Codex passes PR #24 (idea 1).

Source: OMP.md section 3 and reports/OMP-AUDIT.md row 2 (omp at `2220e58`):
- depth 2, after which the child loses the `task` tool (`src/task/settings.ts:328-344`);
- a soft request budget, then a forced stop (`executor.ts:1576-1583`);
- results over 5000 characters become an `agent://` artifact (`result-summary.ts:1-16`);
- cancel stops new siblings and lets started ones clean up (`parallel.ts`).

## Decided (Sasha, 21 Oct)

- A budget has two limits: model requests and wall time. The child stops at whichever runs out first, and the
  reason is recorded.
- `CHILD_DEPTH_LIMIT = 2` and `CHILD_RESULT_CAP = 4,000` bytes.
- **A model request is every model call, hosted or local: one counter.**
- **The top task** gets a default budget that the person can see and raise. The host writes it into the grant, and
  the guest never chooses its own budget. **Children** always need an explicit budget; no budget means refused.
- **Cancel** stops the whole tree: no more model requests anywhere in it. Started children stop at their next model
  request; their partial results are kept and marked `cancelled`.
- **Storage:** option A only if no existing field changes meaning; otherwise option B. It does, so this draft uses
  **option B** (see "Where it is stored").

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
  depth plus one.
- A proposal that would go past `CHILD_DEPTH_LIMIT` is refused with "depth limit", and no step is made. A child at
  the limit cannot propose a child at all.

**R2. Budget.**
- Every budget has `requests` (model calls, hosted or local, one counter) and `seconds` (wall time).
- **The top task's budget comes from its grant.**
  - The host writes it into the grant, with a default the person can see and raise.
  - The Runtime returns the granted limits to the guest as data with the grant. The guest records them and never
    sets or raises them.
- **A child is proposed with an explicit budget**, or it is refused ("no budget"). There is no default and no
  unlimited value (fail closed, PRINCIPLES 11).
- A child's budget may not be larger than its parent's remaining budget, the same way its resource must be narrower
  (3, 7).

**R3. Stop at whichever runs out first, and record which.**
- **Requests:** the guest counts every model call in the child's subtree against that child's budget. When the
  count reaches the budget, the next model call is refused before anything is asked, and the child stops with
  reason `requests`.
- **Time:** the guest has no clock (its imports are capabilities, identity, providers, runtime and types), so it
  cannot measure time and does not pretend to.
  - Time is enforced by the Runtime, because the child's grants expire (RUNTIME-BUDGET.md). A call refused because
    a grant has expired stops the child with reason `time`.
  - Until then, the code that runs the child reports time through the same stop function (in tests, the test
    itself).
- **Which:** the first reason recorded is kept, and a later one does not replace it. The requests check runs before
  each ask and a time refusal comes from an ask, so the order is well defined.
- Reasons: `requests`, `time`, `cancelled`. A crash keeps today's states (not started, or settlement unknown).
- The parent's result line names the reason and what was used, for example
  `child 7 stopped: requests (8 of 8 requests)`.

**R4. Result cap.**
- A child result longer than `CHILD_RESULT_CAP` is not stored inline.
- It must be a spill pointer to an object under the child's resource, read and current (today's `spill_pointer`
  rules).
- Over the cap with no pointer is refused. It is never cut silently.

**R5. Cancel stops the tree.**
- Cancelling a step (from any state that has not settled) marks it and its whole subtree `cancelled`.
- From then on:
  - no model call is sent anywhere in that subtree;
  - a Prepared child becomes Cancelled;
  - a started child stops at its next model call: that call is refused, nothing is asked, and the child stops with
    reason `cancelled`;
  - partial results already recorded are kept, and the parent's result line marks them `cancelled`;
  - new children of a cancelled step are refused ("parent stopped").
- The guest's check is the second line. In the Runtime, cancelling revokes each model grant in the subtree (a token
  can already be revoked one by one: `CapabilityManager::revoke`), so a call that is already on its way is refused
  there too.

## Where it is stored: option B (journal format 2)

**Option A does not work without changing what an existing field means.**
- Putting the budget words in a Child step's `argv` changes that field's meaning: today `argv` is a run's arguments
  (USERSAI-JOURNAL.md documents one `argv` field).
- Putting the budget in a labelled visible record (like `spill`) is not safe. Those records are Person nodes, the
  same source as a person's own message (`admit_user`). Only the label line tells them apart, so a message that
  starts with the label would read as a budget record.

**Option B: format 2.** The guest decodes format 1 and format 2, and writes only format 2.
- A step gains typed fields:
  - `depth u8`;
  - `budget` (`u8` flag, then `requests u32` and `seconds u64`);
  - `requests_used u32`;
  - `stop u8` (none, requests, time, cancelled).
- The journal header gains `cancelled_from` (a `u8` flag, then a `u64` step id), so a resumed journal still knows
  that a tree was cancelled.
- A child host journal stores its own depth and budget in the header.
- **A format-1 journal decodes with:** depth from its `parent_id` chain, no budget, nothing used, and no stop
  reason. A child there with no budget may not send a model call, so it fails closed.
- The format number, USERSAI-JOURNAL.md, the cap test, and the format checks in the S3 e2e test all change. Golden
  bytes in the tests move.

## Tests and falsifiers

| Test | Falsifier |
| --- | --- |
| `a_child_at_the_depth_limit_cannot_propose_a_child` (also inside a child host journal) | raise the limit |
| `a_child_without_a_budget_is_refused` | default to unlimited |
| `a_child_budget_larger_than_the_parent_remaining_is_refused` | skip the parent check |
| `the_guest_never_sets_the_top_task_budget` (it comes from the grant) | let the guest pick one |
| `hosted_and_local_model_calls_share_one_counter` | count only hosted |
| `a_child_over_its_request_budget_stops_with_requests` (nothing asked after the limit) | ignore the count |
| `a_time_refusal_stops_the_child_with_time` | record it as an error |
| `the_first_stop_reason_is_kept` (requests, then time) | let the later reason overwrite |
| `a_long_child_result_is_a_spill_pointer` and `a_long_inline_child_result_is_refused` | store it inline, or cut it |
| `cancelling_a_parent_stops_started_children_at_their_next_model_call` (partial result kept, marked cancelled) | let the started child call once more |
| `no_model_call_anywhere_in_a_cancelled_tree` (grandchild too) | check only direct children |
| `a_cancelled_tree_stays_cancelled_after_resume` | drop `cancelled_from` on encode |
| `a_format_1_journal_decodes_with_no_budget_and_fails_closed` | give it an unlimited budget |
| `every_format_2_field_round_trips` | drop one field on encode |

## Not taken from omp

- Children with `approvalMode: "yolo"`, child tools not narrowed to the parent's, and in-process children that
  share the parent's authority (3, 7, 18).
- No wall-clock limit by default: ours always has one.
- A soft budget with a grace period: ours refuses before the next ask.
- Cancel that lets started children run to the end: ours stops them at their next model call.
- Concurrency (omp allows 32): children in one guest are proposed one at a time today; concurrency waits for
  separate component instances (Bus v2).

## Open

- Format 2 is a journal change. It needs Sasha's yes before building, as format 1 did.
- RUNTIME-BUDGET.md (for Anders, after 0.8.0) covers the Runtime side: grant limits, revoking a tree, and how the
  guest learns its granted limits.
