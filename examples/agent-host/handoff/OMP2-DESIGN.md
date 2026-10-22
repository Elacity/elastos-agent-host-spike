# OMP idea 2: child limits

Written 21 Oct 2026 as a design draft (PR #25). Revised 22 Oct 2026 to match what was built on
`claude/omp2-child-limits` (guest only, `examples/agent-host/src/lib.rs`). This file replaces PR #25's draft; #25 is
superseded by the idea 2 PR. No omp or DeepSeek code.

Source: OMP.md section 3 and reports/OMP-AUDIT.md row 2 (omp at `2220e58`):
- depth 2, after which the child loses the `task` tool (`src/task/settings.ts:328-344`);
- a soft request budget, then a forced stop (`executor.ts:1576-1583`);
- results over 5000 characters become an `agent://` artifact (`result-summary.ts:1-16`);
- cancel stops new siblings and lets started ones clean up (`parallel.ts`).

## Decided (Sasha, 21 and 22 Oct)

- A budget has two limits: model requests and wall time. The child stops at whichever runs out first, and the
  reason is recorded.
- `CHILD_DEPTH_LIMIT = 2` and `CHILD_RESULT_CAP = 4,000` bytes.
- **A model request is every model call, hosted or local: one counter.**
- **The top task** gets a default budget that the person can see and raise. The host writes it into the grant, and
  the guest never chooses its own budget. **Children** always need an explicit budget; no budget means refused.
- **Cancel** stops the whole tree: no more model requests anywhere in it. Started children stop at their next model
  request; their partial results are kept and marked `cancelled`.
- **Storage:** journal format 2 (PR #30), using the reserved kinds 17 (child budget) and 18 (child stop). The format
  stays 2 only if nothing already written changes meaning (22 Oct). See "Format stays 2" below.
- **A child never gets more than its parent** (22 Oct): budget, grants and resources are each a subset, checked when
  the child is created and again after every reload.
- **Path rule** (22 Oct): `path_key` wherever it makes a limit stricter; the exact canonical path wherever it decides
  which file.

## What was built

### Depth (R1)

- Depth is derived, not stored per step: a step's depth is the number of Child steps up its `parent_id` chain
  (`child_chain`), plus the journal's own `depth`. A child host journal stores `depth` in its header (its parent's
  depth plus one, `open_child_host`). The step's depth byte stays 0.
- `propose_child` and `open_child_host` refuse anything past `CHILD_DEPTH_LIMIT` with "depth limit", and no step or
  journal is made. A child at the limit cannot propose a child.

### Budget (R2)

- `Budget { requests, seconds }`. Zero in either part is never a budget.
- **Top task:** `record_task_budget` records the budget the Runtime granted, once, as data. A second call, or a zero
  budget, changes nothing. No guest code path picks a value. Until the Runtime hands it over (RUNTIME-BUDGET.md),
  the guest fixture and the tests use `FIXTURE_TASK_BUDGET` and `FIXTURE_CHILD_BUDGET`; both are documented as never
  defaults.
- **Child:** `propose_child(journal, parent, resource, budget)` refuses, in this order:
  - "no parent";
  - "not a subset" (the resource is not strictly under the parent's);
  - "parent stopped" (the task is cancelled, or a child above has stopped);
  - "depth limit";
  - "no budget" (none, or a zero part);
  - "parent has no budget" (the nearest budgeted owner, or the task, has none);
  - "over the parent's budget" (more requests than the owner has left, or more seconds than the owner has).
- A budget is a cap, not a reservation: two siblings may each get what their owner has left. Their calls together
  stay bounded, because every call also counts against the owner.
- On success the Child step carries its budget, and one child-budget record (kind 17) is written:
  `child <id> budget: <requests> requests, <seconds> s`.

### Model calls (R2, R3)

- `ask_model(journal, under, model)`: every model call, hosted or local, is one `Hosted` step, so there is one
  counter. `under` is the child the call is asked for (stored as the step's `parent_id`), or none for the top task.
- It refuses before anything is asked: "host path", "not a child", "cancelled", "stopped", "no budget" (no task
  budget, or a chain child without one), "requests" (the task, or a child in the chain, has used its requests).
- When a child in the chain is used up, the top-most such child stops with `requests`, and its subtree with it.
- An accepted call counts once against every child in its chain and once against the task.

### Stop and time (R3)

- Reasons: `requests`, `time`, `cancelled` (`StopReason`). A crash keeps today's states.
- `stop_child` stops one child with its reason and every child below it with `cancelled`. Each stop writes one
  child-stop record (kind 18): `child <id> stopped: <reason> (<used> requests used)`. The draft's example
  `(8 of 8 requests)` was not used; the budget is already in the kind 17 record.
- The first reason is kept; a later one does not replace it and writes no record.
- **Time:** the guest has no clock and does not pretend to. `note_time_refusal` is called by the code that runs the
  child when a call is refused because a grant expired (in tests, the test itself). It stops the child with `time`.
  The child's `seconds` is checked as a subset of its owner's when it is made; the Runtime enforces it.

### Result cap (R4)

- `record_child_result` refuses a result longer than `CHILD_RESULT_CAP`; it is never cut. A long result goes as a
  spill pointer (`spill_pointer`, today's rules).
- A stopped child's result is kept and marked: `partial (<reason>): <result>`.

### Cancel (R5)

- `cancel_tree(id)`: a child stops with `cancelled`, and its subtree with it. A step that is not a child is cancelled
  as before (only from Prepared), and the children below it stop.
- `cancel_task`: the header records `cancelled_from` (the last step id at that time). Every child stops with
  `cancelled`, prepared steps become cancelled, and no model call or new child is accepted anywhere in the task. A
  reload stays cancelled.
- In the Runtime, cancelling should revoke each model grant in the subtree (RUNTIME-BUDGET.md). Not built here.

### Grants (subset)

- `authorize_child(journal, child, grant, grant_resource)` gives a child its own grant only when:
  - the step is a Child with a budget, and neither it nor anything above it has stopped;
  - `grant_resource` passes `path_refusal` and is the child's resource or under it (exact canonical path: a
    different case spelling or `//` is refused, never treated as the same file);
  - the parent holds a non-empty grant, and the child's grant is not the parent's.
- Grants are never stored, so after a reload the parent and every child are granted again through the same checks.

### Checked again after reload (`stored_children_ok`)

`decode_journal` refuses a journal where:
- the header depth is past the limit;
- a step names a parent that does not exist or comes after it, or a step other than a Child or a call under a Child
  has a parent;
- a step that is not a Child has a budget, a count or a stop;
- a Child's resource is not strictly under its parent's ("not a subset"), or it is past the depth limit;
- a Child's count is not the number of calls in its subtree;
- a Child's budget is zero, below its count, or larger (requests or seconds) than its owner's budget, or the task's
  ("over the parent's budget"); a Child without a budget has a count;
- the task budget is zero, or fewer than the calls made;
- the child-budget and child-stop records do not match the steps one for one;
- the task is cancelled but a Child has not stopped, or a Child or call came after the cancel point.

### Path rule

- Which file: the child's resource, the grant resource and the result's spill pointer are exact canonical paths
  (byte prefix under the parent). A case or alias spelling is a different path, and as a child of the parent it is
  refused.
- Limits: no idea 2 limit counts files, so no new `path_key` use was needed. Using the exact path for the subset is
  the stricter choice here: `path_key` would accept `demo/SRC` under `demo` as the same tree.

## Format stays 2

Nothing already written changes meaning:
- every idea 2 field (`cancelled_from`, `task_budget`, `depth` in the header; budget, requests used and stop in a
  step) is zero or "none" in a journal written before idea 2, and zero still means none, depth 0, top task;
- the step depth byte stays 0 (depth is derived), so older Child steps stay valid;
- kinds 17 and 18 were refused by decode before, so no older journal holds them;
- the 17 earlier kinds render byte for byte as before (`RENDERING_PIN` unchanged); kinds 17 and 18 have their own
  pin (`IDEA_2_RENDERING_PIN`).

Evidence: `a_journal_written_before_idea_2_still_loads` decodes a journal written by the guest at `cee6d55` and
re-encodes it to the same bytes.

**Behaviour changes (stated, not hidden):** a task with no recorded budget can no longer make a model call, an older
Child step with no budget can make no model call and gets no grant, and a new child needs a budget. These fail
closed (R2, PRINCIPLES 11). They change what the guest allows, not what a stored byte means.

## Tests and falsifiers

Each rule has a test, and each check has a mutation (CL01-CL91, report omp2-child-limits.md).

| Test | What it proves |
| --- | --- |
| `a_child_at_the_depth_limit_cannot_propose_a_child` | depth limit, also in a child host journal |
| `a_child_without_a_budget_is_refused` | no default, no unlimited |
| `a_child_budget_larger_than_the_parent_remaining_is_refused` | requests and seconds are a subset of what is left |
| `the_guest_never_sets_the_top_task_budget` | recorded once, never raised, never zero |
| `hosted_and_local_model_calls_share_one_counter` | one counter |
| `a_child_over_its_request_budget_stops_with_requests` | nothing asked after the limit |
| `a_stopped_child_stops_its_children` | the subtree stops with `cancelled` |
| `a_time_refusal_stops_the_child_with_time` | time is recorded |
| `the_first_stop_reason_is_kept` | requests, then time |
| `a_long_inline_child_result_is_refused`, `a_long_child_result_is_a_spill_pointer` | never inline, never cut |
| `cancelling_a_parent_stops_started_children_at_their_next_model_call` | partial result kept, marked |
| `no_model_call_anywhere_in_a_cancelled_tree` | grandchild too |
| `a_cancelled_tree_stays_cancelled_after_resume` | `cancelled_from` survives encode |
| `every_format_2_field_round_trips` | no field dropped |
| `child_limits_are_checked_again_after_reload` | each stored rule, broken in bytes, refuses the load |
| `a_child_grant_is_a_subset_of_its_parent` | parent grant needed, exact paths, again after reload |
| `a_journal_written_before_idea_2_still_loads` | format stays 2 |
| `the_child_records_render_byte_for_byte_and_are_pinned` | kinds 17 and 18 rendering |

## Not taken from omp

- Children with `approvalMode: "yolo"`, child tools not narrowed to the parent's, and in-process children that
  share the parent's authority (3, 7, 18).
- No wall-clock limit by default: ours always has one.
- A soft budget with a grace period: ours refuses before the next ask.
- Cancel that lets started children run to the end: ours stops them at their next model call.
- Concurrency (omp allows 32): children in one guest are proposed one at a time today; concurrency waits for
  separate component instances (Bus v2).

## Open

- RUNTIME-BUDGET.md (for Anders, after 0.8.0): grant limits, revoking a tree, how the guest learns its granted
  limits, and the refusal codes that let the guest record `time`.
- Home does not show the budget yet; that goes with the Home-wide refusal display, after 0.8.0 with the capsule kit.
