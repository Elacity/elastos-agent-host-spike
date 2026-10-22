# OMP idea 2: child limits

```text
Slice:        OMP idea 2 (child limits), from the approved design in PR #25. Guest only.
Branch / PR:  claude/omp2-child-limits  (draft PR in this repo, base spike/agent-host)
Commit:       9a6fc72 (code and tests), ece49b0 (tests for the first-run survivors; the stopped-subtree reload rule;
              a stale comment), 36a0021 and c9486c9 (notes); parent cee6d55f5 (spike/agent-host, #30 merged);
              this report is the next commit
Develop:      not merged in this slice (base is spike/agent-host at cee6d55f5).
Machine:      Linux 6.18.44 x86_64 (cloud container), rustc 1.91.0.
Changed:      examples/agent-host/src/lib.rs - kinds 17 and 18, the idea 2 header and step fields, the child rules,
                the reload checks, the run fixture's idea 2 block; tests
              examples/agent-host/handoff/OMP2-DESIGN.md - the design note from PR #25, updated to what was built
              examples/agent-host/handoff/RUNTIME-BUDGET.md, EDIT-PROVIDER.md, JOURNAL-FORMAT-2.md,
                reports/OMP2-DESIGN.md - brought over from PR #25 unchanged (JOURNAL-FORMAT-2.md gets a status line
                and the two rendered texts), so nothing is lost when #25 closes
              examples/agent-host/handoff/USERSAI-JOURNAL.md - format 2: kinds 17 and 18, header and step rules,
                the reload refusals
              examples/agent-host/handoff/reports/omp2-child-limits.md - this report
              examples/agent-host/handoff/LOG.md - one line
              No Runtime, Home or provider change.
Invariant:    A child never gets more than its parent: its resource is strictly under the parent's, its budget
              (requests and seconds) is no more than its owner has left, and its grant is its own, for its resource
              or a part of it, and only while the parent holds one. Every model call, hosted or local, counts once
              against the task and every child above it. A used-up, timed-out or cancelled child stops with that
              reason (the first one is kept), and every child below it stops with "cancelled". All of this is
              checked again when a journal is loaded.
Refusals:     propose_child: "no parent", "not a subset", "parent stopped", "depth limit", "no budget",
                "parent has no budget", "over the parent's budget"
              open_child_host: "no parent", "not a subset", "depth limit"
              ask_model: "host path", "not a child", "cancelled", "stopped", "no budget", "requests"
              authorize_child, record_task_budget, record_child_result: false, nothing changes
              decode_journal (stored_children_ok): "depth limit", "not a subset", "over the parent's budget",
                "record" (see USERSAI-JOURNAL.md, Format 2)
Tests run:    ./examples/agent-host/verify.sh -> fmt, "187 passed" (162 - 1 + 26), clippy clean, build OK
              ./examples/agent-host/run-local.sh -> "1 passed" (the guest's run fixture in Wasmtime, now with an
                idea 2 block)
              ./examples/agent-host/run-e2e.sh -> "3 passed"
Not run here: Mac checks (Cursor): verify.sh, run-local.sh, run-e2e.sh and the guest hash.
```

## Format stays 2

Sasha's rule: format 2 stays only if nothing already written changes meaning. It holds:

- Every idea 2 field is zero or "none" in a journal written before idea 2, and zero still means none: no cancel, no
  task budget, depth 0, a step with no budget, no calls and no stop.
- The step depth byte stays 0. Depth is derived from the `parent_id` chain, so an older Child step (depth byte 0) is
  still valid.
- Kinds 17 and 18 were refused by every earlier decoder, so no stored journal holds them.
- The 17 earlier kinds render exactly as before: `RENDERING_PIN` is unchanged. Kinds 17 and 18 have their own pin.
- Evidence: `a_journal_written_before_idea_2_still_loads` decodes a 911-byte journal the guest wrote at `cee6d55`
  (a run and a child with no budget) and re-encodes it to the same bytes.

**What changes is behaviour, not meaning** (fail closed, design R2, PRINCIPLES 11):
- a task with no recorded budget can make no model call;
- an older Child step with no budget can make no model call and gets no grant;
- a new child needs an explicit budget.

These are refusals of things the guest allowed before. If Sasha counts that as "changes meaning", the format would
have to go to 3; I think it does not, because no stored byte reads differently.

## What changed

- **Kinds 17 and 18.** `ChildBudget { child, budget }` and `ChildStop { child, reason, requests_used }`: no free text,
  role user, written only by the host, kept through compaction. Rendering: `child <id> budget: <requests> requests,
  <seconds> s` and `child <id> stopped: <reason> (<used> requests used)`, pinned in `IDEA_2_RENDERING_PIN`.
- **Fields.** Header: `cancelled_from`, `task_budget`, `depth`. Step: `budget`, `requests_used`, `stop`.
- **Depth.** `CHILD_DEPTH_LIMIT = 2`, derived (`child_chain`, `depth_under`). `propose_child` and `open_child_host`
  refuse past it; a child host journal records its depth.
- **Budget.** `record_task_budget` records the Runtime's grant once (never zero, never raised). `propose_child`
  needs an explicit, non-zero budget no larger than the owner's remaining requests and its seconds.
- **Model calls.** `ask_model` (`propose_hosted` is now `ask_model(journal, None, model)`): one `Hosted` step per call,
  hosted or local, so one counter. Refused before anything is asked when the task is cancelled, a child above has
  stopped, there is no budget, or a budget is used up. A used-up child stops with `requests` (the top-most one, and
  its subtree with it).
- **Stop.** `stop_child`, `note_time_refusal` (the guest has no clock; the caller reports an expired grant),
  `cancel_tree`, `cancel_task` (records `cancelled_from`). The first reason is kept; each stop writes one kind 18
  record.
- **Result.** `record_child_result` refuses over `CHILD_RESULT_CAP = 4000` bytes (never cut; use a spill pointer), and
  marks a stopped child's result `partial (<reason>): <result>`.
- **Grants.** `authorize_child` needs a budgeted, unstopped child, a parent that holds a grant, a different grant, and
  a grant resource that passes `path_refusal` and is the child's resource or under it.
- **Reload.** `stored_children_ok` runs after `stored_paths_ok` in `decode_journal` and checks each rule above in
  stored bytes.
- **Path rule.** The child resource, the grant resource and the spill pointer are exact canonical paths (which file).
  No idea 2 limit counts files, so `path_key` had no new use; for the subset, the exact path is the stricter choice
  (`path_key` would accept `demo/SRC` under `demo`).
- **Guest fixture.** The run fixture records `FIXTURE_TASK_BUDGET` before its model call and its two child scenes,
  and a new block runs a child to its request limit, a time stop, a cancelled task, and a reload.

## Tests

Removed: `idea_2_fields_must_be_empty_until_built` (its rule, "empty until idea 2", is what this PR replaces; `idea_2_fields_follow_their_rules` takes its place).

New (26):
- `a_cancelled_tree_stays_cancelled_after_resume`
- `a_child_at_the_depth_limit_cannot_propose_a_child`
- `a_child_below_a_stopped_child_gets_nothing`
- `a_child_budget_larger_than_the_parent_remaining_is_refused`
- `a_child_grant_is_a_subset_of_its_parent`
- `a_child_over_its_request_budget_stops_with_requests`
- `a_child_without_a_budget_is_refused`
- `a_grandchild_budget_is_a_subset_of_its_parent_child`
- `a_journal_written_before_idea_2_still_loads`
- `a_long_child_result_is_a_spill_pointer`
- `a_long_inline_child_result_is_refused`
- `a_model_call_is_asked_only_for_a_budgeted_child`
- `a_stopped_child_stops_its_children`
- `a_time_refusal_stops_the_child_with_time`
- `an_unbudgeted_child_or_a_non_child_gets_no_child_grant`
- `an_unknown_step_stop_reason_is_refused`
- `cancelling_a_parent_stops_started_children_at_their_next_model_call`
- `child_limits_are_checked_again_after_reload`
- `every_format_2_field_round_trips`
- `hosted_and_local_model_calls_share_one_counter`
- `idea_2_fields_follow_their_rules`
- `no_model_call_anywhere_in_a_cancelled_tree`
- `the_child_records_render_byte_for_byte_and_are_pinned`
- `the_first_stop_reason_is_kept`
- `the_guest_never_sets_the_top_task_budget`
- `the_widest_used_up_child_stops_with_requests`

Changed: the existing tests and the run fixture record `FIXTURE_TASK_BUDGET` before a model call or a child (fail closed: without it, both are refused). `an_unknown_kind_is_refused` now tries 0, 20, 21 and 255, plus a child-stop record with an unknown reason. `each_kind_renders_byte_for_byte` covers tags 1 to 19.

## Falsifiers

CL01-CL92: one mutation per check, each alone, restored with `git checkout`, tree clean after; command
`cargo test` for the guest (scratchpad runner, as before).

- **First run (CL01-CL91, at 9a6fc72): 26 survived.** Most were reload checks backed by a second rule (the old
  tamper cases each broke two rules at once), plus CL10, CL18, CL20, CL26, CL49, CL76, CL77, CL79, CL82 and CL88 in
  the live code. That is a finding, not a pass: ece49b0 rewrites the reload test so each case breaks exactly one
  rule, and adds tests for the live ones. It also found one missing reload rule (a child below a stopped child must
  have stopped), added with its failing-first case and CL92.
- **Second run (CL01-CL92, at ece49b0): 92 of 92 caught. No survivors.**
- **JF01-JF37 and the O* set rerun at ece49b0:** all caught except OZ01 (survives by design, as in #24). OY19 is
  caught as a compile error, as before. OS01 and OP01 were retired in #24. JF14 and JF15 ("idea 2 fields must be
  empty") no longer apply: that rule is what this PR replaces, and CL43-CL75 cover the new rules. OY06 and JF07 no
  longer matched their lines; re-targeted as OY06b (stored path rule skipped: 3 tests FAILED) and JF07b (unknown
  kind decodes as a message: `an_unknown_kind_is_refused` FAILED).

| Id | Mutation | Caught by (second run) | First run |
| --- | --- | --- | --- |
| CL01 | propose_child allows one level deeper | `a_child_at_the_depth_limit_cannot_propose_a_child` | caught |
| CL02 | open_child_host allows one level deeper | `a_child_at_the_depth_limit_cannot_propose_a_child` | caught |
| CL03 | a child with no budget gets one | `a_child_without_a_budget_is_refused` | caught |
| CL04 | a child budget of zero requests is accepted | `a_child_without_a_budget_is_refused` | caught |
| CL05 | a child budget of zero seconds is accepted | `a_child_without_a_budget_is_refused` | caught |
| CL06 | a parent with no budget gives unlimited | `the_guest_never_sets_the_top_task_budget` | caught |
| CL07 | the requests over the parent are not checked | `a_child_budget_larger_than_the_parent_remaining_is_refused`, `a_grandchild_budget_is_a_subset_of_its_parent_child` | caught |
| CL08 | the seconds over the parent are not checked | `a_child_budget_larger_than_the_parent_remaining_is_refused`, `a_grandchild_budget_is_a_subset_of_its_parent_child` | caught |
| CL09 | remaining ignores what was used | `a_child_budget_larger_than_the_parent_remaining_is_refused` | caught |
| CL10 | a grandchild is measured against the task, not its parent | `a_grandchild_budget_is_a_subset_of_its_parent_child` | survived |
| CL11 | a child under a stopped parent is accepted | `a_stopped_child_stops_its_children`, `no_model_call_anywhere_in_a_cancelled_tree` | caught |
| CL12 | the task budget can be set twice | `the_guest_never_sets_the_top_task_budget` | caught |
| CL13 | a zero task budget is recorded | `the_guest_never_sets_the_top_task_budget` | caught |
| CL14 | local model calls are not counted for children | `child_limits_are_checked_again_after_reload`, `every_format_2_field_round_trips` (+2) | caught |
| CL15 | the task counter counts hosted models only | `child_limits_are_checked_again_after_reload`, `hosted_and_local_model_calls_share_one_counter` | caught |
| CL16 | the task allows one call past its budget | `hosted_and_local_model_calls_share_one_counter` | caught |
| CL17 | a child allows one call past its budget | `a_child_over_its_request_budget_stops_with_requests`, `a_stopped_child_stops_its_children` (+3) | caught |
| CL18 | the nearest used-up child stops, not the top-most | `the_widest_used_up_child_stops_with_requests` | survived |
| CL19 | a used-up child is refused but not stopped | `a_child_over_its_request_budget_stops_with_requests`, `a_stopped_child_stops_its_children` (+2) | caught |
| CL20 | a chain child with no budget may call | `a_model_call_is_asked_only_for_a_budgeted_child` | survived |
| CL21 | a task with no budget may call | `a_journal_written_before_idea_2_still_loads`, `the_guest_never_sets_the_top_task_budget` | caught |
| CL22 | ask_model ignores a cancelled task (own check) | `a_cancelled_tree_stays_cancelled_after_resume`, `no_model_call_anywhere_in_a_cancelled_tree` | caught |
| CL23 | chain_stopped ignores a cancelled task | `no_model_call_anywhere_in_a_cancelled_tree` | caught |
| CL24 | chain_stopped ignores a stopped child | `a_child_below_a_stopped_child_gets_nothing`, `a_child_over_its_request_budget_stops_with_requests` (+4) | caught |
| CL25 | ask_model ignores a stopped chain | `a_child_below_a_stopped_child_gets_nothing`, `a_child_over_its_request_budget_stops_with_requests` (+3) | caught |
| CL26 | ask_model accepts a step that is not a child | `a_model_call_is_asked_only_for_a_budgeted_child` | survived |
| CL27 | a call is not counted on the chain | `a_cancelled_tree_stays_cancelled_after_resume`, `a_child_budget_larger_than_the_parent_remaining_is_refused` (+9) | caught |
| CL28 | a call forgets which child asked | `a_cancelled_tree_stays_cancelled_after_resume`, `child_limits_are_checked_again_after_reload` (+2) | caught |
| CL29 | a stop does not reach the children | `a_stopped_child_stops_its_children`, `child_limits_are_checked_again_after_reload` (+2) | caught |
| CL30 | the children take the parent's reason | `a_stopped_child_stops_its_children`, `the_widest_used_up_child_stops_with_requests` | caught |
| CL31 | a later reason replaces the first | `child_limits_are_checked_again_after_reload`, `every_format_2_field_round_trips` (+1) | caught |
| CL32 | the stop record carries the wrong count | `a_cancelled_tree_stays_cancelled_after_resume`, `a_child_over_its_request_budget_stops_with_requests` (+7) | caught |
| CL33 | a stop leaves a prepared step prepared | `a_stopped_child_stops_its_children`, `no_model_call_anywhere_in_a_cancelled_tree` | caught |
| CL34 | descendants finds nothing | `a_stopped_child_stops_its_children`, `cancelling_a_parent_stops_started_children_at_their_next_model_call` (+3) | caught |
| CL35 | a time refusal records requests | `a_time_refusal_stops_the_child_with_time`, `an_unknown_step_stop_reason_is_refused` (+3) | caught |
| CL36 | a time refusal acts on any step | `a_time_refusal_stops_the_child_with_time` | caught |
| CL37 | cancel_tree on a child does not stop it | `no_model_call_anywhere_in_a_cancelled_tree` | caught |
| CL38 | cancel_tree on a run leaves its children | `cancelling_a_parent_stops_started_children_at_their_next_model_call` | caught |
| CL39 | cancel_task does not record the cancel | `a_cancelled_tree_stays_cancelled_after_resume`, `every_format_2_field_round_trips` (+1) | caught |
| CL40 | cancel_task records the first step, not the last | `a_cancelled_tree_stays_cancelled_after_resume`, `child_limits_are_checked_again_after_reload` (+1) | caught |
| CL41 | cancel_task leaves the children running | `a_cancelled_tree_stays_cancelled_after_resume`, `child_limits_are_checked_again_after_reload` (+2) | caught |
| CL42 | cancel_task can cancel twice | `no_model_call_anywhere_in_a_cancelled_tree` | caught |
| CL43 | the cancel point is not written | `a_cancelled_tree_stays_cancelled_after_resume`, `child_limits_are_checked_again_after_reload` (+1) | caught |
| CL44 | the task budget is not written | `a_cancelled_tree_stays_cancelled_after_resume`, `a_child_grant_is_a_subset_of_its_parent` (+6) | caught |
| CL45 | a step budget is not written | `a_cancelled_tree_stays_cancelled_after_resume`, `a_child_grant_is_a_subset_of_its_parent` (+6) | caught |
| CL46 | the journal depth is not written | `child_limits_are_checked_again_after_reload`, `every_format_2_field_round_trips` | caught |
| CL47 | a budget with the flag off and values is read as none | `idea_2_fields_follow_their_rules` | caught |
| CL48 | a non-zero step depth byte is read | `idea_2_fields_follow_their_rules` | caught |
| CL49 | an unknown step stop tag is read as cancelled | `an_unknown_step_stop_reason_is_refused` | survived |
| CL50 | an unknown child-stop reason is read as cancelled | `an_unknown_kind_is_refused` | caught |
| CL51 | stored: the header depth is not checked | `idea_2_fields_follow_their_rules` | caught |
| CL52 | stored: a parent after its child is accepted | `child_limits_are_checked_again_after_reload` | survived |
| CL53 | stored: a call under a non-child is accepted | `child_limits_are_checked_again_after_reload` | survived |
| CL54 | stored: any step may have a parent | `child_limits_are_checked_again_after_reload` | survived |
| CL55 | stored: a non-child may carry a budget | `child_limits_are_checked_again_after_reload` | survived |
| CL56 | stored: a non-child may carry a count | `idea_2_fields_follow_their_rules` | caught |
| CL57 | stored: a non-child may carry a stop | `child_limits_are_checked_again_after_reload` | survived |
| CL58 | stored: a wider child resource is accepted | `child_limits_are_checked_again_after_reload` | caught |
| CL59 | stored: one level deeper is accepted | `child_limits_are_checked_again_after_reload` | caught |
| CL60 | stored: the child count is not matched to its calls | `child_limits_are_checked_again_after_reload` | caught |
| CL61 | stored: a zero child budget is accepted | `child_limits_are_checked_again_after_reload` | survived |
| CL62 | stored: a child over its own budget is accepted | `child_limits_are_checked_again_after_reload` | survived |
| CL63 | stored: a child asking more requests than its owner is accepted | `child_limits_are_checked_again_after_reload` | caught |
| CL64 | stored: a child asking more seconds than its owner is accepted | `child_limits_are_checked_again_after_reload` | survived |
| CL65 | stored: a top child is not measured against the task | `child_limits_are_checked_again_after_reload` | caught |
| CL66 | stored: an unbudgeted child may count calls | `child_limits_are_checked_again_after_reload` | survived |
| CL67 | stored: the task may be over its budget | `child_limits_are_checked_again_after_reload` | survived |
| CL68 | stored: a zero task budget is accepted | `child_limits_are_checked_again_after_reload` | survived |
| CL69 | stored: a child-budget record need not match | `child_limits_are_checked_again_after_reload` | survived |
| CL70 | stored: a child-stop record's reason need not match | `child_limits_are_checked_again_after_reload` | survived |
| CL71 | stored: a child-stop record's count need not match | `child_limits_are_checked_again_after_reload` | survived |
| CL72 | stored: the child-budget records are not counted | `child_limits_are_checked_again_after_reload` | caught |
| CL73 | stored: the child-stop records are not counted | `child_limits_are_checked_again_after_reload` | caught |
| CL74 | stored: a cancelled task may hold a running child | `child_limits_are_checked_again_after_reload` | survived |
| CL75 | stored: a cancelled task may gain steps after the cancel | `child_limits_are_checked_again_after_reload` | survived |
| CL76 | authorize_child grants a child with no budget | `an_unbudgeted_child_or_a_non_child_gets_no_child_grant` | survived |
| CL77 | authorize_child skips the path check | `a_child_grant_is_a_subset_of_its_parent` | survived |
| CL78 | authorize_child skips the resource subset | `a_child_grant_is_a_subset_of_its_parent` | caught |
| CL79 | authorize_child grants a stopped child | `a_child_below_a_stopped_child_gets_nothing` | survived |
| CL80 | authorize_child does not need a parent grant | `a_child_grant_is_a_subset_of_its_parent` | caught |
| CL81 | authorize_child accepts the parent's own grant | `a_child_grant_is_a_subset_of_its_parent`, `a_child_grant_is_narrower_and_does_not_inherit_the_parent_grant` | caught |
| CL82 | authorize_child grants a step that is not a child | `an_unbudgeted_child_or_a_non_child_gets_no_child_grant` | survived |
| CL83 | a child host does not record its depth | `a_child_at_the_depth_limit_cannot_propose_a_child` | caught |
| CL84 | a long child result is accepted | `a_long_inline_child_result_is_refused` | caught |
| CL85 | a stopped child's result is not marked partial | `cancelling_a_parent_stops_started_children_at_their_next_model_call` | caught |
| CL86 | a child result is recorded for a step that is not a child | `a_long_inline_child_result_is_refused` | caught |
| CL87 | the depth limit is 3 | `a_child_at_the_depth_limit_cannot_propose_a_child`, `child_limits_are_checked_again_after_reload` | caught |
| CL88 | the child result cap is doubled | `a_long_inline_child_result_is_refused` | survived |
| CL89 | the child stop renders differently, format stays 2 | `a_child_over_its_request_budget_stops_with_requests`, `each_kind_renders_byte_for_byte` (+1) | caught |
| CL90 | the child budget renders differently, format stays 2 | `each_kind_renders_byte_for_byte`, `the_child_records_render_byte_for_byte_and_are_pinned` | caught |
| CL91 | propose_child does not write the budget record | `a_cancelled_tree_stays_cancelled_after_resume`, `a_child_budget_larger_than_the_parent_remaining_is_refused` (+7) | caught |
| CL92 | stored: a child below a stopped child may run | `child_limits_are_checked_again_after_reload` | new |

```text
Guest hash:   09c712ef28242ba663ede78c46c9c2988c1606837462854887c667940fd0028f on verify.sh and a clean rebuild.
              wasm_sections.py: file 652398 bytes (was 636434 at #30); /1/10 388475 991b3a3150a149c4 (code);
              /1/11 176527 cfc784e95b91e5f0 (data).
Import list:  unchanged: the core import section (/1/2, 149 bytes, 5ee6b40d46f6a045) is byte-identical to #30.
Principles:   3, 7: a child's budget, resource and grant are each a subset of its parent's, at creation and after
                reload.
              11: no budget means refused, not unlimited; the guest does not pretend to measure time.
              12: the earlier rendering pin is unchanged; the two new kinds have their own pin.
              16: the child records are host-written; no person's or model's text becomes one.
DeepSeek:     none. omp at 2220e58 for ideas only (cited in OMP2-DESIGN.md); no code copied.
Not proven:   - Time is not measured: the guest records `time` only when told (`note_time_refusal`). The Runtime
                side (grant expiry, revoking a tree, distinct refusal codes) is RUNTIME-BUDGET.md, after 0.8.0.
              - The top task's budget is a fixture constant until the Runtime hands the granted limits to the guest.
              - A budget is a cap, not a reservation: two siblings may each get what their parent has left, and
                their calls together are still bounded, because every call counts against the parent too. The
                reload check compares a child's budget with its owner's whole budget (not what was left when the
                child was made); the stored counts bound the calls.
              - Home does not show a budget or a stop; that goes with the Home-wide refusal display, after 0.8.0.
Checklist:    no item moves.
Questions:    1. Is "behaviour changes, meaning does not" (above) enough to keep format 2?
```

## Update: after the Mac check of b30580f4 (22 Oct)

Cursor at b30580f4: verify 187, local 1, e2e 3/3, tree clean (Mac guest hash 0161bde9; Linux differs, as known).
Sasha's answers: format 2 stays (stored bytes keep their meaning, and the new behaviour fails closed). The refusal for a
task with no recorded budget now says what to do, like the format 1 reason.

```text
Changed:      examples/agent-host/src/lib.rs - TASK_BUDGET_REASON = "the task budget was not recorded; start a new
                task", used by the run fixture's three refusals; the_guest_never_sets_the_top_task_budget pins the text
Tests run:    ./examples/agent-host/verify.sh -> "187 passed", clippy clean, build OK
              ./examples/agent-host/run-local.sh -> "1 passed"; ./examples/agent-host/run-e2e.sh -> "3 passed"
Falsifiers:   TB01 the reason loses "; start a new task" -> the_guest_never_sets_the_top_task_budget FAILED
              CL01-CL92 rerun on this head -> 92 of 92 caught; no survivors; tree clean
Guest hash:   032afd9244427b25211bd9799ed70586cb7c15668a0ad1b5b5115b5e6ba33883 on two clean builds and verify.sh.
              wasm_sections.py: file 652410 bytes; /1/10 388475 301b48d231337dbd; /1/11 176543 5963e6487618a95e.
Import list:  unchanged (the core import section /1/2 is byte-identical to #30).
```

**What is next:** Codex on #31. Sasha closes #25 when #31 merges.
