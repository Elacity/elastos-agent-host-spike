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

## Update: Codex FAIL at 206da0d, seven findings (22 Oct)

All seven reproduced. Root cause for 1-3, as Codex said: some paths skipped the checks. Now one function per kind of
check, and every path calls it. A child's limits come only from the parent's journal.

```text
Commits:      3998623 (merge of spike/agent-host with #33; LOG.md kept both sides)
              b796516 (the fixes and seven tests), bc16234 (propose_child through usable_child only),
              b543367 (no second stopped or cancelled check), 8e6315f (notes); this report is the next commit
Shared:       child_rules       every child, on every load (stored_children_ok) and every live use
              usable_child      child_rules + a budget + not stopped + task not cancelled: propose_child (child
                                parent), ask_model (each child in the chain), child_grant_ok, open_child_host
              child_grant_ok    authorize_child and an inbox answer for a child
              stored_rules_ok   paths and children: decode_journal, and read_stored_journal (reread, resume)
Finding 1:    reread and resume used decode_bytes + stored_paths_ok only. Now stored_rules_ok.
              a_reread_or_resume_refuses_a_journal_that_breaks_a_child_rule (a running child below a stopped one,
              a wider child resource; reread Err, resume Refused, cursor unchanged)
Finding 2:    an inbox answer checked only "not the parent's grant". Now child_grant_ok, for the child's whole
              resource; a deny needs no check.
              an_inbox_answer_grants_only_a_usable_child_under_a_granted_parent (legacy child, parent without a
              grant, stopped child; journal unchanged; control granted)
Finding 3:    open_child_host took a parent step and a resource, and the host could record its own budget. Now it
              takes a child step that must be usable in the parent's journal; a host (depth above 0) refuses
              record_task_budget and ask_model ("child host"), and a stored host with a budget or a model call is
              refused. Its calls are ask_model(parent, Some(child), ..).
              a_child_host_spends_the_parent_budget_and_keeps_its_stop (one-request child: one request, also after
              reload; stopped child gives no host; forged host budget or call refused)
Finding 4:    the granted resource was dropped. A child's grant now keeps its scope in memory (grant_scope: the
              grant resource, or the whole resource for an inbox answer); a grandchild is granted only inside it.
              a_child_grant_scope_bounds_its_children (granted src/a: src/b refused for authorize and inbox, src/a/x
              granted; an inbox-granted child hands its scope on)
Finding 5:    records were counted in total. Now per child.
              each_child_has_exactly_its_own_records (B's budget or stop record moved to A)
Finding 6:    the task was checked before the chain. Now the children first.
              the_task_and_a_child_running_out_together_stops_the_child (child stops with requests, its child with
              cancelled, journal reloads)
Finding 7:    "no budget" and "parent has no budget" for a budget never recorded. Now TASK_BUDGET_REASON, also for
              a child from before idea 2 (its task predates budgets: start a new task).
              a_missing_budget_is_refused_with_the_task_budget_reason (ask_model and propose_child, task and
              legacy child; a legacy parent is refused before the child's own budget)
Failing first: the seven tests on 206da0d's lib.rs: "187 passed; 7 failed" (each of the seven FAILED).
Also:         a_cancelled_task_says_cancelled_on_every_live_path; a_child_that_breaks_a_rule_is_refused_on_every_live_path
              (an in-memory child with a wrong count is refused by every live path, through usable_child)
Changed tests: open_child_host now takes the child step (four tests and the run fixture); every_format_2_field_round_trips
              checks the header depth on a child host; the reload test's depth case is a host-with-a-budget case, plus a
              child past the limit inside a host at the limit; "no budget" expectations are TASK_BUDGET_REASON.
Tests run:    ./examples/agent-host/verify.sh -> "196 passed" (187 + 9), clippy clean, build OK
              ./examples/agent-host/run-local.sh -> "1 passed"; ./examples/agent-host/run-e2e.sh -> "3 passed"
Falsifiers:   CF01-CF21 new; CL01-CL92 rerun, the moved ones re-targeted (same id, same intent); TB01.
              First pass at bc16234: 4 of 113 survived (CL23, CL25, CF18, CF19), all redundancy from the one-path
              change. b543367 removes the two second checks (CL23, CL25 retire with their code) and adds the two
              tests above (CF18, CF19 then fail them).
              Full rerun at b543367: CF, CL, TB 111 of 111 caught (CL24 re-targeted to the dedented line: caught).
              CL02 retires (a host's depth is its child's; CF10 covers it).
              JF01-JF37 and the O* set at b543367: all caught except OZ01 (survives by design, as in #24);
              OY19 caught as a compile error; OS01, OP01, JF14, JF15 retired as before; OY06 and JF07 skip, and their
              re-targets OY06c (stored_rules_ok without the path rule: 4 FAILED) and JF07b (1 FAILED) are caught.
Guest hash:   35102c274fc29f59d187d7af0149361e1bf98a0d4b0813cb8753a63f5f702277 on verify.sh and a clean rebuild.
              wasm_sections.py: file 653844 bytes; /1/10 389892 91384db4aedcf2a8; /1/11 176551 7ca2e33174526964.
Import list:  unchanged (the core import section /1/2, 149 bytes, 5ee6b40d46f6a045, is byte-identical to #30).
```

## Update: the falsifier runner, and Codex FAIL at fe40437 (22 Oct)

```text
Runner:       examples/agent-host/falsify.py with examples/agent-host/falsifiers.json (ce522d1, 43ac688). Every
              live mutation is data: id, file, exact original text, replacement, command (host or e2e), expectation,
              and the named tests that must ALL fail. By id or prefix, --list, --self-test. The original is kept as a
              hard link and renamed back after each mutation, also on error, Ctrl-C or SIGTERM; a run killed outright
              is recovered at the next start; it stops below 2 GiB free or on a full-disk message.
              Checked here: --self-test OK (one named test still passing gives SURVIVED); SIGINT, SIGTERM and SIGKILL
              mid-mutation each leave src/lib.rs byte for byte as committed; the disk check stops with exit 3.
Codex hole 1: a child host kept open after its child stopped still got a grant.
Codex hole 2: a host reached src/b while its child was granted only src/a.
Cause:        the host was checked once, when it opened.
Fix:          d6129f5, 9328f13: every host action takes the parent's current journal and the child and goes through
              host_step_ok (host_scope: usable_child in the parent's journal, the host at the child's depth, the child
              granted; the step's resource on the path rule and inside the child's granted scope; not the parent
              step's grant). The plain authorize, apply_inbox and dispatch refuse a host's steps.
Other copies: a child's grant scope lives on the child step in the parent's journal and is read at each use; the
              journal cursor's revision and head are meant to be kept (compare and swap); grants are in memory only.
              No other object keeps a parent's or a child's state across calls.
Tests:        a_child_host_gets_nothing_once_its_child_stops (time stop, parent stop, cancel; a deny is still
              recorded) and a_child_host_touches_only_what_its_child_was_granted. Both failed on fe40437 (written
              against its API: "1 passed; 2 failed"). The run fixture covers the host inbox and dispatch.
Falsifiers:   HC01-HC14 added (HC03 survived first: its test case used "..", which host_path already refuses; the
              case is now an NFD name, and HC03 is caught).
Tests run:    ./examples/agent-host/verify.sh -> "198 passed", clippy clean, build OK
              ./examples/agent-host/run-local.sh -> "1 passed"; ./examples/agent-host/run-e2e.sh -> "3 passed"
Full run:     python3 -I examples/agent-host/falsify.py at 8f29f73: "206 CAUGHT, 1 CAUGHT (does not build), 1 SURVIVED
                (expected, by design) of 208", exit 0. The 208: CF01-CF21, CL01-CL92 without CL02, CL23, CL25,
                TB01, HC01-HC14, JF01-JF37 without JF07, JF14, JF15 plus JF07b, and the O* set without OS01, OP01,
                OY06 plus OY06c. OY19 must not build; OZ01 survives by design. The first full pass (43ac688) had one
                NO MATCH, CF08: host_scope now has the same line as open_child_host; re-targeted in 8f29f73 and caught.
Guest hash:   d05d64ddd6cb0d8563cc22d044e988dbc5b3c7c23b78492dc00199da5aae75dd on verify.sh and a clean rebuild.
              wasm_sections.py: file 657248 bytes; /1/10 392957 766f332d45d8c9e0; /1/11 176647 638faf0d30d1afd1.
Import list:  unchanged (the core import section /1/2, 149 bytes, 5ee6b40d46f6a045, is byte-identical to #30).
```

## Update: an independent review of 10a31e2 (22 Oct)

Sasha: no cross-family reviewer is available now, so continue. I ran an independent review by a fresh agent in its
own worktree, given only the code, the design note and the rules (not my conclusions). It is the same AI family
(Claude), so it does not replace Codex; the record is reviews/31-10a31e2.md.

```text
Verdict:      FAIL, 10 findings. Each probe test reproduced here before any fix ("0 passed; 10 failed").
Fixes:        63c54fc
  R1  the plain authorize granted a child, even the parent's grant -> a child is granted only through
      authorize_child or an inbox answer
  R2  a denied child kept asking the model, making children, acting in its host -> usable_child needs every child
      in the chain prepared or dispatched ("denied"; cancelled or crashed: "stopped")
  R3  the plain cancel left a child running with no stop -> a child is cancelled as a stop (record and subtree)
  R4  a host kept a scope after the scope above changed -> a child is granted once; scope_still_granted checks every
      step above (a run denied after granting takes the scope away) for host actions and new child grants
  R5  a child below a model call under a stopped child -> only a run or a child is a parent ("not a parent")
  R6, R7  child records written during an open compaction were dropped at commit and at a crash restore, so the task
      no longer loaded -> carried over
  R8  a prepared step put back where a stop or a cancel had reached loaded -> refused on load
  R9  a journal from before idea 2 with children three deep stopped loading -> the depth limit holds for budgeted
      children; older ones load and can do nothing (format 2 promise kept)
  R10 a host was not bound to its child -> host_of, in memory only (no format change); a reloaded host belongs to
      no child
Tests:        nine (R6 and R7 share one), each run on 10a31e2's code: "0 passed; 1 failed" for every one.
Changed:      a_spill_pointer_keeps_the_file_text granted a child through the plain authorize (R1's path); it uses
              authorize_child now. The reload test's depth case gives the over-deep child a budget.
Falsifiers:   RV01-RV17 added, each caught by its test when recorded.
              The full pass at 864c62f: 211 caught, OY19 does not build, OZ01 by design; 8 entries no longer
              matched their moved lines (CF07, CF18, CL59, CL79, HC01, HC04, HC05, HC12) and were re-targeted with
              the same intent; 4 survived because the new rules also covered their old cases (CL24, CL37, CL73,
              CL74). 52442a6: CL24 and CL79 name the tests with a started child; CL37 gets a new test,
              cancelling_a_started_child_stops_it; CL73 and CL74 get reload cases on a child with nothing below it.
Tests run:    ./examples/agent-host/verify.sh -> "208 passed", clippy clean, build OK
              ./examples/agent-host/run-local.sh -> "1 passed"; ./examples/agent-host/run-e2e.sh -> "3 passed"
Full run:     python3 -I examples/agent-host/falsify.py at 52442a6: "223 CAUGHT, 1 CAUGHT (does not build), 1 SURVIVED
                (expected, by design) of 225", exit 0 (CF 21, CL 89, TB 1, HC 14, RV 17, JF 35, O* 48).
Guest hash:   3e25a62cb23a74a94243e73adacff5542636448b85241db9eb31cbf4d2cf2d2a on verify.sh and a clean rebuild.
              wasm_sections.py: file 658799 bytes; /1/10 393728 a739263005d0d442; /1/11 176695 2dcb984f836276f1.
Import list:  unchanged (the core import section /1/2, 149 bytes, 5ee6b40d46f6a045, is byte-identical to #30).
```

## Update: Codex FAIL at 355e659, two findings (23 Oct)

Codex: both fe40437 holes fixed; its run passed 208 / 1 / 3 and 58 of 58 focused mutations; OY19 and OZ01 stand.

```text
Finding 1:    a stored budgeted child moved beneath a model call (resource Models/hosted/x) loaded through decode
              and the provider reread, and once granted its host acted outside the ancestor's src/a scope. Load used
              a second, looser parent rule, and the scope walk stopped at the model call.
Fix:          04a25cc, 6e00cb9: one function, may_hold_a_child (a run or a child), for propose_child, for every
              budgeted child on load (child_rules: decode, reread, resume refuse "not a parent"), and for the scope
              walk (no scope at a step that cannot hold a child). Children from before idea 2 keep loading, like the
              depth limit (a test now also loads one under a read step, and refuses a budgeted one there).
Tests:        a_stored_child_below_a_model_call_is_refused (decode, reread and resume refuse; no grant, inbox
              answer, host or dispatch for it) and the_scope_walk_does_not_stop_at_a_model_call (a parent child
              moved below a granted model call: its child's host gets no grant). Both failed on 355e659.
Falsifiers:   PR01 the load path drops the parent rule; PR02 the walk stops at a step that cannot hold a child;
              PR03 any step may hold a child; PR04 the rule also refuses older children; RV09 re-targeted to the
              shared line. All caught.
Finding 2:    the runner parsed test output, so a panic printing "test genuinely_passing ... FAILED" overwrote a
              real pass (confirmed: the 355e659 parser gives CAUGHT on that case).
Fix:          73843ef: the mutation is built first (a failed build is its own result); each named test is listed
              with --exact (exactly one must match) and run alone with --exact; failed only if it exits non-zero.
              Output is read only to stop on a full disk. --self-test reproduces Codex's case on a throwaway crate
              and must report SURVIVED naming the passing test; verify.sh runs it. --self-test --with-repo also
              runs TB01 with a passing name added (SURVIVED) and as listed (CAUGHT).
Tests run:    ./examples/agent-host/verify.sh -> "210 passed", runner self-test OK, clippy clean, build OK
              ./examples/agent-host/run-local.sh -> "1 passed"; ./examples/agent-host/run-e2e.sh -> "3 passed"
              python3 -I examples/agent-host/falsify.py --self-test --with-repo -> OK
Full run:     python3 -I examples/agent-host/falsify.py at 6e00cb9 -> 227 CAUGHT, 1 CAUGHT (does not build:
              OY19), 1 SURVIVED (expected, by design: OZ01) of 229; no NOT RUN, no NO MATCH
Guest hash:   39a003b2b1b421e3dc0fbdb6bb5580997d0dc264f060783fef8e5921a6501d9e on verify.sh and a clean rebuild.
Import list:  unchanged (the core import section /1/2, 149 bytes, 5ee6b40d46f6a045, is byte-identical to #30).
```

**What is next:** the Mac check and Codex on #31. Sasha closes #25 when #31 merges.

## Update: Codex FAIL at 75ac0ae, four findings (24 Oct)

```text
Finding 1:    provider_write_may_be_asked accepted a granted host edit after the parent task was cancelled,
              while dispatch_in_host refused it.
Fix:          the gate takes the parent journal and the child and calls host_step_ok, the one host check; a host
              journal with no parent context asks nothing.
Finding 2:    record_tool_result(parent, child, text, None) stored a host-only grant; the spill exception was open
              to any caller.
Fix:          child text needs verified host context (host_binding_ok: task mark, child id, depth, system head),
              used by record_child_result and the generic path; the guest's own spill pointer is a separate entry,
              record_spill_result, called only by spill_pointer. A host journal for a non-child step is refused.
Finding 3:    record_task_budget accepted one request on a pre-idea-2 journal with two calls; authorize and
              dispatch checked only presence.
Fix:          the counter rule in record_task_budget (calls already made) and in call_parent_usable before live
              use ("requests"), the same rule the reload check applies.
Finding 4:    a model call under a granted child dispatched after the root run's grant was withdrawn.
Fix:          call_parent_usable also walks the ancestor grants for a granted child (scope_still_granted).
Tests:        a_host_write_needs_its_parent_still_granting_it, a_child_result_needs_a_verified_host,
              an_older_journal_cannot_exceed_a_new_budget,
              a_model_call_under_a_granted_child_needs_the_grant_above_it. Each is caught by the falsifier that
              removes its fix.
Falsifiers:   PX19-PX24 new; PX14 and CL13 re-targeted to the moved checks; CL86, HC01, HC05, RV16, PX03 and
              PX04 re-targeted to host_binding_ok and the separate spill entry.
Full run:     python3 -I examples/agent-host/falsify.py: 251 CAUGHT, 1 CAUGHT (does not build: OY19), 1 SURVIVED
              (expected, by design: OZ01) of 253; no NOT RUN, no NO MATCH.
Tests run:    ./examples/agent-host/verify.sh -> "222 passed", runner self-test OK, clippy clean, build OK
              ./examples/agent-host/run-local.sh -> "1 passed"; ./examples/agent-host/run-e2e.sh -> "3 passed"
Guest hash:   0a1b2c0ca3660e0d9d166faf6f685c29d23f436989be7c546bf57ca30a4eb757 on verify.sh.
              wasm_sections.py: file 660815 bytes; /1/2 149 5ee6b40d46f6a045 (import list unchanged).
Principles:   3 (no new authority), 5 (all work stays in examples/agent-host), 10 (one shared check per rule),
              11 (each refusal keeps its reason and denies by default), 12 (design note updated), 7 (each rule has
              a failing-first test and a caught falsifier).
```

## Update: Codex FAIL at 75ac0ae, round 2 (24 Oct)

```text
Finding 1:    record_tool_result(parent, child, "host-only-grant", Some(&second_host)) stored the grant: the
              binding accepted any host journal for the same child, and only the supplied journal's steps were
              scanned.
Fix:          the parent journal keeps `host_grants` (child id, grant) for the process lifetime; `record_result`
              refuses child text containing any of them, so a second host for the same child cannot hide a grant
              given through the first. `without_grants` clears the list, so reload equality holds.
Finding 2:    record_spill_result accepted arbitrary text through the guest spill exception.
Fix:          the entry takes (journal, step_id, object_resource, version) and needs a dispatched granted step,
              a covering resource, and the journal's last event to be a `Spill` node for that resource and
              version; it builds the text. `spill_pointer` is its only caller.
Finding 3:    the write gate, the result host binding and the budget counter refused without a reason.
Fix:          the gate records `host_step_ok`'s reason or "not this child's host"; the result path records one
              reason for the missing host, the non-child step and the binding failure; the budget counter
              records "requests". All use `record_refusal_reason`.
Tests:        a_child_result_needs_a_verified_host (substituted host, 5 reasons),
              a_spill_pointer_cannot_carry_arbitrary_text,
              a_host_write_needs_its_parent_still_granting_it ("not this child's host", "cancelled"),
              an_older_journal_cannot_exceed_a_new_budget ("requests").
Falsifiers:   PX25-PX29 new; PX04, PX10, PX13, PX17, PX19-PX22, CL13, CL86 and HC07 re-targeted to the moved
              checks. PX10 now removes `child_result_ok` from the shared path; the host-step grant it used to
              remove is covered by the parent ledger (PX25).
Full run:     python3 -I examples/agent-host/falsify.py: 256 CAUGHT, 1 CAUGHT (does not build: OY19), 1
              SURVIVED (expected, by design: OZ01) of 258; no NOT RUN, no NO MATCH.
Tests run:    ./examples/agent-host/verify.sh -> "223 passed", runner self-test OK, clippy clean, build OK
              ./examples/agent-host/run-local.sh -> "1 passed"; ./examples/agent-host/run-e2e.sh -> "3 passed"
Guest hash:   9dae7f24f04bca6e9269e9d15cc0b92a0f48e5889900446abd479294bc6f75ea on verify.sh.
              wasm_sections.py: file 663717 bytes; /1/2 149 5ee6b40d46f6a045 (import list unchanged).
Principles:   3 (no new authority), 5 (all work stays in examples/agent-host), 10 (one shared check per rule),
              11 (each refusal keeps its reason and denies by default), 12 (design note updated), 7 (each rule has
              a failing-first test and a caught falsifier).
```
