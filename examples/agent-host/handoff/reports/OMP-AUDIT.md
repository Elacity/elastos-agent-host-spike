# OMP-AUDIT: ideas worth taking from oh-my-pi, ranked

```text
Slice:        OMP-AUDIT (read only, ideas only, no code), from handoff/OMP-AUDIT.md (queued by Sasha, 92a16fa).
              Run before S3 merged: Sasha said on 20 Oct to keep going while reviews wait. It touches no S3 code.
Branch / PR:  claude/omp-audit  (draft PR in this repo, base spike/agent-host)
Commit:       the commit that adds this file; parent 92a16fa (spike/agent-host)
Develop:      Elacity develop 3beb816438fd567145a8d725e22465bd83277cf0, merged, behind 0.
Machine:      Linux 6.18.44 x86_64 (cloud container).
Read:         oh-my-pi 2220e58146ebe31508e7a216242840d373e082d0, cloned to /tmp/oh-my-pi, outside the repo, never
              built or run. Three read-only agents read the seven areas; I re-read eight citations myself (all match).
Changed:      examples/agent-host/handoff/OMP.md - the comparison, every claim with a file at the read commit
              examples/agent-host/handoff/reports/OMP-AUDIT.md - this report
              examples/agent-host/handoff/LOG.md - one line
Invariant:    none (no code). Every idea is placed in the guest, a provider, Home (render only) or a content capsule;
              nothing goes into the Runtime core; nothing is copied.
Tests run:    none (no code change).
Falsifiers:   none run (no code). Each idea below names the test and the falsifier we would add when it is built.
Guest hash:   unchanged (no code).
Import list:  unchanged.
Principles:   3 No ambient authority, 7 One authority model, 18 Isolated execution: omp runs as the user on the host;
                every idea is moved behind a grant and a provider, and the rest is listed under "Not taken".
              5 Small trusted core: no idea adds to the Runtime core.
              11 Fail closed: omp's automatic recovery of a stale edit and its "skip malformed lines" are not taken.
              16 UI is not authority: approval stays a Runtime decision; Home only draws it.
DeepSeek:     none (this slice reads omp; OMP.md cites omp at 2220e58).
Not proven:   No omp code was run, so its tests are cited as ideas. Grade points below are estimates of what our own
              tests could earn; no grade changes until those tests and their falsifiers exist.
Checklist:    no item moves.
Questions:    1. Should the seen-range rule (idea 1) refuse an edit outside a windowed read, or only warn? I propose
                 refuse (fail closed), matching our read-before-edit rule.
              2. Idea 3 needs a budget per child: count model requests, wall time, or both?
```

## Ranked: what to take

Points are what our own tests could earn on that row (scale in HANDOFF section 1), from today's proven grade (S0b, before the S3 review). "Cloud" means it can be built and proven here; "Mac" means it needs the micro-VM or a real model.

| # | Idea (from OMP.md) | Lands in | Row: now -> could be | Where | Tests we would add (falsifier) |
| --- | --- | --- | --- | --- | --- |
| 1 | **Seen range and edit binding.** An edit may only touch text the journal shows was read (a windowed or cut read covers only its window); each edit carries the Runtime revision it read (S3's `if_revision`); a no-op edit repeated N times is refused; a change of several files applies all or none. omp: `patcher.rs:391-475`, `mismatch.rs:76-117`, `patcher.rs:776-781`; its writes are not atomic (`session.rs:313-331`) and we would be. | guest; edit or object provider | 6: 3 -> 4 | cloud | `an_edit_outside_the_read_window_creates_no_step` (falsifier: drop the window check); `an_edit_names_the_revision_it_read` (drop the revision); `a_repeated_no_op_edit_is_refused` (raise the count to infinity); `a_two_file_change_writes_both_or_neither` (write the first file before checking the second). Their `multi_file_failure_stages_nothing` and `unseen_anchor_without_shift_history_stays_rejected` are the cases to copy. |
| 2 | **Child limits.** Depth limit on child proposals (at the limit no child step); a budget per child with the abort reason recorded; a child result over a cap stored as a spill pointer; cancelling a parent stops new children and lets started ones settle. omp: `settings.ts:328-344`, `structured-subagent.ts:287-294`, `executor.ts:1576-1583`, `result-summary.ts:1-16`, `parallel.ts`. | guest | 9: 3 -> 4 (and helps 1) | cloud | `a_child_at_the_depth_limit_cannot_propose_a_child` (raise the limit); `a_child_over_budget_stops_with_its_reason` (ignore the budget); `a_long_child_result_is_a_spill_pointer` (store it inline); `cancelling_a_parent_starts_no_new_child` (start one anyway). |
| 3 | **Proposal validation and terminal states.** A model tool call that does not parse or fails its schema creates no step and records a model-visible error; a step that has a result never changes state; a step in a cancelled turn is cancelled, not left prepared; a pending capability request is denied when its capsule stops. omp: `utils.ts:572-592`, `tool-arguments.ts:21-41`, `agent-loop.test.ts:3119`, `cfg-approval-timeout.test.ts:199`. | guest; Runtime pending store (existing) | 5: 3 -> 4 | cloud for the guest half; needs the model loop to count fully | `a_malformed_tool_call_creates_no_step` (create a step with empty arguments); `a_settled_step_keeps_its_state` (let cancel or crash overwrite it); `cancelling_a_turn_cancels_its_prepared_steps` (leave them prepared); `a_stopped_capsule_leaves_no_pending_request` (keep it pending). |
| 4 | **Capability flags and honest errors in the model provider.** Typed flags on each offer (context window, max tokens, tools, vision, cache); a network failure is never reported as a bad key; a vision guard. omp: `packages/catalog/src/types.ts:1505-1761`, `api-key-validation.test.ts`, `vision-guard.ts:1-17`. | model provider capsule | 11: 3 -> 4 (10 stays 4) | cloud (provider unit tests) | `an_offer_states_its_context_window_and_tool_support` (drop a flag); `a_network_failure_is_not_a_credential_failure` (map both to one code); `an_image_to_a_text_model_is_replaced_by_a_notice` (pass it through). |
| 5 | **Head includes tool specs; cut rules.** A change in a tool description starts a new series, like a change in the system line; compaction never splits a step from its result and always keeps the newest turn; a provider overflow error triggers compaction, a payload-size error does not. omp: `append-only-context.ts:37-54`, `compaction.ts:509-597`, `session-maintenance.ts:2990-3015`. | guest | 3: 2 -> 2, 4: 3 -> 3 now (the A+ for both needs S4/S5 on the Mac); these harden what we have | cloud | `a_changed_tool_description_starts_a_series` (hash only the system line); `compaction_never_separates_a_step_from_its_result` (cut at the result); `a_payload_error_does_not_compact` (treat it as overflow). |
| 6 | **Resident interpreter inside the micro-VM.** Kept for one task under one grant; interrupt then kill; a "recreated" result; partial output kept and never replayed; an idle limit. omp: `kernel.ts:47-53`, `kernel-base.ts:246-252, 460-505`, `kernel-session-registry.ts:124-131`. | exec provider in the micro-VM | 7: 2 -> 3 | Mac | `an_interrupted_cell_reports_recreated_and_keeps_partial_output` (replay the cell); `a_cell_after_a_crash_runs_in_a_fresh_interpreter` (reuse the dead one). |
| 7 | **Browser limits in the browser capsule.** Allowed domains as part of the grant's resource, enforced in the provider; per-operation time limits naming the stalled step; a bounded close. omp: `network.ts:423-439`, `op-timeouts.ts:20-29`, `tab-worker.ts:2001-2011`. | browser capsule (micro-VM) | 13: 2 -> 3, 5 helps | Mac | `a_request_outside_the_granted_domains_is_refused_in_the_provider` (allow all); `a_timed_out_browser_step_names_what_stalled` (return a bare timeout). |

**If 1 to 4 are built and proven:** rows 6, 9, 5 and 11 each +1, so 37 -> 41 of 70 on the S0b baseline (S3's own effect on rows 2, 5 and 12 is counted separately after its review). 6 and 7 add rows 7 and 13 later on the Mac.

**Suggested order:** 1 (it builds straight on S3's revisions), then 2, then 3, then 4. Each is one slice, tests first, falsifiers for every refusal.

## Not taken (and why)

| omp pattern | Where | Why not | Principle |
| --- | --- | --- | --- |
| Runs as the user on the host; tools in-process; direct file writes with a "privileged fallback writer" | `agent-loop.ts`; `src/edit/index.ts:39-43` | The guest only proposes; a provider acts under a grant | 3, 7, 18 |
| Approval modes that allow without asking ("yolo", "write"); children forced to "yolo" | `approval.ts:44`; `executor.ts:1176-1182` | Every effect needs its own grant; a card is not a grant | 3, 16 |
| Child tools not intersected with the parent's | `executor.ts:4203-4238` | Ours must be strictly narrower | 3, 7 |
| Config values that run shell commands (`!…`) | `resolve-config-value.ts:23, 124` | Hidden execution path | 3, 5 |
| API keys in environment variables and `.env`; the JS worker gets the whole environment; a tool-bridge token in environment variables | `env-api-key.ts:13-55`; `worker-client.ts:185-199`; `tool-bridge.ts:151-160` | Secrets stay in the model provider; no bearer token in a child's environment | 3, 18 |
| Rotating across accounts on auth failure (up to 64) | `auth-retry.ts:135` | One principal, one grant; no account hopping | 7, 11 |
| Automatic recovery that re-applies an edit to a changed file | `recovery.rs:77` | A stale version is refused and read again | 11, 19 |
| Multi-file writes that are not atomic | `session.rs:313-331` | All or none | 19 |
| Session log without fsync; malformed lines skipped on load | `session-manager.ts:873-877`; `session-loader.ts:93-169` | Our journal is a compare-and-swap object and decode refuses any change | 11 |
| Relay to the user's real Chrome tabs; `--no-sandbox`; stealth patches | `browser.ts:158-235`; `launch.ts:55-75, 582` | The browser runs in its own micro-VM with its own profile | 18 |
| Changing to a larger model on overflow by itself | `session-maintenance.ts:3004-3015` | A different model is a new proposal under its own grant | 3 |

## What is next

Sasha reads OMP.md and this ranking, answers the two questions, and picks the first idea to build (I suggest idea 1, which builds on S3). The S3 PRs (#8, #9, #19, #20) and the sweep PR (#11) are still waiting for review.
