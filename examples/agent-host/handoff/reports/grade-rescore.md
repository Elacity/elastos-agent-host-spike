# Grade re-score at cee6d55 (after #30)

```text
Slice:        re-score of the 14-row grade and the checklist (docs only), before OMP idea 2.
Branch / PR:  claude/rescore-grade  (draft PR in this repo, base spike/agent-host)
Commit:       the commit that adds this file; parent cee6d55f5 (spike/agent-host, #30 merged)
Develop:      not merged in this slice.
Machine:      Linux 6.18.44 x86_64 (cloud container), rustc 1.91.0.
Changed:      examples/agent-host/handoff/reports/grade-rescore.md - this report
              examples/agent-host/handoff/HANDOFF.md - grade and checklist lines
              examples/agent-host/handoff/SLICES.md - stale open items reworded (no status change)
              examples/agent-host/handoff/LOG.md - one line
Rule:         the same as S0b: a point counts only if a named test merged on spike/agent-host proves it, and a
              falsifier makes that test fail. Every falsifier below was rerun for this report at cee6d55 (one at a
              time, restored with git checkout, tree clean after), except the two Mac tests, which cite Cursor's
              Mac falsifiers recorded in reports/EXEC-EXIT-CHANNEL.md.
Scale:        0 absent, 1 sketched, 3 real but incomplete, 5 production.
Result:       42 of 70 (was 38). Target 62. DeepSeek Harness 46.
Checklist:    56 of 63 (no status moves; three open items reworded, see below; one question)
Principles:   12 docs, code and tests agree: each point names its test and its falsifier.
DeepSeek:     none (the DeepSeek column is the 12 Oct canvas, unchanged).
Not proven:   listed per row. #21 and #23 merged into spike/photo-viewer, not spike/agent-host, so their tests are
              not counted here (row 14, below).
Answers:      Sasha, 22 Oct (see "Update" at the end): hold-usersai stays open; hold-adversarial gets one review
              record per merged slice (template added); photo PRs do not count toward the agent-host grade.
Questions:    (answered) 1. hold-usersai: mark it complete under the Users/self decision (S3, 20 Oct), or keep it open for the
                 UsersAI root? I kept it open.
              2. hold-adversarial: the record shows Codex (GPT family) reviews of #8, #24 and #27 (reports and
                 LOG), the S3 reports stop for Codex on #8, #9 and #20, and you reported Codex PASS for #30. No
                 review file with "VERDICT: PASS" on an exact head is in the repo. Add one per reviewed slice, or
                 is the item only about a push to Elacity?
              3. Count spike/photo-viewer (#21, #23) toward rows 13 and 14?
```

## Rows

Old is the last proven score (S0b 37, plus row 14 in S1: 38). A point "since S0b" names its merged test and the
falsifier that made it fail at cee6d55.

| Row | DeepSeek | Old | New | Points gained: test (falsifier) | Gap to the target | Needs |
| --- | --- | --- | --- | --- | --- | --- |
| 1 Agent loop | 5 | 3 | 3 | none | The loop makes no model call; one-shot lifecycle. | Runtime (a model grant with a budget, RUNTIME-BUDGET.md) |
| 2 Session log | 5 | 3 | **4** | see "Row 2" | Journal under `Users/self`, not `UsersAI`; the e2e test plays the shell; the hash chain detects corruption, not a hostile writer (owner-only storage does that). | Runtime/Anders (UsersAI root), Home (real shell policy) |
| 3 Prefix cache | 5 | 2 | 2 | none. The rendering is now pinned to the format number (JF05, JF06), but no cache hit is measured. | `--cache-ram` is 0; admission does not count a cache; the live Assistant does not call `packStablePrefix`. | Runtime (model provider), Home (Assistant, slice SA) |
| 4 Compaction | 4 | 3 | 3 | none | The model does not write the summary. | Runtime (a model grant) |
| 5 Tool system | 5 | 3 | **4** | see "Row 5" | Only the journal goes through `providers.invoke`; read, edit and run do not. | Runtime/Anders (read and edit providers) |
| 6 Edit reliability | 4 | 3 | **4** | see "Row 6" | No write through the object provider. | Runtime/Anders (EDIT-PROVIDER.md, after 0.8.0) |
| 7 Shell and tests | 4 | 2 | **3** | see "Row 7" | `cargo` is not in the image; crosvm on Linux is not tested (no KVM). | no Runtime needed (image and Mac) |
| 8 Git and undo | 2 | 2 | 2 | none | A restore is never applied; Versions on Home is manual. | Runtime (provider write), Home |
| 9 Skills | 4 | 3 | 3 | none. G2 is now pinned (S0c `a_child_must_sit_strictly_under_its_parent`, G2a/G2b), which closes an S0b gap, but a child is still not a separate instance. | A child is not a separate instance; child limits are idea 2 (not merged). | Runtime/Anders (Bus v2) for the instance; no Runtime needed for idea 2 |
| 10 Local model ops | 1 | 4 | 4 | none | The idle release and the `input_tokens` refusal are locked by source text, not by a behaviour test. | no Runtime change needed (tests only, model provider) |
| 11 Hosted and secrets | 2 | 3 | 3 | none. G3 is pinned (S0c `a_hosted_proposal_must_name_a_localhost_resource`), and grants are never stored (S2 `a_grant_is_never_stored`, S2e), but there is still no hosted run. | No hosted run. | Runtime/Anders (hosted provider, grant budgets) |
| 12 Capability model | 2 | 4 | 4 | none. The guest now gets real Runtime grants (row 5), but that is the row 5 point. | The real shell policy (`home-auto.json`) is not exercised for the agent; `UsersAI` root; no review file for hold-adversarial. | Home, Runtime/Anders |
| 13 Create an app | 3 | 2 | 2 | none on this branch | No in-Home scaffold write; Demo in Apps is manual. The Photos surface page (#23) is on spike/photo-viewer. | Runtime (provider write), Home |
| 14 Package and sell | 0 | 1 | 1 | none on this branch | The signature covers the entrypoint only; a second Home and revocation. The P4b bundle tool (#21: closure CID, signed trust policy with rollback floor and revocation, staged admission, 49 of 49 falsifiers in its own report) is on spike/photo-viewer, so not counted. | Anders (second Home, revocation). Photo PRs do not count (Sasha, 22 Oct). |

**Total: 42 of 70** (2 + 5 + 6 + 7 each +1). Target 62, so 20 to go. DeepSeek Harness 46.

### Row 2 Session log: 3 -> 4

S0b said: no durable store, no format version, no tamper refusal.
- Durable store, through the real Runtime bridge: `runtime::tests::the_agent_host_writes_and_reads_its_journal_through_the_real_bridge`
  (#20; run by run-e2e.sh). Falsifier Q01 (the guest writes with no precondition, so the bridge refuses it): FAILED (and
  `the_agent_host_refuses_a_format_1_journal_with_its_reason`). Q02 no longer matches the code (the rule moved to
  `provider_resource.rs`), so Q01 is the rerun.
- Format version: `a_wrong_format_version_is_refused` (S2), falsifier S2d, re-targeted at cee6d55 as RS01 (the format check removed): FAILED. A format 1 journal is refused with
  its reason: `a_format_1_journal_is_refused_with_its_reason` (#30), falsifier JF08: FAILED (and `a_format_1_task_shows_its_reason`).
- Integrity: `every_flipped_byte_is_refused` (S2), falsifier S2a: FAILED.
- Resume by head hash: `resume_on_another_head_stays_unknown_and_holds_appends` (#9), falsifier J06: FAILED.
- Typed records, so a person's message never reads as a record: `a_message_starting_with_each_label_stays_a_message`
  (#30), falsifier JF25: FAILED.

Not 5: the journal is under `Users/self`, and the test grants the requests itself.

### Row 5 Tool system: 3 -> 4

S0b said: the guest never calls `providers.invoke`; `fixture-grant` is a test token; gap G1.
- The guest's effect goes through the real Runtime with Runtime grants: the e2e test above, and
  `runtime::tests::the_agent_host_stores_nothing_when_its_journal_grants_are_denied` (#20), falsifier Q04 (a denied
  guest sends with a made-up grant): FAILED.
- It asks for exactly two grants on its own journal: `the_guest_asks_for_exactly_two_grants_on_its_own_journal` (#9),
  falsifiers P01: FAILED (and `a_refused_grant_request_sends_nothing`); P02: FAILED.
- No grant sends nothing: `a_journal_append_without_a_grant_sends_nothing` (#9), falsifier J01, re-targeted at cee6d55 as RS02 (the grant
  type was renamed): FAILED (and `a_refused_grant_request_sends_nothing`).
- G1: `dispatch_without_a_grant_is_denied_even_without_authorize` (S0c), falsifier R5 (dispatch ignores a missing
  grant): FAILED (and `a_grant_is_never_stored`,
  `the_same_command_waits_until_the_first_has_a_result`).

Not 5: only the journal is a real effect.

### Row 6 Edit reliability: 3 -> 4

S0b said: no write through the object provider. That is still true, so the row stops at 4. What is new (#24): an edit
may touch only whole lines the journal shows were read at the revision it names, a change is checked whole, and the
same no-op edit is refused after two.
- `an_edit_names_the_revision_it_read`, falsifier OR01 (the change revision is not compared): FAILED (+3).
- `a_two_file_change_writes_both_or_neither`, falsifier OA03 (the provider's written list is not checked): FAILED (+2).
- `an_older_version_line_is_not_seen_at_the_newer_version`, falsifier OS05: FAILED.
- `a_repeated_no_op_edit_is_refused`, falsifier ON01: FAILED (+4).

DeepSeek's observations are still lost on resume (S0b); ours are in the journal.

### Row 7 Shell and tests: 2 -> 3

S0b said: the boot is Mac only and not run here; `cargo` is not in the image. What is new (#27): the exit code comes
only from a channel the command cannot write, and the command runs unprivileged.
- `a_forged_console_line_with_the_vm_killed_fails` (exec_vm.rs), falsifier XE01: FAILED.
- `an_early_forged_line_does_not_end_or_decide_the_run`, falsifier XE02: FAILED (both forged-line tests).
- `a_command_runs_unprivileged_and_its_code_is_reported` (exec-image supervisor, as root with real vsock here),
  falsifier SV02 (the command stays root): FAILED.
- `test_an_init_that_prints_an_exit_line_is_refused` (initramfs builder), falsifier BI06: FAILED.
- On the Mac (Cursor, 21 Oct, at 088ff76ba, recorded in reports/EXEC-EXIT-CHANNEL.md): `exec_smoke_image_prints_hello`
  and `a_forged_exit_line_cannot_pass` pass 2 of 2; the supervisor skipping the privilege drop, the console read
  without a report, and the harness stopping on a console line are each caught. Not rerun here (no Apple
  Virtualization).

Not 4: `cargo test` cannot run in the image.

## Checklist (56 of 63)

No status moves. The seven open items, each with what it needs:

| Item | State today | Needs |
| --- | --- | --- |
| `prefix-phase-a-pack` | Still true: the live Assistant builds its prompt in `compileLiveContext`; slice SA, with Sasha's yes. | Home (Assistant capsule) |
| `prefix-aplus-hit` | Still true: `--cache-ram` is 0; no cache hit measured in Home. | Runtime (model provider admission) |
| `compact-aplus-model` | Still true: the guest does not call a model. | Runtime (a model grant with a budget) |
| `exec-cargo-in-image` | **Reworded:** the image is now built from this repo (`examples/exec-image`, #27), with an unforgeable exit channel; `cargo` is still not in it. | no Runtime needed (Mac) |
| `hold-usersai` | **Stale, reworded:** the end-to-end test through the real bridge merged in #20. What is left: per-principal UsersAI root (Sasha, 22 Oct: keep open). | Runtime (Anders) |
| `hold-adversarial` | **Reworded:** Codex (GPT family) reviews are recorded for #8, #24 and #27, the S3 PRs stopped for Codex before merging, and #30 had a Codex PASS; no review file records a verdict on an exact head. Sasha, 22 Oct: one record per merged slice, `handoff/reviews/<PR>-<short head>.md`, from `reviews/TEMPLATE.md`; Cursor sends the past verdicts. | Sasha and Cursor (no Runtime change) |
| `sell-second-home` | Still true. | Anders |

## Falsifier reruns at cee6d55

All at cee6d55 in a separate worktree, each alone, restored with `git checkout`, tree clean after.

| Id | Mutation | Failed |
| --- | --- | --- |
| S2a | record link check removed | `every_flipped_byte_is_refused` |
| RS01 (S2d) | format version check removed | `a_wrong_format_version_is_refused` |
| JF08 | format 1 not recognised | `a_format_1_journal_is_refused_with_its_reason`, `a_format_1_task_shows_its_reason` |
| JF25 | a kind read from a text prefix again | `a_message_starting_with_each_label_stays_a_message` |
| J06 | resume accepts any head | `resume_on_another_head_stays_unknown_and_holds_appends` |
| Q01 | the guest writes with no precondition (e2e) | `the_agent_host_writes_and_reads_its_journal_through_the_real_bridge` (+1) |
| Q04 | a denied guest sends with a made-up grant (e2e) | `the_agent_host_stores_nothing_when_its_journal_grants_are_denied` |
| P01 | the guest asks for a third grant | `the_guest_asks_for_exactly_two_grants_on_its_own_journal` (+1) |
| P02 | the guest asks for the Agents folder | `the_guest_asks_for_exactly_two_grants_on_its_own_journal` |
| RS02 (J01) | no grant still sends | `a_journal_append_without_a_grant_sends_nothing` (+1) |
| R5 | dispatch ignores a missing grant | `dispatch_without_a_grant_is_denied_even_without_authorize` (+2) |
| OR01 | the change revision is not compared | `an_edit_names_the_revision_it_read` (+3) |
| OA03 | the provider's written list is not checked | `a_two_file_change_writes_both_or_neither` (+2) |
| OS05 | seen lines ignore the version | `an_older_version_line_is_not_seen_at_the_newer_version` |
| ON01 | the no-op count is infinite | `a_repeated_no_op_edit_is_refused` (+4) |
| XE01 | no report falls back to the console | `a_forged_console_line_with_the_vm_killed_fails` |
| XE02 | the console code wins over the report | both forged-line tests |
| SV02 | the command stays root | `a_command_runs_unprivileged_and_its_code_is_reported` |
| BI06 | an init that prints an exit line is accepted | `test_an_init_that_prints_an_exit_line_is_refused` |

Three older mutations no longer match the code (S2d, J01, Q02): S2d and J01 were re-targeted as RS01 and RS02 with the
same intent, and Q01 stands in for Q02. No mutation survived.

## Update: Sasha's answers (22 Oct)

Cursor: #33 is docs only.
1. `hold-usersai` stays open, reworded "per-principal UsersAI root; needs Runtime (Anders)".
2. `hold-adversarial`: one review record per merged slice in `handoff/reviews/<PR>-<short head>.md`, with the PR,
   the exact head, the reviewer and AI family, the verdict, the date and a one-line finding summary. The template is
   `handoff/reviews/TEMPLATE.md`. Cursor sends the past verdicts; they are not written here.
3. The photo PRs (#21, #23) do not count toward the agent-host grade. The total stays 42 of 70.

Checklist stays 56 of 63.

**What is next:** Codex on #33 (docs only). OMP idea 2 is #31.
