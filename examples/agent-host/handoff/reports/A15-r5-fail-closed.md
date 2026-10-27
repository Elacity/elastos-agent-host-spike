Slice:        A15 r5 lab fix (PR #448 head 3417741a)
Branch / PR:  cursor/a15-r4-fail-closed-c89c  https://github.com/Elacity/elastos-agent-host-spike/pull/448
Commit:       (this commit)   parent 3417741a9d6ca5eccde06eae5f07baa6e7879c03
Base:         cursor/a15-r4-fail-closed-c89c at 3417741a9d6ca5eccde06eae5f07baa6e7879c03
Develop:      not merged this turn (new commit on #448 only; #284 and #469 left unpushed)
Machine:      Linux x86_64, rustc 1.91.0 (f8297e351 2025-10-28)
Changed:      lab/intent-planner/src/lib.rs - validate all grants before spend or bus; mint binds approved resource; Grant.host_id bind
Changed:      lab/intent-planner/src/runtime_bridge.rs - mint_write / scoped_guest / journal_write_ready peek
Changed:      lab/intent-planner/plants/R5-7a-partial-spend.txt, R5-11-wrong-mint.txt, R5-6d-rewritten-host.txt - one plant per r5 hole
Changed:      lab/intent-planner/plants/F-A15-approval.txt, M7-bus-round-trip.txt, R3-11-used-before-validate.txt - keep old plants matching
Changed:      lab/intent-planner/README.md - r5 refusals; RA-4 / RA-5 / NEEDS RUNTIME stay
Changed:      examples/agent-host/handoff/LOG.md - one r5 line
Invariant:    A multi-step execute checks every grant unused and bound to the approved resource before any spend or bus call. The minted token names that resource. Execute refuses unless the executing Host minted the token and the review host_id matches that mint. Deleting any of those three guards fails its pin test.
Refusals:     second grant already spent Bridge (first grant unused, no bus); .../secrets OutsidePlan (token is not the journal); rewritten review host_id ForeignHost
Tests run:    cargo fetch --locked --manifest-path lab/intent-planner/Cargo.toml -> exit 0
Tests run:    cargo fmt --manifest-path lab/intent-planner/Cargo.toml -- --check -> exit 0
Tests run:    cargo clippy --manifest-path lab/intent-planner/Cargo.toml --locked --offline --all-targets -- -D warnings -> exit 0 (intent-planner clean; elastos-server AsyncFd deprecation only)
Tests run:    cargo test --locked --offline --manifest-path lab/intent-planner/Cargo.toml -- --nocapture --skip model_planted_bugs_are_caught -> 44 passed; 0 failed; 0 ignored in 1.18s
Tests run:    cargo test --locked --offline --manifest-path lab/intent-planner/Cargo.toml --lib model_planted_bugs_are_caught -- --exact --nocapture -> 1 passed in 166.92s; every named plant line printed FAILED
Not run here: spawned elastos (NEEDS RUNTIME)
Falsifiers:   R5-7a delete ready loop -> failed_two_step_execute_does_not_spend_the_first_grant FAILED (audit not empty) -> restored. R5-11 plant mint_journal_write -> secrets_path_does_not_mint_a_journal_token FAILED -> restored. R5-6d delete grant host_id bind -> rewritten_host_id_does_not_run_on_a_second_host FAILED -> restored. lib.rs SHA-256 4152256c5a128847b3f1f66aa6e7094e0f44e242835a4052136fef28572c4151 before and after. runtime_bridge.rs SHA-256 744de7720f282f0ced1e22cf1f893070511fe1160424553d5ad60d7c85295f18.
Guest hash:   unchanged (lab crate only)
Import list:  unchanged
Principles:   3 no ambient authority on a secrets path or a rewritten host_id; 10 one bind path; 11 fail closed; 12 docs match BLOCKED rows; 18 token bound to minting host
DeepSeek:     none
Not proven:   stored journal BLOCKED (RA-4); UsersAI notes BLOCKED (RA-5); spawned elastos NEEDS RUNTIME
Checklist:    A15 still open
Questions:    none

## Plant table

Old plants remain CAUGHT. New R5 plants are CAUGHT.

| Plant | Named tests FAILED | Grade |
| --- | --- | --- |
| F-A15-approval | 5/5 | CAUGHT |
| M1 | 1/1 `rejected_plan_executes_nothing` | CAUGHT |
| M2 | 1/1 `plan_altered_after_approval_is_refused` | CAUGHT |
| M3 | 1/1 `reordered_approved_steps_are_refused` | CAUGHT |
| M4 | 1/1 `approved_grant_runs_once` | CAUGHT |
| M5 | 1/1 `grant_lookup_uses_covers_for_the_exact_resource` | CAUGHT |
| M6 | 1/1 `execute_spends_the_allow_once_grant_at_the_lab_manager` | CAUGHT |
| M6-host | 1/1 `unused_review_does_not_run_on_a_second_host` | CAUGHT |
| M7 | 1/1 `blocked_journal_effect_comes_from_an_in_process_library_call` | CAUGHT |
| M8 | 1/1 `approval_for_one_principal_does_not_execute_for_another` | CAUGHT |
| N1 | 1/1 `newline_fields_do_not_collide` | CAUGHT |
| N2 | 1/1 `plan_altered_after_approval_is_refused` | CAUGHT |
| N3 | 1/1 `trailing_space_principal_is_a_different_plan` | CAUGHT |
| N4 | 1/1 `prefix_resource_does_not_cover_a_child_journal` | CAUGHT |
| N5 | 1/1 `grant_lookup_uses_covers_for_the_exact_resource` | CAUGHT |
| N6 | 1/1 `approved_plan_refuses_a_stored_bus_reply` | CAUGHT |
| N7 | 1/1 `prefix_host_id_stays_foreign` | CAUGHT |
| N8 | 1/1 `execute_spends_the_allow_once_grant_at_the_lab_manager` | CAUGHT |
| N9 | 1/1 `execute_spends_the_allow_once_grant_at_the_lab_manager` | CAUGHT |
| N10 | 1/1 `failed_execute_does_not_spend_the_grant` | CAUGHT |
| R3-1 | 1/1 `nfc_nfd_principals_do_not_collide` | CAUGHT |
| R3-2 | 1/1 `cyrillic_confusable_principal_is_a_different_plan` | CAUGHT |
| R3-3 | 1/1 `over_length_field_is_not_truncated` | CAUGHT |
| R3-4 | 1/1 `dotdot_path_does_not_cover_journal` | CAUGHT |
| R3-5 | 1/1 `trailing_slash_path_does_not_cover_journal` | CAUGHT |
| R3-6 | 1/1 `ascii_case_path_does_not_cover_journal` | CAUGHT |
| R3-7 | 1/1 `blocked_reply_is_a_whole_token` | CAUGHT |
| R3-8 | 1/1 `empty_or_nul_host_id_is_foreign` | CAUGHT |
| R3-9 | 1/1 `approved_step_order_is_bound` | CAUGHT |
| R3-10 | 1/1 `percent_encoded_path_does_not_cover_journal` | CAUGHT |
| R3-11 | 1/1 `failed_execute_does_not_spend_the_grant` | CAUGHT |
| R3-12 | 1/1 `unused_review_does_not_run_on_a_second_host` | CAUGHT |
| R4-1 | 1/1 `dot_or_dotdot_host_id_is_foreign` | CAUGHT |
| R4-2 | 1/1 `dotdot_notes_path_is_refused_at_execute` | CAUGHT |
| R4-3 | 1/1 `constructed_plain_principal_is_refused_at_execute` | CAUGHT |
| R4-4 | 1/1 `empty_plan_cannot_be_approved` | CAUGHT |
| R4-5 | 1/1 `duplicate_journal_steps_are_refused` | CAUGHT |
| R4-6 | 1/1 `embedded_dotdot_host_id_is_foreign` | CAUGHT |
| R4-7 | 1/1 `nul_intent_is_refused_at_execute` | CAUGHT |
| R5-7a | 1/1 `failed_two_step_execute_does_not_spend_the_first_grant` | CAUGHT |
| R5-11 | 1/1 `secrets_path_does_not_mint_a_journal_token` | CAUGHT |
| R5-6d | 1/1 `rewritten_host_id_does_not_run_on_a_second_host` | CAUGHT |
