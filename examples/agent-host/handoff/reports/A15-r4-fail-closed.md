Slice:        A15 r4 lab fix (PR #284 head 36049b90)
Branch / PR:  cursor/a15-r4-fail-closed-c89c  https://github.com/Elacity/elastos-agent-host-spike/pull/448
Commit:       89c1cdc7556bc7db86dc5b20d913e0382428df8d   parent 2e82d3a5eb82ec5432ddda369d586a6c276aced4
Base:         cursor/intent-planner-a15-10c1 at 36049b90b6102b3dff937bf761f1a03029ce24e1
Develop:      not merged this turn (new draft PR targeting #284; #284 left unpushed)
Machine:      Linux x86_64, rustc 1.91.0 (f8297e351 2025-10-28)
Changed:      lab/intent-planner/src/lib.rs - one name grammar at execute; empty/duplicate refused; host_id `.` `..` `a..b` `...`; notes/foo/.. pinned
Changed:      lab/intent-planner/plants/R4-1-host-dot.txt through R4-7-nul-intent.txt - one plant per r4 hole
Changed:      lab/intent-planner/README.md - r4 refusals; RA-4 / RA-5 / NEEDS RUNTIME stay
Changed:      examples/agent-host/handoff/LOG.md - one r4 line
Invariant:    The strict ASCII name grammar plan() applies is also applied at execute. An empty plan cannot be approved. Duplicate resources never mint two grants or make two bus calls. Deleting the `.`/`..` host_id check or the execute path loop fails the suite.
Refusals:     `_ada` / `ada.` / `.ada` BadPrincipal; NUL intent BadIntent; empty plan EmptyPlan; [journal, journal] DuplicateStep; host_id `.` `..` `a..b` `...` ForeignHost; notes/foo/.. OutsidePlan
Tests run:    cargo fetch --locked --manifest-path lab/intent-planner/Cargo.toml -> exit 0
Tests run:    cargo fmt --manifest-path lab/intent-planner/Cargo.toml -- --check -> exit 0
Tests run:    cargo clippy --manifest-path lab/intent-planner/Cargo.toml --locked --offline --all-targets -- -D warnings -> exit 0 (intent-planner clean; elastos-server AsyncFd deprecation only)
Tests run:    cargo test --locked --offline --manifest-path lab/intent-planner/Cargo.toml -- --nocapture --skip model_planted_bugs_are_caught -> 41 passed; 0 failed; 0 ignored in 1.32s
Tests run:    cargo test --locked --offline --manifest-path lab/intent-planner/Cargo.toml --lib model_planted_bugs_are_caught -- --exact --nocapture -> 1 passed in 142.92s; every named plant line printed FAILED
Not run here: spawned elastos (NEEDS RUNTIME)
Falsifiers:   every named plant test FAILED, then source restored. lib.rs SHA-256 7a30fda81a2a12e5ea80428cfc69355b5fcb5f1a14cfdaed73785e909bb05ca3 before and after. runtime_bridge.rs SHA-256 b5a35da21f95b989ac473a03ea5f3ca2a1e3a064cdcd07de62ffc6f250c31932 (unchanged).
Guest hash:   unchanged (lab crate only)
Import list:  unchanged
Principles:   3 no ambient authority on constructed plans; 10 one bind path; 11 fail closed; 12 docs match BLOCKED rows; 18 host_id grammar
DeepSeek:     none
Not proven:   stored journal BLOCKED (RA-4); UsersAI notes BLOCKED (RA-5); spawned elastos NEEDS RUNTIME
Checklist:    A15 still open
Questions:    none

## Plant table

Old plants remain CAUGHT. New R4 plants are CAUGHT.

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
