Slice:        A15 r6 lab fix (PR #448 head 94535044)
Branch / PR:  cursor/a15-r4-fail-closed-c89c  https://github.com/Elacity/elastos-agent-host-spike/pull/448
Commit:       a2d9e954217ce82cc4f9045ae301b6401cd42158   parent f1e17359cb3afb62c383281e37298e1ce73df753
Base:         cursor/a15-r4-fail-closed-c89c at 94535044a34f91305afe1cdc988ade9a48ea7b5c
Develop:      not merged this turn (new commits on #448 only; #284 left unpushed)
Machine:      Linux x86_64, rustc 1.91.0 (f8297e351 2025-10-28)
Changed:      lab/intent-planner/src/runtime_bridge.rs - ready peek verifies issuer and signature
Changed:      lab/intent-planner/src/lib.rs - fail-closed grant host_id bind against this Host; four r6 pins
Changed:      lab/intent-planner/plants/R6-1-foreign-token.txt, R6-2-rewritten-pair.txt, R6-3-empty-grant-host.txt, R6-4-copied-host.txt - one plant per r6 hole
Changed:      lab/intent-planner/plants/F-A15-approval.txt, R5-6d-rewritten-host.txt - old text matches the new bind
Changed:      lab/intent-planner/plants/M6-foreign-host.txt, N7-host-prefix.txt, R3-8-host-id.txt - also remove the new self.id bind so those hunts stay CAUGHT
Changed:      lab/intent-planner/README.md - r6 refusals; RA-4 / RA-5 / NEEDS RUNTIME stay
Changed:      examples/agent-host/handoff/LOG.md - one r6 line
Invariant:    journal_write_ready proves this Host minted the token (issuer and signature) before any bus call. An empty grant host_id is ForeignHost. The bind compares the grant to this Host's own id. A second Host that copies the minting id still fails the issuer check. Deleting either guard fails its pin.
Refusals:     foreign token Bridge (no bus, minted grant unused); rewritten grant and review pair Bridge (no bus); empty grant host_id ForeignHost; copied Host.id Bridge (no bus)
Tests run:    cargo fetch --locked --manifest-path lab/intent-planner/Cargo.toml -> exit 0
Tests run:    cargo fmt --manifest-path lab/intent-planner/Cargo.toml -- --check -> exit 0
Tests run:    cargo clippy --manifest-path lab/intent-planner/Cargo.toml --locked --offline --all-targets -- -D warnings -> exit 0 (intent-planner clean; elastos-server AsyncFd deprecation only)
Tests run:    cargo test --locked --offline --manifest-path lab/intent-planner/Cargo.toml -- --nocapture --skip model_planted_bugs_are_caught -> 48 passed; 0 failed; 0 ignored (run 1 on f1e17359, run 2 and run 3 on a2d9e954)
Tests run:    cargo test --locked --offline --manifest-path lab/intent-planner/Cargo.toml --lib model_planted_bugs_are_caught -- --exact --nocapture -> 1 passed in 164.97s then 164.96s; every named plant line printed FAILED
Not run here: spawned elastos (NEEDS RUNTIME)
Falsifiers:   every named plant test FAILED, then source restored. R6-1 / R6-2 / R6-4 delete the issuer check. R6-3 restores the fail-open bind. lib.rs SHA-256 ec911d70ef90ec37707d78f13617c2f2aaf3fe7aa5c49c3b4c23e4442263eaab before and after both plant runs. runtime_bridge.rs SHA-256 e2d6a97aa9a1eb29747d7d1b868e1c37f721ee1c8b1096a4ff6ed15e65945047 before and after both plant runs.
Guest hash:   unchanged (lab crate only)
Import list:  unchanged
Principles:   3 no ambient authority on a foreign token or a copied host id; 10 one bind path; 11 fail closed; 12 docs match BLOCKED rows; 18 token bound to the minting Host key
DeepSeek:     none
Not proven:   stored journal BLOCKED (RA-4); UsersAI notes BLOCKED (RA-5); spawned elastos NEEDS RUNTIME
Checklist:    A15 still open
Questions:    none

The copied-id hunt does not need a Runtime-side host identity. Each lab Host already has its own CapabilityManager key. Copying the `id` string leaves that key behind, so the ready peek refuses. A Runtime host identity is not claimed and is not added to NEEDS RUNTIME.

## Plant table

Old plants remain CAUGHT. New R6 plants are CAUGHT. 46 of 46.

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
| R6-1 | 1/1 `forged_foreign_token_does_not_reach_the_bus` | CAUGHT |
| R6-2 | 1/1 `rewritten_grant_and_review_host_id_does_not_reach_the_bus` | CAUGHT |
| R6-3 | 1/1 `invalid_grant_host_id_does_not_skip_the_bind` | CAUGHT |
| R6-4 | 1/1 `copied_host_id_does_not_run_on_a_second_host` | CAUGHT |
