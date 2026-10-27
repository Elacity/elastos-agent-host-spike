# Independent review A15 r6 of draft PR #448

```text
PR:        #448 A15 r5: pin partial spend, wrong mint, and rewritten host_id
Head:      94535044a34f91305afe1cdc988ade9a48ea7b5c
Base:      cursor/a15-r4-fail-closed-c89c (same head); stacked on #284
Reviewer:  Cursor Grok (xAI family; #448 author is Claude)
Verdict:   FIX
Date:      27 Oct 2026
```

The claimed r5 suite is real. This reviewer re-ran it on that exact head:

- 44 host/library tests passed; 0 failed (the 45th is the plant runner).
- 42 of 42 plants CAUGHT. Source hashes after the run match the r5 report.
- Deleting each r5 guard fails its pin, then the file restores to the same SHA-256.
- RA-4, RA-5, and NEEDS RUNTIME are unchanged. `RUNTIME-ASK.md` is byte-identical to #284.

Four new ways still make a bus call without a matching approval on the executing Host. No grant is spent. The bus is still called. That is enough for FIX.

## Verdict

**FIX**

R5-7a, R5-11, and the one R5-6d shape (review `host_id` rewritten, grant `host_id` left as the minting host) fail closed. The ready peek does not prove this Host minted the token. The grant `host_id` bind is fail-open when that field is empty or when both `host_id` fields are rewritten together. A second Host that copies the minting `host_id` also reaches the bus.

## Plant table

Re-run of `model_planted_bugs_are_caught` on 94535044. Every named line printed `FAILED`, then the planted file was restored.

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

Manual delete of each r5 guard, then restore. `lib.rs` SHA-256 before and after each cycle: `4152256c5a128847b3f1f66aa6e7094e0f44e242835a4052136fef28572c4151`. `runtime_bridge.rs` stayed `744de7720f282f0ced1e22cf1f893070511fe1160424553d5ad60d7c85295f18`.

| Guard deleted | Pin | Result |
| --- | --- | --- |
| R5-7a ready-all loop | `failed_two_step_execute_does_not_spend_the_first_grant` | FAILED (audit not empty) |
| R5-11 mint always journals | `secrets_path_does_not_mint_a_journal_token` | FAILED (token resource is journal, not secrets) |
| R5-6d grant `host_id` bind | `rewritten_host_id_does_not_run_on_a_second_host` | FAILED (`Bridge` instead of `ForeignHost`) |

## Hunt

Same-crate field writes are in scope. Earlier rounds already mutate `Review.host_id` that way.

| Hunt | Result |
| --- | --- |
| Concurrent `execute` of one review on one Host (`Arc<Mutex<Host>>`, two threads) | CLOSED. One `Ok`, one `GrantSpent`. One spend. `&mut self` is the gate. |
| Grant spent (`validate_journal_write`) then `execute` | CLOSED. `Bridge`, no bus, retry is `Bridge` not `GrantSpent`. |
| Mint for a prefix or alias of the approved journal | CLOSED. Parent path and `.../journal2` mint that exact URI and `execute` is `OutsidePlan` with no bus. `Users/Self` does not mint (`runtime_gap`). |
| Public `Grant` constructor or serde | CLOSED. Fields are private. No `Serialize`/`Deserialize` on `Grant` or `Review`. No public constructor. |
| Cloned review, second `execute` | CLOSED. `GrantSpent`. One bus pair. |
| Error after the first of two journal bus calls | CLOSED. Forced fail on the first invoke leaves both grants unused. Retry runs. |
| Bus error, then grant state | CLOSED. Forced fail and `stored` reply leave the grant unused. Honest retry is not `GrantSpent`. |
| Integer overflow in step ids | CLOSED. `u32::MAX` and `0` have different canonical bytes. `execute` is `PlanAltered`. No bus. |
| Foreign token written into an approved grant | **SURVIVES.** `execute` returns `Bridge` after a `component.invoke` pair. |
| Review and grant `host_id` both rewritten to a second Host | **SURVIVES.** Same bus pair on the second Host. |
| Grant `host_id` cleared; review `host_id` rewritten | **SURVIVES.** The bind is skipped because `validated_name` is `None`. Same bus pair. |
| Second Host copies the minting `id` | **SURVIVES.** String compare passes. Same bus pair. |

The four survivors share one cause. `journal_write_ready` checks the URI and the use counter on this Host's store. It does not verify the signature or the issuer. `validate_journal_write` does, but only after `invoke_journal`. Each Host has its own `CapabilityManager` key (`SigningKey::generate`). A token this manager did not mint still looks ready, reaches the bus, then fails signature and returns `Bridge`. The grant on the minting Host stays unused. The bus still ran.

R5-6d only refuses when both `host_id` values are valid names and they differ. An empty grant `host_id` skips the bind. Rewriting both fields to the executing Host also skips it. Copying `Host.id` makes the strings match without a mint on that Host.

`Grant.host_id` is a string on a `Clone` struct. It is not the minting key.

## RA-4, RA-5, NEEDS RUNTIME

Unchanged.

- Notes read stays BLOCKED (STATIC). Needs RA-5.
- Stored journal stays BLOCKED. The public entry still returns `principal_context_required` / `principal-root storage requires an in-runtime protected storage bridge`. Needs RA-4.
- Spawned `elastos` stays NEEDS RUNTIME.
- `lab/intent-planner/RUNTIME-ASK.md` matches #284 (`origin/cursor/intent-planner-a15-10c1`) byte for byte.

A15 stays open.

## Minimal patches

Apply both. The string bind alone does not catch a copied `Host.id`. The signature check alone leaves the fail-open bind in place.

### 1. Ready peek must prove this Host minted the token

`lab/intent-planner/src/runtime_bridge.rs`, in `journal_write_ready`, after decode, before the URI check:

```rust
        if !token.verify_signature(self.manager.public_key())
            || token.issuer() != &self.manager.public_key_bytes()
        {
            return Err("token was not minted by this host".to_owned());
        }
```

Do not spend. Do not call the bus. A foreign token, a transplanted review, or a copied `Host.id` then returns `Bridge` with an empty audit.

### 2. Grant `host_id` bind must fail closed

`lab/intent-planner/src/lib.rs`, replace the three-`and` bind in `approval_check`:

```rust
            if validated_name(&grant.host_id).is_none()
                || grant.host_id != review.host_id
                || grant.host_id != self.id
            {
                return Err(Refuse::ForeignHost);
            }
```

An empty, NUL, or dotted grant `host_id` is `ForeignHost` before peek. A rewritten pair is `ForeignHost` when the grant field still names the minting host.

### 3. Pins (add to `src/lib.rs` tests)

Four tests. Each asserts `component_invoke_audit` is empty.

1. Swap `review.grants[0].token` for `Grants::new().mint_journal_write("ada")`. Expect a refusal and no bus.
2. Clone the review onto a second Host. Set both `review.host_id` and `grant.host_id` to that Host. Expect a refusal and no bus. The string bind matches; the ready peek must still refuse.
3. Same, but `grant.host_id.clear()`. Expect `ForeignHost` and no bus.
4. Set `host_b.id = host_a.id` and execute the original review. Expect a refusal from the ready peek, and no bus.

Suggested names: `forged_foreign_token_does_not_reach_the_bus`, `rewritten_grant_and_review_host_id_does_not_reach_the_bus`, `invalid_grant_host_id_does_not_skip_the_bind`, `copied_host_id_does_not_run_on_a_second_host`.

Applyable copies: `patches/ready-verify.diff`, `patches/host-bind.diff`, `patches/r6-pins.rs`.

### 4. Plants

Draft plants are in `plants/`. Copy them under `lab/intent-planner/plants/` after the pins exist. R6-1, R6-2, and R6-4 delete the ready-peek issuer check. R6-3 restores the fail-open bind.

## Commands

Machine: Linux x86_64, rustc 1.91.0 (f8297e351 2025-10-28). Subject crate restored after every mutation. This review did not push to #448 or #284.

```bash
export RUST_TEST_THREADS=2
git rev-parse HEAD
# 94535044a34f91305afe1cdc988ade9a48ea7b5c

sha256sum lab/intent-planner/src/lib.rs lab/intent-planner/src/runtime_bridge.rs lab/intent-planner/RUNTIME-ASK.md
# 4152256c5a128847b3f1f66aa6e7094e0f44e242835a4052136fef28572c4151  lib.rs
# 744de7720f282f0ced1e22cf1f893070511fe1160424553d5ad60d7c85295f18  runtime_bridge.rs
# 6377da9110cfeb5baab74cbbaab691e12d1bbd1f5bd43e86ca30cf3f24691d5b  RUNTIME-ASK.md

cargo fetch --locked --manifest-path lab/intent-planner/Cargo.toml
# exit 0
cargo fmt --manifest-path lab/intent-planner/Cargo.toml -- --check
# exit 0
cargo clippy --manifest-path lab/intent-planner/Cargo.toml --locked --offline --all-targets -- -D warnings
# exit 0 (intent-planner clean; elastos-server AsyncFd deprecation only)
cargo test --locked --offline --manifest-path lab/intent-planner/Cargo.toml -- --nocapture --skip model_planted_bugs_are_caught
# 44 passed; 0 failed; 0 ignored in 1.30s
cargo test --locked --offline --manifest-path lab/intent-planner/Cargo.toml --lib model_planted_bugs_are_caught -- --exact --nocapture
# 1 passed in 147.36s; 42 named plant lines printed FAILED

# Manual r5 guard deletes (each restored; lib.rs hash matched after):
# R5-7a -> failed_two_step_execute_does_not_spend_the_first_grant FAILED
# R5-11 -> secrets_path_does_not_mint_a_journal_token FAILED
# R5-6d -> rewritten_host_id_does_not_run_on_a_second_host FAILED

git diff --quiet origin/cursor/intent-planner-a15-10c1 -- lab/intent-planner/RUNTIME-ASK.md && echo UNCHANGED
# UNCHANGED
```

R6 probes were compiled in, run, then `git checkout -- lab/intent-planner/src/lib.rs`. The four survivors printed a `component.invoke.requested` / `component.invoke.completed` pair on the executing Host. Closed hunts are listed above.

## Next

On a new commit, not this review branch and not a push to #448 until Sasha says so: apply the two production patches, add the four pins and plants, re-run the 42 old plants plus the four new ones. Keep RA-4, RA-5, and NEEDS RUNTIME as they are. A15 stays open.
