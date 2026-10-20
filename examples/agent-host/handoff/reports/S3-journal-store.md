# S3 journal store: tests first, stopped before the shipping change

```text
Slice:        S3 hold-usersai (journal under Users/self for now), item c of the 20 Oct plan.
              STOPPED as instructed before any change to shipping Runtime code outside test modules.
Branch / PR:  claude/s3-journal-store  (draft PR in this repo; link in LOG.md and the PR)
Commit:       67be5df98d43e52e336fcb0a4353f694069e82a9 (tests); parent 3702769 (merge of claude/guard-sweep, PR #5)
              This report is the next commit.
Develop:      Elacity develop 3beb816438fd567145a8d725e22465bd83277cf0, merged, behind 0.
Machine:      Linux 6.18.44 x86_64 (cloud container), rustc 1.91.0.
Changed:      elastos/crates/elastos-server/src/resource_bridge.rs - test module only: 5 tests that pass today
                and 2 #[ignore] tests for the shipping change; no production line changed
              examples/agent-host/handoff/reports/S3-journal-store.md - this report
              examples/agent-host/handoff/LOG.md - one line
Invariant:    Today, for localhost://Users/self/.AppData/Agents/<agent-id>/tasks/<task-id>/journal:
              a write with no grant, a read grant, another task's grant, or another principal's root never
              reaches storage. A granted write is stored encrypted under the launching person. An
              oversized frame is refused. (Holds now; pinned by the five tests.)
              Target, not yet true: a journal write must carry create_only or if_revision, a stale revision
              is refused, and the stored journal is kept (the two ignored tests).
Refusals:     no token                         -> missing_token, no file
              read grant / grant for task-2      -> capability_denied, no file
              Users/<other principal>/...        -> invalid_resource_invoke "localhost://Users roots must use
                                                    Users/self or the active principal root", no file
              frame > 1 MiB                      -> request_too_large, no file
              (target) stale if_revision         -> revision_conflict, journal unchanged
              (target) no create_only/if_revision -> revision_required, no file
Tests run:    export RUST_TEST_THREADS=2
              (cd elastos && cargo test -p elastos-server --lib -- <the 7 journal tests>) -> "5 passed; 0 failed; 2 ignored"
              (cd elastos && cargo test -p elastos-server --lib -- --ignored <the 2 target tests>) -> "0 passed; 2 failed"
                (expected: no "revision" in the write result; an unconditional write is accepted)
              (cd elastos && cargo clippy -p elastos-server --lib --tests -- -D warnings) -> clean
              (cd elastos && cargo fmt -p elastos-server -- --check) -> ok
              ./examples/agent-host/verify.sh -> 86 passed, 0 warnings; ./examples/agent-host/run-local.sh -> ok
              (cd elastos && cargo test -p elastos-compute --lib -- --include-ignored) -> 16 passed
              cargo test --manifest-path capsules/model-provider/Cargo.toml local_memory -> 7 passed
              node --test scripts/home-agent-prefix.test.mjs scripts/home-agent-no-store.test.mjs -> 4 passed
Not run here: Mac-only tests.
Falsifiers:   one at a time on the committed tests, undone with git checkout; tree clean after.
              S3a missing-token check skipped        -> a_journal_write_without_a_grant_never_reaches_storage FAILED
              S3b capability validation skipped     -> a_read_grant_or_another_tasks_grant_cannot_write_the_journal FAILED
              S3c alias scoping accepts a foreign root -> another_principals_journal_is_refused_before_the_grant_check
                                                        FAILED (+ team test handle_request_denies_foreign_user_root_before_pending)
              S3d both foreign-root checks removed   -> same two FAILED
              S3e handle_request frame cap removed   -> an_oversized_journal_write_is_refused_by_the_frame_cap FAILED
              The two ignored tests are their own falsifiers today: they fail because the change is missing.
Guest hash:   fa10cca7929f1d538e914337999230e9daf6cd5413edf8256824ceb893d6be33 (unchanged; guest not touched)
Import list:  unchanged (identity, runtime, types). See Question 1.
Principles:   3 No ambient authority / 11 Fail closed: no grant, a wrong grant, or a foreign root stops before storage.
              7 One authority model: the journal sits in the launching person's space, scoped the way
                Users/self is scoped for every app.
              19 Consequences: the target makes every journal write conditional, so a replay or a lost
                result cannot overwrite a newer journal.
DeepSeek:     none
Not proven:   The compare-and-swap through the bridge (the shipping change below). The guest does not
              propose or send an append yet (Question 1).
Checklist:    56 of 63 (hold-usersai stays pending)
Questions:    1. The guest needs elastos:bus/providers@1.0.0 to send an append: the three current imports
                 offer only runtime.info() and identity.context(). May S3 add it (with the adversarial
                 review), or should the Runtime collect the journal another way?
              2. May I make the shipping change below in resource_bridge.rs (about 40 lines, protected write
                 branch only)? It is security code, so the GPT review applies.
```

## Proposed shipping change (not made)

All of it goes in `protected_principal_root_resource_response`, `"write"` branch, `elastos/crates/elastos-server/src/resource_bridge.rs:525-566`:

1. **Read the precondition from the body.**
   - `create_only: true` becomes `PrincipalRootObjectPrecondition::Absent`.
   - `if_revision: "<rev>"` becomes `Revision(rev)`.
   - Both together, or either one together with `append: true`, is `invalid_content`.
2. **Journal paths must be conditional.** A path under `<root>/.AppData/Agents/` with no precondition returns `revision_required` and writes nothing.
3. **Write through `crate::auth::write_principal_root_object_if_revision` only** when a precondition is present. `PrincipalRootObjectWriteConflict` becomes a provider error with code `revision_conflict`. Writes with no precondition outside `Agents/` keep today's behaviour, so other apps are unchanged.
4. **Return the new revision.** On success, add `"revision": principal_root_object_revision(principal_id, &rooted, &bytes)`, so the guest can name it on the next append.
5. **Protection must not decide the path.** Today, when the principal root has no protection configured, this function returns `None` (line 487) and the write falls through to the localhost provider, with no compare-and-swap. A journal path must stay on the compare-and-swap path in that case too. `write_principal_root_object_if_revision` already writes plaintext when no protection is present (`require_protection: false`). Otherwise a Home without principal-root protection would store journals with blind writes.
6. **Tests.** Remove `#[ignore]` from the two target tests. Add "a journal write on a root with no protection still uses the compare-and-swap". Each step above gets a falsifier.

After that, the guest side (once Question 1 is answered):
- `ProposalKind::JournalAppend` and `propose_journal_append(agent_id, task_id, seen_revision)`;
- dispatch through `providers.invoke` with the launch grant;
- `note_crash` after dispatch is `settlement_unknown`, and resume compares the stored head hash (S2) with the guest's;
- the import list changes, with the adversarial review.

## What is next

Sasha answers the two questions. Then the shipping change above, then the guest side.
