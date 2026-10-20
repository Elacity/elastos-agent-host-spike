# S3 bridge: revision preconditions and Agent journal rules

```text
Slice:        S3 part 1, the bridge change (hold-usersai, journal under Users/self). Security code: stop here
              for the GPT-family adversarial review before the guest side.
Branch / PR:  claude/s3-bridge-cas  (draft PR in this repo; link in LOG.md and the PR)
Commit:       52c5f311a33feed799edd563fab545b83b830f46 (bridge change, tests, 192 KiB cap, docs)
              942dcf6dba095de92e5a482b2462c5fdc93dd903 (clippy: compile-time frame-fit check)
              parent d9b1a82 (merge of claude/s3-journal-store, PR #6); this report is the next commit
Develop:      Elacity develop 3beb816438fd567145a8d725e22465bd83277cf0, merged, behind 0.
Machine:      Linux 6.18.44 x86_64 (cloud container), rustc 1.91.0. No IPv6 in the container.
Changed:      elastos/crates/elastos-server/src/resource_bridge.rs - SHIPPING CODE: protected principal-root
                write/read in protected_principal_root_resource_response, plus is_agent_journal_path,
                WritePrecondition, write_precondition; tests in the test module
              examples/agent-host/src/lib.rs - JOURNAL_CAP 256 KiB -> 192 KiB; test tying it to the bridge
              examples/agent-host/handoff/USERSAI-JOURNAL.md - cap and wire format corrected
              examples/agent-host/handoff/S3-DESIGN.md - cap mentions updated
              examples/agent-host/handoff/reports/S3-bridge-cas.md - this report
              examples/agent-host/handoff/LOG.md - one line
Invariant:    A protected principal-root write may carry create_only or if_revision. With one, it goes through
              write_principal_root_object_if_revision (atomic, under the mutation lock), and a mismatch writes
              nothing. Under <root>/.AppData/Agents/ (any ASCII case), a write needs a precondition, may not
              append, and needs principal-root protection. Writes without a precondition elsewhere behave as
              before. Writes and reads return the object revision.
Refusals:     (all before storage unless noted; codes in the existing shapes)
              journal write, no create_only/if_revision -> error "revision_required"
              journal write with append                 -> error "append_not_allowed"
              journal write, root has no protection     -> error "principal_root_protection_required"
                                                           (does not fall through to the localhost provider)
              create_only not a bool, if_revision not a non-empty string, both set, append + either
                                                         -> error "invalid_content"
              stale if_revision / create_only on an existing object (in storage, under the lock)
                                                         -> result {status: error, code: "revision_conflict"}
              journal frame > 1 MiB                      -> "request_too_large" (unchanged)
Tests run:    export RUST_TEST_THREADS=2
              (cd elastos && cargo test -p elastos-server --lib -- resource_bridge::tests) -> "55 passed; 0 failed"
                (all pre-existing bridge tests pass: existing callers unchanged)
              (cd elastos && cargo test -p elastos-server --lib) -> "3015 passed; 13 failed; 22 ignored".
                The 13 fail the same way on d9b1a82 without this change (run in a separate worktree): 12
                custody, process, room, and gateway-child tests, plus one IPv6 test ("Address family not
                supported by protocol"). Container limits, not this change.
              (cd elastos && cargo clippy -p elastos-server --lib --tests -- -D warnings) -> clean
              (cd elastos && cargo fmt -p elastos-server -- --check) -> ok
              ./examples/agent-host/verify.sh -> "87 passed", 0 warnings, OK; ./examples/agent-host/run-local.sh -> ok
              (cd elastos && cargo test -p elastos-compute --lib -- --include-ignored) -> 16 passed
              cargo test --manifest-path capsules/model-provider/Cargo.toml local_memory -> 7 passed
              node --test scripts/home-agent-prefix.test.mjs scripts/home-agent-no-store.test.mjs -> 4 passed
              (cd elastos && cargo test -p elastos-server launch_refuses_untrusted) -> 1 passed
Not run here: Mac-only tests.
Falsifiers:   one at a time on the committed code, undone with git checkout; tree clean after.
              B01 unprotected journal goes to the provider   -> a_journal_on_a_root_without_protection_is_refused FAILED
              B02 journal append allowed                     -> an_append_to_a_journal_is_refused FAILED
              B03 append with a precondition allowed         -> a_malformed_precondition_is_refused_before_storage FAILED
              B04 unconditional journal write allowed        -> an_unconditional_journal_write_is_refused,
                                                                a_journal_path_is_matched_without_regard_to_case FAILED
              B05 journal path match case-sensitive          -> a_journal_path_is_matched_without_regard_to_case FAILED
              B06 precondition ignored (blind write)         -> a_stale_journal_revision_is_refused_and_the_stored_journal_is_kept,
                                                                preconditions_are_optional_outside_agents_and_honoured_when_sent FAILED
              B07 conflict reported as write_failed          -> same two FAILED
              B08 write returns no revision                  -> 4 FAILED (incl. a_read_returns_the_revision_the_next_write_needs)
              B09 read returns no revision                   -> a_read_returns_the_revision_the_next_write_needs FAILED
              B10 create_only of any type accepted           -> a_malformed_precondition_is_refused_before_storage FAILED
              B11 empty if_revision accepted                 -> same FAILED
              B12 create_only and if_revision both accepted  -> same FAILED
              B13 guest cap back to 256 KiB                  -> the guest test build fails (compile-time frame-fit
                                                                assertion); before the clippy fix, the runtime form
                                                                failed the_cap_fits_the_runtime_frame_at_four_bytes_per_byte
              Tightened during the slice: a_read_returns_the_revision_the_next_write_needs first passed with
              the change missing (null == null); it now requires a 66-character revision string.
Guest hash:   f300c0b111b616da6520f003091d120a94e006d7eeb21ab722429dca21232d39 on two builds (verify.sh, run-local.sh).
              Changed from fa10cca7 because JOURNAL_CAP changed (a constant in the guest).
              wasm_sections.py: file 273815 bytes; /1/10 213981 1ad9e330fc3bac61.
Import list:  unchanged in this PR (identity, runtime, types). The providers import comes with the guest side.
Principles:   3 No ambient authority / 11 Fail closed: a journal write with no precondition, an append, or no
                protection is refused. It never falls through to the unprotected provider.
              19 Consequences: every journal write is a compare-and-swap; a replay or a lost reply cannot
                overwrite a newer journal; the conflict is explicit.
              12 Docs, code, tests agree: USERSAI-JOURNAL.md states the real wire format (a JSON number array)
                and the 192 KiB cap; a guest test ties the cap to the bridge test.
              7 One authority model: the journal uses the same Users/self scoping and token check as every app.
DeepSeek:     none
Not proven:   The guest does not send an append yet (next PR). Path matching is ASCII-case-insensitive only;
              Unicode case folding or normalization on the filesystem is not handled (no Agents path uses
              non-ASCII letters). A plain write with no precondition outside Agents/ is still a blind overwrite,
              as before (by the review's rule).
Checklist:    56 of 63 (hold-usersai stays pending until the guest side lands)
Questions:    none for this PR. For the adversarial review: please look hardest at is_agent_journal_path (prefix
              and case), the no-protection refusal, and the precondition parsing.
```

## What changed, in order of the review's rules

1. **Optional everywhere, required under Agents.** `write_precondition` reads `create_only` (bool) and `if_revision` (non-empty string). Absent or `null` means no precondition. Everything else is `invalid_content`. Under `.AppData/Agents/`, a write with no precondition is `revision_required`. Elsewhere, no precondition means today's path, `write_principal_root_object`. All 55 bridge tests pass, including every pre-existing one.
2. **No append under Agents.** `append_not_allowed`, because append is read-then-write. Outside Agents, `append` combined with a precondition is `invalid_content`, so the meaning is never ambiguous.
3. **No protection means refused.** The refusal sits in the protection match, before `Ok(None) => return None`, so a journal write never reaches the generic provider. Outside Agents, an unprotected root still goes to the provider as before; the test checks this.
4. **The revision is returned.** It is `principal_root_object_revision(principal, rooted_uri, bytes)`, the value the compare-and-swap checks. The write returns it, and so does the read, computed over the whole object before any read window, so a resumed guest can name it. Conflicts are `revision_conflict` in the existing `provider_error_result` shape.
5. **The cap.** `request_content_bytes` takes a JSON number array, up to four characters per byte. `a_worst_case_journal_at_the_cap_fits_through_the_bridge` writes 192 KiB of `0xFF` (accepted, read back equal) and 256 KiB of `0xFF` (refused: `request_too_large`). The guest `JOURNAL_CAP` is 192 KiB. `the_cap_fits_the_runtime_frame_at_four_bytes_per_byte` checks that the bridge test uses the same cap, and asserts at compile time that `4 × cap + 64 KiB` fits the frame.

## Added beyond the rules (flagged for review)

- **ASCII-case-insensitive Agents match.** The default macOS filesystem ignores case, so `.appdata/agents/` reaches the same folder. A case-sensitive match would let a lower-case path skip `revision_required`. Test: `a_journal_path_is_matched_without_regard_to_case`.
- **Read returns the revision.** Needed for resume after a crash. Additive field.

## What is next

The GPT-family adversarial review of this PR. Then the guest side: the providers import, a launch grant held in memory and never journaled, `propose_journal_append`, and resume by head hash. Then tests for the sweep's gaps, `begin_exec` first.
