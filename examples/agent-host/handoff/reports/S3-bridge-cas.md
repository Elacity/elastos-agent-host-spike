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

## Fix after self-review (20 Oct)

Sasha could not run the GPT-family review yet, so another Claude agent did a read-only adversarial review of this PR with no memory of writing it. **This is not the independent review that HANDOFF asks for, and it does not replace it.** It found **two blocking holes**, both confirmed by running them, and both with one cause. Fixed in `0b0b02b`.

**The cause.** `is_agent_journal_path` matched the raw rooted URI. `rooted_localhost_uri` keeps empty (`//`) and `.` segments. But the file path (`rooted_localhost_fs_path`) skips empty segments, and token matching (`ResourceId::matches`) drops both. So `localhost://Users/self//.AppData/Agents/...` and `.../self/./.AppData/Agents/...` reached the journal file, and the Agent Host's own exact journal token authorised them, but they did not match the Agents prefix.

1. **On a protected root:** a write to the `//` form with no precondition was accepted. It replaced the journal and labelled the new envelope with the `//` URI, so the next canonical read failed with "damaged". The journal was destroyed.
2. **On a root with no protection:** the `//` or `/./` form skipped `principal_root_protection_required` and fell through to the generic localhost provider, which writes the same file.

**The fix.**
- The Agents rule now checks `canonical_rooted_uri(rooted)`, which drops empty and `.` segments as the file path does. A `..` or `\` segment gives none; the file path and the localhost provider both refuse those already.
- An Agents path that is not in canonical form is refused with `invalid_localhost_path`, on read and on write, before the protection check. The stored object is labelled with the URI it was written under, so only one URI may name it.
- Also from the review:
  - (finding 7) a **read** under Agents on a root with no protection is refused, not sent to the provider;
  - (finding 3) `create_only` / `if_revision` on a root with no protection is refused (`principal_root_protection_required`) instead of being silently dropped on the way to the provider, which has no such fields. No caller sends them today.

```text
Commit:       0b0b02b (fix)
Tests run:    (cd elastos && cargo test -p elastos-server --lib -- resource_bridge::tests) -> "58 passed" (55 + 3 new)
              (cd elastos && cargo clippy -p elastos-server --lib --tests -- -D warnings) -> clean; fmt -> ok
              (cd elastos && cargo test -p elastos-server --lib) -> "3017 passed; 14 failed; 22 ignored". Before the fix
                the same run had 13 failures. The extra one,
                remote_model::denial_authority::a_denial_that_could_not_be_saved_cancels_nothing, forces a save failure
                with chmod 0o500, and this container runs as root (uid 0). It fails the same way with the bridge file
                from before the fix (2396520), checked by swapping the file in and back. The other 13 are the same
                custody, process, room, gateway-child and IPv6 tests as before.
New tests:    a_journal_path_with_empty_or_dot_segments_is_refused (protected root: 4 odd URIs x 3 bodies, and reads;
                the stored journal is unchanged and still reads back)
              an_odd_journal_path_on_a_root_without_protection_never_reaches_the_provider (and the canonical read)
              a_precondition_on_a_root_without_protection_is_refused
Falsifiers:   C01 a non-canonical Agents path is not refused     -> both odd-path tests FAILED
              C02 the Agents rule matches the raw path            -> both odd-path tests FAILED
              C03 canonical form keeps "." segments               -> ..._never_reaches_the_provider FAILED (on a protected
                                                                     root the file path already refuses "/./")
              C04 canonical form keeps empty segments             -> both odd-path tests FAILED
              C05 a precondition on an unprotected root goes on   -> a_precondition_on_a_root_without_protection_is_refused FAILED
              C06 an unprotected Agents read goes to the provider -> ..._never_reaches_the_provider FAILED
Guest hash:   unchanged by the fix (no guest change).
```

**Recorded, not changed** (questions for Sasha):

- **(finding 4) `delete` and `mkdir` under Agents skip the new rules.** `principal_root_read_write_uri` covers only read and write. A delete needs a Delete grant, which the Agent Host is not given. A `mkdir` at the journal path would block the journal: that harms only the caller's own journal, and only with a grant for that path. Should Agents paths refuse every operation except read and write?
- **(finding 5) No protection check inside the mutation lock.** Writes under Agents pass `require_protection: false`. The check runs just before, outside the lock. Making it `true` means a new parameter on `write_principal_root_object_if_revision`, which `viewer_gateway.rs` also calls. The reviewer found no way to remove protection, so this is defence in depth only.
- **(finding 6) Only ASCII case is folded.** On NTFS, and maybe APFS, `Agentſ` (U+017F) or a trailing dot (`Agents.`) could alias `Agents`. This matters only if the data directory sits on such a filesystem.
- **(finding 8) Audit outcome.** The audit outcome is keyed on `type == resource_result`, so a `revision_conflict` (a result with status error) is audited as ok. `write_failed` already worked this way before this PR.
- **Not from the review, noticed while fixing.** `scope_current_user_alias` lets a `..` through, for example `Users/<own root>/../<other>/x`. Both the file path and the localhost provider refuse `..`, so I found no way through. This is older shipping code, not this PR.

## Fix 2: after the review of 4584bf357 (20 Oct)

The review found one more blocking hole, proven on a Mac (APFS: case-insensitive, with Unicode folding). `is_agent_journal_path` folded ASCII only. `localhost://Users/self/.AppData/Agentſ/demo-agent/tasks/task-1/journal` (U+017F, long s) reaches the Agents directory on APFS, but the bridge did not treat it as an Agents path. With a manifest and token covering `{root}/*`:
1. `create_only` v1 was accepted;
2. a write to the alias with no precondition was accepted;
3. the real journal file changed;
4. the canonical read then failed ("damaged ... labelled for .AppData/Agentſ/...").

Linux ext4 keeps the two names apart, so the rule is tested on the strings themselves. Fixed in `c184382`:

1. **One spelling.**
   - **Finding the area:** the first two segments under the person's root, ignoring empty and `.` ones, fold to `.appdata/agents` under full case folding (`to_uppercase().to_lowercase()`).
   - **Inside the area:** a path must be spelled exactly `.AppData/Agents`, and every segment below must match `^[a-z0-9][a-z0-9._-]*$`. Anything else is refused with `invalid_localhost_path` on read and write.
   - **Extra (flagged):** a write needs a name below `Agents`, so the `Agents` folder itself cannot be replaced by a file.
2. **Only read and write in the area.** `delete`, `mkdir`, `list`, `stat` and `exists` get `operation_not_allowed`. This also covers misspelled forms such as `.appdata/AGENTS/...`. The rule runs in the dispatch, after the token check, for every localhost operation. It runs again in the protected storage path, so that path never depends on the caller's order.
3. **Audit.** A `revision_conflict` is audited as `conflict`, not `ok`.

`canonical_rooted_uri` and `is_agent_journal_path` are replaced by `agent_area_segments`, `agent_path_is_exact`, `agent_path_refusal` and `agents_area_refusal`. The old `a_journal_path_is_matched_without_regard_to_case` test is replaced: lower-case forms are now refused as misspellings, not accepted as Agents paths.

```text
Commit:       c184382
Tests run:    (cd elastos && cargo test -p elastos-server --lib -- resource_bridge::tests) -> "61 passed"
              (cd elastos && cargo clippy -p elastos-server --lib --tests -- -D warnings) -> clean; fmt -> ok
New tests:    the_agents_area_folds_unicode_case_and_allows_one_spelling (strings: Agentſ, AGENTS, .appdata, .APPDATA,
                Demo-Agent, Tasks, -task, leading empty or "." segments, "..", a space, a non-ASCII letter, the bare
                Agents folder, the Kelvin sign that folds to "k", another person's root, near misses)
              a_folded_or_misspelled_agents_path_is_refused_before_storage (handle_request, manifest and token {root}/*,
                the reviewer's setup: writes with and without create_only, reads; the stored journal is unchanged)
              only_read_and_write_are_allowed_under_agents (delete, mkdir, list, stat, exists, and a folded delete; no
                provider call; a delete outside the area still reaches the provider)
              a_revision_conflict_is_audited_as_a_conflict
Falsifiers:   one at a time on c184382, undone with git checkout; tree clean after.
              D01 the Agents area folds ASCII only            -> the_agents_area_folds_unicode_case_and_allows_one_spelling,
                                                                 a_folded_or_misspelled_agents_path_is_refused_before_storage FAILED
              D02 the Agents area is not folded at all        -> 8 FAILED
              D03 the exact .AppData/Agents spelling is dropped -> the same two FAILED
              D04 segments below Agents are not checked       -> 4 FAILED
              D05 a segment may start with any allowed byte   -> the same two FAILED
              D06 empty and "." segments count for the area   -> 3 FAILED (incl. both odd-path tests)
              D07 every operation is allowed in the area      -> only_read_and_write_are_allowed_under_agents FAILED
              D08 the dispatch skips the Agents rule          -> only_read_and_write_are_allowed_under_agents FAILED
              D09 the protected path skips the Agents rule    -> SURVIVES, by design: the dispatch rule (D08) always runs
                                                                 first, so the copy in the storage path is a second
                                                                 guard that no input reaches today. Same pattern as J14w.
              D10 the bare Agents folder may be written       -> the_agents_area_folds_unicode_case_and_allows_one_spelling FAILED
              D11 a conflict is audited as ok                 -> a_revision_conflict_is_audited_as_a_conflict FAILED
Guest hash:   unchanged by this fix (no guest change on this branch): f300c0b1.
```

**On Sasha's private list; no spike change** (from the review):
- the protection re-check inside the mutation lock;
- older write failures audited as ok;
- `scope_current_user_alias` letting `..` through.

The earlier "recorded, not changed" items are settled:
- finding 4 is done (only read and write under Agents);
- finding 6 is done (full folding);
- finding 8 is done for conflicts.

**For PR #9 (next, after this review).** The guest's `journal_id_ok` allows upper-case ASCII letters, and a leading `-`. The bridge now refuses both under Agents. So the guest rule must become `^[a-z0-9][a-z0-9._-]*$` too, or the guest would build paths the bridge refuses. That change goes in the PR #9 update, with option B and the error mapping.
