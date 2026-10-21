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
                as in the reviewer's probe: create_only v1 first, then each alias written with and without create_only
                and read; every request is refused; after each alias the alias path is absent (ext4) or the journal
                itself (APFS, same device and inode), and the journal bytes are unchanged. Corrected in edb6bd8: the
                first version asserted the alias path does not exist, which is false on APFS.)
              only_read_and_write_are_allowed_under_agents (delete, mkdir, list, stat, exists, and a folded delete; no
                provider call; a delete outside the area still reaches the provider)
              a_revision_conflict_is_audited_as_a_conflict
Full suite:   (cd elastos && cargo test -p elastos-server --lib) -> "3021 passed; 13 failed; 22 ignored". All 13 are in
                the previous run's 14 (container limits); term_drains_gateway_streams_and_separate_owned_child_groups
                passed this time, so it depends on timing.
              ./examples/agent-host/verify.sh -> "87 passed", OK (the guest test that reads resource_bridge.rs still holds)
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

## Fix 3: portable alias test, after the Mac review of a759eef8a (20 Oct)

Review on the Mac: **PASS on fix 2.** The real APFS check confirms that the six aliasing spellings are refused on write (with and without a precondition) and on read, and that the journal bytes stay unchanged. One test failed on macOS: `a_folded_or_misspelled_agents_path_is_refused_before_storage` asserted that the alias path does not exist, but on APFS the alias path *is* the journal.

Test-only fix in `edb6bd8`:
- After each alias request, the test now asserts that the alias path is absent, or is the same file as the journal (same device and inode).
- It also asserts that the journal bytes are unchanged after each alias request, not only at the end.
- A new unit test, `absent_or_same_file_tells_the_journal_from_a_copy`, pins the helper on Linux: a hard link counts as the same file, a copy with the same bytes does not, and a missing path counts as absent.

```text
Commit:       edb6bd8 (test only; no change outside the test module)
Tests run:    (cd elastos && cargo test -p elastos-server --lib -- resource_bridge::tests) -> "62 passed"; clippy clean
Falsifiers:   E01 the helper compares the device only          -> absent_or_same_file_tells_the_journal_from_a_copy FAILED
              E02 the helper treats any existing alias as the journal -> same FAILED
              D01, D03 rerun on edb6bd8                         -> a_folded_or_misspelled_agents_path_is_refused_before_storage
                                                                   and the string test still FAILED (the portable test bites)
Not run here: the macOS run of the portable test (this container is Linux ext4).
```


## Fix 4: one Agents rule on every route, after the Codex review of c85c2755 (20 Oct)

Codex: **FAIL**, confirmed in code by Cursor. Cursor's Mac results at that head: #8 63 of 63 pass on APFS; #20 `run-e2e.sh` 2 of 2 pass on APFS.

1. **The attached (HTTP) bridge skipped the Agents rule.** `handle_remote_request_with_audit_dir` refused only principal-root read and write. It forwarded `mkdir`, `list`, `stat`, `exists` and `delete` to `/api/provider/localhost/<op>`, and the Runtime API proxy (`handlers/provider.rs`, `provider_proxy`) forwarded them to the localhost provider with no Agents rule.
2. **Audit.** A `resource_result` whose result was not ok (for example `read_failed`) was audited as ok.

**The fix** (code `89ff7d6`, clippy fix `5bf47d8`):

- **One rule function**, `provider_resource::agents_area_refusal(rooted, operation)`, with `in_agents_area(rooted)`.
  - It no longer depends on whose root the path is in, so the proxy, which has no principal, can use it.
  - The area is found under `localhost://Users/<root>/` by full case folding, ignoring empty and `.` segments.
  - Inside the area: only read and write; only the exact spelling `.AppData/Agents/<seg>...`, with `^[a-z0-9][a-z0-9._-]*$` segments and no empty or `.` segment anywhere; a write needs a name below `Agents`.
- **It runs on every route a capsule can use** to reach localhost under Agents:

| Route | Where | Before or after the token check |
| --- | --- | --- |
| Local dispatch (in-Runtime bridge, component hostcall) | `authorize_and_dispatch_resource_invoke` -> `agents_area_dispatch_refusal` | after the token check, before storage or provider |
| Protected storage | `protected_principal_root_resource_response` -> `agent_path_refusal` | second guard on the same path |
| Attached bridge (`elastos run` / `elastos capsule` attached to a running Runtime) | `handle_remote_request_with_audit_dir` -> `agents_area_dispatch_refusal` | after the manifest and token-present checks, **before any HTTP call** |
| Runtime API provider proxy, `POST /api/provider/localhost/<op>` | `handlers/provider.rs` `provider_proxy` -> `agents_area_refusal` on the rooted `resource` | for **every session**, before `enforce_capability`, so also before the shell's no-token path |
| `request_capability`, local | `handle_request` -> `agents_area_capability_refusal` on the scoped resource | at once, before `parse_action`, the manifest bound and the pending request |
| `request_capability`, attached | `handle_remote_request_with_audit_dir` -> same | at once, before the manifest bound and any HTTP call |

- **Audit:** `invoke_outcome(result)` gives "ok" only for status ok (or no status), "conflict" for `revision_conflict`, and "error" for anything else. It is used on the local protected path, the local provider path, and the attached bridge (when the HTTP status is a success).

**Every caller of `/api/provider/localhost`** (searched by a read-only agent and checked):

| Caller | Who runs it | Localhost operations | How it is covered |
| --- | --- | --- | --- |
| `resource_bridge.rs` `handle_remote_request_with_audit_dir`, used by `run_cmd.rs:247` and `capsule_cmd.rs:158` | a component capsule run attached to a running Runtime (this includes the agent-host guest) | any the manifest allows | the bridge refuses before HTTP; the API proxy refuses again |
| `elastos-guest/src/runtime.rs` `http_call` (guest SDK in HTTP mode) | carrier-service providers (`supervisor.rs`), the Home CLI renderer, the shell | any | the API proxy (`provider_proxy`) |
| `capsules/home-cli/src/runtime_io.rs` (`storage_read_utf8`, `storage_write`) | Home CLI renderer, through the guest SDK | read, write on `Local/SharedByLocalUsersAndBots/Home/sessions/...` | not under Users; the API proxy rule does not apply there |
| `elastos-server/src/home_cmd.rs` `provider_call` | the `elastos home` CLI, host side | exists, read, write on the same session root | not under Users; the API proxy rule does not apply there |

- **Not reachable for localhost:**
  - The Home gateway route `/api/provider/:scheme/:op` (`gateway_provider_proxy`) serves only `documents`, `object`, `chain`, `net`, `inspect` and `model`. `localhost` gets 404, so browser capsule pages in Home cannot reach it.
  - The shell capsule calls only `tunnel/start`.
  - `chat_cmd`, `operator_control`, `gateway_room`, `gateway_home_system`, `gateway_local_control` and `inspect_provider` use other schemes.
- **The sibling storage route** `/api/localhost/*path` (`handlers/storage.rs`, six handlers) refuses every `Users` path (`reject_principal_root_storage_path`). A lower-case `users/...` is not a known root, so `rooted_localhost_uri` gives none and the request fails as an invalid path. No change.
- **Tests** that call the route (`home_cmd.rs` mock router, `handlers/provider.rs`, `resource_bridge.rs`, `api/gateway_tests/*`) are not callers.

3. **(Your #9 question, yes.)** `request_capability`, both handlers, refuses any action other than read or write in the Agents area at once, with the same rule. A request for a wildcard under Agents (a `*` segment) is refused as a misspelling too; the manifest bound is where patterns belong.

```text
Commit:       89ff7d6 (code and tests), 5bf47d8 (clippy, test only)
Changed:      elastos/crates/elastos-server/src/provider_resource.rs - SHIPPING: agents_area_refusal, in_agents_area
              elastos/crates/elastos-server/src/resource_bridge.rs - SHIPPING: the rule on the attached bridge and both
                capability request handlers; invoke_outcome for the audit; tests
              elastos/crates/elastos-server/src/api/handlers/provider.rs - SHIPPING: the rule in provider_proxy; test
Tests run:    (cd elastos && cargo test -p elastos-server --lib -- resource_bridge::tests api::handlers::provider::tests)
                -> "82 passed" (66 bridge, 16 proxy); clippy clean; fmt ok
New tests:    the_attached_bridge_applies_the_agents_rule_before_http (delete, mkdir, list, stat, exists, a folded delete,
                an Agentſ write, a "//" read; the API URL has nothing listening, so a request past the rule would fail
                to connect instead of returning the refusal)
              the_provider_proxy_applies_the_agents_rule_for_every_session (shell session with no token: the same eight
                requests are refused and the provider sees none; the exact journal read and a delete outside the area
                still reach the provider)
              a_forbidden_agents_capability_request_is_refused_at_once (delete, execute, admin and a folded delete, local
                and attached; no pending request; under 5 s, not the 30 s approval wait; a misspelled write request is
                refused too)
              a_missing_journal_read_is_audited_as_an_error
              a_failed_provider_result_is_audited_as_an_error (the local provider path)
Falsifiers:   G01 the shared rule allows every operation      -> 4 FAILED (proxy, attached, capability, local)
              G02 the shared rule folds ASCII only            -> 4 FAILED (proxy, attached, string test, alias test)
              G03 the attached bridge skips the rule          -> the_attached_bridge_applies_the_agents_rule_before_http FAILED
              G04 the provider proxy skips the rule           -> the_provider_proxy_applies_the_agents_rule_for_every_session FAILED
              G05 local request_capability skips the rule     -> a_forbidden_agents_capability_request_is_refused_at_once FAILED
                                                                 (it waited the full 30 s for the shell)
              G06 attached request_capability skips the rule  -> same FAILED (it reached HTTP)
              G07 every result is audited ok                  -> a_missing_journal_read_is_audited_as_an_error,
                                                                 a_failed_provider_result_is_audited_as_an_error FAILED
              G08 the provider path audits ok                 -> a_failed_provider_result_is_audited_as_an_error FAILED
              G09 a conflict is audited as error              -> a_revision_conflict_is_audited_as_a_conflict FAILED
              G10 local dispatch skips the rule               -> only_read_and_write_are_allowed_under_agents FAILED
Full suite:   on the PR #20 merge, which has all of #8, #9 and #19: (cd elastos && cargo test -p elastos-server --lib)
                -> "3028 passed; 13 failed; 24 ignored"; the 13 are the same container limits as before, none new.
Not proven:   The attached bridge's audit classification of a 200 reply with an error body is not tested (it would need
              a listening HTTP server); it uses the same invoke_outcome that G07 pins.
Guest hash:   no guest change on this branch.
```

## Fix 5: Library, storage and proxy routes, after a second self-review of fix 4 (20 Oct)

Sasha asked to keep going while the Codex re-review waits. Another Claude agent did a read-only adversarial review of fix 4. It is not the Codex review. It confirmed three gaps with probes in a scratch worktree.

1. **Blocking: the object provider (Library) ignored the Agents area.** `handle_object_provider_raw_request` checks paths only in `library_target` / `clean_library_uri`, which knew nothing about Agents.
   - `write` (with no precondition), `read`, `move`, `copy`, `rename`, `mkdir` and `trash` all worked there.
   - Callers: the Library capsule through the Home gateway (`/api/provider/object/<op>`), and any capsule holding an `elastos://object/write` token.
   - A probe wrote a forged journal with status ok. **Fix:** `clean_library_uri` refuses any path in the Agents area. Every object operation goes through it, including move and copy targets and rename's new URI.
2. **The `/api/localhost/*` storage route** checked `Users` on the raw text. A leading space (`" Users/..."`, or `%20` in the URL) got past the check, and the path was trimmed later. **Fix:** the check also runs on the canonical URI the route uses.
3. **The Runtime API provider proxy** checked the trimmed, rooted path, but forwarded the raw text, so a trailing space or `\u{a0}` made a second file named `journal ` on disk. It also let an exact journal read or write reach the plain localhost provider, without principal-root protection or the revision check. **Fix:** the proxy refuses every Agents-area operation (`principal_context_required`; journals are reachable only through the in-Runtime protected bridge), and forwards the rooted path the rule checked.

```text
Commit:       fe1d2dd
Changed:      elastos/crates/elastos-server/src/library.rs - SHIPPING: clean_library_uri refuses the Agents area; test
              elastos/crates/elastos-server/src/api/handlers/storage.rs - SHIPPING: Users check on the canonical URI; test
              elastos/crates/elastos-server/src/api/handlers/provider.rs - SHIPPING: no Agents path on the proxy; rooted
                path forwarded; test updated
Tests run:    (cd elastos && cargo test -p elastos-server --lib -- api::handlers::provider::tests resource_bridge::tests
                api::handlers::storage::tests library::tests::agent_journals) -> "92 passed"; clippy clean
              Full suite on the PR #20 merge (all of #8, #9, #19): "3030 passed; 13 failed; 24 ignored"; the same 13
                container failures as before, none new.
              (cd elastos && cargo test -p elastos-server --lib library) -> "115 passed; 4 failed": the 4 are the custody
                tests that fail in this container before and after (same names as the full-suite list)
New tests:    library::tests::agent_journals_are_not_library_objects (write, folded write, read, stat, list, trash, mkdir,
                move, copy, rename into Agents: all refused; no Agents folder is created; the source document stays)
              api::handlers::storage::tests::a_users_path_is_refused_however_it_is_spaced
              the_provider_proxy_applies_the_agents_rule_for_every_session, extended: exact read and write, trailing space
                and \u{a0} refused; a path outside the area is forwarded rooted and trimmed
Falsifiers:   H01 Library allows the Agents area              -> agent_journals_are_not_library_objects FAILED
              H02 storage checks only the raw text            -> a_users_path_is_refused_however_it_is_spaced FAILED
              H03 proxy lets exact Agents paths through       -> the_provider_proxy_applies_the_agents_rule_for_every_session FAILED
              H04 proxy forwards the raw path                 -> same FAILED
```

**Checked and safe** (from the review):
- the webspace scheme;
- carrier targets;
- the Home gateway proxy (it does not serve localhost);
- the supervisor;
- `..`;
- percent-encoding and backslashes (not decoded, so they name a different file);
- NFD/NFC, the Kelvin sign and the long s against the area rule;
- a `users` root, or a hash root in upper case.

**Notes, not changed:**
- **Broad capability requests.** A `request_capability` for a scope above the area (`Users/self/*` or `Users/self/.AppData/*` with `delete`) is not refused at once. Every route now refuses its use in the area: local dispatch, the attached bridge, the proxy, Library and storage.
- **`invoke_outcome` and a missing `status`.** A result with no `status` field is audited "ok", which matches how the component host reads it.
- **The attached bridge's own refusals** (manifest, missing token, Agents) and a non-JSON reply: now audited, in fix 7 below.
- **A trailing `.` in a segment** (`journal.`): answered yes, done in fix 6 below.


## Fix 6: refuse a segment that ends in "." (20 Oct)

```text
Commit:       d358ba79a75cbfe99e94b7761a22a23dcdc18430 (rule, test cases, report edit); this section is the next commit
Changed:      elastos/crates/elastos-server/src/provider_resource.rs - agents_area_refusal: a segment below
                .AppData/Agents/ may not end in '.'; the refusal message says so
              elastos/crates/elastos-server/src/resource_bridge.rs - three cases in
                the_agents_area_folds_unicode_case_and_allows_one_spelling
Why:          On Windows, "journal." and "journal" name the same file. Answered yes in the review of fix 5.
Refusals:     .AppData/Agents/demo-agent/tasks/task-1/journal.    read, write -> invalid_localhost_path
              .AppData/Agents/demo-agent./tasks/task-1/journal    read, write -> invalid_localhost_path
              .AppData/Agents/demo-agent/tasks/task-1/journal...  read, write -> invalid_localhost_path
              The rule is shared, so every route gets it: local dispatch, protected storage, the attached
              bridge, the provider proxy, request_capability, Library, storage.
Not done:     Windows device names (con, nul and so on), left for when Windows is a target.
Tests:        cargo test -p elastos-server --lib -- resource_bridge::tests provider -> 367 passed, 0 failed
              cargo clippy -p elastos-server --all-targets -- -D warnings -> clean
Falsifier:    T01 remove the ends_with('.') check -> FAILED
                the_agents_area_folds_unicode_case_and_allows_one_spelling; restored, tree clean
Guest:        the guest's journal_id_ok (#9) still allows an id that ends in '.'. The bridge now refuses such a
              path, so the guest fails closed. Aligning the guest rule is a small change on #9 for later.
Principles:   fail closed; one rule, many routes.
DeepSeek:     none used.
Guest hash:   unchanged (no guest change in this PR).
```

## Fix 7: viewer storage and attached-bridge audit, after the Codex review of 004962206 (20 Oct)

Codex: #19 PASS, #8 FAIL on two new findings (both checked by Cursor). Fixes 1 to 6 confirmed.

```text
Commits:      2962c75 viewer storage refuses the Agents area
              440774a attached bridge audits refusals and non-JSON replies
              this section is the next commit
Changed:      elastos/crates/elastos-server/src/api/viewer_gateway.rs - viewer_storage_target refuses a storage root or
                object inside .AppData/Agents/ (in_agents_area, any case) -> 403 "viewer storage does not support
                .AppData/Agents/ (agent journals)"; save and state scopes, viewer and content-capsule routes, GET and PUT
              elastos/crates/elastos-server/src/resource_bridge.rs - handle_remote_request_with_audit_dir: "requested" is
                recorded as soon as the resource_invoke parses; every way out then writes one "completed" record:
                denied   manifest_capability_denied, missing_token, the Agents rule, principal_context_required
                         (the refusal carries the audit id, as local dispatch does)
                error    send failure, bad API URL, a reply body that does not read or is not JSON (Err to the
                         caller, as before, now with "was not JSON (HTTP <status>)")
                ok/conflict/error  a JSON reply, as before
Not audited:  a resource_invoke that does not parse (invalid_resource_invoke): there is no resource to record. Local
                dispatch does the same.
              (Corrected in fix 8: a bad API URL also exited before "requested".)
Finding 1:    Before: a viewer manifest with storage under Users/self/.AppData/Agents/... could PUT and GET files there
                (on Linux both journal and Journal), with no journal rule. After: refused before any file access.
              Also refused: a .AppData/* root saving a file named Agents (the object check, not only the root).
Tests:        cargo test -p elastos-server --lib -- resource_bridge::tests api::handlers::provider::tests gateway_tests::gba
                -> 93 passed, 0 failed
              cargo clippy -p elastos-server --all-targets -- -D warnings -> clean
              cargo test -p elastos-server --lib -> "3032 passed; 13 failed; 22 ignored"; the same 13 container failures
                as fix 5 (custody, room, gateway-child, IPv6, the chmod-as-root save test), none new
New tests:    api::gateway::gateway_tests::gba::viewer_storage_cannot_reach_the_agents_area (5 manifests x PUT/GET: exact,
                Journal, .appdata/AGENTS, .AppData root + "Agents", content capsule; all 403; no file under Agents on disk)
              resource_bridge::tests::attached_bridge_refusals_are_audited (5 refusals: requested + completed/denied,
                same id, id in the response)
              resource_bridge::tests::a_non_json_provider_reply_is_audited_as_an_error (a real socket answers a
                plain-text 403: Err, requested + completed/error, same id)
Falsifiers:   V01 viewer storage may reach Agents            -> viewer_storage_cannot_reach_the_agents_area FAILED
              V02 viewer storage checks the root only        -> same FAILED (the .AppData + "Agents" case)
              A01 bridge refusal skips "completed"           -> attached_bridge_refusals_are_audited FAILED
              A02 non-JSON reply skips "completed"           -> a_non_json_provider_reply_is_audited_as_an_error FAILED
              A03 refusals checked before "requested"        -> both audit tests FAILED
              each restored; tree clean
Principles:   fail closed; one rule, many routes; every request leaves a complete audit record.
DeepSeek:     none used.
Guest hash:   unchanged (no guest change in this PR).
```

## Fix 8: check the string that is resolved; audit a bad API URL, after Codex round 3 on 4d8cfae37 (20 Oct)

Codex round 3: #19 PASS stands; the merges, #9's guest change and its hash confirmed; #8 FAIL on two findings (both
checked by Cursor).

```text
Commits:      944bc26 check the Agents rule on the string that is resolved
              cb00fcf attached bridge audits a bad API URL
              8e13a61 drop a redundant canonical check in the Agents rule (falsifier W03 survived, see below)
              this section is the next commit
Finding 1:    The path resolver (elastos-common parse_localhost_path) trims surrounding whitespace and slashes. A viewer
                storage grant "localhost://Users/self/.AppData/Agents /*" (space, tab or newline) was checked as "Agents "
                and resolved as the real Agents folder (Codex read a plaintext file there with 200). Library had the same
                hole: "<root>/.AppData/Agents \t/" is trimmed of "/" only, checked as "Agents \t", resolved as "Agents"
                (so list, stat or trash of the whole folder).
Changed:      provider_resource.rs - in_agents_area canonicalises its own input with rooted_localhost_uri, the same parse
                the resolver uses. agents_area_refusal finds the area through it; its exact-spelling rule then refuses any
                path in the area that is not already canonical (whitespace or a trailing "/" makes a bad or empty segment).
              api/viewer_gateway.rs - the storage root is canonicalised once (refused if it does not canonicalise), and
                that one string is used for the principal-scope check, the Agents guard, the object URI and the path.
              library.rs - clean_library_uri cleans to the canonical URI, and library_target resolves that same string.
Callers:      every caller now checks exactly the string it resolves:
                resource_bridge.rs protected storage (~489): rooted_localhost_uri -> check -> rooted_localhost_fs_path, same
                  string (already so)
                api/handlers/provider.rs proxy (~64): build_capability_resource gives rooted_localhost_uri; that string is
                  checked and forwarded as the path (already so since fix 5)
                library.rs (~3304): now the canonical URI
                api/viewer_gateway.rs: now the canonical root
                api/handlers/storage.rs: checks the canonical URI (fix 5)
              and the shared rule canonicalises anyway, so a caller that passes a raw string is still covered.
Not an alias: "<root>/.AppData/Agents\n/" as a raw path: the resolver strips the "/" and keeps the "\n", so it names a
                different folder; the rule treats it as outside the area, which matches.
Finding 2:    LoopbackHttpBaseUrl::parse ran before the request was parsed, so a bad API URL left no record. A
                resource_invoke now checks it right after "requested" and records "completed / error". Other request types
                (ping, request_capability, ...) are still refused at once, as before.
Tests:        cargo test -p elastos-server --lib -- resource_bridge::tests api::handlers::provider::tests
                api::handlers::storage::tests gateway_tests::gba library::tests -> "113 passed; 1 ignored"
              cargo clippy -p elastos-server --all-targets -- -D warnings -> clean
              cargo test -p elastos-server --lib -> "3035 passed; 13 failed; 22 ignored"; the same 13 container failures
                as fix 7, none new; +3 passing are the new tests
New tests:    gateway_tests::gba::viewer_storage_whitespace_root_cannot_reach_the_agents_area: space, tab, newline in the
                declared root x viewer and content-capsule grants x save and state x GET and PUT, against planted
                plaintext journals: all 403, no "planted" in any body, both files unchanged, no other file under Agents
              library::tests::whitespace_after_agents_does_not_reach_the_agents_folder: list, stat, trash on
                "Agents<ws>/" and ".appdata/agents<ws>/" for space, tab, newline, CRLF: all error, journal unchanged
              the_agents_area_folds_unicode_case_and_allows_one_spelling: "journal " "journal\t" "journal\n" "journal/"
                and ".AppData/Agents \t" are in the area and refused (invalid_localhost_path) for read and write
              resource_bridge::tests::a_bad_api_url_is_audited_as_an_error: Err, requested + completed/error with one id;
                a ping with the same URL still fails and writes nothing
Falsifiers:   W01 every guard on the raw string (rule, viewer, Library) -> viewer whitespace test, Library whitespace test
                and the rule test FAILED
              W02 in_agents_area on the raw string only     -> the rule test FAILED
              W04 bad API URL checked before "requested"    -> a_bad_api_url_is_audited_as_an_error FAILED
              W05 viewer root raw only                      -> survives, by design: the shared rule canonicalises
              W06 Library URI raw only                      -> survives, by design: same
              W03 remove the extra "is canonical" test in agents_area_refusal -> survived; the exact-spelling rule
                already refuses every such path, so the extra test was dead code and is removed (8e13a61)
              each restored; tree clean
Not done:     Windows also drops trailing spaces inside a segment ("Agents /journal"); left with the device names for when
                Windows is a target.
Principles:   fail closed; one rule, many routes; check the string you resolve; every request leaves a complete audit record.
DeepSeek:     none used.
Guest hash:   unchanged (no guest change in this PR).
```

**What is next:** merge into #9 and #20, then stop for Codex.
