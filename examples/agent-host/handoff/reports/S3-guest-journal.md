# S3 guest side: journal append with the launch grant, resume by head hash

```text
Slice:        S3 part 2, the guest side (hold-usersai). Import-list change: a security change, needs the
              GPT-family adversarial review. Sasha asked to keep going without waiting for the PR #8 review.
Branch / PR:  claude/s3-guest-journal  (draft PR in this repo, base spike/agent-host; link in the PR)
Commit:       2bf0914bb0274b0b71165b2ed97706813ffb480a (guest code, tests, import-list test)
              e916d8714927d534e3babd6102c231ce18950cf5 (test: only an ok reply with a revision counts)
              parent a45dc67 (merge of claude/s3-bridge-cas, PR #8, not yet reviewed); this report is the next commit
Develop:      Elacity develop 3beb816438fd567145a8d725e22465bd83277cf0, merged, behind 0.
Machine:      Linux 6.18.44 x86_64 (cloud container), rustc 1.91.0.
Changed:      examples/agent-host/src/lib.rs - journal append, launch grant, resume, 15 tests, kind tag 9
              examples/agent-host/Cargo.toml, Cargo.lock - serde_json 1.0.154 as a guest dependency (it was
                already in the lock as a build dependency of wit-bindgen; no new package)
              elastos/crates/elastos-compute/src/providers/component.rs - TEST ONLY: the ignored Wasmtime test
                expects the providers import and checks that no bridge line is sent
              examples/agent-host/handoff/USERSAI-JOURNAL.md - kind and state tags; guest side section
              examples/agent-host/handoff/S3-DESIGN.md - guest side done; two gaps
              examples/agent-host/handoff/SLICES.md - hold-bus-fixture text (new import list); hold-usersai note
              examples/agent-host/handoff/reports/S3-guest-journal.md - this report
              examples/agent-host/handoff/LOG.md - one line
Invariant:    The guest writes its task journal only as a whole format 1 encoding with create_only (first)
              or if_revision (after), only with the launch grant, which lives in memory and is never stored
              or printed. A lost reply makes the append settlement_unknown, and no append is sent until
              resume reads the stored head back.
Refusals:     (guest side; none of these sends anything unless noted)
              no launch grant, or an empty one           -> Denied; the step is denied; no Bus call
              an append still open (pending or unknown)  -> Held; no step, no Bus call
              a journal over the 192 KiB cap             -> TooLarge; the step is cancelled; no Bus call
              a cursor outside Users/self/.AppData/Agents/, or with "..", "\" or a leading "/"
                                                         -> Held ("host path"); no step, no Bus call
              an agent or task id that is not 1-64 ASCII letters, digits or "-" -> "journal id"
              (after one call) revision_conflict          -> Conflict; closed "conflict"; no retry
              (after one call) Bus denied / invalid       -> Refused; closed "refused"
              (after one call) no answer, write_failed, an ok reply with no revision, garbage
                                                         -> Unknown; step settlement_unknown
              resume with no read grant                   -> Denied; no Bus call
              resume on a head that is neither the sent head nor the parent, or bytes that do not decode,
                or nothing stored                        -> Unknown; stays held
Tests run:    export RUST_TEST_THREADS=2
              ./examples/agent-host/verify.sh -> "102 passed" (87 before, 15 new), clippy clean, OK
              ./examples/agent-host/run-local.sh -> "1 passed" (new import list, no bridge line sent)
              (cd elastos && cargo test -p elastos-compute --lib -- --include-ignored) -> "16 passed"
              (cd elastos && cargo clippy -p elastos-compute --lib --tests -- -D warnings) -> clean; fmt -> ok
              (cd elastos && cargo test -p elastos-server --lib -- resource_bridge::tests) -> "55 passed"
              (cd elastos && cargo test -p elastos-server launch_refuses_untrusted) -> "1 passed"
              cargo test --manifest-path capsules/model-provider/Cargo.toml local_memory -> "7 passed"
              node --test scripts/home-agent-prefix.test.mjs scripts/home-agent-no-store.test.mjs -> "pass 4"
Not run here: Mac-only tests. No end-to-end run of the guest against a real Runtime: there is no grant
              channel (see Questions).
Falsifiers:   one at a time on the committed code, undone with git checkout; tree clean after.
              J01 no grant still sends (fallback grant)      -> a_journal_append_without_a_grant_sends_nothing FAILED
              J02 write body drops if_revision                -> 5 FAILED (incl. the_write_body_is_what_the_bridge_reads,
                                                                 the_first_append_creates_..._names_its_revision)
              J03 conflict retried once                       -> a_stale_journal_revision_is_refused_and_nothing_is_written FAILED
              J04 append not held while one is open           -> a_crash_between_append_and_result_is_settlement_unknown_and_not_retried,
                                                                 resume_on_another_head_stays_unknown_and_holds_appends FAILED
              J05 no answer counted as written                -> 7 FAILED
              J06 resume accepts any head                     -> resume_on_another_head_stays_unknown_and_holds_appends FAILED
              J07 resume reads the parent as written          -> resume_on_the_parent_head_lets_the_append_be_proposed_again FAILED
              J08 resume reads without a grant                -> resume_without_a_read_grant_sends_nothing FAILED
              J09 over the cap still sent                     -> an_append_over_the_cap_is_not_sent FAILED
              J10 journal id allows any byte but space        -> a_journal_id_is_letters_digits_and_dashes FAILED
              J11 propose accepts another root                -> same FAILED
              J11b propose accepts ".."                       -> same FAILED
              J12 LaunchGrant Debug prints the id             -> a_launch_grant_is_held_in_memory_only FAILED
              J13 a denied reply counted as unknown           -> a_refused_append_is_closed_and_not_sent_again FAILED
              J14 an empty launch grant is a grant            -> a_journal_append_without_a_grant_sends_nothing FAILED
              J14w same, checked in Wasmtime                  -> SURVIVES: authorize() also refuses an empty grant
                                                                 (the S0c G1 rule), so the wasm guest still sends
                                                                 nothing. Two guards; J14 pins the first.
              J15 guest stops calling providers               -> agent_host_example_keeps_the_head_across_a_compaction
                                                                 FAILED (import list)
              J16 decoder refuses kind tag 9                  -> 8 FAILED (round trip and append tests)
              J17 ok reply without a revision is written      -> only_an_ok_reply_with_a_revision_counts_as_written FAILED
              J18w the wasm build has a launch grant id       -> agent_host_example_keeps_the_head_across_a_compaction FAILED
                                                                 (the guest sends; the test sees it)
Guest hash:   610897ff6b101bc99300d0c40e2ac88a527ef0b7608a4aa880a40d81a08980fa on two builds (verify.sh, build.sh).
              Changed from f300c0b1: new guest code and serde_json.
              wasm_sections.py: file 374279 bytes (was 273815); /1/10 284442 484e73c99d335496.
Import list:  CHANGED to elastos:bus/identity, providers, runtime, types (all @1.0.0) because the guest
              writes its own task journal with providers.invoke. capabilities is still absent. Security
              change: needs the adversarial review. The import is present because the call is reachable in
              the code; today the wasm build has no grant, so it never calls (the Wasmtime test checks this).
Principles:   3 No ambient authority: the guest calls only with the launch grant; with none it sends nothing.
              11 Fail closed: no grant, an open append, an over-cap journal, an unknown reply, or an
                unexpected head all stop the write and say why.
              16 / 15 The grant is a bearer token: it is held in memory, never journaled, never printed.
              19 Consequences: every write is a compare-and-swap on the revision the guest last saw; a lost
                reply is settlement_unknown and is settled by reading the head, never by a blind retry.
              12 Docs, code, tests agree: a guest test reads resource_bridge.rs and component.rs for the
                exact request and reply keys it depends on.
DeepSeek:     none
Not proven:   - No end-to-end write from the wasm guest through a real Runtime: there is no grant channel.
                The guest logic is proven against FakeRuntime, a stand-in that copies the bridge rules; the
                bridge itself is proven by its own 55 tests. The shapes are tied by source-text checks.
              - "Not written" is true at the time of the read. If a lost write could still land later, the
                revision check stops it and a new append from both landing, but the closed step would say
                "not written". In this Runtime the bridge call is synchronous, so this needs a host timeout
                that keeps running, which does not exist today.
              - A lost first append with nothing stored stays unknown: the bridge reports a missing object
                as read_failed, the same as any read failure.
              - The import is present because the optimizer keeps the call. If a later build drops it, the
                Wasmtime import test fails loudly.
Checklist:    56 of 63 (hold-usersai stays pending: the grant channel and the read grant are open)
Questions:    1. How does the Runtime hand the guest its launch grant? The WIT world has no launch argument,
                 lifecycle.run takes nothing, and the guest does not import capabilities. Options I see:
                 (a) a WIT change: a launch context argument to run, or a new import; (b) allow the
                 capabilities import for this one journal; (c) the host adds the launch grant itself when the
                 guest names its own journal (then the guest sends no grant, which changes answer 1). I did
                 not pick one. Until then the wasm guest has no grant and sends nothing.
              2. Resume needs a read grant: a token covers one resource and one action. Should the launch
                 hand over two grants (write and read) for the one journal, or one token with two actions?
```

## What the guest does now

1. **Where.** `journal_resource(agent_id, task_id)` gives `localhost://Users/self/.AppData/Agents/<agent-id>/tasks/<task-id>/journal`. Ids are 1 to 64 ASCII letters, digits or `-`. The bridge scopes `Users/self` to the launching person.
2. **Append.** `append_journal` records a `journal append` step (kind tag 9), takes the launch grant, and marks the step dispatched. It encodes the whole journal with the cursor's head as `prev_head`, then sends one `write`: `create_only` first, `if_revision` after. A conflict, a refusal, or an unknown reply each have their own outcome. Only an ok reply with a revision moves the cursor.
3. **Grant.** `LaunchGrant` is held in memory. `Debug` prints `LaunchGrant(..)`. The step's grant is copied for `dispatch` (the S0c G1 rule), and the encoding has no field for it.
4. **Lost reply.** The step becomes `settlement_unknown` and the cursor keeps the sent head as `pending`. No append is proposed while it is pending.
5. **Resume.** `resume_journal` reads with a read grant. The sent head means written; the parent head means not written, and the cursor stays on the parent so the next append names the parent revision. Anything else stays unknown.
6. **Wasm run.** The run builds a cursor for `agent-host/demo`, has no launch grant (empty id), and checks that the append is denied, resume has nothing to do, and nothing was sent. The Wasmtime test installs a recording bridge and checks it saw no line.

## What is next

1. Sasha decides the grant channel (question 1) and the read grant (question 2). Then a small Runtime slice wires it, with an end-to-end Wasmtime test that writes a journal through the real bridge.
2. The GPT-family review of PR #8 and this PR.
3. Tests for the guard sweep's gaps, `begin_exec` first (next PR, as planned).

## Fix after self-review (20 Oct)

Sasha could not run the GPT-family review yet, so another Claude agent did a read-only adversarial review of this PR with no memory of writing it. **This is not the independent review that HANDOFF asks for, and it does not replace it.** It found nothing blocking, and two real problems, fixed in `54d9a04`:

1. **The grant stayed in the append step after dispatch.** `authorize` copies it into `step.grant`, and `Journal` derives `Debug`, so printing the journal showed it. It never reached the stored bytes. Now the step drops the grant once it is dispatched, and on the over-cap path. Test: `no_journal_step_keeps_the_launch_grant` (written, conflict, unknown, over the cap, refused).
2. **After a conflict, every later append conflicted again.** The cursor kept the stale precondition, and nothing read the stored copy unless an append was pending. A conflict now marks the cursor `stale`, and appends are held until `reread_journal` reads the stored version. `reread_journal` returns that version for the caller to look at; it does not merge. It waits while an append is unknown, because `resume_journal` handles that case. Tests: `after_a_conflict_appends_wait_for_a_reread`, `a_reread_waits_while_an_append_is_unknown`, and `a_stale_journal_revision_is_refused_and_nothing_is_written` (now also checks `stale`).

```text
Commit:       54d9a04 (fix), on top of 06e52fd (grant channel note, S3-GRANT-CHANNEL.md)
Tests run:    ./examples/agent-host/verify.sh -> "105 passed", OK; ./examples/agent-host/run-local.sh -> "1 passed"
Falsifiers:   K01 the step keeps the grant after dispatch    -> no_journal_step_keeps_the_launch_grant FAILED
              K02 the over-cap step keeps the grant           -> same FAILED
              K03 a conflict does not mark the cursor stale   -> a_stale_journal_revision_is_refused_and_nothing_is_written,
                                                                 after_a_conflict_appends_wait_for_a_reread FAILED
              K04 propose ignores a stale cursor              -> after_a_conflict_appends_wait_for_a_reread FAILED
              K05 reread runs while an append is unknown      -> a_reread_waits_while_an_append_is_unknown FAILED
              K06 reread keeps the cursor stale               -> after_a_conflict_appends_wait_for_a_reread FAILED
Guest hash:   457ef823e77644c2b46e430c2be26190d49a99943ef516870574cf7545d51f6e on two builds.
              wasm_sections.py: file 375413 bytes; /1/10 285437 1fb48843638d9158.
Import list:  unchanged by the fix (identity, providers, runtime, types).
```

Also raised by the review; recorded here and not changed:

- **Question 3 (new): some refusals made before storage come back as "unknown".** The component host's `bus_error` (`component.rs`) maps only a few bridge codes to `Denied` or `Invalid`. Others become `Internal`, which the guest treats as `settlement_unknown`: `revision_required`, `principal_root_protection_required`, `principal_context_required`, `invalid_content`, `append_not_allowed`, and the manifest refusal. That is safe, but a Runtime with no principal-root protection then leaves the guest stuck on its first append: nothing is stored, so resume reads `read_failed` and stays unknown. Mapping those codes to `Invalid` would fix it. That is a shipping change to `elastos-compute`, so I did not make it. Should I?
- **The Wasmtime "no bridge line" check is weaker than it reads.** The host refuses an empty grant before the bridge, so an empty bridge log cannot tell "the guest sent nothing" from "the guest sent with no grant". The guest's own check in `run()` proves the first. J18w shows the bridge log does catch a guest that sends a non-empty grant.
- **Small things, left as is:** a journal over the cap gains one cancelled step per try. A settled resume leaves the step `settlement_unknown` with its result word.

## Update: option B (20 Oct)

Sasha's answers: question 1, option B (the `capabilities` import, reversing answer 3); question 2, ask for exactly two grants, read and write, on the agent's own journal, with the manifest declaring only `.AppData/Agents/<agent-id>/*`; question 3, the error mapping goes in its own `elastos-compute` PR. PR #8 fixes 2 and 3 are merged in (`4db812b`).

```text
Commit:       85186ec (option B), plus a test-only commit for an id falsifier that survived (P04, see below)
Changed:      examples/agent-host/src/lib.rs - request_journal_grants; JournalGrant (was LaunchGrant); id rule; run()
              examples/agent-host/capsule.json - capabilities: ["localhost://Users/self/.AppData/Agents/agent-host/*"]
              elastos/crates/elastos-compute/src/providers/component.rs - TEST ONLY: import list and bridge lines
              elastos/crates/elastos-server/src/resource_bridge.rs - TEST ONLY: the manifest and grants cannot delete
Invariant:    The guest asks for exactly two grants, write then read, on its own journal, through the existing Runtime
              path (Users/self scoping, manifest bound, pending request, shell decision, audit). It never asks for
              anything else. A refusal leaves that grant empty and nothing is sent with it.
Refusals:     a cursor outside Users/self/.AppData/Agents/ or with ".."    -> no grant is asked for
              a refused grant request                                      -> no grant; append Denied; nothing sent
              an agent or task id not matching ^[a-z0-9][a-z0-9._-]*$      -> "journal id" (the bridge's segment rule)
              the Agent Host's manifest and its two grants: delete on .AppData, the person's root, the Agents folder
                -> manifest_capability_denied; delete on the journal -> capability_denied (no Delete grant); with a
                Delete grant inside the bound -> operation_not_allowed (the Agents rule from PR #8)
Tests run:    ./examples/agent-host/verify.sh -> "108 passed", OK
              ./examples/agent-host/run-local.sh -> "1 passed": imports capabilities, identity, providers, runtime,
                types; with no Runtime answering, each guest sends exactly two request_capability lines (write, read)
                for its own journal and no resource call
              (cd elastos && cargo test -p elastos-server --lib -- resource_bridge::tests) -> "63 passed"
              (cd elastos && cargo test -p elastos-compute --lib -- --include-ignored) -> "16 passed"; clippy clean
New tests:    the_guest_asks_for_exactly_two_grants_on_its_own_journal, a_refused_grant_request_sends_nothing,
              no_grant_is_asked_for_a_path_outside_the_agents_journal,
              the_agent_host_manifest_and_grants_cannot_delete_appdata_or_the_root (bridge; reads the real capsule.json)
Falsifiers:   P01 the guest asks for a third grant           -> the_guest_asks_for_exactly_two_grants_on_its_own_journal,
                                                                a_refused_grant_request_sends_nothing FAILED
              P02 the guest asks for the Agents folder        -> the_guest_asks_for_exactly_two_grants_on_its_own_journal FAILED
              P03 grants asked for any cursor path            -> no_grant_is_asked_for_a_path_outside_the_agents_journal FAILED
              P04 ids may hold upper case                     -> SURVIVED at first: every upper-case id in the test began
                                                                with an upper-case letter, caught by the first-byte check.
                                                                Added "aB" and "demo-Agent"; now
                                                                a_journal_id_is_letters_digits_and_dashes FAILED
              P05 ids may start with any allowed byte         -> a_journal_id_is_letters_digits_and_dashes FAILED
              P07 the guest never calls capabilities          -> agent_host_example_keeps_the_head_across_a_compaction FAILED
              P08 the manifest declares all of Users/self     -> the_agent_host_manifest_and_grants_cannot_delete_appdata_or_the_root FAILED
Guest hash:   99bacd9df2b448a9b94e579754644a217d74f718662702e29973d44d7f4e583c on two builds (verify.sh, build.sh).
              wasm_sections.py: file 405170 bytes; /1/10 304296 3fee1380a0f27311.
Import list:  CHANGED to elastos:bus/capabilities, identity, providers, runtime, types (all @1.0.0). capabilities asks
              for the two journal grants. Security change: needs the GPT-family review.
Not proven:   No end-to-end write through a real Runtime yet. That is the next test, after the elastos-compute PR.
              WasmBus refuses a grant whose resource or actions differ from the request; the host builds the grant
              from the request, so no input reaches that check today (defence).
Questions:    One gap found while writing the delete test. A request_capability for a delete inside the manifest bound
              (for example on the journal) is not refused at request time: it waits up to 30 s for the shell to decide.
              Even if granted, using it is refused (operation_not_allowed). Should request_capability refuse every
              action except read and write under Agents too? That is shipping Runtime code; I left it.
```

## Update: PR #8 fix 4 merged in (20 Oct)

Merge `0aa92bf`. The only conflict was in `resource_bridge.rs` tests, where both sides had added tests at the same place. I kept PR #8's file and re-added this branch's `the_agent_host_manifest_and_grants_cannot_delete_appdata_or_the_root`, updated for fix 4: a delete-grant request inside the Agents area is now refused at once by the Agents rule (`operation_not_allowed`), not left waiting for the shell. This closes the question raised in the option B section.

```text
Tests run:    (cd elastos && cargo test -p elastos-server --lib -- resource_bridge::tests api::handlers::provider::tests)
                -> "83 passed"; clippy clean
              ./examples/agent-host/verify.sh -> "108 passed", OK; ./examples/agent-host/run-local.sh -> "1 passed"
              The full server suite on the PR #20 merge (all of #8, #9, #19): "3028 passed; 13 failed" (container
                limits only).
Guest hash:   99bacd9df2b448a9b94e579754644a217d74f718662702e29973d44d7f4e583c (unchanged)
```
