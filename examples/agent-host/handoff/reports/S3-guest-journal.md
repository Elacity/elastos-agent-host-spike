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
