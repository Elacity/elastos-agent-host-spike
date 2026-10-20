# S3 end to end: the guest's journal through the real Runtime bridge

```text
Slice:        S3, the end-to-end Wasmtime test (after PR #9 option B and the elastos-compute mapping, PR #19).
Branch / PR:  claude/s3-e2e  (draft PR in this repo, base spike/agent-host). It merges PR #9 (which holds PR #8) and
              PR #19, so its diff shows all three until they merge; the new work is two tests and one script.
Commit:       0d3dd84 (e2e tests and run-e2e.sh); parent cbc0592 (merge of PR #19); report ea37b68
Develop:      Elacity develop 3beb816438fd567145a8d725e22465bd83277cf0, merged, behind 0.
Machine:      Linux 6.18.44 x86_64 (cloud container), rustc 1.91.0.
Changed:      elastos/crates/elastos-server/src/runtime.rs - TEST MODULE ONLY: two ignored end-to-end tests
              examples/agent-host/run-e2e.sh - builds the guest, runs the two tests
              examples/agent-host/handoff/reports/S3-e2e.md - this report
              examples/agent-host/handoff/LOG.md - one line
Invariant:    In one process, the built agent-host component, loaded by the Runtime with the real resource bridge,
              asks for exactly two grants (write, read) on its own journal; with both granted it writes the journal
              with a revision precondition and reads it back; the stored object is encrypted under the person's
              principal-root protection and decrypts to format 1. With both denied it stores nothing and makes no
              resource call.
Refusals:     both grants denied by the shell -> the guest finishes, no component.invoke event, no stored object
Tests run:    export RUST_TEST_THREADS=2
              ./examples/agent-host/run-e2e.sh -> "2 passed" (both ignored tests)
              ./examples/agent-host/run-local.sh -> "1 passed"
              (cd elastos && cargo test -p elastos-compute --lib) -> "16 passed; 1 ignored"
              (cd elastos && cargo clippy -p elastos-server --lib --tests -- -D warnings) -> clean
New tests:    runtime::tests::the_agent_host_writes_and_reads_its_journal_through_the_real_bridge
              runtime::tests::the_agent_host_stores_nothing_when_its_journal_grants_are_denied
              The test plays the shell: it takes each pending request and grants (or denies) it, the way
              component_conformance_exercises_bus_authorization_dispatch_and_audit does.
Not run here: Mac-only tests. The e2e tests run on Linux ext4 here.
Falsifiers:   one at a time, undone with git checkout; tree clean after; each run rebuilds the guest.
              Q01 the guest writes with no precondition    -> ..._writes_and_reads_its_journal_through_the_real_bridge FAILED
                                                              (the bridge refuses revision_required; with PR #19 that is
                                                              Invalid, so the guest closes the step as refused)
              Q02 the bridge refuses reads under Agents    -> ..._writes_and_reads_... FAILED (the read back is real)
              Q03 the guest asks for the Agents folder     -> both FAILED (the manifest bound refuses the request at
                                                              once; no pending request appears)
              Q04 a denied guest sends with a made-up grant -> ..._stores_nothing_when_its_journal_grants_are_denied
                                                              FAILED (the bridge audits the refused call)
Guest hash:   99bacd9df2b448a9b94e579754644a217d74f718662702e29973d44d7f4e583c (no guest change on this branch;
              same as PR #9).
Import list:  unchanged from PR #9: capabilities, identity, providers, runtime, types.
Principles:   3 No ambient authority: the guest writes only after the shell grants its two requests.
              7 One authority model: the same pending request, shell decision, token and bridge as any app.
              11 Fail closed: denied grants mean no call and no object.
              12 Docs, code, tests agree: the S3 route is now tested end to end, not only in parts.
DeepSeek:     none
Not proven:   The test grants requests itself; it does not run the real shell or its home-auto.json policy.
              It runs on ext4, not APFS. hold-usersai stays pending: the journal lives under Users/self, not UsersAI.
Checklist:    56 of 63 (hold-usersai and hold-adversarial stay pending)
Questions:    none.
```

## What is next

The GPT-family review of PRs #8, #9, #19 and this one. After #8 and #9 merge, the omp audit (`handoff/OMP-AUDIT.md`).

## Update: after the Codex review of #8 (20 Oct)

Cursor's Mac results at the previous heads: `run-e2e.sh` 2 of 2 pass on APFS. This branch now merges PR #8 fix 4 (one Agents rule on every route, the audit fix) through PR #9 (`c113d56`), and PR #19 with the three extra `Invalid` codes (`be1f537`). The end-to-end tests did not change.

```text
Tests run:    ./examples/agent-host/run-e2e.sh -> "2 passed"
              (cd elastos && cargo test -p elastos-compute --lib) -> "16 passed; 1 ignored"
              (cd elastos && cargo test -p elastos-server --lib) -> "3028 passed; 13 failed; 24 ignored". These are all
                the code from #8, #9 and #19 together. The 13 failures are the same container limits as every earlier
                run (custody, process, room, gateway-child, IPv6, and the chmod test that cannot fail as root); none
                is new. The 24 ignored include the two e2e tests.
Guest hash:   99bacd9df2b448a9b94e579754644a217d74f718662702e29973d44d7f4e583c (unchanged)
```
