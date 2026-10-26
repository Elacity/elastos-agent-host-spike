Slice:        A2 load latest journal on new launch
Branch / PR:  cursor/a2-journal-load-b1e8  https://github.com/Elacity/elastos-agent-host-spike/pull/341
Commit:       98f4c3588ad3a7a4b04746edf9a7e6c71697723e   parent 6ac3438299a674f239eaeafa62524f1e7957e0da
              first commit 6ac3438299a674f239eaeafa62524f1e7957e0da   parent 9bb68053feea8426f33ade652f87f5ad47d03bb8
Develop:      not merged (this slice is guest load only; Elacity Runtime untouched)
Machine:      Linux x86_64, rustc 1.91.0 (f8297e351 2025-10-28)
Changed:      examples/agent-host/src/lib.rs - load a stored format-2 journal on a new launch; always-on resume test
              examples/agent-host/handoff/reports/A2-journal-load.md - this report
              examples/agent-host/handoff/LOG.md - one line
Invariant:    A new launch loads the latest stored format-2 journal revision. The first write still uses create_only only when nothing is stored. A stale if_revision stays revision_conflict. A newer stored journal is never overwritten.
Refusals:     stale if_revision on a later revision              -> revision_conflict; stored bytes unchanged
              stored format 1 on load                           -> FORMAT_1_REASON; old object not touched
              create_only after a stored journal (no load)      -> conflict; nothing written
              no write grant on a first create                  -> Denied; nothing sent
Tests run:    cargo test --locked --manifest-path examples/agent-host/Cargo.toml tests::a_journal_survives_a_new_launch_and_a_stale_write_is_refused -- --exact -> ok
              cargo test --locked --manifest-path examples/agent-host/Cargo.toml -- (9 journal tests) -> 9 passed
              ./examples/agent-host/verify.sh -> fmt, 231 passed + 2 ignored, clippy clean, wasm build OK
              ./examples/agent-host/run-local.sh -> agent_host_example_keeps_the_head_across_a_compaction ok
              lab/a2-e2e-proof/run.sh (from PR #331, not committed) -> WRITE PASS, STALE PASS, RESUME FAIL (harness), F-A2-REVISION CAUGHT, A2_counted no
Not run here: Mac verify; a guest e2e that restarts the Runtime process and then launches again
Falsifiers:   skip load_latest_journal in open_task_journal (always create_only) -> tests::a_journal_survives_a_new_launch_and_a_stale_write_is_refused FAILED left Err("conflict") right Ok(Loaded) -> reverted
Guest hash:   b234ac47ca4f52de27b17ff999ec2af6b9694135e53bf059e49c16897df058e4 (two builds, 668807 bytes)
              wasm_sections.py: without-name 7bc525de9cbf49bb21a3a794becb241a4c93b9f698fe192fb75a740f1c18f404
Import list:  unchanged
Principles:   3 grants still required to read or write the journal
              10 one path: load latest, then create_only only if nothing is stored
              11 fail closed: stale revision_conflict; format 1 refused; no silent overwrite
              12 the always-on test names write, stale refuse, new launch, read latest
DeepSeek:     none
Not proven:   The ignored Runtime e2e still reads back in one process. The #331 lab harness still hardcodes RESUME FAIL because journal_write_body keeps create_only for the first write. That skip is not a pass. The always-on host test is the resume proof in this slice.
Checklist:    unchanged (hold-usersai already recorded the write/read e2e)
Questions:    Should a later lab slice update a2-e2e-proof/harness.py so RESUME looks at open_task_journal / Loaded, not at create_only in journal_write_body?

## Why this test is not the exact resource_bridge.rs snippet

PROPOSED-CHANGE.md puts the journey in elastos-server resource_bridge.rs. That test never calls the guest load path. Reverting run() to create_only would leave it green, so it cannot be the falsifier. The same journey lives in examples/agent-host as tests::a_journal_survives_a_new_launch_and_a_stale_write_is_refused: write, stale revision_conflict, new FakeRuntime on the same store, read the latest revision. No WASM artifact.

## Lab journey (this session)

| Step | Result | Evidence |
| --- | --- | --- |
| Write through the real bridge | PASS | ignored e2e, `--ignored --exact`, ok in 0.53s |
| Stale-revision write refused | PASS | `a_stale_journal_revision_is_refused_and_the_stored_journal_is_kept` ok; reason revision_conflict |
| Resume after restart | FAIL in harness | harness still says run() only create_only; e2e does not restart. Host test Loaded + latest revision is the proof here |
| F-A2-REVISION | CAUGHT | stale if_revision accepted when the plant lands; resource_bridge.rs restored |
| Runtime serve | ready | health 200 on 127.0.0.1:50395 |

A2 is still not counted by that lab runner.

## Next

Do not merge. GPT-family review of 98f4c3588ad3a7a4b04746edf9a7e6c71697723e.
