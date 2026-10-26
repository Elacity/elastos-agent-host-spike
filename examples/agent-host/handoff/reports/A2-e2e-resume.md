Slice:        A2 end-to-end resume proof
Branch / PR:  cursor/a2-e2e-resume-27c8  https://github.com/Elacity/elastos-agent-host-spike/pull/351
Commit:       9e7a85d631aec12de8c1da4fc4958bce18252d21   parent a9e0e28048ee42fd42f6c017780dc8bf9aa22b05
              earlier 6d49de3b2fdfb9df7c49cc968cf9bc4ced350c24   parent a97a6373181f526af2eba17fe95d2898201ab63d
Develop:      not merged (lab + off-by-default lab-protection feature)
Machine:      Linux x86_64, rustc 1.91.0 (f8297e351 2025-10-28)
Changed:      examples/agent-host/src/lib.rs - guest stale probe and post-load write through providers.invoke
              elastos/crates/elastos-server/src/resource_bridge.rs - handle_component_resource_request is pub(crate)
              elastos/crates/elastos-server/src/auth.rs - test helper is cfg(test) or lab-protection
              elastos/crates/elastos-server/Cargo.toml - lab-protection feature, off by default
              lab/a2-e2e-resume/ - two-process journey; computed rows; review plants
              examples/agent-host/handoff/reports/A2-e2e-resume.md - this report
              examples/agent-host/handoff/LOG.md - one line
Invariant:    After a write and a stale refusal, a new Runtime process on the same store loads the latest format-2 journal (guest read then write) and can write again with that revision. A skip is NOT RUN. A create_only conflict that only rereads is not a resume.
Refusals:     stale if_revision -> revision_conflict; stored bytes unchanged
              create_only on a stored journal (no load) -> guest launch fails; stored bytes unchanged
              flipped guest byte -> WRITE FAIL
              first process exit != 0 -> STOP FAIL
Tests run:    python3 -I lab/a2-e2e-resume/run.sh -> exit 0; WRITE/STALE/STOP/START/RESUME/WRITE2 PASS; A2_counted yes
              first pid=48301; second pid=48311; store lab/a2-e2e-resume/homes/store-48205
              cargo test --manifest-path examples/agent-host/Cargo.toml --lib -- a_stale_probe_is_refused_and_leaves_the_store a_loaded_journal_can_be_written_at_its_revision a_journal_survives_a_new_launch_and_a_stale_write_is_refused -> 3 passed
              cargo build -p elastos-server --release -> 0; probe without lab-protection -> E0425 cannot find store_test_principal_root_protection
Not run here: Mac verify; elastos serve
Falsifiers:   F-A2-CREATE-ONLY -> RESUME FAIL -> restored CAUGHT
              F-A2-SKIP-LOAD -> RESUME FAIL -> restored CAUGHT
              F-A2-REVISION -> STALE FAIL -> restored CAUGHT
              F-REV-SECOND-STALE-WRITE -> WRITE2 FAIL RESUME PASS -> restored CAUGHT
              F-REV-OLDER-JOURNAL -> RESUME FAIL -> restored CAUGHT
              F-REV-STORE-WIPE -> RESUME not PASS -> restored CAUGHT
              F-REV-GUEST-HASH -> WRITE FAIL -> restored CAUGHT
              F-REV-HARDCODED-HARNESS-PASS -> Proof.row refused PASS CAUGHT
              F-REV-SKIPPED-STALE -> STALE NOT RUN CAUGHT
              F-REV-STOP-NONZERO -> STOP FAIL first_exit=1 CAUGHT
Guest hash:   0e868fc1b7565f317c06b514992c90e1d75bdeeb1c0e92d2172e4dd4d41cbace (672045 bytes; guest now probes stale and writes after load)
Import list:  unchanged (capabilities.request, providers.invoke)
Principles:   3 grants still required to read or write
              10 one path: guest load latest, then create_only only if nothing is stored
              11 fail closed: stale revision_conflict; no silent overwrite on restart
              12 docs, code, tests agree: a skip is NOT RUN; PASS is computed
DeepSeek:     none
Not proven:   This lab drives the same in-process Runtime + real resource bridge as the ignored e2e, as two OS processes on one store. It does not start `elastos serve`.
Checklist:    unchanged
Questions:    none

## Review of #368

Draft PR #368 said A2 could not be counted. The six findings are fixed:

1. STALE and WRITE2 go through the guest `providers.invoke` hostcall. The driver no longer mints a token or calls `handle_component_resource_request`. That function is `pub(crate)` again.
2. `store_test_principal_root_protection` is `pub(crate)` under `cfg(test)`, or public only with the off-by-default `lab-protection` feature. A default release build does not export it.
3. `Proof.row` refuses PASS. Every row is computed. `A2_counted` is yes only if every row is computed PASS.
4. STOP requires exit code 0 exactly.
5. WRITE compares the built guest bytes to `lab/a2-e2e-resume/guest.sha256`.
6. The seven review plants run in this lab's falsifier and were CAUGHT.

## Journey (this machine)

| Step | Result | Evidence |
| --- | --- | --- |
| WRITE | PASS | first pid 48301; format-2; sha256 `fca6e299…931d30`; guest `0e868fc1…cbace` |
| STALE | PASS | `revision_conflict`; stored sha256 unchanged |
| STOP | PASS | first process exited 0; store `homes/store-48205` |
| START | PASS | second pid 48311 on the same store |
| RESUME | PASS | guest read then write of the stored journal |
| WRITE2 | PASS | new revision `eba4e7eb…271d6f` |
| F-A2-CREATE-ONLY | CAUGHT | RESUME FAIL |
| F-A2-SKIP-LOAD | CAUGHT | RESUME FAIL |
| F-A2-REVISION | CAUGHT | STALE FAIL |
| F-REV-SECOND-STALE-WRITE | CAUGHT | WRITE2 FAIL |
| F-REV-OLDER-JOURNAL | CAUGHT | RESUME FAIL |
| F-REV-STORE-WIPE | CAUGHT | RESUME not PASS |
| F-REV-GUEST-HASH | CAUGHT | WRITE FAIL |
| F-REV-HARDCODED-HARNESS-PASS | CAUGHT | PASS refused |
| F-REV-SKIPPED-STALE | CAUGHT | STALE NOT RUN |
| F-REV-STOP-NONZERO | CAUGHT | STOP FAIL |

A2 is counted by this runner. Skipped rows: none.

## Next

Do not merge. GPT-family review of this draft.
