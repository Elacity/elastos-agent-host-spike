Slice:        A2 end-to-end resume proof
Branch / PR:  cursor/a2-e2e-resume-27c8  https://github.com/Elacity/elastos-agent-host-spike/pull/351
Commit:       (this folder; see evidence.txt)   parent 85e3afd30aa89bb8145133cd8436c2403e899448 then this run
              first commit 85e3afd30aa89bb8145133cd8436c2403e899448   parent db8f7510d99f4e1f887801fc642861043d10b474
Develop:      not merged (lab + two public lab hooks)
Machine:      Linux x86_64, rustc 1.91.0 (f8297e351 2025-10-28)
Changed:      lab/a2-e2e-resume/ - real process-restart journey; rows derived from output
              elastos/crates/elastos-server/src/resource_bridge.rs - handle_component_resource_request is pub for the lab
              elastos/crates/elastos-server/src/auth.rs - store_test_principal_root_protection is pub for the lab
              examples/agent-host/handoff/reports/A2-e2e-resume.md - this report
              examples/agent-host/handoff/LOG.md - one line
Invariant:    After a write and a stale refusal, a new Runtime process on the same store loads the latest format-2 journal and can write again with that revision. A skip is NOT RUN.
Refusals:     stale if_revision -> revision_conflict; stored bytes unchanged
              create_only on a stored journal (no load) -> guest launch fails; stored bytes unchanged
Tests run:    python3 -I lab/a2-e2e-resume/harness.py -> WRITE/STALE/STOP/START/RESUME/WRITE2 PASS; A2_counted yes
              python3 -I lab/a2-e2e-resume/falsify.py F-A2-CREATE-ONLY -> CAUGHT (RESUME FAIL)
              python3 -I lab/a2-e2e-resume/falsify.py F-A2-SKIP-LOAD -> CAUGHT (RESUME FAIL)
              python3 -I lab/a2-e2e-resume/falsify.py F-A2-REVISION -> CAUGHT (STALE FAIL)
Not run here: Mac verify
Falsifiers:   F-A2-CREATE-ONLY revert run() to create_only -> RESUME FAIL -> restored
              F-A2-SKIP-LOAD load_latest_journal always Ok(None) -> RESUME FAIL -> restored
              F-A2-REVISION stale write returns ok -> STALE FAIL -> restored
Guest hash:   b234ac47ca4f52de27b17ff999ec2af6b9694135e53bf059e49c16897df058e4 (668807 bytes; same as #341)
Import list:  unchanged (guest code not edited)
Principles:   3 grants still required to read or write
              10 one path: load latest, then create_only only if nothing is stored
              11 fail closed: stale revision_conflict; no silent overwrite on restart
              12 docs, code, tests agree: a skip is NOT RUN
DeepSeek:     none
Not proven:   This lab drives the same in-process Runtime + real resource bridge as the ignored e2e, as two OS processes on one store. It does not start `elastos serve`.
Checklist:    unchanged
Questions:    none

## Independent review of #341 (not its own claims)

`open_task_journal` loads first through `load_latest_journal`. That function only
reads. A stored format-2 journal becomes `OpenOutcome::Loaded` and no write is
sent. `create_only` runs only when the load returns `Ok(None)` (nothing stored,
or no read grant). A later `create_only` on an existing object is
`revision_conflict` on both FakeRuntime and the real bridge, so a newer stored
journal is not overwritten. A stale `if_revision` still goes through
`append_journal`, which maps `revision_conflict` to `AppendOutcome::Conflict`
and leaves `cursor.stale`. `run()` now calls `open_task_journal`; the guest
import list stays `capabilities.request` and `providers.invoke`. #341's always-on
test uses FakeRuntime in one process. That is not a process restart. This lab
is the restart proof.

## Journey (this machine)

| Step | Result | Evidence |
| --- | --- | --- |
| WRITE | PASS | first process; format-2 journal; revision `5a9ce060…ae6b01bc` |
| STALE | PASS | `revision_conflict`; sha256 `fca6e299…931d30` unchanged |
| STOP | PASS | first process exited 0; store kept |
| START | PASS | second process printed `PROCESS second` on the same store |
| RESUME | PASS | same revision and sha256; no overwrite |
| WRITE2 | PASS | write with loaded revision; new revision `5e3156e3…9040cfeb` |
| F-A2-CREATE-ONLY | CAUGHT | RESUME FAIL |
| F-A2-SKIP-LOAD | CAUGHT | RESUME FAIL |
| F-A2-REVISION | CAUGHT | STALE FAIL |

A2 is counted by this runner. Skipped rows: none.

## Next

Do not merge. GPT-family review of this draft.
