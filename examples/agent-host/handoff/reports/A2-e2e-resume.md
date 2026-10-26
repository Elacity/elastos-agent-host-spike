Slice:        A2 end-to-end resume proof
Branch / PR:  cursor/a2-e2e-resume-27c8  (draft, base cursor/a2-journal-load-b1e8)
Commit:       (filled after the run)
Develop:      not merged (lab + two public lab hooks)
Machine:      (filled after the run)
Changed:      lab/a2-e2e-resume/ - real process-restart journey; rows derived from output
              elastos/crates/elastos-server/src/resource_bridge.rs - handle_component_resource_request is pub for the lab
              elastos/crates/elastos-server/src/auth.rs - store_test_principal_root_protection is pub for the lab
              examples/agent-host/handoff/reports/A2-e2e-resume.md - this report
              examples/agent-host/handoff/LOG.md - one line
Invariant:    After a write and a stale refusal, a new Runtime process on the same store loads the latest format-2 journal and can write again with that revision. A skip is NOT RUN.
Refusals:     stale if_revision -> revision_conflict; stored bytes unchanged
              create_only on a stored journal (no load) -> guest launch fails; stored bytes unchanged
Tests run:    (filled after the run)
Not run here: Mac verify
Falsifiers:   (filled after the run)
Guest hash:   (filled after the run)
Import list:  unchanged (guest code not edited)
Principles:   3 grants still required to read or write
              10 one path: load latest, then create_only only if nothing is stored
              11 fail closed: stale revision_conflict; no silent overwrite on restart
              12 docs, code, tests agree: a skip is NOT RUN
DeepSeek:     none
Not proven:   (filled after the run)
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

## Next

Do not merge. GPT-family review of this draft.
