Slice:        A15 r4 lab fix (PR #284 head 36049b90)
Branch / PR:  cursor/a15-r4-fail-closed-c89c  (new draft PR targeting #284)
Commit:       pending first push
Develop:      not merged this turn (lab fix on #284 only; #284 left unpushed)
Machine:      Linux x86_64, rustc 1.91.0 (f8297e351 2025-10-28)
Changed:      lab/intent-planner/src/lib.rs - one name grammar at execute; empty/duplicate refused; host_id `.` `..` `a..b` `...`; notes/foo/.. pinned
Changed:      lab/intent-planner/plants/R4-1-host-dot.txt through R4-7-nul-intent.txt - one plant per r4 hole
Changed:      lab/intent-planner/README.md - r4 refusals; RA-4 / RA-5 / NEEDS RUNTIME stay
Changed:      examples/agent-host/handoff/LOG.md - one r4 line
Invariant:    The strict ASCII name grammar plan() applies is also applied at execute. An empty plan cannot be approved. Duplicate steps never mint two grants or make two bus calls. Deleting the `.`/`..` host_id check or the execute path loop fails the suite.
Refusals:     `_ada` / `ada.` / `.ada` BadPrincipal; NUL intent BadIntent; empty plan EmptyPlan; [journal, journal] DuplicateStep; host_id `.` `..` `a..b` `...` ForeignHost; notes/foo/.. OutsidePlan
Tests run:    pending
Not run here: spawned elastos (NEEDS RUNTIME)
Falsifiers:   pending plant table
Guest hash:   unchanged (lab crate only)
Import list:  unchanged
Principles:   3 no ambient authority on constructed plans; 10 one bind path; 11 fail closed; 12 docs match BLOCKED rows; 18 host_id grammar
DeepSeek:     none
Not proven:   stored journal BLOCKED (RA-4); UsersAI notes BLOCKED (RA-5); spawned elastos NEEDS RUNTIME
Checklist:    A15 still open
Questions:    none
