Slice:        A15 r2 fix (PR #284)
Branch / PR:  cursor/intent-planner-a15-10c1  https://github.com/Elacity/elastos-agent-host-spike/pull/284
Commit:       pending after tests
Develop:      not merged this turn (review fix on #284 only)
Machine:      Linux x86_64, rustc 1.91.0
Changed:      lab/intent-planner/src/lib.rs - length-prefix bind, component covers, spend after success, stored-reply refuse, named tests
Changed:      lab/intent-planner/src/runtime_bridge.rs - test-only forced journal reply/fail after the real in-process call
Changed:      lab/intent-planner/plants/* - N1-N10 plus M6/M7 retarget
Changed:      lab/intent-planner/README.md - honest BLOCKED / NEEDS RUNTIME rows
Invariant:    An approved plan executes only the exact bound bytes. A failed execute does not spend. A stored bus reply fails the run.
Refusals:     newline field split PlanAltered; trailing-space principal PlanAltered; parent path does not cover child; host-1 vs host-10 ForeignHost; stored or other reply Bridge; failed execute leaves the grant unused
Tests run:    see the PR after the suite
Not run here: spawned elastos (NEEDS RUNTIME)
Falsifiers:   N1-N10 and M1-M8, M6-host, F-A15-approval; each named test FAILED then source restored
Guest hash:   unchanged (lab crate only)
Import list:  unchanged
Principles:   3 no ambient authority on constructed plans; 10 one bind path; 11 fail closed; 12 docs match BLOCKED rows; 18 host_id exact equality
DeepSeek:     none
Not proven:   stored journal BLOCKED (RA-4); UsersAI notes BLOCKED (RA-5); spawned elastos NEEDS RUNTIME
Checklist:    A15 still open
Questions:    none
