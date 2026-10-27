Slice:        A15 r3 fix (PR #284)
Branch / PR:  cursor/intent-planner-a15-10c1  https://github.com/Elacity/elastos-agent-host-spike/pull/284
Commit:       pending
Develop:      not merged this turn (review fix on #284 only)
Machine:      Linux x86_64, rustc 1.91.0
Changed:      lab/intent-planner/src/lib.rs - grammar before compare, ordered canonical, empty/NUL host_id, R3-1..R3-10 tests
Changed:      lab/intent-planner/src/runtime_bridge.rs - whole-reply BLOCKED token
Changed:      lab/intent-planner/plants/* - R3-1..R3-12 plus N4 retarget
Changed:      lab/intent-planner/README.md - r3 binds; RA-4 / RA-5 / NEEDS RUNTIME stay
Invariant:    Names and paths are validated before compare and refused, never folded or truncated. Approving [notes, journal] never binds [journal, notes]. The BLOCKED reply is a whole token. Empty or NUL host_id is ForeignHost before invoke.
Refusals:     NFC/NFD PlanAltered; Cyrillic confusable PlanAltered; over-length PlanAltered or BadPrincipal; .. / trailing slash / ASCII case / percent covers false; inexact BLOCKED Bridge; empty or NUL host_id ForeignHost; swapped plan object PlanAltered
Tests run:    pending
Not run here: spawned elastos (NEEDS RUNTIME)
Falsifiers:   pending
Guest hash:   unchanged (lab crate only)
Import list:  unchanged
Principles:   3 no ambient authority on constructed plans; 10 one bind path; 11 fail closed; 12 docs match BLOCKED rows; 18 host_id grammar and equality
DeepSeek:     none
Not proven:   stored journal BLOCKED (RA-4); UsersAI notes BLOCKED (RA-5); spawned elastos NEEDS RUNTIME
Checklist:    A15 still open
Questions:    none
