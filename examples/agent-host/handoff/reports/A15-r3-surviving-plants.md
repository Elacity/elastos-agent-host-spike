Slice:        A15 r3 fix (PR #284)
Branch / PR:  cursor/intent-planner-a15-10c1  https://github.com/Elacity/elastos-agent-host-spike/pull/284
Commit:       c2e7936e13f6be5dcfda372c0d2de9d1596337cd   parent d169f90d5f5dae2de52d40c8fb4f4ab908481124
Develop:      not merged this turn (review fix on #284 only)
Machine:      Linux x86_64, rustc 1.91.0 (f8297e351 2025-10-28)
Changed:      lab/intent-planner/src/lib.rs - grammar before compare, ordered canonical, empty/NUL host_id, R3-1..R3-10 tests
Changed:      lab/intent-planner/src/runtime_bridge.rs - whole-reply BLOCKED token
Changed:      lab/intent-planner/plants/* - R3-1..R3-12 plus N4 retarget
Changed:      lab/intent-planner/README.md - r3 binds; RA-4 / RA-5 / NEEDS RUNTIME stay
Invariant:    Names and paths are validated before compare and refused, never folded or truncated. Approving [notes, journal] never binds [journal, notes]. The BLOCKED reply is a whole token. Empty or NUL host_id is ForeignHost before invoke.
Refusals:     NFC/NFD PlanAltered; Cyrillic confusable PlanAltered; over-length PlanAltered or BadPrincipal; .. / trailing slash / ASCII case / percent covers false; inexact BLOCKED Bridge; empty or NUL host_id ForeignHost; swapped plan object PlanAltered
Tests run:    cargo fetch --locked --manifest-path lab/intent-planner/Cargo.toml -> exit 0
Tests run:    cargo fmt --manifest-path lab/intent-planner/Cargo.toml -- --check -> exit 0
Tests run:    cargo clippy --manifest-path lab/intent-planner/Cargo.toml --locked --offline --all-targets -- -D warnings -> exit 0
Tests run:    cargo test --locked --offline --manifest-path lab/intent-planner/Cargo.toml -- --nocapture --skip model_planted_bugs_are_caught -> 34 passed; 0 failed; 0 ignored in 1.31s
Tests run:    cargo test --locked --offline --manifest-path lab/intent-planner/Cargo.toml --lib model_planted_bugs_are_caught -- --exact --nocapture -> 1 passed in 131.00s; every named plant line printed FAILED
Not run here: spawned elastos (NEEDS RUNTIME)
Falsifiers:   every named plant test FAILED, then source restored. lib.rs SHA-256 443ea480cf2775e583b4e376b1b7687fa0e8655c2c321e6c15fe1f498164e2cb before and after. runtime_bridge.rs SHA-256 b5a35da21f95b989ac473a03ea5f3ca2a1e3a064cdcd07de62ffc6f250c31932 before and after
Guest hash:   unchanged (lab crate only)
Import list:  unchanged
Principles:   3 no ambient authority on constructed plans; 10 one bind path; 11 fail closed; 12 docs match BLOCKED rows; 18 host_id grammar and equality
DeepSeek:     none
Not proven:   stored journal BLOCKED (RA-4); UsersAI notes BLOCKED (RA-5); spawned elastos NEEDS RUNTIME
Checklist:    A15 still open
Questions:    none
