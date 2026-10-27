Slice:        A15 r2 fix (PR #284)
Branch / PR:  cursor/intent-planner-a15-10c1  https://github.com/Elacity/elastos-agent-host-spike/pull/284
Commit:       9664738431c065a7c69cb07577ee6fc2eb898152   parent 4f17e482f9be239aa880a5da574429a49d46276e
Develop:      not merged this turn (review fix on #284 only)
Machine:      Linux x86_64, rustc 1.91.0 (f8297e351 2025-10-28)
Changed:      lab/intent-planner/src/lib.rs - length-prefix bind, component covers, spend after success, stored-reply refuse, named tests
Changed:      lab/intent-planner/src/runtime_bridge.rs - test-only forced journal reply/fail after the real in-process call
Changed:      lab/intent-planner/plants/* - N1-N10 plus M6/M7 retarget
Changed:      lab/intent-planner/README.md - honest BLOCKED / NEEDS RUNTIME rows
Invariant:    An approved plan executes only the exact bound bytes. A failed execute does not spend. A stored bus reply fails the run.
Refusals:     newline field split PlanAltered; trailing-space principal PlanAltered; parent path does not cover child; host-1 vs host-10 ForeignHost; stored or other reply Bridge; failed execute leaves the grant unused
Tests run:    cargo fetch --locked --manifest-path lab/intent-planner/Cargo.toml -> exit 0
Tests run:    cargo fmt --manifest-path lab/intent-planner/Cargo.toml -- --check -> exit 0
Tests run:    cargo clippy --manifest-path lab/intent-planner/Cargo.toml --locked --offline --all-targets -- -D warnings -> exit 0
Tests run:    cargo test --locked --offline --manifest-path lab/intent-planner/Cargo.toml -- --nocapture -> 25 passed; 0 failed; 0 ignored in 88.19s
Not run here: spawned elastos (NEEDS RUNTIME)
Falsifiers:   every named plant test FAILED, then source restored. lib.rs SHA-256 dba94e5b1b456f878fc463565ff5f1d11b892df283acac1ed421fccb9445093b before and after
Guest hash:   unchanged (lab crate only)
Import list:  unchanged
Principles:   3 no ambient authority on constructed plans; 10 one bind path; 11 fail closed; 12 docs match BLOCKED rows; 18 host_id exact equality
DeepSeek:     none
Not proven:   stored journal BLOCKED (RA-4); UsersAI notes BLOCKED (RA-5); spawned elastos NEEDS RUNTIME
Checklist:    A15 still open
Questions:    none
