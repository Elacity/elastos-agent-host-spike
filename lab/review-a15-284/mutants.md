# Per-guard mutants run at cb102ed1

Applied in `/tmp/a15-review/cb102ed1/lab/intent-planner/src/lib.rs`, then the five Host tests from `F-A15-approval` were rerun with `--exact`. `src/lib.rs` was restored to SHA-256 `d96a2079c805bdae534db92dc4b0aa34d85afd7aea8193a1126011fc25d218af` after each mutant.

| Id | Edit | Result |
| --- | --- | --- |
| M1 | delete the `Choice::Approve` check | CAUGHT by `rejected_plan_executes_nothing` |
| M2 | delete the canonical check | CAUGHT by `plan_altered_after_approval_is_refused` |
| M3 | keep length, drop zip equality | SURVIVED the five tests. Extra probe `review_m3_reorder_probe` then executed swapped steps (`Ok`, 2 effects). |
| M4 | delete the `used` list check | CAUGHT by `approved_grant_runs_once` (`Bridge` vs `GrantSpent`) |
| M5 | `review.grants.first()` instead of `covers` | SURVIVED the five tests |
| M6 | delete `validate_journal_write` in `execute` | SURVIVED the five tests. Extra probe `review_m6_cross_host_probe` then ran an unused Review on a second Host (`Ok`, 2 effects). |
| M7 | hardcode the known BLOCKED effect; skip `invoke_journal` | SURVIVED the five tests |
| M8 | drop `principal` from `canonical()` | SURVIVED the five tests |
| M9 | plant runner: count a non-FAILED cargo run as caught | current plants still print `FAILED`; no plant exercises a timeout |

Details and the bookability verdict are in `REPORT.md`.
