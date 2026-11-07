# Per-guard mutants run at 4f17e482

Author plants were applied from `lab/intent-planner/plants/*.txt` in
`/tmp/a15-review-r2/4f17e482`. New plants were applied to `src/lib.rs` or
`src/runtime_bridge.rs`. After every plant, `src/lib.rs` was restored to
SHA-256 `f09d572393060f2b56e6796b2a9ba2227a3d024867078f031efa2d000830bc64`.

## Author plants (r1 list plus M6-host)

| Id | Result on the author's 18 tests |
| --- | --- |
| F-A15-approval | CAUGHT. Named 5/5 FAILED. Suite 11 failed / 7 passed. |
| M1 | CAUGHT. 1 failed / 17 passed. |
| M2 | CAUGHT. 2 failed / 16 passed. |
| M3 | CAUGHT. 1 failed / 17 passed. |
| M4 | CAUGHT. 1 failed / 17 passed. |
| M5 | CAUGHT. 1 failed / 17 passed. |
| M6 | CAUGHT. 1 failed / 17 passed. |
| M6-host | CAUGHT. 1 failed / 17 passed. |
| M7 | CAUGHT. 1 failed / 17 passed. |
| M8 | CAUGHT. 1 failed / 17 passed. |

## Reviewer plants

| Id | Result on the author's 18 tests | Probe |
| --- | --- | --- |
| N1 length prefix dropped | SURVIVED 18/0 | LIVE execute of a newline-split plan |
| N2 canonical omits resource | CAUGHT 17/1 | — |
| N3 canonical trims | SURVIVED 18/0 | LIVE execute of `ada` vs `ada ` |
| N4 covers prefix | SURVIVED 18/0 | LIVE parent-path covers child journal |
| N5 covers last segment | CAUGHT 17/1 | — |
| N6 ignore bus reply | SURVIVED 18/0 | `approved_plan_*` still ok when the bus returns `stored` |
| N7 host_id starts_with | SURVIVED 18/0 | LIVE `host-1` vs `host-10` |
| N8 mint unlimited | CAUGHT 15/3 | — |
| N9 validate guest URI | CAUGHT 13/5 | — |
| N10 used before bus | SURVIVED 18/0 | LIVE: retry after a failed execute becomes `GrantSpent` |

Details and the bookability verdict are in `REVIEW.md`. Probes are in `attacks.rs`.
