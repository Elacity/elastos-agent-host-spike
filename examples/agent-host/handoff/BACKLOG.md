# Agent Host lane backlog

Now 45 of 70 (was 42/70). Baseline: `reports/grade-rescore-2.md`.

One item per piece carried by a merged task 005 to 018, with its true state. A piece is done only when its merged
test and falsifier are recorded; blocked means a named outside owner holds it; deferred means it is not planned in
this lane.

| # | Piece | Carried by | State | Evidence |
| --- | --- | --- | --- | --- |
| 1 | Compaction: model proposal through the Hosted path, checked before the journal records it | 006, 012, 015 | done | Row 4, 3 -> 4. `a_model_summary_that_changes_a_required_fact_is_refused` (FC10); opt-in `a_real_model_compaction_summary_is_judged_by_the_same_check` |
| 2 | Prefix bytes stable across two turns | 007, 016 | done | `the_prompt_prefix_is_byte_identical_across_two_turns` (FP01); no grade point, a precondition for row 3 |
| 3 | Falsify runner: a catch and a survivor each need error-free per-named-test evidence | 004, 005, 010 | done | Methodology, not a grade row; `--self-test` OK, 86 of 86 falsifiers as expected |
| 4 | Git and undo: a granted restore applies through the single Edit write path | 014 | done | Row 8, 2 -> 3. `a_granted_restore_uses_the_write_path_and_records_the_checkpoint_text` (FE01, FE04) |
| 5 | Skills: admit a skill from granted content named by its SHA-256 CID | 017 | blocked | Row 9 stays 3. Content identity is done, but a child is not a separate instance; child limits are #31, owned by Claude Code, and need Runtime/Anders (Bus v2) |
| 6 | Create an app: a granted scaffold applies through the write path and the project opens again with the same tree digest | 018 | done | Row 13, 2 -> 3. `a_granted_scaffold_applies_through_the_write_path` (FS64), `a_scaffolded_project_opens_again_with_the_same_tree_digest` (FS66). The build or run provider and the Home surface are still missing |
| 7 | Child limits (#31) | not started | deferred | Not this lane; Claude Code owns it. It is the next piece for row 9 and needs Runtime/Anders for a separate instance |
| 8 | Remaining grade headroom (17 points) | none | deferred | Every open row needs Runtime, Home, Anders, Sasha, the Mac or Claude Code #31; no row can gain purely in-lane |

Next: no graded row is in-lane. The smallest next gains are #31 (row 9), Runtime provider work (rows 5, 6, 13) and
Home work (rows 2, 3, 12).
