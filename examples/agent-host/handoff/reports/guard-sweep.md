# Guard sweep

```text
Slice:        Guard sweep, no code change (item 5 of OVERNIGHT-1.md; item b of the 20 Oct plan).
Branch / PR:  claude/guard-sweep  (draft PR in this repo; link in LOG.md and the PR)
Commit:       the commit that adds this file; parent 1a63d557157b8fcbd72d37ce11721ac20f2a9b3b
              (merge of claude/fixes-after-overnight-1, PR #4, which contains PRs #1-#3)
Develop:      Elacity develop 3beb816438fd567145a8d725e22465bd83277cf0, merged, behind 0.
Machine:      Linux 6.18.44 x86_64 (cloud container), rustc 1.91.0.
Changed:      examples/agent-host/handoff/reports/guard-sweep.md - this report (the only change)
              examples/agent-host/handoff/LOG.md - one line
Invariant:    none (no code change). The tree at the end equals 1a63d55 apart from this report and the
              LOG line: every mutation was undone with git checkout, and `git status` was clean after each sweep.
Refusals:     the tables below
Tests run:    at the start: agent-host host tests 86 passed; elastos-compute exec_vm 10 passed.
              Per mutation: the full agent-host host suite (lib.rs), or `cargo test -p elastos-compute --lib exec_vm`
              (exec_vm.rs).
Not run here: Mac-only VM boots (exec_vm's boot paths are only reachable through the launcher test hook).
Falsifiers:   this whole item is a falsifier run: 142 scripted mutations plus 17 manual ones.
Guest hash:   fa10cca7929f1d538e914337999230e9daf6cd5413edf8256824ceb893d6be33 (unchanged; no code change)
Import list:  unchanged
Principles:   11 Fail closed and 12 Docs, code, tests agree: each refusal below either fails a test when removed,
              or is listed as a gap for the next slice.
DeepSeek:     none
Not proven:   Refusals written as plain boolean expressions (for example `rest.starts_with('/') && ...`) are
              not "returns" and are not in this sweep. S0b and S0c covered the ones found then.
Checklist:    56 of 63
Questions:    1. 30 refusals fail no test (24 in lib.rs, 6 in exec_vm.rs), plus 5 decoder refusals and 5 exec_vm
                 refusals found by hand (lists below). Should the next slice pin all of them, or only the
                 security-relevant ones (begin_exec, the child and grant checks, the decoder)?
```

## How the sweep worked

- **Scripted.** Find every explicit `return false`, `return None` and `return Err(..)` in production code. The test module and `run()`'s self-checks are left out, because they are not input refusals. Delete that one statement so the function goes on to accept, run the tests, record which tests fail, then `git checkout` the file.
  - `lib.rs`: 118 sites. `exec_vm.rs`: 24 sites.
  - "Not caught" means every test still passed with the refusal removed.
  - "No accept path" means deleting the return does not compile. That covers a `let ... else` with no value to fall back on (usually "unknown step id"), and a match arm that must produce a value.
- **By hand.** For the match arms, for refusals written as `Err(..)` without `return`, and for the `let ... else` sites that have a sensible accepting value, I wrote one accepting mutation each (tables "Manual").

## Summary

| File | Sites | Caught | **Not caught** | No accept path |
| --- | --- | --- | --- | --- |
| `examples/agent-host/src/lib.rs` (scripted) | 118 | 51 | **24** | 43 |
| `elastos/crates/elastos-compute/src/exec_vm.rs` (scripted) | 24 | 11 | **6** | 7 |
| `lib.rs` manual (match arms, decoder) | 7 | 2 | **5** | 0 |
| `exec_vm.rs` manual | 10 | 5 | **5** | 0 |

The manual `exec_vm.rs` gaps (GXa, GXb, GXe, GXh, GXj) are all different branches from the scripted rows. GXj is the unreadable-file branch at line 361, and scripted row 370 is the seek failure. So the new gaps found by hand are 5 in `lib.rs` and 5 in `exec_vm.rs`.

## The gaps (next slice: tests for these)

Most relevant first:

1. **`begin_exec` obeys a refused decision** (`exec_vm.rs:280`, manual GXe). If `begin_exec` ignores `ExecDecision::Refuse`, no test fails. `decide_exec`'s refusals (missing grant, cancel, host path) are tested on `decide_exec` itself, not through the launcher gate.
2. **The child and grant checks:**
   - `authorize_child` (`lib.rs:2017`)
   - `open_child_host` "inherited" (`:2051`)
   - `same_run_is_open` (`:2207`)
   - `provider_write_may_be_asked` (`:1488`)
   - `note_provider_wrote` (`:1539`)
3. **The S2 decoder's enum and length refusals** (manual GLc-GLg): unknown role, source, state or kind tags, and leftover payload bytes. They are only reachable with re-linked crafted bytes, and the S2 relink test does not try them. **The S2 report listed these as refusals; they hold in the code but are not pinned.**
4. **Project and boot admission in `exec_vm.rs`:**
   - a workspace outside `Users/`, or without `/Projects/` (manual GXa, GXb)
   - `admit_project_files:143`
   - `admit_boot_image:338`
   - `elf_kernel:354`
   - `ext4_superblock:370`, and an unreadable rootfs (manual GXj)
   - an unsupported host (manual GXh)
   - `cap_exec_output` "log too long" (`:229`)
   - `perform_edit` "not unique" (`:315`)
5. **Journal fold rules in `lib.rs`:**
   - `record_visible:774`
   - `spill_pointer:800, :819`
   - `text_at_spill:831`
   - `admit_snapshot:890`
   - `admit_skill:922`
   - `commit_compact:1014`
   - `note_crash_during_compact:1030`
   - `shadowed_summary_input:1077`
   - `read_observation:1201, :1209, :1216`
   - `open_step:1335`
   - `observed_project_files:1594`
   - `quoted_note_matches:1645`
   - `quoted_files_match:1668`
   - `propose_scaffold:1828, :1851`
6. **Redundant by design:** `encode_journal:407` (the cap check inside the loop) is backed by the final cap check, which `the_cap_holds_at_the_last_byte` pins. Removing the loop check alone changes nothing a caller can see.

Some of these may be redundant with another check in the same function. The next slice should decide each one: pin it with a test, or remove it as dead.

## Manual mutations

| Id | File | Mutation | Failing test |
| --- | --- | --- | --- |
| GLa | lib.rs `replay` | unknown role read as User | `assistant_and_tool_result_tags_replay_together` |
| GLb | lib.rs `replay` | unknown source read as Person | `a_snapshot_replays_with_its_source` |
| GLc | lib.rs `decode_node` | unknown role read as User | **none** |
| GLd | lib.rs `decode_node` | unknown source read as Person | **none** |
| GLe | lib.rs `decode_step` | unknown state read as Prepared | **none** |
| GLf | lib.rs `decode_step` | unknown kind read as Unspecified | **none** |
| GLg | lib.rs `JournalReader::done` | leftover payload bytes accepted | **none** |
| GXa | exec_vm.rs `admit_project_files` | workspace outside `Users/` accepted | **none** |
| GXb | exec_vm.rs `admit_project_files` | workspace without `/Projects/` accepted | **none** |
| GXc | exec_vm.rs `parse_exec_console` | an unparsable exit read as 0 | `a_console_without_an_exit_mark_is_not_success_and_a_failed_command_stays_failed` |
| GXd | exec_vm.rs `parse_exec_console` | no exit mark read as 0 | same (+1) |
| GXe | exec_vm.rs `begin_exec` | a refused decision ignored | **none** |
| GXf | exec_vm.rs `admit_exec_argv` | `cargo` accepted | `cargo_is_not_in_the_image_and_an_unknown_command_does_not_launch` |
| GXg | exec_vm.rs `admit_exec_argv` | an unknown command accepted | same |
| GXh | exec_vm.rs host adapter | an unsupported host accepted | **none** |
| GXi | exec_vm.rs `elf_kernel` | an unreadable kernel accepted | `a_browser_disk_or_a_missing_kernel_is_not_an_exec_image` |
| GXj | exec_vm.rs `ext4_superblock` | an unreadable rootfs accepted | **none** |

Not mutated (no accepting value exists): `JournalReader::take` (`truncated` reads), `journal_link`'s length overflow (unreachable under the cap). The S2 falsifiers S2l, S2n and S2p already cover the decoder's bool and option arms.

## Scripted tables

### `examples/agent-host/src/lib.rs`

| # | Function | Line | Refusal | Mutation result | Failing test |
| --- | --- | --- | --- | --- | --- |
| 0 | `replay` | 238 | `_ => return None,` | no accept path (does not compile) | `match` arms have incompatible types |
| 1 | `replay` | 251 | `_ => return None,` | no accept path (does not compile) | `match` arms have incompatible types |
| 2 | `encode_journal` | 407 | `return None;` | **not caught** | **none** |
| 3 | `decode_node` | 493 | `_ => return Err("record"),` | no accept path (does not compile) | `match` arms have incompatible types |
| 4 | `decode_node` | 505 | `_ => return Err("record"),` | no accept path (does not compile) | `match` arms have incompatible types |
| 5 | `decode_step` | 527 | `_ => return Err("record"),` | no accept path (does not compile) | `match` arms have incompatible types |
| 6 | `decode_step` | 538 | `_ => return Err("record"),` | no accept path (does not compile) | `match` arms have incompatible types |
| 7 | `decode_journal` | 595 | `return Err("too large");` | caught | `a_journal_over_the_cap_is_refused` |
| 8 | `decode_journal` | 600 | `return Err("not a journal");` | caught | `a_wrong_format_version_is_refused` |
| 9 | `decode_journal` | 603 | `return Err("format version");` | caught | `a_wrong_format_version_is_refused` |
| 10 | `decode_journal` | 625 | `return Err("hash");` | caught | `every_flipped_byte_is_refused` |
| 11 | `decode_journal` | 630 | `return Err("hash");` | caught | `every_flipped_byte_is_refused` |
| 12 | `decode_journal` | 633 | `return Err("trailing bytes");` | caught | `every_truncation_is_refused` |
| 13 | `decode_journal` | 643 | `return Err("record");` | caught | `a_relinked_but_malformed_journal_is_refused` |
| 14 | `decode_journal` | 653 | `return Err("record");` | caught | `a_relinked_but_malformed_journal_is_refused` |
| 15 | `decode_journal` | 663 | `_ => return Err("record"),` | caught | `a_relinked_but_malformed_journal_is_refused` |
| 16 | `record_visible` | 768 | `return false;` | caught | `a_goal_survives_shortening_and_does_not_grant` |
| 17 | `record_visible` | 771 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 18 | `record_visible` | 774 | `return false;` | **not caught** | **none** |
| 19 | `spill_pointer` | 800 | `return false;` | **not caught** | **none** |
| 20 | `spill_pointer` | 805 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 21 | `spill_pointer` | 808 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 22 | `spill_pointer` | 815 | `return false;` | caught | `a_spill_pointer_keeps_the_file_text` |
| 23 | `spill_pointer` | 819 | `return false;` | **not caught** | **none** |
| 24 | `text_at_spill` | 831 | `return None;` | **not caught** | **none** |
| 25 | `text_at_spill` | 838 | `return None;` | caught | `a_spill_pointer_keeps_the_file_text` |
| 26 | `admit_snapshot` | 884 | `return false;` | caught | `a_snapshot_appends_without_moving_the_head`, `an_empty_snapshot_leaves_the_journal_unchanged` |
| 27 | `admit_snapshot` | 887 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 28 | `admit_snapshot` | 890 | `return false;` | **not caught** | **none** |
| 29 | `admit_skill` | 916 | `return false;` | caught | `an_over_budget_skill_leaves_the_journal_unchanged` |
| 30 | `admit_skill` | 919 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 31 | `admit_skill` | 922 | `return false;` | **not caught** | **none** |
| 32 | `begin_compact` | 945 | `return false;` | caught | `a_crash_during_compaction_restores_the_saved_bytes`, `compaction_refuses_a_summary_that_does_not_shrink` (+1) |
| 33 | `begin_compact` | 948 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 34 | `begin_compact` | 951 | `return false;` | caught | `the_same_command_waits_until_the_first_has_a_result` |
| 35 | `begin_compact` | 997 | `return false;` | caught | `compaction_refuses_a_summary_that_does_not_shrink`, `the_same_command_waits_until_the_first_has_a_result` |
| 36 | `commit_compact` | 1014 | `return false;` | **not caught** | **none** |
| 37 | `commit_compact` | 1017 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 38 | `note_crash_during_compact` | 1030 | `return false;` | **not caught** | **none** |
| 39 | `note_crash_during_compact` | 1035 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 40 | `shadowed_summary_input` | 1077 | `return None;` | **not caught** | **none** |
| 41 | `read_observation` | 1201 | `return None;` | **not caught** | **none** |
| 42 | `read_observation` | 1209 | `return None;` | **not caught** | **none** |
| 43 | `read_observation` | 1216 | `return None;` | **not caught** | **none** |
| 44 | `current_observed_text` | 1238 | `return None;` | caught | `a_scaffold_stays_empty_after_it_is_sent`, `the_same_command_waits_until_the_first_has_a_result` |
| 45 | `observe` | 1281 | `return false;` | caught | `an_observation_stays_in_the_log_and_out_of_the_view`, `the_same_command_waits_until_the_first_has_a_result` |
| 46 | `observe` | 1287 | `return false;` | caught | `a_later_note_read_uses_the_rewritten_sentence`, `a_restore_proposes_an_observed_version_and_does_not_apply_it` (+3) |
| 47 | `open_step` | 1335 | `return None;` | **not caught** | **none** |
| 48 | `earlier_write_is_open` | 1352 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 49 | `earlier_write_is_open` | 1355 | `return false;` | caught | `a_crash_after_dispatch_does_not_apply_the_note` |
| 50 | `record_tool_result` | 1374 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 51 | `record_tool_result` | 1377 | `return false;` | caught | `a_second_write_stays_prepared_until_the_first_has_a_result`, `a_tool_result_enters_the_view_and_a_step_without_one_stays_in_the_log` |
| 52 | `propose_edit` | 1436 | `return Err("not observed");` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 53 | `propose_edit` | 1439 | `return Err("stale");` | caught | `a_later_note_read_uses_the_rewritten_sentence`, `an_unread_or_stale_edit_creates_no_step` |
| 54 | `propose_edit` | 1442 | `return Err("empty");` | caught | `an_unread_or_stale_edit_creates_no_step` |
| 55 | `propose_edit` | 1445 | `return Err("not observed");` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 56 | `propose_edit` | 1448 | `return Err("not unique");` | caught | `an_edit_requires_the_old_text_once_and_replay_keeps_the_observation` |
| 57 | `provider_write_may_be_asked` | 1470 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 58 | `provider_write_may_be_asked` | 1482 | `return false;` | caught | `a_provider_write_needs_a_grant_and_the_current_version`, `a_scaffold_stays_empty_after_it_is_sent` |
| 59 | `provider_write_may_be_asked` | 1485 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 60 | `provider_write_may_be_asked` | 1488 | `return false;` | **not caught** | **none** |
| 61 | `provider_write_may_be_asked` | 1491 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 62 | `note_provider_wrote` | 1503 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 63 | `note_provider_wrote` | 1512 | `return false;` | caught | `a_cancel_before_send_keeps_the_note_and_a_cancel_after_send_does_not_unsend_it`, `a_crash_after_dispatch_does_not_apply_the_note` (+2) |
| 64 | `note_provider_wrote` | 1531 | `return false;` | caught | `a_later_note_read_uses_the_rewritten_sentence`, `a_scaffold_stays_empty_after_it_is_sent` |
| 65 | `note_provider_wrote` | 1539 | `return false;` | **not caught** | **none** |
| 66 | `propose_run` | 1563 | `return Err("host path");` | caught | `a_run_proposal_keeps_arguments_as_data_and_a_cancelled_run_does_not_start` |
| 67 | `observed_project_files` | 1594 | `return None;` | **not caught** | **none** |
| 68 | `quoted_digest_matches` | 1622 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 69 | `quoted_digest_matches` | 1629 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 70 | `quoted_note_matches` | 1645 | `return false;` | **not caught** | **none** |
| 71 | `quoted_note_matches` | 1648 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 72 | `quoted_note_matches` | 1651 | `return false;` | caught | `a_cancelled_scaffold_lets_the_note_rewrite_land`, `a_crash_after_dispatch_does_not_apply_the_note` (+4) |
| 73 | `quoted_files_match` | 1668 | `return false;` | **not caught** | **none** |
| 74 | `quoted_files_match` | 1678 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 75 | `record_run_result` | 1758 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 76 | `record_run_result` | 1776 | `return false;` | caught | `a_cancel_before_send_keeps_the_note_and_a_cancel_after_send_does_not_unsend_it`, `a_cancelled_scaffold_lets_the_note_rewrite_land` (+14) |
| 77 | `project_tree_hash` | 1800 | `return None;` | caught | `a_non_entrypoint_change_changes_the_project_tree_hash` |
| 78 | `propose_scaffold` | 1825 | `return Err("no project");` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 79 | `propose_scaffold` | 1828 | `return Err("no project");` | **not caught** | **none** |
| 80 | `propose_scaffold` | 1835 | `return Err("host path");` | caught | `a_scaffold_write_uses_the_version_rules_and_does_not_apply` |
| 81 | `propose_scaffold` | 1839 | `return Err("not observed");` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 82 | `propose_scaffold` | 1842 | `return Err("stale");` | caught | `a_scaffold_write_uses_the_version_rules_and_does_not_apply` |
| 83 | `propose_scaffold` | 1845 | `return Err("not observed");` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 84 | `propose_scaffold` | 1848 | `return Err("not empty");` | caught | `a_scaffold_write_uses_the_version_rules_and_does_not_apply` |
| 85 | `propose_scaffold` | 1851 | `return Err("empty");` | **not caught** | **none** |
| 86 | `observed_text_at` | 1880 | `return None;` | caught | `a_later_note_read_uses_the_rewritten_sentence`, `a_restore_proposes_an_observed_version_and_does_not_apply_it` (+3) |
| 87 | `propose_restore` | 1895 | `return Err("unknown");` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 88 | `propose_restore` | 1898 | `return Err("unknown");` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 89 | `propose_restore` | 1901 | `return Err("stale");` | caught | `a_restore_proposes_an_observed_version_and_does_not_apply_it`, `the_same_command_waits_until_the_first_has_a_result` |
| 90 | `propose_hosted` | 1923 | `return Err("host path");` | caught | `a_hosted_proposal_has_no_secret_and_a_missing_grant_is_denied`, `a_hosted_proposal_must_name_a_localhost_resource` |
| 91 | `propose_child` | 1945 | `return Err("no parent");` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 92 | `propose_child` | 1948 | `return Err("not a subset");` | caught | `a_child_grant_is_narrower_and_does_not_inherit_the_parent_grant`, `a_child_must_sit_strictly_under_its_parent` |
| 93 | `propose_init` | 1978 | `return Err("host path");` | caught | `a_project_resource_is_not_a_host_path` |
| 94 | `narrower_resource` | 2004 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 95 | `authorize_child` | 2014 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 96 | `authorize_child` | 2017 | `return false;` | **not caught** | **none** |
| 97 | `authorize_child` | 2027 | `return false;` | caught | `a_child_grant_is_narrower_and_does_not_inherit_the_parent_grant` |
| 98 | `open_child_host` | 2042 | `return Err("no parent");` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 99 | `open_child_host` | 2045 | `return Err("not a subset");` | caught | `a_child_grant_is_narrower_and_does_not_inherit_the_parent_grant`, `a_child_must_sit_strictly_under_its_parent` |
| 100 | `open_child_host` | 2051 | `return Err("inherited");` | **not caught** | **none** |
| 101 | `grant_child_host` | 2060 | `return false;` | caught | `a_child_grant_is_narrower_and_does_not_inherit_the_parent_grant` |
| 102 | `grant_child_host` | 2072 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 103 | `record_child_result` | 2088 | `return false;` | caught | `a_child_grant_is_narrower_and_does_not_inherit_the_parent_grant` |
| 104 | `record_child_result` | 2095 | `return false;` | caught | `a_child_grant_is_narrower_and_does_not_inherit_the_parent_grant` |
| 105 | `authorize` | 2107 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 106 | `authorize` | 2110 | `return false;` | caught | `a_second_authorize_stays_denied` |
| 107 | `apply_inbox` | 2148 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 108 | `apply_inbox` | 2151 | `return false;` | caught | `a_goal_survives_shortening_and_does_not_grant` |
| 109 | `apply_inbox` | 2167 | `return false;` | caught | `a_child_grant_is_narrower_and_does_not_inherit_the_parent_grant` |
| 110 | `same_run_is_open` | 2204 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 111 | `same_run_is_open` | 2207 | `return false;` | **not caught** | **none** |
| 112 | `dispatch` | 2225 | `return false;` | caught | `a_cancelled_scaffold_lets_the_note_rewrite_land`, `a_second_write_stays_prepared_until_the_first_has_a_result` (+1) |
| 113 | `dispatch` | 2228 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 114 | `dispatch` | 2234 | `return false;` | caught | `a_cancel_before_send_keeps_the_note_and_a_cancel_after_send_does_not_unsend_it`, `a_child_grant_is_narrower_and_does_not_inherit_the_parent_grant` (+13) |
| 115 | `cancel` | 2244 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 116 | `note_crash` | 2265 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 117 | `note_crash` | 2268 | `return false;` | caught | `a_crash_after_the_result_does_not_erase_it`, `a_spill_pointer_keeps_the_file_text` (+1) |

Counts: compile_error 43, failed 51, none 24

### `elastos/crates/elastos-compute/src/exec_vm.rs`

| # | Function | Line | Refusal | Mutation result | Failing test |
| --- | --- | --- | --- | --- | --- |
| 0 | `admit_project_files` | 126 | `return Err("host path");` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 1 | `admit_project_files` | 129 | `return Err("host path");` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 2 | `admit_project_files` | 143 | `return Err("host path");` | **not caught** | **none** |
| 3 | `admit_project_files` | 154 | `return Err("host path");` | caught | `cargo_is_not_in_the_image_and_an_unknown_command_does_not_launch` |
| 4 | `admit_project_files` | 157 | `return Err("host path");` | caught | `cargo_is_not_in_the_image_and_an_unknown_command_does_not_launch` |
| 5 | `admit_listed_file` | 173 | `return Err("host path");` | caught | `cargo_is_not_in_the_image_and_an_unknown_command_does_not_launch` |
| 6 | `cap_exec_output` | 217 | `return Err("host path");` | caught | `a_console_without_an_exit_mark_is_not_success_and_a_failed_command_stays_failed`, `an_ext4_rootfs_is_handed_to_the_launcher_and_a_host_path_is_dropped` |
| 7 | `cap_exec_output` | 229 | `return Err("log too long");` | **not caught** | **none** |
| 8 | `parse_exec_console` | 251 | `_ => return Err("exit missing"),` | no accept path (does not compile) | mismatched types |
| 9 | `parse_exec_console` | 255 | `return Err("exit mismatch");` | caught | `a_console_without_an_exit_mark_is_not_success_and_a_failed_command_stays_failed` |
| 10 | `parse_exec_console` | 261 | `return Err("exit missing");` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 11 | `begin_exec` | 280 | `ExecDecision::Refuse(reason) => return Err(reason),` | no accept path (does not compile) | `match` arms have incompatible types |
| 12 | `begin_exec` | 284 | `return Err("rootfs not bootable");` | caught | `a_fake_rootfs_never_reaches_the_launcher` |
| 13 | `perform_edit` | 306 | `return Err("missing grant");` | caught | `a_provider_edit_returns_text_and_writes_no_file` |
| 14 | `perform_edit` | 309 | `return Err("host path");` | caught | `a_provider_edit_returns_text_and_writes_no_file` |
| 15 | `perform_edit` | 312 | `return Err("stale");` | caught | `a_provider_edit_returns_text_and_writes_no_file` |
| 16 | `perform_edit` | 315 | `return Err("not unique");` | **not caught** | **none** |
| 17 | `admit_boot_image` | 332 | `return Err("browser image");` | caught | `a_browser_disk_or_a_missing_kernel_is_not_an_exec_image` |
| 18 | `admit_boot_image` | 335 | `return Err("kernel missing");` | caught | `a_browser_disk_or_a_missing_kernel_is_not_an_exec_image` |
| 19 | `admit_boot_image` | 338 | `return Err("rootfs not bootable");` | **not caught** | **none** |
| 20 | `elf_kernel` | 349 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 21 | `elf_kernel` | 354 | `return false;` | **not caught** | **none** |
| 22 | `ext4_superblock` | 361 | `return false;` | no accept path (does not compile) | `else` clause of `let...else` does not diverge |
| 23 | `ext4_superblock` | 370 | `return false;` | **not caught** | **none** |

Counts: compile_error 7, failed 11, none 6

## What is next

Item c (S3) on its own branch. The gaps above become the next test slice.
