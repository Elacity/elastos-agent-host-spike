# Sweep gap tests: pin the refusals no test caught

```text
Slice:        Tests for the guard sweep's gaps (reports/guard-sweep.md), begin_exec first. Tests only.
Branch / PR:  claude/sweep-gap-tests  (draft PR in this repo, base spike/agent-host; link in the PR)
Commit:       d954861296b5348da1f7006d55437e051c9e87c7 (exec_vm.rs: begin_exec, project and boot admission, edit)
              6b5374872b071f434a00d20763aa3d8c7d07b0f6 (lib.rs: child and grant checks, S2 decoder tags)
              6628915985c9bb542c6d1fc12ac419b9792dcfef (lib.rs: journal fold rules)
              parent 8a57035 (merge of claude/guard-sweep, PR #5, review PASS; it holds PRs #1-#4)
              This branch does not contain the S3 PRs #6, #8, #9. The lib.rs tests sit at the top of the
              test module, away from where #9 adds its tests, so the two merge without a conflict.
Develop:      Elacity develop 3beb816438fd567145a8d725e22465bd83277cf0, merged, behind 0.
Machine:      Linux 6.18.44 x86_64 (cloud container), rustc 1.91.0.
Changed:      elastos/crates/elastos-compute/src/exec_vm.rs - TEST MODULE ONLY: 4 tests
              examples/agent-host/src/lib.rs - TEST MODULE ONLY: 13 tests
              examples/agent-host/handoff/reports/sweep-gap-tests.md - this report
              examples/agent-host/handoff/LOG.md - one line
Invariant:    Every refusal the guard sweep found uncaught now fails a named test when it is removed, or
              is listed below as unreachable or redundant, with the reason.
Refusals:     no new refusals; the existing ones below are now pinned
Tests run:    export RUST_TEST_THREADS=2
              ./examples/agent-host/verify.sh -> "99 passed" (86 before, 13 new), clippy clean, OK
              ./examples/agent-host/run-local.sh -> "1 passed"
              (cd elastos && cargo test -p elastos-compute --lib -- --include-ignored) -> "20 passed" (16 + 4)
              (cd elastos && cargo clippy -p elastos-compute --lib --tests -- -D warnings) -> clean; fmt -> ok
Not run here: Mac-only VM boots (begin_exec is tested with a recording launcher, as before).
Falsifiers:   40, one at a time on the committed code, undone with git checkout; tree clean after each run.
              All 40 fail the named test. Full list below. The sweep's own GLa-GLg were rerun too: all fail.
Guest hash:   fa10cca7929f1d538e914337999230e9daf6cd5413edf8256824ceb893d6be33 on two builds (verify.sh,
              run-local.sh). Unchanged from the guard sweep: tests are not in the wasm32 build.
Import list:  unchanged (identity, runtime, types on this branch)
Principles:   11 Fail closed: every refusal on the list now has a test that fails when it is removed.
              12 Docs, code, tests agree: the S2 report listed the decoder's tag refusals; now they are pinned.
              3 No ambient authority: begin_exec cannot launch on a refused decision; a child grant needs a
                child step; an empty grant string cannot ask for a write.
DeepSeek:     none
Not proven:   The four refusals in "Not pinned" below. They cannot be reached through any input today.
Checklist:    56 of 63 (no checklist item moves; this is test hardening)
Questions:    Should the four unreachable refusals stay as defence, or be removed? I left them; removing
              them would be a production change.
```

## What is pinned now

### `exec_vm.rs` (begin_exec first)

| Gap (guard sweep) | Test | Falsifier |
| --- | --- | --- |
| GXe `begin_exec` ignores a refused decision | `begin_exec_obeys_every_refused_decision_before_the_launcher`: no grant, empty grant, cancel, host workspace, host argv, missing rootfs, unsupported host; the launcher is never called; a good request still launches once | X01 |
| GXa workspace outside `Users/`; GXb no `/Projects/`; `admit_project_files:143` | `a_project_workspace_must_be_a_users_project` | X02, X03, X04, X04b |
| GXh unsupported host (`admit_boot_image`) | `a_boot_image_needs_a_whole_kernel_a_readable_ext4_rootfs_and_a_known_host` | X05 |
| `elf_kernel:354` short kernel | same | X06 |
| GXj unreadable rootfs; `admit_boot_image:338` | same (plain, short and absent rootfs) | X07, X08, X09 |
| `perform_edit:315` "not unique" | `an_edit_needs_old_text_that_occurs_exactly_once` (empty, twice, absent, and empty in empty) | X10, X10b |

### `lib.rs`: child and grant checks

| Gap | Test | Falsifier |
| --- | --- | --- |
| `authorize_child:2017` | `a_child_grant_needs_a_child_step` | L01 |
| `same_run_is_open:2207` | `only_an_earlier_run_holds_a_later_run` | L02 |
| `provider_write_may_be_asked:1488` | `an_empty_grant_string_cannot_ask_for_a_write` (sets the field directly; no API stores an empty grant) | L03 |
| `note_provider_wrote:1539` | `an_edit_at_the_last_version_number_is_denied_and_not_recorded` (version `u64::MAX` cannot go up) | L04 |

### `lib.rs`: the S2 decoder (GLc-GLg)

`a_relinked_journal_with_an_unknown_tag_or_spare_bytes_is_refused`: tag values 0 and 99 for the role, source, state and kind, and one spare byte in a node, a step and a turn. Every link is recomputed. Falsifiers GLc, GLd, GLe, GLf, GLg. The test uses 99, not 9, for an unknown kind, so it stays right after S3 adds kind 9.

### `lib.rs`: journal fold rules

| Gap | Test | Falsifier |
| --- | --- | --- |
| `record_visible:774`, `admit_snapshot:890`, `admit_skill:922`, `shadowed_summary_input:1077` | `records_skills_and_snapshots_need_the_system_head_first` | F01, F02, F03, F08 |
| `spill_pointer:819` | `a_spill_pointer_on_a_headless_journal_records_no_result` | F04 |
| `text_at_spill:831` | `only_a_person_spill_line_points_at_a_version` | F05 |
| `commit_compact:1014`, `note_crash_during_compact:1030` | `a_compaction_that_is_not_open_is_neither_committed_nor_rolled_back` (state set directly, as a decoded journal can carry it) | F06, F07 |
| `read_observation:1201, :1209, :1216` | `only_a_well_formed_observation_counts_as_a_read` (a person's line, an empty resource, a short hash, a forged hash) | F09, F10, F10b, F11 |
| `open_step:1335` | `a_step_on_an_unknown_turn_adds_nothing` | F12 |
| `observed_project_files:1594`, `quoted_note_matches:1645`, `quoted_files_match:1668` | `project_files_and_quoted_lines_refuse_odd_names` | F13, F14, F15, F15b |
| `propose_scaffold:1828, :1851` | `a_scaffold_needs_an_init_project_and_text` | F16, F17 |

## Not pinned: unreachable or redundant today

| Refusal | Why no test can reach it |
| --- | --- |
| `open_child_host` "inherited" (`lib.rs:2051`) | The child journal is built fresh, and `propose_run` never sets a grant. Defence against a later change. |
| `spill_pointer:800` (empty or host path object) | No observation exists for such a resource (`observe` refuses it), and `resource_covers` also refuses a host path. Two later checks cover it. |
| `cap_exec_output:229` "log too long" (`exec_vm.rs`) | The kept tail is at most the budget minus the notice, and `host_path` already ran on the whole log. The notice starts the text, so a cut cannot create a leading `/` or a lone `..` segment. |
| `ext4_superblock:370` seek failure (`exec_vm.rs`) | Seeking a regular file past its end succeeds. A short file is caught by `read_exact` (pinned: X09 and the short rootfs). |
| `encode_journal:407` | Already listed in the sweep: the final cap check covers it. |

## Falsifier list

```text
X01 begin_exec ignores a refused decision        -> begin_exec_obeys_every_refused_decision_before_the_launcher FAILED
X02 workspace outside Users accepted              -> a_project_workspace_must_be_a_users_project FAILED
X03 workspace without Projects accepted           -> same FAILED
X04 workspace shape check removed                 -> same FAILED
X04b workspace root may hold a slash              -> same FAILED
X05 boot image accepts an unsupported host        -> a_boot_image_needs_a_whole_kernel_a_readable_ext4_rootfs_and_a_known_host FAILED
X06 a short kernel read accepted                  -> same FAILED
X07 an unreadable rootfs accepted                 -> same FAILED
X08 boot image skips the ext4 check               -> same FAILED
X09 the ext4 magic is not compared                -> same FAILED
X10 edit accepts old text that is not unique      -> an_edit_needs_old_text_that_occurs_exactly_once FAILED
X10b edit accepts empty old text                  -> same FAILED
L01 authorize_child accepts any step              -> a_child_grant_needs_a_child_step FAILED
L02 same_run_is_open holds any step               -> only_an_earlier_run_holds_a_later_run FAILED
L03 an empty grant string may ask for a write     -> an_empty_grant_string_cannot_ask_for_a_write FAILED
L04 a failed observe still records the write      -> an_edit_at_the_last_version_number_is_denied_and_not_recorded FAILED
GLc decoder reads an unknown role as User         -> a_relinked_journal_with_an_unknown_tag_or_spare_bytes_is_refused FAILED
GLd decoder reads an unknown source as Person     -> same FAILED
GLe decoder reads an unknown state as Prepared    -> same FAILED
GLf decoder reads an unknown kind as Unspecified  -> same FAILED
GLg decoder accepts spare payload bytes           -> same FAILED
F01 record_visible skips the head check           -> records_skills_and_snapshots_need_the_system_head_first,
                                                     a_spill_pointer_on_a_headless_journal_records_no_result FAILED
F02 admit_snapshot skips the head check           -> records_skills_and_snapshots_need_the_system_head_first FAILED
F03 admit_skill skips the head check              -> same FAILED
F04 spill result recorded without the pointer     -> a_spill_pointer_on_a_headless_journal_records_no_result FAILED
F05 any node's spill line points at a version     -> only_a_person_spill_line_points_at_a_version FAILED
F06 commit_compact without an open compaction     -> a_compaction_that_is_not_open_is_neither_committed_nor_rolled_back FAILED
F07 crash rollback without an open compaction     -> same FAILED
F08 summary input without the head                -> records_skills_and_snapshots_need_the_system_head_first FAILED
F09 any node read as an observation               -> only_a_well_formed_observation_counts_as_a_read FAILED
F10 observation with an empty resource            -> same FAILED
F10b observation with a short hash                -> same FAILED
F11 observation hash not checked                  -> same FAILED
F12 open_step on an unknown turn                  -> a_step_on_an_unknown_turn_adds_nothing FAILED
F13 project files keep an odd relative path       -> project_files_and_quoted_lines_refuse_odd_names FAILED
F14 a quoted note may be empty or a host path     -> same FAILED
F15 a quoted file name is not checked             -> same FAILED
F15b a quoted file name may hold a slash          -> same FAILED
F16 scaffold on a step that is not a project      -> a_scaffold_needs_an_init_project_and_text FAILED
F17 scaffold with no text                         -> same FAILED
```

## What is next

1. Sasha's answer on the launch grant channel and the read grant (PR #9, questions 1 and 2).
2. The GPT-family review of PR #8, PR #9, and this PR.
3. If this PR passes, the guard sweep's gap list is closed except for the four unreachable refusals above.

## Update: spike/agent-host merged in (21 Oct)

Merge `c87c972` of spike/agent-host at `0ee4f24` (S3: #8, #9, #19, #20). One conflict, in handoff/LOG.md: both sides
kept, ordered by date and then by the time each line was committed. `examples/agent-host/src/lib.rs` merged without
conflict.

```text
Tests run:    export RUST_TEST_THREADS=2
              ./examples/agent-host/verify.sh -> "121 passed" (108 on spike/agent-host + this PR's 13), clippy clean, OK
              ./examples/agent-host/run-local.sh -> "1 passed"
              (cd elastos && cargo test -p elastos-compute --lib -- --include-ignored) -> "21 passed"
              (cd elastos && cargo clippy -p elastos-compute --all-targets -- -D warnings) -> clean
Guest hash:   70a95319c4996f6a7607f4ad02380c19d861d0d5107d0a286e8d6f334b1d52a3, the same as spike/agent-host: this PR
              adds tests only, and tests are not in the wasm32 build.
```
