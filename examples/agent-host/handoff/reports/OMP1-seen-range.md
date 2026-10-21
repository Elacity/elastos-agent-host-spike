# OMP idea 1: seen range and edit binding

```text
Slice:        OMP idea 1 (ranked first in reports/OMP-AUDIT.md on claude/omp-audit, PR #22): seen range and edit
              binding. Guest only.
Branch / PR:  claude/omp-seen-range  (draft PR in this repo, base spike/agent-host)
Commit:       a1a05207e8a0981c6107a9c6b1c99dfcea8d209e (code, tests, run() self-test)
              4160fb7d44c16cdbe0a0f41196c16baefe15a66b (tests: the provider's written list; falsifier OA03 had survived)
              parent 0ee4f24dee18b4627332fb10d2b6a7217d6f8ab9 (spike/agent-host, the #20 merge); this report is the
              next commit
Develop:      Elacity develop 3beb816438fd567145a8d725e22465bd83277cf0, merged, behind 0.
Machine:      Linux 6.18.44 x86_64 (cloud container), rustc 1.91.0.
Changed:      examples/agent-host/src/lib.rs - guest only: bound reads, seen range, propose_change, edit_request,
                note_change_wrote, no-op guard, whole-file helpers fail closed on a window, run() self-test, 10 tests
              examples/agent-host/handoff/reports/OMP1-seen-range.md - this report
              examples/agent-host/handoff/LOG.md - one line
Invariant:    An edit may touch only whole lines the journal shows were read for the version it names; a change
              names the Runtime revision each file was read at and is sent as one request with if_revision per
              file; a change is checked whole before any step exists and is recorded whole or not at all; the
              same no-op edit is refused after NOOP_EDIT_LIMIT (2) proposals.
```

## What a read records now

A read row in the journal (an Observation node) keeps its old head `<version> <sha256> <resource>` and may add
words after the resource:
- `revision=<word>`: the Runtime revision the read returned (S3's revision; one word, no '=' or whitespace);
- `lines=<first>+<count>`: the read showed only `count` whole lines starting at line `first`; needs a revision;
- `cut`: the text ends in a partial line, which is shown but not part of the window; needs `lines=`.

An unknown, repeated or malformed word, or a window whose text does not have exactly `count` whole lines, makes the
row unreadable (fail closed). Old rows still read as whole reads with no revision. **No journal format change:** the
words live in the node text, and a change's steps share the existing `effect_id` field (PRINCIPLES 19: one durable
effect id for one consequence).

## Refusals

```text
observe_read (a read with a revision):
  empty, whitespace or host-path resource; revision not one word         -> nothing recorded (false)
  a window with no whole line, line 0, cut without a window,
  cut with no partial tail                                             -> false
  a version older than the current one                                 -> false
  the current version again with another revision                      -> false
  the current version again with a line that disagrees                 -> false
  a part past the end of a whole read of that version, or a whole read
  shorter than the parts shown                                         -> false
propose_edit (single edit, as before, plus):
  old text not exactly once in what that version showed               -> "outside the read window" (window read,
                                                                          not found) or "not unique"
  the same no-op edit (old == new) a third time                        -> "repeated no-op edit"
propose_change (one or more files; Err names the edit index and the reason; no step is made on any refusal):
  no file, or more than CHANGE_FILES_LIMIT (16)                         -> (0, "change size")
  a file named twice                                                    -> (i, "one file twice in one change")
  not read                                                              -> (i, "not observed")
  read with no revision                                                 -> (i, "no revision")
  the edit names another revision than the current read                 -> (i, "stale revision")
  empty old text                                                        -> (i, "empty")
  old text outside the shown lines (window, gap, cut line)              -> (i, "outside the read window")
  old text more than once in what was shown                             -> (i, "not unique")
  an edit that removes a window's last line break                       -> (i, "edit removes the window's last
                                                                              line break")
  a host path in the old or new text                                    -> (i, "host path")
  the same no-op edit a third time                                      -> (i, "repeated no-op edit")
edit_request / note_change_wrote (bind_change, checked for every file first):
  no such change                                                        -> "no change"
  a step not dispatched, without a grant, or already with a result      -> "not dispatched"
  a write outside this change still open                                -> "an earlier write is open"
  the file read again since the edit was made                           -> "stale"
  the read has no revision                                              -> "no revision"
  (and every propose_change text check again)
note_change_wrote only:
  the provider's list does not name each file exactly once with a one-word revision, or names another
  file                                                                  -> "written files do not match the change"
  Any refusal here records nothing for any file and denies every step of the change.
note_provider_wrote (the old single-step writer):
  a step that belongs to a change of several files                      -> false, nothing recorded
  an edit made on a windowed read                                       -> denied (no whole text to apply to)
Whole-file helpers (current_observed_text, observed_text_at, version_list, observed_project_files):
  the last read was a window                                            -> nothing (restore, quoting and the old
                                                                          writer then refuse)
```

## Tests and evidence

```text
Tests run:    (cd examples/agent-host && ./verify.sh) -> fmt, "118 passed" (108 + 10 new), clippy clean, build OK
              ./examples/agent-host/run-local.sh -> "1 passed" (runs run(), including the new self-test block)
              ./examples/agent-host/run-e2e.sh -> "2 passed" (real Runtime bridge; runs run() in the real guest)
Not run here: nothing needs the Mac for this slice.
New tests:    an_edit_outside_the_read_window_creates_no_step (older version, gap between two parts, cut line)
              an_edit_names_the_revision_it_read (stale and missing revision; the request carries if_revision; a
                newer read makes the change stale, records nothing, denies the step)
              a_repeated_no_op_edit_is_refused
              a_two_file_change_writes_both_or_neither (one effect id; both written; second file reread -> neither;
                provider list missing, doubled, extra or bad -> neither; one file alone -> nothing)
              a_change_that_fails_on_any_file_stages_nothing (omp's multi_file_failure_stages_nothing)
              a_windowed_change_records_only_the_edited_lines (and the window line-break and host-path refusals)
              a_window_is_not_a_whole_file
              reads_of_one_version_must_agree
              an_observation_row_with_an_unknown_word_is_not_a_read
              a_bound_change_survives_the_journal_round_trip (format 1 encode/decode keeps windows and effect ids)
Falsifiers:   OS01 every version counts as seen              -> an_edit_outside_the_read_window_creates_no_step FAILED
              OS02 a cut line counts as seen                 -> same FAILED
              OS03 runs join across a gap                    -> same FAILED
              OS04 an edit may remove the window line break  -> a_windowed_change_records_only_the_edited_lines FAILED
              OR01 the change revision is not compared       -> an_edit_names_the_revision_it_read,
                                                                a_change_that_fails_on_any_file_stages_nothing FAILED
              OR02 the request drops if_revision             -> an_edit_names_the_revision_it_read,
                                                                a_two_file_change_writes_both_or_neither FAILED
              OR03 a read without revision binds             -> an_edit_names_the_revision_it_read FAILED
              OR04 a stale file still binds                  -> an_edit_names_the_revision_it_read,
                                                                a_two_file_change_writes_both_or_neither FAILED
              ON01 the no-op count is infinite               -> a_repeated_no_op_edit_is_refused FAILED
              OA01 the first file is staged before the second is checked
                                                             -> a_change_that_fails_on_any_file_stages_nothing (+3) FAILED
              OA02 the first file is written before the second is checked (a stale file is skipped)
                                                             -> a_two_file_change_writes_both_or_neither (+1) FAILED
              OA03 the provider's written list is not checked -> a_two_file_change_writes_both_or_neither FAILED
                (it survived at first: the count check hid it; 4160fb7d44c16cdbe0a0f41196c16baefe15a66b added the doubled, extra and bad-word cases)
              OA04 one file of a change is written alone     -> a_two_file_change_writes_both_or_neither FAILED
              OA05 a change waits on itself (no dispatch)    -> same FAILED
              OA06 the written count is not checked          -> same FAILED
              OP01 an unknown word in a read row is accepted -> an_observation_row_with_an_unknown_word_is_not_a_read FAILED
              OW01 a window counts as the whole text         -> a_window_is_not_a_whole_file (+1) FAILED
              OW02 a window counts as a whole version        -> a_window_is_not_a_whole_file FAILED
              each restored with git checkout; tree clean
Guest hash:   fb3e2d96d5d32c692ae4e5c160d573ea46dc9d368a7ff942f3f8753ffbf0a24b on three builds (verify.sh,
              run-local.sh, run-e2e.sh). Was 70a95319c4996f6a7607f4ad02380c19d861d0d5107d0a286e8d6f334b1d52a3 on
              spike/agent-host (rebuilt in a scratch worktree: same hash).
              wasm_sections.py: file 455419 bytes; /1/10 339452 6ae68e5ad3a99490.
Import list:  unchanged. Against the spike/agent-host build, every top-level component section and the core
              module's import section (/1/2) are byte-identical. The core type, function, global, export (same
              size; function indices move), element, code and data sections differ, as new guest code does.
Principles:   3 No ambient authority: the guest only proposes; the request is data, a provider would act under grants.
              5 Small trusted core: nothing in the Runtime; guest only.
              11 Fail closed: unknown read words, disagreeing reads, a window as whole text, and any miss in a change
                all refuse; omp's automatic re-apply of a stale edit is not taken.
              19 Consequences govern effects: one change is one effect id, recorded all or none.
DeepSeek:     none. Ideas from oh-my-pi at 2220e58 (patcher.rs:391-475 seen lines, mismatch.rs:76-117 stale tag,
              patcher.rs:776-781 no-op repeat, session.rs:58 multi_file_failure_stages_nothing); no code copied.
```

## Not proven

- **No edit provider exists.** `edit_request` is the request the guest would send (one call per change,
  `all_or_none: true`, each file with `if_revision`, `first_line`, `line_count`, `old`, `new`). The guest
  guarantees it sends one request and records all files or none; writing all files atomically is the provider's
  job and is not built or tested here.
- **Revisions come from the caller.** Today only the journal itself is read through the bridge with a revision.
  `observe_read` takes the revision as given; when a read provider exists, its reply revision is what goes in.
- A long line cut in the middle of a window (column truncation) is not modelled; only a cut last line is.
- Compaction can drop read rows; then edits on those files are refused until read again (fail closed, untested).
- Windows also drops trailing spaces and dots in names; not handled here (same as S3).

```text
Checklist:    no item moves (omp idea 1 has no checklist item). OMP-AUDIT estimated grade row 6 could go 3 -> 4
              once these tests and falsifiers exist; that is Sasha's call.
Questions:    1. NOOP_EDIT_LIMIT = 2 (the third identical no-op is refused, as in omp). Keep?
              2. CHANGE_FILES_LIMIT = 16 files per change. Keep?
              3. The edit provider (all-or-none writes with if_revision per file): in the object provider, or its
                 own capsule? Its request shape is edit_request above.
```

## Fix 1, after the Codex review of 4a431ff (21 Oct)

Codex: FAIL, with three findings, all reproduced. The 16-file cap and the host grants held; 118 tests and clippy
passed.

```text
Commits:      9179183 (code and tests), 469aa0d (test: an older version's lines; falsifier OS05 had survived)
              this section is the next commit
Changed:      examples/agent-host/src/lib.rs - guest only; no journal format change, no import change
Finding 1:    Seen ranges mixed revisions. Repro: legacy v0; v1 at rev-a showing line 1; legacy v0 again; v1 at
                rev-b showing line 2. Line 1 could then be edited with if_revision rev-b.
              Now:
                - only the newest run of reads at one version and one revision counts as seen (current_reads); a
                  read at another revision, or with none, ends the run, so it clears what was seen before it;
                - a version is bound forever to the revision, or to no revision, it was first read at
                  (version_bound_elsewhere): observe_read and observe refuse a version reused with another one;
                - an edit is checked only against the lines of the current run, so every touched line was seen at
                  the exact revision it sends;
                - a written change takes a version number never used for that file (next_version).
Finding 2:    Path aliases bypassed the no-op limit and the duplicate check. Repro: two no-ops on
                Documents/notes.txt, a third via Documents//notes.txt; three slash spellings in one change.
              Now:
                - a path that is not canonical is refused by observe, observe_read, propose_edit and
                  propose_change ("path not canonical"). Canonical: after the scheme, no empty, ".", ".." or
                  trailing-"." segment, so "//", "/./", "/../", a trailing "/" and a trailing "." are refused. This
                  is the segment rule of the Runtime's Agents check;
                - the no-op counter and the duplicate check use the case-folded path (to_uppercase().to_lowercase(),
                  as the Agents check), so NOTES.txt and notes.txt count as one file.
Finding 3:    Refusals wrote no record. Now every propose_edit and propose_change refusal writes exactly one record,
                "refused\n<reason>\n<what>", where <what> is the path or "edit <i>: <path>". A path that is not
                canonical is not written into the record.
              "Counted per window like the other refusals": the guest has no windowed refusal counter to match, so
                each refusal writes one record and none are merged. Say if a window was meant.
Failing first: the three tests below were added before the fix and failed on 4a431ff's code:
                seen_lines_never_mix_revisions -> panicked at the propose_change with rev-b on line 1 (accepted)
                path_aliases_are_refused_and_case_counts_as_one_file -> panicked: the "//" alias was accepted
                each_refusal_writes_exactly_one_record -> "change size": left 0, right 1
Changed tests: four older tests asserted that a refused proposal leaves the journal byte-identical. They now assert
                it is identical apart from its refusal records, and count them. The run() self-test is changed the
                same way, and now also checks an alias and a second revision for one version.
Tests run:    (cd examples/agent-host && ./verify.sh) -> fmt, "124 passed" (118 + 6), clippy clean, build OK
              ./examples/agent-host/run-local.sh -> "1 passed"; ./examples/agent-host/run-e2e.sh -> "2 passed"
New tests:    seen_lines_never_mix_revisions (Codex repro 1, plus a new revision clears what was seen, plus a legacy
                read at a bound version is refused)
              path_aliases_are_refused_and_case_counts_as_one_file (Codex repro 2: six alias spellings; NOTES.txt as
                the third no-op; three spellings in one change; a case variant twice in one change)
              each_refusal_writes_exactly_one_record (size, unread target, stale revision, unseen range, no
                revision, alias; and propose_edit's refusals)
              a_stored_journal_that_mixes_revisions_still_does_not_mix_seen_lines (decode does not check binding)
              a_written_change_takes_a_version_never_used
              an_older_version_line_is_not_seen_at_the_newer_version
Falsifiers:   OV01 a version may change revision        -> seen_lines_never_mix_revisions FAILED
              OV02 the current reads ignore the revision -> a_stored_journal_that_mixes_revisions_... FAILED
              OV03 a write takes the number after the current read -> a_written_change_takes_a_version_never_used FAILED
              OS05 seen lines ignore the version         -> an_older_version_line_is_not_seen_at_the_newer_version
                FAILED (it survived first, because every caller passes the current version; 469aa0d pins the
                helper's contract)
              OS06 the current reads span versions       -> 4 tests FAILED
              OC01 any path spelling is accepted         -> path_aliases_..., each_refusal_... FAILED
              OC02 case counts as another file           -> path_aliases_... FAILED
              OX01 a refusal writes no record            -> 4 tests FAILED
              OX02 a change refusal writes no record     -> 2 tests FAILED
              The 17 earlier falsifiers still fail on this head. OS01 no longer applies, because its target was
                rewritten; OS05 and OS06 cover it. Each restored; tree clean.
Guest hash:   d926df46d9000c72f7af496a11728d82bd925becb4e6b22acb19f1d7f6f3b3cd on three builds (verify.sh,
              run-local.sh, run-e2e.sh). wasm_sections.py: file 497980 bytes; /1/10 353148 0bf09292ba7e537a.
Import list:  unchanged. Against the spike/agent-host build, the core import section (/1/2) and every top-level
              component section are byte-identical.
Principles:   10 one canonical rule for paths (the Agents segment rule), and one revision per version; 11 fail
                closed: a version reused with another revision, an alias, and a mixed stored journal all refuse;
                every refusal leaves a record.
DeepSeek:     none.
Not proven:   - A refusal record is a Person node with a label, like the existing spill, todo and goal records. A
                person's message that starts with the same label reads the same way; this matters for audit, not
                for authority.
              - Windows' trailing-space aliases are still not handled (as in S3).
```

**What is next:** Cursor verifies on the Mac, then Codex re-reviews. Building idea 2 still waits.
