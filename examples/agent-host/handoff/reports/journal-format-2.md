# Journal format 2: typed record kinds

```text
Slice:        journal format 2 (the code PR for JOURNAL-FORMAT-2.md, approved in PR #25). OMP idea 2 comes after.
Branch / PR:  claude/journal-format-2  (draft PR in this repo, base spike/agent-host)
Commit:       8b5f1de (code), b01e4f9 (tests, S3 test), 979c718 (two tests that leaned on the checks they test),
              7602b6b (USERSAI-JOURNAL.md); parent f8739571d (spike/agent-host, #24 merged); this report is the next commit
Develop:      not merged in this slice (base is spike/agent-host at f8739571d).
Machine:      Linux 6.18.44 x86_64 (cloud container), rustc 1.91.0.
Changed:      examples/agent-host/src/lib.rs - typed kinds, format 2 encoder and decoder, rendering table, cache bytes,
                format 1 refusal on every load, the run's format 1 refusal; tests
              elastos/crates/elastos-server/src/runtime.rs - tests only: the S3 test asserts format 2; a new ignored
                end-to-end test for a stored format 1 journal (Sasha's answer, 22 Oct)
              examples/agent-host/handoff/USERSAI-JOURNAL.md - format 2: bytes, kinds, rendering, refusals
              examples/agent-host/handoff/reports/journal-format-2.md - this report
              examples/agent-host/handoff/LOG.md - one line
Invariant:    Every journal node has a typed kind, and no reader decides a kind from text: a person's message is a
              message whatever it starts with. The text the model sees for a record comes from one table, which
              changes only with a format bump. A format 1 journal is refused with "journal format 1 not supported;
              start a new task", on every load, and never touched.
Refusals:     format 1                                                  -> "journal format 1 not supported; start a new task"
                (decode, reread; resume -> FormatNotSupported(that text); the run -> BusError::Invalid(that text))
              a format other than 1 or 2                                -> "format version"
              an unknown kind (17 and 18 included), a kind with the wrong role -> "record"
              an observation whose fields do not fit its text, an absent revision or window holding a value -> "record"
              an unknown inbox answer                                   -> "record"
              a non-zero OMP idea 2 field (header or step)              -> "record"
              a stored spill pointer that breaks the path rule          -> "path not canonical" / "path not NFC"
              encode: a wrong role, text on a kind without text, a read whose fields do not fit -> nothing
              replay: cache bytes whose rendered text is not what the record renders to -> nothing
Tests run:    ./examples/agent-host/verify.sh -> fmt, "161 passed" (146 + 15), clippy clean, build OK
              ./examples/agent-host/run-local.sh -> "1 passed" (the guest's whole run fixture in Wasmtime)
              ./examples/agent-host/run-e2e.sh -> "3 passed" (was 2; the new format 1 test)
              (cd elastos && cargo clippy -p elastos-server --tests -- -D warnings) -> clean
Not run here: Mac checks (Cursor): verify.sh, run-local.sh, run-e2e.sh and the guest hash.
```

## What changed

- **Kinds.** `NodeSource` is the typed kind, with its fields:
  - head, history, message, snapshot, skill, turn marker, step marker (its step id), compaction checkpoint;
  - observation (resource, version, text hash, revision, window, cut);
  - todo, plan entered, plan exit asked, goal;
  - spill (resource, version), inbox (answer), refused (reason, what).

  `role_fits` fixes each kind's role, and `kind_has_text` says which kinds carry free text.
  - The writers create typed nodes: `record_visible`, `spill_pointer`, `apply_inbox`, `record_refusal`, `open_step`,
    `observe` and `observe_read`.
  - The readers match on the kind: `is_durable_visible`, `text_at_spill`, `is_refusal_record` and `read_observation`.
    Nothing reads a label or a text head any more.
- **Bytes.** Format 2, as in `USERSAI-JOURNAL.md`: kind tags 1-16, with 17 and 18 refused. The header is 84 bytes. The
  OMP idea 2 fields are written empty and refused when not empty.
- **Rendering.** `render_record` is the one table. `visible_bytes`, the summary input and the cache bytes use it.
  - Frozen texts: `todo: …`, `plan entered: …`, `plan exit asked: …`, `goal: …`, `spill: <resource> version <n>`,
    `inbox: <answer>`, `refused: <reason> (<what>)`.
  - The answer names are `allow-once`, `allow-session`, `standing` and `deny`, the names the step already keeps.
  - There is no trailing newline.
- **Cache bytes.** `model_bytes` carries the rendered text and the typed record. `replay` refuses a mismatch.
- **Format 1.**
  - `decode_bytes` refuses format 1 with its reason before reading anything else.
  - `read_stored_journal` passes the reason up: resume gives `FormatNotSupported(reason)` and reread gives the reason.
  - `stored_task_refusal` turns it into the run's refusal after the first append meets the stored object (a
    conflict). Nothing is written over the old object.
- **Paths (Sasha, 22 Oct).**
  - `path_key` is used where a limit gets stricter: the no-op count and both duplicate checks, as in #24.
  - The exact canonical NFC path is used where the code decides which file: reads, versions, seen ranges, spill
    lookup, the project, grants.
  - The one new path comparison, spill lookup, is exact. A stored spill pointer follows the path rule on load.
- **One addition to the design note.** A later system line (`admit_system(.., true)`) is its own kind, 19, written
  only by the host. History allows only an assistant line or a tool result (Sasha, 22 Oct; see the update below).

## Tests (new: 15)

```text
a_message_starting_with_each_label_stays_a_message   7 labels, their format 1 pointer forms ("spill\n<path>\n1", ...)
                                                     and their rendered forms ("goal: x", ...): kind message in the
                                                     log, after a round trip and in the cache bytes; not durable, not
                                                     a refusal, no spill pointer; summarized, not kept, by compaction
each_kind_renders_byte_for_byte                      one golden example per kind (tags 1-16), exact bytes
the_rendering_changes_only_with_the_format_number    sha256 of the rendered golden table pinned with format 2:
                                                     fb358dc06c691ec7e529fd3a488e20123374ce7e8587e89f18d08756f1219771
every_kind_round_trips                               journal bytes and cache bytes
a_format_1_journal_is_refused_with_its_reason        a real format 1 journal (698 bytes, written by the format 1
                                                     encoder at f873957), and format 2 bytes relabelled as 1
a_format_1_task_shows_its_reason                     reread, the append conflict, stored_task_refusal, resume ->
                                                     FormatNotSupported; only reads after the append; the stored
                                                     bytes unchanged; a format 2 object is not a refusal
an_unknown_kind_is_refused                           tags 0, 17, 18, 19, 255, bare and with fields
a_kind_with_the_wrong_role_is_refused                46 pairings, at encode and decode
a_kind_without_text_must_have_none                   the five kinds, listed by hand
an_observation_with_a_wrong_hash_or_window_is_refused 11 malformed payloads; the encoder refuses a forged read
an_unknown_inbox_answer_is_refused                   0, 5, 255; each answer's tag round-trips
idea_2_fields_must_be_empty_until_built              every header byte 25..48 and the last 19 step bytes
the_cache_bytes_refuse_a_rendering_that_does_not_match
a_stored_spill_pointer_follows_the_path_rule         not canonical, not NFC
two_files_that_differ_only_in_case_stay_two_files    NOTES.txt and notes.txt: a read of one never binds an edit of
                                                     the other (propose_edit, propose_change, edit_request); a version
                                                     of one is not bound by the other; spill lookup is exact; one key
                                                     for limits
runtime::tests::the_agent_host_refuses_a_format_1_journal_with_its_reason (ignored; run-e2e.sh)
                                                     a format 1 journal stored for the person; the real guest's run
                                                     fails with exactly the text; the stored object is unchanged
```

Changed tests:
- The older tests now check typed kinds, for example `Goal` with "finish the note" in place of
  "goal\nfinish the note".
- `an_observation_row_with_an_unknown_word_is_not_a_read` became `an_observation_whose_fields_do_not_fit_is_not_a_read`.
  Typed fields have no words to parse.
- The spill tests push typed spill nodes. A message shaped like a format 1 pointer is now never a pointer, so the
  missing-version case uses a typed spill at version 9.
- The S3 end-to-end test asserts format 2.

## Falsifiers

```text
JF01 any role fits any kind                       -> a_kind_with_the_wrong_role_is_refused FAILED
JF02 decode skips the role check                  -> a_kind_with_the_wrong_role_is_refused FAILED
JF03 encode skips the role and text check         -> wrong_role, without_text FAILED
JF04 every kind may carry text                    -> SURVIVED first: the test chose its cases with kind_has_text.
                                                     979c718 lists them by hand; then FAILED
JF05 one rendering changes                        -> golden bytes, pinned hash, cache bytes FAILED
JF06 a rendering and its golden bytes change together, format stays 2
                                                  -> the_rendering_changes_only_with_the_format_number FAILED
JF07 an unknown kind decodes as a message         -> SURVIVED first: every unknown-kind payload had trailing bytes.
                                                     979c718 adds bare kinds; then FAILED
JF08 format 1 is not recognised                   -> both format 1 tests FAILED
JF09 format 1 gets a generic error                -> both format 1 tests FAILED
JF10 resume says Unknown for format 1             -> a_format_1_task_shows_its_reason FAILED
JF11 the stored read hides the format 1 reason    -> a_format_1_task_shows_its_reason FAILED
JF12 the run ignores a format 1 journal           -> the e2e format 1 test FAILED (run-e2e.sh)
JF13 stored_task_refusal never refuses            -> a_format_1_task_shows_its_reason FAILED
JF14 idea 2 header fields are not checked         -> idea_2_fields_must_be_empty_until_built FAILED
JF15 idea 2 step fields are not checked           -> idea_2_fields_must_be_empty_until_built FAILED
JF16-JF22 a read's hash / window count / cut without window / window without revision / revision token /
     window at line 0 / empty resource is not checked -> the observation tests FAILED (each)
JF23 absent read fields may hold values           -> an_observation_with_a_wrong_hash_or_window_is_refused FAILED
JF24 an unknown inbox answer decodes              -> an_unknown_inbox_answer_is_refused FAILED
JF25 a kind is read from a text prefix again ("goal\n" -> Goal)
                                                  -> a_message_starting_with_each_label_stays_a_message FAILED
JF26 replay trusts the rendered text              -> the_cache_bytes_refuse_a_rendering_... FAILED
JF27 encode drops a spill's version               -> 4 tests FAILED (every_kind_round_trips among them)
JF28 a stored spill pointer skips the path rule   -> a_stored_spill_pointer_follows_the_path_rule FAILED
JF29 spill lookup folds case                      -> two_files_that_differ_only_in_case_stay_two_files FAILED
JF30 a read's file is matched by path_key         -> 5 tests FAILED
JF31 the cache bytes carry no rendered text       -> 26 tests FAILED
JF32 the guest writes a format other than 2       -> the S3 end-to-end test FAILED (run-e2e.sh)
Earlier lib.rs falsifiers (55): 49 FAILED as written.
  OZ01 survives by design, as recorded on #24 (the final NFD of path_key).
  OW01, OC02 and OY02 were moved to their new code lines and FAILED.
  OS01 was already retired. OP01 (an unknown word in a read's text head) is retired: format 2 reads have typed
  fields, and JF16-JF23 cover them.
Each restored; tree clean.
```

Survivors, honestly: none among the new checks after 979c718; OZ01 (by design, from #24).

```text
Guest hash:   2296962221c4a58872676d8af7cecd92c0f5d399dc0a399fc0ab82a5190f75d5 on two clean builds and verify.sh.
              wasm_sections.py: file 636434 bytes (was 632777 at #24); /1/10 375182 6769b148feef4bf7 (code);
              /1/11 175767 74340358f9526d79 (data).
Import list:  unchanged: the core import section (/1/2, 149 bytes, 5ee6b40d46f6a045) and every top-level component
              section are byte-identical to the #24 build.
Principles:   3 and 16: a person's words never become a record, and a record never grants; the person sees the
                format 1 reason, and Home only renders (when it does, below).
              11: format 1, unknown kinds, wrong roles, malformed reads and idea 2 values are refused; nothing is
                guessed or migrated.
              12: one rendering table, pinned with the format number.
DeepSeek:     none.
Not proven:   - Home does not show the refusal today. Sasha, 22 Oct: this is a Home-wide gap (every capsule's launch
                reason is dropped). It goes after 0.8.0 with the capsule kit, not in this PR. Checked read only:
                  - The agent host is not launched from Home ("No Home icon", run only by the scripts and the
                    ignored tests).
                  - For an ordinary Home launch, the run error reaches POST /api/capsules as the 400 body, and the
                    gateway turns it into launch_detail.
                  - shell-windows.js then shows generic copy ("The app did not start…") with the detail empty, and
                    only logs it to the console (capsules/home-gui/browser/shell-windows.js:1511-1524, :1641-1648).
                  - The Assistant face is the one view that shows error.message.
                  - So the person-visible part needs that Home change. It is proven only once Home shows it on the Mac.
              - The gateway's Runtime client has a 5 s timeout (gateway_home_runtime.rs:526). A run that waits on
                grant prompts may time out before the guest's text comes back; not tested here.
              - The rendering texts are frozen by this PR; the design note left them open.
Checklist:    no item moves.
Questions:    none (both answered by Sasha on 22 Oct; see the update below).
```

## Update after the Mac check of 23c56874 (22 Oct)

Cursor: verify 161, run-local 1, run-e2e 3/3, tree clean; Mac guest hash 25d8cd27 (Linux differs, as known). Sasha's
answers to the two questions:

```text
Commits:      503dc11 (the system line kind and its test), 659bd0b (USERSAI-JOURNAL.md); this update is the next commit
Change:       a later system line (admit_system with in_history) is kind 19, "system line", role system, written only
              by the host. History allows only an assistant line or a tool result. 17 and 18 stay kept for idea 2.
              Its rendering is its text; the golden table pins it ("Reply in one short paragraph."), and the pinned
              rendering hash moves with it while format 2 is still open:
              93e50ef9b12235326ff9cf3f910b227021d80f1a97a0ae9b731cfbb9494e9da8.
New test:     only_the_host_writes_a_later_system_line
                - admit_system(.., true) writes a system line;
                - a person's, the model's and a tool's text never becomes one: admit_user, admit_assistant,
                  admit_tool_result and record_tool_result, with "system\n...", "system: ...", the head's own
                  words and a system line's words; in the log and after a round trip;
                - decode refuses a system line with any other role, and history with the system role.
Changed tests: the golden table has 17 kinds (tags 1-16 and 19); the wrong-role count is 50; the unknown-kind
              tests use tag 20 where they used 19.
Home:         recorded under "Not proven" as a Home-wide gap, after 0.8.0 with the capsule kit.
Tests run:    ./examples/agent-host/verify.sh -> fmt, "162 passed" (161 + 1), clippy clean, build OK
              ./examples/agent-host/run-local.sh -> "1 passed"; ./examples/agent-host/run-e2e.sh -> "3 passed"
Falsifiers:   JF33 history may carry the system role again      -> wrong_role, only_the_host_... FAILED
              JF34 a later system line is written as history     -> 51 tests FAILED
              JF35 a system line may carry any role              -> wrong_role, only_the_host_... FAILED
              JF36 a person's text can become a system line      -> only_the_host_writes_a_later_system_line FAILED
                   ("system\n..." in admit_user)
              JF37 the system line renders differently, format stays 2
                                                                 -> golden bytes, pinned hash, only_the_host_... FAILED
              JF01-JF32 rerun: each still FAILED. Each restored; tree clean. Survivors: none (OZ01 by design, #24).
Guest hash:   b3fd14e2d95eec5fbdee65e0456600a7557b5a328378dce6dc855a15df0bf774 on two clean builds and verify.sh.
              wasm_sections.py: file 636514 bytes.
Import list:  unchanged: the core import section (/1/2, 149 bytes, 5ee6b40d46f6a045) and every top-level component
              section are byte-identical to the #24 build.
```

**What is next:** Cursor verifies on the Mac, then Codex reviews. OMP idea 2 (child limits) starts after format 2
merges.
