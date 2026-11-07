Slice:        S12 FC12: a falsifier for the compaction proposal-shaping positive test (BACKLOG item 8, no grade
              point). The slice number follows the falsifier id, as S70 did for FS70.
Branch / PR:  spark/agent-host/021-falsifier-for-compaction-proposal-shaping (PR to follow; this file is in the
              task commit)
Commit:       the commit that adds this file
Develop:      not merged in this slice (falsifier data and docs only)
Machine:      macOS 25.5.0 arm64 (Apple silicon), rustc 1.91.0 (f8297e351 2025-10-28)
Changed:      examples/agent-host/falsifiers.json - add FC12, which drops the shadowed head from the summary request
              examples/agent-host/handoff/reports/S12-compaction-proposal-falsifier.md - this report
              examples/agent-host/handoff/LOG.md - one line
Invariant:    The positive compaction proposal-shaping effect is load-bearing: one compilation-safe mutation of
              `compact_summary_prompt` makes `a_compaction_summary_request_uses_the_hosted_model_path` fail while the
              round-trip, dropped-fact and stale tests still pass, so FC12 pins the shaping, not only the refusals.
Refusals:     no production refusal changed. FC12 mutates only the request text that `compact_summary_prompt` builds
              (`src/lib.rs:1523`): a valid request still goes through `propose_hosted` (`src/lib.rs:1491`), and the
              empty required fact, host path, no summary input, stale, not dispatched, settled, empty summary,
              dropped or changed fact, node-0, shrink and no-grant refusals stay as merged and still pass under the
              mutation.
Tests run:    RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 python3 -I examples/agent-host/falsify.py FC12
              -> FC12 CAUGHT; summary: 1 CAUGHT of 1
              the same mutation with three more named tests (see "Specificity proof") -> failed: the positive test;
              passed: `a_model_written_compaction_summary_is_recorded`,
              `a_model_summary_that_drops_a_required_fact_is_refused`,
              `a_summary_answer_after_new_history_is_stale`
              RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 python3 -I examples/agent-host/falsify.py --self-test
              -> self-test: OK
              RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 python3 -I examples/agent-host/falsify.py
              -> summary: 88 CAUGHT of 88 (was 87; FC12 added)
              RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 bash examples/agent-host/verify.sh
              -> 215 passed; 0 failed; 2 ignored; agent-host capsule verification: OK
              RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 bash examples/agent-host/run-local.sh
              -> 1 passed (`agent_host_example_keeps_the_head_across_a_compaction`)
              RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 bash examples/agent-host/run-e2e.sh
              -> 3 passed
              git status --short after every run -> only this task's files
Not run here: none; every lane gate ran on this Mac. The two opt-in real-model tests stay ignored because they need
              SPARKS_MODEL_URL, as merged.
Falsifiers:   FC12 (new): the summary request keeps only the lines after the shadowed head, so the provider never
              sees the head it is asked to work under -> `tests::a_compaction_summary_request_uses_the_hosted_model_path`
              failed -> reverted by the runner.
Guest hash:   12d02f29ff55935706ce2c1ae5d011fb236ee3b702e62bcb4f2d4906d796f071, unchanged before and after every
              gate and falsifier run (no production code, no test body and no build change; the mutation is applied
              only transiently by the runner).
Import list:  unchanged (the wasm32 build is byte-identical).
Principles:   7 Tests prove it: FC12 is the named falsifier for the merged proposal-shaping rule and it is caught.
              10 One path: the mutation proves the one prompt builder (`src/lib.rs:1523`) that feeds the one
              `propose_hosted` path (`src/lib.rs:1491`); FC12 adds no second path and no second copy of a rule.
              11 Fails closed: the refusals stay as merged and still pass under the FC12 mutation.
              12 Docs, code, tests and operations agree: this report states the mutation, the one failing test and the
              three passing tests that were actually run.
              3 No ambient authority / 5 Small trusted core: no code change; the request remains a Hosted proposal
              with no grant, and the guest is not rebuilt differently.
              1 Named by hash: the request digest still binds the answer to the request text
              (`src/lib.rs:1491`, `src/lib.rs:1550`); FC12 does not weaken it.
DeepSeek:     none (the lane's falsifier method, no DeepSeek pattern used).
Not proven:   this closes a BACKLOG item 8 proof-set orphan: the weak-test sweep item from the cycle brief ("any
              test that is weak, found while doing the above"), not the merged `BACKLOG.md` table row 8 (grade
              headroom). It does NOT move the grade. Row 4 stays 4, and that point rests on the refusal test
              `a_model_summary_that_changes_a_required_fact_is_refused` with FC10, per `reports/grade-rescore-2.md`.
              The total stays 45 of 70, the lane's cloud ceiling. One further orphan is named under "Audit", not
              fixed, by task scope.
Checklist:    56 of 63 (no ids moved).
Questions:    none.
```

## FC12 detail

`propose_compact_summary` (`src/lib.rs:1491`) refuses an empty required fact, routes through `propose_hosted`,
records the required facts in `step.argv`, builds the request with `compact_summary_prompt`, and stores the 64-hex
digest of that request text in `step.new`. `compact_summary_prompt` (`src/lib.rs:1523`) builds the one instruction,
the facts as `Keep these facts exactly: ...`, and the shadowed head plus the lines compaction would replace
(`input`). The positive test `a_compaction_summary_request_uses_the_hosted_model_path` (`src/lib.rs:12571`) proves
that shaping: a `ProposalKind::Hosted` step, `resource == "localhost://Models/hosted"`, `grant == None`,
`state == Prepared`, `argv == ["hello", "second turn"]`, a 64-byte `new`, and a prompt that starts with the
instruction, carries the facts, carries `SYSTEM_HEAD` and `BUILD_ID=7F3A`, does not carry `COMPACTION_SUMMARY`, and
leaves the journal unchanged; a no-grant authorize denies and dispatch is refused.

FC12 replaces the last two lines of that builder:

```rust
    prompt.push_str("\n\n");
    prompt.push_str(&input);
```

with a form that keeps the instruction and the facts but drops the shadowed head line:

```rust
    prompt.push_str("\n\n");
    let history = input.split_once('\n').map_or("", |(_head, history)| history);
    prompt.push_str(history);
```

The mutation compiles, and it weakens exactly the positive effect: the provider receives a request that no longer
carries the head the summary must work under. The named test fails on `assert!(prompt.contains(SYSTEM_HEAD))`.

## Specificity proof

The digest stays self-consistent because `propose_compact_summary` and `record_compact_summary` both call the same
`compact_summary_prompt`. Only the head line is dropped, so the shadowed lines remain in the request text and a new
instruction still changes the digest. That is why the mutation is specific, not a duplicate of FC07 to FC11:
FC07 to FC11 each break a refusal or the recorded path, and none of them edits this builder.

Run under the same mutation, by importing the merged runner and passing the three extra names:

```bash
RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 python3 -I -c "
import sys; sys.path.insert(0, '/Users/sash/code/wt-lane-agent-host/examples/agent-host')
import falsify
entry = next(e for e in falsify.load() if e['id'] == 'FC12')
extra = ['tests::a_model_written_compaction_summary_is_recorded',
         'tests::a_model_summary_that_drops_a_required_fact_is_refused',
         'tests::a_summary_answer_after_new_history_is_stale']
probe = dict(entry, tests=entry['tests'] + extra)
with falsify.Mutation(probe):
    build_failed, outcomes = falsify.evaluate(probe, falsify.spec(probe['command']))
for name, outcome in outcomes.items(): print(outcome, name)
"
```

Result:

```text
build_failed: False
failed tests::a_compaction_summary_request_uses_the_hosted_model_path
passed tests::a_model_written_compaction_summary_is_recorded
passed tests::a_model_summary_that_drops_a_required_fact_is_refused
passed tests::a_summary_answer_after_new_history_is_stale
```

The round-trip still records (the digest matches the prompt the same builder now produces), the dropped-fact
refusal still denies, and the stale check still denies after `admit_user` adds a line to the shadowed history.

## Why no code or test changed

The merged rule and its test are correct; the proof set was incomplete. The only committed change is one entry in
`falsifiers.json`, this report, and the LOG line. The runner applies and restores the mutation itself, so the tree
is clean after every run (`git status --short` showed only this task's files).

## Audit: merged positive/effect tests and their biting falsifiers

| Effect test | Biting falsifier |
| --- | --- |
| `a_granted_restore_uses_the_write_path_and_records_the_checkpoint_text` (row 8) | FE01 (also FE04, FE05) |
| `a_granted_scaffold_applies_through_the_write_path` (row 13) | FS64 (also FS65, FS69) |
| `a_scaffolded_project_opens_again_with_the_same_tree_digest` (row 13) | FS66 |
| `a_skill_from_an_observed_read_named_by_hash_is_admitted` (row 9) | FS70 |
| `a_model_written_compaction_summary_is_recorded` (row 4) | FC08 |
| `the_prompt_prefix_is_byte_identical_across_two_turns` (row 3 precondition) | FP01 (`falsifiers.json:397`; the brief's `:382` was the line before FC12 was inserted) |
| `a_compaction_summary_request_uses_the_hosted_model_path` (row 4) | FC12 (`falsifiers.json:381`) |

I compared every `#[test]` name in `src/lib.rs` (217 today) with every test name in `falsifiers.json` (32 of them
named). One further orphan was found, and it is named here for a future cycle, not fixed:

- `a_granted_edit_becomes_the_current_text_and_does_not_write_a_host_file` (row 6, the granted-edit effect) is not
  named by any entry in `falsifiers.json`. Its rule shares the write path with the restore and scaffold entries, so
  FS64/FS65 and FE01 would bite it, but no entry names it as their target. A later cycle can add that entry in the
  shape of FC12.

No other merged effect test from tasks 005 to 020 is unnamed: tasks 006, 007, 013, 014, 017, 018 and 020 each have
their positive tests named by FC10/FC11, FP01, FS23 to FS50, FE01 to FE05, FS59 to FS63 and FS70, FS64 to FS69, and
FS70 respectively. The two opt-in real-model tests stay `#[ignore]`d and cannot be run by the runner's host command,
as merged.

## Principles check

1. Named by hash: yes. No new code; the request digest still binds the answer to the request text (`src/lib.rs:1491`,
   `src/lib.rs:1550`), and FC12 weakens only the prompt text.
2. No ambient authority: yes. No code change; the compaction request remains a Hosted proposal with `grant == None`
   (`src/lib.rs:1491`), and no capsule, Home or UI surface gains authority.
3. One path (P10): yes. The mutation proves the one builder at `src/lib.rs:1523` feeding the one `propose_hosted`
   path; no second builder, digest rule or proposal path is added.
4. Trusted core: yes. Falsifier data and docs only; no Runtime, provider or capsule code changed.
5. Fails closed (P11): yes. No new refusal; the existing empty-fact, host-path, no-input, stale, not-dispatched,
   settled, empty-summary, dropped-fact, node-0, shrink and no-grant refusals are unchanged and still pass under the
   mutation.
6. Self-contained (Rong): yes. The prompt and the check stay in the guest; no host file, network or wasi import is
   added.
7. Tests prove it: yes. `a_compaction_summary_request_uses_the_hosted_model_path` fails under FC12 and is restored
   by the runner; the three related tests still pass under the same mutation.
