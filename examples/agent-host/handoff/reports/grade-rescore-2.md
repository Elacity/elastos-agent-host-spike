# Grade re-score after tasks 005 to 018 merged

```text
Slice:        re-score of the 14-row grade (docs only), after tasks 005 to 018 merged
Branch / PR:  spark/agent-host/019-grade-rescore-after-005-to-018 (base spike/agent-host)
Commit:       the commit that adds this file; parent adeb59a82e01276ab0b7141129d11a075b778bdb
Develop:      not merged in this slice.
Machine:      macOS 25.5.0 arm64 (Apple silicon), rustc 1.91.0 (f8297e351 2025-10-28).
Changed:      examples/agent-host/handoff/reports/grade-rescore-2.md - this report
              examples/agent-host/handoff/HANDOFF.md - grade line and section-1 note
              examples/agent-host/handoff/BACKLOG.md - lane backlog record (absent at the base, see below)
              examples/agent-host/handoff/LOG.md - one line
Invariant:    The proven total is honest: a point moves only when a named merged test proves it and a listed
              falsifier makes that test fail. Every other row keeps its old score.
Refusals:     none new (docs only); the code's existing summary, stale, no-grant and empty-old refusals are
              unchanged and pinned.
Tests run:    all green at adeb59a82; exact commands and result lines under "Tests run" below.
Not run here: none; every lane gate ran on this Mac. The two opt-in real-model tests stay ignored because they
              need SPARKS_MODEL_URL, as merged.
Falsifiers:   seven listed mutations re-run for this report, all CAUGHT and reverted; see "Falsifier reruns".
Guest hash:   12d02f29ff55935706ce2c1ae5d011fb236ee3b702e62bcb4f2d4906d796f071, unchanged across verify.sh,
              run-local.sh and the falsifier runs.
Import list:  unchanged (no code change).
Rule:         the method is the same as grade-rescore.md: a point counts only if a named merged test proves it,
              and a listed falsifier makes that test fail. Every gain below was re-run at this head with the merged
              falsify.py runner (tasks 005 and 010): one mutation alone, every named test must run and fail, then
              the original is restored. The runner's hard-link restore replaces the 22 Oct manual `git checkout`;
              the tree was clean after every run (`git status --short` empty) and the guest hash did not change.
              This report supersedes grade-rescore.md as the baseline.
Scale:        0 absent, 1 sketched, 3 real but incomplete, 5 production.
Result:       45 of 70 (was 42). Target 62. DeepSeek Harness 46.
Checklist:    56 of 63 (no status moves).
Principles:   12 docs, code and tests agree: each row that moved names its merged test and a re-run falsifier.
DeepSeek:     none (the DeepSeek column is the 12 Oct canvas, unchanged).
Not proven:   listed per row. Rows 1, 2, 3, 5, 6, 7, 10, 11, 12 and 14 carry over from grade-rescore.md; their
              falsifiers were not re-run. BACKLOG.md did not exist at this base: `git log --all -- 
              examples/agent-host/handoff/BACKLOG.md` is empty and no ref contains the path. The file added here
              records the eight merged pieces from LOG.md and the merged task ids; it is not the supervisor's
              original text.
Answers:      none.
Questions:    none.
```

## Rows

Old is the last proven score in grade-rescore.md (42 of 70). A row moves only with its named test and one listed
falsifier re-run for this report.

| Row | Old | New | Point: named test (re-run falsifier) | Gap to the HANDOFF target | Needs |
| --- | --- | --- | --- | --- | --- |
| 4 Compaction | 3 | **4** | `a_model_summary_that_changes_a_required_fact_is_refused` (FC10) | Target 4 met: the guest proposes the summary through the one Hosted Model path, and the answer is checked before the journal records it. | none to 4; A+ (5) needs Home's own model (S5, Mac); the production answer needs a Runtime hosted-model grant (row 11) |
| 8 Git and undo | 2 | **3** | `a_granted_restore_uses_the_write_path_and_records_the_checkpoint_text` (FE01) | Target 3 met: a granted restore applies through the single Edit write path and is refused without a grant or at a moved version. | none to 3; Versions on Home stays a manual screen (Home, beyond the target) |
| 9 Skills | 3 | 3 | none (row does not move) | The 22 Oct gap is still open: a child is not a separate instance. Child limits are #31, which Claude Code owns, not this lane; a separate instance also needs Runtime/Anders (Bus v2). | Claude Code (#31) and Runtime/Anders; not in-lane |
| 13 Create an app | 2 | **3** | `a_granted_scaffold_applies_through_the_write_path` (FS64) | A granted scaffold applies through the same write path and the project opens again with the same tree digest. A running project still needs a build or run provider. | Runtime (build or run provider) and Home (app surface); 4 is out of reach in-lane |

Carried over unchanged from grade-rescore.md: rows 1 (3), 2 (4), 3 (2), 5 (4), 6 (4), 7 (3), 10 (4), 11 (3),
12 (4) and 14 (1). Their tests and falsifiers stay as recorded there.

**Total: 45 of 70** = 42 + 1 (row 4) + 1 (row 8) + 1 (row 13); row 9 stays 3. Target 62, so 17 to go.
DeepSeek Harness 46.

### Row 4 Compaction: 3 -> 4

The 22 Oct gap was "The model does not write the summary." The merged tasks 006, 012 and 015 close that gap at the
guest rule and at a real model answer:

- `propose_compact_summary` sends the request through the one `propose_hosted` path (`src/lib.rs:1491`), with the
  required facts in `argv` and the digest of the request text in `new`.
- `compact_summary_prompt` builds the summary request from node 0 plus the shadowed history (`src/lib.rs:1523`).
- `record_compact_summary` accepts only a dispatched Hosted step with a matching request digest and passes the
  answer unchanged to `compact_refusal` (`src/lib.rs:1550`).
- `compact_refusal` refuses an empty summary, a host path, one that touches node 0, too little history, an open
  compaction, a dropped or changed required fact (whole tokens only), and a summary that does not shrink
  (`src/lib.rs:1379`).
- The opt-in real-model test `a_real_model_compaction_summary_is_judged_by_the_same_check` (`src/lib.rs:12866`)
  feeds a real DeepSeek answer through the same check; the always-on test is
  `a_model_summary_that_changes_a_required_fact_is_refused` (`src/lib.rs:12664`).

Re-run for this report: FC10 (the whole-token continuation removed) made
`a_model_summary_that_changes_a_required_fact_is_refused` fail; FC11 (a combining mark ends a token) made the
combining-mark test fail; FS46 (the answer is `.trim()`ed before the check) made
`a_padded_model_answer_is_not_trimmed_before_the_check` fail. All three were CAUGHT, restored, tree clean.

Not proven: no Runtime hosted-model grant or run exists, so the production call is still a proposal; the real-model
test is opt-in and uses the test-only `sparks_http` client. A+ (5) needs Home's own model (S5, Mac).

### Row 8 Git and undo: 2 -> 3

The 22 Oct gap was "A restore is never applied; Versions on Home is manual." Task 014 applies a granted restore
through the existing write path:

- `bind_change` selects `is_write` (Edit or Restore) steps (`src/lib.rs:2619`, `src/lib.rs:3268`), so a dispatched
  restore sends the edit request instead of nothing.
- `note_change_wrote` records the restore at the checkpointed text (`src/lib.rs:2742`).
- `provider_write_may_be_asked` still requires a non-empty grant, a dispatched step and the current version
  (`src/lib.rs:2843`).
- The test `a_granted_restore_uses_the_write_path_and_records_the_checkpoint_text` (`src/lib.rs:10218`) proves the
  granted restore writes and records, and `a_restore_without_a_grant_is_refused_and_records_nothing` proves the
  refusal.

Re-run: FE01 (bind_change selects Edit only) and FE04 (a restore may be asked without a grant) both made the named
restore test fail; FE04 also made the no-grant refusal test fail. Both CAUGHT, restored, tree clean.

Not proven: Home's Versions screen stays manual. That is beyond the row's target of 3; the row now has a real
restore through the one write path.

### Row 9 Skills: stays 3

Task 017 merged a real admission rule: `admit_skill_from_read` (`src/lib.rs:1243`) admits a skill only from text the
journal observed whole and current at that version, and only when `hex_digest(&sha256(text))` equals the stated CID;
it then calls the unchanged `admit_skill` (`src/lib.rs:1204`), so the budget, host-path and head-first rules stay in
one place. The named test `a_skill_from_an_observed_read_named_by_hash_is_admitted` is at `src/lib.rs:13585`.

The row does not move for two reasons:

1. The 22 Oct gap to the target is "a child is not a separate instance; child limits are idea 2". That is #31, owned
   by Claude Code, not this lane, and it also needs Runtime/Anders (Bus v2) for a separate instance. Loading a skill
   by content hash closes a content-identity gap; it does not make a child a separate instance. Child limits are
   required for row 9 to reach 4.
2. None of the listed falsifiers FS60 to FS63 names the row's admission test. FS60, FS62 and FS63 make
   `a_skill_from_unobserved_content_is_refused` fail; FS61 makes the over-budget/host-path test fail. They pin the
   refusals, not the positive admission test, so under this method the named test cannot carry a point even as the
   feature grows.

### Row 13 Create an app: 2 -> 3

The 22 Oct gap was "No in-Home scaffold write; Demo in Apps is manual." Task 018 applies a granted scaffold through
the same single write path:

- `propose_scaffold` keeps the observed empty-file version and the scaffold text (`src/lib.rs:3212`).
- `bind_change` binds an empty old text only to a whole read that showed no text, so a scaffold cannot overwrite a
  file that shows text (`src/lib.rs:2619`).
- The tests `a_granted_scaffold_applies_through_the_write_path` (`src/lib.rs:11002`) and
  `a_scaffolded_project_opens_again_with_the_same_tree_digest` (`src/lib.rs:11070`) prove the write and the reopen;
  `a_scaffold_without_a_grant_is_refused_and_records_nothing` (`src/lib.rs:11152`) proves the grant refusal.

Re-run: FS64 (the scaffold does not keep the observed version) made the granted-scaffold test fail; FS66 (a quoted
digest is compared to itself) made the same-tree-digest test fail. Both CAUGHT, restored, tree clean.

Not proven: there is no build or run provider and no Home app surface, so a scaffolded project cannot run from Home.
Task 018 says 4 is still out of reach; 3 is real but incomplete.

## Falsifier reruns at adeb59a82

One mutation at a time, run by `python3 -I examples/agent-host/falsify.py <id>`; each named test ran alone with
`--exact` and failed. The runner restored every original; `git status --short` was empty after the set and the guest
hash stayed `12d02f29ff55935706ce2c1ae5d011fb236ee3b702e62bcb4f2d4906d796f071`.

| Id | Mutation | Failed test | Result |
| --- | --- | --- | --- |
| FC10 | the whole-token continuation check is removed | `tests::a_model_summary_that_changes_a_required_fact_is_refused` | CAUGHT, reverted |
| FC11 | a combining mark ends a token | `tests::a_model_summary_that_changes_a_required_fact_with_a_combining_mark_is_refused` | CAUGHT, reverted |
| FS46 | the model answer is trimmed before the check | `tests::a_padded_model_answer_is_not_trimmed_before_the_check` | CAUGHT, reverted |
| FE01 | `bind_change` selects edits only, so a restore sends no request | `tests::a_granted_restore_uses_the_write_path_and_records_the_checkpoint_text` | CAUGHT, reverted |
| FE04 | a restore may be asked without a grant | `tests::a_granted_restore_uses_the_write_path_and_records_the_checkpoint_text`, `tests::a_restore_without_a_grant_is_refused_and_records_nothing` | CAUGHT, reverted |
| FS64 | the scaffold does not keep the observed version | `tests::a_granted_scaffold_applies_through_the_write_path` | CAUGHT, reverted |
| FS66 | a quoted project digest passes without being compared | `tests::a_scaffolded_project_opens_again_with_the_same_tree_digest` | CAUGHT, reverted |

Summary of the targeted run: 7 CAUGHT of 7. The full runner run of all 86 entries is recorded under "Tests run".

## Remaining headroom

Every row still under its HANDOFF target, the smallest next piece, and who it needs:

| Row | Now / target | Smallest next piece | Needs |
| --- | --- | --- | --- |
| 1 Agent loop | 3 / 5 | One model call per turn under a Runtime grant with a budget; the loop is still one-shot. | Runtime (model grant, RUNTIME-BUDGET.md), Anders |
| 2 Session log | 4 / 5 | A per-principal `UsersAI` root and the real shell policy; the e2e test still plays the shell. | Runtime (Anders), Home |
| 3 Prefix cache | 2 / 4 | Wire `packStablePrefix` into the live Assistant (`compileLiveContext`), then measure one cache hit with `--cache-ram` above 0. | Home (Assistant, slice SA), Sasha's yes; Runtime (model provider admission) |
| 5 Tool system | 4 / 5 | Read, edit and run through `providers.invoke` with Runtime grants; only the journal does today. | Runtime (read and edit providers), Anders |
| 6 Edit reliability | 4 / 5 | One write through the object provider. | Runtime (EDIT-PROVIDER.md, after 0.8.0), Anders |
| 7 Shell and tests | 3 / 4 | Put `cargo` in the exec image and run one test in the VM. | Mac (image); no Runtime change |
| 9 Skills | 3 / 4 | Child limits (#31): a child as a separate instance with its own limits. | Claude Code (#31) and Runtime/Anders (Bus v2); not this lane |
| 10 Local model ops | 4 / 5 | Behaviour tests for the idle release and the `input_tokens` refusal, replacing the source-text pins. | capsules/model-provider tests (outside this lane), Mac or cloud |
| 11 Hosted and secrets | 3 / 5 | One real hosted run with a grant budget. | Runtime (hosted provider), Anders |
| 12 Capability model | 4 / 5 | Exercise `home-auto.json` for the agent and record the cross-family review. | Home, Runtime (Anders), Sasha |
| 13 Create an app | 3 / 4 | A build or run provider for the scaffolded project, then the Home app surface. | Runtime (provider), Home |
| 14 Package and sell | 1 / 4 | A second Home and a revocation check; photo PRs on spike/photo-viewer do not count. | Anders |

Rows 4 and 8 meet their target and are not listed. The remaining gaps sum to 17 points.

**No row can gain a point purely in-lane.** Every open row needs the Runtime, Home, Anders, Sasha, the Mac, or
Claude Code's #31; row 10's behaviour tests live in `capsules/model-provider`, outside this lane's edit scope. The
lane is at its cloud ceiling at 45 of 70.

## Checklist (56 of 63)

No status moves. `compact-aplus-model` stays open: the guest proposes a hosted model request and a test proves a
real answer passes the same check, but Home's own model does not write the summary in production (S5, Mac). The
other six open items and their owners are unchanged from grade-rescore.md.

## Tests run

All at adeb59a82 with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`; this report changes docs only, so the committed
head has the same code and counts.

```text
bash examples/agent-host/verify.sh      -> 215 passed; 0 failed; 2 ignored; guest hash 12d02f29; capsule verification: OK
bash examples/agent-host/run-local.sh   -> 1 passed (the guest in the Runtime's Wasmtime); guest hash 12d02f29
bash examples/agent-host/run-e2e.sh     -> 3 passed (the guest in a test Runtime)
python3 -I examples/agent-host/falsify.py --self-test -> OK
python3 -I examples/agent-host/falsify.py             -> 86 of 86 as expected
```

Guest hash before and after the gates and falsifier runs:
`12d02f29ff55935706ce2c1ae5d011fb236ee3b702e62bcb4f2d4906d796f071` (unchanged). Import list unchanged.

## Principles

1. **Named by hash:** yes. No new code; the report cites the skill admission rule by SHA-256 (`src/lib.rs:1243`) and
   no new URL or name identity.
2. **No ambient authority:** yes. No code change; the model request remains a Hosted proposal with no grant
   (`src/lib.rs:1491`), and the restore and scaffold stay on the granted write path.
3. **One path (P10):** yes. Restore and scaffold use the existing `bind_change`/`note_change_wrote` path
   (`src/lib.rs:2619`, `src/lib.rs:2742`); no second write function was added.
4. **Trusted core:** yes. Docs only; no Runtime, provider or capsule code changed.
5. **Fails closed (P11):** yes. No new refusal; the existing summary, stale, no-grant and empty-old refusals are
   unchanged and pinned.
6. **Self-contained (Rong):** yes. No code change; the summary prompt and check stay in the guest.
7. **Tests prove it:** yes. Rows 4, 8 and 13 each name a merged test and a re-run falsifier that made it fail; row 9
   stays 3 because its named test has no listed falsifier, and child limits are open.

## What is next

The next planner cycle starts at 45 of 70. No graded row is in-lane; the smallest next gains are #31 (row 9),
Runtime provider work (rows 5, 6, 13), and Home work (rows 2, 3, 12). Do not retry stopped tasks 001, 003, 004, 008,
009 or 011; they are superseded.
