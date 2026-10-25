Slice:        S70 FS70: a falsifier for the skill positive-admission rule (BACKLOG item 8, no grade point)
Branch / PR:  spark/agent-host/020-skill-positive-falsifier (PR to follow; this file is in the task commit)
Commit:       the commit that adds this file
Develop:      not merged in this slice (falsifier data and docs only)
Machine:      macOS 25.5.0 arm64 (Apple silicon), rustc 1.91.0 (f8297e351 2025-10-28)
Changed:      examples/agent-host/falsifiers.json - add FS70, which mutates the admitted skill node's source
              examples/agent-host/handoff/reports/S70-skill-positive-falsifier.md - this report
              examples/agent-host/handoff/LOG.md - one line
Invariant:    The positive skill admission effect is load-bearing: one compilation-safe mutation of the admitted
              node makes `a_skill_from_an_observed_read_named_by_hash_is_admitted` fail while the three skill
              refusal tests still pass, so FS70 pins the admission, not only the refusals.
Refusals:     no production refusal changed. FS70 mutates only the successful append in `admit_skill`
              (`src/lib.rs:1222`): a valid, observed, hash-matching skill is recorded as
              `source: NodeSource::Snapshot` instead of `NodeSource::Skill`. The earlier gates are untouched, so
              `not observed`, `stale`, `not whole`, `wrong cid`, `empty`, `over budget`, `host path` and `no head`
              still deny with their causes.
Tests run:    python3 -I examples/agent-host/falsify.py FS70 -> 1 CAUGHT of 1 (the positive test failed, then was restored)
              the same mutation with the four skill tests -> failed: the positive test; passed: the three refusals
                (`a_skill_from_unobserved_content_is_refused`,
                 `an_over_budget_or_host_path_skill_from_a_read_is_still_refused`,
                 `a_skill_cid_that_does_not_match_the_observed_text_is_refused`)
              python3 -I examples/agent-host/falsify.py --self-test -> self-test: OK
              python3 -I examples/agent-host/falsify.py -> 87 CAUGHT of 87 (was 86; FS70 added)
              bash examples/agent-host/verify.sh -> 215 passed; 0 failed; 2 ignored; capsule verification: OK
              bash examples/agent-host/run-local.sh -> 1 passed (the guest in the Runtime's Wasmtime)
              bash examples/agent-host/run-e2e.sh -> 3 passed (the guest in a test Runtime)
              git status --short after every run -> only this task's files
Not run here: none; every lane gate ran on this Mac. The two opt-in real-model tests stay ignored because they need
              SPARKS_MODEL_URL, as merged.
Falsifiers:   FS70 (new): an admitted skill is recorded as a snapshot, so the positive admission effect is lost ->
              `tests::a_skill_from_an_observed_read_named_by_hash_is_admitted` failed -> reverted by the runner.
Guest hash:   12d02f29ff55935706ce2c1ae5d011fb236ee3b702e62bcb4f2d4906d796f071, unchanged (no production code,
              no test body and no build change; the mutation is applied only transiently by the runner).
Import list:  unchanged (the wasm32 build is byte-identical).
Principles:   7 Tests prove it: FS70 is the named falsifier for the merged positive admission rule and it is caught.
              10 One path: the mutation proves the one append inside `admit_skill` (`src/lib.rs:1222`); FS70 adds no
              second path and no second copy of the budget, host-path or head rule.
              11 Fails closed: the refusals stay as merged and still pass under the FS70 mutation; FS70 changes only
              what a granted, matching read records.
              12 Docs, code, tests and operations agree: the report states the mutation, the one failing test and the
              three passing refusal tests that were actually run.
              3 No ambient authority / 5 Small trusted core: no code change; the guest is not rebuilt differently.
              1 Named by hash: the positive test still checks the SHA-256 CID of the observed text
              (`src/lib.rs:13585`); FS70 does not weaken the hash gate.
DeepSeek:      none (the lane's falsifier method, no DeepSeek pattern used).
Not proven:    this closes BACKLOG item 8's row-9 orphan: every merged rule now has a falsifier that bites its named
              test, the positive admission included. It does NOT move the grade. Row 9 stays 3 and remains blocked
              out-of-lane on child limits (#31, Claude Code with Runtime/Anders for Bus v2), per
              `reports/grade-rescore-2.md`. The total stays 45 of 70.
Checklist:    56 of 63 (no ids moved).
Questions:    none.
```

## FS70 detail

`admit_skill_from_read` (`src/lib.rs:1243`) keeps the observation, version, whole-text and `!= cid` gates and then
calls `admit_skill` (`src/lib.rs:1204`), which applies the budget, host-path and head-first rules and appends one
`SurfaceNode { role: Role::User, text, source: NodeSource::Skill }` (`src/lib.rs:1222`). That append is the positive
admission effect.

FS70 replaces the appended node's source with `NodeSource::Snapshot`; it compiles and the journal still gains one
node at the head-preserving position. The positive test asserts `last.source == NodeSource::Skill`
(`src/lib.rs:13585`), so it fails. The three refusal tests stop before the append (`not observed` / `stale` /
`not whole`, `over budget` / `host path` / `empty` / `no head`, `wrong cid`), so they pass under the same
mutation. That separation is why FS70 is not a duplicate of FS59 to FS63: those falsifiers break earlier gates and
never reach the append's recorded shape.

## Why no code or test changed

The merged rule and its test are correct; the proof set was incomplete. The only committed change is one entry in
`falsifiers.json`, this report, and the LOG line. The runner applies and restores the mutation itself, so the tree
is clean after every run.
