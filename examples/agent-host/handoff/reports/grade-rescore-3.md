# Grade re-score of row 10 by behaviour, each proof labelled by kind

```text
Slice:        re-score of grade row 10 (docs only), after tasks 002, 003 and 008 merged
Branch / PR:  spark/provider/009-rescore-row-10-by-behaviour (base spike/agent-host)
Commit:       the commit that adds this file; parent 0cfbbee272065a214f91f2ce6538cbf2d046627a
Develop:      not merged in this slice.
Machine:      macOS 25.5.0 arm64 (Apple silicon), rustc 1.91.0 (f8297e351 2025-10-28).
Changed:      examples/agent-host/handoff/reports/grade-rescore-3.md - this report
              examples/agent-host/handoff/LOG.md - one line
              examples/agent-host/handoff/HANDOFF.md - grade line only, applied at merge by the owner
              (outside this lane's allowed paths; the exact line is under "HANDOFF grade-line change")
Invariant:    A point moves only when a named merged test proves it and a listed falsifier makes that test
              fail. Every row except 10 keeps its old score.
Refusals:     none new (docs only); the provider's existing refusals are unchanged by this slice.
Tests run:    fmt, provider cargo tests, self-test and the three id-selected falsifier re-runs are green on
              this Mac; exact commands and result lines under "Tests run" below.
Not run here: the full provider falsifier list (this task selects three representatives by id), the default
              agent-host falsifier list, and any guest build (no guest source changed). No other row's
              falsifiers were re-run, so their scores are carried over unchanged.
Falsifiers:   MP02, MP05 and MP11 re-run through the one runner and the id filter; all three CAUGHT and
              reverted; `git status --short` was empty immediately after the set, and a later repeat run
              showed only this report and the LOG line, with no mutated source.
Guest hash:   not rebuilt (docs only; no guest source changed); no hash is claimed here.
Import list:  unchanged (no code change).
Rule:         a point counts only if a named merged test proves it and a listed falsifier makes that test
              fail. The re-run is one mutation alone, every named test must run and fail, then the original
              is restored by the runner's hard link. Row 10 is re-scored here; every other row keeps its
              grade-rescore-2.md score. This report supersedes grade-rescore-2.md for row 10 only.
Kind labels:  each proof row names its kind - behaviour (drives the fake engine or scheduler and observes
              what happens) or argv / source construction (asserts the launched argument vector or source
              text, not engine behaviour).
Scale:        0 absent, 1 sketched, 3 real but incomplete, 5 production.
Result:       46 of 70 (was 45). Target 62. DeepSeek Harness 46.
Checklist:    56 of 63 (no status moves; docs only).
Principles:   docs, code and tests agree: row 10 names its merged tests, each proof's kind and a re-run
              falsifier.
DeepSeek:     none (the DeepSeek column is the 12 Oct canvas, unchanged).
Not proven:   row 10's cache-off guarantee is argv-level, not an observed engine behaviour; this report does
              not make an engine-behaviour cache proof. Every other row is carried over from
              grade-rescore-2.md with its old score.
Answers:      none.
Questions:    none.
```

## Rows

Old is the row 10 score in grade-rescore-2.md (45 of 70). A row moves only with its named tests and one
listed falsifier re-run per proof for this report.

| Row | Old | New | Point: named test (kind; re-run falsifier) | Gap to the HANDOFF target | Needs |
| --- | --- | --- | --- | --- | --- |
| 10 Local model ops | 4 | **5** | idle release `local_llama::tests::idle_engine_is_released_and_next_request_restarts_it` (**behaviour**; MP02); input-token refusal `execution::tests::local_llama_refuses_input_and_output_that_reach_the_context_window` with its under-window pair (**behaviour**; MP05); cache-off `local_llama::tests::engine_argument_vector_is_exact` (**argv / source construction**; MP11) | Target 5 met: the idle release and the context-window refusal are observed behaviour; the cache-off guarantee is proven at argv level only | none to 5; an engine-behaviour cache proof needs a real llama.cpp run with `--cache-ram 0` against a nonzero value (Mac, real model) |

Carried over unchanged from grade-rescore-2.md: rows 1 (3), 2 (4), 3 (2), 4 (4), 5 (4), 6 (4), 7 (3), 8 (3),
9 (3), 11 (3), 12 (4), 13 (3) and 14 (1). Their tests and falsifiers stay as recorded there; the 25 Oct gains
for rows 4, 8 and 13 keep their scores.

**Total: 46 of 70** = 45 + 1 (row 10). Target 62, so 16 to go. DeepSeek Harness 46.

### Row 10 Local model ops: 4 -> 5

The grade-rescore-2 gap was "Behaviour tests for the idle release and the `input_tokens` refusal, replacing
the source-text pins." Tasks 002, 003 and 008 merged, and the two named behaviour proofs now exist:

- **Idle release (behaviour).** `local_llama::tests::idle_engine_is_released_and_next_request_restarts_it`
  (`capsules/model-provider/src/local_llama.rs:1316`) drives the scheduler itself. It begins a run, arms the
  release with a 50 ms delay, sleeps 200 ms and observes that the engine process still exists and answers
  while the run is active; it then drops the run, waits for the engine artifacts to be released, observes
  the first process gone, starts a new run and observes `start:` twice with an answering endpoint. The
  60-second production delay is `IDLE_RELEASE_DELAY` (`local_llama.rs:26`) and the release is armed by
  `Drop for LocalRun` (`local_llama.rs:138`). MP02 makes the drop arm nothing and the test fails.
- **Input-token refusal (behaviour).** The boundary pair merged in PR #61 (merge `fa047f786`; branch commit
  `41f29dda9`) drives the fake engine through the coordinator and counts the engine's own events:
  `execution::tests::local_llama_refuses_input_and_output_that_reach_the_context_window`
  (`capsules/model-provider/src/execution.rs:3456`) proves 224 counted + 32 max = 256 is refused with
  `context_rejected` / "model context is full" and zero chat requests; the under-window pair
  `execution::tests::local_llama_generates_when_input_and_output_stay_under_the_context_window`
  (`execution.rs:3499`) proves 223 + 32 = 255 completes with exactly one chat request. The threshold is in
  `adapters.rs:1943` and the reason text at `adapters.rs:1946`. MP05 turns `>=` into `>`, so the exact window
  runs, and the refusal test fails.
- **Cache off (argv / source construction).** `local_llama::tests::engine_argument_vector_is_exact`
  (`local_llama.rs:1352`) asserts the whole vector returned by `engine_arguments_with_cpu_budget`
  (`local_llama.rs:603`), including `--cache-ram` `0` (`local_llama.rs:639`). The test never launches an
  engine: it proves the argument vector the provider constructs, not what llama.cpp does with a cache at run
  time. The cache-off guarantee is therefore an **argv-level** proof (P11), and this report does not call it
  an engine behaviour test. MP11 replaces `0` with `512` and the test fails.

The source-text pin that stays: `local_model_cache_and_idle_release_stay_as_they_are`
(`examples/agent-host/src/lib.rs:10883`) reads `local_llama.rs` and `adapters.rs` text, including the
`--cache-ram` value and the `/input_tokens` count route. It is kept unchanged; it is a cheap guard of the
constants it names, and the merged behaviour proofs above carry the row. This report cites it and does not
delete or edit it.

Row 10 moves because the idle release and the input-token refusal are each carried by a named merged
behaviour test whose listed falsifier makes it fail. The cache-off proof is listed with its true kind, so the
point does not rest on a stronger claim than the test makes.

## Proof kinds

| Kind | What the test observes | Proofs in row 10 |
| --- | --- | --- |
| behaviour | the fake engine, the scheduler or the coordinator: process liveness, engine events, chat requests, terminal status | idle release; input-token refusal |
| argv / source construction | the argument vector the provider builds, or source text; no engine is launched | cache-off `--cache-ram 0` |

The cache-off guarantee is argv-level, not an engine behaviour test (P11). A stronger proof would run a real
engine twice, with `--cache-ram 0` and with a nonzero value, and observe that a cached prompt does not enlarge
what admission measured. That run is not made here and is not claimed.

## Falsifier reruns at 0cfbbee27

One mutation at a time, selected by id through the one runner:

```text
python3 -I examples/agent-host/falsify.py --from capsules/model-provider/falsifiers.json MP02 MP05 MP11
MP02   CAUGHT   22s  a finished run never arms the idle release
MP05   CAUGHT    5s  the context check refuses only past the window, so the exact window runs
MP11   CAUGHT    4s  the engine launches with a nonzero cache size, so a cached prompt enlarges what admission measured
summary: 3 CAUGHT of 3
```

The id filter selects exactly those three entries, so the run touched neither the `selftest` entries that
mutate `falsify.py` nor the other MP entries. `git status --short` was empty immediately after the set (it
happened before this report and its LOG line existed); a repeat run after the docs showed only those two
files, with no mutated source.

| Id | Proof | Mutation | Failed test | Result |
| --- | --- | --- | --- | --- |
| MP02 | idle release (behaviour) | `Drop for LocalRun` no longer arms the idle release | `local_llama::tests::idle_engine_is_released_and_next_request_restarts_it` | CAUGHT, reverted |
| MP05 | input-token refusal (behaviour) | the context check refuses only past the window (`>=` becomes `>`) | `execution::tests::local_llama_refuses_input_and_output_that_reach_the_context_window` | CAUGHT, reverted |
| MP11 | cache-off (argv / source construction) | the launched `--cache-ram` value changes from `0` to `512` | `local_llama::tests::engine_argument_vector_is_exact` | CAUGHT, reverted |

Summary of the targeted run: 3 CAUGHT of 3.

## HANDOFF grade-line change (applied by the owner at merge)

`examples/agent-host/handoff/HANDOFF.md` is outside this lane's allowed paths. The one line the new total
needs is:

```text
old: Current proven total after tasks 005 to 018: **45 of 70** (`reports/grade-rescore-2.md`, 25 Oct).
new: Current proven total after tasks 005 to 018 plus 009: **46 of 70** (`reports/grade-rescore-3.md`, 25 Oct).
```

The historical bullet for the 005-to-018 re-score stays as it is.

## Remaining headroom

Row 10 now meets its target of 5 and is not listed. Rows 4 and 8 also meet their targets. Every row still
under its target, the smallest next piece, and who it needs:

| Row | Now / target | Smallest next piece | Needs |
| --- | --- | --- | --- |
| 1 Agent loop | 3 / 5 | One model call per turn under a Runtime grant with a budget; the loop is still one-shot. | Runtime (model grant, RUNTIME-BUDGET.md), Anders |
| 2 Session log | 4 / 5 | A per-principal `UsersAI` root and the real shell policy; the e2e test still plays the shell. | Runtime (Anders), Home |
| 3 Prefix cache | 2 / 4 | Wire `packStablePrefix` into the live Assistant (`compileLiveContext`), then measure one cache hit with `--cache-ram` above 0. | Home (Assistant, slice SA), Sasha's yes; Runtime (model provider admission) |
| 5 Tool system | 4 / 5 | Read, edit and run through `providers.invoke` with Runtime grants; only the journal does today. | Runtime (read and edit providers), Anders |
| 6 Edit reliability | 4 / 5 | One write through the object provider. | Runtime (EDIT-PROVIDER.md, after 0.8.0), Anders |
| 7 Shell and tests | 3 / 4 | Put `cargo` in the exec image and run one test in the VM. | Mac (image); no Runtime change |
| 9 Skills | 3 / 4 | Child limits (#31): a child as a separate instance with its own limits. | Claude Code (#31) and Runtime/Anders (Bus v2); not this lane |
| 11 Hosted and secrets | 3 / 5 | One real hosted run with a grant budget. | Runtime (hosted provider), Anders |
| 12 Capability model | 4 / 5 | Exercise `home-auto.json` for the agent and record the cross-family review. | Home, Runtime (Anders), Sasha |
| 13 Create an app | 3 / 4 | A build or run provider for the scaffolded project, then the Home app surface. | Runtime (provider), Home |
| 14 Package and sell | 1 / 4 | A second Home and a revocation check; photo PRs on spike/photo-viewer do not count. | Anders |

The remaining gaps sum to 16 points. The cache-off engine-behaviour proof named above is a Mac task with a
real model, not a point on the grade.

## Checklist (56 of 63)

No status moves; this slice changes no product behaviour, so no checklist item changes. The seven open items
and their owners are unchanged from grade-rescore-2.md.

## Tests run

All on this Mac at 0cfbbee27 with `RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0`; this report changes docs only, so
the committed head has the same code and counts.

```text
cargo fmt --manifest-path capsules/model-provider/Cargo.toml -- --check
  -> FMT OK
cargo test --locked --manifest-path capsules/model-provider/Cargo.toml
  -> lib: 299 passed; 0 failed; 2 ignored
  -> tests/process.rs: 8 passed; 0 failed
python3 -I examples/agent-host/falsify.py --self-test
  -> self-test: OK
python3 -I examples/agent-host/falsify.py --from capsules/model-provider/falsifiers.json MP02 MP05 MP11
  -> summary: 3 CAUGHT of 3
git status --short
  -> empty
python3 -I examples/agent-host/falsify.py --list capsules/model-provider/falsifiers.json
  -> 91 entries from the default examples/agent-host/falsifiers.json (list mode takes its path from --from)
python3 -I examples/agent-host/falsify.py --from capsules/model-provider/falsifiers.json --list
  -> 57 entries: 41 selftest, 16 provider
```

The two ignored provider tests are opt-in and need a real model service, as merged. `git diff --quiet
"$BASE_SHA" -- examples/agent-host/falsify.py` exited 0, so the runner is unchanged by this slice.

## Principles

1. **Named by hash:** yes. No new code; this report cites tests and source by path and line, and makes no
   new name or URL identity claim.
2. **No ambient authority:** yes. No code change; the provider tests run against the fake engine, and the
   cache-off proof asserts arguments only (`local_llama.rs:603`).
3. **One path (P10):** yes. The report names the one runner
   (`examples/agent-host/falsify.py`) and the one context threshold (`adapters.rs:1943`); no second route or
   second copy of a rule is added.
4. **Trusted core:** yes. Docs only; no Runtime, provider or capsule code changed.
5. **Fails closed (P11):** yes. The context refusal is denied by default at the window with
   `context_rejected` / "model context is full" (`adapters.rs:1943`, `adapters.rs:1946`), and the cache-off
   proof is labelled argv-level instead of claiming unobserved engine behaviour.
6. **Self-contained (Rong):** yes. No code change; the provider keeps its model loop, admission and argument
   construction inside its own crate.
7. **Tests prove it:** yes. Each of the three row-10 proofs names a merged test and a re-run falsifier that
   made it fail: MP02, MP05 and MP11, 3 CAUGHT of 3.

## What is next

The next planner cycle starts at 46 of 70. No graded row gained here is still in-lane; row 10 now meets its
target. Remaining gains need the Runtime, Home, Anders, Sasha, the Mac, or Claude Code's #31.
