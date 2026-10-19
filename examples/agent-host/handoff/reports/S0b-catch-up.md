# S0b catch-up

```text
Slice:        S0b catch-up (reading only, no code change)
Branch / PR:  claude/s0b-catch-up  https://github.com/SashaMIT/elastos-agent-host-spike/pull/2
Commit:       b367f1dcc23b619f2fb3db3de3806059874b7ec4   parent c2e1a7aab583450ae7f7e653b2b5bd11f6aa6301
              (this PR link and SHA were filled in by the next commit on the branch)
Base:         origin/spike/agent-host 043e5a6577a6117c2edd5a288650e4648c657ec4. PR #1 (S0, review PASS) was
              still open and not merged when this session started, so this branch merges it first
              (c2e1a7a, a merge commit, no rebase). If PR #1 merges first, this PR still merges cleanly.
Develop:      Elacity develop 3beb816438fd567145a8d725e22465bd83277cf0, already merged (d465df3bc), behind 0.
Machine:      Linux 6.18.44 x86_64 (cloud container), rustc 1.91.0 (f8297e351 2025-10-28),
              cargo 1.91.0 (ea2d97820 2025-10-10), Python 3.13.16, Node 22.22.0. No /dev/kvm.
Changed:      examples/agent-host/handoff/reports/S0b-catch-up.md - this report
              examples/agent-host/handoff/LOG.md - one line for S0b
              (from the S0 merge: SLICES.md, reports/S0-baseline.md, the LOG.md S0 line - already reviewed PASS)
Invariant:    No code changes. Each row grade below counts only what a named test proves, and I broke each
              cited rule on purpose and saw that test fail.
Refusals:     None new.
Tests run:    export RUST_TEST_THREADS=2
              ./examples/agent-host/verify.sh -> "test result: ok. 72 passed; 0 failed", 0 warnings, "agent-host capsule verification: OK"
              ./examples/agent-host/run-local.sh -> "agent_host_example_keeps_the_head_across_a_compaction ... ok"
              (cd elastos && cargo test -p elastos-compute --lib -- --include-ignored) -> "test result: ok. 16 passed; 0 failed"
              cargo test --manifest-path capsules/model-provider/Cargo.toml local_memory -> "test result: ok. 7 passed; 0 failed"
              node --test scripts/home-agent-prefix.test.mjs -> "# tests 2 # pass 2 # fail 0"
              node scripts/home-agent-shell-smoke.mjs -> "canonical Assistant shell smoke: ok"
              python3 examples/agent-host/handoff/tools/wasm_sections.py examples/agent-host/agent-host.component.wasm -> below
Not run here: home-version-list-smoke.mjs (Playwright 1.59.1 wants Chromium build 1217, this machine has 1194; same as S0).
              Exec micro-VM boots and elastos-vz tests (Mac only; exec_smoke_image_prints_hello skips off an Apple Silicon Mac).
Falsifiers:   22 mutations, one at a time, each undone with git checkout; tree clean after each.
              21 are listed in "Spike grade today"; the prompt-packer one is in "History check".
              Four mutations failed no test. That is a finding, not a pass (see "Test gaps").
              Guest hash: changing only the host units' profile changes the wasm (see "Guest hash").
Guest hash:   e34772d1a03a24327eea7626ba4928e19dfb13d214d14c2b70a42d698bc489a1 on two builds (verify.sh, run-local.sh).
              Same as the S0 Linux reference. wasm_sections.py output is below.
Import list:  unchanged (elastos:bus/identity@1.0.0, runtime@1.0.0, types@1.0.0)
Principles:   12 Docs, code, tests agree: the history check and the grade table compare the record with the
                 code. Four rules in the code are not pinned by a test (Test gaps).
              15 Trust travels with signed content: the guest bytes depend on the build machine type
                 (Cargo, cited below). A rebuild matches a signed capsule only on the same machine type.
              3, 11, 18: unchanged, because no code changed; the import list was checked again.
DeepSeek:     deepseek-ai/deepseek-harness 5cf7ac9c (read) and 687f282e (latest; still master on 19 Oct).
              No code copied. The files read are named in "DeepSeek since 12 Oct".
Not proven:   That the `host:` line is the only input that differs between the Mac and Linux builds.
              Rows 7, 8, 13: the Mac boots and the screens Sasha saw are not re-run here, so they do not count.
Checklist:    56 of 63 (no todo moved; S0b is reading only)
Questions:    1. Spike grade today is 37 of 70, not "about 43". OK to use 37 as the baseline?
              2. Four test gaps (below). Add the missing tests as a small slice before S1, or fold them into S2?
              3. PR #1 is still open. Merge it first, or merge this PR (it already contains S0)?
              4. One history mismatch: the prompt packer is tested but not on the live Assistant path.
                 Reword the 13 Oct 20:30 entry, the todo prefix-phase-a-pack and HANDOFF section 6,
                 or wire the packer in? Wiring it in edits the shipping Assistant, so it is not for the cloud without your yes.
```

## DeepSeek since 12 Oct

Clone at `/tmp/.../deepseek-harness` (outside this repo). `master` is still `687f282e` on 19 Oct (0 newer commits).

`git diff --stat 5cf7ac9c 687f282e -- docs packages/core/session packages/core/agent-loop packages/fs SAFETY.md` reports 148 files, +16,867 / -2,272. Most of that is translated docs, upgrade guides, and regenerated schema catalogs. Real code changes in those paths:

- `packages/core/session`: 3 source files, a `resource: 'session'` type tag only.
- `packages/session/session-persistence-jsonl/src/index.ts`: one commit, `6aa157a05a` "bound listing reads with a shared concurrency limit" (`listConcurrency`, default 3). No change to the format version, the JSONL generations, or zstd.
- `packages/fs/tool-fs/src/index.ts`: switches to turn `read`, `write`, `edit`, `readImage` on or off.
- Every other package in those paths: the version number in `package.json` only.

Unchanged byte for byte (I checked with `git diff --shortstat`): `docs/architecture.md`, `docs/subsystems/compaction.md`, `docs/subsystems/core.md`, `docs/tool-execution-pipeline.md`, `packages/core/agent-loop/src/runtime-context.ts`, `SAFETY.md`, `packages/fs/tool-str-replace-editor/src`. `fs-observation-policy` changed only its `package.json` version.

Per pattern we copy:

| Pattern | Changed? | What (file:line at 687f282e) |
| --- | --- | --- |
| Journal is the only model context | No, in substance | User RPC messages gain an optional `source.principal` field that is logged but is "not part of any model request"; "SESSION_FORMAT_VERSION does not change" (`docs/persistence-changes/2026-10-13-user-rpc-principal.md:50`). Logged does not mean model-visible. |
| Replay to the same bytes | Small change, at the wire | The DeepSeek serializer now drops empty assistant text, and drops an assistant message left empty (`packages/llm/llm-deepseek/src/serialize.ts:30`, `:123`). Same log, different request bytes after an upgrade. Their tests: `serialize.spec.ts:26` "omits saved empty assistant text without changing tool ids or thinking signatures", `:48` "does not flush a system update at an omitted empty assistant message". |
| Node 0 and the series | No | Team identity goes into the runtime context, not the system prompt, so the inherited prefix is not rewritten (helper read `.agents/notes/implemented/architecture/2026-10-13-team-identity-runtime-context.md`; not re-checked by me). |
| Compaction | No | Compaction packages are unchanged. Only image offload changed one line: it no longer writes its repair after cancel. |
| Tool pipeline | No | Pipeline doc and approval and guard packages unchanged. |
| Observations | No | Still in memory only: `packages/fs/fs-observation-policy/src/index.ts:28` `private observed = new WeakMap<...>()`. It is still lost on resume. New test `packages/fs/tool-fs/tests/integration.spec.ts:74` "without read, creates and edits a new file while protecting unobserved existing files". |

Suggestions for `SLICES.md` (Sasha decides; nothing changed here):

- S2: keep "model-visible" a field-level decision in the format, and hash the whole record anyway. Their new principal field is logged but not sent.
- S4: the prefix cache key should include the serializer (projection) version. Copy their falsifier: a log with an empty assistant text gives the same bytes before and after a change. Our `model_bytes` keeps empty assistant lines and `derive` drops them; this is tested by `an_empty_assistant_stays_in_the_log_and_drops_out_of_the_view` (mutation R2 broke it).
- S3 or S4: a resume keeps the series only when the rebuilt head bytes are equal. Their system can change the head on a cold resume of a child. Test it, do not assume it.
- Row 6: add their "read disabled" case: hiding the read tool must not let a write reach an unobserved file.

## History check

I read all 144 entries in `HISTORY.md`. A helper agent in this session also went through every entry against the code. I re-checked each finding below myself before writing it here. Guest hashes and test counts in the history are point-in-time and were not re-proven.

### Mismatch: one

**13 Oct 20:30, "The model prompt is now the system line, then notes, then excerpts."** That is true of `packStablePrefix` (`capsules/assistant/browser/agent-context.js:956`), but nothing on the live path calls it. The only caller is `scripts/home-agent-prefix.test.mjs`. The live prompt is built by `compileLiveContext` (`capsules/assistant/browser/agent-live.js:381-423`). It puts the system line first, then the notes as a second **system** message (`role: "system"`, line 412), then history. It has no retrieved excerpts in that function. The head still comes first in the live path, but no test covers that order.

Falsifier: I removed the head from `packStablePrefix`. `home-agent-prefix.test.mjs` failed (1 pass, 1 fail). `home-agent-shell-smoke.mjs` ("ok") and `home-agent-cancellation.test.mjs` (50 pass) still passed. So the packer is not on the path those tests cover. Reverted, 2 of 2 pass.

This also touches the todo `prefix-phase-a-pack` (completed) and HANDOFF section 6 ("Phase A packing is already in the spike"). I did not change either; see Question 4.

### Claims checked and still true

| History claim | Today | Proof today |
| --- | --- | --- |
| Live prompt says "You have no tools and no capsule authority in this session" (12 Oct 21:02) | holds | `capsules/assistant/browser/agent-live.js:57`; `node scripts/home-agent-shell-smoke.mjs` -> ok |
| Import list is identity, runtime, types (12 Oct 20:57) | holds | `component.rs:643-656`; S0 falsifier 2 |
| No-grant component invoke is Denied before the bridge (12 Oct 21:10) | holds | `provider_invoke_without_a_grant_is_denied_before_the_bridge`; R12 |
| `--cache-ram` 0, idle release 60 s, `input_tokens` refuse (12 Oct 21:55) | holds | `local_llama.rs:639-640, 1379-1380`; `local_model_cache_and_idle_release_stay_as_they_are`; R10 |
| Capsule admission hashes the entrypoint file only (12 Oct 22:00) | holds | `elastos-server/src/runtime.rs:389` "hash the entrypoint file" |
| cargo is refused, not in the image (12 Oct 23:58) | holds | `exec_vm.rs:189`; S0 falsifier 3 |
| Tool result longer than 80 bytes is cut before a summary (13 Oct 20:40) | holds | `lib.rs:635-642`; `a_large_tool_result_is_shortened_before_a_summary` |
| Repeated prompt line is counted in admission (13 Oct 20:35) | holds | `local_memory.rs:322`; `admission_counts_a_repeated_prefix`; R10b |
| Guest loaded twice with different ids (14 Oct 18:05) | holds, partly | `component.rs:669-689` asserts the ids differ and both runs pass. "Each start builds its own store" is not asserted. |
| Mac guest hash fe9bcaa4 (14 Oct 17:55) | holds | Same as the HANDOFF Mac reference. |

Other constants named in the history still hold: the 4000-byte budgets (`lib.rs:493`, `exec_vm.rs:80`) and the 60 s idle release (`local_llama.rs:26`).

Weaker than the history says (true in code, but the test does not prove the words):

- 13 Oct 20:35 "a different first line counts as zero": `admission_counts_a_repeated_prefix` tests the addition only. Nothing feeds it a real `cached_tokens` count.
- 13 Oct 20:15 "the log is not uploaded": the guest test only checks that no event text contains "upload" (`lib.rs:6125`).
- The 60 s idle release and "admission hashes the entrypoint" are locked by checking source text, not by behaviour.

Superseded or renamed, not a mismatch:

- `agent_host_example_runs_one_turn_in_wasmtime` and `agent_host_example_runs_two_turns_in_wasmtime` (12 Oct 17:40, 17:55) no longer exist. The single ignored test is now `agent_host_example_keeps_the_head_across_a_compaction`.
- Summary role `System` (12 Oct 18:05 to 20:53) was replaced on purpose by a user checkpoint (12 Oct 21:30); `compaction_summary_is_a_user_checkpoint`.
- Snapshots "replaced" by compaction (12 Oct 20:53) became "kept" (13 Oct 03:15). The unknown-source tag moved from 9 to 10 (12 Oct 21:30). A later write that waited (12 Oct 21:42) no longer waits behind a denied write (13 Oct 02:20).
- Exec test counts (three, five, nine) grew to ten today.

Proven only by hand or on the Mac (no automated test runs here):

- The micro-VM boots (12 Oct 22:50 to 13 Oct 01:00): `elastos-vz/tests/concurrent_launch.rs:766` `exec_smoke_image_prints_hello`, which skips unless it runs on an Apple Silicon Mac with `ELASTOS_EXEC_KERNEL` set.
- Versions on the open Home, Demo in Apps, Approval on Home (13 Oct 19:42 to 20:16): Sasha saw them. `home-version-list-smoke.mjs` covers the Versions screen on a fixture port, not run here.
- Qwen's summary sentence and the tiny model prefix reuse (14 Oct): one-time runs. The guest stores the fixed sentence (`a_model_sentence_shortens_the_log_and_replays`); no model runs in a test.

Oddities in the record:

- The 13 Oct entries from 11:30 to 12:00 appear twice with different content (HISTORY lines 426-452, then 454-484). The second set is probably 12:30 to 13:00. Also, "15:45" (line 542) comes before "15:35" (line 546).
- Line 5 (a list of Anders' PRs) is not spike work. The 13 Oct 14:30 entry records a push to an Elacity phone-layout branch with the pre-push hook off. That was before today's rules and was not spike work, but today it would break CLAUDE.md rule 1.
- Wording: `lib.rs:15` says a skill "under 4000 bytes", but the code and test allow exactly 4000. 13 Oct 20:40 says "80 characters"; the code counts bytes.

### Seen while checking, not spike code

`cargo test --manifest-path capsules/model-provider/Cargo.toml --test process` fails 2 of 8 here: `normal_provider_shutdown_reaps_local_llama_engine` (`tests/process.rs:366`) and `managed_streaming_stop_reaps_engine_and_activates_different_model_without_restart` (`:452`). The same two fail on plain Elacity develop `3beb816` in a separate worktree in this container. So the spike did not cause them, and they are not in the section 10 list. Probably this container (process reaping), not proven.

## Spike grade today

The rule: a grade counts only what a named automated test proves on this branch, and I must have broken the rule on purpose and seen that test fail. "Rn" is a mutation from the list below. Scale as in HANDOFF section 1.

| Row | 12 Oct ElastOS | Spike proven | Tests that prove it (mutation that broke it) | Not proven |
| --- | --- | --- | --- | --- |
| 1 Agent loop | 1 | 3 | `a_crash_after_dispatch_is_settlement_unknown` (R1a), `cancel_before_dispatch_never_dispatches` (R1b), `open_turn_returns_a_turn_id_and_leaves_the_epoch` | No model call in the loop; one-shot lifecycle; task state is not Runtime-owned |
| 2 Session log | 2 | 3 | `a_recorded_journal_replays_to_the_same_bytes`, `assistant_and_tool_result_tags_replay_together` (R2) | No durable store, no format version, no tamper refusal (S2, S3) |
| 3 Prefix cache | 1 | 2 | `an_incapable_prompt_rewrites_the_head_and_starts_a_series`, `the_same_head_text_does_not_start_a_new_series` (R3); `admission_counts_a_repeated_prefix` (R10b) | No cache hit measured; `--cache-ram` is 0 (S4); the live Assistant does not use `packStablePrefix` (History check) |
| 4 Compaction | 2 | 3 | `compaction_refuses_a_summary_that_does_not_shrink` (R4), `compaction_keeps_node_zero_and_starts_a_new_series`, `a_crash_during_compaction_restores_the_saved_bytes` (R3) | The model does not write the summary (S5) |
| 5 Tool system | 0 | 3 | `provider_invoke_without_a_grant_is_denied_before_the_bridge` (R12), `a_tool_result_enters_the_view_and_a_step_without_one_stays_in_the_log`, `a_hosted_proposal_has_no_secret_and_a_missing_grant_is_denied` (R11b) | The guest never calls `providers.invoke`; `fixture-grant` is a test token; gap G1 |
| 6 Edit reliability | 0 | 3 | `an_unread_or_stale_edit_creates_no_step` (R6a), `an_edit_requires_the_old_text_once_and_replay_keeps_the_observation` (R6b), `a_second_write_stays_prepared_until_the_first_has_a_result` (R6c) | No write through the object provider (phase C) |
| 7 Shell and tests | 0 | 2 | `a_rust_test_result_keeps_its_exit_code` (R7), `cargo_is_not_in_the_image_and_an_unknown_command_does_not_launch` (S0 falsifier 3) | The boot is Mac only and not run here; cargo is not in the image |
| 8 Git and undo | 0 | 2 | `a_restore_proposes_an_observed_version_and_does_not_apply_it` (R8) | Restore is never applied; Home screen is manual |
| 9 Skills | 0 | 3 | `an_over_budget_skill_leaves_the_journal_unchanged` (S0 falsifier 1), `compaction_keeps_a_skill_node` (R3), `a_child_grant_is_narrower_and_does_not_inherit_the_parent_grant` (R9a) | A child is not a separate instance; gap G2 |
| 10 Local model ops | 5 | 4 | `admission_counts_a_repeated_prefix` (R10b), `local_model_cache_and_idle_release_stay_as_they_are` (R10a) | The idle release and `input_tokens` refuse are locked by source text, not by a behaviour test here |
| 11 Hosted and secrets | 4 | 3 | `a_hosted_proposal_has_no_secret_and_a_missing_grant_is_denied`, `a_goal_survives_shortening_and_does_not_grant` (R11b) | No hosted run; gap G3 |
| 12 Capability model | 4 | 4 | Wasmtime import list (S0 falsifier 2), `provider_invoke_without_a_grant_is_denied_before_the_bridge` (R12) | No Runtime grant is issued to the guest; no adversarial review yet (`hold-adversarial`) |
| 13 Create an app | 1 | 2 | `a_non_entrypoint_change_changes_the_project_tree_hash` (R13) | No in-Home scaffold write; Demo in Apps is manual |
| 14 Package and sell | 2 | 0 | none in the spike | The team test `installed_release_refuses_unsigned_and_foreign_signed_local_capsules` (`elastos-server/src/runtime.rs:722`) exists; S1 cites and falsifies it. Admission still hashes the entrypoint only. |

**Total: 37 of 70.** The 13 Oct "about 43" had no breakdown. Row 14 is 0 because the spike has not proven it yet, not because the product lost it. Row 10 is 4 because the spike only locks the provider, and two of its three rules are locked by source text.

### Mutations (each on its own, undone by `git checkout`, full suite each time)

| Id | What I broke | Tests that failed |
| --- | --- | --- |
| R1a | `note_crash`: after dispatch becomes `NotStarted` | 6, incl. `a_crash_after_dispatch_is_settlement_unknown` |
| R1b | `cancel`: Prepared stays Prepared | 7, incl. `cancel_before_dispatch_never_dispatches` |
| R2 | `replay`: tag 3 read as User | `assistant_and_tool_result_tags_replay_together`, `an_empty_assistant_stays_in_the_log_and_drops_out_of_the_view` |
| R3 | `bump_epoch` does nothing | 8, incl. `an_incapable_prompt_rewrites_the_head_and_starts_a_series`, `compaction_keeps_node_zero_and_starts_a_new_series` |
| R4 | `begin_compact`: shrink check off | `compaction_refuses_a_summary_that_does_not_shrink` (+1) |
| R5 | `dispatch`: missing grant ignored | only `the_same_command_waits_until_the_first_has_a_result` (gap G1) |
| R6a | `propose_edit`: any seen version accepted | `an_unread_or_stale_edit_creates_no_step`, `a_later_note_read_uses_the_rewritten_sentence` |
| R6b | `propose_edit`: old text may occur twice | `an_edit_requires_the_old_text_once_and_replay_keeps_the_observation` |
| R6c | `dispatch`: open earlier write ignored | `a_second_write_stays_prepared_until_the_first_has_a_result` (+1) |
| R7 | `exit_agrees_with_log` always true | `a_rust_test_result_keeps_its_exit_code` |
| R8 | `propose_restore`: version not current accepted | `a_restore_proposes_an_observed_version_and_does_not_apply_it` (+1) |
| R9a | `grant_child_host`: parent grant accepted | `a_child_grant_is_narrower_and_does_not_inherit_the_parent_grant` |
| R9b | `narrower_resource`: `rest.starts_with('/')` removed | **none** (gap G2) |
| R9c | `narrower_resource`: `rest.len() > 1` removed | **none** (gap G2) |
| R9 | `narrower_resource`: both removed | **none** (gap G2) |
| R10a | `IDLE_RELEASE_DELAY` 60 -> 61 s | `local_model_cache_and_idle_release_stay_as_they_are` |
| R10b | `counted_input_tokens` drops the cached prefix | `admission_counts_a_repeated_prefix` |
| R11 | `propose_hosted`: `localhost://` prefix check removed | **none** (gap G3) |
| R11b | allow-once mints a grant when none was sent | `a_hosted_proposal_has_no_secret_and_a_missing_grant_is_denied`, `a_goal_survives_shortening_and_does_not_grant` |
| R12 | component `invoke`: empty grant accepted | `provider_invoke_without_a_grant_is_denied_before_the_bridge` |
| R13 | `project_tree_hash` ignores file text | 10, incl. `a_non_entrypoint_change_changes_the_project_tree_hash` |

### Test gaps

These rules are in the guest code, and the code is right today. But no test fails when they are removed. All are in the spike guest (`examples/agent-host/src/lib.rs`), not in shipping ElastOS code, so they are not security findings. S0b changes no code; these are suggestions.

- **G1** `dispatch` refuses a Prepared step with no grant (`lib.rs:1813`). The short tests always call `authorize` first, and that already sets Denied. Suggested test: propose, then `dispatch` with no `authorize`, expect false and Denied.
- **G2** `narrower_resource` refuses `…/Projects/demo2` under `…/Projects/demo` (a shared prefix), and refuses `…/Projects/demo/` (`lib.rs:1590`). The test only tries `…/Projects/other`. Suggested test: both cases, expect no child step. This is the child-grant boundary, so it matters.
- **G3** `propose_hosted` refuses a resource that is not `localhost://`, for example `https://api.example.com/v1/model` (`lib.rs:1503`). The test only tries `/tmp/model`, which `host_path` refuses anyway. Suggested test: an `https://` resource, expect `Err("host path")` and no step.

## Guest hash

Two builds on this machine, both `e34772d1a03a24327eea7626ba4928e19dfb13d214d14c2b70a42d698bc489a1`.

`python3 examples/agent-host/handoff/tools/wasm_sections.py examples/agent-host/agent-host.component.wasm`:

```text
file e34772d1a03a24327eea7626ba4928e19dfb13d214d14c2b70a42d698bc489a1 259928 bytes
/7                                    201 37a0f0d849fc0081
/10                                    28 ad847dfd026c7cf4
/6                                     17 79843aba75ee5a6e
/7                                     40 0bb24decd3bc5073
/10                                    30 ad1133871d497437
/6                                     21 7fe42a6dff44ef11
/7                                     47 c310b353ccf5e494
/10                                    31 6eec1d20524617f5
/1                                 257495 5e6f71b301707041 nested
/1/1                                  237 c22fdbac81cc8f06
/1/2                                   71 01205c965ffff66e
/1/3                                  461 ead371d08c165519
/1/4                                    5 11c32ac348de9f2d
/1/5                                    3 f0b84402ff5181a6
/1/6                                   25 7eb149dd7ac9f38d
/1/7                                  168 dd82532349808124
/1/9                                   70 6f6e7ad8e6cadd2a
/1/10                              201840 7de05070202bdf50
/1/11                               17857 5defeb3eec7cdb85
/1/0:name                           36443 4c43945b8b10708a left out
/1/0:producers                        123 24ae0100e8d09334
/1/0:target_features                  148 97ceea95e0687b14
/1                                    121 614f645a62418111 nested
/1/1                                    5 1b0181aa765f15b4
/1/3                                    3 070b13c004e9475f
/1/4                                    5 b49cd276a7cc0a0b
/1/7                                   20 a2331edbbe809526
/1/10                                  21 f24604d028cde024
/1/0:producers                         47 89d829eab929f8c7
/1                                    102 2765936846b92b7d nested
/1/1                                    5 1b0181aa765f15b4
/1/2                                   26 46deeaf68d39b29c
/1/9                                    8 993ffa2520ab1fda
/1/0:producers                         47 89d829eab929f8c7
/2                                      4 507503b51960cced
/6                                     20 88cccebbe6270989
/2                                     10 ec79f591ce3c7bcf
/6                                      7 6dd030cfe0fe86f9
/2                                     73 2cc3caa09d1d2282
/6                                     50 6b1177525ee39893
/8                                     10 620e54a7bf5db326
/6                                     12 15749c725cd215e6
/8                                     10 7cca3517c3870570
/2                                     28 5f4f2bb7d7eb4dff
/7                                      9 74f77b3c5d6cb1d6
/6                                     83 fe562036431d20a5
/8                                     11 653c112c8d974862
/6                                     14 10d3a74f12dbd278
/4                                    215 e9b4b2563ee2fed6 nested
/4/7                                   75 7f1d229bed857793
/4/10                                  54 ef6ed17611ff2b4f
/4/7                                    9 c0c8afe7d9d8b179
/4/10                                  20 0b03c4f33bc5849f
/4/11                                  15 0aafa66e535b544b
/4/7                                    9 74f77b3c5d6cb1d6
/4/11                                  11 8a17118816f2d04c
/5                                     71 a84eba5f0bcf1db3
/11                                    33 410eaaaad57bd9ff
/0:component-name                    1015 332d00685b5b2a62
/0:producers                           47 89d829eab929f8c7
without-name c831ace8c47a3b2b01a0231f6ba62246e9625e3206df4607fc71edd4ed0d8031
```

The main code section (`/1/10`) is 201,840 bytes, the same size the S0 review measured on the Mac.

### The Cargo line

Rust 1.91.0 ships cargo `ea2d97820` (from `cargo --version`). That is tag `0.92.0` of rust-lang/cargo, commit `ea2d97820c16195b0ca3fadb4319fe512c199a43`. File: `src/cargo/core/compiler/build_runner/compilation_files.rs` at that tag.

- Line 672, in `compute_metadata`: `hash_rustc_version(bcx, &mut shared_hasher, unit);` puts the compiler version into every unit's metadata hash.
- Lines 792-793, in `hash_rustc_version` (stable channel): `for line in bcx.rustc().verbose_version.lines() {` / `if unit.kind.is_host() || !line.starts_with("host: ") {`. The `host:` line of `rustc -vV` is hashed for **host units only**. A comment at lines 787-791 says the host line is left out for cross-compiled units.
- Lines 721-728: `c_metadata` (the symbol-mangling hash, see the comment at line 80) also hashes the `c_metadata` of every dependency (`dep_c_metadata_hashes.hash(&mut c_metadata_hasher);`).

So the `host:` line is **not** put directly into the hash of our guest, because the guest is built for `wasm32-unknown-unknown`, a target unit. It enters **indirectly**. The guest depends on two proc-macros, `wit-bindgen-rust-macro` and `serde_derive` (`cargo tree --target wasm32-unknown-unknown`). Proc-macros are host units, so their hash includes `host: x86_64-unknown-linux-gnu` here and `host: aarch64-apple-darwin` on the Mac. Lines 721-728 then carry that into the `c_metadata` of `wit-bindgen`, then into `agent_host`, then into every mangled symbol (`...17h<hash>E`). That changes the `name` section and the order of functions in the code section.

Falsifier (stable Cargo, no file edited): `CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_OPT_LEVEL` sets the profile of host units only. The profile is part of the hash at line 656. Our guest's own code is a target unit and does not use it.

| Build | File sha256 | `/1/10` code | `name` section |
| --- | --- | --- | --- |
| `...OPT_LEVEL=0` (the default, control) | `e34772d1…` | 201840, `7de05070…` | 36443, `4c43945b…` |
| `...OPT_LEVEL=1` (host units only) | `8882bb73…` | 201840, `912eb0cd…` | 36443, `9e5eeaeb…` |
| default again | `e34772d1…` | | |

The sizes stay the same, but the code bytes and the names change. That is the same pattern the S0 review saw on the Mac with `__CARGO_DEFAULT_LIB_METADATA`. It shows that a change confined to host-unit metadata reaches the guest bytes.

Not proven: that the `host:` line is the only input that differs between the Mac and Linux. I tried a second host toolchain here (`1.91.0-x86_64-unknown-linux-musl`, which changes only the host line). Its `rustc` needs a musl `libgcc_s`, which this container does not have, so I removed it. Other host-only inputs, such as platform-specific dependencies of the proc-macros, could also differ. A check on the Mac: compare `cargo build -v` `-C metadata=` values for `wit-bindgen-rust-macro` on both machines. They should differ, while `-C metadata` for a target-only crate with no proc-macro deps, such as `dlmalloc`, should match.

## What is next

S1 `sell-closed-admission` (cloud, test only), after Sasha merges this PR, unless Sasha wants the three gap tests first (Question 2).
