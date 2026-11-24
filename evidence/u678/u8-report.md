# U8: one agent, one live run

Head of the rule: `d86dcf566236fe7e972a1cffbd7f3fb99226cedd` on `claude/u8-one-run`.

The accepted design is in the code. A second live run of one agent is refused. The old sentence, that distinct grants may start independent sessions for the same agent, is gone from `start_agent_once`.

## The rule, in the five sentences

`docs/AGENT_ARCHITECTURE.md` section "One live run":

1. One agent has one live run.
2. A second Start while that run is live is refused, and the refusal says "this agent is already running".
3. The run ends when the owner stops it, when the guest fails or crashes, when that run is cancelled, or when the Home process starts again, and a later Start can then begin.
4. Retire refuses a later Start because the agent is retired.
5. Two different agents may run at the same time, and two Starts of one agent at the same moment produce one run.

## Where the code does that

`start_agent_once` (`elastos/crates/elastos-server/src/runtime.rs:1318`) holds `agent_launches` for the whole start. The production caller is `launch_capsule` (`elastos/crates/elastos-server/src/api/routes.rs:101`).

The one-use grant is checked first (`runtime.rs:1339`). A second use of the same grant is still "agent launch grant was already used". After that, and before the grant is marked used (`runtime.rs:1351`), the function reads `running_capsules` and refuses when a row for this agent has `ended_at` unset (`runtime.rs:1346` and `agent_has_live_row` at `runtime.rs:1436`). The read waits for the registry. A refused grant is not marked used.

The sentence is the constant `AGENT_ALREADY_RUNNING` (`runtime.rs:1387`): "this agent is already running". `launch_capsule` maps that sentence to HTTP 409 (`routes.rs:233`). The gateway maps that exact sentence to JSON `code` `agent_already_running` and `reason` "this agent is already running" (`gateway_home_runtime.rs:697`). Any other 409 stays a plain refusal. A non-success that is not 409 would be a 500, and the page retries a 500. This 409 is not retried (`agents-section.js` `retryable`, status 409).

The page treats `agent_already_running` as the state Running, disables Start, and shows the sentence (`agents-section.js:74`, `:88`, `:203`). Stopping still wins when both are set. A reload clears Running, because `load` clears the set and the agent list has no session.

A row ends when `ended_at` is set (`runtime.rs:659`) and the session record is then dropped (`runtime.rs:678`). The manifest ceiling for that session is removed at the detached end (`runtime.rs:577`). Stop, a guest failure, a crash, and a cancel all go through that end, so the next Start sees no live row. A Home restart starts a new process. `running_capsules` is that process's memory, so the new process has no row.

Retire sets `retired_at` (`agents.rs:1036`) and does not clear the live row. A later Start is refused at admission because the agent is retired (`stored_agent`, `agents.rs:1125`). Stop of a retired agent stays allowed (`stored_agent_for_stop`, `agents.rs:1138`). This slice does not stop the guest on retire.

## Two Runtimes on one Home

`start_agent_once` looks at this process's registry. Nothing in that function spans processes.

A second non-subordinate host is stopped by the exclusive host lock (`host_lock.rs:120`). `elastos serve` takes it (`serve_cmd.rs:43`). `elastos gateway` takes it (`gateway_cmd.rs:71`). The lock error is "another ElastOS host already owns".

`elastos serve` skips that lock when `ELASTOS_ALLOW_SUBORDINATE_RUNTIME_HOST` is `1` (`serve_cmd.rs:36`). The managed child is started with that variable (`runtime_control.rs:1424`). `ensure_managed_runtime` holds a start lock only while it is starting (`runtime_control.rs:1213`), then reuses one live managed child and stops sibling children (`runtime_control.rs:1253` and `:1277`). A product Home is one gateway plus that one subordinate Runtime.

A second subordinate Runtime on the same Home is not stopped by the agent rule. This slice does not add a cross-process agent lock.

## Journal, plain writes, and appends

The journal code was not changed.

`in_agents_area` (`provider_resource.rs:566`) matches `localhost://Users/` only. A path under `localhost://UsersAI/` is outside that area.

Under `.AppData/Agents` on `localhost://Users/...`, a whole-object write needs `create_only` or `if_revision`, and append is refused (`resource_bridge.rs:1441` and `:1453`). A revision that is not the stored revision is `revision_conflict` (`resource_bridge.rs:1513`). That is the revision rule in the agents document:

A journal under `.AppData/Agents` is written as a whole object. The write carries `create_only` when the object is new, or `if_revision` with the revision last read, and append is refused. A write whose revision is not the stored revision is a conflict, so a run that has ended cannot replace the journal after a later run has stored a new revision.

Outside `.AppData/Agents`, a precondition is optional and is honoured when it is sent (`resource_bridge.rs` `preconditions_are_optional_outside_agents_and_honoured_when_sent`, the test at `:7696`). A plain write replaces the object (`resource_bridge.rs:1495`). An append extends a file that is already there (`resource_bridge.rs:1459`). One live run does not change those writes. An ended session cannot write because its manifest ceiling is gone (`runtime.rs:577`), so the bridge answers `manifest_capability_denied`.

An agent's own root is `localhost://UsersAI/...`. Those journal paths are outside `.AppData/Agents` for the area rule. The two-run rows use that root, with `create_only` and `if_revision`, and they use a plain write and an append on `memory/notes.md`.

## Rows

`a_second_start_is_refused_while_the_first_run_can_write` (`routes.rs`). One agent spins. A second grant is 409 with "this agent is already running", and that grant is not consumed. The live run writes its journal with `create_only` and then `if_revision`, writes `memory/notes.md` as "one", and appends "two", and the file is `onetwo`. A different agent is live beside it and then completes. Stop frees the agent. The refused grant then starts.

`two_starts_at_once_produce_one_run`. Two `launch_from` calls of one spinning agent at the same moment. One is accepted. The other is 409 with "this agent is already running", and the body does not say "already used". One live row remains. Stop ends it.

`an_ended_run_cannot_write_after_the_next_run_starts`. The first run writes the journal and is stopped. The second run starts. A write as the first session is `manifest_capability_denied` and the bytes stay `journal v1`. The second run writes `journal v2` with `if_revision` of the stored revision. A write that repeats the old revision is `revision_conflict`, and the bytes stay `journal v2`.

`a_second_start_is_agent_already_running` (`gateway_tests/agent_launch.rs`). A planted live row, then Start through the gateway. The answer is 409, `code` `agent_already_running`, `reason` "this agent is already running", and the live count stays 1.

The page test `a refused Start with the already-running code stays Running and does not offer Retry` (`scripts/system-agents-section.test.mjs`). The state is Running, Start is disabled, the sentence is shown, Retry stays hidden, a second click sends no launch, and a reload returns the state to On.

## Rows that already start two runs, and what happened to each

These were left as they are. The posted design does not contradict them.

- `agent_launch_double_click_with_one_grant_starts_one_guest` (`routes.rs`). One grant, clicked twice. The loser is "already used". One guest starts. The live-row check runs after that one-use check, so this sentence stays.
- `agent_launch_id_is_one_use_after_the_guest_ends` (`routes.rs`). The same grant after the guest has ended is "already used". A new grant after the end is a new run, which the design allows.
- `two_starts_with_one_step_up_start_one_guest` (`gateway_tests/agent_launch.rs`). Two Starts of one agent share one passkey step-up. One guest starts. Re-run on this head: passed.
- `an_agent_launch_binds_each_agents_own_principal_and_root` (`routes.rs`). Two agents, then the same agent again after the first guest has completed. Re-run: passed.
- `a_stop_racing_a_trap_ends_once` and the trap relaunch (`routes.rs` around the second `home.launch(a)` after the trap). The crash ends the row. The later Start is a new run.
- `cancel_mid_compute` (`routes.rs`). Stop of a spinning guest. It does not start a second run. The new stop-then-start row covers the free after Stop.
- `two_agents_resident_at_once` (`routes.rs`) and `both_resident_b_is_refused_a_journal_and_a_reads_its_own`, `both_resident_b_is_refused_a_memory_file_and_a_reads_its_own`, `both_resident_b_is_refused_a_foreign_file_and_a_reads_its_own`. Two different agents. Re-run of `two_agents_resident_at_once`: passed.
- The runtime test whose comment is "Two instances, two sessions" (`runtime.rs` near `:5776`). It starts `agents[0]` and `agents[1]`. Two agents.
- `a_live_row_without_a_matching_start_record_is_not_stopped` (`gateway_tests/agent_launch.rs`). It plants a second row. It does not call Start twice. Stop still ignores a row with no matching start record.
- `two_starts_of_one_cid_are_two_instances` (`bundle_start_tests.rs:2686`). Two starts of one bundle CID. The principal is not one agent id.
- `a15r_double_clicks_claim_one_plan` (`gateway_tests/agent_plan.rs`). One plan claim. Not two agent runs.
- `standin_two_launches_are_two_instances` (`lab/agent-conformance/standin-runtime/mod.rs:4254`) and `standin_valid_signature_alone_yields_no_grant` (`lab/capsule-identity`, the signed `agent-host` launched twice). Stand-in capsule instances, not a Runtime agent principal.
- `receipt_records_observed_engine_versions` (`lab/wasm-capsule`). Two runs of one bundle. Not an agent principal.
- Gateway "a second start on this data dir" (`gateway_server.rs`). A second gateway process. Not an agent.
- `scripts/update-hop-compare-test.py` "second start". The update journey's oldest release. Not an agent.

## Stricter readings

The spec did not say which row counts as live. The row is the in-memory registry entry whose `ended_at` is unset and whose principal is this agent. It is checked under the launch lock, after the one-use check, and before the grant is stored.

The spec did not say to consume the refused grant. The grant is not stored, so it can start after the row ends. The same-grant double-click still says "already used".

The spec says retire frees the run. Retire does not clear the row and does not stop the guest. A later Start is refused because the agent is retired. The document says that, and this slice does not add an automatic stop.

The spec says the rule holds if two Runtimes exist on one Home. The in-process check cannot see the other process. The host lock stops a second non-subordinate host. A second subordinate Runtime is not stopped. No cross-process agent lock was added.

The journal paths of a real agent are under `UsersAI`. They are outside the `.AppData/Agents` area rule. The area rule was not widened. The rows show the writes the agent can actually make, and the document says what the area rule still does.

## Plants

Each plant was reverted. The tree that was committed is the tree that passed the restored run.

- The live-row check removed. `a_second_start_is_refused_while_the_first_run_can_write` failed: "a second start was accepted". Receipt `plant-no-live-row.log`.
- The check treated any live row as this agent. The same test failed on the spinner's start: `409 "this agent is already running"`, while the other agent was the one already live. Receipt `plant-any-live-row.log`.
- An ended row still counted as live. The same test failed after Stop: "stop frees the agent, and the refused grant was not used" with `409 "this agent is already running"`. Receipt `plant-ended-still-live.log`.
- The detached end kept the manifest ceiling (`runtime.rs` `release`). `an_ended_run_cannot_write_after_the_next_run_starts` failed: the ended session's write returned `status` `ok`, and the code was not `manifest_capability_denied`. Receipt `plant-ceiling-kept.log`.
- A stale `if_revision` wrote the object and returned `ok`. The same test failed: the code was not `revision_conflict`. Receipt `plant-stale-revision.log`.
- The page did not handle `agent_already_running`. The page test failed: state stayed `On` instead of `Running`. Receipt `plant-page.log`.

## Checks

`CARGO_TARGET_DIR=/Users/sash/code/target-u8`, `CARGO_BUILD_JOBS=4`, `cargo test -j 4 --offline --locked -p elastos-server --features prototype-agents --lib`. This worktree's `.cargo/config.toml` sets `build-dir` to `target-build`, so the test binary was `/Users/sash/code/wt-u8/target-build/debug/deps/elastos_server-556bbe6a767f1f4b`. The compile did not use another worktree's target directory.

Feature `prototype-agents` was on. Without it, `require_build` returns early and these rows would not run.

First run, 9 passed, 0 failed, 9.14s, in `u8-lib-tests.log`: the three new route rows, the gateway row, `agent_launch_double_click_with_one_grant_starts_one_guest`, `agent_launch_id_is_one_use_after_the_guest_ends`, `two_agents_resident_at_once`, `two_starts_with_one_step_up_start_one_guest`, `an_agent_launch_binds_each_agents_own_principal_and_root`.

After the plants were reverted, 4 passed, 0 failed, 2.80s, in `u8-restored-tests.log`: the three route rows and the gateway row.

`cargo fmt --all -- --check` passed (`u8-fmt.log`). `node --test scripts/system-agents-section.test.mjs` passed, 19 tests (`u8-page-test.log`). `python3 scripts/core-size.py --check` passed: core code is 13122 (`u8-core-size.log`). `git diff --check` was clean before the commit.

No `auth.rs` edit. No new `#[allow]`. Core stayed 13122. Product lines added outside tests: runtime.rs 26, the launch match in routes.rs 2, gateway_home_runtime.rs 7, agents-section.js 9. That is 44. The agents document adds 6. The cap was 80.

## Commits

`d86dcf566236fe7e972a1cffbd7f3fb99226cedd`

Subject: Refuse a second live run of one agent.

Non-test lines added: 50. runtime.rs 26, gateway_home_runtime.rs 7, agents-section.js 9, the launch match in routes.rs 2, docs/AGENT_ARCHITECTURE.md 6. Deletions in those places: 9. Net non-test lines: 41. The other 396 added lines are tests.

## Receipts

These files sit in `evidence/u678/`. `*.log` is gitignored, so they are on this machine and not in the commit. sha256:

- `evidence/u678/u8-lib-tests.log` `499e9d72a585df66fe8355ed835eb7cc059349167d2a17ec6bc2bb487ee03c5a`
- `evidence/u678/u8-restored-tests.log` `f6eb4725cfdcd9f86355e1e4a0d86f4f45614cad1caca4085b3cdd3ea24f8fc4`
- `evidence/u678/u8-page-test.log` `86158ac6e47d290df84ba7ef0f7ab06ed574e5ce45b79a13dde3f133f62e7e13`
- `evidence/u678/u8-fmt.log` `d161aa59069147d0e306244e576f9987245f5c284673a1b80a14f96a14d2becd`
- `evidence/u678/u8-core-size.log` `60f75bdc07f54444c025b97379a59c150461d1ce46920ad709ef4b5c78cc4c11`
- `evidence/u678/plant-no-live-row.log` `7f205588fc7e2835cdbbe6bc91bc8668606aa25b05dc5dc314b28ec047624d34`
- `evidence/u678/plant-any-live-row.log` `b6d672d3882a1ff51ccc58338ecdbc7a6a4c8f3348d8be580eb31f7021a7505e`
- `evidence/u678/plant-ended-still-live.log` `1243a2dfe0bdbf17b868f89c4a98cec085ab78c40e66f2507db8e2baa1fb2366`
- `evidence/u678/plant-ceiling-kept.log` `b6c367303ec59254ac0bdfd055a56deebe3a887becbd172c475b88a42dd33159`
- `evidence/u678/plant-stale-revision.log` `d906719f65870b86339ab7511c3f4e98c93b26ecb6b73f94e6526e9cf2072dc2`
- `evidence/u678/plant-page.log` `34c030577cc48fe57a0b527a7b6e6a28dea0ed4fb75081ef0b78f130f5eadf05`

## What this run did not prove

A second subordinate Runtime was not started. The skip of the host lock is `serve_cmd.rs:36`. The agent check does not cross processes.

A Home restart was not run as a second process. The registry is process memory. A new process has an empty registry.

Retire was not exercised against a live guest. The code sets `retired_at` and leaves the row. Admission refuses the next Start.

A new crash test and a new cancel-then-start test were not added. The stop-then-start row is new. Crash-then-start remains the existing trap relaunch. Cancel remains `cancel_mid_compute`.

The page was proven by the node harness that mounts the section. A Home was not opened in a browser.

Clippy was not run. `cargo fmt --check`, the core-size check, the page test, and the named server tests were run.
