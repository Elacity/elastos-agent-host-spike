# Where a budget reservation must come before each model dispatch

Task 034. Discovery only: this report changes no code and books no M1 check.
Base commit: `2c664d3a8dec8c9b713ea55603103949bcdc5bfe` from
`git rev-parse HEAD`. The planner's grep base `04f1e93b4` is an ancestor of
this commit; every line below was re-read at the base commit. Some planner
line numbers moved with merged work: `AdapterConfig` is at
`capsules/model-provider/src/config.rs:286-324` at this commit, and the
planner's `config.rs:558-562` reference points at a different declaration
now.

Anders's rule for spending is the measure used here: admission sets the
ceiling, and the Runtime reserves a bounded budget before each dispatch and
keeps one account across concurrent calls, retries, cancellation and an
uncertain outcome. Today the model provider has admission checks and run
state. It has no budget reservation, no settlement against a reservation, and
no account shared by concurrent or retried calls. This report maps each send
site and each of the four cases to the code and the tests that pin today's
behaviour.

## Two kinds of model call

The names come from task 031's report
(`examples/agent-host/handoff/reports/provider-a4-deepseek-turn-gaps.md:20-33`).

A **call by URL** goes from the provider to the model address it holds in the
offer. The address is an HTTP URL or a local engine socket. The provider
builds the request at `capsules/model-provider/src/adapters.rs:45-70`, with
`direct_url` selected when `runtime_socket` is absent (`:55-58`).

A **call through the Runtime grant and hosted transport** goes from the
provider to the Runtime's Unix socket as `http://runtime.invalid/v1/hosted-effect`
(`capsules/model-provider/src/adapters.rs:42`, `:55-68`). The Runtime then
forwards the request to the model at
`elastos/crates/elastos-server/src/api/model_provider_egress.rs:1584`. Only
this second kind can carry a Runtime budget reservation.

## Dispatch paths

One row per site that sends a request. Ten sites send. The "last point"
column gives the line just before the send expression, where a reservation
could be taken, and the admission point where the provider currently checks a
limit. No row has a budget check.

| # | Path | Send `file:line` | Kind | Last point before the send | Limit checked there today |
| --- | --- | --- | --- | --- | --- |
| 1 | OpenRouter decisions | `capsules/model-provider/src/adapters.rs:2197` | hosted transport, or by URL when no Runtime socket | `capsules/model-provider/src/adapters.rs:2196`; dispatch at `:1098`; admission at `capsules/model-provider/src/state.rs:621-623` | Concurrency (`state.rs:608-609`), input bytes (`state.rs:570`). No token cap. |
| 2 | OpenAI-compatible text | `capsules/model-provider/src/adapters.rs:1995` | hosted transport, or by URL | `capsules/model-provider/src/adapters.rs:1994`; dispatch at `:1292-1293`; admission at `state.rs:621-623` | Concurrency (`state.rs:608-609`), input bytes (`state.rs:570`), output cap from `inline_output_bytes_limit / 4` (`adapters.rs:2389`, body at `:2363`), run deadline from `runtime_ms_limit` (`config.rs:444-450`). |
| 3 | OpenAI Responses text | `capsules/model-provider/src/adapters.rs:1995` | hosted transport, or by URL | `capsules/model-provider/src/adapters.rs:1994`; dispatch at `:1292-1293`; admission at `state.rs:621-623` | Same as row 2; the output field is `max_output_tokens` (`adapters.rs:2385`). |
| 4 | Local llama input-token count | `capsules/model-provider/src/adapters.rs:1912` | local engine socket | `capsules/model-provider/src/adapters.rs:1911`; after engine admission at `capsules/model-provider/src/local_llama.rs:200` | None before the count. The context check runs after it (`adapters.rs:1943`). |
| 5 | Local llama text | `capsules/model-provider/src/adapters.rs:1995` | local engine socket | `capsules/model-provider/src/adapters.rs:1994`; engine slot at `local_llama.rs:187`, `:200` | Context window (`adapters.rs:1943`), `max_tokens` from the request or the local limit (`adapters.rs:1876`; `config.rs:728-731`), offer concurrency (`state.rs:608-609`). |
| 6 | Artifact job create | `capsules/model-provider/src/adapters.rs:1675` | hosted transport, or by URL | `capsules/model-provider/src/adapters.rs:1674`; dispatch at `:1179` | Concurrency (`state.rs:608-609`), input bytes (`state.rs:570`). No token cap. |
| 7 | Artifact job status read | `capsules/model-provider/src/adapters.rs:1748` | hosted transport, or by URL | `capsules/model-provider/src/adapters.rs:1747`; scheduled at `:2915` | Cancel settlement deadline (`adapters.rs:1720-1726`). No token cap. |
| 8 | Artifact job cancel | `capsules/model-provider/src/adapters.rs:3020` | hosted transport, or by URL | `capsules/model-provider/src/adapters.rs:3019`; sent only when `allow_send` is true (`:2962-2978`) | Cancel settlement deadline (`adapters.rs:2956-2961`). No token cap. |
| 9 | Local engine readiness read | `capsules/model-provider/src/local_llama.rs:811` | local engine socket | `capsules/model-provider/src/local_llama.rs:810` | None. The health loop stops at its own deadline (`local_llama.rs:759-789`). |
| 10 | Runtime hosted forward | `elastos/crates/elastos-server/src/api/model_provider_egress.rs:1584` | Runtime to model | `elastos/crates/elastos-server/src/api/model_provider_egress.rs:1557-1563`; job-create reservation at `:1533` | Run binding and grant (`bridge.rs:1063`, `egress.rs:768`), destination pins (`egress.rs:1673-1716`, `:1761`). No budget. |

Re-send paths that send nothing:

- A retried `runs_create` returns the stored run before dispatch. The journal
  lookup and replay is `capsules/model-provider/src/state.rs:505-518`.
- A local cancel sends one in-process signal, `cancel_tx.send(true)` at
  `capsules/model-provider/src/adapters.rs:1469`, and makes no HTTP request.
- A local reconcile reads the worker map and returns still-running or
  settlement-unknown, `capsules/model-provider/src/adapters.rs:1414-1442`.
- A hosted cancel stores its reservation first and sends only when the
  reservation allows it: `capsules/model-provider/src/state.rs:726-750`;
  `capsules/model-provider/src/adapters.rs:2949-2966`.

The provider's concurrency ceiling is a count of journal rows, not a reserved
amount. `active_run_count` (`capsules/model-provider/src/journal.rs:406`) is
read after the prepared run is stored (`state.rs:606-609`). A count above the
offer limit fails the new run with `rate_limited`/`model_busy`
(`state.rs:609-623`). The local engine adds one execution slot
(`local_llama.rs:187`, `:200`), so concurrent local runs queue.

## The four cases

Usage travels only in a hosted run's `backend_report`, carried by every run
event and the terminal outcome (`capsules/model-provider/src/contract.rs:166-173`,
`:282`). Its `usage` field holds `BackendTokenUsage` (`contract.rs:185-192`,
`:204-209`), and the journal refuses an empty report
(`capsules/model-provider/src/journal.rs:1861-1883`). A hosted terminal
transition with no report records `unknown` (`state.rs:1352-1355`). A local
run that supplies a report is refused (`state.rs:1356-1361`). The Runtime
streams the response bytes and keeps no usage record
(`elastos/crates/elastos-server/src/api/model_provider_egress.rs:1584-1665`).

### Case 1: two concurrent runs

| Test | `file:line` | What it asserts | Usage recorded |
| --- | --- | --- | --- |
| `concurrency_limit_is_enforced` | `capsules/model-provider/src/state.rs:4464` | Offer limit is 1 (`:4477`); the first run is running; the second is failed with `rate_limited`/`model_busy` (`:4501-4507`); dispatch ran once (`:4509`); the replay keeps the same run and result (`:4512-4520`); the terminal event keeps the refusal (`:4536-4540`). | None. The offer is local and terminal transitions record no report (`state.rs:1358`). |
| `private_and_remote_principals_share_one_hosted_concurrency_limit` | `capsules/model-provider/src/state.rs:4544` | A hosted offer gives one dispatch to the private principal and refuses the remote principal with `model_busy` (`:4588-4591`); after settlement the remote run may start (`:4599-4604`). | For the first run the terminal event records a hosted report with no usage facts, which becomes `unknown` (`state.rs:1354`). The test does not assert that field. |
| `local_llama_streams_concurrent_runs_reuses_child_and_guards_refresh` | `capsules/model-provider/src/execution.rs:3951` | Two runs return their own text (`:3973-3979`); one engine start and both requests (`:3984-3989`); the local terminal has no backend report (`:3976-3978`). | None. The test asserts the report field is absent. |

```
test state::tests::concurrency_limit_is_enforced ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 0.05s
test state::tests::private_and_remote_principals_share_one_hosted_concurrency_limit ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 0.06s
test execution::tests::local_llama_streams_concurrent_runs_reuses_child_and_guards_refresh ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 0.38s
```

### Case 2: a retried run

| Test | `file:line` | What it asserts | Usage recorded |
| --- | --- | --- | --- |
| `conflicting_retry_reuses_run_id_and_fails_by_stable_request_fingerprint` | `capsules/model-provider/src/state.rs:4898` | Three retries with changed input, operation or offer hit the same run id and fail `invalid_request` (`:4973`). No dispatch happens. | None. No run terminal is produced. |
| `create_retry_after_session_and_grant_rotation_returns_same_run_without_redispatch` | `capsules/model-provider/src/state.rs:4978` | The rotated retry returns the same run id (`:5025`), dispatch ran once (`:5026`), and the stored binding keeps the original session and grant (`:5031-5032`). | None. The offer is local and the completed terminal records no report. |
| `responses_terminal_failures_are_generic_and_not_retried` | `capsules/model-provider/src/execution.rs:4719` | Each of three terminal stream failures gives `backend_failed` with a generic message (`:4750-4759`), records an unknown backend report (`:4761-4763`), and makes exactly one request per run (`:4765`). | Hosted report with `usage` = unknown (`contract.rs:204-209`; `state.rs:1354`), asserted at `execution.rs:4761-4763`. |

```
test state::tests::conflicting_retry_reuses_run_id_and_fails_by_stable_request_fingerprint ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 0.01s
test state::tests::create_retry_after_session_and_grant_rotation_returns_same_run_without_redispatch ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 0.02s
test execution::tests::responses_terminal_failures_are_generic_and_not_retried ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 0.12s
```

### Case 3: a cancelled run

| Test | `file:line` | What it asserts | Usage recorded |
| --- | --- | --- | --- |
| `cancel_reservation_is_stored_before_io` | `capsules/model-provider/src/state.rs:5249` | The cancel returns `reconciling` (`:5290`), the stored backend state has `cancel_requested` true (`:5293`) and `cancel_sent` true (`:5297`), and the adapter is called with `allow_send` true (`:5300`). | None. The cancel path records state, not usage. |
| `reserved_cancel_retry_does_not_send_again_or_extend_deadline` | `capsules/model-provider/src/state.rs:5304` | The first cancel stores deadline 1234 (`:5345`); the retry is reconciling (`:5373`), is called with `allow_send` false (`:5375-5378`), and keeps deadline 1234 (`:5382`). | None. No second send and no usage record. |
| `local_llama_cancel_with_active_backend_settles_cancelled_without_redispatch` | `capsules/model-provider/src/execution.rs:4061` | The cancel is reconciling, the terminal is `cancelled` (`:4076`), one terminal event exists (`:4079-4087`), and the engine saw one stalled request (`:4110-4114`). | None. A local run has no backend report. |

```
test state::tests::cancel_reservation_is_stored_before_io ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 0.03s
test state::tests::reserved_cancel_retry_does_not_send_again_or_extend_deadline ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 0.06s
test execution::tests::local_llama_cancel_with_active_backend_settles_cancelled_without_redispatch ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 0.94s
```

### Case 4: a `settlement_unknown` outcome

| Test | `file:line` | What it asserts | Usage recorded |
| --- | --- | --- | --- |
| `prepared_run_becomes_settlement_unknown_after_restart` | `capsules/model-provider/src/state.rs:3210` | A prepared run with no backend state reads as `settlement_unknown` (`:3239`) through `refresh_run_if_needed` (`:953-971`). | None. The offer is local. |
| `cancel_deadline_settles_unknown_on_later_read` | `capsules/model-provider/src/state.rs:5514` | A reconciling run past its cancel deadline reads as `settlement_unknown` (`:5546`). | None. The offer is local. |
| `responses_and_chat_cancel_with_active_backend_settle_unknown` | `capsules/model-provider/src/execution.rs:4925` | Both hosted adapters cancel to `reconciling`, then settle `settlement_unknown` (`:4955`), keep one terminal event (`:4958-4966`), keep the request active (`:4953`, `:4990`) and make one request (`:4954`, `:4992`). | Hosted report with `usage` = unknown (`state.rs:1354`). The test does not assert that field. |
| `local_llama_cancel_with_active_backend_settles_unknown_without_redispatch` | `capsules/model-provider/src/execution.rs:3704` | The retained unknown run returns the same run id and `settlement_unknown` (`:3834-3838`), and the journal bytes and engine events stay unchanged (`:3842`), so no new inference starts. | None. A local run has no backend report. |

```
test state::tests::prepared_run_becomes_settlement_unknown_after_restart ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 0.02s
test state::tests::cancel_deadline_settles_unknown_on_later_read ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 0.02s
test execution::tests::responses_and_chat_cancel_with_active_backend_settle_unknown ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 0.16s
test execution::tests::local_llama_cancel_with_active_backend_settles_unknown_without_redispatch ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 1.04s
```

All four cases are pinned for today's behaviour. No case is **not pinned**.

## Gaps for a Runtime reservation

Each row is Runtime-side and names the nearest existing Runtime code. No row
proposes a Runtime design; each names what is missing.

1. **Reserve a bounded amount before each dispatch.** Runtime-side (Anders).
   The Runtime has admission and a run binding, and no amount. The nearest
   pre-send reservation is the job-create key at
   `elastos/crates/elastos-server/src/api/model_provider_egress.rs:1428-1446`,
   taken at `:1533`; it reserves job identity only. Admission for a model run
   is `elastos/crates/elastos-runtime/src/provider/bridge.rs:926-1010`, which
   records offer, run, request and input hash. The broker's request admission
   is `egress.rs:419-510`, and the grant check is `egress.rs:768`. The
   capability check that authorises `runs_create` is
   `elastos/crates/elastos-server/src/provider_resource.rs:162-166`,
   `:641-657`.
2. **Settle the reservation from the reported outcome.** Runtime-side
   (Anders). The Runtime forwards the response and keeps no usage. The send is
   `egress.rs:1584`; the stream copy loop runs at `egress.rs:1626-1665`.
   `bridge.rs:1021-1032` lowers only a `pending` count and raises an `accepted`
   flag. `HostedRunBinding` has no amount
   (`bridge.rs:573-583`).
3. **Release on cancel.** Runtime-side (Anders). A cancel is one more effect
   through the same forward (`egress.rs:1513-1583`); the binding is removed
   when a terminal response arrives (`bridge.rs:1034-1059`). No amount is
   released.
4. **Hold on `settlement_unknown`.** Runtime-side (Anders). The binding is
   removed on any terminal status, `settlement_unknown` included
   (`bridge.rs:1034-1059`). The provider keeps the unknown run truthful
   (`capsules/model-provider/src/state.rs:846-879`), and the Runtime keeps no
   corresponding hold.
5. **One account across concurrent and retried calls.** Runtime-side
   (Anders). Retries join one binding by the run id, and concurrent runs each
   add to `pending` (`bridge.rs:985-1010`); the binding cap is 4096
   (`bridge.rs:45`, `:997`). That accounting covers run identity and pending
   effects, and has no spend field that concurrent and retried calls share.
   The provider side already joins a retry to the original run
   (`capsules/model-provider/src/state.rs:505-518`, `:5025-5026`).

## Tests still missing

These tests would pin the reservation rules. Each needs the Runtime
reservation contract first, so none can pass today:

1. `hosted_dispatch_takes_one_reservation_before_the_effect` in
   `capsules/model-provider/tests/process.rs`. It asserts one reservation
   exists before the first hosted effect. It needs no `src` change, because
   the hosted socket is an existing test seam
   (`examples/agent-host/handoff/reports/provider-a4-deepseek-turn-gaps.md:112-121`).
2. `hosted_concurrent_runs_share_one_reserved_ceiling` in the same file. It
   asserts two concurrent hosted runs draw on one account and the second stops
   at the ceiling.
3. `hosted_usage_settles_the_reservation_and_cancel_releases_it` in the same
   file. It asserts reported usage settles the reservation and a cancel
   releases the unused part.
4. `settlement_unknown_holds_the_reservation` in the same file. It asserts the
   account stays held while the outcome is unknown.

## Next task

None for this lane. Every one of the four cases has a passing pinning test,
and the missing rules are Runtime-side. A pin test for a reservation cannot
pass until Anders's Runtime reservation exists; writing it now would test an
absence, and the lane's rule keeps provider behaviour unchanged.

## What this report did not check

- No network call, no model call, no key, no hosted effect.
- No test ran with `SPARKS_MODEL_URL` or `ELASTOS_MODEL_EVAL_ROOT` set.
- No Runtime build and no installed Runtime or provider.
- No `capsules/*/src` change, so no Sasha note is needed.

## Principles check

1. **Named by hash:** Yes. The report cites paths and lines; it adds no name
   or URL identity. Run identity is the contract run id
   (`elastos/crates/elastos-model-contract/src/lib.rs:200`).
2. **No ambient authority:** Yes. No code change and no new access. The
   provider still needs the Runtime socket for hosted calls
   (`capsules/model-provider/src/adapters.rs:111-128`).
3. **One path (P10):** Yes. The report adds no second path. It lists the
   existing send sites and their single shared admission check
   (`state.rs:608-623`).
4. **Trusted core:** Yes. No Runtime or core change.
5. **Fails closed (P11):** Yes. No new refusal. Existing refusals keep their
   named reason, for example `model_busy` (`state.rs:609-620`).
6. **Self-contained (Rong):** Yes. No capsule or provider logic change.
7. **Tests prove it:** Yes for today's rules. The 13 named tests pass, as
   quoted above. The missing reservation rules have named tests above; they
   wait on the Runtime side.
8. **Separate decisions:** Yes. Identity (`bridge.rs:926-1010`), admission
   (`state.rs:608-623`) and allowance (missing, gaps 1-5) stay distinct.
