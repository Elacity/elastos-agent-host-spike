# Where a budget reservation must come before each model dispatch

Task 034, re-landed as task 038 after the merge-gate flake. Discovery only:
this report changes no code and books no M1 check.
Base commit: `4e0a2888dcac98f145200c43f8909d93209d5bf0` from
`git rev-parse HEAD`, which includes tasks 037-050. Every line below was
re-read at this base. Since the report's previous base `093d1f798`,
`capsules/model-provider/tests/process.rs` moved: tasks 044-050 added lines
above its hosted tests, and its line numbers below are the ones at this base.
The provider's `src/` files cited below kept their lines between `093d1f798`
and this base, and the moves of `execution.rs` and
`provider-a4-deepseek-turn-gaps.md` belong to the report's earlier base
`2c664d3a8`. The planner's grep base `04f1e93b4` is an ancestor of this
commit. `AdapterConfig` is at
`capsules/model-provider/src/config.rs:286-324` at this commit, and the
planner's `config.rs:558-562` reference points at a different declaration
now. The result blocks under the four cases are the ones captured at
`093d1f798`; the two runs at this base are in "Runs at this base" below.

Anders's rule for spending is the measure used here: admission sets the
ceiling, and the Runtime reserves a bounded budget before each dispatch and
keeps one account across concurrent calls, retries, cancellation and an
uncertain outcome. The model provider keeps no budget reservation. It reports
usage in a hosted run's backend report, and it reports `settlement_unknown`
when the outcome cannot be confirmed. Reservation, settle and release are
modelled only in `lab/grant-binding` (`lab/grant-binding/src/ledger.rs:81-135`
for the outcome and refusal types, `:191-235` for `settle` and `:241-263` for
`release`), and the real account is Runtime-side (Anders). Today the model
provider has admission checks and run state, with no reservation, no
settlement against a reservation, and no account shared by concurrent or
retried calls. This report maps each send site and each of the four cases to
the code and the tests that pin today's behaviour.

## Runs at this base

Both runs read `1 passed`:

```
$ RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 cargo test --locked --manifest-path capsules/model-provider/Cargo.toml --test process hosted_cancel_while_the_answer_is_held -- --exact hosted_cancel_while_the_answer_is_held_settles_unknown_and_sends_nothing_more
test hosted_cancel_while_the_answer_is_held_settles_unknown_and_sends_nothing_more ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 15 filtered out; finished in 1.86s
exit status 0

$ RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 cargo test --locked --manifest-path lab/grant-binding/Cargo.toml model_unknown_outcome_keeps_the_hold
test ledger::model_unknown_outcome_keeps_the_hold ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 95 filtered out; finished in 0.00s
exit status 0
```


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

One row per site that sends a request. Eleven sites send. The "last point"
column gives the line just before the send expression, where a reservation
could be taken, and the admission point where the provider currently checks a
limit. No row has a budget check.

| # | Path | Send `file:line` | Kind | Last point before the send | Limit checked there today |
| --- | --- | --- | --- | --- | --- |
| 1 | OpenRouter decisions | `capsules/model-provider/src/adapters.rs:2197` | hosted transport, or by URL when no Runtime socket | `capsules/model-provider/src/adapters.rs:2196`; dispatch at `:1098`; admission at `capsules/model-provider/src/state.rs:608-624` | Concurrency (`state.rs:608-609`), input bytes (`state.rs:570`). No token cap. |
| 2 | OpenAI-compatible text | `capsules/model-provider/src/adapters.rs:1995` | hosted transport, or by URL | `capsules/model-provider/src/adapters.rs:1994`; dispatch at `:1292-1293`; admission at `state.rs:608-624` | Concurrency (`state.rs:608-609`), input bytes (`state.rs:570`), output cap from `inline_output_bytes_limit / 4` (`adapters.rs:2389`, body at `:2363`), run deadline from `runtime_ms_limit` (`config.rs:444-450`). |
| 3 | OpenAI Responses text | `capsules/model-provider/src/adapters.rs:1995` | hosted transport, or by URL | `capsules/model-provider/src/adapters.rs:1994`; dispatch at `:1292-1293`; admission at `state.rs:608-624` | Same as row 2; the output field is `max_output_tokens` (`adapters.rs:2385`). |
| 4 | Local llama input-token count | `capsules/model-provider/src/adapters.rs:1912` | local engine socket | `capsules/model-provider/src/adapters.rs:1911`; after engine admission at `capsules/model-provider/src/local_llama.rs:200` | Concurrency (`state.rs:608-609`), input bytes (`state.rs:570`) before dispatch. The context check runs after the count (`adapters.rs:1943`). No token cap. |
| 5 | Local llama text | `capsules/model-provider/src/adapters.rs:1995` | local engine socket | `capsules/model-provider/src/adapters.rs:1994`; engine slot at `local_llama.rs:184`, `:200` | Context window (`adapters.rs:1943`), `max_tokens` from the request or the local limit (`adapters.rs:1876`; `config.rs:727-731`), offer concurrency (`state.rs:608-609`). |
| 6 | Artifact job create | `capsules/model-provider/src/adapters.rs:1675` | hosted transport, or by URL | `capsules/model-provider/src/adapters.rs:1674`; dispatch at `:1179` | Concurrency (`state.rs:608-609`), input bytes (`state.rs:570`). No token cap. |
| 7 | Artifact job status read | `capsules/model-provider/src/adapters.rs:1748` | hosted transport, or by URL | `capsules/model-provider/src/adapters.rs:1747`; scheduled at `:2915` | Cancel settlement deadline (`adapters.rs:1720-1726`). No token cap. |
| 8 | Artifact job cancel | `capsules/model-provider/src/adapters.rs:3020` | hosted transport, or by URL | `capsules/model-provider/src/adapters.rs:3019`; sent only when `allow_send` is true (`:2962-2978`) | Cancel settlement deadline (`adapters.rs:2956-2961`). No token cap. |
| 9 | Local engine readiness read | `capsules/model-provider/src/local_llama.rs:811` | local engine socket | `capsules/model-provider/src/local_llama.rs:810` | None. The health loop stops at its own deadline (`local_llama.rs:759-789`). |
| 10 | Runtime hosted forward | `elastos/crates/elastos-server/src/api/model_provider_egress.rs:1584` | Runtime to model | `elastos/crates/elastos-server/src/api/model_provider_egress.rs:1557-1563`; job-create reservation at `:1533` | Run binding and grant (`bridge.rs:1063`, `egress.rs:768`), destination pins (`egress.rs:1673-1716`, `:1761`). No budget. |
| 11 | Hosted validation GET | `elastos/crates/elastos-server/src/api/model_provider_egress.rs:320-323` | Runtime to model | `elastos/crates/elastos-server/src/api/model_provider_egress.rs:311-319`; grant re-checked while the send waits at `:329-332` | Grant and destination pins only (`egress.rs:311-319`). No budget. It validates hosted key access or lists models with the hosted credential, so it reports no token usage. |

Row 11 is not a model inference, so a token reservation has no usage to
settle there. It is listed because it sends to the model host with the hosted
credential; a request-count or byte reservation would count it.

Re-send paths that send nothing:

- A retried `runs_create` checks the stored run first
  (`capsules/model-provider/src/state.rs:518-531`). A different fingerprint is
  refused at `:521-524`. A same-fingerprint run returns at `:530`, after
  `refresh_run_if_needed` at `:526-528` when the run is still open.
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
(`local_llama.rs:184`, `:200`), so concurrent local runs queue.

## The four cases

Usage travels only in a hosted run's `backend_report`, carried by every run
event and the terminal outcome (`capsules/model-provider/src/contract.rs:166-173`,
`:282`). Its `usage` field holds `BackendTokenUsage` (`contract.rs:185-192`,
`:204-209`), and the journal refuses an empty report
(`capsules/model-provider/src/journal.rs:1861-1883`). A hosted terminal
transition with no report records `unknown` (`state.rs:1352-1355`). A local
run that supplies a report is refused (`state.rs:1356-1361`). The Runtime
streams the response bytes and keeps no usage record
(`elastos/crates/elastos-server/src/api/model_provider_egress.rs:1584-1652`).

### Case 1: two concurrent runs

| Test | `file:line` | What it asserts | Usage recorded |
| --- | --- | --- | --- |
| `concurrency_limit_is_enforced` | `capsules/model-provider/src/state.rs:4464` | Offer limit is 1 (`:4477`); the first run is running; the second is failed with `rate_limited`/`model_busy` (`:4501-4507`); dispatch ran once (`:4509`); the replay keeps the same run and result (`:4512-4520`); the terminal event keeps the refusal (`:4536-4540`). | The offer from `offer("local-text")` is a hosted `OpenAiCompatibleText` (`state.rs:1861`, `:1877`), so the rate-limited terminal stores `BackendReport::unknown()` (`state.rs:1354`, `contract.rs:212-218`). The test does not assert that field. |
| `private_and_remote_principals_share_one_hosted_concurrency_limit` | `capsules/model-provider/src/state.rs:4544` | A hosted offer gives one dispatch to the private principal and refuses the remote principal with `model_busy` (`:4588-4591`); after settlement the remote run may start (`:4599-4604`). | For the first run the terminal event records a hosted report with no usage facts, which becomes `unknown` (`state.rs:1354`). The test does not assert that field. |
| `local_llama_streams_concurrent_runs_reuses_child_and_guards_refresh` | `capsules/model-provider/src/execution.rs:3955` | Two runs return their own text (`:3973-3980`); one engine start and both requests (`:3984-3992`); the local terminal has no backend report (`:3981-3983`). | None. The test asserts the report field is absent. |
| `hosted_second_concurrent_run_is_refused_model_busy_and_sends_no_effect` | `capsules/model-provider/tests/process.rs:2099` | On macOS, the stand-in holds the answer. Run A returns the contract run id and an open status with one connection. Run B, with its own `request_id`, returns its own run id and `failed`/`model_busy` with no output, and the stand-in still has one connection. After A settles `failed`/`hosted_effect_refused`, run C is admitted, reaches the socket and settles `hosted_effect_refused`; the stand-in has two connections and two requests, each `POST /v1/hosted-effect HTTP/1.1` with no `authorization` header. Off macOS it prints one `SKIP` line and returns. Result: `test hosted_second_concurrent_run_is_refused_model_busy_and_sends_no_effect ... ok`, `test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 13 filtered out; finished in 0.89s`. | `usage` is `unknown`: the refused run is hosted and stores `BackendReport::unknown()` (`state.rs:1352-1354`), so `resolved_model`, `usage` and `cost` are all `unknown` (`contract.rs:212-219`), the same value a sent run with no report records. The test asserts that field. |

```
test state::tests::concurrency_limit_is_enforced ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 0.05s
test state::tests::private_and_remote_principals_share_one_hosted_concurrency_limit ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 0.07s
test execution::tests::local_llama_streams_concurrent_runs_reuses_child_and_guards_refresh ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 1.17s
```

### Case 2: a retried run

| Test | `file:line` | What it asserts | Usage recorded |
| --- | --- | --- | --- |
| `conflicting_retry_reuses_run_id_and_fails_by_stable_request_fingerprint` | `capsules/model-provider/src/state.rs:4898` | Three retries with changed input, operation or offer hit the same run id and fail `invalid_request` (`:4973`). No dispatch happens. | None. No run terminal is produced. |
| `create_retry_after_session_and_grant_rotation_returns_same_run_without_redispatch` | `capsules/model-provider/src/state.rs:4978` | The rotated retry returns the same run id (`:5025`), dispatch ran once (`:5026`), and the stored binding keeps the original session and grant (`:5031-5032`). | The offer from `offer("local-text")` is hosted (`state.rs:1861`, `:1877`), so the completed terminal stores `BackendReport::unknown()` (`state.rs:1354`, `contract.rs:212-218`). The test does not assert that field. |
| `responses_terminal_failures_are_generic_and_not_retried` | `capsules/model-provider/src/execution.rs:4731` | Each of three terminal stream failures gives `backend_failed` with a generic message (`:4763-4770`), records an unknown backend report (`:4772-4775`), and makes exactly one request per run (`:4777`). | Hosted report with `usage` = unknown (`contract.rs:204-209`; `state.rs:1354`), asserted at `execution.rs:4772-4775`. |
| `hosted_retry_of_an_open_run_returns_the_same_run_and_sends_no_second_effect` | `capsules/model-provider/tests/process.rs:1616` | On macOS, the first `runs_create` returns the contract run id and stays open with status `prepared` or `running`; the stand-in has one connection. The same request again returns the same run id and an open status with one connection. After the held answer is released the run settles `failed`/`hosted_effect_refused`, and a third send returns the same run id, terminal status and code, with one connection and one request in total. Off macOS it prints one `SKIP` line and returns. Task 039 keeps this name; 038's report named a `src/state.rs` test `a_same_fingerprint_retry_of_an_open_run_returns_after_refresh`. The connection count is proven by `MP26`, which removes both stops for one run: the open-run return (`src/state.rs:518-531`, return at `:530`) and the local text worker refusal (`src/adapters.rs:768-774`). `MP26` is caught by the final `observe()` connection count (`tests/process.rs:1753`, `left: 2, right: 1`), not by the count check right after the retry (`:1712-1715`), because the second send connects asynchronously. | The run is hosted and the adapter reports nothing, so the terminal stores `BackendReport::unknown()` (`state.rs:1352-1355`, the arm at `:1354`, `contract.rs:212-218`). The test does not assert that field. |

A same-fingerprint retry of a still-open run is pinned by
`hosted_retry_of_an_open_run_returns_the_same_run_and_sends_no_second_effect`
(`capsules/model-provider/tests/process.rs:1616`) on the hosted path. The
retry returns at `state.rs:530` after `refresh_run_if_needed` (`state.rs:526-528`),
which can settle a prepared run to `settlement_unknown` before the replay; the
test holds the hosted answer back, so the replay is observed while the run is
still open, and the held stand-in proves the retry made no second send.

```
test state::tests::conflicting_retry_reuses_run_id_and_fails_by_stable_request_fingerprint ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 0.01s
test state::tests::create_retry_after_session_and_grant_rotation_returns_same_run_without_redispatch ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 0.02s
test execution::tests::responses_terminal_failures_are_generic_and_not_retried ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 0.11s
test hosted_retry_of_an_open_run_returns_the_same_run_and_sends_no_second_effect ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.87s
```

### Case 3: a cancelled run

| Test | `file:line` | What it asserts | Usage recorded |
| --- | --- | --- | --- |
| `cancel_reservation_is_stored_before_io` | `capsules/model-provider/src/state.rs:5249` | The cancel returns `reconciling` (`:5290`), the stored backend state has `cancel_requested` true (`:5293`) and `cancel_sent` true (`:5297`), and the adapter is called with `allow_send` true (`:5300`). | None. The cancel path records state, not usage. |
| `reserved_cancel_retry_does_not_send_again_or_extend_deadline` | `capsules/model-provider/src/state.rs:5304` | The first cancel stores deadline 1234 (`:5345`); the retry is reconciling (`:5373`), is called with `allow_send` false (`:5374-5377`), and keeps deadline 1234 (`:5382`). | None. No second send and no usage record. |
| `local_llama_cancel_with_active_backend_settles_cancelled_without_redispatch` | `capsules/model-provider/src/execution.rs:4065` | The cancel is reconciling (`:4077`), the terminal is `cancelled` (`:4080`), one terminal event exists (`:4084-4093`), and the engine saw one stalled request (`:4113-4119`). | None. A local run has no backend report. |
| `hosted_cancel_while_the_answer_is_held_settles_unknown_and_sends_nothing_more` | `capsules/model-provider/tests/process.rs:1929` | On macOS, the stand-in holds the Runtime's answer. `runs_create` returns the contract run id and an open status (`prepared` or `running`); `runs_cancel` returns the same run id and `reconciling`; with the answer still held the terminal is `settlement_unknown` with code `settlement_unknown` and no output. The stand-in saw one connection and one request, `POST /v1/hosted-effect HTTP/1.1`, with no cancel request and no `authorization` header. Result: `test hosted_cancel_while_the_answer_is_held_settles_unknown_and_sends_nothing_more ... ok`, `test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 1.80s`. Off macOS it prints one `SKIP` line and returns. | All three facts are `unknown` (`state.rs:1352-1355`, `contract.rs:212-219`). No usage is recorded and no cancel effect is sent; the Runtime sees only the connection close. |

```
test state::tests::cancel_reservation_is_stored_before_io ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 0.03s
test state::tests::reserved_cancel_retry_does_not_send_again_or_extend_deadline ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 0.06s
test execution::tests::local_llama_cancel_with_active_backend_settles_cancelled_without_redispatch ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 0.55s
test hosted_cancel_while_the_answer_is_held_settles_unknown_and_sends_nothing_more ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 1.80s
```

### Case 4: a `settlement_unknown` outcome

| Test | `file:line` | What it asserts | Usage recorded |
| --- | --- | --- | --- |
| `prepared_run_becomes_settlement_unknown_after_restart` | `capsules/model-provider/src/state.rs:3210` | A prepared run with no backend state reads as `settlement_unknown` (`:3239`) through `refresh_run_if_needed` (`:953-971`). | The offer from `offer("local-text")` is hosted (`state.rs:1861`, `:1877`), so the unknown terminal stores `BackendReport::unknown()` (`state.rs:1354`). The test does not assert that field. |
| `cancel_deadline_settles_unknown_on_later_read` | `capsules/model-provider/src/state.rs:5514` | A reconciling run past its cancel deadline reads as `settlement_unknown` (`:5546`). | The offer from `offer("local-text")` is hosted (`state.rs:1861`, `:1877`), so the unknown terminal stores `BackendReport::unknown()` (`state.rs:1354`). The test does not assert that field. |
| `responses_and_chat_cancel_with_active_backend_settle_unknown` | `capsules/model-provider/src/execution.rs:4937` | Both hosted adapters cancel to `reconciling` (`:4961`), then settle `settlement_unknown` (`:4967`), keep one terminal event (`:4971-4980`), keep the request active (`:4965`, `:5002`) and make one request (`:4966`, `:5004`). | Hosted report with `usage` = unknown (`state.rs:1354`). The test does not assert that field. |
| `local_llama_cancel_with_active_backend_settles_unknown_without_redispatch` | `capsules/model-provider/src/execution.rs:3708` | The retained unknown run returns the same run id and `settlement_unknown` (`:3838-3842`), and the journal bytes and engine events stay unchanged (`:3844`, `:3845-3849`), so no new inference starts. | None. A local run has no backend report. |
| `hosted_stream_cut_by_the_runtime_fails_the_run_with_unknown_usage` | `capsules/model-provider/tests/process.rs:1793` | On macOS, the stand-in writes the Runtime's accepted head and one chunk that holds `ready`, then closes with no `0\r\n\r\n` and no usage event. The run settles `failed`/`transport_interrupted`, not `settlement_unknown`, with no output; the stand-in saw one connection and one request, `POST /v1/hosted-effect HTTP/1.1`, with no `authorization` header. Result: `test hosted_stream_cut_by_the_runtime_fails_the_run_with_unknown_usage ... ok`. Off macOS it prints one `SKIP` line and returns. | All three facts are `unknown` (`state.rs:1352-1354`, `contract.rs:212-219`), although the cut stream named `resolved-model` and the backend did work. |
| `hosted_cancel_while_the_answer_is_held_settles_unknown_and_sends_nothing_more` | `capsules/model-provider/tests/process.rs:1929` | On macOS, the Runtime socket holds the answer while one hosted text run is cancelled. The run settles `settlement_unknown` with code `settlement_unknown`; `terminal.output` is absent; `resolved_model`, `usage` and `cost` are all `unknown`; and the stand-in saw one connection and one request with no cancel effect. Result: `test hosted_cancel_while_the_answer_is_held_settles_unknown_and_sends_nothing_more ... ok`, `test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 1.80s`. Off macOS it prints one `SKIP` line and returns. | All three facts are `unknown` (`state.rs:1352-1355`, `contract.rs:212-219`) even though the Runtime still held the answer. No usage is reported. |

```
test state::tests::prepared_run_becomes_settlement_unknown_after_restart ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 0.02s
test state::tests::cancel_deadline_settles_unknown_on_later_read ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 0.02s
test execution::tests::responses_and_chat_cancel_with_active_backend_settle_unknown ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 0.14s
test execution::tests::local_llama_cancel_with_active_backend_settles_unknown_without_redispatch ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 302 filtered out; finished in 1.16s
test hosted_stream_cut_by_the_runtime_fails_the_run_with_unknown_usage ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 11 filtered out; finished in 1.43s
test hosted_cancel_while_the_answer_is_held_settles_unknown_and_sends_nothing_more ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 1.80s
```

Note: the unflushed `ready` delta is dropped on the fault. The chunk error
returns from the worker at `capsules/model-provider/src/adapters.rs:2027`
before the flush arm (`:2021-2023`) runs again, and the delta stays in
`stream_state.delta_buffer` (`:2004`) until it goes out of scope. The test
asserts nothing about `text_delta` events for this reason.

Cases 1, 3 and 4 are pinned for today's behaviour, and case 1 is now pinned on
the hosted path too. In case 2 the conflicting retries, the completed-run retry
and the same-fingerprint retry of a still-open hosted run are pinned.

## Gaps for a Runtime reservation

Each row is Runtime-side and names the nearest existing Runtime code. No row
proposes a Runtime design; each names what is missing.

1. **Reserve a bounded amount before each dispatch.** Runtime-side (Anders).
   The Runtime has admission and a run binding, and no amount. The nearest
   pre-send reservation is the job-create key at
   `elastos/crates/elastos-server/src/api/model_provider_egress.rs:1428-1446`,
   taken at `:1533`; it reserves job identity only. Admission for a model run
   is `elastos/crates/elastos-runtime/src/provider/bridge.rs:926-1018`, which
   records offer, run, request and input hash. The broker's request admission
   is `egress.rs:419-510`, and the grant check is `egress.rs:768`. The
   capability check that authorises `runs_create` is
   `elastos/crates/elastos-server/src/provider_resource.rs:162-166`,
   `:641-657`.
2. **Settle the reservation from the reported outcome.** Runtime-side
   (Anders). The Runtime forwards the response and keeps no usage. The send is
   `egress.rs:1584`; the stream copy loop runs at `egress.rs:1626-1652`.
   `bridge.rs:1021-1032` lowers only a `pending` count and raises an `accepted`
   flag. `HostedRunBinding` has no amount
   (`bridge.rs:573-583`). For a stream the Runtime cuts, the provider records
   no usage at all (case 4), so the Runtime's account cannot come from the
   provider's usage; this is Runtime-side (Anders) and this report proposes no
   design.
3. **Release on cancel.** Runtime-side (Anders). A cancel is one more effect
   through the same forward (`egress.rs:1513-1583`); the binding is removed
   when a terminal response arrives (`bridge.rs:1034-1059`). No amount is
   released. For a hosted text run the provider sends no cancel effect at
   all: `hosted_cancel_while_the_answer_is_held_settles_unknown_and_sends_nothing_more`
   (`capsules/model-provider/tests/process.rs:1929`) shows the provider
   signals only its worker (`adapters.rs:1469-1473`) and settles
   `settlement_unknown` while the stand-in still holds the answer, so one
   connection and one request reach the socket and nothing more is sent. That
   the Runtime then sees the provider socket close with no terminal is read
   from the code, not asserted by that test: the Runtime's write to the closed
   socket fails in the copy loop
   (`elastos/crates/elastos-server/src/api/model_provider_egress.rs:1645-1648`),
   and the caller shuts the socket (`:531-533`). In grant-binding a release
   after an unknown outcome is refused
   (`model_release_after_unknown_is_refused`,
   `lab/grant-binding/src/ledger.rs:1134`) with
   `uncertain hold is not released` (`:1150`), so this case keeps the hold and
   agrees with gap 4. A Runtime hold for this case is Anders-owned, with no
   design here.
4. **Hold on `settlement_unknown`.** Runtime-side (Anders). The binding is
   removed on any terminal status, `settlement_unknown` included
   (`bridge.rs:1034-1059`). The real provider case is
   `hosted_cancel_while_the_answer_is_held_settles_unknown_and_sends_nothing_more`
   (`capsules/model-provider/tests/process.rs:1929`): the provider settles
   nothing itself. It reports `settlement_unknown`, keeps the unknown run
   truthful (`capsules/model-provider/src/state.rs:846-879`), and the Runtime
   keeps no corresponding hold. Grant-binding's Unknown settle is the model
   for that outcome: `settle(..., SettleOutcome::Unknown)`
   (`lab/grant-binding/src/ledger.rs:191-212`) keeps the hold, and
   `model_unknown_outcome_keeps_the_hold` (`:486-505`) asserts the refusal
   `unknown outcome keeps the hold` (`:497`). With the answer held, `forward`
   is still in `outbound.send()` (`egress.rs:1584`), so nothing has been
   written to the provider socket; when the answer arrives the copy-loop
   write to the closed socket fails
   (`elastos/crates/elastos-server/src/api/model_provider_egress.rs:1645-1648`)
   and the caller shuts the socket (`:531-533`). `retire_terminal_model_run`
   runs only on a later provider response with a terminal status
   (`elastos/crates/elastos-runtime/src/provider/bridge.rs:1437`, function at
   `:1034-1060`); whether the Runtime then polls `runs_get` is not checked.
5. **One account across concurrent and retried calls.** Runtime-side
   (Anders). Retries join one binding by the run id, and concurrent runs each
   add to `pending` (`bridge.rs:995`, `:1009`); the binding cap is 4096
   (`bridge.rs:45`, `:997`). That accounting covers run identity and pending
   effects, and has no spend field that concurrent and retried calls share.
   It exists only on macOS: `HostedRunBinding` (`bridge.rs:572-583`),
   `record_confined_model_run` (`:925-1018`) and `settle_confined_model_run`
   (`:1020-1032`) are `#[cfg(target_os = "macos")]`, and `send_raw` sets
   `dispatch_run` to `None` on other targets (`:1410-1411`). Other targets
   record no binding and keep no pending account.
   The provider side already joins a retry to the original run
   (`capsules/model-provider/src/state.rs:518-531`, `:5025-5026`).
   A run the provider refuses at its own ceiling sends nothing to the Runtime,
   yet records `usage` as `unknown`
   (`capsules/model-provider/tests/process.rs:2099`,
   `capsules/model-provider/src/state.rs:1352-1354`), the same value a sent run
   with no report records, so a Runtime account cannot tell "not sent" from
   "sent, not reported" by the usage field alone; that is Anders-owned, with no
   design.

## Tests still missing

No provider test models a reservation. The provider keeps no reservation, so
`capsules/model-provider/tests/process.rs` holds no reservation test and needs
none. The four rules are modelled only in `lab/grant-binding/src/ledger.rs`,
and each one maps to the grant-binding model test that already models it and
to its Runtime-side home (Anders), unchanged from the gaps above. The
Runtime-side test files are
`elastos/crates/elastos-runtime/src/provider/bridge.rs` (`mod tests` at
`:1857`, which compiles for every tested target; the macOS-only items are
`HostedRunBinding` (`:572-583`), `record_confined_model_run` (`:925-1018`) and
`settle_confined_model_run` (`:1020-1032`)) and
`elastos/crates/elastos-server/src/api/model_provider_egress.rs` (`mod tests`
at `:1883`). No test of these rules can pass until the Runtime reservation
contract exists.

1. **Reserve a bounded amount before each dispatch.** Modelled by
   `model_outstanding_hold_counts_toward_the_ceiling`
   (`lab/grant-binding/src/ledger.rs:366`): a held reservation counts toward
   the ceiling. Runtime-side home (Anders): gap 1, the two test modules above.
2. **One account across concurrent reserves.** Modelled by
   `model_concurrent_reserves_keep_one_ceiling`
   (`lab/grant-binding/src/ledger.rs:622`): two concurrent reserves leave one
   allowed and one refused at one ceiling. Runtime-side home (Anders): gap 5,
   the two test modules above.
3. **Settle from the measured figure; a cancel releases only a known hold.**
   Modelled by `model_settle_known_outcome_charges_the_measured_figure`
   (`lab/grant-binding/src/ledger.rs:423`) and
   `model_release_returns_the_unused_hold` (`:508`). A real hosted cancel
   settles `settlement_unknown`, and a release after that outcome is refused
   by `model_release_after_unknown_is_refused` (`:1134`) with
   `uncertain hold is not released` (`:1150`). Runtime-side home (Anders):
   gap 3, the two test modules above.
4. **Hold on `settlement_unknown`.** Modelled by
   `model_unknown_outcome_keeps_the_hold`
   (`lab/grant-binding/src/ledger.rs:486`): the hold stays at 10 with nothing
   charged, the reservation stays open, and a later known settle charges it.
   Runtime-side home (Anders): gap 4, the two test modules above.

## Next task

The same-fingerprint retry of an open hosted run is pinned in case 2 by
`hosted_retry_of_an_open_run_returns_the_same_run_and_sends_no_second_effect`
(`capsules/model-provider/tests/process.rs:1616`). Task 043 proves the
no-second-send half with `MP26`, which removes both stops for one run
(`src/state.rs:530`, `src/adapters.rs:768-774`). The four reservation rules
above wait on the Runtime side; the provider lane writes no reservation test,
because reservation, settle and release live in `lab/grant-binding` and the
real account is Runtime-side (Anders).

## What this report did not check

- The four cases' result blocks are from `093d1f798`; at this base two tests
  were re-run ("Runs at this base"), and no Runtime test was run.
- No network call, no model call, no key; a hosted effect reached only the
  Runtime socket stand-in.
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
7. **Tests prove it:** Yes for the 14 named behaviours. The same-fingerprint
   retry of a still-open hosted run is pinned in case 2. No provider test
   models a reservation: the four rules wait on the Runtime side, and the
   grant-binding model tests above prove them.
8. **Separate decisions:** Yes. Identity (`bridge.rs:926-1018`), admission
   (`state.rs:608-623`) and allowance (missing, gaps 1-5) stay distinct.
