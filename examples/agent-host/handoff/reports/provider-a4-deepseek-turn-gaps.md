# One real DeepSeek turn through the Runtime: what the tree still lacks

Task 031, discovery only. Base commit: `ce62fa9ce1eed4d7d33930604e72d077059740f6`
(`git rev-parse HEAD`). All line numbers below are at that commit.

This report books no M1 check as passed. A4 and A7 are not decided here. It
names gaps and their owners only.

## Two kinds of model call

A call by URL is a call where the test or the provider reaches the model's
address itself. The address can be an HTTP URL or a local engine socket.
Neither a Runtime grant nor the Runtime hosted transport carries the call.

A call through the Runtime grant and hosted transport is a call where the
Runtime authorises the run and carries it over its own hosted socket. The
provider holds no key.

Only the second kind can serve A4. A by-URL test shows that a model answers. It
gives no A4 evidence.

## What exists

| Test | `file:line` | Waits on | What it proves | Path (deciding `file:line`) | Serves A4 |
| --- | --- | --- | --- | --- | --- |
| `an_opt_in_real_model_keeps_one_packed_prefix_across_two_turns` | `examples/agent-host/src/lib.rs:10094` (`#[ignore]` at `:10093`) | `SPARKS_MODEL_URL` (read at `:10096` through `sparks_model_url`, `examples/agent-host/src/lib.rs:8505`) | Two consecutive turns with a byte-identical packed prefix; the model answers both turns; the engine's `/metrics` counters are read before and after. This path is not the A4 path | **by URL**: `sparks_http::post_json(&base_url, "/v1/chat/completions", ...)` at `examples/agent-host/src/lib.rs:10161` and `:10171`, with `base_url` from `:10096`. | no |
| `a_real_model_compaction_summary_is_judged_by_the_same_check` | `examples/agent-host/src/lib.rs:13239` (`#[ignore]` at `:13238`) | `SPARKS_MODEL_URL` (read at `:13241`) | The real summary reaches `compact_refusal` and `record_compact_summary` unchanged, and the same check refuses a summary that drops a required fact. This path is not the A4 path | **by URL**: `sparks_http::post_json(&base_url, "/v1/chat/completions", &body)` at `examples/agent-host/src/lib.rs:13262`. | no |
| `the_model_url_opt_in_is_one_guard` | `examples/agent-host/src/lib.rs:9277` | `SPARKS_MODEL_URL` only | That one guard reads the variable: no value, a value, no value again (`:9278`, `:9280`, `:9282`). It calls no model. | **no model call**: the whole test is the three environment reads and three assertions at `examples/agent-host/src/lib.rs:9277-9283`. | no |
| `qwen_artifact_verification_within_runtime_profile` | `capsules/model-provider/src/config.rs:943` (`#[ignore]` at `:942`) | `ELASTOS_TEST_QWEN_PATH` (read at `capsules/model-provider/src/config.rs:945`) | That the production artifact verifier accepts the exact 6,169,341,984-byte Qwen weights within the Runtime's 120 s profile. It calls no model. | **no model call**: `revalidate_local_artifact` on local bytes at `capsules/model-provider/src/config.rs:957`. | no |
| `opt_in_local_llama_evaluation_root_smoke` | `capsules/model-provider/src/execution.rs:4283` (`#[ignore]` at `:4282`) | `ELASTOS_MODEL_EVAL_ROOT` (`:4287`), optional `ELASTOS_MODEL_EVAL_MODEL` (`:4292`) | That a real local `llama-server` and a real GGUF answer one prompt through the provider's local engine branch. This path is not the A4 path | **by URL**: the provider starts the local engine and reaches its socket itself; `create_run` at `capsules/model-provider/src/execution.rs:4349` dispatches through `AdapterConfig::LocalLlamaCppText`, which skips the external-containment check at `capsules/model-provider/src/adapters.rs:1081`. | no |

Task history: the two agent-host opt-in tests came from agent-host tasks 015
and 016, on the one client that task 013 merged
(`examples/agent-host/handoff/LOG.md:52-53`).

No test in the tree takes the Runtime grant + hosted transport path with a real
model. The two halves exist only against stand-ins: the provider's hosted
socket control answers through a fake Runtime socket
(`capsules/model-provider/tests/confine/main.rs:1533-1560`), and the Runtime's
egress tests forward to loopback fixture URLs
(`hosted_job_effects_require_the_persisted_create_result` at
`elastos/crates/elastos-server/src/api/model_provider_egress.rs:2650` calls
`forward` at `:2740`, but its sink accepts nothing, which it asserts at
`:2748-2752`; the first forward whose sink accepts is
`hosted_job_create_with_lost_response_blocks_identical_retry` at `:2756`,
`forward` at `:2846`).

## The A4 path, as Anders states it

Anders (Flint's INBOX note, 26 Oct 23:18): A4 and A7 are proven together,
through the Runtime's model service and hosted transport, with an approved
OpenRouter or Venice connection and a validated DeepSeek offer.

### 1. The Runtime's model service

Exists. The Runtime registers the `model` sub-provider and requires an exact
identity and version (`elastos/crates/elastos-server/src/server_infra.rs:282-293`,
`:397-410`). A capsule reaches it through the Bus `providers.invoke` call with a
grant (`elastos/wit/elastos-bus-v1.wit:78-81`;
`elastos/crates/elastos-compute/src/providers/component.rs:392-440`). The
resource bridge checks the manifest bound and then the capability token
(`elastos/crates/elastos-server/src/resource_bridge.rs:253-270`, `:333-460`).
The capability names are canonical: `elastos://model/offers`,
`elastos://model/offers/sha256/<offer-hash>/runs`, and the run reads
(`elastos/crates/elastos-server/src/provider_resource.rs:636-688`), with
`read` for `offers_list`/`runs_get`/`runs_events` and `execute` for
`runs_create`/`runs_cancel` (`:162-166`). The Home HTTP model route serves `offers_list`
only to `assistant`, `home-agent` and `marketplace`, and the run operations
only to `assistant` and `home-agent`
(`elastos/crates/elastos-server/src/api/gateway_provider_proxy.rs:1688-1698`),
so an agent capsule uses the Bus path. The gateway path builds the run binding
from the verified Home launch token, and it refuses a caller-supplied binding
(`elastos/crates/elastos-server/src/api/gateway_provider_proxy.rs:3995-4030`;
test `elastos/crates/elastos-server/src/api/gateway_tests/model.rs:504-545`).

Missing: items 1, 2 and 4 below, plus the agent-side items 5 and 6.

### 2. The Runtime's hosted transport

Exists. The Runtime creates a private `hosted.sock`, grants the confined model
provider outbound access to that one socket, and passes its path in the Init
config (`elastos/crates/elastos-runtime/src/provider/bridge.rs:755-774`;
`elastos/crates/elastos-runtime/src/provider/registry.rs:784-785`, `:840-841`).
The provider sends each external effect to that socket as
`http://runtime.invalid/v1/hosted-effect` with the offer, run, request and
effect headers, and it adds no key (`capsules/model-provider/src/adapters.rs:42`,
`:45-70`, `:1982-1986`). The provider's answer leg is now pinned by
`hosted_answer_through_the_runtime_socket_completes_the_run_with_text_and_usage`
(`capsules/model-provider/tests/process.rs:1213`), through a stand-in, not a
real Runtime. The Runtime's broker accepts only that one request
shape and host, then checks the offer, the effect, the model selector, the
output cap, the destination and the run binding
(`elastos/crates/elastos-server/src/api/model_provider_egress.rs:536-600`,
`:629-690`). The broker reads the key from the Home and never gives it to the
provider (`:684`). The public routes are pinned to three routes: OpenRouter
chat, Venice chat and OpenRouter decisions (`:63-68`, `:1767-1769`). The
Runtime records each hosted run before dispatch and checks it on every effect
and every 250 ms
(`elastos/crates/elastos-runtime/src/provider/bridge.rs:926-1010`, `:1077-1092`,
`:1407-1437`;
`elastos/crates/elastos-server/src/api/model_provider_egress.rs:471-500`).
Owner consent is one Inbox decision per route, or one saved connection approval
for a saved connection (`elastos/crates/elastos-server/src/api/model_provider_egress.rs:282-290`;
`elastos/crates/elastos-server/src/api/model_provider_egress_decision.rs:319-470`;
approve/deny routes at `elastos/crates/elastos-server/src/api/gateway_inbox.rs:499-536`).

Missing: item 3 below.

### 3. An approved OpenRouter or Venice connection, and a validated DeepSeek offer

Exists. The Home save route validates the key and the model against the
provider's own model list before it writes the hosted offer and its secret
(`elastos/crates/elastos-server/src/api/gateway_home_system_ai_provider.rs:755-830`,
model-list check at `:813-815`; offer shape at
`elastos/crates/elastos-server/src/api/model_provider_config.rs:671-714`;
offer and secret written at `:1682-1745`). The provider config reload is the one
refresh call at `:1745-1747`. The hosted offer carries `connection-v1`, so the
broker uses the saved connection approval
(`elastos/crates/elastos-server/src/api/model_provider_config.rs:716-727`).

Missing: a real key, an approved connection, and a DeepSeek selector that the
provider lists. These are operator inputs, not code. No hosted offer or
Runtime config names a DeepSeek model id: the `deepseek-v4-flash` strings in
the tree are the `model` field of two by-URL tests
(`examples/agent-host/src/lib.rs:10153`, `:13256`); `home_system.rs:12071` holds
`"DeepSeek"`, a fixture connection name, not a model id.
This part is not checked here, because it needs a key and a network call.

### The Sparks or DGX engine is not a path

A DGX or Sparks-backed engine counts only after an explicit backend integration
and an installed lifecycle proof. Neither exists. `SPARKS_MODEL_URL` is a
test-only variable (`examples/agent-host/src/lib.rs:8505`), the provider has no
Sparks adapter among its five adapter kinds
(`capsules/model-provider/src/config.rs:286-325`), and the installed model
journey proves a local llama engine, not a host engine
(`scripts/ci-installed-journeys.py:511`, `:1081`). In production the provider
also refuses every external adapter that has no Runtime socket
(`capsules/model-provider/src/adapters.rs:111-128`), and the broker forwards
only to those three pinned routes
(`elastos/crates/elastos-server/src/api/model_provider_egress.rs:1767-1769`).
A private Sparks URL therefore has no production route. The Sparks or DGX model
reached by URL (`SPARKS_MODEL_URL`) is not the A4 path (Anders, 26 Oct).

## What is missing

Each item sits on the Runtime grant + hosted transport path.

1. **A capsule-issued model run is not bound to the verified caller.**
   Runtime-side (Anders). On the Home route the Runtime writes the binding from
   the verified launch token and rejects a caller-supplied one
   (`elastos/crates/elastos-server/src/api/gateway_provider_proxy.rs:3995-4030`;
   test `elastos/crates/elastos-server/src/api/gateway_tests/model.rs:504-545`).
   Build: the Runtime replaces the guest's identity fields with the verified
   principal, session and grant on the Bus path.

2. **The component launch supplies no verified principal.** Runtime-side
   (Anders). `elastos run` calls `Runtime::run_local`
   (`elastos/crates/elastos-server/src/run_cmd.rs:264-266`, the component
   path; the capsule path calls it at `:71`), which passes
   `None` (`elastos/crates/elastos-server/src/runtime.rs:231-233`), and the
   component keeps that `None`
   (`elastos/crates/elastos-compute/src/providers/component.rs:201-213`). The
   agent therefore has no verified name to bind its model run to. Build: the
   launch path carries a verified principal to the component bridge.

3. **Hosted transport exists on macOS only.** Runtime-side (Anders). The
   hosted socket, the broker and the run bindings are built in the macOS
   branch (`elastos/crates/elastos-server/src/server_infra.rs:1031-1096`;
   `elastos/crates/elastos-runtime/src/provider/bridge.rs:755-774`,
   `:926-1010`), and the provider refuses every external adapter off macOS
   (`capsules/model-provider/src/adapters.rs:111-128`). A Linux or Jetson
   installed proof of one hosted turn cannot run. A Mac proof is possible.
   Build: the Runtime owns a hosted socket and broker on Linux, then the
   provider's platform gate follows.

4. **The offer-resource name is a private Runtime rule.** Runtime-side
   (Anders). The grant resource hashes the offer id with SHA-256
   (`elastos/crates/elastos-server/src/provider_resource.rs:704-714`, used at
   `:650-657`). A guest must reproduce that rule to request the grant. The
   shared contract crate exposes the run id and the input hash but no offer
   hash (`elastos/crates/elastos-model-contract/src/lib.rs:200-216`). Build: the
   contract crate exposes one offer-resource function that the Runtime and the
   guest both call.

5. **No agent capsule asks for or uses a model grant.** lab-side, other lane
   (agent-host). The example capsule declares one journal capability and no
   model capability (`examples/agent-host/capsule.json:15-17`). Its lifecycle
   body exercises the journal fold and makes no model run
   (`examples/agent-host/src/lib.rs:4268` onward). Its hosted proposal records
   a step and sends nothing (`examples/agent-host/src/lib.rs:3341-3356`,
   `:1512-1545`). Build: one useful task that asks for `execute` on
   `elastos://model/offers/sha256/<offer>/runs`, creates one run, and records
   the answer through the existing `record_compact_summary`
   (`examples/agent-host/src/lib.rs:1571`).

6. **The agent cannot build the typed run request.** lab-side, other lane
   (agent-host). The example has no model-contract dependency
   (`examples/agent-host/Cargo.toml:11-14`), so it cannot build the `runs_create`
   body (`runtime_binding`, `input_hash`, text v2 input) or read the run
   (`elastos/crates/elastos-server/src/api/gateway_provider_proxy.rs:3995-4030`;
   `elastos/crates/elastos-server/src/provider_resource.rs:636-688`). Build: the
   agent uses the contract crate's builder and hash functions.

Count: Runtime-side 4, lab-side (other lane, agent-host) 2, lab-side (this
lane) 0.

## Smallest next task this lane could build

Goal: pin the provider's half of the Runtime hosted effect join. Today a drift
in those headers fails closed inside the Runtime with no named test. Only the
request line is observed
(`capsules/model-provider/tests/confine/main.rs:1533-1560`;
`capsules/model-provider/src/adapters.rs:4428`), while the Runtime refuses any
request with a missing or extra header
(`elastos/crates/elastos-server/src/api/model_provider_egress.rs:536-600`).

The test is
`hosted_run_posts_the_runtime_effect_headers_with_the_contract_run_id_and_no_key`.
It goes in `capsules/model-provider/tests/process.rs`, which already starts the
provider binary and builds a hosted offer
(`capsules/model-provider/tests/process.rs:534-600`). The test changes no `src`
file, so it needs no fresh Sasha note. It waits on no environment variable. It
uses the Init extra `runtime_hosted_socket` as a test seam and a local Unix
socket that answers `403` with `X-Elastos-Hosted-Access: refused`. No model, key
or network is involved. It runs on macOS, because off macOS the provider
refuses hosted dispatch before any socket
(`capsules/model-provider/tests/confine/main.rs:1537-1545`).

The test asserts one request with `POST /v1/hosted-effect`, `host:
runtime.invalid`, `x-elastos-offer-id` equal to the offer id, `x-elastos-run-id`
equal to `elastos_model_contract::model_run_id(&binding)`, `x-elastos-request-id`
equal to the request id, `x-elastos-effect: text`, no `authorization` header, and
no other `x-elastos-*` header.

The falsifier is one new entry in `capsules/model-provider/falsifiers.json` with
`command: "provider"`, `expect: "caught"` and the new test in `tests`. Use the
next free `MP` id (`MP21` at this commit; the file has 134 entries and none
touches the hosted headers). The edits change only `effect_request`
(`capsules/model-provider/src/adapters.rs:61-67`) to put the request id in
`x-elastos-run-id`, or add the bearer header on the hosted branch
(`capsules/model-provider/src/adapters.rs:1982-1986`). The named test must fail,
and only that test.

This task proves the provider's half only. It does not serve A4. A4 needs items
1-4 and an approved DeepSeek offer. If the next planner wants A4 evidence only,
this lane has none to build: the smallest A4 step is Runtime work plus an
operator key.

## Not checked

- Any network call, any key, any credential. No hosted effect was sent.
- The Sparks or DGX model. No test ran with `SPARKS_MODEL_URL` set.
- Any Runtime build, any installed Runtime, any installed model-provider.
- A real DeepSeek answer, a real OpenRouter or Venice connection, or one
  approved Inbox decision.
