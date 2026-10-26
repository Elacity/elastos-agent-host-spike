# Intent planner lab (M1 check A15)

This crate is the lab model of one intent-planner flow. A person states an
intent. A local planner turns that intent into a typed plan. Each step names
one capability and one resource. The host renders a preview. The person
approves or rejects that preview. Execution runs after an approval, and it
runs the approved steps with the grants recorded for those steps.

The planner is a fixed table. It calls no hosted model.

This folder is the check. It leaves the Runtime unchanged, and an effect here
is a record of the step the host allowed. A real effect still needs the
Runtime to mint the capability token and a provider to perform the operation.

## Journey

The person is the agent principal `ada`. The intent is `summarize my notes
into the journal`.

The plan has two steps:

1. Capability `read`, operation `read`, resource `UsersAI/ada/notes`.
2. Capability `write`, operation `append`, resource
   `UsersAI/ada/.AppData/Agents/agent-host/journal`.

The preview lists those steps. Approving records one allow-once grant for
each step. The grant names that step's action, operation and resource.
Running the approved steps records one effect per grant, and the effect
carries that grant's token.

Rejecting records no grant. A later run records no effect and returns
`the plan was not approved`.

Changing the journal resource to `UsersAI/ada/secrets` after approval makes
the run return `the plan was altered after approval`. The effect list stays
empty.

Passing the approved plan plus a step that runs `UsersAI/ada/Projects/build`
makes the run return `a step is outside the approved plan`. The effect list
stays empty. The host runs the whole call or none of it.

Running the same approval a second time returns `the approved grant was
already used`.

## Where the rules come from

A Runtime capability token names a resource and an action (`read`, `write`,
`execute`, `message`). A resource call also names an operation. The shell
grants the token, and the caller presents it. See
`elastos/crates/elastos-runtime/src/capability/token.rs` and
`handle_grant_capability` in
`elastos/crates/elastos-runtime/src/handler/request_handler.rs`.

The Agent Host dispatches a prepared step when a grant id is recorded. A
prepared step with an empty grant becomes denied. See `dispatch` in
`examples/agent-host/src/lib.rs`.

`docs/AGENT_ARCHITECTURE.md` says a model proposal carries no authority, Home
presents the approval, and the visible card is not the grant. Allow once
authorizes one exact operation. This lab is that allow-once path. A session
grant and a standing mandate stay outside this check.

The principal is one agent id, the same shape as `journal_id_ok` in the Agent
Host: 1 to 64 bytes, `[a-z0-9][a-z0-9._-]*`, and it does not end in `.`.
Resources sit under `UsersAI/<principal>/...`, the agent root from
`docs/AGENT_ARCHITECTURE.md` and `lab/grant-binding`. This crate does not
link to that crate.

## Refusals

| Input | Reason |
| --- | --- |
| Principal is outside the agent-id rule | principal is not a single plain name |
| Intent is outside the planner table | the planner has no steps for this intent |
| The review rejected the plan | the plan was not approved |
| The plan bytes differ from the approved plan | the plan was altered after approval |
| The run list differs from the approved steps | a step is outside the approved plan |
| The same approval runs again | the approved grant was already used |

A refused run leaves the effect list as it was.

## Falsifier

`plants/F-A15-approval.txt` replaces `approval_check` with a body that
returns a fresh grant for every presented step. `model_planted_bugs_are_caught`
runs that plant and requires each of these tests to fail, then restores
`src/lib.rs`:

- `approved_plan_executes_with_the_approved_grants`
- `rejected_plan_executes_nothing`
- `plan_altered_after_approval_is_refused`
- `extra_step_injected_at_run_time_is_refused`
- `approved_grant_runs_once`

## Checks

From the repository root:

```bash
export RUST_TEST_THREADS=2
cargo fmt --manifest-path lab/intent-planner/Cargo.toml -- --check
cargo clippy --manifest-path lab/intent-planner/Cargo.toml --locked --offline --all-targets -- -D warnings
cargo test --locked --offline --manifest-path lab/intent-planner/Cargo.toml
```
