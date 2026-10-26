# Intent planner lab (M1 check A15)

This crate is the lab model of one intent-planner flow. A person states an
intent. A local planner turns that intent into a typed plan. Each step names
one capability and one resource. The host renders a preview. The person
approves or rejects that preview.

Approval mints a real Runtime capability token for each step the Runtime can
name. The token is one write grant, one use, over the scoped journal resource.
Execution sends that token on the public elastos:bus bridge,
`handle_remote_request_with_audit_dir`. The planner is a fixed table. It calls
no hosted model.

## Journey

The person is the agent principal `ada`. The launching person on the bridge is
`person:local:intent-planner`. The intent is `summarize my notes into the journal`.

The plan has two steps:

1. Capability `read`, operation `read`, resource `localhost://UsersAI/ada/notes`.
   The preview marks this step BLOCKED. The missing capability is
   `scope_current_user_alias does not bind a UsersAI principal root`.
   No grant is minted.
2. Capability `write`, operation `write`, resource
   `localhost://Users/self/.AppData/Agents/ada/tasks/task-1/journal`.
   Approval mints one Runtime token for the scoped `localhost://Users/<id>/...`
   path, with `max_uses` 1. Execution sends that token on the bus bridge.

The public bridge answers the journal write with `principal_context_required`
and `principal-root storage requires an in-runtime protected storage bridge`.
The host records that as BLOCKED. It does not record a stored journal.

Rejecting records no grant. A later run records no effect and returns
`the plan was not approved`.

Changing the journal resource after approval makes the run return
`the plan was altered after approval`. The effect list stays empty.

Passing the approved plan plus another step makes the run return
`a step is outside the approved plan`. The effect list stays empty.

Running the same approval a second time returns
`the approved grant was already used`.

## What runs on the real Runtime

| Row | Where | Result |
| --- | --- | --- |
| Unapproved journal step | public bus bridge, empty token | denied: `missing_token` / `resource_invoke requires a capability token` |
| Altered journal resource | `CapabilityManager::validate`, the check the in-runtime bridge runs | denied: `wrong resource` |
| Same altered resource on the public bus bridge | `handle_remote_request_with_audit_dir` | BLOCKED. The bridge returns `principal_context_required` before `capability_denied`. Missing capability: `principal-root storage requires an in-runtime protected storage bridge`. `handle_component_resource_request` is `pub(crate)`. |
| First use of the allow-once grant | `CapabilityManager::validate` | allowed |
| Second use of that grant | `CapabilityManager::validate` | denied: `use limit exceeded` |
| Second use on the public bus bridge | same public function | BLOCKED. The bridge returns `principal_context_required` before the use counter. Same missing capability. |
| Approved journal write stored | public bus bridge | BLOCKED. Same missing capability. Nothing is stored. |

## What stays in this lab

The planner table, the preview text, and the approval gate stay here. The gate
is the plan binding: the approved bytes, the exact step list, and one use of
the recorded token. The Runtime has no plan object. `UsersAI` notes stay
BLOCKED. Session grants and standing mandates stay outside this check.

## Falsifier

`plants/F-A15-approval.txt` replaces `approval_check` with a body that returns
a fresh grant for every presented step. `model_planted_bugs_are_caught` runs
that plant and requires each of these tests to fail, then restores `src/lib.rs`:

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
