# Intent planner lab (M1 check A15)

This crate is the lab model of one intent-planner flow. A person states an
intent. A local planner turns that intent into a typed plan. Each step names
one capability and one resource. The host renders a preview. The person
approves or rejects that preview.

Approval mints a lab `CapabilityManager` token for each step the Runtime can
name. The token is one write grant, one use, over the scoped journal resource.
Execution sends that token through in-process
`handle_remote_request_with_audit_dir`. That call is a linked crate function
in the test process. It is not a spawned `elastos` process.

The planner is a fixed table. It calls no hosted model.

## Journey

The person is the agent principal `ada`. The launching person on the bridge is
`person:local:intent-planner`. The intent is `summarize my notes into the journal`.

The plan has two steps:

1. Capability `read`, operation `read`, resource `localhost://UsersAI/ada/notes`.
   The preview marks this step BLOCKED. The missing capability is
   `scope_current_user_alias does not bind a UsersAI principal root`.
   No grant is minted. The Host records this from `runtime_gap`. It does not
   call the bus.
2. Capability `write`, operation `write`, resource
   `localhost://Users/self/.AppData/Agents/ada/tasks/task-1/journal`.
   Approval mints one lab token for the scoped `localhost://Users/<id>/...`
   path, with `max_uses` 1. Execution sends that token through the in-process
   public bus entry.

The in-process public entry answers the journal write with
`principal_context_required` and
`principal-root storage requires an in-runtime protected storage bridge`.
The host records that as BLOCKED. It does not record a stored journal.

Rejecting records no grant. A later run records no effect and returns
`the plan was not approved`.

Changing the journal resource after approval makes the run return
`the plan was altered after approval`. The effect list stays empty.

Reordering the approved steps, or passing the approved plan plus another
step, makes the run return `a step is outside the approved plan`. The effect
list stays empty.

Approval for principal `ada` does not execute a plan whose principal is
`bea`. The run returns `the plan was altered after approval`.

A Review minted by one Host does not run on a second Host. The run returns
`the review was minted by another host`. The effect list stays empty.

Running the same approval a second time returns
`the approved grant was already used`.

A constructed plan `principal="a\nb"` / `intent="c"` does not execute as
`principal="a"` / `intent="b\nc"`. `ada` and `ada ` are different plans.
A grant for `.../Agents/ada/tasks` does not cover the child journal.
A Review from `host-1` does not run on `host-10`.
A bus reply `stored`, or any reply other than the explicit storage BLOCKED
text, returns `the bus bridge did not answer` and does not spend the grant.
A failed execute leaves the grant unused, so a retry is not `GrantSpent`.

## Rows

None of these rows is a Runtime process. A spawned `elastos` binary over the
bus is NEEDS RUNTIME. See `RUNTIME-ASK.md`.

| Row | Where the call goes | Class |
| --- | --- | --- |
| Preview of the two-step plan | `preview()` in this crate | lab |
| Notes step BLOCKED (`UsersAI` alias) | `runtime_gap()` string, no bus call | BLOCKED (STATIC). Needs RA-5 |
| Reject / altered plan / extra step / reorder / spent grant / other principal | `Host::approval_check` | lab |
| Review from another Host | `Host::approval_check` (`host_id`) | lab |
| Unapproved journal step `missing_token` | in-process `handle_remote_request_with_audit_dir` | evidence (library) |
| Altered journal resource `wrong resource` | lab `CapabilityManager::validate` | evidence (library) |
| Same altered resource on the public bus entry | in-process `handle_remote_request_with_audit_dir` | BLOCKED. The entry returns `principal_context_required` before `capability_denied`. Needs RA-4 |
| First use of the allow-once grant | lab `CapabilityManager::validate` | evidence (library) |
| Second use `use limit exceeded` | lab `CapabilityManager::validate` | evidence (library) |
| Second use on the public bus entry | in-process public function | BLOCKED. Same storage refusal first. Needs RA-4 |
| Approved journal write stored | in-process public function | BLOCKED. Nothing is stored. Needs RA-4 |
| BLOCKED journal effect from an in-process library call | `execute` → `invoke_journal` with an audit dir | evidence (library). The test reads `component.invoke` audit records. The recorded BLOCKED text is `classify` of the actual reply. A `stored` reply fails the run. |
| Spawned `elastos` binary over the bus | not in this lab | NEEDS RUNTIME |

## What stays in this lab

The planner table, the preview text, and the approval gate stay here. The gate
is the plan binding: the Host that minted the Review, length-prefixed
canonical bytes (including the principal, compared as exact bytes), the
exact ordered step list, `covers` by exact path components, `validate_journal_write`
on that Host's manager after the in-process library call confirms the
explicit BLOCKED reply, and one use of the recorded token. A parent path
does not cover a child journal. `host-1` does not match `host-10`. A
`stored` bus reply, or any reply other than the explicit storage BLOCKED
text, fails the run and does not spend the grant. The Runtime has no plan
object. `UsersAI` notes stay BLOCKED (RA-5). A stored journal stays BLOCKED
(RA-4). Session grants and standing mandates stay outside this check.

`Grants::mint_journal_write` and `invoke_journal` stay callable as test
helpers. They skip preview and `Host::execute`.

## Falsifier

`plants/F-A15-approval.txt` replaces `approval_check` with a body that returns
a fresh grant for every presented step. `plants/M1-approve-check.txt` through
`plants/M8-principal.txt` and `plants/N1-length-prefix.txt` through
`plants/N10-used-before-bus.txt` each remove one guard.
`model_planted_bugs_are_caught` requires every named test to fail, then
restores the planted file:

| Plant | Guard removed | Named test |
| --- | --- | --- |
| F-A15-approval | whole `approval_check` | the five Host refusal tests |
| M1 | Approve check | `rejected_plan_executes_nothing` |
| M2 | canonical bytes | `plan_altered_after_approval_is_refused` |
| M3 | ordered step equality; length kept | `reordered_approved_steps_are_refused` |
| M4 | `used` token list | `approved_grant_runs_once` |
| M5 | `covers`; first grant used | `grant_lookup_uses_covers_for_the_exact_resource` |
| M6 | `validate_journal_write` | `execute_spends_the_allow_once_grant_at_the_lab_manager` |
| M6-host | Review `host_id` | `unused_review_does_not_run_on_a_second_host` |
| M7 | `invoke_journal`; hardcoded BLOCKED | `blocked_journal_effect_comes_from_an_in_process_library_call` |
| M8 | `principal` in `canonical()` | `approval_for_one_principal_does_not_execute_for_another` |
| N1 | length prefix on `push_field` | `newline_fields_do_not_collide` |
| N2 | `step.resource` in `canonical()` | `plan_altered_after_approval_is_refused` |
| N3 | `push_field` trims whitespace | `trailing_space_principal_is_a_different_plan` |
| N4 | `covers` treats a parent as a prefix | `prefix_resource_does_not_cover_a_child_journal` |
| N5 | last path segment only; `step_id` dropped | `grant_lookup_uses_covers_for_the_exact_resource` |
| N6 | bus reply ignored; hardcoded BLOCKED | `approved_plan_refuses_a_stored_bus_reply` |
| N7 | `host_id` `starts_with` | `prefix_host_id_stays_foreign` |
| N8 | mint with `max_uses: None` | `execute_spends_the_allow_once_grant_at_the_lab_manager` |
| N9 | validate the guest URI | `execute_spends_the_allow_once_grant_at_the_lab_manager` |
| N10 | mark `used` before the bus | `failed_execute_does_not_spend_the_grant` |

## Checks

From the repository root, Linux or macOS:

```bash
export RUST_TEST_THREADS=2
cargo fetch --locked --manifest-path lab/intent-planner/Cargo.toml
cargo fmt --manifest-path lab/intent-planner/Cargo.toml -- --check
cargo clippy --manifest-path lab/intent-planner/Cargo.toml --locked --offline --all-targets -- -D warnings
cargo test --locked --offline --manifest-path lab/intent-planner/Cargo.toml -- --nocapture
```
