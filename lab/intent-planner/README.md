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
NFC `café` and NFD `cafe\u{301}` are different plans. Latin `ada` and
Cyrillic `аda` are different plans. A 256-byte field is refused, never
truncated. Approving `[notes, journal]` does not execute `[journal, notes]`.
A grant for `.../journal` does not cover `.../journal/foo/..`,
`.../journal/`, `.../Agents/Ada/...`, or `.../journa%6c`.
A Review from `host-1` does not run on `host-10`. An empty, NUL, `.`, `..`,
`a..b`, or `...` `host_id` is `ForeignHost` before any bus call.
`plan()` and `execute()` share one strict ASCII name grammar. A constructed
principal `_ada`, `ada.`, or `.ada` is `BadPrincipal` at execute. A NUL in
the intent is `BadIntent`. `notes/foo/..` is `OutsidePlan` at execute.
An empty or zero-step plan cannot be approved: the recorded choice is
Reject, no grant is minted, and execute returns `the plan has no steps`.
Duplicate resources in one plan (`[journal, journal]`) are refused at
approval: no grants, no bus calls, and execute returns
`the plan lists a step more than once`. Two steps may share an id when
their resources differ.
A bus reply `stored`, or any reply other than the exact storage BLOCKED
token, returns `the bus bridge did not answer` and does not spend the grant.
A failed execute leaves every grant unused, so a retry is not `GrantSpent`
and does not make another bus call. Multi-step execute checks every grant
before it spends or calls the bus. The minted token names the approved
step resource and URI; approving `.../secrets` does not mint a journal
token. A cloned review with a rewritten `host_id` is `ForeignHost`.

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
is the plan binding: the Host that minted the Review, `host_id` grammar
before the host_id compare, empty and duplicate step lists before mint or
bind, then the raw length-prefixed bind in plan step order. A matched
constructed principal that `plan()` would refuse (`_ada`, `ada.`, `.ada`),
a NUL intent, or a path that fails the segment grammar (including
`notes/foo/..` and embedded `..`) is then refused, never folded or
truncated. Differing invalid principals stay `PlanAltered` so the r3
collision plants stay CAUGHT. `covers` compares exact path components on
validated forms. `validate_journal_write` runs on that Host's manager after
the in-process library call confirms the exact BLOCKED token, and the
recorded token has one use. Every grant is checked unused and bound to
the approved resource before the first invoke. A parent path, a `..` segment, a trailing
slash, ASCII case, or percent-encoding does not cover a child journal.
`host-1` does not match `host-10`. Empty, NUL, `.`, `..`, `a..b`, and `...`
`host_id` are `ForeignHost` before invoke. A rewritten review `host_id`
that does not match the minting grant is `ForeignHost`. A `stored` bus reply, or any
reply other than the exact storage BLOCKED token, fails the run and does
not spend the grant. The Runtime has no plan object. `UsersAI` notes stay
BLOCKED (RA-5). A stored journal stays BLOCKED (RA-4). Session grants and
standing mandates stay outside this check.

`Grants::mint_journal_write` and `invoke_journal` stay callable as test
helpers. They skip preview and `Host::execute`.

## Falsifier

`plants/F-A15-approval.txt` replaces `approval_check` with a body that returns
a fresh grant for every presented step. `plants/M1-approve-check.txt` through
`plants/M8-principal.txt`, `plants/N1-length-prefix.txt` through
`plants/N10-used-before-bus.txt`, `plants/R3-1-nfc.txt` through
`plants/R3-12-constant-host.txt`, `plants/R4-1-host-dot.txt` through
`plants/R4-7-nul-intent.txt`, and `plants/R5-7a-partial-spend.txt`,
`plants/R5-11-wrong-mint.txt`, and `plants/R5-6d-rewritten-host.txt`
each remove one guard.
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
| R3-1 | NFC/NFD fold in `push_field` | `nfc_nfd_principals_do_not_collide` |
| R3-2 | Cyrillic `а` folded to `a` | `cyrillic_confusable_principal_is_a_different_plan` |
| R3-3 | length prefix `min(255)` truncate | `over_length_field_is_not_truncated` |
| R3-4 | `covers` resolves `.` and `..` | `dotdot_path_does_not_cover_journal` |
| R3-5 | `covers` strips a trailing `/` | `trailing_slash_path_does_not_cover_journal` |
| R3-6 | `covers` is ASCII case-insensitive | `ascii_case_path_does_not_cover_journal` |
| R3-7 | `classify` trims, case-folds, prefix-matches | `blocked_reply_is_a_whole_token` |
| R3-8 | empty or NUL `host_id` skipped | `empty_or_nul_host_id_is_foreign` |
| R3-9 | `canonical()` sorts steps by resource | `approved_step_order_is_bound` |
| R3-10 | `covers` percent-decodes | `percent_encoded_path_does_not_cover_journal` |
| R3-11 | mark `used` before `validate` | `failed_execute_does_not_spend_the_grant` |
| R3-12 | `new_host_id` always `host-1` | `unused_review_does_not_run_on_a_second_host` |
| R4-1 | `validated_name` drops exact `.` / `..` | `dot_or_dotdot_host_id_is_foreign` |
| R4-2 | delete the `execute` path loop | `dotdot_notes_path_is_refused_at_execute` |
| R4-3 | execute uses `validated_name` not `plain_principal` | `constructed_plain_principal_is_refused_at_execute` |
| R4-4 | empty step list allowed | `empty_plan_cannot_be_approved` |
| R4-5 | duplicate steps allowed | `duplicate_journal_steps_are_refused` |
| R4-6 | `validated_name` keeps embedded `..` | `embedded_dotdot_host_id_is_foreign` |
| R4-7 | NUL in intent skipped | `nul_intent_is_refused_at_execute` |
| R5-7a | ready-all-grants loop deleted | `failed_two_step_execute_does_not_spend_the_first_grant` |
| R5-11 | mint always journals | `secrets_path_does_not_mint_a_journal_token` |
| R5-6d | grant `host_id` bind skipped | `rewritten_host_id_does_not_run_on_a_second_host` |

## Checks

From the repository root, Linux or macOS:

```bash
export RUST_TEST_THREADS=2
cargo fetch --locked --manifest-path lab/intent-planner/Cargo.toml
cargo fmt --manifest-path lab/intent-planner/Cargo.toml -- --check
cargo clippy --manifest-path lab/intent-planner/Cargo.toml --locked --offline --all-targets -- -D warnings
cargo test --locked --offline --manifest-path lab/intent-planner/Cargo.toml -- --nocapture
```
