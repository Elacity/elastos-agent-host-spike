# RA-5 A `UsersAI` alias that resolves to the verified agent principal's root

Rank 5 of 7. Effort M (2 points). Checks named: A15 (1). Score 0.50.

Source: `lab/intent-planner/` in #284 (the notes step of the A15 journey). The
Runtime text in `lab/agent-conformance/GAPS.md` ("UsersAI binding") and in
`examples/agent-host/handoff/USERSAI-JOURNAL.md` describes the same change.

## The ask

A guest that names `UsersAI/self` reaches the root of the agent principal that
the Runtime verified for the launch. This works like `Users/self`, which the
Runtime already resolves to the launching person's root. A request for another
agent's `UsersAI` root is refused.

## Checks it unblocks

| Check | Row that names it | Where | What else it needs |
| --- | --- | --- | --- |
| A15 | Step 1 of the journey, `read` of `localhost://UsersAI/ada/notes`, previewed as BLOCKED | #284 `README.md`, `src/lib.rs` | RA-4 (the read goes over the same bridge) and a live probe in the lab (see Acceptance test) |

The agent-conformance rows blocked on "UsersAI binding" overlap this ask. Their
labels carry no A number, so they are not counted here (see "Related").

## Today: evidence

| Citation | Text on that line | What it shows |
| --- | --- | --- |
| `elastos/crates/elastos-server/src/resource_bridge.rs:803` | `fn scope_current_user_alias(` | The one function that resolves `Users/self`. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:811` | `if is_unscoped_current_user_alias(&rooted) {` | It handles the `Users/self` alias. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:840` | `Ok(rooted)` | Any other path, `UsersAI` included, leaves unchanged. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:703` | `fn principal_root_read_write_uri(operation: &str, request: &serde_json::Value) -> Option<String> {` | The test for "is this principal-root storage". |
| `elastos/crates/elastos-server/src/resource_bridge.rs:712` | `rooted.starts_with("localhost://Users/").then_some(rooted)` | It accepts the `Users` root only. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:473` | `let localhost_root = crate::auth::principal_localhost_root(principal_id);` | The protected storage path derives the root from `principal_localhost_root`. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:494` | `match crate::auth::load_principal_root_protection(data_dir, principal_id, &localhost_root) {` | The protection record is looked up by principal and root. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:43` | `pub principal_id: Option<String>,` | The bridge context holds one principal id. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:196` | `let uri = scope_current_user_alias(uri, principal_id)?;` | The alias runs before the manifest and grant checks. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:1344` | `let scoped_resource = match scope_current_user_alias(resource, principal_id) {` | It also runs on a capability request, so grants name the resolved root. |
| `elastos/crates/elastos-server/src/auth.rs:7037` | `pub fn principal_localhost_root(principal_id: &str) -> String {` | The only principal-to-root mapping. |
| `elastos/crates/elastos-server/src/auth.rs:7039` | `localhost://Users/` | It maps to `Users/<hash>`. It has no `UsersAI` form. |
| `elastos/crates/elastos-common/src/localhost.rs:16` | `"UsersAI",` | `UsersAI` is a canonical local root. |
| `elastos/crates/elastos-common/src/localhost.rs:118` | `const OWNER_ONLY_ROOTS: &[&str] = &["Users", "UsersAI"];` | Both roots are owner-only. |
| `elastos/crates/elastos-server/src/api/routes.rs:131` | `principal_id is not launch authority; use signed launch_grant` | The Runtime does not take a principal that the caller names. |
| `docs/AGENT_ARCHITECTURE.md:332` | `Agent state is rooted under the agent principal's` | The documented state ownership. |
| `docs/AGENT_ARCHITECTURE.md:341` | `This document does not freeze the exact path layout below` | The layout under `UsersAI` is not fixed. |
| `docs/AGENT_ARCHITECTURE.md:343` | `applications may depend on them.` | A versioned object contract comes first. |
| `examples/agent-host/handoff/USERSAI-JOURNAL.md:12` | `Nothing maps a principal to a` | Nothing maps a principal to a `UsersAI/<id>` root yet. |
| `examples/agent-host/handoff/USERSAI-JOURNAL.md:23` | `UsersAI/self/.AppData/ElastOS/AgentHost/tasks/<task-id>/journal` | The journal contract names `UsersAI/self`. |
| `examples/agent-host/handoff/USERSAI-JOURNAL.md:24` | `The guest only ever names` | The Runtime would rewrite `self` to the agent principal's root and refuse other roots. |
| `lab/agent-conformance/GAPS.md:605` | `UsersAI binding` | The agent-conformance blocker for the same change. |
| `lab/agent-conformance/GAPS.md:619` | `Anders must bind the existing component launch to a verified agent principal,` | The lab's wording of the Runtime change. |
| `lab/agent-conformance/GAPS.md:625` | `whose principal context is` | The CLI launch carries no principal today. |
| `#284 lab/intent-planner/src/runtime_bridge.rs:26` | `pub const USERS_AI_GAP: &str = "scope_current_user_alias does not bind a UsersAI principal root";` | The gap text the lab records. |
| `#284 lab/intent-planner/src/runtime_bridge.rs:45` | `format!("localhost://UsersAI/{agent}/notes")` | The lab names the agent in the path. |
| `#284 lab/intent-planner/src/lib.rs:364` | `pub fn runtime_gap(step: &Step) -> Option<&'static str> {` | The lab decides "blocked" in its own function. |
| `#284 lab/intent-planner/src/lib.rs:372` | `} else if step.resource.starts_with("localhost://UsersAI/") {` | Any `UsersAI` step is blocked by this rule. It does not call the Runtime. |
| `#284 lab/intent-planner/src/lib.rs:559` | `missing: runtime_bridge::USERS_AI_GAP.to_owned(),` | The test asserts the notes step is BLOCKED. |
| `#290 lab/owned-storage/src/lib.rs:189` | `let owned_root = format!("UsersAI/{identity}/{session}/{instance}");` | A9's lab names identity, session and instance in the root. |
| `lab/grant-binding/src/lib.rs:377` | `.bind_grant(agent, "UsersAI/agent-1/notes", rights())` | The grant-binding lab names the agent in the root. |

## Smallest change

1. In `scope_current_user_alias` (`resource_bridge.rs:803-840`), add the
   `UsersAI/self` rule next to the `Users/self` rule. It resolves to a root
   derived from the agent principal and refuses any other `UsersAI/<root>`.
2. In `principal_root_read_write_uri` (`:703-712`), accept the `UsersAI` root,
   so the protected storage path treats it like `Users`.

Both are in one file. They need three decisions first.

- **The path layout.** `AGENT_ARCHITECTURE.md:341-343` says a versioned object
  contract comes before any application depends on it. The labs use two
  naming styles. The journal contract has the guest name `UsersAI/self`
  (`USERSAI-JOURNAL.md:23`). The A15 lab names the agent (`UsersAI/ada/notes`),
  and A9's lab names identity, session and instance. The alias should wait for
  that contract.
- **The agent principal.** The bridge context holds one principal id
  (`resource_bridge.rs:43`). `GAPS.md:619-625` says the launch must carry a
  verified agent principal and that the CLI launch carries none today. Whether
  that id is the agent principal for an agent launch, or a second field is
  added, is open.
- **The protection record.** The protected path looks up protection by principal
  and `Users` root (`resource_bridge.rs:473`, `:494`). Because the record is
  keyed by root, a `UsersAI` root would need a record of its own. This is an
  inference from the key. No document states that contract.

## How it fits the capability and grant model

The alias works at the same point as `Users/self`, before the manifest bound and
the grant match (`resource_bridge.rs:196`, `:1344`). Grants then name the
resolved root, as they do for a person. An agent has one authority model with a
person (Principle 7). Only the root differs.

## Risks

- **Fixing a layout too early.** The root layout is not frozen
  (`AGENT_ARCHITECTURE.md:341`). A Runtime alias before the contract gives a
  second migration.
- **Folder names from principal text.** The person mapping uses a hash of the
  principal id (`auth.rs:7039`). The labs' `UsersAI/<name>/...` roots use plain
  names. If the Runtime used plain names, host file systems that fold case
  could map two names to one directory. This is an inference from the two
  naming styles. No lab measured it.
- **A caller-named principal.** The Runtime refuses a caller-named principal at
  launch (`routes.rs:131`). The agent principal must come from the same kind of
  verified source.
- **Review class.** The change is in the bridge and the principal boundary.
  `AGENTS.md` requires an independent adversarial review.

## Acceptance test already written

- **The notes step in #284.** Class: STATIC. `runtime_gap` returns the gap for
  any `UsersAI` resource without calling the Runtime (`lib.rs:372`), and
  `approved_plan_executes_with_the_approved_grants` asserts it (`lib.rs:559`).
  When this ask lands, nothing in the lab turns red or green. The lab needs a
  live probe of the notes read, in the style of `invoke_journal`, before the
  step can leave BLOCKED. That probe does not exist.
- No `#[ignore]` row names this ask.

## Related, not counted

agent-conformance blocks five rows on "UsersAI binding" (`GAPS.md:605-640`):
`agent_memory_under_own_principal`,
`real_agent_host_journal_under_usersai_principal`,
`real_agent_host_gets_no_ungranted_authority`,
`agent_cannot_read_other_agent_memory`,
`agent_can_read_human_space_with_grant`. `GAPS.md` gives those rows no M1 check
number, so this file does not count them. Three of them also wait on a typed
launch selector and result (AC-002-ARGS), which this proposal leaves out. One
change may serve both lanes. Anders decides.

## Not shown

- No Runtime change was run.
- No lab measured a `UsersAI` read through any Runtime path. The gap rests on
  the source lines above.
