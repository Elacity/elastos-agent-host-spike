# RA-4 A way to reach the in-runtime protected storage bridge for the A15 journal step

Rank 4 of 7. Effort S (1 point) for the smallest literal change. Checks named:
A15 (1). Score 1.00.

Source: `lab/intent-planner/` in #284 (`README.md`, `src/runtime_bridge.rs`,
`src/lib.rs`).

## The ask

The A15 host can send an approved journal write through the Runtime's own
protected storage path, so the write is stored under the person's protected
root. Today the only public path refuses that write.

## Checks it unblocks

| Check | Rows that name it | Where | What else it needs |
| --- | --- | --- | --- |
| A15 | Three BLOCKED rows of the "What runs on the real Runtime" table: altered resource on the public bridge, second use on the public bridge, approved journal write stored | #284 `README.md` | Lab assertions for the stored outcome (not written). The notes step also needs RA-5. |

## Today: evidence

| Citation | Text on that line | What it shows |
| --- | --- | --- |
| `elastos/crates/elastos-server/src/resource_bridge.rs:870` | `pub(crate) async fn handle_component_resource_request(` | The in-runtime bridge entry is crate-private. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:1153` | `pub async fn handle_remote_request_with_audit_dir(` | The public entry that #284 calls. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:1250` | `} else if principal_root_read_write_uri(&dispatch.operation, &dispatch.request)` | On the public path a principal-root read or write is refused. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:1255` | `"principal-root storage requires an in-runtime protected storage bridge",` | The refusal text the lab records. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:333` | `async fn authorize_and_dispatch_resource_invoke(` | The in-runtime path: manifest, token, validate, then storage. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:392` | `.validate(` | The in-runtime path validates the token with the capsule id. For a principal-root resource the public path refuses before the request reaches any validation. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:411` | `if let Some(refusal) = agents_area_dispatch_refusal(&dispatch) {` | Then the agents-area rule. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:415` | `if let Some(response) = protected_principal_root_resource_response(` | Then the protected principal-root storage. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:499` | `"Agent journals under .AppData/Agents/ require principal-root protection",` | The storage step needs principal-root protection to be active. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:36` | `pub struct BridgeContext {` | The context the entry takes. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:43` | `pub principal_id: Option<String>,` | The principal is a plain string the caller sets. |
| `elastos/crates/elastos-server/src/api/routes.rs:131` | `principal_id is not launch authority; use signed launch_grant` | The launch route refuses a principal id that the caller names. |
| `elastos/crates/elastos-server/src/auth.rs:5011` | `pub fn store_principal_root_protection(` | A public function stores a principal-root protection record. |
| `elastos/crates/elastos-server/src/auth.rs:10312` | `#[cfg(test)]` | The helper the Runtime's own test uses exists only in tests. |
| `elastos/crates/elastos-server/src/auth.rs:10313` | `pub(crate) fn store_test_principal_root_protection(` | That helper. |
| `elastos/crates/elastos-server/src/runtime.rs:128` | `.block_on(crate::resource_bridge::handle_component_resource_request(` | The Runtime calls the in-runtime entry for its own component launches. |
| `elastos/crates/elastos-server/src/runtime.rs:1036` | `crate::auth::store_test_principal_root_protection(&data_dir, AGENT_HOST_PERSON);` | The Runtime's own test sets up protection with the test helper. |
| `elastos/crates/elastos-server/src/runtime.rs:1112` | `#[ignore = "loads examples/agent-host/agent-host.component.wasm` | The Runtime's own end-to-end journal test is ignored by default. |
| `elastos/crates/elastos-server/src/runtime.rs:1113` | `async fn the_agent_host_writes_and_reads_its_journal_through_the_real_bridge() {` | It stores and reads back a journal through the in-runtime bridge. |
| `#284 lab/intent-planner/src/runtime_bridge.rs:7` | `that function is` | #284 states that the in-runtime entry is `pub(crate)`. |
| `#284 lab/intent-planner/src/runtime_bridge.rs:142` | `pub fn invoke_journal(token: &str, guest_uri: &str)` | The lab sends the journal write on the public entry. |
| `#284 lab/intent-planner/README.md:52` | `Same altered resource on the public bus bridge` | Row 1 of the BLOCKED rows. |
| `#284 lab/intent-planner/README.md:55` | `Second use on the public bus bridge` | Row 2 of the BLOCKED rows. |
| `#284 lab/intent-planner/README.md:56` | `Approved journal write stored` | Row 3 of the BLOCKED rows. Nothing is stored. |
| `#284 lab/intent-planner/src/lib.rs:548` | `fn approved_plan_executes_with_the_approved_grants() {` | This test asserts the journal step is BLOCKED. |
| `#284 lab/intent-planner/src/lib.rs:702` | `fn runtime_denies_an_altered_journal_resource() {` | The manager-level check of "wrong resource" passes today. |
| `#284 lab/intent-planner/src/lib.rs:719` | `fn runtime_denies_a_reused_single_use_grant() {` | The manager-level check of "use limit exceeded" passes today. |
| `#284 lab/intent-planner/src/lib.rs:736` | `fn public_bridge_blocks_journal_storage_before_token_checks() {` | This test asserts the public bridge refuses first. |
| `#284 lab/intent-planner/src/lib.rs:743` | `assert_ne!(reply.code, "capability_denied");` | It requires that the answer is not `capability_denied`. |

## Smallest change

Form A, the literal change. Make `handle_component_resource_request`
(`resource_bridge.rs:870`) `pub`. This is one keyword. It is not enough on its
own. The lab also needs principal-root protection active for its data
directory, because the storage step refuses an agent journal path without it
(`resource_bridge.rs:499`). The helper the Runtime's own test uses is
test-only (`auth.rs:10312`). A public `store_principal_root_protection` exists
(`auth.rs:5011`). Whether it is enough for a lab was not tested.

Form B, no new entry. Keep the function crate-private. Take the evidence for
"journal stored" from a Runtime-tree test, as `runtime.rs:1113` already does
for the Agent Host. The three lab rows then stay BLOCKED and cite that test.
This flips nothing in the lab.

Anders chooses between them. Form A is cheaper in lines. Form B is cheaper in
risk (see the first risk).

## How it fits the capability and grant model

The in-runtime path already runs the checks the A15 journey needs, in this
order: manifest bound, token present, token validated for the capsule id, agents
area rule, then protected storage (`resource_bridge.rs:333-415`). The ask adds
no grant type and no new check. It makes the existing path reachable for one
journey.

## Risks

- **The principal becomes a caller's claim.** `BridgeContext.principal_id` is a
  plain string (`resource_bridge.rs:43`). The launch route refuses a principal
  id that the caller names and requires a signed launch grant
  (`routes.rs:131`). A `pub` entry lets any linked crate state a principal.
  This touches the principal boundary (Principles 3 and 7). If Anders picks
  Form A, the entry needs a principal that the Runtime verified. How to carry
  that is his decision. This proposal does not design it.
- **It proves the bridge, not the launch path.** A direct call skips the
  Runtime's own launch. On the launch route the principal comes from a signed
  launch grant (`routes.rs:131`). A15's check is about preview and approval, so
  the bridge alone may be enough. Anders decides.
- **The answer order changes.** Today the public bridge refuses before it
  validates (`:1250`). After Form A the lab's ordering test fails by design.
- **Review class.** The change is in the bridge and the principal boundary.
  `AGENTS.md` requires an independent adversarial review.

## Acceptance test already written

- **`public_bridge_blocks_journal_storage_before_token_checks`** and
  **`approved_plan_executes_with_the_approved_grants`** in #284. Class:
  TRIPWIRE. Both assert today's BLOCKED text. After Form A they fail. That
  failure is the signal to replace them with the stored outcome. The PASS
  assertions are not written: a stored journal after approval, `wrong resource`
  for an altered path, and `use limit exceeded` on the second use, all on the
  bridge.
- The same two denials already pass at manager level
  (`runtime_denies_an_altered_journal_resource`,
  `runtime_denies_a_reused_single_use_grant`). They show the gate logic. They do
  not show the bridge.
- Re-run on this base: all 13 tests of `lab/intent-planner` pass on
  `a76268e7`, and the planted approval bug is caught by its five named tests
  (see the README of this folder, "What was re-run").

## Not shown

- Form A was not built or run. Read-only evidence only.
- Nothing shows that a public `store_principal_root_protection` call gives the
  lab a working protected root.
- No stored journal exists in #284 (its README says nothing is stored).
