# RA-6 Resident component instances in one Runtime: world, launch, list, stop

Rank 6 of 7. Effort 11 points (RI-1 L, RI-2 M, RI-3 S, RI-4 L). Checks named:
A3, A6, A10, A11, A12 (5). Score 0.45.

Sources: RI-1 to RI-4 in #293 (`lab/resident-instances/SPEC.md`), and the
blocker RT4 in `lab/agent-conformance/GAPS.md`. RT4 is the same Runtime
capability: resident component instances hosted by one Runtime.

This ask is the largest and the base of the other resident asks. Every
resident row names RI-1 to RI-4. No resident row flips without them.

## The ask

One Runtime hosts two or more component instances at the same time. The shell
launches an instance and gets back its Bus session. The shell lists live
instances with status and cause. The shell stops one instance with a reason.
The stop ends that instance's execution and authority and leaves the others
untouched.

| Part | Change | Effort |
| --- | --- | --- |
| RI-1 | A WIT world whose component exports a resident lifecycle (`start`, `stop`), bound by the component provider | L (4) |
| RI-2 | `POST /api/capsules` answers once the instance is admitted, before `start` returns, with its `session_id` | M (2) |
| RI-3 | `GET /api/capsules` lists each resident instance with status and cause, including after it ends | S (1) |
| RI-4 | `DELETE /api/capsules/:id` takes a reason, ends execution (also during a request wait), revokes the instance's grants and refuses its later Bus calls | L (4) |

## Checks it unblocks

| Check | Acceptance row | Where | What else the row needs |
| --- | --- | --- | --- |
| A3 | `acceptance_a3_two_resident_instances_in_one_runtime`, blocked: RI-1; RI-2; RI-3; RI-4 | #293 `tests/acceptance.rs` | Fixture guests (not written) |
| A6 | `acceptance_a6_instance_grant_does_not_authorise_sibling` | #293 | RA-1 |
| A10 | `acceptance_a10_cancel_one_instance_sibling_unaffected` | #293 | RA-2 |
| A11 | `acceptance_a11_failed_instance_request_settled_by_runtime` | #293 | RA-2 and RA-7 |
| A12 | `acceptance_a12_stopped_instances_leave_nothing_behind` | #293 | RA-1 |

A3 flips with this ask alone, once the fixture guests exist.
agent-conformance also keeps `parallel_capsules_complete_independently`,
blocked: RT4, with no A label.

## Today: evidence

| Citation | Text on that line | What it shows |
| --- | --- | --- |
| `elastos/wit/elastos-bus-v1.wit:84` | `interface lifecycle {` | The lifecycle interface has one function. |
| `elastos/wit/elastos-bus-v1.wit:87` | `run: func() -> result<_, bus-error>;` | That function is `run`. There is no `start` and no `stop`. |
| `elastos/wit/elastos-bus-v1.wit:90` | `world product-capsule-v1 {` | The only world. |
| `elastos/wit/elastos-bus-v1.wit:95` | `export lifecycle;` | The world exports `lifecycle` only. |
| `elastos/crates/elastos-compute/src/providers/component.rs:25` | `world: "product-capsule-v1",` | The component provider binds that one world. |
| `elastos/crates/elastos-server/src/component.rs:76` | `if name == "import-func-run" {` | The component validator names `run` in its import rules. A world with other function names needs a check against it. |
| `elastos/crates/elastos-common/src/manifest.rs:1062` | `ElastosComponentV1,` | The manifest ABI value for components today. |
| `elastos/crates/elastos-server/src/api/routes.rs:74` | `pub struct LaunchResponse {` | The launch answer holds `id`, `name` and `status`. It names no session. |
| `elastos/crates/elastos-server/src/api/routes.rs:95` | `.run_local_with_principal(path, vec![], principal_id)` | The route waits for the whole launch. |
| `elastos/crates/elastos-server/src/api/routes.rs:100` | `"completed"` | A component launch answers `completed` after `run` returned. |
| `elastos/crates/elastos-server/src/runtime.rs:317` | `let start = provider.start(&handle).await;` | The launch awaits `start` in line. |
| `elastos/crates/elastos-server/src/runtime.rs:320` | `component.clear_bridge_principal(&handle.id).await;` | The launch clears the instance's principal as soon as `start` returns. |
| `elastos/crates/elastos-server/src/runtime.rs:324` | `bounds.remove(&handle.id.0);` | It also removes the instance's manifest bounds. |
| `elastos/crates/elastos-compute/src/providers/component.rs:212` | `let result = tokio::task::spawn_blocking(move || {` | The guest runs on a blocking task that `start` awaits. |
| `elastos/crates/elastos-compute/src/providers/component.rs:218` | `self.instances.write().await.remove(&handle.id);` | The activation record is removed when `run` returns. |
| `elastos/crates/elastos-compute/src/providers/component.rs:168` | `let id = CapsuleId::new(format!("component-{}", uuid::Uuid::new_v4()));` | Each activation already gets its own id. |
| `elastos/crates/elastos-compute/src/providers/component.rs:352` | `session: self.capsule_id.clone(),` | The guest's session is that id. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:984` | `elastos_runtime::session::SessionId(ctx.capsule_id.clone()),` | Its requests are filed under that session. |
| `elastos/crates/elastos-server/src/api/handlers/capability.rs:339` | `// Use session ID as capsule ID for now` | A grant token is minted for the requesting session's id. |
| `elastos/crates/elastos-runtime/src/capability/manager.rs:411` | `return Err(ValidationError::WrongCapsule {` | `validate` refuses a caller whose capsule id differs from the token's. |
| `elastos/crates/elastos-server/src/runtime.rs:18` | `pub struct RunningCapsuleInfo {` | The registry entry has no session and no cause. |
| `elastos/crates/elastos-server/src/runtime.rs:434` | `pub async fn register_capsule(` | A register call exists. |
| `elastos/crates/elastos-server/src/serve_cmd.rs:167` | `runtime_arc.register_capsule(capsule_info).await;` | Another capsule kind uses it. |
| `elastos/crates/elastos-server/src/api/routes.rs:47` | `pub async fn list_capsules(` | The list route reads that registry. |
| `elastos/crates/elastos-server/src/runtime.rs:502` | `self.unregister_capsule(id).await;` | A stop removes the entry at once. The SPEC wants it listed for 60 seconds. |
| `elastos/crates/elastos-compute/src/providers/component.rs:223` | `async fn stop(&self, handle: &CapsuleHandle)` | The provider stop. |
| `elastos/crates/elastos-compute/src/providers/component.rs:232` | `component/v1 is a bounded activation contract and has no resident stop operation` | It refuses to stop a running component. |
| `elastos/crates/elastos-server/src/api/routes.rs:202` | `match runtime.stop_capsule_by_id(&id).await {` | The stop route takes an id and no body. |
| `elastos/crates/elastos-server/src/runtime.rs:489` | `provider.stop(handle).await?;` | The Runtime stop calls the provider stop. |
| `elastos/crates/elastos-compute/src/providers/component.rs:83` | `config.consume_fuel(true);` | The engine limits a guest by fuel. |
| `elastos/crates/elastos-compute/src/providers/component.rs:28` | `const COMPONENT_FUEL: u64 = 100_000_000;` | One fixed budget. |
| `elastos/crates/elastos-compute/src/providers/component.rs:121` | `.set_fuel(COMPONENT_FUEL)` | It is set once when the instance is created. |
| `elastos/crates/elastos-compute/src/providers/component.rs:32` | `engine: Engine,` | The activation record holds the engine, the component, a status and the manifest. |
| `elastos/crates/elastos-compute/src/providers/component.rs:35` | `manifest: CapsuleManifest,` | It holds no handle that can interrupt a running guest. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:1008` | `for _ in 0..CAPABILITY_APPROVAL_MAX_POLLS {` | A guest in a request wait sits inside this loop for up to 30 seconds. |
| `#293 lab/resident-instances/SPEC.md:93` | `A WIT world in` | RI-1 in the SPEC. |
| `#293 lab/resident-instances/SPEC.md:104` | `world resident-capsule {` | The proposed world. |
| `#293 lab/resident-instances/SPEC.md:162` | `DELETE /api/capsules/:id` | RI-4: stop with a reason. |
| `#293 lab/resident-instances/SPEC.md:166` | `issues/177` | The real stop follows Elacity issue 177. |
| `#293 lab/resident-instances/SPEC.md:168` | `its session grants are revoked at once;` | A stop revokes grants at once. |
| `#293 lab/resident-instances/SPEC.md:251` | `**A3.**` | The A3 journey: two launches, both resident after a 1-second dwell, no new process. |
| `#293 lab/resident-instances/SPEC.md:310` | `The fixture source joins this folder when RI-1 lands` | The fixture guests wait for RI-1. |
| `#293 lab/resident-instances/SPEC.md:337` | `Names.` | The names of the world and ABI value are open. |
| `#293 lab/resident-instances/tests/acceptance.rs:22` | `blocked: RI-1; RI-2; RI-3; RI-4` | The A3 row. |
| `#293 lab/resident-instances/LOG.md:46` | `26 CAUGHT of 26` | The harness falsifiers, run against the harness's own double. |
| `#293 lab/resident-instances/LOG.md:134` | `The fixture guests are specified` | The fixture guests are specified and not written. |
| `lab/agent-conformance/GAPS.md:552` | `RT4` | agent-conformance records the same blocker. |
| `lab/agent-conformance/tests/effects.rs:21` | `fn parallel_capsules_complete_independently() {` | Its row body is a panic. |

## Smallest change

The SPEC extends existing routes (Principle 10). Each part, from its evidence:

- **RI-1.** Add a `resident` interface (`start`, `stop`) and a world that
  exports it, beside `product-capsule-v1` in `elastos/wit/`. Bind it in the
  component provider. Select it by the manifest ABI. Check the validator
  (`component.rs:76`) against the new function names.
- **RI-2.** For a resident component, spawn `start` and return after admission
  with the activation id and session (`component.rs:168`, `:352`). Keep the
  bridge principal and manifest bounds registered until the instance ends.
  Today the launch clears them when `start` returns (`runtime.rs:320`, `:324`).
- **RI-3.** Call `register_capsule` from the launch. Add `session_id` and
  `cause` to `RunningCapsuleInfo` and to the list answer. Keep a stopped or
  failed entry for the retention the SPEC states.
- **RI-4.** Accept a reason on `DELETE /api/capsules/:id`. Give the component
  provider a real stop. The engine uses fuel only, and the activation record
  holds no interrupt handle (`component.rs:83`, `:32-35`). A guest inside a
  request wait must also end (`resource_bridge.rs:1008`). The stop then revokes
  the session's grants and settles its pending requests (RA-2).

The SPEC fixes only what A3, A6, A10, A11 and A12 observe. It leaves events,
streams, restart and the full Bus v2 operation set to Elacity issues 181 and
463.

## How it fits the capability and grant model

- An instance's authority is its session's grants plus its manifest bound.
  Both exist today and are keyed by the activation id (`runtime.rs:299-302`,
  `capability.rs:339`). `validate` refuses a token for another capsule id
  (`manager.rs:411`). A grant for one instance then does not cover a sibling,
  with no new grant type (A6, Principle 3).
- Launch, list and stop extend `/api/capsules` and stay shell-only
  (`server.rs:463-465`).
- A stop that revokes grants and settles requests keeps the Runtime as the one
  owner of authority (Principles 5 and 7). The Home screens stay views.

## Risks

- **It is the largest ask.** The stop needs a way to end a running guest,
  including one that waits in a hostcall. The engine has fuel only today.
- **A resident guest and the fuel budget.** The fuel is one fixed amount set
  when the instance starts (`component.rs:28`, `:121`). A guest that stays
  resident for long may exhaust it. The SPEC does not say what budget a
  resident instance gets. This is a question for Anders and is not in SPEC
  section 7.
- **One blocking task per instance.** The guest runs on a blocking task
  (`component.rs:212`). A resident instance would hold that task for its whole
  life. This is an inference from that line. The SPEC does not discuss it.
- **A long-lived contract.** The WIT world is an ABI. The names are open (SPEC
  section 7, question 1). Anders may prefer to fold this into the Bus v2
  prototype (Elacity issues 181 and 463).
- **Review class.** The change touches the guest ABI, the compute provider and
  the shell routes. `AGENTS.md` requires an independent adversarial review.

## Acceptance test already written

- **`acceptance_a3_two_resident_instances_in_one_runtime`** and the four other
  `acceptance_a*` rows in #293. Class: READY as journeys, written once against
  a `ResidentRuntime` trait and an operator adapter. They have run only against
  the harness's reference double. The fixture guests `read-shared` and
  `fail-after-submit` are specified and not written, because they need the RI-1
  world. The gate test `blocker_evidence_still_holds` tells the lab when a
  pinned line moved and a capability needs a fresh measurement.
- **`parallel_capsules_complete_independently`** in agent-conformance. Class:
  PLACEHOLDER. The body is a panic (`effects.rs:21`).

## Not shown

- No journey ran against a Runtime. The one live probe covered today's routes.
- The fixture guests do not exist.
- The fuel and thread questions above are not answered by any lab.
