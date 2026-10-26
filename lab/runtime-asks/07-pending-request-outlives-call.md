# RA-7 A capability request that stays pending after the guest's call returns

Rank 7 of 7. Effort L (4 points) for the non-blocking call. Checks named: A11
(1). Score 0.25.

Source: RI-6 in #293 (`lab/resident-instances/SPEC.md`).

## The ask

A guest can submit a capability request and continue before the decision. The
Runtime records the pending request before the submit call returns. The
decision reaches the guest later. With this, an instance can fail while its own
request is pending, which is what A11 needs.

## Checks it unblocks

| Check | Acceptance row | Where | What else the row needs |
| --- | --- | --- | --- |
| A11 | `acceptance_a11_failed_instance_request_settled_by_runtime`, blocked: RI-1; RI-2; RI-3; RI-4; RI-5; RI-6 | #293 `tests/acceptance.rs` | RA-6, RA-2, and the `fail-after-submit` fixture (not written) |

## Today: evidence

| Citation | Text on that line | What it shows |
| --- | --- | --- |
| `elastos/wit/elastos-bus-v1.wit:75` | `request: func(request: capability-request) -> result<capability-grant, bus-error>;` | The one capability call returns the grant itself. |
| `elastos/crates/elastos-compute/src/providers/component.rs:358` | `impl elastos::bus::capabilities::Host for ComponentState {` | The guest's call lands here. |
| `elastos/crates/elastos-compute/src/providers/component.rs:359` | `fn request(` | The host function that blocks the guest until the bridge answers. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:984` | `elastos_runtime::session::SessionId(ctx.capsule_id.clone()),` | The bridge records the pending request here. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:1005` | `// Poll for the shell's decision (AutoGrantEngine or manual).` | The same call then polls for the decision. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:1008` | `for _ in 0..CAPABILITY_APPROVAL_MAX_POLLS {` | The poll loop. |
| `#293 lab/resident-instances/SPEC.md:204` | `### RI-6 A pending request outlives the guest's call` | The SPEC section. |
| `#293 lab/resident-instances/SPEC.md:206` | `The RI-1 world lets a guest submit a capability request and continue before` | The proposed behaviour. |
| `#293 lab/resident-instances/SPEC.md:212` | `Gap evidence: the only capability call returns the grant itself, so the guest` | The SPEC's gap evidence. |
| `#293 lab/resident-instances/SPEC.md:307` | `fail-after-submit` | The `fail-after-submit` fixture submits without waiting, then traps (line 308). |
| `#293 lab/resident-instances/SPEC.md:165` | `waits on a capability request` | The stop in RI-4 must also end a guest in a request wait. |
| `#293 lab/resident-instances/SPEC.md:340` | `2. RI-6 or interruption.` | The SPEC asks Anders how an instance can fail while a blocking request is pending. |
| `#293 lab/resident-instances/SPEC.md:341` | `instance fail while its request is pending? One option is a Runtime-enforced` | The option the SPEC offers. |
| `#293 lab/resident-instances/SPEC.md:342` | `The A11 journey stays the same;` | With that option the journey stays. Only the fixture changes (line 343). |
| `elastos/crates/elastos-runtime/src/capability/pending.rs:24` | `pub const MAX_PENDING_PER_SESSION: usize = 32;` | One session can hold at most 32 pending requests. |
| `#293 lab/resident-instances/src/capability.rs:126` | `meaning: "the only capability call returns the grant, so the guest waits inside it",` | The harness pins this gap. |
| `#293 lab/resident-instances/tests/acceptance.rs:40` | `blocked: RI-1; RI-2; RI-3; RI-4; RI-5; RI-6` | The A11 row names RI-6. |

## Smallest change

The SPEC gives two ways.

- **Option 1, a non-blocking submit.** In the resident world, add a call that
  records the pending request and returns its id. The decision reaches the guest
  later, as an event or through a later call (`SPEC.md:206-209`). This changes
  the Bus call model. Effort L.
- **Option 2, an instance deadline.** The Bus v2 request stays blocking. The
  Runtime enforces a deadline that ends a waiting guest. The A11 journey stays
  the same and only the `fail-after-submit` fixture changes (`SPEC.md:340-343`).
  The Runtime then settles the left-over request (RA-2). This reuses the
  "end a guest in a request wait" step that RI-4 already needs (`SPEC.md:165`).
  My reading is that Option 2 is nearer to effort M. That is an inference, not a
  measurement. If Anders chooses it, this ask moves up to a tie with RA-5.

## How it fits the capability and grant model

The pending request stays an ordinary request in the same store, filed under the
instance's session (`resource_bridge.rs:984`). The shell decides it through the
same routes. Only the moment the guest learns of the decision changes. Option 2
changes nothing in the grant model. It adds a limit on how long an instance can
wait.

## Risks

- **Option 1 changes a long-lived ABI.** The decision delivery overlaps the Bus
  v2 prototype (Elacity issues 181 and 463). The SPEC states this and leaves it
  to them.
- **Option 2 weakens the A11 story.** The instance fails from outside (a
  deadline), not from its own trap while a request is pending. The SPEC says the
  journey stays the same. Anders decides whether that meets A11.
- **A guest that never reads the decision.** Option 1 can leave requests pending
  without a reader. RA-2 settles them when the instance ends. Until then the
  per-session cap of 32 pending requests applies (`pending.rs:24`).
- **Review class.** The change touches the guest ABI and the bridge.
  `AGENTS.md` requires an independent adversarial review.

## Acceptance test already written

- **`acceptance_a11_failed_instance_request_settled_by_runtime`** in #293.
  Class: READY as a journey. It needs RA-6 and RA-2 first. The
  `fail-after-submit` fixture is specified and not written, and its shape
  depends on the option chosen.

## Not shown

- Neither option was built or run.
- The effort of Option 2 is my reading of the SPEC, not a lab result.
