# RA-2 The Runtime settles the requests of an ended requester, and the shell reads the record

Rank 2 of 7. Effort M (2 points). Checks named: A10, A11 (2). Score 1.00.

Sources: RI-5 in #293 (`lab/resident-instances/SPEC.md`) and AC-027-ORPHAN in
`lab/agent-conformance/GAPS.md`. Both ask the Runtime to settle a pending
request when whoever made it has ended. RI-5 adds a record the shell can read.
This file merges them and keeps the two parts apart.

## The ask

Part A, settle. When a requester ends, the Runtime denies each of its pending
requests and gives a reason that names the end. The requester is a stopped
instance, a failed instance, or a `run` client that is gone.

Part B, record. The shell reads the settled request and learns who settled it,
the shell or the Runtime.

## Checks it unblocks

| Check | Acceptance row that names it | Where | What else the row needs |
| --- | --- | --- | --- |
| A10 | `acceptance_a10_cancel_one_instance_sibling_unaffected`, blocked: RI-1; RI-2; RI-3; RI-4; RI-5 | #293 `tests/acceptance.rs` | RA-6 |
| A11 | `acceptance_a11_failed_instance_request_settled_by_runtime`, blocked: RI-1; RI-2; RI-3; RI-4; RI-5; RI-6 | #293 `tests/acceptance.rs` | RA-6 and RA-7 |

AC-027-ORPHAN names no BLOCKED row. It is a recorded gap behind two journeys
that pass today with the fixture doing the settling (see "Acceptance test").
It adds evidence to A11 but is not counted above.

## Today: evidence

| Citation | Text on that line | What it shows |
| --- | --- | --- |
| `elastos/crates/elastos-server/src/resource_bridge.rs:984` | `elastos_runtime::session::SessionId(ctx.capsule_id.clone()),` | A component's request is filed under its own capsule id as the session. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:1005` | `// Poll for the shell's decision (AutoGrantEngine or manual).` | The in-process bridge waits inside the guest's call. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:1078` | `"message": "capability request not approved within 30s",` | After the wait the bridge answers a timeout. It makes no store call, so the request stays pending. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:30` | `const CAPABILITY_APPROVAL_POLL_MS: u64 = 100;` | One poll is 100 ms. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:31` | `const CAPABILITY_APPROVAL_MAX_POLLS: usize = 300;` | 300 polls make the 30 seconds. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:1423` | `for _ in 0..CAPABILITY_APPROVAL_MAX_POLLS {` | The attached `run` client waits the same way. |
| `elastos/crates/elastos-server/src/resource_bridge.rs:1454` | `anyhow::anyhow!("capability request still pending after 30s")` | The client wait ends with an error. The request stays pending in the operator. |
| `elastos/crates/elastos-runtime/src/capability/pending.rs:17` | `pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 300;` | A pending request expires after 300 seconds. |
| `elastos/crates/elastos-runtime/src/capability/pending.rs:20` | `pub const MAX_PENDING_REQUESTS: usize = 1024;` | The store's capacity. |
| `elastos/crates/elastos-runtime/src/capability/pending.rs:263` | `self.cleanup_old(0).await;` | Resolved requests are removed here, and only when the store is at capacity. |
| `elastos/crates/elastos-runtime/src/capability/pending.rs:66` | `Denied { reason: String },` | A denial holds a reason and no settler. |
| `elastos/crates/elastos-runtime/src/capability/pending.rs:386` | `pub async fn deny_request(&self, request_id: &str, reason: &str)` | The store already denies one request by id with a reason. |
| `elastos/crates/elastos-runtime/src/capability/pending.rs:368` | `if !matches!(request.status, RequestStatus::Pending) {` | A grant applies only to a pending request. |
| `elastos/crates/elastos-runtime/src/capability/pending.rs:393` | `if !matches!(request.status, RequestStatus::Pending) {` | A denial applies only to a pending request. A late shell decision on a settled request is refused. |
| `elastos/crates/elastos-server/src/api/handlers/capability.rs:182` | `Cannot access another session's request` | A request's status is readable only by the session that made it. |
| `elastos/crates/elastos-server/src/api/handlers/capability.rs:383` | `pub async fn deny_request(` | The shell's deny route. |
| `elastos/crates/elastos-runtime/src/session/registry.rs:113` | `pub async fn invalidate_session(` | A session ends here. |
| `elastos/crates/elastos-runtime/src/session/registry.rs:131` | `reason: "invalidated".to_string(),` | The end emits an audit event only. It settles no request. |
| `elastos/crates/elastos-runtime/src/session/registry.rs:200` | `pub async fn cleanup_stale_sessions(` | The idle sweep removes sessions the same way. |
| `elastos/crates/elastos-server/src/serve_cmd.rs:451` | `let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));` | The sweep runs every 60 seconds. |
| `elastos/crates/elastos-server/src/serve_cmd.rs:454` | `let removed = registry.cleanup_stale_sessions(600).await;` | It removes sessions idle for 600 seconds. |
| `elastos/crates/elastos-server/src/run_cmd.rs:265` | `.run_local(capsule_dir, capsule_args)` | The `run` client returns after this call with no detach. |
| `elastos/crates/elastos-server/src/runtime_control.rs:936` | `let client_token = call_attach(&client, &api_base, &coords.attach_secret, "client").await?;` | A `run` client holds a client session on the operator. |
| `lab/agent-conformance/GAPS.md:881` | `and returns its 30-second refusal without removing the request. The pending` | The lab states the same gap for the `run` client. |
| `lab/agent-conformance/GAPS.md:887` | `Runtime can close AC-027-ORPHAN by binding pending requests to a supervised` | The lab's wording of the Runtime change. |
| `lab/agent-conformance/GAPS.md:894` | `closing AC-027-ORPHAN turns them FAIL` | When the Runtime settles, the two journeys fail on purpose until re-measured. |
| `lab/agent-conformance/LOG.md:4624` | `orphan_before:1 orphan_after:0` | Measured: the orphan was pending after the worker was killed. The fixture settled it. |
| `lab/agent-conformance/tests/effects.rs:647` | `fn killed_worker_settlement_recorded_without_retry() {` | The kill-worker journey (lab half of A11). |
| `lab/agent-conformance/tests/effects.rs:692` | `fn no_policy_file_does_not_mean_allow() {` | The absent-policy journey. It also ends with a fixture settlement. |
| `#293 lab/resident-instances/SPEC.md:82` | `Runtime settles an ended instance's requests, shell reads the record` | The resident SPEC names RI-5 and the checks A10 and A11. |
| `#293 lab/resident-instances/SPEC.md:178` | `When an instance stops or fails, the Runtime denies each of its pending` | The settle rule. |
| `#293 lab/resident-instances/SPEC.md:186` | `GET /api/capability/requests?session=<session_id>` | The new shell-only read route. |
| `#293 lab/resident-instances/SPEC.md:198` | `readable for at least 60 seconds after its instance ends.` | The retention the harness reads. |
| `#293 lab/resident-instances/src/capability.rs:107` | `rule: Rule::Lacks("/api/capability/requests"),` | The harness pins the missing route in `server.rs`. |
| `#293 lab/resident-instances/LOG.md:107` | `HTTP 405` | A live probe of today's operator got 405 on that path. |
| `#293 lab/resident-instances/tests/acceptance.rs:34` | `blocked: RI-1; RI-2; RI-3; RI-4; RI-5` | The A10 row names RI-5. |
| `#293 lab/resident-instances/tests/acceptance.rs:40` | `blocked: RI-1; RI-2; RI-3; RI-4; RI-5; RI-6` | The A11 row names RI-5. |

## Smallest change

Part A, settle:

1. One function that denies every `Pending` request of one session with a given
   reason. It can call the store's own `deny_request` (`pending.rs:386`).
2. Call it where a requester ends. For a resident instance that is stop and
   failure (RA-6). A `run` client has no such moment today. The nearest end
   signal is session removal, and the idle sweep removes a session after 600
   seconds idle (`serve_cmd.rs:454`). A request expires after 300 seconds
   (`pending.rs:17`). The sweep is slower than the expiry, so it cannot be the
   trigger alone. `GAPS.md:887` names the fix for `run` clients: tie requests
   to a supervised client lifetime and settle when the client detaches or dies.
   The lab text does not say how the Runtime learns that a `run` client died.
   That piece is not sized here.
3. A guest blocked in a wait (`resource_bridge.rs:1008`) must also be able to
   end. That belongs to the stop in RA-6.

Part B, record:

4. Add a settler to the denial. `Denied` holds only a reason today
   (`pending.rs:66`). The SPEC wants `settled_by` to be `shell` or `runtime`.
5. Add the shell-only read route from the SPEC (`GET
   /api/capability/requests?session=`), next to `/api/capability/pending`.

This touches `elastos-runtime` (the denial field and the settle function) and
`elastos-server` (the route and the callers).

## How it fits the capability and grant model

- The Runtime settles with the same store call the shell uses, so there is one
  request record and one set of states (Principle 10).
- A request that a dead requester left behind stops being live authority
  (Principle 3, no ambient authority). The reason names the end (Principle 11,
  fail closed, then explain).
- The store lets only a pending request change state (`pending.rs:368`, `:393`).
  A shell decision that arrives after the Runtime settled is refused. The
  reverse holds too.

## Risks

- **The end signal for `run` clients is open.** Part A is only as good as the
  signal that a requester ended. The idle sweep is too slow (above). A detach
  call from the client or a connection-tied lifetime is new work.
- **A grant given before the end is a different case.** Settling denies pending
  requests. It does not revoke grants that were already given. RA-1 shows them
  and RA-6 revokes them on stop.
- **Two lab journeys fail on purpose.** After Part A they report FAIL until the
  lab re-measures and cites the Runtime line (`GAPS.md:894`).
- **The reason text can carry an instance's failure text.** Only a shell
  session reads the record, and a shell already reads each pending request's
  reason.
- **Retention is a habit, not a contract.** The store keeps resolved requests
  until a capacity cleanup runs (`pending.rs:263`, when the store holds 1024
  requests). The SPEC asks for at least 60 seconds. Today's code meets that,
  but nothing states it.
- **Review class.** The change is in capability and session code. `AGENTS.md`
  requires an independent adversarial review for that code.

## Acceptance test already written

- **`acceptance_a10_*` and `acceptance_a11_*`** in #293. Class: READY as
  journeys. The harness has run them only against its reference double. The
  fixture guests are not written, and each row also needs RA-6 (A11 also RA-7).
  The A10 journey stops instance 1 while its request is pending and requires a
  `denied` record settled by the Runtime. A11 does the same for a failed
  instance.
- **`killed_worker_settlement_recorded_without_retry`** and
  **`no_policy_file_does_not_mean_allow`** in agent-conformance. Class:
  TRIPWIRE. They pass today with `orphan_before:1 orphan_after:0` settled by
  the fixture. Part A turns them to FAIL. The lab then rewrites them to cite
  the Runtime as settler. No PASS assertion for that exists yet.

## Not shown

- No Runtime change was run. No grade changed.
- The resident journeys never ran against a Runtime. The one live probe of
  today's operator covered existing routes (#293 `LOG.md`).
- How a `run` client's death reaches the Runtime is open.
