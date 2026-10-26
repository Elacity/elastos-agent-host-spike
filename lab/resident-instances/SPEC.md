# Resident instances: the interface the acceptance harness expects

LAB DRAFT for review by the Runtime team (Anders). It is design input for the
Bus v2 resident-component prototype
([#181](https://github.com/Elacity/elastos-runtime/issues/181)). It fixes only
what M1 checks A3, A6, A10, A11 and A12 must observe. It leaves the Bus v2
operation set, events, streams, UI channels and restart to #181 and
[#463](https://github.com/Elacity/elastos-runtime/issues/463).

The harness in this folder runs the five checks against a live operator
Runtime. Until the Runtime has every capability a check needs, that check
reports BLOCKED and names the missing capabilities below. Nothing in this lane
changes the Runtime.

## 1. The checks

- **A3**: two or more agents run at the same time as independent resident
  capsule instances inside one Runtime. Separate Runtimes or `elastos run`
  client processes do not count.
- **A6**: each instance has its own grants. A grant for one instance does not
  authorise its sibling.
- **A10**: the shell cancels one instance. The sibling is unaffected.
- **A11**: one instance fails. The Runtime settles that instance's pending
  request.
- **A12**: after the instances end, the cleanup census finds nothing left.

`lab/agent-conformance` already proves the process-isolation half of these
checks with two `elastos run` clients on one operator (its `GAPS.md`, sections
"023" to "AC-027-ORPHAN"). There, each client builds its own component host,
so that proof stops at the process boundary (its blocker RT4). This lane is the
resident half: the same claims, with both instances hosted by the operator
itself.

## 2. The Runtime today

Paths are under `elastos/`. Line numbers are at `spike/agent-host` `fe1e1c7e`.

- The Bus world `product-capsule-v1` exports one interface, `lifecycle`, with
  one function, `run` (`wit/elastos-bus-v1.wit:84-96`).
- The component provider binds that world
  (`crates/elastos-compute/src/providers/component.rs:23-26`). `start` waits
  for `run` to return, then removes the instance (`component.rs:187-221`).
  `stop` refuses a running component: "component/v1 is a bounded activation
  contract and has no resident stop operation" (`component.rs:223-238`).
- The operator can already run a component inside its own process. The
  shell-only `POST /api/capsules` (`crates/elastos-server/src/api/server.rs:462-473`)
  calls `Runtime::run_local_with_principal` (`api/routes.rs:80-118`,
  `runtime.rs:237-329`). The operator's component host has an in-process Bus
  bridge (`runtime.rs:105-135`), and each activation gets its own session,
  `component-<uuid>` (`component.rs:168`, `component.rs:352`,
  `resource_bridge.rs:984`).
- That launch answers only after `run` returned, with status `completed`
  (`api/routes.rs:99-103`). The activation is never registered, so
  `GET /api/capsules` cannot list it (`runtime.rs:449-452`) and
  `DELETE /api/capsules/:id` answers 404 for it (`api/routes.rs:198-210`,
  `runtime.rs:473-482`).
- A component's capability request waits inside the guest's call. The bridge
  polls for the shell's decision, then answers "capability request not approved
  within 30s" and leaves the request pending (`resource_bridge.rs:1005-1079`).
  The pending store expires a request after 300 seconds
  (`crates/elastos-runtime/src/capability/pending.rs:17`). No call settles an
  ended instance's requests.
- The shell lists pending requests only (`api/handlers/capability.rs:244-264`).
  A request's status is readable only by the session that asked
  (`api/handlers/capability.rs:162-184`). `GET /api/capability/list` returns
  the caller's own session grants (`api/handlers/capability.rs:428-434`).

So a component can run in the operator's process today, but only once, without
an address the shell can see or stop, and its requests outlive it.

## 3. Capabilities the harness needs

The harness extends existing routes where one exists, so each operation keeps
one path (PRINCIPLES.md 10).

| ID | Capability | Needed by | Extends |
| --- | --- | --- | --- |
| RI-1 | resident component world in the Bus WIT | A3, A6, A10, A11, A12 | `elastos/wit/` |
| RI-2 | launch returns a live instance with its Bus session | A3, A6, A10, A11, A12 | `POST /api/capsules` |
| RI-3 | shell list of live instances with status and cause | A3, A6, A10, A11, A12 | `GET /api/capsules` |
| RI-4 | stop one instance with a reason | A3, A6, A10, A11, A12 | `DELETE /api/capsules/:id` |
| RI-5 | Runtime settles an ended instance's requests, shell reads the record | A10, A11 | new `GET /api/capability/requests` |
| RI-6 | a capability request can stay pending after the guest's call returns | A11 | the RI-1 world |
| RI-7 | shell view of every session's live grants | A6, A12 | `GET /api/capability/list` |

All bounds below are the harness's: 10 seconds for every awaited transition,
a 2-second watch after an instance ends, and a 1-second dwell for residency.
10 seconds is a third of the bridge's 30-second wait and far below the store's
300-second expiry, so neither timeout can stand in for a settlement.

### RI-1 Resident component world

A WIT world in `elastos/wit/` whose component exports a resident lifecycle.
It imports the same Bus interfaces as Bus v1 and gets no WASI, files, sockets
or environment. Proposed shape (names are open, see section 7):

```wit
interface resident {
  use types.{bus-error};
  start: func() -> result<_, bus-error>;
  stop: func(reason: string);
}

world resident-capsule {
  import runtime;
  import identity;
  import capabilities;
  import providers;
  export resident;
}
```

The Runtime calls `start` once per instance. When `start` returns `ok`, the
instance is `running` and stays resident until the Runtime stops it. When
`start` returns an error or traps, the instance is `failed`, and its cause
holds that error text. `stop(reason)` lets the guest tidy up. The Runtime ends
execution and authority within the bound even when the hook traps or does not
return.

Gap evidence: no world in `elastos/wit/*.wit` exports an interface that defines
both `start` and `stop`; the component provider binds only
`product-capsule-v1`.

### RI-2 Launch returns a live instance

`POST /api/capsules` with `{"path": "<capsule directory>"}`, shell only, as
today. For a resident component the answer comes once the instance is admitted
and `start` was called, before `start` returns:

```json
{"id": "...", "name": "...", "status": "starting", "session_id": "..."}
```

`status` is one of the RI-3 values. Two launches of one capsule directory give
two instances with different `id` and `session_id`. `session_id` is the Bus
session on every pending request, request record and grant of that instance.
Today's in-process bridge already uses the activation id as that session.

Gap evidence: the launch answers `completed` after `run` returned; the answer
names no session.

### RI-3 Live instance list

`GET /api/capsules`, as today, lists each resident instance from its launch
until its end:

```json
{"capsules": [{"id": "...", "name": "...", "status": "running",
               "session_id": "...", "cause": ""}]}
```

`status` is `starting`, `running`, `stopping`, `stopped` or `failed`. `cause`
is written by the Runtime for `stopped` (it contains the stop reason) and
`failed` (it contains the start error or trap text). A `stopped` or `failed`
entry stays listed with its cause for at least 60 seconds. Other capsule kinds
keep their current fields.

Gap evidence: `run_local_with_principal` never calls `register_capsule`.

### RI-4 Stop one instance

`DELETE /api/capsules/:id` with `{"reason": "<text>"}`. The Runtime answers
200 when it accepts the stop. Within the bound, the instance is `stopped` and
its cause contains the reason. The stop ends execution, also while the guest
waits on a capability request, and ends all future authority of that instance
([#177](https://github.com/Elacity/elastos-runtime/issues/177) real stop):

- its session grants are revoked at once;
- its pending requests are settled (RI-5);
- later Bus calls from it are refused.

Other instances keep their state, requests and grants.

Gap evidence: the component provider refuses to stop a running component.

### RI-5 Runtime settlement and the request record

When an instance stops or fails, the Runtime denies each of its pending
requests within the bound. The denial reason names the end: it contains the
stop reason, or the failure cause.

The shell reads a session's requests, pending or settled, with a new shell-only
route:

```text
GET /api/capability/requests?session=<session_id>
```

```json
{"requests": [{"request_id": "...", "session_id": "...", "resource": "...",
               "action": "read", "reason": "...", "status": "denied",
               "decision_reason": "instance stopped: ...",
               "settled_by": "runtime"}]}
```

`status` is `pending`, `granted`, `denied` or `expired`. `settled_by` is
`shell` or `runtime`, and `null` only while pending. A session's records stay
readable for at least 60 seconds after its instance ends.

Gap evidence: no shell route reads a session's settled requests; a request's
status is readable only by the session that asked; the bridge wait ends in a
timeout that leaves the request pending.

### RI-6 A pending request outlives the guest's call

The RI-1 world lets a guest submit a capability request and continue before
the decision. The decision reaches the guest later, as an event or through a
later call. The Runtime records the pending request before the submit call
returns. Only with this can an instance fail while its own request is pending,
which A11 needs.

Gap evidence: the only capability call returns the grant itself, so the guest
waits inside it, and the bridge polls inside that call.

### RI-7 Live-grant view for every session

`GET /api/capability/list?scope=all_sessions_live`, shell only:

```json
{"scope": "all_sessions_live",
 "capabilities": [{"request_id": "...", "session_id": "...",
                   "resource": "...", "action": "read",
                   "duration": "session"}]}
```

The Runtime leaves out exhausted, revoked and expired grants. Client sessions
keep their own view. This is the same contract as agent-conformance's
AC-021-GRANTS (`lab/agent-conformance/GAPS.md`, "AC-021-GRANTS"); this lane
uses it unchanged.

Gap evidence: the list returns the caller's own session grants and has no
global scope.

## 4. Journeys

| Check | Acceptance row | Needs |
| --- | --- | --- |
| A3 | `acceptance_a3_two_resident_instances_in_one_runtime` | RI-1, RI-2, RI-3, RI-4 |
| A6 | `acceptance_a6_instance_grant_does_not_authorise_sibling` | RI-1, RI-2, RI-3, RI-4, RI-7 |
| A10 | `acceptance_a10_cancel_one_instance_sibling_unaffected` | RI-1, RI-2, RI-3, RI-4, RI-5 |
| A11 | `acceptance_a11_failed_instance_request_settled_by_runtime` | RI-1, RI-2, RI-3, RI-4, RI-5, RI-6 |
| A12 | `acceptance_a12_stopped_instances_leave_nothing_behind` | RI-1, RI-2, RI-3, RI-4, RI-7 |

Every journey starts the same way. It requires `GET /api/health` ok, seeds the
fixture file through the existing `POST /api/provider/localhost/write`, then
takes the baseline of processes below the operator pid. Every journey launches
its instances only through the operator's shell API; the harness starts no
`elastos run` client. Every journey ends with the census, and a failed journey
stops what it launched before it reports.

**A3.** Launch `read-shared` twice. Wait for one pending read from each
session. In one list snapshot both instances are live. Grant both for their
sessions. Both reach `running`. After the dwell, one snapshot still shows both
`running`, so `start` returned and they stayed resident. No new process
appeared below the operator. Stop both, then run the census.

**A6.** Launch `read-shared` twice. Grant instance 1 only, and wait until it
is `running`. The live-grant view shows exactly one grant, bound to instance 1.
Instance 2's request for the same resource is still pending, in its own
session. Deny it. Instance 2 ends `failed` with the denial in its cause, and
instance 1 is still `running` with the same single grant. Stop instance 1. The
census also requires zero live grants for both sessions.

**A10.** Launch `read-shared` twice and wait for both pending requests. Stop
instance 1 with the cancel reason while its request is pending. Instance 1 is
`stopped` with that reason. Its request record is `denied`, settled by the
Runtime, with the reason in its decision, and the harness never decided it.
Instance 2 is still live and its request is still pending. Grant it; instance
2 reaches `running`. For the watch, instance 1 makes no request and stays
`stopped`. Stop instance 2, then run the census.

**A11.** Launch `fail-after-submit` and `read-shared`. Instance 1 ends
`failed` with a cause. Its one request record is `denied`, settled by the
Runtime, with the failure cause in its decision, and the harness never decided
it. Nothing from instance 1 is pending. Grant instance 2; it reaches
`running`. For the watch, instance 1 makes no request and stays `failed`. Stop
instance 2, then run the census.

**A12.** Launch `read-shared` twice, grant both, and wait for both `running`.
The pending view saw both requests, and the live-grant view shows a grant for
each session. These are the census's positive controls. Stop both. The census
then requires zero live grants as well.

**Census.** No launched instance is `starting`, `running` or `stopping`. No
pending request comes from a journey session. In A6 and A12, no live grant
belongs to a journey session. No process below the operator pid is new since
the baseline. `GET /api/health` is still ok.

The census samples points in time. Its process check walks the operator's
process tree, so a process that leaves the tree would escape it; the Runtime
keeps resident instances in its own process, as the component host does today.
Socket and file censuses stay with agent-conformance.

## 5. Fixture guests

One source builds both guests against the RI-1 world. Each manifest declares
the bound `localhost://Public/resident-instances/*`. The fixtures are unsigned
and run on a throwaway operator with `dev_mode = true`.

- `read-shared`: `start` requests `read` on
  `localhost://Public/resident-instances/shared.txt` with the reason
  `resident instances: shared read`, and waits for the decision. When granted,
  it reads the file with that grant and compares the bytes with the seeded
  `resident-instances shared fixture bytes` line. A match returns `ok`; the
  guest then does nothing until it is stopped. A denial returns the denial as
  the `start` error.
- `fail-after-submit`: `start` submits the same request without waiting
  (RI-6), then traps.

The fixture source joins this folder when RI-1 lands; until then it is blocked
with the rows. Its behaviour is fixed here and in `src/contract.rs`.

## 6. Grading

- **BLOCKED**: a capability the check needs is missing. The row names the
  capabilities and the evidence for each gap, read from this checkout on every
  run. A blocked row never reads setup or contacts an operator.
- **SKIPPED**: every capability is there, but the live setup is incomplete:
  `RESIDENT_RUNTIME_COORDS`, a fixture directory, or the shell attach. SKIPPED
  is a failed command, never a pass.
- **FAIL**: the journey ran against the operator and an assertion failed.
- **PASS**: the journey ran against the operator and every assertion held. No
  other path produces PASS.

`tests/gates.rs` keeps the BLOCKED grades current. When a gap's evidence stops
holding, `blocker_evidence_still_holds` fails and names the capability to
re-measure. A capability leaves the missing list only after a live journey
measured it.

The reference double under `tests/common/` runs every journey for the
harness's own tests: the honest double passes, and each wrong behaviour is
refused for its own reason. It is not the Runtime, and its results count
toward no M1 check.

## 7. Open questions for the Runtime team

1. Names. The world, interface and function names and the manifest ABI value
   for RI-1 are a proposal. The harness changes one rule
   (`Rule::NoResidentExport`) and this file if they differ.
2. RI-6 or interruption. If the Bus v2 request stays blocking, how does an
   instance fail while its request is pending? One option is a Runtime-enforced
   instance deadline that ends a waiting guest. The A11 journey stays the same;
   only `fail-after-submit` changes.
3. Stop reason. The harness sends the reason as a JSON body on `DELETE`. A
   query parameter works as well; say which.
4. Retention. The harness reads ended instances and their request records for
   60 seconds. A count bound instead of a time bound also works.
5. Handles. When grants become host-side handles bound to instance and session
   (#463, #177), A10 and A12 add one step: a stopped instance's handle is
   refused.

## 8. Principles

- 3 No ambient authority: every effect needs a grant bound to one instance.
- 7 One authority model: instances ask and the shell decides through the same
  Runtime routes a person's capsules use.
- 10 One canonical path: launch, list and stop extend the existing capsule
  routes; the live-grant view reuses AC-021-GRANTS.
- 11 Fail closed, then explain: an instance's end settles its requests with a
  reason.
- 12 Docs, code and tests agree: `tests/gates.rs` checks this file's tables
  against the code.
- 18 Executable capsules are isolated: each instance has its own session,
  grants and lifecycle inside the one Runtime.
