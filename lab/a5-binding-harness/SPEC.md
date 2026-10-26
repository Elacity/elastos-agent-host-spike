# A5 grant binding: the acceptance harness

LAB DRAFT for review by the Runtime team (Anders). It is design input for M1
check A5, *Grants bound to agent identity, session, capsule instance and owned
storage*. A5 comes before A4 and A7 acceptance. A Public-storage read does not
establish binding. A check counts only when its whole journey as worded
passes, with refusal evidence from the Runtime.

This folder is the acceptance spec and a harness that a later real-Runtime
run can plug into. Real-Runtime rows for A5 are owned by
`cx-agent-conformance`. This lane writes none of those rows and does not
touch that lane's folders.

`lab/grant-binding` is the pure-Rust reference model. It counts toward no M1
check. This harness talks to the operator's public API. It changes no Runtime
code and no file outside `lab/a5-binding-harness/`.

## 1. The check

A grant is bound to four dimensions at once:

1. the verified **agent identity**;
2. the **session** that minted it;
3. the **capsule instance** that holds it;
4. the **owned storage** root of that instance.

The guest may carry claims. The stored binding and the host record decide
every use. A forged identity, session, instance or root changes nothing.

A5 stays open until every row below has run against a live operator and
passed. One dimension in isolation does not close the check.

## 2. The Runtime today

Paths are under `elastos/`. Line numbers are re-read from this checkout on
every run (`src/capability.rs`).

- A capability token names a capsule id, a resource and an action
  (`crates/elastos-runtime/src/capability/token.rs`). It holds no agent
  identity, no session and no owned storage root.
- `grant` takes a capsule id and stores that id on the token
  (`crates/elastos-runtime/src/capability/manager.rs`). `validate` refuses a
  caller whose capsule id differs (`WrongCapsule`). That is a capsule-id
  check. It is not A5: it does not bind identity, session or owned storage,
  and it is not a public API journey.
- `GET /api/capability/list` returns the caller's own session grants
  (`crates/elastos-server/src/api/handlers/capability.rs`). The list entry
  has request id, resource, action, duration and time. It names no identity,
  session, instance or owned root. There is no `all_sessions_live` scope
  (RA-1).
- Ending a session emits `invalidated` and revokes no grant
  (`crates/elastos-runtime/src/session/registry.rs`). There is no shell route
  that reads a settled request record (RA-2).
- `elastos run` still builds storage at `/tmp/elastos/storage`
  (`crates/elastos-server/src/run_cmd.rs`, three sites). That is not a
  per-instance owned root (RA-3).
- `scope_current_user_alias` resolves `Users/self`. Any other path, `UsersAI`
  included, is left unchanged
  (`crates/elastos-server/src/resource_bridge.rs`).
  `principal_localhost_root` maps to `localhost://Users/<hash>` only
  (`crates/elastos-server/src/auth.rs`) (RA-5).
- A component launch answers `completed` after `run` returned, with no
  session, and the provider refuses a resident stop
  (`crates/elastos-server/src/api/routes.rs`,
  `crates/elastos-compute/src/providers/component.rs`) (RA-6).
- A Public-storage read through the localhost provider can succeed today.
  That read is not a bound grant.

## 3. Capabilities the harness needs

The harness names the ranked Runtime asks from `lab/runtime-asks` (#309). It
extends existing routes where one exists (PRINCIPLES.md 10).

| ID | Capability | Needed by |
| --- | --- | --- |
| RA-1 | a shell view of every session's live grants | A5-ID-POS, A5-ID-REPLAY, A5-SESS-POS, A5-SESS-END, A5-INST-POS, A5-INST-SIB |
| RA-2 | the Runtime settles an ended requester's pending requests, and the shell reads who settled | A5-SESS-END |
| RA-3 | the run launcher takes its storage directory from the selected Home | A5-STOR-POS, A5-STOR-OTHER, A5-PUB |
| RA-5 | a UsersAI alias that resolves to the verified agent principal's root | A5-ID-POS, A5-ID-REPLAY, A5-STOR-POS, A5-STOR-OTHER, A5-PUB |
| RA-6 | resident component instances: world, launch, list, stop | A5-ID-POS, A5-ID-REPLAY, A5-SESS-POS, A5-SESS-END, A5-INST-POS, A5-INST-SIB, A5-STOR-POS, A5-STOR-OTHER |

RA-4 and RA-7 are not named here. They unblock A15 and A11.

### RA-1 Live-grant view

`GET /api/capability/list?scope=all_sessions_live`, shell only, as #293 and
#309 ask. Each entry names `request_id`, `session_id`, `identity`,
`instance_id`, `resource`, `action` and `owned_root`. Exhausted, revoked and
expired grants are left out.

Gap evidence: the list selects the caller's session; the entry type has no
binding fields; the file lacks `all_sessions_live`.

### RA-2 Session end settles grants

When a session ends, the Runtime denies each of its pending requests and
revokes its live grants within the bound. The shell reads the record:

```text
GET /api/capability/requests?session=<session_id>
```

`settled_by` is `runtime`. A later use of a revoked grant is refused by the
Runtime, not by the guest.

Gap evidence: `invalidate_session` revokes nothing; no shell route reads
settled requests.

### RA-3 Owned storage under Home

`elastos run` takes storage from the selected Home, as #290 and #309 ask.
Each resident instance then has its own root under that Home. The grant
names `UsersAI/<identity>/<session>/<instance>`.

Gap evidence: three `create_runtime("/tmp/elastos/storage")` call sites.

### RA-5 UsersAI principal root

`UsersAI/self` resolves to the verified agent principal's root, like
`Users/self`. A request for another agent's `UsersAI` root is refused. A
grant's owned root is that resolved name.

Gap evidence: the alias leaves `UsersAI` unchanged; the only
principal-to-root map is `localhost://Users/<hash>`.

### RA-6 Resident instances

World, launch, list and stop for resident instances, as #293 (RI-1 to RI-4)
and #309 ask. Two launches of one capsule give two instances with different
`id` and `session_id`. The session is the Bus session on every grant of that
instance.

Gap evidence: the component world is `run` only; launch answers `completed`
with no session; stop refuses a running component.

## 4. Rows

| Check | Acceptance row | Needs |
| --- | --- | --- |
| A5-ID-POS | `acceptance_a5_identity_grant_used_by_bound_agent` | RA-1, RA-5, RA-6 |
| A5-ID-REPLAY | `acceptance_a5_identity_grant_replayed_by_other_agent` | RA-1, RA-5, RA-6 |
| A5-SESS-POS | `acceptance_a5_session_grant_used_in_bound_session` | RA-1, RA-6 |
| A5-SESS-END | `acceptance_a5_session_grant_reused_after_session_end` | RA-1, RA-2, RA-6 |
| A5-INST-POS | `acceptance_a5_instance_grant_used_by_bound_instance` | RA-1, RA-6 |
| A5-INST-SIB | `acceptance_a5_instance_grant_used_by_sibling` | RA-1, RA-6 |
| A5-STOR-POS | `acceptance_a5_owned_storage_grant_used_on_bound_root` | RA-3, RA-5, RA-6 |
| A5-STOR-OTHER | `acceptance_a5_owned_storage_grant_pointed_at_other_root` | RA-3, RA-5, RA-6 |
| A5-PUB | `acceptance_a5_public_storage_read_is_not_binding` | RA-3, RA-5 |

Every journey starts with `GET /api/health` ok. Every journey launches only
through the operator's shell API. Every journey ends by stopping what it
launched. A failed journey stops first, then reports.

The owned resource is `localhost://UsersAI/<identity>/<session>/<instance>/notes`.
The Public resource is `localhost://Public/a5-binding/notes`. Positive rows
use the owned resource only.

### Agent identity

**A5-ID-POS.** Launch agent A and agent B, two verified principals. Seed A's
owned root. Mint a grant for A's owned read. The live-grant view shows that
grant bound to A's identity, A's session, A's instance and A's owned root.
A uses the grant on that root. The Runtime allows. The bytes come from A's
root through the operator.

**A5-ID-REPLAY.** Same mint for A. B presents A's grant on A's root. The
Runtime refuses. The reason contains `identity`. A's grant stays bound to A
in the live-grant view. B's own request, if any, stays B's.

### Session

**A5-SESS-POS.** Launch one instance. Mint a grant in its session. The
live-grant view names that session. The same session uses the grant on the
bound root. The Runtime allows.

**A5-SESS-END.** Mint a grant in session S. End S. The request record is
`denied` or the grant is revoked, `settled_by` is `runtime`, and the harness
never decided it. A later use of that grant is refused. The reason contains
`session`. The live-grant view no longer lists it.

### Capsule instance

**A5-INST-POS.** Launch one instance. Mint a grant for it. The live-grant
view names that instance. The same instance uses the grant. The Runtime
allows.

**A5-INST-SIB.** Launch instance X and sibling Y of the same capsule and the
same agent identity. Mint a grant for X. Y presents X's grant. The Runtime
refuses. The reason contains `instance`. X's grant stays bound to X.

### Owned storage

**A5-STOR-POS.** Launch one instance. The grant's `owned_root` is
`UsersAI/<identity>/<session>/<instance>`. A use on that root or a child
succeeds.

**A5-STOR-OTHER.** Same grant. A use pointed at the sibling instance's root
is refused. The reason contains `owned root` or `outside`. A's root is
unchanged.

**A5-PUB.** Present a Public-storage read as A5 binding evidence. The harness
refuses that claim. A bind or use of `localhost://Public/...` as a bound
grant is refused by the Runtime with `public storage read does not bind`. A
successful Public read, if the operator serves one, is recorded and is not
a PASS.

## 5. What proves the Runtime refused

A refusal counts only when the operator produced it. The harness accepts:

- an HTTP status from the operator on a grant-use or validate route, with
  the Runtime's reason text;
- a request record from `GET /api/capability/requests` whose `settled_by`
  is `runtime` and whose decision contains the dimension name;
- a live-grant view that still shows the original binding and does not show
  a grant for the refusing caller.

A refusal does not count when:

- a fixture guest returns "denied" with no operator status and no request
  id;
- the double, or any in-process stand-in, is the only speaker;
- the only event is a Public-storage read, granted or denied by the
  localhost provider without a binding record.

`src/contract.rs` is the one checker: `require_runtime_refusal` and
`require_runtime_allow`. `grade_pass` builds `PASS` only from evidence whose
source is the live operator and which does not claim a Public resource as a
binding.

## 6. Grading

- **BLOCKED**: a capability the row needs is missing. The row names the
  capabilities and the evidence for each gap, read from this checkout on
  every run. A blocked row never reads setup or contacts an operator.
- **SKIPPED**: every capability is there, but the live setup is incomplete:
  `A5_RUNTIME_COORDS` or the shell attach. SKIPPED is a failed command,
  never a pass. `counts_as_accepted` is true only for `PASS`.
- **FAIL**: the journey ran against the operator and an assertion failed,
  or a journey returned ok without live operator evidence.
- **PASS**: the journey ran against the operator and every assertion held,
  with Runtime evidence. No other path produces PASS.

`tests/gates.rs` keeps the BLOCKED grades current. When a gap's evidence
stops holding, `blocker_evidence_still_holds` fails and names the
capability to re-measure. A capability leaves the missing list only after
a live journey measured it.

The reference double under `tests/common/` runs every journey for the
harness's own tests. The honest double passes. A fixture that fakes a
refusal, a skipped row counted as passed, and a Public-storage read counted
as binding are each refused for their own reason. The double is not the
Runtime and counts toward no M1 check.

## 7. Open questions for Anders

1. Path layout. This SPEC names `UsersAI/<identity>/<session>/<instance>`,
   as #290. The journal contract names `UsersAI/self`. A15 names
   `UsersAI/<agent>/notes`. Which layout should A5 bind?
2. Public grants. Should the Runtime refuse to mint a grant on `Public/` as
   a bound grant (the grant-binding `PublicRead` rule), or only the harness
   refuse to count a successful Public read as A5 evidence?
3. RA-1 route form. #309 records two callers: the plain
   `GET /api/capability/list` and `?scope=all_sessions_live`. Which one
   carries identity, instance and owned root?
4. Session end. Does `invalidate_session` revoke grants (RA-2), or is the
   A5 session refusal a validate-time check against the live session
   registry?
5. Token or handle. A5 can be a token with identity, session and owned
   root, or a host-side handle (#463, #177). The journeys stay the same.
   Which record should the live-grant view read?
6. Whole-check rule. This folder keeps one row per dimension plus Public.
   A5 stays open until every row PASSES. Should A4/A7 wait on that, or on a
   single combined journey?

## 8. Principles

- 3 No ambient authority: a grant is bound to one identity, session,
  instance and owned root.
- 7 One authority model: agents ask and the shell decides through the same
  Runtime routes a person's capsules use.
- 10 One canonical path: the harness extends the existing capability and
  capsule routes; it names the RA-* asks already written.
- 11 Fail closed, then explain: a mismatched use is refused with the
  dimension name.
- 12 Docs, code and tests agree: `tests/gates.rs` checks this file's
  tables against the code.
- 18 Executable capsules are isolated: each instance has its own session,
  grants and owned root inside the one Runtime.
