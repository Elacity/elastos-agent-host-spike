# RA-1 A shell view of every session's live grants

Rank 1 of 7. Effort M (2 points). Checks named: A6, A10, A11, A12 (4). Score 2.00.

Sources: RI-7 in #293 (`lab/resident-instances/SPEC.md`) and AC-021-GRANTS in
`lab/agent-conformance/GAPS.md`. Both labs ask for the same Runtime behaviour.
This file merges them.

## The ask

A shell session can read the live grants of every session. The Runtime leaves
out grants that are exhausted, revoked or expired. A client session keeps
seeing only its own grants.

## Checks it unblocks

| Check | Acceptance row that names it | Where | What else the row needs |
| --- | --- | --- | --- |
| A10, A11, A12 (lab half, grant census) | `run_leaves_no_live_grant`, blocked: AC-021-GRANTS | `lab/agent-conformance/tests/effects.rs` | No other Runtime change. With the query-only route form (below), one lab line changes. Runs on the Mac. |
| A6 | `acceptance_a6_instance_grant_does_not_authorise_sibling`, blocked: RI-1; RI-2; RI-3; RI-4; RI-7 | #293 `tests/acceptance.rs` | RA-6 (resident core) |
| A12 | `acceptance_a12_stopped_instances_leave_nothing_behind`, blocked: RI-1; RI-2; RI-3; RI-4; RI-7 | #293 `tests/acceptance.rs` | RA-6 (resident core) |

The report prints `run_leaves_no_live_grant` with the label "cleanup census, lab
half of A10/A11/A12" (`src/report.rs:227`).

## Today: evidence

Paths are in this repo at `a76268e7`, the base commit. `check-citations.py`
re-reads every row.

| Citation | Text on that line | What it shows |
| --- | --- | --- |
| `elastos/crates/elastos-server/src/api/server.rs:247` | `.route("/api/capability/list", get(handlers::list_capabilities))` | The list route is in the group for any authenticated session. |
| `elastos/crates/elastos-server/src/api/server.rs:258` | `// Shell-only routes (require shell session)` | The shell-only group starts here. |
| `elastos/crates/elastos-server/src/api/server.rs:260` | `.route("/api/capability/pending", get(handlers::list_pending))` | The shell already reads pending requests of every session on a shell-only route. |
| `elastos/crates/elastos-server/src/api/handlers/capability.rs:226` | `pub struct PendingRequestOutput {` | The pending list entry. It carries `session_id`, request id, resource and action. |
| `elastos/crates/elastos-server/src/api/handlers/capability.rs:244` | `pub async fn list_pending(` | The handler for that route. |
| `elastos/crates/elastos-server/src/api/handlers/capability.rs:428` | `pub async fn list_capabilities(` | The handler for the grant list. |
| `elastos/crates/elastos-server/src/api/handlers/capability.rs:434` | `list_session_granted(&session_id)` | The list selects grants by the caller's own session. |
| `elastos/crates/elastos-runtime/src/capability/pending.rs:517` | `r.session_id.to_string() == session_id && r.is_granted()` | The store filter keeps every request whose status is `Granted`. |
| `elastos/crates/elastos-runtime/src/capability/pending.rs:177` | `pub fn is_granted(&self) -> bool {` | `is_granted` reads the request status. It does not read use counts. |
| `elastos/crates/elastos-server/src/api/handlers/capability.rs:335` | `GrantDuration::Once => TokenConstraints::new(0, false, None, Some(1)),` | A `once` grant is a token with `max_uses` 1. |
| `elastos/crates/elastos-runtime/src/capability/manager.rs:487` | `self.store.try_use_token(&token.id, max_uses)` | The use is spent when `validate` runs. The pending store is not touched. |
| `elastos/crates/elastos-runtime/src/capability/store.rs:140` | `pub async fn try_use_token(` | The counter lives in the capability store. |
| `elastos/crates/elastos-runtime/src/capability/manager.rs:95` | `store: Arc<CapabilityStore>,` | The manager's store field is private. |
| `elastos/crates/elastos-runtime/src/capability/manager.rs:641` | `pub fn current_epoch(&self) -> u64 {` | One of the two public getters on the manager. |
| `elastos/crates/elastos-runtime/src/capability/manager.rs:646` | `pub fn audit_log(&self) -> &Arc<AuditLog> {` | The other public getter. No getter reads use counts or revocations. |
| `elastos/crates/elastos-runtime/src/capability/store.rs:111` | `pub fn is_epoch_valid(` | The store has a reader for the epoch. |
| `elastos/crates/elastos-runtime/src/capability/store.rs:116` | `pub async fn get_use_count(` | The store has a reader for the use count. |
| `elastos/crates/elastos-runtime/src/capability/store.rs:161` | `pub async fn is_token_revoked(` | The store has a reader for revocation. |
| `elastos/crates/elastos-runtime/src/capability/pending.rs:525` | `pub async fn revoke_request(&self, request_id: &str) {` | A revoked grant changes the request to `Denied`, so it leaves the list. |
| `elastos/crates/elastos-server/src/api/handlers/capability.rs:345` | `None, // No expiry for now (session-scoped)` | A grant token carries no expiry today. |
| `elastos/crates/elastos-server/src/api/handlers/capability.rs:412` | `pub struct CapabilityOutput {` | The list entry type. Its fields are request id, resource, action, duration and time. It holds no token. |
| `elastos/crates/elastos-runtime/src/session/registry.rs:113` | `pub async fn invalidate_session(` | A session ends here. |
| `elastos/crates/elastos-runtime/src/session/registry.rs:131` | `reason: "invalidated".to_string(),` | Ending a session emits an audit event. It revokes no grant. |
| `elastos/crates/elastos-server/src/run_cmd.rs:265` | `.run_local(capsule_dir, capsule_args)` | The `run` client leaves after this call. It sends no detach and no revoke. |
| `lab/agent-conformance/GAPS.md:764` | `Shell-authorized view of every session's live grants` | The blocker row for `run_leaves_no_live_grant`. |
| `lab/agent-conformance/GAPS.md:790` | `scope: "all_sessions_live"` | The lab expects this marker in the list response. |
| `lab/agent-conformance/tests/effects.rs:676` | `#[ignore = "blocked: AC-021-GRANTS"]` | The row is ignored with its blocker ID. |
| `lab/agent-conformance/tests/effects.rs:678` | `exercise_read(Effect::GrantedRead, ReadOutcome::Granted, true);` | The row has a written body. The last argument requires live grants. |
| `lab/agent-conformance/tests/common/grants.rs:788` | `self.call("GET", "/api/capability/list", &Value::Null)?` | agent-conformance calls the plain list route as the shell. |
| `lab/agent-conformance/tests/common/grants.rs:1220` | `if response["scope"] != "all_sessions_live" {` | Without the marker the grade stays BLOCKED. |
| `lab/agent-conformance/tests/common/grants.rs:1224` | `return Err("live grant leftover");` | A marked list with an entry fails the row. |
| `lab/agent-conformance/src/report.rs:227` | `cleanup census, lab half of A10/A11/A12` | The report label for the row. |
| `lab/agent-conformance/fixtures/grants.json:8` | `"duration": "once"` | The lab seeds one `once` grant. |
| `lab/agent-conformance/GAPS.md:794` | `F-cleanup-grant is deferred until` | The planned falsifier for this row is not written yet. |
| `#293 lab/resident-instances/SPEC.md:84` | `RI-7` | The resident SPEC names the same capability and the checks A6 and A12. |
| `#293 lab/resident-instances/SPEC.md:217` | `scope=all_sessions_live` | The resident SPEC asks for a query parameter on the same route. |
| `#293 lab/resident-instances/src/http.rs:515` | `"/api/capability/list?scope=all_sessions_live",` | The resident adapter sends that query. |
| `#293 lab/resident-instances/tests/acceptance.rs:28` | `blocked: RI-1; RI-2; RI-3; RI-4; RI-7` | The A6 row names RI-7. |
| `#293 lab/resident-instances/tests/acceptance.rs:46` | `blocked: RI-1; RI-2; RI-3; RI-4; RI-7` | The A12 row names RI-7. |

## Smallest change

1. Add one read-only method on `CapabilityManager` that answers "can this token
   still be used now?". It reads the store the manager already owns: epoch,
   individual revocation, use count against `max_uses`, and the token's own
   expiry. A handler cannot do this today. The store field is private and the
   manager has two public getters, neither of which reads use counts or
   revocations (`manager.rs:95`, `:641`, `:646`).
2. In `list_capabilities`, when the caller is a shell session and asks for the
   global view, list every `Granted` request that passes that test. Add
   `"scope": "all_sessions_live"` to the response, and add the session id to
   each entry (today's entry type has none). Every other caller keeps today's
   own-session list.

This touches two crates, `elastos-runtime` (the method) and `elastos-server`
(the handler and the response marker). It adds no route if the query form is
used.

### Route form: the two labs disagree

agent-conformance calls the plain `GET /api/capability/list` as the shell and
expects the marker (`grants.rs:788`, `:1220`). The resident harness calls
`GET /api/capability/list?scope=all_sessions_live` (`http.rs:515`). Two options:

- The Runtime returns the marked global view to a shell session on both calls.
  Both labs pass as written. The plain call changes meaning for shell sessions.
  A search of this tree outside `lab/` finds no other caller of
  `/api/capability/list`.
- The Runtime serves the global view only with the query. The plain call stays
  as it is. agent-conformance then changes its one call at `grants.rs:788`.

Anders picks one. Either way the other lab's contract is unaffected.

## How it fits the capability and grant model

- The view is read-only. It mints, revokes and settles nothing.
- It uses the two records that already hold grant state: the pending store for
  who asked and what for, and the capability store for use, revocation and
  epoch. No third record appears (Principle 10, one canonical path).
- Only a shell session sees it, like `/api/capability/pending` (Principle 7,
  one authority model: the shell decides and the shell can see what it decided).
- It exposes fields the shell already reads for pending requests: request id,
  session id, resource, action (`capability.rs:226`). The list entry type holds
  no token (`capability.rs:412`).

## Risks

- **"Live" needs an exact definition.** A `session` grant of a client that has
  exited stays live. Ending a session revokes nothing (`registry.rs:113`,
  `:131`), and the `run` client sends no detach (`run_cmd.rs:265`). The view
  will list that grant. This is
  the right answer for A12, but a journey that uses a `session` grant fails the
  census until RA-2 and RA-6 end grants with their owner. The lab's seeded grant
  is `once`, so `run_leaves_no_live_grant` does not meet this case.
- **Point in time.** The view is a snapshot. A use can happen between the read
  and the check.
- **Expiry.** Grant tokens carry no expiry today (`capability.rs:345`). The
  expiry test in the new method has nothing to filter until grants carry one.
- **Review class.** The change is in capability and auth code. `AGENTS.md`
  requires an independent adversarial review for that code.

## Acceptance test already written

- **`run_leaves_no_live_grant`** in `lab/agent-conformance/tests/effects.rs`.
  Class: READY. The body is written. It passes when `live_grant_state` returns
  `pending:0 grants:0`, which needs the `all_sessions_live` marker and an empty
  list. Today it is ignored with `blocked: AC-021-GRANTS`. It runs on the Mac
  only, because the harness refuses other hosts (`harness.rs:18`).
- **`acceptance_a6_*` and `acceptance_a12_*`** in #293. Class: READY as
  journeys, but the fixture guests are not written (see RA-6) and each row also
  needs RA-6.
- The lab's synthetic cases at `grants.rs:1550-1562` already show both ends:
  a marked empty list gives `grants:0`, a marked list with an entry gives
  `live grant leftover`.

## Not shown

- No Runtime change was run. No grade changed.
- `run_leaves_no_live_grant` needs a Mac. It was not run here.
- The planned falsifier F-cleanup-grant (seed a `session` grant, expect
  `live grant leftover`) is deferred in `GAPS.md` and is not written.
