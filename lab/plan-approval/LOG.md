# plan-approval lane log

> A proposal carries no authority.

- 001: `preview` returns the plan bytes and `agent_conformance::identity::sha256` of those bytes and calls no `StandIn` method; the exact-name test reads the stand-in only through `get_capability_list` and `get_capsules`; two hand-run plants caught and restored; 1 test, 2 plants.
- 009: `deny_shown_plan` calls the one shell deny route with reason `deny the shown plan`; `deny_one_shown_step` proves the deny store, the pending sibling, its one allow-once grant and the `unknown grant` refusal; three hand-run plants caught and restored; 1 test, 3 plants.
- 010: `age_shown_plan` only calls `set_instant`; `unanswered_shown_step_expires` proves a shown step unanswered for 300 seconds expires while the step approved once stays granted; two hand-run plants caught and restored; 1 test, 2 plants.
- 011: `stop_shown_session` only calls `delete_capsule` as the shell with reason `stop the shown session`; `stop_settles_that_sessions_shown_steps` proves the stopped session's pending step is denied by the runtime and its allow-once grant revoked while the other session's step stays pending; two hand-run plants caught and restored; 1 test, 2 plants.
- 012: `shown_allow_once_expires` finds the stand-in's own grant lifetime through the existing `age_shown_plan` and proves an unspent allow-once leaves the live list there and is refused at `execute` with `grant is not live: Expired`, while the spent step stays refused as `Exhausted` and both requests stay granted; two hand-run plants caught and restored; 1 test, 2 plants.
- 013: `approve` gains `duration: &str` after `request_id` and sends that word as the `duration` key, staying the one grant call; `shown_session_lasts_until_stop` proves a `session` grant survives two uses of its plan and the stand-in's once lifetime, refuses another duration word and a different plan without spending it, and is revoked by `stop_shown_session` so `execute` refuses it as `Revoked`; three hand-run plants caught and restored; 1 test, 3 plants.
- 014: `shown_grant_authorises_only_its_session` proves a shown grant authorises only the session that asked for it; another session's use is refused as `wrong capsule` and spends nothing, both client live lists show one grant each without `session_id`, and each session's own use still runs until its `once` grant leaves the live list; two hand-run plants caught and restored; 1 test, 2 plants.
- 015: `owner_approves_only_the_shown_hash` proves the owner's grant mints only the hash the shown request stored; another plan, an empty hash and a 63-character hash are refused with `approved plan does not match the requested plan` and mint nothing while the request stays pending, and the exact hash then grants one use that `execute` spends; two hand-run plants caught and restored; 1 test, 2 plants.
- 016: `approve` gains `caller: Caller<'_>` after `stand_in` and passes that value to `post_capability_grant`, staying the one grant call; `agent_cannot_approve_its_own_shown_plan` proves the session that posted a plan and the other running session are refused with `This endpoint requires shell privileges` before the body is read, for another hash, an empty hash, a 63-character hash and the duration word `standing` too, and that the shell's call with the exact hash then grants one use which `execute` spends; two hand-run plants caught and restored; 1 test, 2 plants.
- 017: `execute` gains `caller: Caller<'_>` after `stand_in` and passes that value to `post_capability_validate`, staying the one use call; `shell_cannot_spend_a_shown_grant` proves a shell caller is refused for the bound plan, a different plan and empty plan bytes before the plan check, the grant stays live, the other session is refused as `wrong capsule` without a spend, the owning session's use then runs once, and a shell call after that spend is still the session refusal; two hand-run plants caught and restored; 1 test, 2 plants.
- 023: `deny_one_shown_step` stores both shown steps through `journeys::request` after `running_agent`; the shell deny of `request-1` for `PLAN_A` settles it as denied and leaves `request-2` for `PLAN_B` pending, whose allow-once `approve` lets `execute` spend `PLAN_B`; the test calls no `seed_request` and the helpers stay unchanged; two hand-run plants caught and restored; 1 test, 2 plants.
- 024: `only_a_live_session_submits_a_shown_plan` proves `request` is submitted only by a live instance session: the never-launched session and the stopped session are each refused for `PLAN_A`, `PLAN_B` and empty plan bytes and store nothing, while the other running session's submit stores one pending request that the shell grants and that session's `execute` spends; two hand-run plants return the route error as `Ok("request-1")` and neither calls `seed_request`; 1 test, 2 plants.
- 020: `deny_shown_plan` gains `caller: Caller<'_>` after `stand_in` and passes that value to `post_capability_deny`, staying the one deny call; `agent_cannot_deny_its_own_shown_plan` proves the session that posted the shown plan and the other running session are refused with `This endpoint requires shell privileges` for their own step, the sibling step and an absent id before the deny body is read, both requests stay pending with the live list empty, the shell's deny then settles `request-1` and leaves `request-2` pending for its allow-once `approve` and `execute`; two hand-run plants caught and restored; 1 test, 2 plants.
- 022: `running_agent` gains `caller: Caller<'_>` after `stand_in`, passes it to `get_capsules` and `post_capsules`, and returns `Result<String, (u16, String)>`, staying the one launch journey; `agent_cannot_launch_a_shown_session` proves a client launch for a never-launched id, an absent id and an empty id is the 403 shell refusal before `admit_resident` and stores nothing, the shell's launches then start `component-1` and `component-2` and a client launch after them mints no `component-3`, and both shell sessions submit, are granted once and spend that one use; two hand-run plants caught and restored; 1 test, 2 plants.
- 025: `read_shown_request` is the one status call and passes the caller it is given to `get_capability_request`, so an absent id is not found for every caller, another session, an empty id and the shell are refused as another session's request, and the owning session reads only `{"status":"pending"}`, `{"status":"granted"}`, the denied reason or the expired reason with no plan; two hand-run plants caught and restored; 1 test, 2 plants.
- 028: `journeys::request` gains `resource` and `action` after `plan` and passes both to the one submit route; `shown_submit_names_a_declared_ask` proves a shown submit stores a pending request only for an exact declared ask, while two early refusals, five undeclared pairs, a shell submit and an unknown instance store nothing, `READ` and `Write` are stored lowercased, the shared file is stored as its own resource, and the once grant of the write request carries action `write` until its one use; two hand-run plants caught and restored; 1 test, 2 plants.

## 001

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md) Request flow step 5:

> A proposal carries no authority.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib preview_makes_no_effect -- --exact
```

### F-preview-writes-grant

- old bytes, 17: `let _ = stand_in;`
- new bytes, 164: `stand_in.seed_grant("req-plant", "component-1", "localhost://Public/plan-approval/a.txt", "read", "once", 1, agent_conformance::standin_runtime::Life::Live, false);`
- planted crate compiled; `preview_makes_no_effect` failed at `src/lib.rs:56:5` on the first unchanged-grants assertion: `assertion left == right failed: the preview returned the plan bytes, the hash is sha256 of those bytes, and the live grants and the capsule list are unchanged on a fresh stand-in`; left held the seeded `req-plant` entry, right was empty.
- restored, the test passes.

### F-preview-fixed-hash

- old bytes, 41: `agent_conformance::identity::sha256(plan)`
- new bytes, 77: `"0000000000000000000000000000000000000000000000000000000000000000".to_owned()` (the literal is 64 zeroes; `.to_owned()` makes it an owned `String` so the planted crate compiles, per the spec check).
- planted crate compiled; `preview_makes_no_effect` failed at `src/lib.rs:74:5` on the `previews[0].sha256` assertion: left `0000000000000000000000000000000000000000000000000000000000000000`, right `156e544f8e98e81c5e504dfd7ed21d2adb703b8f9dafa8701b064255b69f85ae`.
- restored, the test passes.

After both restores, `git diff -- lab/plan-approval/src/lib.rs` shows no plant. The restored proof command took 0.56 s real. This lane has no `falsifiers.json`; the runner has no `plan-approval` command (BACKLOG item 3).

## 009

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md) Request flow step 8:

> If additional consent is required, Runtime records a pending request and
> Home or Inbox presents it. The UI does not mint the grant itself.

And the Delegation section:

> Allow once authorizes one exact operation.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib deny_one_shown_step -- --exact
```

### F-deny-grants

- old bytes, 175: `    stand_in.post_capability_deny(\n        Caller::Shell,\n        &json!({\n            "request_id": request_id,\n            "reason": "deny the shown plan",\n        }),\n    )`
- new bytes, 206: `    stand_in.post_capability_grant(\n        Caller::Shell,\n        &json!({\n            "request_id": request_id,\n            "duration": "once",\n            "rationale": "owner approved",\n        }),\n    )`
- planted crate compiled; `deny_one_shown_step` failed at `src/lib.rs:544:5` on the denied-request assertion: `assertion left == right failed: the denied step stores the shell reason and settler`; left held status `granted` with `decision_reason` `owner approved`, right expected `denied` with `deny the shown plan`.
- restored, the test passes.

### F-deny-sibling

- old bytes, 175: the same `post_capability_deny` call block as F-deny-grants.
- new bytes, 439: `    let denied = stand_in.post_capability_deny(\n        Caller::Shell,\n        &json!({\n            "request_id": request_id,\n            "reason": "deny the shown plan",\n        }),\n    );\n    if denied.is_ok() {\n        return stand_in.post_capability_deny(\n            Caller::Shell,\n            &json!({\n                "request_id": "req-b",\n                "reason": "deny the shown plan",\n            }),\n        );\n    }\n    denied`
- planted crate compiled; `deny_one_shown_step` failed at `src/lib.rs:568:5` on the sibling assertion: `assertion left == right failed: a shell deny settles one step and the sibling stays pending`; left held `denied`, right expected `pending`.
- restored, the test passes.

### F-missing-grant-appends-id

- old bytes, 163: `    stand_in.post_capability_validate(\n        Caller::Client { session_id },\n        &json!({ "request_id": request_id, "plan_sha256": plan_sha256(plan) }),\n    )`
- new bytes, 362: `    let result = stand_in.post_capability_validate(\n        Caller::Client { session_id },\n        &json!({ "request_id": request_id, "plan_sha256": plan_sha256(plan) }),\n    );\n    match result {\n        Err((400, reason)) if reason == "unknown grant" => {\n            Err((400, format!("unknown grant: {request_id}")))\n        }\n        result => result,\n    }`
- planted crate compiled; `deny_one_shown_step` failed at `src/lib.rs:579:5` on the first denied-step execute assertion: `assertion left == right failed: running a denied step is refused with unknown grant, without an id`; left held `Err((400, "unknown grant: req-a"))`, right expected `Err((400, "unknown grant"))`.
- restored, the test passes.

After all three restores, `git diff -- lab/plan-approval/src/lib.rs` shows no plant, and the diff adds only `deny_shown_plan` and `deny_one_shown_step`. The restored proof commands took 1.06 s real. This lane has no `falsifiers.json`.

## 010

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md), Session and interaction contract:

> approval requests that remain pending across UI, Agent Host, or Runtime
> restart until approved, denied, expired, revoked, or cancelled;

This task proves the expired settlement; restart across a process is BACKLOG item 4.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib unanswered_shown_step_expires -- --exact
```

### F-age-skips

- old bytes, 27: `stand_in.set_instant(secs);`
- new bytes, 25: `let _ = (stand_in, secs);`
- planted crate compiled; `unanswered_shown_step_expires` failed at `src/lib.rs:798:5` on the expired-step assertion: `assertion left == right failed: an unanswered shown step expires at 300 seconds and keeps its plan hash`; left held `status` `pending` with `settled_by` null, right expected `status` `expired` with `decision_reason` `Request timed out` and `settled_by` `runtime`.
- restored, the test passes.

### F-age-early

- old bytes, 27: `stand_in.set_instant(secs);`
- new bytes, 26: `stand_in.set_instant(300);`
- planted crate compiled; `unanswered_shown_step_expires` failed at `src/lib.rs:758:5` on the 299-second pending assertion: `assertion left == right failed: an unanswered shown step is still pending at 299 seconds`; left held `status` `expired` with `decision_reason` `Request timed out` and `settled_by` `runtime`, right expected `status` `pending` with `settled_by` null.
- restored, the test passes.

After both restores, `git diff -- lab/plan-approval/src/lib.rs` shows no plant, and the diff adds only `age_shown_plan` and `unanswered_shown_step_expires`. The restored proof command set (`unanswered_shown_step_expires`, `deny_one_shown_step`, `a_grant_bound_to_one_plan_is_refused_for_another_plan`, `plan_sha256_hashes_the_exact_bytes`, `preview_makes_no_effect` and the fmt check) took 0.882 s real. This lane has no `falsifiers.json`.

## 011

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md), Session and interaction contract:

> an explicit interrupt or cancel operation that reports its settlement

A stop is that cancel. `stop_shown_session` calls `delete_capsule` as `Caller::Shell` with the id and the one body key `reason`, `stop the shown session`. The shown steps come from `journeys::request`, the allowed step from `approve`, and the revoked grant is read back through `execute`. The stand-in keeps one admitted row per lab CID, so `journeys::running_agent` admits `SignedBundle::distinct` for each session after the first: another lab CID for the second session, through the stand-in's own admission route, with no second launch path.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib stop_settles_that_sessions_shown_steps -- --exact
```

### F-stop-skips

- old bytes, 133: `    stand_in.delete_capsule(\n        Caller::Shell,\n        session_id,\n        &json!({ "reason": "stop the shown session" }),\n    )`
- new bytes, 67: `    let _ = (stand_in, session_id);\n    Ok(serde_json::Value::Null)`
- planted crate compiled; `stop_settles_that_sessions_shown_steps` failed at `src/lib.rs:947:5` (planted tree) on the absent-session assertion: `assertion left == right failed: a stop of an absent session refuses with the id it named`; left held `Ok(Null)`, right expected `Err((400, "unknown instance: component-absent"))`. The settlement assertions behind it fail for the same reason: no stop ran.
- restored, the test passes.

### F-stop-sibling

- old bytes, 133: the same `delete_capsule` call block as F-stop-skips.
- new bytes, 356: `    let stopped = stand_in.delete_capsule(\n        Caller::Shell,\n        session_id,\n        &json!({ "reason": "stop the shown session" }),\n    );\n    if stopped.is_ok() {\n        return stand_in.delete_capsule(\n            Caller::Shell,\n            "component-2",\n            &json!({ "reason": "stop the shown session" }),\n        );\n    }\n    stopped`
- planted crate compiled; `stop_settles_that_sessions_shown_steps` failed at `src/lib.rs:1086:5` (planted tree) on the other-session assertion: `assertion left == right failed: a stop settles that session's shown steps and leaves the other session pending`; left held `request-3` `denied` with `settled_by` `runtime` and `decision_reason` `stopped: stop the shown session`, right expected `pending` with `settled_by` null.
- restored, the test passes.

After both restores, `git diff -- lab/plan-approval/src/lib.rs` shows no plant, and the diff adds only `stop_shown_session`, the distinct-CID admission in `journeys::running_agent` and `stop_settles_that_sessions_shown_steps`. The restored proof command set (the seven commands in the task, the fmt check included) took 2.09 s real. This lane has no `falsifiers.json`.

`journeys::running_agent` changes only its fixture choice: the stand-in refuses a second admit of one CID with `bundle already admitted: <cid>`, so a session after the first admits `SignedBundle::distinct`. Every call still runs admit, launch and start, so this is the one launch journey with no second launch path.

## 012

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md) Request flow step 7:

> Runtime verifies the exact resource, action, operation, principal, session,
> capsule, grant, expiry, and revocation state

This task proves the expiry of an allow-once grant. Revocation of a live grant by a session stop stays 011; restart across a process stays BACKLOG item 4. `age_shown_plan` is the one clock call, and the test calls it; the test never calls `set_instant`. The shown steps come from `journeys::request`, the allow-once is `approve`, and the expired use is read back through the existing `execute`. The test names no instant: it probes the stand-in's own lifetime and walks to the first instant where the unspent grant is absent. `preview`, `plan_sha256`, `approve`, `execute`, `deny_shown_plan`, `age_shown_plan`, `stop_shown_session`, `running_agent`, `request` and the existing tests are unchanged; the diff adds only `shown_allow_once_expires`.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_allow_once_expires -- --exact
```

### F-age-freezes

- old bytes, 27: `stand_in.set_instant(secs);`
- new bytes, 38: `let _ = secs; stand_in.set_instant(0);`
- planted crate compiled; `shown_allow_once_expires` failed at `src/lib.rs:1308:5` on `assert!(!is_live(&stand_in, "request-2"), "the unspent allow-once left the live list")`: the clock never advanced, so the unspent grant stayed live through all 24 probes.
- restored, the test passes.

### F-expired-grant-performs

- old bytes, 163: `    stand_in.post_capability_validate(\n        Caller::Client { session_id },\n        &json!({ "request_id": request_id, "plan_sha256": plan_sha256(plan) }),\n    )`
- new bytes, 353: `    let result = stand_in.post_capability_validate(\n        Caller::Client { session_id },\n        &json!({ "request_id": request_id, "plan_sha256": plan_sha256(plan) }),\n    );\n    match result {\n        Err((400, reason)) if reason == "grant is not live: Expired" => {\n            Ok(json!({ "valid": true }))\n        }\n        result => result,\n    }`
- planted crate compiled; `shown_allow_once_expires` failed at `src/lib.rs:1358:5` (planted tree) on the unspent-grant use assertion: `assertion left == right failed: an unused allow-once expires at the stand-in's grant lifetime, so its use is refused as Expired`; left held `Ok(Object {"valid": Bool(true)})`, right expected `Err((400, "grant is not live: Expired"))`.
- restored, the test passes.

After both restores, `git diff -- lab/plan-approval/src/lib.rs` shows no plant, and the diff adds only `shown_allow_once_expires`. The restored proof command set (the seven test commands in the task, the fmt check included) took 0.896 s real. This lane has no `falsifiers.json`; no id is added.

## 013

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md), Delegation and mandates:

> Allow for this session authorizes a bounded operation set until the session
> ends or the grant is revoked.

`approve` takes the duration word after the request id and sends it unchanged as the route's `duration` key, so it stays the one grant call. `shown_session_lasts_until_stop` walks the stand-in's own once lifetime through `age_shown_plan` without naming an instant, proves the session grant stays live across two uses of its plan, refuses a different plan with `grant is not bound to this plan`, and proves `stop_shown_session` revokes it so `execute` refuses it with `grant is not live: Revoked`. This crate stores no lifetime and does not copy the expiry rule.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_session_lasts_until_stop -- --exact
```

### F-duration-fixed-once

- old bytes, 20: `"duration": duration`
- new bytes, 18: `"duration": "once"`
- planted crate compiled; `shown_session_lasts_until_stop` failed at `src/lib.rs:1442:5` on the invalid-duration assertion: `assertion left == right failed: a shown step allowed for standing is refused with the stand-in's invalid-duration reason`; left held `Ok(Object {"success": Bool(true)})`, right expected `Err((400, "Invalid duration: standing. Expected 'once' or 'session'"))`.
- restored, the test passes.

### F-duration-fixed-session

- old bytes, 20: `"duration": duration`
- new bytes, 21: `"duration": "session"`
- planted crate compiled; `shown_session_lasts_until_stop` failed at the same `src/lib.rs:1442:5` invalid-duration assertion with the same left and right values, because the refused word was granted as a session grant instead of reaching the stand-in's refusal.
- restored, the test passes.

### F-session-omits-hash

- old bytes, 40: the body line `            "plan_sha256": plan_sha256,` with its newline
- new bytes, 0: that line removed, so the grant body carries no plan hash
- planted crate compiled; `shown_session_lasts_until_stop` failed at `src/lib.rs:1472:5` (planted tree) on the session approval: `assertion left == right failed: the owner allows the first shown step for this session`; left held `Err((403, "approved plan does not match the requested plan"))`, right expected `Ok(Object {"success": Bool(true)})`.
- restored, the test passes.

After all three restores, `git diff -- lab/plan-approval/src/lib.rs` shows no plant. The restored proof command set (the fmt check and the eight test commands) took 0.799 s real. This lane has no `falsifiers.json`; no id is added.

## 014

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md) Request flow step 7:

> Runtime verifies the exact resource, action, operation, principal, session,
> capsule, grant, expiry, and revocation state

This task proves the session and capsule check for one shown grant. Expiry stays 012; revocation by a session stop stays 011; the principal stays BACKLOG item 4, so full A15 stays item 4. The test uses only `journeys::running_agent`, `journeys::request`, `approve`, `execute` and `get_capability_list`; it calls no `seed_request`, `post_capability_request`, `post_capability_grant`, `post_capability_validate`, `admit_resident`, `post_capsules`, `finish_start`, `set_instant` or `delete_capsule`. `execute` is the one use call and passes the session it is given. This crate stores no session check of its own and does not copy the stand-in's `session_authorises` or `wrong_capsule`.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_grant_authorises_only_its_session -- --exact
```

### F-execute-fixes-session

- old bytes, 38: `        Caller::Client { session_id },`
- new bytes, 53: `        Caller::Client { session_id: "component-1" },`
- planted crate compiled with one `unused variable: session_id` warning; `shown_grant_authorises_only_its_session` failed at `src/lib.rs:1839:5` on the first cross-session use assertion: `assertion left == right failed: a shown grant authorises only its session: the second session's use of request-1 is refused`; left held `Ok(Object {"valid": Bool(true)})`, right expected `Err((403, "wrong capsule: expected component-1, got component-2"))`.
- restored, the test passes.

### F-wrong-session-returns-valid

- old bytes, 163: `    stand_in.post_capability_validate(\n        Caller::Client { session_id },\n        &json!({ "request_id": request_id, "plan_sha256": plan_sha256(plan) }),\n    )`
- new bytes, 326: `    match stand_in.post_capability_validate(\n        Caller::Client { session_id },\n        &json!({ "request_id": request_id, "plan_sha256": plan_sha256(plan) }),\n    ) {\n        Err((403, reason)) if reason.starts_with("wrong capsule:") => {\n            Ok(json!({ "valid": true }))\n        }\n        result => result,\n    }`
- planted crate compiled; `shown_grant_authorises_only_its_session` failed at `src/lib.rs:1844:5` on the same first cross-session use assertion: `assertion left == right failed: a shown grant authorises only its session: the second session's use of request-1 is refused`; left held `Ok(Object {"valid": Bool(true)})`, right expected `Err((403, "wrong capsule: expected component-1, got component-2"))`.
- restored, the test passes.

After both restores, `git diff -- lab/plan-approval/src/lib.rs` shows no plant, and the diff adds only `shown_grant_authorises_only_its_session`. The restored proof command set (the fmt check and the nine test commands in the task) took 0.72 s real. This lane has no `falsifiers.json`; no id is added.

## 015

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md) Request flow step 8:

> The UI does not mint the grant itself.

and principle 16:

> A visible approval card is not the grant authority.

This task proves that a card's hash mints a grant only when it is the hash the shown request stored. The session check stays 014, expiry stays 012, and full A15 stays BACKLOG item 4. `approve` stays the one grant call and sends the hash it is given; this crate stores no hash compare of its own, so the test calls `approve` and never `post_capability_grant`. The shown step comes from `journeys::request`, the request view and the live list come from the shell reads, and the refused and spent uses come from the existing `execute`.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib owner_approves_only_the_shown_hash -- --exact
```

### F-approve-sends-stored-plan

- old bytes, 250: `    stand_in.post_capability_grant(\n        Caller::Shell,\n        &json!({\n            "request_id": request_id,\n            "duration": duration,\n            "rationale": "owner approved",\n            "plan_sha256": plan_sha256,\n        }),\n    )\n}`
- new bytes, 581: `    let stored = stand_in\n        .get_capability_requests(Caller::Shell, Some("component-1"))?["requests"]\n        .as_array()\n        .and_then(|rows| rows.iter().find(|row| row["request_id"] == request_id))\n        .and_then(|row| row["plan"].as_str())\n        .map(str::to_owned)\n        .unwrap_or_else(|| plan_sha256.to_owned());\n    stand_in.post_capability_grant(\n        Caller::Shell,\n        &json!({\n            "request_id": request_id,\n            "duration": duration,\n            "rationale": "owner approved",\n            "plan_sha256": stored,\n        }),\n    )\n}`
- planted crate compiled; `owner_approves_only_the_shown_hash` failed at `src/lib.rs:1998:9` (planted tree) on the first refused-hash assertion: `assertion left == right failed: the owner grant mints only the hash the shown request stored: the owner's approval with a hash other than 156e544f8e98e81c5e504dfd7ed21d2adb703b8f9dafa8701b064255b69f85ae is refused`; left held `Ok(Object {"success": Bool(true)})`, right expected `Err((403, "approved plan does not match the requested plan"))`. The lookup read the stored hash, so another plan minted a grant.
- restored, the test passes.

### F-approve-appends-x

- old bytes, 27: `"plan_sha256": plan_sha256,`
- new bytes, 41: `"plan_sha256": format!("{plan_sha256}x"),`
- planted crate compiled; `owner_approves_only_the_shown_hash` failed at `src/lib.rs:2021:5` (planted tree) on the exact-hash approval assertion: `assertion left == right failed: the owner grant mints only the hash the shown request stored: the owner's approval with the stored hash is accepted`; left held `Err((403, "approved plan does not match the requested plan"))`, right expected `Ok(Object {"success": Bool(true)})`.
- restored, the test passes.

After both restores, `git diff -- lab/plan-approval/src/lib.rs` shows no plant, and the diff adds only `owner_approves_only_the_shown_hash`. The restored proof command set (the fmt check and the ten test commands in the task) took 1.306 s real. This lane has no `falsifiers.json`; no id is added.

## 016

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md) Request flow step 8:

> The UI does not mint the grant itself.

This task proves that sentence for the agent that posted the shown plan and for the other running session. The hash check stays 015; the session check stays 014; a standing mandate stays BACKLOG item 11. `approve` takes the caller after the stand-in, passes it unchanged to the one grant route and does not judge it, so the stand-in's own shell check runs before the body is read. The test calls only `journeys::running_agent`, `journeys::request`, `approve` and `execute`, and the six refusals leave the request pending with its stored hash and the live list empty.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib agent_cannot_approve_its_own_shown_plan -- --exact
```

### F-approve-forces-shell

- old bytes, 16: `        caller,\n`
- new bytes, 23: `        Caller::Shell,\n`
- planted crate compiled; `agent_cannot_approve_its_own_shown_plan` failed at `src/lib.rs:2230:9` on the first client-refusal assertion: `assertion left == right failed: the agent that showed the plan cannot mint its grant: the client's approval with duration once and hash "156e544f8e98e81c5e504dfd7ed21d2adb703b8f9dafa8701b064255b69f85ae" is refused as a client on a shell-only route`; left held `Ok(Object {"success": Bool(true)})`, right expected `Err((403, "This endpoint requires shell privileges"))`. The posting session minted its own grant.
- restored, the test passes.

### F-duration-before-shell

- old bytes, 36: `    stand_in.post_capability_grant(\n`
- new bytes, 228: `    if duration != "once" && duration != "session" {\n        return Err((\n            400,\n            format!("Invalid duration: {duration}. Expected 'once' or 'session'"),\n        ));\n    }\n    stand_in.post_capability_grant(\n`
- planted crate compiled; `agent_cannot_approve_its_own_shown_plan` failed at `src/lib.rs:2236:9` (planted tree) on the same client-refusal assertion for the `standing` call: `assertion left == right failed: the agent that showed the plan cannot mint its grant: the client's approval with duration standing and hash "156e544f8e98e81c5e504dfd7ed21d2adb703b8f9dafa8701b064255b69f85ae" is refused as a client on a shell-only route`; left held `Err((400, "Invalid duration: standing. Expected 'once' or 'session'"))`, right expected `Err((403, "This endpoint requires shell privileges"))`. The duration check ran before the shell check, so a client reached a body check.
- restored, the test passes.

After both restores, `git diff -- lab/plan-approval/src/lib.rs` shows no plant. The restored proof command set (the fmt check and the eleven test commands in the task) took 3.212 s real. This lane has no `falsifiers.json`; no id is added.

## 017

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md), Non-negotiable boundaries:

> A provider implements an operation; Runtime authorizes the caller.

This task proves that sentence for a shell caller on the use path. The session check stays 014, the hash check stays 015, the shell check on `approve` stays 016, a standing mandate stays BACKLOG item 11, and an audit record of the use stays item 16. `execute` gains `caller: Caller<'_>` after `stand_in` and passes that value to `post_capability_validate`, so it stays the one use call and does not match on `Caller`. Each existing call replaces its session argument with `Caller::Client { session_id: <that session> }` and keeps its other arguments and assertions. The new test calls only `journeys::running_agent`, `journeys::request`, `approve` and `execute`; it does not call `post_capability_validate`, `seed_request`, `set_instant` or `delete_capsule`. This crate stores no copy of the caller check and does not copy the stand-in.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shell_cannot_spend_a_shown_grant -- --exact
```

### F-execute-forces-client

- old bytes, 16: `        caller,\n`
- new bytes, 54: `        Caller::Client { session_id: "component-1" },\n`
- planted crate compiled with one `unused variable: caller` warning; `shell_cannot_spend_a_shown_grant` failed at `src/lib.rs:2571:9` (planted tree) on the first shell-use assertion: `assertion left == right failed: the shell cannot spend a shown grant: the shell's use of request-1 with plan bytes [123, 34, 115, 116, 101, 112, 115, 34, 58, 91, 123, 34, 114, 101, 115, 111, 117, 114, 99, 101, 34, 58, 34, 108, 111, 99, 97, 108, 104, 111, 115, 116, 58, 47, 47, 80, 117, 98, 108, 105, 99, 47, 112, 108, 97, 110, 45, 97, 112, 112, 114, 111, 118, 97, 108, 47, 97, 46, 116, 120, 116, 34, 44, 34, 97, 99, 116, 105, 111, 110, 34, 58, 34, 114, 101, 97, 100, 34, 125, 93, 125] is refused as a shell on an instance-session route`; left held `Ok(Object {"valid": Bool(true)})`, right expected `Err((403, "capability validate needs an instance session"))`. The forced client spent the grant.
- restored, the test passes.

### F-empty-before-caller

- old bytes, 39: `    stand_in.post_capability_validate(\n`
- new bytes, 143: `    if plan.is_empty() {\n        return Err((403, "grant is not bound to this plan".to_owned()));\n    }\n    stand_in.post_capability_validate(\n`
- planted crate compiled; `shell_cannot_spend_a_shown_grant` failed at `src/lib.rs:2574:9` (planted tree) on the shell-use assertion for empty plan bytes: `assertion left == right failed: the shell cannot spend a shown grant: the shell's use of request-1 with plan bytes [] is refused as a shell on an instance-session route`; left held `Err((403, "grant is not bound to this plan"))`, right expected `Err((403, "capability validate needs an instance session"))`. The plan check ran before the caller check, so a shell reached a body check.
- restored, the test passes.

After both restores, `git diff -- lab/plan-approval/src/lib.rs` shows no plant. The restored proof command set (the fmt check and the twelve test commands in the task) took 1.54 s real. This lane has no `falsifiers.json`; no id is added.

## 018

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md), Request flow step 6:

> The Agent Host submits the proposed operation to Runtime as the active agent principal and session

This task proves the session half of that sentence: the shell is not the instance session, so a shell submit is refused before the plan body is read and stores nothing, while that session's own submit stores one pending request that the shell grants and that session's `execute` spends. The principal stays BACKLOG item 4, the shell check on `approve` stays 016, the shell check on `execute` stays 017, a standing mandate stays item 11, and an audit record stays item 16. `request` gains `caller: Caller<'_>` in place of `session` and returns `Result<String, (u16, String)>`; it stays the only caller of `post_capability_request`, passes that caller through, does not match on `Caller` and holds no copy of the refusal string. Each of the seventeen existing calls replaces its session argument with `Caller::Client { session_id: <that session expression> }` and unwraps the Ok id with `expect("the agent's request route stores one pending request")`, keeping its other arguments and assertions. The new test calls only `journeys::running_agent`, `journeys::request`, `approve` and `execute`; it calls `seed_request`, the route methods, `set_instant` and `delete_capsule` nowhere.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shell_cannot_submit_a_shown_plan -- --exact
```

### F-request-forces-client

- old bytes, 16: `        caller,\n`
- new bytes, 75: `        Caller::Client {\n            session_id: "component-1",\n        },\n`
- planted crate compiled with one `unused variable: caller` warning; `shell_cannot_submit_a_shown_plan` failed at `src/lib.rs:2872:5` (planted tree) on the first shell-submit assertion: `assertion left == right failed: the shell cannot submit a shown plan: the shell's submit of plan A on a fresh stand-in is refused as a caller without an instance session`; left held `Err((400, "unknown instance: component-1"))`, right expected `Err((403, "capability request needs an instance session"))`. The forced client caller reached the instance lookup, so the shell was not refused as a caller.
- restored, the test passes.

### F-empty-before-caller

- old bytes, 55: `        let stored = stand_in.post_capability_request(\n`
- new bytes, 167: `        if plan.is_empty() {\n            return Err((400, "request body needs resource".to_owned()));\n        }\n        let stored = stand_in.post_capability_request(\n`
- planted crate compiled; `shell_cannot_submit_a_shown_plan` failed at `src/lib.rs:2933:9` (planted tree) on the shell-submit assertion for empty plan bytes: `assertion left == right failed: the shell cannot submit a shown plan: the shell's submit with plan bytes [] is refused as a caller without an instance session`; left held `Err((400, "request body needs resource"))`, right expected `Err((403, "capability request needs an instance session"))`. The plan-body check ran before the caller check, so a shell reached a body check.
- restored, the test passes.

After both restores, `git diff -- lab/plan-approval/src/lib.rs` shows no plant. The restored proof command set (the fmt check and the thirteen test commands in the task) took 1.52 s real. This lane has no `falsifiers.json`; no id is added.

## 023

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md), Request flow step 8:

> The UI does not mint the grant itself.

This task proves that sentence for a shell deny on the public request route: the deny settles one shown step and leaves the sibling grantable, while Home or Inbox mints nothing. The two steps now come from `journeys::running_agent` and `journeys::request`, so the crate no longer calls `seed_request` and compiles where that method is `pub(crate)`. The absent-id refusal runs before any launch. `deny_one_shown_step` asserts the fresh deny `unknown request: req-absent` with an empty capsule list and an empty live list, `running_agent` returns `component-1` as `running` with cause `""`, both submits return `request-1` and `request-2` with 64-character plan hashes, the deny stores `request-1` as `denied` under `shell` with `deny the shown plan` while `request-2` stays pending, `execute` of `request-1` refuses as `unknown grant`, `approve` of `request-1` refuses as `request is not pending: request-1`, `approve` of `request-2` with `plan_sha256(PLAN_B)` stores one `once` grant at `granted_at` 0 on resource `localhost://Public/plan-approval/a.txt`, and `execute` of `request-2` spends `PLAN_B` and leaves the live list empty. The test calls only `journeys::running_agent`, `journeys::request`, `deny_shown_plan`, `approve` and `execute`; it does not call `seed_request`, `post_capability_request`, `post_capability_grant`, `post_capability_deny`, `post_capability_validate`, `admit_resident`, `post_capsules`, `finish_start`, `set_instant` or `delete_capsule`. `deny_shown_plan`, `approve`, `execute`, `running_agent` and `request` are unchanged, no function is added, and `request` stays the only caller of `post_capability_request`, `approve` the only caller of `post_capability_grant`, and `deny_shown_plan` the only caller of `post_capability_deny`. The sibling settle is 009, the session check is 018, a standing mandate stays BACKLOG item 11, an audit record stays item 16, and full A15 stays item 4.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib deny_one_shown_step -- --exact
```

### F-fake-request-id

- old bytes, 51: `        let hash = preview(stand_in, plan).sha256;\n`
- new bytes, 90: `        return Ok("req-a".to_owned());\n        let hash = preview(stand_in, plan).sha256;\n`
- planted crate compiled with an `unused variable: plan` warning; `deny_one_shown_step` failed at `src/lib.rs:663:5` (planted tree) on the first submit assertion: `assertion left == right failed: the session's first shown step is the stand-in's first request`; left held `"req-a"`, right expected `"request-1"`. The fake id never reached the request route.
- restored, the test passes.

### F-deny-sibling

- old bytes, 176: `    stand_in.post_capability_deny(\n        Caller::Shell,\n        &json!({\n            "request_id": request_id,\n            "reason": "deny the shown plan",\n        }),\n    )\n`
- new bytes, 355: `    stand_in.post_capability_deny(\n        Caller::Shell,\n        &json!({\n            "request_id": request_id,\n            "reason": "deny the shown plan",\n        }),\n    )?;\n    stand_in.post_capability_deny(\n        Caller::Shell,\n        &json!({\n            "request_id": "request-2",\n            "reason": "deny the shown plan",\n        }),\n    )\n`
- planted crate compiled; `deny_one_shown_step` failed at `src/lib.rs:744:5` (planted tree) on the sibling assertion: `assertion left == right failed: a shell deny settles one shown step and the sibling stays pending`; left held `request-2` with `status` `denied`, `settled_by` `shell` and `decision_reason` `deny the shown plan`, right expected `status` `pending` with `settled_by` null and `decision_reason` empty. The deny settled a second step.
- restored, the test passes.

After both restores, `git diff -- lab/plan-approval/src/lib.rs` shows no plant. The restored proof command set (the fmt check and the thirteen test commands in the task) took 3.39 s real. This lane has no `falsifiers.json`; no id is added.

## 024

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md), Request flow step 6:

> The Agent Host submits the proposed operation to Runtime as the active agent principal and session

This task proves the live-instance half of that sentence: a session that was never launched and a
session that was stopped are each refused before anything is stored, while the other running
session's own submit stores one pending request that the shell grants and that session's `execute`
spends. The principal stays BACKLOG item 4; the shell checks on `approve`, `execute` and `request`
stay 016, 017 and 018, and a client deny stays 020. `request` stays the only submit call and gains
no branch on `Caller`; the two plants below are temporary. `only_a_live_session_submits_a_shown_plan`
asserts the never-launched refusal `unknown instance: component-absent` for `PLAN_A`, `PLAN_B` and
empty plan bytes with an empty capsule list, empty request arrays and an empty live list; both
`running_agent` calls return `component-1` and `component-2` as `running` with cause `""`;
`stop_shown_session` of `component-1` returns JSON null and leaves it `stopped` with cause
`stopped: stop the shown session` while `component-2` stays running; the stopped session's submits
for the same three bodies are `instance is not live: stopped` and store nothing; `component-2`'s
submit of `PLAN_A` is `request-1` with the 64-character shown hash; the shell's `approve` with
`once` stores `granted` under `shell` with `owner approved` and one live grant, which the session's
`execute` spends; a stopped-session submit after that spend is still `instance is not live: stopped`
and leaves `request-1` granted with the live list empty. This crate stores no copy of the instance
lookup, does not copy the stand-in and names no planner. A passing run gives the Runtime no A15
credit.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib only_a_live_session_submits_a_shown_plan -- --exact
```

### F-not-live-returns-ok

- old bytes, 258:
  ```
          let stored = stand_in.post_capability_request(
              caller,
              &json!({
                  "resource": "localhost://Public/plan-approval/a.txt",
                  "action": "read",
                  "plan": hash,
              }),
          )?;
  ```
- new bytes, 454:
  ```
          let stored = match stand_in.post_capability_request(
              caller,
              &json!({
                  "resource": "localhost://Public/plan-approval/a.txt",
                  "action": "read",
                  "plan": hash,
              }),
          ) {
              Err((400, reason)) if reason.starts_with("instance is not live:") => {
                  return Ok("request-1".to_owned());
              }
              result => result?,
          };
  ```
- planted crate compiled; `only_a_live_session_submits_a_shown_plan` failed at `src/lib.rs:3351:9`
  (planted tree) on the stopped-session assertion: `assertion left == right failed: only a live
  session submits a shown plan: the stopped session's submit with plan bytes [...] is refused as not
  live`; left held `Ok("request-1")`, right expected `Err((400, "instance is not live: stopped"))`.
  The not-live refusal returned Ok instead of the route error.
- restored, the test passes.

### F-unknown-returns-ok

- old bytes, 258: the same `old bytes` block as F-not-live-returns-ok.
- new bytes, 450:
  ```
          let stored = match stand_in.post_capability_request(
              caller,
              &json!({
                  "resource": "localhost://Public/plan-approval/a.txt",
                  "action": "read",
                  "plan": hash,
              }),
          ) {
              Err((400, reason)) if reason.starts_with("unknown instance:") => {
                  return Ok("request-1".to_owned());
              }
              result => result?,
          };
  ```
- planted crate compiled; `only_a_live_session_submits_a_shown_plan` failed at `src/lib.rs:3214:9`
  (planted tree) on the never-launched-session assertion: `assertion left == right failed: only a
  live session submits a shown plan: the never-launched session's submit with plan bytes [...] is
  refused as an unknown instance`; left held `Ok("request-1")`, right expected `Err((400, "unknown
  instance: component-absent"))`. The unknown-instance refusal returned Ok instead of the route
  error.
- restored, the test passes.

After both restores, `git diff -- lab/plan-approval/src/lib.rs` shows no plant. The restored proof
command set (the fmt check and the fourteen test commands in the task) took 2.31 s real. This lane
has no `falsifiers.json`; no id is added.

## 020

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md), Request flow step 8:

> The UI does not mint the grant itself.

This task proves that sentence for a deny: the agent that posted the shown plan and the other
running session cannot settle it, while the shell's own deny settles exactly one step and leaves
the sibling for its own allow-once grant. `deny_shown_plan` stays the one deny call and gains
`caller: Caller<'_>` after `stand_in`; it passes that value to `post_capability_deny`, contains no
match on `Caller` and no copy of the shell check. `agent_cannot_deny_its_own_shown_plan` asserts a
fresh client deny of `request-absent` is the 403 shell refusal and not an unknown request, with an
empty capsule list and an empty live list; two `running_agent` calls return `component-1` and
`component-2`; both submits return `request-1` and `request-2` with 64-character hashes; four client
denies (the posting session on its own step, the other session on `request-1`, the posting session
on `request-2` and on the absent id) are each the same 403 refusal, never an unknown-request or
not-pending error, and leave both requests pending with the live list empty; the shell's absent-id
deny is `unknown request: request-absent`; the shell's deny of `request-1` stores `denied` under
`shell` with `deny the shown plan` and leaves `request-2` pending; a client deny after that
settlement is still the shell refusal; `approve` of `request-2` as the shell with `once` and the
`PLAN_B` hash stores the one live entry; `execute` of `request-1` is `unknown grant` and leaves it
live; `execute` of `request-2` spends it. This test calls no `seed_request` and no
`post_capability_*` method. This crate stores no copy of the shell check, does not copy the
stand-in and names no planner. A passing run gives the Runtime no A15 credit.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib agent_cannot_deny_its_own_shown_plan -- --exact
```

### F-deny-forces-shell

- old bytes, 51:
  ```
      stand_in.post_capability_deny(
          caller,
  ```
- new bytes, 58:
  ```
      stand_in.post_capability_deny(
          Caller::Shell,
  ```
- planted crate compiled; `agent_cannot_deny_its_own_shown_plan` failed at `src/lib.rs:891:5`
  (planted tree) on the first client deny: `assertion left == right failed: the agent that showed
  the plan cannot deny it: a client deny runs before the request lookup, so even an absent id is
  the shell refusal`; left held `Err((400, "unknown request: request-absent"))`, right expected
  `Err((403, "This endpoint requires shell privileges"))`. The forced shell caller settled the
  client's deny before the caller was judged.
- restored, the test passes.

### F-absent-before-shell

- old bytes, 51: the same `old bytes` block as F-deny-forces-shell.
- new bytes, 166:
  ```
      if request_id == "request-absent" {
          return Err((400, format!("unknown request: {request_id}")));
      }
      stand_in.post_capability_deny(
          caller,
  ```
- planted crate compiled; `agent_cannot_deny_its_own_shown_plan` failed at `src/lib.rs:894:5`
  (planted tree) on the first client deny: the same assertion, left held
  `Err((400, "unknown request: request-absent"))`, right expected
  `Err((403, "This endpoint requires shell privileges"))`. The absent-id branch ran before the
  shell check.
- restored, the test passes.

After both restores, `git diff -- lab/plan-approval/src/lib.rs` shows no plant. The restored proof
command set (the fmt check and the fifteen test commands in the task) took 2.66 s real. This lane
has no `falsifiers.json`; no id is added.

## 021

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md), Session and
interaction contract:

> an explicit interrupt or cancel operation that reports its settlement

This task proves the stop-caller half of that sentence: the agent that posted the shown plan, and
the other running session, cannot stop it, while the shell's own stop settles exactly that session
and leaves the other one able to submit, be granted and spend one use. `stop_shown_session` stays
the one stop call and gains `caller: Caller<'_>` after `stand_in`; it passes that value to
`delete_capsule`, contains no match on `Caller` and no copy of the shell check. Every existing call
now passes `Caller::Shell` and keeps its other arguments and assertions.
`agent_cannot_stop_a_shown_session` asserts a fresh client stop of `component-absent` and of an
empty id is the 403 shell refusal, not an unknown instance or a missing stop body, with an empty
capsule list and an empty live list; two `running_agent` calls return `component-1` and
`component-2`, both running with no cause; `request` of `PLAN_A` and `PLAN_B` as the `component-1`
client returns `request-1` and `request-2` with 64-character hashes; `approve` of `request-1` as the
shell with `once` stores the one live entry; four client stops (the posting session on its own id,
the other session on `component-1`, the posting session on `component-2` and on the absent id) are
each the same 403 refusal, never an unknown-instance, not-live or stop-body error, and leave both
sessions running, `request-1` granted under `shell` with `owner approved`, `request-2` pending and
the live list unchanged; the shell's stop of `component-1` reports JSON null and stores `stopped`
with `stopped: stop the shown session`, leaves `component-2` running, denies `request-2` under
`runtime`, keeps `request-1` granted and leaves the live list empty; `execute` of `request-1` is
`grant is not live: Revoked`; a client stop after that settlement is still the shell refusal and
not `instance is not live: stopped`; `component-2` then submits `request-3`, the shell grants it
`once`, and its own `execute` spends it. This test calls no `seed_request` and no
`post_capability_*` method. This crate stores no copy of the shell check, does not copy the
stand-in and names no planner. A passing run gives the Runtime no A15 credit.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib agent_cannot_stop_a_shown_session -- --exact
```

### F-stop-forces-shell

- old bytes, 65:
  ```
      stand_in.delete_capsule(
          caller,
          session_id,
  ```
- new bytes, 72:
  ```
      stand_in.delete_capsule(
          Caller::Shell,
          session_id,
  ```
- planted crate compiled; `agent_cannot_stop_a_shown_session` failed at `src/lib.rs:3909:5`
  (planted tree) on the first client stop: `assertion left == right failed: the agent that showed
  the plan cannot stop its session: a client stop of an absent id is the shell refusal, not an
  unknown instance`; left held `Err((400, "unknown instance: component-absent"))`, right expected
  `Err((403, "This endpoint requires shell privileges"))`. The forced shell caller ran the stop
  route for the client caller.
- restored, the test passes.

### F-absent-before-shell

- old bytes, 65: the same `old bytes` block as F-stop-forces-shell.
- new bytes, 183:
  ```
      if session_id == "component-absent" {
          return Err((400, format!("unknown instance: {session_id}")));
      }
      stand_in.delete_capsule(
          caller,
          session_id,
  ```
- planted crate compiled; `agent_cannot_stop_a_shown_session` failed at `src/lib.rs:3912:5`
  (planted tree) on the first client stop: the same assertion, left held
  `Err((400, "unknown instance: component-absent"))`, right expected
  `Err((403, "This endpoint requires shell privileges"))`. The absent-id branch ran before the
  shell check.
- restored, the test passes.

After both restores, `git diff -- lab/plan-approval/src/lib.rs` shows no plant. The restored proof
command set (the fmt check and the sixteen test commands in the task) took 2 s real. This lane has
no `falsifiers.json`; no id is added.

## 022

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md),
Non-negotiable boundaries:

> A provider implements an operation; Runtime authorizes the caller.

This task proves that sentence for a launch: the agent is not the shell, so it cannot start a
session, while the shell's own launch stays the existing journey. `running_agent` stays the one
launch journey and gains `caller: Caller<'_>` after `stand_in`; it returns
`Result<String, (u16, String)>`, passes that caller to the one `get_capsules` call and the one
`post_capsules` call, and returns the list error with `?` before it reads the list length and
before `admit_resident`. The Ok list's length still chooses `SignedBundle::new()` for 0 and
`SignedBundle::distinct` with name `agent-host-{sessions}` otherwise; `admit_resident`,
`post_capsules` and `finish_start` propagate with `?`, and the Ok value is the launch `id`. It
contains no match on `Caller` and no copy of the shell check. Every existing call now passes
`Caller::Shell` and unwraps with `expect("the shell launches one running session")`, keeping its
other arguments and assertions.

`agent_cannot_launch_a_shown_session` asserts the fresh client launches for `component-1`,
`component-absent` and an empty id are each the 403 shell refusal
`This endpoint requires shell privileges`, not an unknown instance, an unadmitted bundle, a missing
launch cid or an already-admitted bundle, and that each leaves the capsule list, both request
arrays and the live list empty; the shell's launch then returns `component-1`, running with no
cause and with no grant or request; the client launches for `component-1`, for `component-2` and
for an empty id after it are each still the 403 refusal, never `bundle already admitted`, an
unknown instance or a not-live instance, and leave `component-1` running and the capsule list
holding only `component-1`; the shell's second launch returns `component-2`, and both sessions stay
running; `request` of `PLAN_A` as the `component-1` client returns `request-1` with a 64-character
hash, pending with the stored hash, no settler and empty reasons, while the other request array and
the live list stay empty; `approve` of `request-1` as the shell with `once` and that hash stores
the one live entry and the request as granted under `shell` with `owner approved`; `execute` as the
`component-1` client spends that one use and the live list ends empty; a client launch after both
shell sessions is still the 403 refusal and not `bundle already admitted`, the capsule list holds
`component-1` and `component-2` and no `component-3`, both stay running, and `request-1` stays
granted with the live list empty; the `component-2` client then submits `request-2`, the shell
grants it `once`, and its own `execute` spends it. The test calls no `seed_request`, no
`post_capability_*` method, no `admit_resident`, `post_capsules`, `finish_start`, `set_instant`,
`delete_capsule` or `worker_exited`. This crate stores no copy of the shell check, does not copy
the stand-in and names no planner. A passing run gives the Runtime no A15 credit.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib agent_cannot_launch_a_shown_session -- --exact
```

### F-launch-forces-shell

- old bytes, 66 and 79: the two planted lines of `running_agent`:
  ```
          let sessions = stand_in.get_capsules(caller)?["capsules"]
          let launched = stand_in.post_capsules(caller, &bundle.launch_body())?;
  ```
- new bytes, 73 and 86:
  ```
          let sessions = stand_in.get_capsules(Caller::Shell)?["capsules"]
          let launched = stand_in.post_capsules(Caller::Shell, &bundle.launch_body())?;
  ```
- planted crate compiled; `agent_cannot_launch_a_shown_session` failed at `src/lib.rs:4351:9`
  (planted tree) on the first fresh client launch: `assertion left == right failed: the agent
  cannot launch a shown session: a client launch for component-1 on a fresh stand-in is the shell
  refusal`; left held `Ok("component-1")`, right expected
  `Err((403, "This endpoint requires shell privileges"))`. The forced shell caller ran the list
  and launch routes for the client caller.
- restored, the test passes.

### F-admit-before-shell

- old bytes, 66: the `get_capsules` line above.
- new bytes, 361:
  ```
          let forced = SignedBundle::new();
          stand_in
              .admit_resident(
                  forced.path(),
                  &forced.signature(),
                  forced.accepted(),
                  Start::Ok,
              )
              .expect("the stand-in admits the signed fixture");
          let sessions = stand_in.get_capsules(caller)?["capsules"]
  ```
- planted crate compiled; `agent_cannot_launch_a_shown_session` failed at `src/lib.rs:400:14`
  (planted tree) in `running_agent` on the shell's own launch: `the stand-in admits the signed
  fixture: (403, "bundle already admitted: bafybeidjg24vyrqdcsfau5cz3emylziuu2dn7cpjqpszlnyq6knb66w5xm")`.
  The admission ran before the list route's shell check, so the shell's later
  `SignedBundle::new()` could not admit the same CID.
- restored, the test passes.

After both restores, `git diff -- lab/plan-approval/src/lib.rs` shows no plant. The restored proof
command set (the fmt check and the seventeen test commands in the task) took 2.447 s real. This
lane has no `falsifiers.json`; no id is added.

## 025

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md), Request flow step 10:

> The result returns to the Agent Host and Home without exposing provider credentials or broader authority

This task proves that sentence for one shown request: the status route returns the stored status,
and a denied or expired record's decision reason, and it returns no plan and no token. Reading it
stores nothing and spends nothing. `read_shown_request` is the one new function and the only caller
of `get_capability_request`; it takes `&StandIn`, passes the caller and the id through, and returns
that result. It contains no match on `Caller` and no copy of the lookup, the owner check or the
shell check. The shell request list stays `get_capability_requests`, the presentation read the
existing tests already use.

`shown_request_status_is_not_the_grant` reads an absent id as the owning session, as the other
session, as an empty session id and as the shell: each is `Err((404, "Request not found:
request-absent"))`, never another session's request, the shell refusal or an unknown request, and
each leaves the shell capsule list and the shell live list empty. It then launches `component-1`
and `component-2` through `journeys::running_agent`, both running with no cause; submits `PLAN_A`
as the first session for `request-1`; reads the owner's `{"status":"pending"}` with no `plan`,
`resource`, `request_id` or `token` while the shell row stays pending with the stored hash and the
live list stays empty; reads `request-1` as the other session, as an empty id and as the shell for
`Err((403, "Cannot access another session's request"))`, each leaving the row and the live list
alone; submits `PLAN_B` as the second session for `request-2` and reads the other session's row as
a refusal; denies `request-1` as the shell and reads the owner's
`{"status":"denied","reason":"deny the shown plan"}` with no `plan` and no `decision_reason` while
the shell row shows the shell settlement and `request-2` stays pending; approves `request-2` once
with its hash and reads `{"status":"granted"}`, then spends the one use with `execute`, reads the
same `granted` and takes `Err((400, "grant is not live: Exhausted"))` on the next use; submits
`PLAN_A` again for `request-3`, ages the clock by 300 seconds with `age_shown_plan`, and reads
`{"status":"expired","reason":"Request timed out"}` with no `plan` while the shell rows keep their
settlements and the live list stays empty. The test calls no `get_capability_request`,
`seed_request`, `post_capability_*` method, `admit_resident`, `post_capsules`, `finish_start`,
`set_instant`, `delete_capsule` or `worker_exited`. This crate stores no copy of the owner check,
does not copy the stand-in and names no planner. A passing run gives the Runtime no A15 credit.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_request_status_is_not_the_grant -- --exact
```

### F-status-returns-plan

- old bytes, 190: `    stand_in.get_capability_request(caller, request_id)`
- new bytes, 190, 191 and 192:
  ```
      let mut read = stand_in.get_capability_request(caller, request_id)?;
      read["plan"] = json!("pending");
      Ok(read)
  ```
- planted crate compiled; `shown_request_status_is_not_the_grant` failed at `src/lib.rs:4883:5`
  (planted tree) on the owner's pending read: `assertion left == right failed: a shown request
  status is not the grant: the owning session's status read is the stored status word`; left held
  `Ok(Object {"plan": String("pending"), "status": String("pending")})`, right expected
  `Ok(Object {"status": String("pending")})`. The status body carried the plan key.
- restored, the test passes.

### F-absent-is-forbidden

- old bytes, 190: the same status line as above.
- new bytes, 190 to 196:
  ```
      let read = stand_in.get_capability_request(caller, request_id);
      match read {
          Err((404, reason)) if reason.starts_with("Request not found:") => {
              Err((403, "Cannot access another session's request".to_owned()))
          }
          read => read,
      }
  ```
- planted crate compiled; `shown_request_status_is_not_the_grant` failed at `src/lib.rs:4743:9`
  (planted tree) on the first absent-id read: `assertion left == right failed: a shown request
  status is not the grant: the status read of an absent id is not found for the session
  component-1`; left held `Err((403, "Cannot access another session's request"))`, right expected
  `Err((404, "Request not found: request-absent"))`. A missing id was reported as another
  session's request.
- restored, the test passes.

Neither plant calls `seed_request`. After both restores, `git diff -- lab/plan-approval/src/lib.rs`
shows no plant. The restored proof command set (the fmt check and the eighteen test commands in the
task) took 2.178 s real. This lane has no `falsifiers.json`; no id is added.

## 026

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md), Request flow step 10:

> The result returns to the Agent Host and Home without exposing provider credentials or broader authority

This task proves that sentence for the live grant list: the list returns the caller's own live entries,
a client does not receive another session's grant, and reading it stores nothing and spends nothing.
`read_shown_grants` is the one new function and the only product read of the live list; it takes
`&StandIn`, passes the caller and the scope through, and returns that result. It contains no match on
`Caller` and no copy of the scope check, the shell check, `render`, `visible`, `entry` or `body`. The
shell request list stays `get_capability_requests`, the presentation read the existing tests already
use.

`shown_live_list_is_not_another_sessions_grant` reads the list only through `read_shown_grants`. On a
fresh stand-in, the no-scope read for `component-1`, `component-2`, `component-absent` and the empty
session id is `{"capabilities":[]}` with no `scope` key and not the shell body, while the shell's
no-scope read and its `all_sessions_live` read are the same `{"scope":"all_sessions_live",
"capabilities":[]}`; each of those reads leaves the shell live list empty and the capsule list empty.
The scope `session`, for `component-1`, the empty id and the shell, is `Err((400, "unknown capability
list scope: session"))`; the empty scope, for `component-1` and the shell, is `Err((400, "unknown
capability list scope: "))`; none is the shell refusal or an Ok body, and each leaves the shell live
list and the capsule list empty. A client ask for `all_sessions_live`, for `component-1`,
`component-absent` and the empty id, is `Err((403, "This endpoint requires shell privileges"))` with
no body that names `request-1`, and each leaves the shell live list and the capsule list empty. Two
`running_agent` shell calls then start `component-1` and `component-2`, both `running` with cause
`""`; the first session's list stays empty and its ask for every session stays refused. The first
session submits `PLAN_A` for `request-1` and the second submits `PLAN_B` for `request-2`; both stay
pending in the shell request view with their 64-character hashes, and both live lists stay empty. The
shell's `approve` of `request-1` once makes the shell live list, for no scope and for the live scope,
that one `once` entry with `session_id` and no `plan` or `token`, and makes the first session's list
that entry without `session_id`, `plan`, `token` or a `scope` key; the second session, an empty id and
an unknown id see `{"capabilities":[]}`, and a client ask for every session is still the shell
refusal. The shell's `approve` of `request-2` for the session makes both shell reads the two entries,
one `once` and one `session`, while the first session's list stays its one entry and the second
session's list is its one entry without `session_id`, `plan`, `scope` or `request-1`. The first
session's `execute` of `request-2` is `Err((403, "wrong capsule: expected component-2, got
component-1"))` and leaves both grants; its `execute` of `request-1` spends the once grant, so the
shell list and the first session's list drop it while the second session's grant stays, and a second
use is `Err((400, "grant is not live: Exhausted"))` with both lists unchanged. The second session's
`execute` twice is `{"valid":true}` each time and its session grant stays listed after both uses. The
shell's `stop_shown_session` of `component-2` is JSON null, the capsule is `stopped` with cause
`stopped: stop the shown session`, `component-1` stays `running` with cause `""`, the shell live list
is the empty shell body, both client lists are empty, and the next `execute` is `Err((400, "grant is
not live: Revoked"))`. Both request records stay `granted` under `shell` with `owner approved`. The
test calls no `get_capability_list`, `get_capability_request`, `seed_request`, `seed_grant`,
`post_capability_*` method, `admit_resident`, `post_capsules`, `finish_start`, `set_instant`,
`delete_capsule` or `worker_exited`. This crate stores no copy of the list renderer, does not copy
the stand-in and names no planner. A passing run gives the Runtime no A15 credit.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_live_list_is_not_another_sessions_grant -- --exact
```

### F-client-sees-shell

- old bytes, line 215: `    stand_in.get_capability_list(caller, scope)`
- new bytes, lines 215 to 221:
  ```
      let read = stand_in.get_capability_list(caller, scope);
      match read {
          Ok(_) if matches!(caller, Caller::Client { .. }) => {
              stand_in.get_capability_list(Caller::Shell, Some("all_sessions_live"))
          }
          read => read,
      }
  ```
- planted crate compiled; `shown_live_list_is_not_another_sessions_grant` failed at `src/lib.rs:5330:9`
  (planted tree) on the first fresh client read: `assertion left == right failed: a shown live list is
  not another session's grant: the no-scope read for component-1 on a fresh stand-in is the empty
  client list`; left held `Ok(Object {"capabilities": Array [], "scope":
  String("all_sessions_live")})`, right expected `Ok(Object {"capabilities": Array []})`. A client read
  returned the shell's body.
- restored, the test passes.

### F-global-scope-is-shell

- old bytes, line 215: `    stand_in.get_capability_list(caller, scope)`
- new bytes, lines 215 to 219:
  ```
      let caller = if scope == Some("all_sessions_live") {
          Caller::Shell
      } else {
          caller
      };
  ```
- planted crate compiled; `shown_live_list_is_not_another_sessions_grant` failed at `src/lib.rs:5443:9`
  (planted tree) on the first fresh client ask for every session: `assertion left == right failed: a
  shown live list is not another session's grant: a client ask for every session is the shell refusal
  for component-1`; left held `Ok(Object {"capabilities": Array [], "scope":
  String("all_sessions_live")})`, right expected `Err((403, "This endpoint requires shell
  privileges"))`. A client ask for every session ran as the shell.
- restored, the test passes.

Neither plant calls `seed_grant` or `seed_request`. After both restores, no plant line remains:
`sed -n '210,216p' lab/plan-approval/src/lib.rs` shows the signature and the single
`stand_in.get_capability_list(caller, scope)` line, and `git diff -- lab/plan-approval/src/lib.rs`
holds no `match read`, no shadowed `caller` and no `Caller::Client { .. }` guard. The restored proof
command set (the fmt check and the nineteen test commands in the task) took 2.09 s real. This lane
has no `falsifiers.json`; no id is added.

## 027

Design sentence followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md), Session and
interaction contract:

> Reconnecting presentation reads durable state; it does not rerun inference or submit the proposed
> effect again.

This task proves that sentence for the shell's per-session request list: the list is the durable
records, a second read stores nothing and spends nothing, and each record keeps the plan the owner was
shown. `read_shown_requests` is the one new function and the only product read of that list; it takes
`&StandIn`, passes the caller and the session through, and returns that result. It contains no match
on `Caller` and no copy of the shell check, the session check or `request_entry`. The owner grant stays
`approve`, the one-request status read stays `read_shown_request` and the live list stays
`read_shown_grants`.

`shown_request_list_does_not_submit_again` reads the list only through `read_shown_requests` and the
live list only through `read_shown_grants`; it calls no `get_capability_requests` and no
`get_capability_list` of its own. On a fresh stand-in, a client read is `Err((403, "This endpoint
requires shell privileges"))` for `component-1` with session `component-1`, `component-2` with
session `component-1`, the empty id with an empty session, `component-absent` with its own session,
and `component-1` with no session; none is the session refusal, none is an Ok body, none names
`request-1`, and each leaves the capsule list and the shell live list empty. A shell read with no
session and with the empty session is `Err((400, "requests need a session"))` and is not the shell
refusal, and each leaves both shell lists empty. A shell read for `component-absent`, `component-1`
and `component-2` on a fresh stand-in is `Ok({"requests":[]})` and leaves both shell lists empty. Two
`running_agent` shell calls then start `component-1` and `component-2`, both `running` with cause
`""`, and both shell reads are still the empty list while the client read stays refused. The first
session submits `PLAN_A` for `request-1` and the second submits `PLAN_B` for `request-2`; each
session's list holds only its own pending record with `settled_by` null, an empty
`decision_reason` and its 64-character plan hash, a second read is the same value, and both live lists
stay empty. The shell's `deny_shown_plan` of `request-1` gives `{"success":true}` and that record stays
on the first session's list as `denied` under `shell` with `deny the shown plan`, unchanged by a
second read, while the second session's record stays pending. The shell's `approve` of `request-2`
once gives `{"success":true}` and that record stays on the second session's list as `granted` under
`shell` with `owner approved`, unchanged by a second and a third read, with the one live entry in the
shell live list throughout. The second session's `execute` of `PLAN_B` is `{"valid":true}`; the
record stays `granted`, the shell live list becomes the empty shell body, a read leaves both
unchanged, and the next use is `Err((400, "grant is not live: Exhausted"))`. The first session
submits `PLAN_A` again for `request-3`, `age_shown_plan` of 300 runs, and the first session's list is
the denied `request-1` then the expired `request-3` under `runtime` with `Request timed out`, in
request id order and without `request-2`; a second read is the same value, the second session's list
stays that one granted entry, the shell live list stays empty, and a shell read with no session is
still `Err((400, "requests need a session"))`. The test calls no `seed_request`, no
`post_capability_*` method, `admit_resident`, `post_capsules`, `finish_start`, `set_instant`,
`delete_capsule` or `worker_exited`. This crate stores no copy of `request_entry`, does not copy the
stand-in and names no planner. A passing run gives the Runtime no A15 credit.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_request_list_does_not_submit_again -- --exact
```

### F-client-reads-shell

- old bytes, line 244: `    stand_in.get_capability_requests(caller, session)`
- new bytes, line 244: `    stand_in.get_capability_requests(Caller::Shell, session)`
- planted crate compiled; `shown_request_list_does_not_submit_again` failed at `src/lib.rs:6131:9`
  (planted tree) on the first fresh client read: `assertion left == right failed: a shown request list
  does not submit again: a client read is the shell refusal for Client { session_id: "component-1" }
  with session Some("component-1")`; left held `Ok(Object {"requests": Array []})`, right expected
  `Err((403, "This endpoint requires shell privileges"))`. A client read ran as the shell.
- restored, the test passes.

### F-second-read-adds-request

- old bytes, line 244: `    stand_in.get_capability_requests(caller, session)`
- new bytes, lines 244 to 258:
  ```
      let read = stand_in.get_capability_requests(caller, session);
      match read {
          Ok(mut value)
              if value["requests"]
                  .as_array()
                  .is_some_and(|requests| !requests.is_empty()) =>
          {
              value["requests"]
                  .as_array_mut()
                  .expect("requests array")
                  .push(json!({ "request_id": "request-plant", "status": "pending" }));
              Ok(value)
          }
          read => read,
      }
  ```
- planted crate compiled; `shown_request_list_does_not_submit_again` failed at `src/lib.rs:6297:5`
  (planted tree) on the first non-empty read: `assertion left == right failed: a shown request list
  does not submit again: the shell read for the first session shows the pending step with its hash`;
  left held the `request-1` record followed by `{"request_id": "request-plant", "status":
  "pending"}`, right expected the one `request-1` record. A read stored a second record.
- restored, the test passes.

Neither plant calls `seed_request` or `post_capability_request`. After both restores,
`git diff -- lab/plan-approval/src/lib.rs` holds no `request-plant`, no `Caller::Shell, session` and
no `match read` line, and `sed -n '239,245p' lab/plan-approval/src/lib.rs` shows the signature and
the single `stand_in.get_capability_requests(caller, session)` line. The restored proof command set
(the fmt check and the twenty test commands in the task) took 2.398 s real. This lane has no
`falsifiers.json`; no id is added.

027: added `read_shown_requests` and `shown_request_list_does_not_submit_again`; the shown request list returns the stored records and does not submit again.

## 028

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md) Request flow step 7:

> Runtime verifies the exact resource, action, operation, principal, session,
> capsule, grant, expiry, and revocation state

This task proves the resource and the action for a shown submit. `journeys::request` gains
`resource: &str` and `action: &str` after `plan`, sends both unchanged as the route's
`resource` and `action` keys, and returns that route's result with its `request_id` on Ok. It
matches no `Caller`, contains none of the route's refusal reasons and calls no other `StandIn`
method. Every existing call passes `"localhost://Public/plan-approval/a.txt"` and `"read"`; no
other argument and no assertion changed.

`shown_submit_names_a_declared_ask` drives two sessions through `running_agent`. On a fresh
stand-in the `https://` resource is the scheme refusal before the instance is read, and the
`mint` action is the action refusal; each stores nothing and leaves both shell lists empty.
The five pairs the signed bundle did not declare are each status 403 with `ask not declared in
the signed manifest: <resource> <action>` and each leaves the first session's list empty, the
shell live list empty and both capsules listed. A shell submit is the caller refusal and the
absent session is the instance refusal, neither the ask reason. `READ` of the plan A file
stores `read` as `request-1`, `Write` of plan B stores `write` as `request-2`, and the shared
file with `read` stores that resource as `request-3`; a repeat of the undeclared pair stores
nothing. The once grant of `request-2` lists action `write` and no `request-1` or `request-3`;
its one use is `{"valid":true}`, the live list empties, and the next use is
`Err((400, "grant is not live: Exhausted"))` with the three records kept and `request-2`
granted. The test calls no `post_capability_request`, `get_capability_requests`,
`get_capability_request`, `get_capability_list`, `seed_request`, `post_capability_*` method,
`admit_resident`, `post_capsules`, `finish_start`, `set_instant`, `delete_capsule` or
`worker_exited`. This crate stores no copy of `declared_ask`, does not copy the stand-in and
names no planner. A passing run gives the Runtime no A15 credit.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_submit_names_a_declared_ask -- --exact
```

### F-undeclared-is-stored

Old bytes, 225:

```rust
        let stored = stand_in.post_capability_request(
            caller,
            &json!({
                "resource": resource,
                "action": action,
                "plan": hash,
            }),
        )?;
```

New bytes, 440:

```rust
        let stored = match stand_in.post_capability_request(
            caller,
            &json!({
                "resource": resource,
                "action": action,
                "plan": hash,
            }),
        ) {
            Err((403, reason)) if reason.starts_with("ask not declared in the signed manifest:") => {
                return Ok("request-1".to_owned());
            }
            stored => stored?,
        };
```

The planted crate compiled. `shown_submit_names_a_declared_ask` failed at `src/lib.rs:6965:9`
(planted tree) on the first refused pair: `assertion left == right failed: a shown submit
names a declared ask: the pair localhost://Public/plan-approval/b.txt read is the
declared-ask refusal`; left held `Ok("request-1")`, right expected `Err((403, "ask not
declared in the signed manifest: localhost://Public/plan-approval/b.txt read"))`. The
refusal was stored as a request. Restored, the test passes.

### F-other-resource-is-a-txt

Old bytes, 138:

```rust
            &json!({
                "resource": resource,
                "action": action,
                "plan": hash,
            }),
```

New bytes, 468:

```rust
            &json!({
                "resource": if resource == "localhost://Public/plan-approval/a.txt" {
                    resource
                } else {
                    "localhost://Public/plan-approval/a.txt"
                },
                "action": if resource == "localhost://Public/plan-approval/a.txt" {
                    action
                } else {
                    "read"
                },
                "plan": hash,
            }),
```

The planted crate compiled. `shown_submit_names_a_declared_ask` failed at `src/lib.rs:6843:5`
(planted tree) on the scheme refusal: `assertion left == right failed: a shown submit names
a declared ask: a resource outside elastos:// and localhost:// is the scheme refusal`; left
held `Err((400, "unknown instance: component-1"))`, right expected `Err((400, "Unsupported
resource scheme. Allowed: elastos://, localhost://"))`. The `https://` resource reached the
instance lookup as the plan A file with action `read`. Restored, the test passes.

Neither plant calls `seed_request`. After both restores,
`git diff -- lab/plan-approval/src/lib.rs` holds no `stored => stored?`, no
`reason.starts_with("ask not declared` and no
`resource == "localhost://Public/plan-approval/a.txt"` line. The restored proof command set
(the fmt check and the twenty-one test commands in the task) took 2.648 s real. This lane has
no `falsifiers.json`; no id is added.

028: `journeys::request` takes the resource and the action it is given; `shown_submit_names_a_declared_ask` proves an exact declared ask is the only stored submit and the grant keeps that action; two hand-run plants caught and restored.

## 029

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md) Request flow step 8:

> Runtime records a pending request and Home or Inbox presents it.

This task proves the reason recorded with a shown request. `journeys::request` gains
`reason: &str` after `action`, sends it unchanged as the route's `reason` key, and returns
that route's result with its `request_id` on Ok. It matches no `Caller` and no `reason`,
contains no `seed_grant`, and calls no other `StandIn` method. Every existing call passes
`""`; no other argument and no assertion changed.

`shown_request_reason_is_not_the_grant` drives two sessions through `running_agent`. On a
fresh stand-in the shell submit with reason `show this step` is the caller refusal and
stores no capsule, request or grant. The absent instance and the undeclared `b.txt` ask
with reason `approved` each store nothing. `request-1` stores `show this step` and stays
pending while the shell list shows that reason, the status body is `{"status":"pending"}`
with no reason key, and the shell and client live lists stay empty. `request-2` stores
`approved` as a second pending row: its status body is `{"status":"pending"}`, not
`{"status":"granted"}`, and the live lists stay empty. `request-3` stores `""` as `""` on
the write action. A repeat of the undeclared ask stores nothing. The owner's `once` grant of
`request-1` puts one live entry without a reason or (for the client) a session id on each
live list, while the request list keeps `show this step` on the granted record. The owner
status body is `{"status":"granted"}` alone. One `execute` spends the grant, a second use
is `grant is not live: Exhausted`, and the three records keep their reasons and statuses.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_request_reason_is_not_the_grant -- --exact
```

### F-stated-reason-is-blank

Old bytes, 33:

```rust
                "reason": reason,
```

New bytes, 70:

```rust
                "reason": if reason.is_empty() { reason } else { "" },
```

The planted crate compiled. `shown_request_reason_is_not_the_grant` failed at
`src/lib.rs:7617:5` (planted tree) on the shell request list: `assertion left == right
failed: a shown request reason is not the grant: the shell list shows the stated reason on
the pending request`; left held a row with `reason` `""`, right expected `show this step`.
The stated reason was blanked before the route stored it. Restored, the test passes.

### F-approved-reason-mints

Old bytes, 43:

```rust
        )?;
        Ok(stored["request_id"]
```

New bytes, 411:

```rust
        )?;
        if reason == "approved" {
            stand_in.seed_grant(
                "request-plant",
                "component-1",
                "localhost://Public/plan-approval/a.txt",
                "read",
                "once",
                0,
                agent_conformance::standin_runtime::Life::Live,
                false,
            );
        }
        Ok(stored["request_id"]
```

The planted crate compiled. `shown_request_reason_is_not_the_grant` failed at
`src/lib.rs:7770:5` (planted tree) on the shell live list: `assertion left == right failed:
a shown request reason is not the grant: the reason approved leaves the shell live list
empty`; left held the seeded `request-plant` grant, right expected the empty shell body. A
request reason of `approved` minted a grant. Restored, the test passes.

Neither plant calls `seed_request`. After both restores,
`git diff -- lab/plan-approval/src/lib.rs` holds no `request-plant`, no
`reason.is_empty` and no plant `seed_grant` inside `journeys::request`. The restored proof
command set (the fmt check and the twenty-two test commands in the task) took 1.72 s real.
This lane has no `falsifiers.json`; no id is added.

029: `journeys::request` takes the reason it is given and sends it on the one submit; `shown_request_reason_is_not_the_grant` proves the reason stays on the request, a pending or granted status body and a live grant carry none, and `approved` mints nothing; two hand-run plants caught and restored.

## 030

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md) Non-negotiable boundaries:

> A visible approval card is not the grant authority.

This task proves the rationale the owner states with the grant. `approve` gains
`rationale: &str` after `plan_sha256`, sends it unchanged as the route's `rationale` key,
and returns that route's result. It matches no `Caller`, no `duration`, no hash and no
rationale, contains no `Shell auto-grant` or `owner approved`, and adds no function. Every
existing call passes `"owner approved"`; no other argument and no assertion changed.

`shown_grant_rationale_is_not_the_grant` drives two sessions through `running_agent`. A
client approval before any request exists is the shell-only refusal and stores no capsule,
request or grant. Three requests go through `request`: `request-1` stores `show this
step`, `request-2` stores `approved`, and `request-3` stores `""` on the write action. A
client approval, a duration of `standing`, a mismatched plan hash and an unknown request
id each store nothing and mint nothing. The shell's `once` grant with rationale `show this
grant` stores that text as `decision_reason` while the reason stays `show this step`; the
granted status body is `{"status":"granted"}` alone, and the live entries carry no
rationale. A rationale of `session` with duration `once` gives `decision_reason` `session`
and grant duration `once`; an empty rationale is stored as `""`. A second approval of a
granted request is `request is not pending: request-1` and keeps the first
`decision_reason`. One `execute` spends the once grant while `decision_reason` stays
`show this grant`; a second use is `grant is not live: Exhausted`.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_grant_rationale_is_not_the_grant -- --exact
```

### F-stated-rationale-is-owner-approved

Old bytes, 71:

```rust
) -> Result<Value, (u16, String)> {
    stand_in.post_capability_grant(
```

New bytes, 189:

```rust
) -> Result<Value, (u16, String)> {
    let rationale = if rationale == "owner approved" {
        rationale
    } else {
        "owner approved"
    };
    stand_in.post_capability_grant(
```

The planted crate compiled. `shown_grant_rationale_is_not_the_grant` failed at
`src/lib.rs:8460:5` (planted tree) on the shell request list: `assertion left == right
failed: a shown grant rationale is not the grant: the stated rationale is the decision
reason`; left held `decision_reason` `owner approved`, right expected `show this grant`.
The stated rationale was replaced before the route stored it. Restored, the test passes.

### F-approved-rationale-mints

Old bytes, 71:

```rust
) -> Result<Value, (u16, String)> {
    stand_in.post_capability_grant(
```

New bytes, 394:

```rust
) -> Result<Value, (u16, String)> {
    if rationale == "approved" {
        stand_in.seed_grant(
            "request-plant",
            "component-1",
            "localhost://Public/plan-approval/a.txt",
            "read",
            "once",
            0,
            agent_conformance::standin_runtime::Life::Live,
            false,
        );
    }
    stand_in.post_capability_grant(
```

The planted crate compiled. `shown_grant_rationale_is_not_the_grant` failed at
`src/lib.rs:8248:5` (planted tree) on the shell live list: `assertion left == right failed:
a shown grant rationale is not the grant: a refused client approval mints no grant`; left
held the seeded `request-plant` grant, right expected the empty shell body. A rationale of
`approved` minted a grant. Restored, the test passes.

Neither plant calls `seed_request`; the second plant calls `seed_grant`. After both
restores, `git diff -- lab/plan-approval/src/lib.rs` holds no `request-plant`, no plant
`seed_grant` inside `approve` and no rationale replacement. The restored proof command set
(the fmt check and the twenty-three test commands in the task) took 2.05 s real. This lane
has no `falsifiers.json`; no id is added.

030: `approve` takes the rationale it is given and sends it on the one grant call; `shown_grant_rationale_is_not_the_grant` proves the rationale is the decision reason on the request, a granted status body and a live grant omit it, four refusals store none, and `""` stays `""`; two hand-run plants caught and restored.

## 031

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md), Request flow step 8:

> If additional consent is required, Runtime records a pending request and
> Home or Inbox presents it. The UI does not mint the grant itself.

This task proves the reason the owner states with the deny. `deny_shown_plan`
gains `reason: &str` after `request_id`, sends it unchanged as the route's
`reason` key, and returns that route's result. It matches no `Caller` and no
reason, contains no `deny the shown plan` or `Denied by user`, and adds no
function. Every existing call passes `"deny the shown plan"`; no other
argument and no assertion changed.

`shown_deny_reason_is_not_the_grant` drives two sessions through
`running_agent`. A client deny before any request exists is the shell-only
refusal and stores no capsule, request or grant. The same refusal covers the
asking session, an absent id, and the step before it is settled. A shell deny
of `request-1` with reason `do not run this` stores that text as
`decision_reason` while the reason stays `show this step`, and the sibling
`request-2` with reason `approved` stays pending. A reason of `granted` stores
status `denied` and mints nothing. An empty reason is stored as `""`, not
`Denied by user`. A deny of a granted request is `request is not pending:
request-4` and keeps `decision_reason` `show this grant` and the live `once`
grant; one `execute` spends it while `decision_reason` stays `show this
grant`, and the next use is `grant is not live: Exhausted`.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_deny_reason_is_not_the_grant -- --exact
```

### F-stated-deny-reason-is-hardcoded

Old bytes, 97:

```rust
        &json!({
            "request_id": request_id,
            "reason": reason,
        }),
```

New bytes, 223:

```rust
        &json!({
            "request_id": request_id,
            "reason": if reason == "deny the shown plan" {
                reason
            } else {
                "deny the shown plan"
            },
        }),
```

The planted crate compiled. `shown_deny_reason_is_not_the_grant` failed at
`src/lib.rs:9226:5` (planted tree) on the shell request list: `assertion left == right
failed: a shown deny reason is not the grant: the stated reason is the decision reason
while the sibling stays pending`; left held `decision_reason` `deny the shown plan`,
right expected `do not run this`. The stated reason was replaced before the route
stored it. Restored, the test passes.

### F-approved-deny-mints

Old bytes, 72:

```rust
) -> Result<Value, (u16, String)> {
    stand_in.post_capability_deny(
```

New bytes, 392:

```rust
) -> Result<Value, (u16, String)> {
    if reason == "approved" {
        stand_in.seed_grant(
            "request-plant",
            "component-1",
            "localhost://Public/plan-approval/a.txt",
            "read",
            "once",
            0,
            agent_conformance::standin_runtime::Life::Live,
            false,
        );
    }
    stand_in.post_capability_deny(
```

The planted crate compiled. `shown_deny_reason_is_not_the_grant` failed at
`src/lib.rs:9010:5` (planted tree) on the shell live list: `assertion left == right failed:
a shown deny reason is not the grant: a refused client deny mints no grant`; left held
the seeded `request-plant` grant, right expected the empty shell body. A deny reason of
`approved` minted a grant. Restored, the test passes.

Neither plant calls `seed_request`; the second plant calls `seed_grant`. After both
restores, `git diff -- lab/plan-approval/src/lib.rs` holds no `request-plant` and no
plant `seed_grant` inside `deny_shown_plan`. The restored proof command set (the fmt
check and the twenty-four test commands in the task) took 3.02 s real. This lane has no
`falsifiers.json`; no id is added.

031: `deny_shown_plan` takes the reason it is given and sends it on the one deny call; `shown_deny_reason_is_not_the_grant` proves the stated reason is the decision reason on the request, a denied status body carries it, a sibling stays pending, `granted` and `""` store as text and mint nothing, and a deny of a granted request leaves the grant; two hand-run plants caught and restored.

## 032

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md), Session and interaction contract:

> an explicit interrupt or cancel operation that reports its settlement

This task proves the reason the owner states with the stop. `stop_shown_session`
gains `reason: &str` after `session_id`, sends it unchanged as the route's only
body key, and returns that route's result. It matches no `Caller` and no
reason, contains no `stop the shown session` or `stopped:`, and adds no
function. Every existing call passes `"stop the shown session"`; no other
argument and no assertion changed.

`shown_stop_reason_is_not_the_grant` drives two sessions through
`running_agent`. A client stop before any session runs is the shell-only
refusal and stores no capsule, request or grant. A shell stop of an absent id
with an empty reason is `stop needs a reason`, before the instance lookup. Two
sessions then run with no cause; a client stop with an empty reason is still
the shell refusal. The first session submits `request-1`, and a shell stop with
an empty reason leaves it pending. The shell grants `request-1` once and the
other session's write once. The first session then submits `request-2` with
reason `approved`, and the other session submits `request-4`. A client stop of
the first session with reason `cancel this session` is the shell refusal and
leaves everything. A shell stop of an absent id with the same reason is
`unknown instance: component-absent`. The shell stop of `component-1` with
reason `cancel this session` stores the cause `stopped: cancel this session`,
denies `request-2` under `runtime` with that cause, revokes `request-1`'s once
grant, and leaves the other session's pending step and its live grant. `execute`
then returns `grant is not live: Revoked`. A later stop of that stopped session
with reason `granted` is `instance is not live: stopped` and leaves the first
cause. The shell stop of `component-2` with reason `granted` stores the cause
`stopped: granted`, denies `request-4` with that cause, revokes its once grant
and mints nothing; `execute` returns `grant is not live: Revoked` and the shell
live list is empty.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_stop_reason_is_not_the_grant -- --exact
```

### F-stated-stop-reason-is-hardcoded

Old bytes, 77:

```rust
    stand_in.delete_capsule(caller, session_id, &json!({ "reason": reason }))
```

New bytes, 261:

```rust
    stand_in.delete_capsule(
        caller,
        session_id,
        &json!({
            "reason": if reason == "stop the shown session" {
                reason
            } else {
                "stop the shown session"
            },
        }),
    )
```

The planted crate compiled. `shown_stop_reason_is_not_the_grant` failed at
`src/lib.rs:9898:5` (planted tree) on the empty-reason stop of an absent id:
`assertion left == right failed: a shown stop reason is not the grant: an empty
reason is the route's reason refusal`; left held `unknown instance:
component-absent`, right expected `stop needs a reason`. The stated reason was
replaced before the route read it. Restored, the test passes.

### F-granted-stop-mints

Old bytes, 77:

```rust
    stand_in.delete_capsule(caller, session_id, &json!({ "reason": reason }))
```

New bytes, 423:

```rust
    let stopped = stand_in.delete_capsule(caller, session_id, &json!({ "reason": reason }));
    if reason == "granted" {
        stand_in.seed_grant(
            "request-plant",
            "component-2",
            "localhost://Public/plan-approval/a.txt",
            "read",
            "once",
            0,
            agent_conformance::standin_runtime::Life::Live,
            false,
        );
    }
    stopped
```

The planted crate compiled. `shown_stop_reason_is_not_the_grant` failed at
`src/lib.rs:9893:5` (planted tree) on the shell live list after the refused
client stop: `assertion left == right failed: a shown stop reason is not the
grant: a refused client stop mints no grant`; left held the seeded
`request-plant` grant, right expected the empty shell body. A stop reason of
`granted` minted a grant. Restored, the test passes.

Neither plant calls `seed_request`; the second plant calls `seed_grant`. After both
restores, `git diff -- lab/plan-approval/src/lib.rs` holds no `request-plant` and no
plant `seed_grant` inside `stop_shown_session`. The restored proof command set (the
fmt check and the twenty-five test commands in the task) took 1.91 s real. This
lane has no `falsifiers.json`; no id is added.

032: `stop_shown_session` takes the reason it is given and sends it on the one stop call; `shown_stop_reason_is_not_the_grant` proves the stated reason is the capsule cause and the pending step's decision reason, that `granted` and `""` are text and mint nothing, and that a use of either stopped session's once grant is revoked; two hand-run plants caught and restored.

## 033

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md), Harness conformance:

> accept Runtime denial, expiry, revocation, and unknown settlement as
> authoritative outcomes.

This task proves the reap the Runtime performs when the worker dies with no stop
request. `shown_worker_exited(stand_in, session_id)` is the one reap call: it
passes the session id to the stand-in's own `worker_exited` seam and returns
that result. It takes no caller and no reason, matches no id, contains no
`worker exited`, `stopped:` or `Caller`, and adds no second settle step. The
cause is the stand-in's fixed cause; this crate stores no copy of `end_instance`,
`settle_pending` or `revoke_live`, and it does not call `watch_ended`. No
existing helper and no existing assertion changed.

`shown_worker_exit_is_not_the_grant` drives two sessions through `running_agent`.
A reap before any launch is `unknown instance: component-1` and stores no
capsule, request or grant. Two sessions then run with no cause; a reap of
`component-absent` is `unknown instance: component-absent` and leaves both
running. The first session submits `request-1` and `request-2`; the owner grants
`request-1` once. The other session submits `request-3` (write) and `request-4`;
the owner grants `request-3` once. The reap of `component-1` stores the capsule
status `failed` with cause `worker exited`, denies `request-2` under `runtime`
with that cause, and revokes `request-1`'s once grant. `execute` then returns
`grant is not live: Revoked`. A second reap of that failed session is
`instance is not live: failed` and leaves the first cause, the two rows and the
other live grant. A later shell stop with reason `granted` is the same refusal
and stores no `stopped: granted`. A later submit on that session is
`instance is not live: failed` and stores nothing. The reap of `component-2`
stores the same fixed cause, denies `request-4` under `runtime` with it, and
revokes `request-3`'s once grant; `execute` returns `grant is not live:
Revoked` and the shell live list is empty.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_worker_exit_is_not_the_grant -- --exact
```

### F-worker-exit-is-a-stop

Old bytes, 38:

```rust
    stand_in.worker_exited(session_id)
```

New bytes, 170:

```rust
    stand_in
        .delete_capsule(
            Caller::Shell,
            session_id,
            &json!({ "reason": "worker exited" }),
        )
        .map(|_| ())
```

The planted crate compiled. `shown_worker_exit_is_not_the_grant` failed at
`src/lib.rs:10824:5` (planted tree) on the capsule state after the first reap:
`assertion left == right failed: a shown worker exit is not the grant: the reap
stores the fixed cause as the capsule cause`; left held status `stopped` with
cause `stopped: worker exited`, right expected status `failed` with cause
`worker exited`. The reap was a stop route, not the fixed cause. Restored, the
test passes.

### F-worker-exit-mints

Old bytes, 38:

```rust
    stand_in.worker_exited(session_id)
```

New bytes, 377:

```rust
    let reaped = stand_in.worker_exited(session_id);
    if reaped.is_ok() {
        stand_in.seed_grant(
            "request-plant",
            "component-2",
            "localhost://Public/plan-approval/a.txt",
            "read",
            "once",
            0,
            agent_conformance::standin_runtime::Life::Live,
            false,
        );
    }
    reaped
```

The planted crate compiled. `shown_worker_exit_is_not_the_grant` failed at
`src/lib.rs:10973:5` (planted tree) on the shell live list after the first reap:
`assertion left == right failed: a shown worker exit is not the grant: the reap
revokes only the reaped session's live grant`; left held the seeded
`request-plant` grant, right expected only `request-3`. The fixed cause minted a
grant. Restored, the test passes.

Neither plant calls `seed_request`; the second plant calls `seed_grant`. After
both restores, `git diff -- lab/plan-approval/src/lib.rs` holds no
`request-plant` and no plant `delete_capsule` inside `shown_worker_exited`. The
restored proof command set (the fmt check and the twenty-six test commands in
the task) took 4.46 s real. This lane has no `falsifiers.json`; no id is added.

033: `shown_worker_exited(stand_in, session_id)` is the one reap call and passes only the session id to the stand-in's own seam; `shown_worker_exit_is_not_the_grant` proves the fixed cause `worker exited` is the capsule cause and the pending step's decision reason with `settled_by` `runtime`, that the granted step and the other session's live grant stay, that a second reap and a later shell stop and submit are `instance is not live: failed`, and that a use of either failed session's once grant is revoked; two hand-run plants caught and restored.

## 034

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md), Request flow step 10:

> The result returns to the Agent Host and Home without exposing provider
> credentials or broader authority

This task proves the pair the grant route stores beside its answer is a read for
the owning session, and that the pair is not the grant. `read_shown_run(stand_in,
caller, request_id)` is the one pair read: it passes the caller and the request
id to the stand-in's own `get_run_binding` and returns that result. It takes
`&StandIn`, matches no caller and no id, holds no `run-` text, and calls no
store, seed, validate, effect or capsule seam. The lookup runs before the life
check and before the caller check: a pending or absent id is `unknown grant`
for the owner, another session and the shell; a grant that is not live is
`grant is not live: ` with its own word for the owner and the shell alike; a
live grant then refuses the shell with the expected session alone and another
session with `, got ` and its own session. Ok is `run_id` and `request_id` only.
No existing helper and no existing assertion changed.

`shown_run_pair_is_not_the_grant` drives two sessions through `running_agent`.
A pair read before any launch is `unknown grant`, not the request lookup and not
a caller refusal, and stores no capsule or grant. Two sessions then run with no
cause. The first session submits `request-1` (read); its pair read as the owner,
as the shell and as the other session is `unknown grant`, and its status stays
`pending`. The owner grants `request-1` once with the hash of `PLAN_A`; the
answer is `{"success": true}` with no `run_id` key. The shell is `wrong
capsule: expected component-1` with no `, got`; `component-2` is `wrong capsule:
expected component-1, got component-2`; the empty session is `wrong capsule:
expected component-1, got `. The owner reads `{"run_id":"run-request-1",
"request_id":"request-1"}` with no status, plan, token, session, reason or
rationale key, and a second read returns the same pair. The live list holds one
entry without `run_id`, and the status is `granted` without `run_id`. The other
session submits `request-2` (write of `PLAN_B`) and the owner grants it for a
session with the hash of `PLAN_B`. Its pair read is `run-request-2`; the cross
reads are `wrong capsule` each. The live list holds both entries without
`run_id`. `execute` of `request-1` then makes its pair read `grant is not live:
Exhausted` for the owner and for the shell, and only `request-2` stays live. A
use of `request-2` leaves the session grant readable and listed. A shell stop of
`component-2` stores `stopped: stop the shown session`, leaves `component-1`
running with no cause, and makes `request-2`'s pair read `grant is not live:
Revoked` for the owner and the shell, while `request-1` stays `Exhausted`. The
shell live list is empty.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_run_pair_is_not_the_grant -- --exact
```

### F-run-read-spends

Old parameter bytes, 23:

```rust
    stand_in: &StandIn,
```

New parameter bytes, 27:

```rust
    stand_in: &mut StandIn,
```

Old body bytes, 48:

```rust
    stand_in.get_run_binding(caller, request_id)
```

New body bytes, 357:

```rust
    let read = stand_in.get_run_binding(caller, request_id);
    if read.is_ok() {
        let _ = stand_in.post_capability_validate(
            caller,
            &json!({
                "request_id": request_id,
                "plan_sha256": "156e544f8e98e81c5e504dfd7ed21d2adb703b8f9dafa8701b064255b69f85ae",
            }),
        );
    }
    read
```

The planted crate compiled. `shown_run_pair_is_not_the_grant` failed at
`src/lib.rs:11508:5` (planted tree) on the second pair read of `request-1`:
`assertion left == right failed: a shown run pair is not the grant: a second
pair read returns the same pair`; left held `Err((400, "grant is not live:
Exhausted"))`, right expected the pair `{"run_id":"run-request-1",
"request_id":"request-1"}`. The read spent the once grant it read. Restored, the
test passes.

### F-run-read-mints

Old parameter bytes, 23:

```rust
    stand_in: &StandIn,
```

New parameter bytes, 27:

```rust
    stand_in: &mut StandIn,
```

Old body bytes, 48:

```rust
    stand_in.get_run_binding(caller, request_id)
```

New body bytes, 381:

```rust
    let read = stand_in.get_run_binding(caller, request_id);
    if read.is_ok() {
        stand_in.seed_grant(
            "request-plant",
            "component-2",
            "localhost://Public/plan-approval/a.txt",
            "read",
            "once",
            0,
            agent_conformance::standin_runtime::Life::Live,
            false,
        );
    }
    read
```

The planted crate compiled. `shown_run_pair_is_not_the_grant` failed at
`src/lib.rs:11518:5` (planted tree) on the shell live list after the two owner
reads: `assertion left == right failed: a shown run pair is not the grant: the
paired step is the live list`; left held the `request-1` entry plus two
`request-plant` entries and right expected the `request-1` entry alone. The read
minted a grant. Restored, the test passes.

Neither plant calls `seed_request`; the first plant calls
`post_capability_validate` and the second calls `seed_grant`. After both
restores, `git diff -- lab/plan-approval/src/lib.rs` holds no `request-plant` and
no plant validate call inside `read_shown_run`. The restored proof command set
(the fmt check and the twenty-seven test commands in the task) took 4.39 s real.
This lane has no `falsifiers.json`; no id is added.

034: `read_shown_run(stand_in, caller, request_id)` is the one pair read and passes the caller and the request id to the stand-in's own pair route; `shown_run_pair_is_not_the_grant` proves a pending request is `unknown grant`, the shell and another session are refused while the grant is live, a second read keeps the once grant live, `execute` makes the owner's and the shell's read `grant is not live: Exhausted`, a session grant stays readable after one `execute`, a stop makes that session's read `grant is not live: Revoked`, and the grant answer, status body and live entry omit `run_id`; two hand-run plants caught and restored.

## 035

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md), Request flow step 9:

> Runtime dispatches an approved operation to the owning provider and records the result in the same audit path used for a human action

This task proves a shown use names the run pair the grant route minted.
`execute(stand_in, caller, request_id, plan, run_id)` is the only use call. It
passes the caller and the body `request_id` and `plan_sha256` of the plan bytes
to the stand-in's own `post_capability_validate`, adds a `run_id` key only when
`run_id` is `Some`, and returns that route's result. It matches no caller and no
run id text, holds no `run-` or `effect run` text, and calls no seed, store,
pair, effect or capsule seam. Every earlier call passes `None`, so its body has
no `run_id` key. No existing helper and no existing assertion changed.

`shown_use_names_the_minted_run` drives two sessions through `running_agent`.
A use before any launch is `unknown grant`, not the unminted-run refusal and not
a caller refusal, and stores no capsule or grant. The two sessions run with no
cause. The first session submits `request-1` (read of `PLAN_A`); a use that
presents the upcoming `run-request-1` is still `unknown grant`, the step stays
`pending` and the live list stays empty. The owner grants `request-1` once with
the hash of `PLAN_A`; the answer is `{"success": true}` with no `run_id` key,
and the owner reads `{"run_id":"run-request-1","request_id":"request-1"}`. The
shell's use with the minted pair and with `run-other` is `capability validate
needs an instance session`, and the once grant and its pair stay live. The other
session's `run-other` is `effect run run-other is not bound to request
request-1`, and its minted pair is `wrong capsule: expected component-1, got
component-2`; neither spends. The owner's `run-other`, `""`, `granted` and
`run-request-2` are the unminted-run refusal naming each id, and the grant stays
live. The minted pair with `PLAN_B` is `grant is not bound to this plan` and
leaves the grant live. The minted pair with `PLAN_A` is `{"valid": true}` with
no `run_id` key, and the pair read then is `grant is not live: Exhausted`; a
later `run-other` and the minted pair are each `Exhausted`, not the unminted
reason. The second session submits `request-2` (write of `PLAN_B`) and the owner
grants it for a session. Its pair read is `run-request-2`; the first request's
pair is `effect run run-request-1 is not bound to request request-2`. An omitted
run id succeeds, then the minted pair succeeds, and each use leaves the session
grant live and readable. A shell stop of `component-2` stores `stopped: stop the
shown session`, leaves `component-1` running with no cause, and makes a
presented `run-other` and the minted pair each `grant is not live: Revoked`,
while `request-1` stays `Exhausted`. The shell live list is empty.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_use_names_the_minted_run -- --exact
```

### F-use-drops-run

Old body bytes, 223:

```rust
    let mut body = json!({ "request_id": request_id, "plan_sha256": plan_sha256(plan) });
    if let Some(run_id) = run_id {
        body["run_id"] = json!(run_id);
    }
    stand_in.post_capability_validate(caller, &body)
```

New body bytes, 158:

```rust
    let body = json!({ "request_id": request_id, "plan_sha256": plan_sha256(plan) });
    let _ = run_id;
    stand_in.post_capability_validate(caller, &body)
```

The planted crate compiled. `shown_use_names_the_minted_run` failed at
`src/lib.rs:12019:5` (planted tree) on the other session's different run id:
`assertion left == right failed: a shown use names the minted run pair: the
other session's different run id is the unminted-run refusal`; left held
`Err((403, "wrong capsule: expected component-1, got component-2"))`, right
expected `Err((403, "effect run run-other is not bound to request
request-1"))`. The dropped run id skipped the compare. Restored, the test
passes.

### F-unminted-run-mints

Old body bytes, 223:

```rust
    let mut body = json!({ "request_id": request_id, "plan_sha256": plan_sha256(plan) });
    if let Some(run_id) = run_id {
        body["run_id"] = json!(run_id);
    }
    stand_in.post_capability_validate(caller, &body)
```

New body bytes, 677:

```rust
    let mut body = json!({ "request_id": request_id, "plan_sha256": plan_sha256(plan) });
    if let Some(run_id) = run_id {
        body["run_id"] = json!(run_id);
    }
    let result = stand_in.post_capability_validate(caller, &body);
    if let Err((403, reason)) = &result {
        if reason.starts_with("effect run ") {
            stand_in.seed_grant(
                "request-plant",
                "component-2",
                "localhost://Public/plan-approval/a.txt",
                "read",
                "once",
                0,
                agent_conformance::standin_runtime::Life::Live,
                false,
            );
        }
    }
    result
```

The planted crate compiled. `shown_use_names_the_minted_run` failed at
`src/lib.rs:12075:5` (planted tree) on the shell live list after the other
session's refusals: `assertion left == right failed: a shown use names the
minted run pair: the other session's refusals leave the once grant live`; left
held the `request-1` entry plus a `request-plant` entry, right expected the
`request-1` entry alone. The unminted-run refusal minted a grant. Restored, the
test passes.

Neither plant calls `seed_request`; the first plant calls no other seam and the
second plant calls `seed_grant`. After both restores, `git diff -- lab/plan-approval/src/lib.rs`
holds no `request-plant` and no plant validate call inside `execute`. The
restored proof command set (the fmt check and the twenty-eight test commands in
the task) took 3.91 s real. This lane has no `falsifiers.json`; no id is added.

035: `execute(stand_in, caller, request_id, plan, run_id)` is the only use call and passes a run id only when one is given; `shown_use_names_the_minted_run` proves an absent grant is `unknown grant` even with a run id, the shell is `capability validate needs an instance session`, a different or empty run id is `effect run ... is not bound to request ...`, the minted pair from another session is `wrong capsule`, the minted pair with another plan is `grant is not bound to this plan`, the minted pair runs a once grant once and then reads `Exhausted`, an omitted run id and the minted pair each keep a session grant live, and a presented run id after a stop is `Revoked`; two hand-run plants caught and restored.

## 036

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md), Request flow step 3:

> Runtime launches the isolated Agent Host instance with only its initial scoped resources

This task proves the start outcome stored at admission settles the shown
session. `running_agent(stand_in, caller, start)` still calls `get_capsules`
first, chooses the bundle by the list length, and passes `start` to
`admit_resident` unchanged; it calls `post_capsules` and returns the launch id,
and it calls no finish. `shown_finish_start(stand_in, id)` calls the stand-in's
own `finish_start` with the id alone and returns that result; it takes no caller
and no reason. A launched session stays `starting` with cause `""` until that
one finish. Every earlier shell launch passes `Start::Ok` and now calls
`shown_finish_start` on that id immediately after its existing expect; every
earlier client launch passes `Start::Ok` and is followed by no finish. No
existing helper and no existing assertion changed.

`shown_failed_start_is_not_the_grant` proves a shown failed start is not the
grant. A finish of `component-1` before any launch is `unknown instance:
component-1`, not `start already returned`, and stores nothing. The shell
launches `component-1` with `Start::Error("start refused")`; the capsule is
`starting` with cause `""`, which is not `start refused`, and the live list
stays the empty shell body. The starting session submits `request-1` (read of
`PLAN_A`, reason `show this step`) and the owner grants it once with rationale
`show this grant`; it submits `request-2` (read of `PLAN_B`, reason `approved`)
and stays `starting`. The one finish stores `failed` with cause `start refused`,
which is not `stopped: start refused` and not `worker exited`; it revokes the
live once grant and denies `request-2` with `decision_reason` `start refused`
and `settled_by` `runtime`. `request-1` stays `granted` with `decision_reason`
`show this grant`, and its once use is `grant is not live: Revoked`, not
`grant is not live: Exhausted`. A second finish is `start already returned`, not
`instance is not live: failed`, and leaves the cause and the two request rows.

The shell launches `component-2` with `Start::Ok`; it stays `starting` with
cause `""` until its finish, and `component-1` stays failed. `component-2`
submits `request-3` (write of `PLAN_A`) and the owner grants it for the session;
it submits `request-4` (read of `PLAN_B`, reason `show this step`). The one
finish stores `running` with cause `""` and leaves `request-4` pending, with
`request-3` the only live entry. The shell launches `component-3` with
`Start::Trap("start trapped")`; the owner grants its `request-5` once and it
submits `request-6` (read of `PLAN_B`, reason `show this step`). The finish
stores cause `start trapped`, which is not `stopped: start trapped` and not
`start refused`; it denies `request-6` with that cause and makes the once use
`grant is not live: Revoked`, while `request-5` stays `granted` and
`component-2` stays running with `request-4` pending.

The shell launches `component-4` with `Start::Error("granted")` and it submits
`request-7` (read of `PLAN_A`, reason `granted`). The finish stores cause
`granted`, which is not `stopped: granted`; it denies `request-7` with
`decision_reason` `granted` and `settled_by` `runtime` and mints nothing, so its
status is `denied` with reason `granted`, not `{"status":"granted"}`. A later
submit and a later shell stop of the failed `component-1` are each `instance is
not live: failed`; the capsule keeps cause `start refused` and stores no
`stopped: granted`, and the two `component-1` rows stay. The sibling session's
grant for `request-3` stays the one live entry and its `PLAN_A` use returns
`{"valid": true}`.

This crate stores no copy of `apply_start`, `settle_pending` or `revoke_live`.
`preview`, `plan_sha256`, `approve`, `execute`, `deny_shown_plan`,
`age_shown_plan`, `stop_shown_session`, `read_shown_request`, `read_shown_grants`,
`read_shown_requests`, `shown_worker_exited`, `read_shown_run` and `request` are
unchanged, and neither plant calls `seed_request`.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_failed_start_is_not_the_grant -- --exact
```

### F-failed-start-is-a-stop

Old body bytes, 122:

```rust
pub fn shown_finish_start(stand_in: &mut StandIn, id: &str) -> Result<(), (u16, String)> {
    stand_in.finish_start(id)
}
```

New body bytes, 208:

```rust
pub fn shown_finish_start(stand_in: &mut StandIn, id: &str) -> Result<(), (u16, String)> {
    stand_in
        .delete_capsule(Caller::Shell, id, &json!({ "reason": "start refused" }))
        .map(|_| ())
}
```

The planted crate compiled. `shown_failed_start_is_not_the_grant` failed at
`src/lib.rs:12697:5` (planted tree) on the finished capsule:
`assertion `left == right` failed: a shown failed start is not the grant: the
finish stores the start's own cause`; left held `{"cause":"stopped: start
refused","id":"component-1","status":"stopped"}`, right expected
`{"cause":"start refused","id":"component-1","status":"failed"}`. The stop route
stored a stop cause instead of the stored start. Restored, the test passes.

### F-failed-start-mints

Old body bytes, 122:

```rust
pub fn shown_finish_start(stand_in: &mut StandIn, id: &str) -> Result<(), (u16, String)> {
    stand_in.finish_start(id)
}
```

New body bytes, 461:

```rust
pub fn shown_finish_start(stand_in: &mut StandIn, id: &str) -> Result<(), (u16, String)> {
    let result = stand_in.finish_start(id);
    if result.is_ok() {
        stand_in.seed_grant(
            "request-plant",
            "component-2",
            "localhost://Public/plan-approval/a.txt",
            "read",
            "once",
            0,
            agent_conformance::standin_runtime::Life::Live,
            false,
        );
    }
    result
}
```

The planted crate compiled. `shown_failed_start_is_not_the_grant` failed at
`src/lib.rs:12814:5` (planted tree) on the live list after the failed start:
`assertion `left == right` failed: a shown failed start is not the grant: the
revoked once grant leaves the live list empty`; left held the empty shell body
plus the `request-plant` entry, right expected the empty shell body. The finish
minted a grant after its own revoke. Restored, the test passes.

Neither plant calls `seed_request`; the first plant calls `delete_capsule` and
the second plant calls `seed_grant`. After both restores, `git diff -- lab/plan-approval/src/lib.rs`
holds no `request-plant` and no plant call inside `shown_finish_start`. The
restored proof command set (the fmt check and the twenty-nine test commands in
the task) took 5.10 s real. This lane has no `falsifiers.json`; no id is added.

036: `running_agent(stand_in, caller, start)` is the only launch and passes the stored start to `admit_resident` without finishing; `shown_finish_start(stand_in, id)` is the only finish call and passes only the id; `shown_failed_start_is_not_the_grant` proves a failed start stores its own cause, denies the pending step with that cause and `runtime`, revokes the live once grant, leaves the granted step and the sibling session alone, refuses a second finish and a later submit or stop with the not-live reason, and stores no stop reason; two hand-run plants caught and restored.
