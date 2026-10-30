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
