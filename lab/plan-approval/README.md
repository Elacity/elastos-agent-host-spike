# plan-approval lab: preview, approve, deny, stop or leave a shown step pending

This crate is the approval half of the agent plan approval slice. It follows
[`docs/AGENT_ARCHITECTURE.md`](../../docs/AGENT_ARCHITECTURE.md), Request flow
step 5:

> A proposal carries no authority.

Step 8 records the other settlement of the pending request:

> If additional consent is required, Runtime records a pending request and
> Home or Inbox presents it. The UI does not mint the grant itself.

The Delegation section states the allow-once scope:

> Allow once authorizes one exact operation.

`preview` returns the plan bytes and `agent_conformance::identity::sha256` of
those bytes. It calls no `StandIn` method, takes no path, parses no fixture and
reads no clock, directory or planner. The test reads the stand-in only through
`get_capability_list` and `get_capsules`, so the live grant list and the
capsule list stay as they were.

`deny_shown_plan` only calls `post_capability_deny` as the shell with reason
`deny the shown plan`. A denied step is not a live grant and cannot be granted
later. `execute` of a step with no live grant is refused with the reason
`unknown grant`, and that reason omits the id. A deny settles one request, so
the sibling request stays pending for its own allow-once grant.

`age_shown_plan` only calls the stand-in's `set_instant`. The shown steps come
from `journeys::request`, and the allowed step comes from `approve`. A pending
shown step whose age reaches 300 seconds becomes `expired` with
`Request timed out` and `runtime` as settler. An expired shown step is not a
live grant and cannot be granted later. A step already allowed once stays
granted at instant 300, and its `once` grant stays live until its own expiry.
The design keeps this pending state for every settlement kind:

> approval requests that remain pending across UI, Agent Host, or Runtime
> restart until approved, denied, expired, revoked, or cancelled;

`stop_shown_session` is the other settlement the design names:

> an explicit interrupt or cancel operation that reports its settlement

A stop is that cancel. It only calls the stand-in's `delete_capsule` as the
shell with the reason `stop the shown session`, takes no plan and no approved
flag, and returns that result; Ok is JSON null. The shown steps come from
`journeys::request`, and the allowed step comes from `approve`. The stopped
session's pending step is denied by the runtime with the cause
`stopped: stop the shown session`, and that session's allow-once grant is
revoked, so `execute` refuses it with `grant is not live: Revoked`. The
granted record stays `granted`. The other session's step stays pending and can
still be allowed once.

An unused allow-once grant ends at the stand-in's own grant lifetime. The
Request flow states that check at step 7:

> Runtime verifies the exact resource, action, operation, principal, session,
> capsule, grant, expiry, and revocation state

`age_shown_plan` is the only clock call. This crate stores no lifetime and does
not copy the expiry rule; the stand-in mints a `once` grant with its own expiry
and compares the instant it stores. The shown steps come from
`journeys::request`, and the allow-once is `approve`. When the instant reaches
that expiry, the stand-in's live list drops the unspent grant and `execute` is
refused with `grant is not live: Expired`, while the request record stays
`granted`. A step already spent stays refused with `grant is not live:
Exhausted`, because the life check runs before the expiry check.

The Delegation section gives the session scope:

> Allow for this session authorizes a bounded operation set until the session
> ends or the grant is revoked.

`approve` is the one grant call, and it sends the duration word it is given as
the route's `duration` key without judging it. A session shown step is a live
grant that lasts until that session stops: it stays on the live list after two
uses of its plan and after the stand-in's once lifetime, because the stand-in
stores no expiry for it. A different plan is refused with `grant is not bound
to this plan` and the grant stays live. Another duration word reaches the
stand-in's own refusal, `Invalid duration: <word>. Expected 'once' or
'session'`, and the request stays pending. Stopping that session revokes the
grant, so `execute` returns `grant is not live: Revoked` and the request record
stays `granted`. This crate stores no lifetime and does not copy the expiry
rule; the stand-in owns it.

`preview`, `plan_sha256`, `execute`, `deny_shown_plan`, `age_shown_plan` and
`stop_shown_session` are unchanged by this slice; `approve` gains the duration
argument and remains the only grant call. This crate calls
`agent_conformance::standin_runtime` and does not copy it. There is one
stand-in and one hasher. The stand-in keeps one admitted row per lab CID, so
the one launch journey admits a distinct fixture CID for each session after
the first; it adds no second launch path. The June planner path is an open
question with Sash via Flint; this crate names no planner and guesses no path.

A passing run gives the Runtime no A15 credit. The expiry of an allow-once grant
and the lifetime of a session grant are the two halves of M1 check A15;
approval binding (step 8, where an allow-once decision authorises one exact
operation, and principle 16, "A visible approval card is not the grant
authority") is a later slice; RA-4 and RA-5 stay open.

## Layout

- `src/lib.rs`: `Preview`, `preview`, `plan_sha256`, `approve`,
  `age_shown_plan`, `deny_shown_plan`, `stop_shown_session`, `execute`,
  `preview_makes_no_effect`, `plan_sha256_hashes_the_exact_bytes`,
  `deny_one_shown_step`, `unanswered_shown_step_expires`,
  `stop_settles_that_sessions_shown_steps`, `shown_allow_once_expires`,
  `shown_session_lasts_until_stop` and the bound-plan journey.

## Checks

```bash
cargo fmt --manifest-path lab/plan-approval/Cargo.toml -- --check
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_session_lasts_until_stop -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_allow_once_expires -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib stop_settles_that_sessions_shown_steps -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib unanswered_shown_step_expires -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib a_grant_bound_to_one_plan_is_refused_for_another_plan -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib plan_sha256_hashes_the_exact_bytes -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib deny_one_shown_step -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib preview_makes_no_effect -- --exact
```

The hand-run plants are recorded in `LOG.md`; this lane has no
`falsifiers.json`.
