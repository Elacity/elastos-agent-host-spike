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

A shown grant authorises only the session that asked for it. `execute` is the
only use call, and it passes the caller it is given. Another session's use of
that shown grant is refused with status 403 and `wrong capsule: expected ` that
grant's session, then `, got ` the caller's session, and the grant stays on the
live list. The owning session's own use still runs, and a `once` grant then
leaves the live list. This crate stores no session check of its own; the
stand-in compares the grant's session with the caller's. `preview`,
`plan_sha256`, `approve`, `deny_shown_plan`, `age_shown_plan` and
`stop_shown_session` are unchanged by this slice. The crate does not copy the
stand-in, and it names no planner. A passing run gives the Runtime no A15
credit.

A shown grant mints only the hash the shown request stored. `approve` is the
only grant call and sends the hash it is given; this crate stores no hash
compare of its own. The design keeps the grant in the Runtime:

> The UI does not mint the grant itself.

and principle 16 states the card's place:

> A visible approval card is not the grant authority.

A shown request whose record stores a plan hash is granted only when the body
carries that same hash. Another plan, an empty hash and the first 63 characters
of the stored hash are each refused with status 403 and `approved plan does not
match the requested plan`. Each refusal mints nothing, and the request stays
pending with its stored hash. The exact hash then grants one use, which
`execute` spends, and a second use is refused with `grant is not live:
Exhausted`. `preview`, `plan_sha256`, `approve`, `execute`, `deny_shown_plan`,
`age_shown_plan` and `stop_shown_session` are unchanged by this slice. This
crate stores no hash compare of its own; the stand-in's grant route compares
the body hash with the hash the request stored. The crate does not copy the
stand-in, and it names no planner. A passing run gives the Runtime no A15
credit.

A client call through `approve` is refused before the grant body is read, so
the agent that showed a plan cannot mint its grant. `approve` is the only grant
call and passes the caller it is given. The design keeps the grant in the
Runtime:

> The UI does not mint the grant itself.

The session that posted the shown plan and the other running session are each
refused with status 403 and `This endpoint requires shell privileges`. A
different plan hash, an empty hash, the first 63 characters of the stored hash
and the duration word `standing` get that same refusal, because the shell check
runs before the hash and the duration check. Each refusal mints nothing: the
request stays pending with its stored hash and the shell's live list stays
empty. The shell's call with the exact hash then grants one use, which
`execute` spends; a second use is refused with `grant is not live: Exhausted`.
This crate stores no copy of the shell check; the stand-in's grant route makes
it. `preview`, `plan_sha256`, `execute`, `deny_shown_plan`, `age_shown_plan`
and `stop_shown_session` are unchanged by this slice. The crate does not copy
the stand-in, and it names no planner. A passing run gives the Runtime no A15
credit.

A shell call through `execute` cannot spend a shown grant. The design states
the boundary:

> A provider implements an operation; Runtime authorizes the caller.

`execute` is the only use call, and it passes the caller it is given. A shell
caller is refused with status 403 and `capability validate needs an instance
session` for the bound plan, for a different plan and for empty plan bytes,
because the caller check runs before the plan check. Each refusal spends
nothing: the request stays granted and the `once` grant stays live. The other
session's use is refused with status 403 and `wrong capsule`, and the grant
stays live. The owning session's own use then runs once and the grant leaves
the live list. A shell call after that spend is still the session refusal,
`capability validate needs an instance session`, and not `grant is not live:
Exhausted`. This crate stores no copy of the caller check; the stand-in's use
route makes it. `preview`, `plan_sha256`, `approve`, `deny_shown_plan`,
`age_shown_plan` and `stop_shown_session` are unchanged by this slice. The
crate does not copy the stand-in, and it names no planner. A passing run gives
the Runtime no A15 credit.

`preview`, `plan_sha256`, `execute`, `deny_shown_plan`, `age_shown_plan` and
`stop_shown_session` are unchanged by this slice; `approve` gains the duration
argument and remains the only grant call. This crate calls
`agent_conformance::standin_runtime` and does not copy it. There is one
stand-in and one hasher. The stand-in keeps one admitted row per lab CID, so
the one launch journey admits a distinct fixture CID for each session after
the first; it adds no second launch path. The June planner path is an open
question with Sash via Flint; this crate names no planner and guesses no path.

A passing run gives the Runtime no A15 credit. The expiry of an allow-once grant
and the lifetime of a session grant are two parts of M1 check A15; the
owner-hash binding of this slice is the third part. The principal and restart
stay open, and the remaining binding rules stay open, so RA-4 and RA-5 stay
open.

## Layout

- `src/lib.rs`: `Preview`, `preview`, `plan_sha256`, `approve`,
  `age_shown_plan`, `deny_shown_plan`, `stop_shown_session`, `execute`,
  `preview_makes_no_effect`, `plan_sha256_hashes_the_exact_bytes`,
  `deny_one_shown_step`, `unanswered_shown_step_expires`,
  `stop_settles_that_sessions_shown_steps`, `shown_allow_once_expires`,
  `shown_session_lasts_until_stop`, `shown_grant_authorises_only_its_session`,
  `owner_approves_only_the_shown_hash`,
  `agent_cannot_approve_its_own_shown_plan`,
  `shell_cannot_spend_a_shown_grant` and the bound-plan journey.

## Checks

```bash
cargo fmt --manifest-path lab/plan-approval/Cargo.toml -- --check
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shell_cannot_spend_a_shown_grant -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib agent_cannot_approve_its_own_shown_plan -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib owner_approves_only_the_shown_hash -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_grant_authorises_only_its_session -- --exact
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
