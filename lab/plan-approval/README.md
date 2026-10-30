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

`deny_shown_plan` only calls `post_capability_deny`, with the caller it is
given and the reason `deny the shown plan`. A denied step is not a live grant
and cannot be granted later. `execute` of a step with no live grant is refused
with the reason `unknown grant`, and that reason omits the id. A deny settles
one request, so the sibling request stays pending for its own allow-once grant.
`deny_one_shown_step` stores both steps through `journeys::request` after
`running_agent` names the running session. The denied step is `request-1` for
`PLAN_A`, and the sibling is `request-2` for `PLAN_B`; both use resource
`localhost://Public/plan-approval/a.txt`. A shell deny of `request-1` refuses
`execute` with `unknown grant` and leaves a later `approve` of it refused as
`request is not pending: request-1`, while the sibling allow-once is `approve`
with that plan hash, and `execute` spends `PLAN_B` so the live list ends empty.
The session stays `running` with no cause. This test does not call
`seed_request`. `deny_shown_plan`, `approve`, `execute`, `running_agent` and
`request` are unchanged by this slice. The crate does not copy the stand-in,
and it names no planner. A passing run gives the Runtime no A15 credit.

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

A stop is that cancel. `stop_shown_session` is the only stop call and passes
the caller it is given to the stand-in's `delete_capsule`, with the reason
`stop the shown session`; it takes no plan and no approved flag, and returns
that result, so Ok is JSON null. The shown steps come from
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

A shell call through `request` cannot submit a shown plan. The design states
the submit boundary at Request flow step 6:

> The Agent Host submits the proposed operation to Runtime as the active agent
> principal and session

`request` is the only submit call, and it passes the caller it is given. A
shell caller is refused with status 403 and `capability request needs an
instance session` for `PLAN_A`, for `PLAN_B` and for empty plan bytes, before
any instance exists and while both sessions are running, because the caller
check runs before the body is read and before the instance lookup. Each refusal
stores nothing: both request arrays stay empty, the live list stays empty and
both capsules stay `running` with no cause. The instance session's own submit
then stores one pending request with the shown hash, which the shell grants
with `once`, and that session's `execute` spends. A shell submit after that
spend is still the session refusal, `capability request needs an instance
session`, and not `request is not pending: request-1` or
`unknown request: request-1`. This crate stores no copy of the caller check;
the stand-in's request route makes it. `preview`, `plan_sha256`, `approve`,
`execute`, `deny_shown_plan`, `age_shown_plan`, `stop_shown_session` and
`running_agent` are unchanged by this slice. The crate does not copy the
stand-in, and it names no planner. A passing run gives the Runtime no A15
credit.

Only a live instance session submits a shown plan. `request` is the only
submit call, and it passes the caller it is given. A session with no instance
is refused with status 400 and `unknown instance: ` plus that session for
`PLAN_A`, for `PLAN_B` and for empty plan bytes, because the instance lookup
runs after the body is accepted. A stopped session is refused with status 400
and `instance is not live: stopped` for those same three bodies. Neither
refusal stores anything: the capsule list, both request arrays and the live
list stay empty. The other running session's submit then stores one pending
request with the shown hash, which the shell grants with `once`, and that
session's `execute` spends. A submit from the stopped session after that spend
is still the not-live refusal, `instance is not live: stopped`, and not
`request is not pending: request-1` or `unknown request: request-1`. This
crate stores no copy of the instance lookup; the stand-in's request route
makes it. The two hand-run plants return the route error as `Ok("request-1")`
and neither plant calls `seed_request`. `preview`, `plan_sha256`, `approve`,
`execute`, `deny_shown_plan`, `age_shown_plan`, `stop_shown_session`,
`running_agent` and `request` are unchanged by this slice. The crate does not
copy the stand-in, and it names no planner. A passing run gives the Runtime no
A15 credit.

A client call through `deny_shown_plan` is refused before the deny body is
read, so the agent that showed the plan cannot settle it. `deny_shown_plan` is
the only deny call and passes the caller it is given. The design keeps the
settlement in the Runtime:

> The UI does not mint the grant itself.

The session that posted the shown plan and the other running session are each
refused with status 403 and `This endpoint requires shell privileges`, for the
step they own and for the sibling step. A missing id is that same refusal,
because the shell check runs before the request lookup. Each refusal settles
nothing: both requests stay pending with their stored hashes and the shell's
live list stays empty. The shell's deny of `request-1` then stores `denied`
under `shell` with `deny the shown plan` and leaves the sibling `request-2`
pending for its own allow-once use, which `approve` grants and `execute`
spends. A client deny after that settlement is still the shell refusal, and
not `request is not pending: request-1`. This crate stores no copy of the shell
check; the stand-in's deny route makes it. `preview`, `plan_sha256`, `approve`,
`execute`, `age_shown_plan` and `stop_shown_session` are unchanged by this
slice. The crate does not copy the stand-in, and it names no planner. A
passing run gives the Runtime no A15 credit.

A client call through `stop_shown_session` is refused before the stop body is
read, so the agent that showed the plan cannot stop its session.
`stop_shown_session` is the only stop call and passes the caller it is given.
The session that posted the shown plan and the other running session are each
refused with status 403 and `This endpoint requires shell privileges`; an
absent id and an empty id are that same refusal, because the shell check runs
before the instance lookup and the body check. Each refusal stops nothing: both
sessions stay `running` with no cause, the granted step stays `granted` under
`shell` with `owner approved`, the pending step stays pending with its stored
hash, and the live list keeps its one grant. The design names the cancellation
this refusal withholds:

> an explicit interrupt or cancel operation that reports its settlement

The shell's stop of that session then stores `stopped` with the cause
`stopped: stop the shown session`, denies that session's pending step under
`runtime`, and revokes its live grant, so `execute` returns `grant is not
live: Revoked`; the granted record stays `granted` and the other session stays
`running`. A client stop after that settlement is still the shell refusal, and
not `instance is not live: stopped`. The other session can then submit, be
granted `once` and spend that one use. This crate stores no copy of the shell
check; the stand-in's stop route makes it. `preview`, `plan_sha256`, `approve`,
`execute`, `deny_shown_plan`, `age_shown_plan` and `running_agent` are
unchanged by this slice. The crate does not copy the stand-in, and it names no
planner. A passing run gives the Runtime no A15 credit.

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

A client call through `running_agent` cannot launch a shown session. The
design states the boundary:

> A provider implements an operation; Runtime authorizes the caller.

`running_agent` is the only launch journey, and it passes the caller it is
given to `get_capsules` and `post_capsules`. A client caller is refused with
status 403 and `This endpoint requires shell privileges` at the list route,
before `admit_resident` and before this crate reads the list. A session id that
was never launched, an absent id and an empty id are that same refusal, because
the list route's shell check does not read the session id. Each refusal stores
nothing: the capsule list, both request arrays and the live list stay empty.
The shell's own launch then starts `component-1`, and its second launch starts
`component-2`; a client launch after those two is still the shell refusal and
mints no `component-3`. Both shell sessions can submit a plan, be granted once
and spend that one use. The distinct-bundle choice stays and runs only after
the list returns. This crate stores no copy of the shell check; the stand-in's
list and launch routes make it. `preview`, `plan_sha256`, `approve`, `execute`,
`deny_shown_plan`, `age_shown_plan`, `stop_shown_session` and `request` are
unchanged by this slice. The crate does not copy the stand-in, and it names no
planner. A passing run gives the Runtime no A15 credit.

A status read of a shown request is not the grant. The design states the result
boundary at Request flow step 10:

> The result returns to the Agent Host and Home without exposing provider
> credentials or broader authority

`read_shown_request` is the only status call, and it passes the caller it is
given to the stand-in's own status route. The route looks up the request before
it checks the caller. A missing id returns status 404 with `Request not found: `
plus that id for the owning session, for the other session, for an empty session
id and for the shell. An existing id returns status 403 with `Cannot access
another session's request` for the other session, for an empty session id and
for the shell. The owning session reads only the status word:
`{"status":"pending"}` or `{"status":"granted"}`, and for a settled record
`{"status":"denied","reason":"deny the shown plan"}` or
`{"status":"expired","reason":"Request timed out"}`. Those bodies carry no plan,
no resource, no request id and no token, and the read changes neither the shell
request view nor the live list. A spent once grant still reads `granted`, and
the next use is refused with `grant is not live: Exhausted`, because the status
is not the grant. `shown_request_status_is_not_the_grant` reads the shell
request view and the shell live list the way the other tests do, so the shell
list stays `get_capability_requests`. This crate stores no copy of the owner
check; the stand-in's status route makes it. `preview`, `plan_sha256`,
`approve`, `execute`, `deny_shown_plan`, `age_shown_plan`, `stop_shown_session`,
`running_agent` and `request` are unchanged by this slice. The crate does not
copy the stand-in, and it names no planner. A passing run gives the Runtime no
A15 credit.

A read of the live grant list is not a grant. The design states the result
boundary at Request flow step 10:

> The result returns to the Agent Host and Home without exposing provider
> credentials or broader authority

`read_shown_grants` is the only product read of the live list, and it passes
the caller and the scope it is given to the stand-in's own list route. A scope
other than `all_sessions_live` returns status 400 with `unknown capability
list scope: ` plus that scope, for the shell and for a client, because the
scope check runs before the caller check. A client with scope
`all_sessions_live` returns status 403 with `This endpoint requires shell
privileges`. The shell with no scope and the shell with that scope return the
same body: `scope` `all_sessions_live` and every live entry, each with
`request_id`, `session_id`, `resource`, `action`, `duration` and `granted_at`.
A client with no scope receives `capabilities` only, and its entries carry
those fields except `session_id`; the client list keeps a grant only when its
`session_id` is the caller's. A pending request stays out of the list, and a
read leaves the list unchanged. A spent `once` grant leaves the list, a
`session` grant stays listed after two uses, and a stop drops that session's
live grant. `shown_live_list_is_not_another_sessions_grant` drives the two
sessions through `running_agent`, submits and grants both plans through
`request` and `approve`, and spends them through `execute`; it calls
`read_shown_grants` for every list read and no `get_capability_list` of its
own. This crate stores no copy of the list renderer, and the shell request
list stays `get_capability_requests`. `preview`, `plan_sha256`, `approve`,
`execute`, `deny_shown_plan`, `age_shown_plan`, `stop_shown_session`,
`read_shown_request`, `running_agent` and `request` are unchanged by this
slice. The crate does not copy the stand-in, and it names no planner. A
passing run gives the Runtime no A15 credit.

A read of a session's request list does not submit again. The design states the
presentation boundary under the session contract:

> Reconnecting presentation reads durable state; it does not rerun inference or
> submit the proposed effect again.

`read_shown_requests` is the only product read of the per-session request list,
and it passes the caller and the session it is given to the stand-in's own
`GET /api/capability/requests?session=` route. A client returns status 403 with
`This endpoint requires shell privileges` for a named session, for an empty
session id and for no session, because the shell check runs before the session
is read. A shell with no session, or with an empty session, returns status 400
with `requests need a session`; neither result is the shell refusal, and neither
carries a body. A shell with any other session returns `{"requests":[]}` when
that session has no records, including a session that was never launched.

The list holds that session's records only, sorted by `request_id`. Each entry
is the stand-in's own record with `request_id`, `session_id`, `resource`,
`action`, `reason`, `status`, `decision_reason`, `settled_by` and `plan`, so
each record keeps the plan hash the owner was shown. A pending record has
`settled_by` null and an empty `decision_reason`. A denied record stores
`denied`, `shell` and `deny the shown plan`; an owner grant stores `granted`,
`shell` and `owner approved`; an expiry at instant 300 stores `expired`,
`runtime` and `Request timed out`. A denied, granted or expired record stays on
the list with its settler. A second read leaves the list and the live grants
unchanged. A spent once grant stays `granted` on the list, and the next use is
refused with `grant is not live: Exhausted`.
`shown_request_list_does_not_submit_again` drives two sessions through
`running_agent`, submits and settles their plans through `request`, `approve`,
`deny_shown_plan`, `age_shown_plan` and `execute`, and reads every request list
through `read_shown_requests` and every live list through `read_shown_grants`;
it calls no `get_capability_requests` of its own. This crate stores no copy of
`request_entry`. The one-request status read stays `read_shown_request`, and the
live list stays `read_shown_grants`. `preview`, `plan_sha256`, `approve`,
`execute`, `deny_shown_plan`, `age_shown_plan`, `stop_shown_session`,
`read_shown_request`, `read_shown_grants`, `running_agent` and `request` are
unchanged by this slice. The crate does not copy the stand-in, and it names no
planner. A passing run gives the Runtime no A15 credit.

A shown submit stores a pending request only for an exact ask the signed bundle
declared. The Request flow states the check at step 7:

> Runtime verifies the exact resource, action, operation, principal, session,
> capsule, grant, expiry, and revocation state

`journeys::request` is the only submit, and it passes the resource and the
action it is given. It sends both unchanged as the route's `resource` and
`action` keys and adds no rule of its own: this crate stores no copy of
`declared_ask`, of `request_body` or of the action allow-list.

The route checks the resource scheme before the instance is read. A resource
that starts with neither `elastos://` nor `localhost://` is status 400 with
`Unsupported resource scheme. Allowed: elastos://, localhost://`. The route
then checks the action word after lowercasing it: an action outside `read`,
`write`, `execute`, `delete`, `message` and `admin` is status 400 with
`Invalid action: ` plus that action and the expected list. A session with no
instance is status 400 with `unknown instance: ` plus that id.

A live session's pair must equal one declared ask. A pair that matches no ask
is status 403 with `ask not declared in the signed manifest: ` plus the
resource, one space and the lowercased action, and it stores nothing. The
match is equality, so the parent path, a longer path, the same path under
`elastos://` and the allowed action `execute` are each refused. `READ` is
stored as `read` and `Write` as `write`, and
`localhost://Public/resident-instances/shared.txt` with `read` is stored as
that resource. The once grant of the write request carries action `write`
until its one use spends it.

`shown_submit_names_a_declared_ask` drives two sessions through
`running_agent`. It proves the scheme and action refusals on a fresh stand-in,
the five refused pairs, the shell and unknown-instance refusals, the three
stored records, and the once grant of the write request. Every earlier submit
still passes `localhost://Public/plan-approval/a.txt` and `read`. `preview`,
`plan_sha256`, `approve`, `execute`, `deny_shown_plan`, `age_shown_plan`,
`stop_shown_session`, `read_shown_request`, `read_shown_grants`,
`read_shown_requests` and `running_agent` are unchanged by this slice. The
crate does not copy the stand-in, and it names no planner. A passing run gives
the Runtime no A15 credit.

A shown request reason is text on the request, not the grant. The Request flow
states the recorded step at step 8:

> Runtime records a pending request and Home or Inbox presents it.

`journeys::request` is the only submit, and it passes the reason it is given
unchanged as the route's `reason` key. The route stores that string as given,
so `""` is stored as `""` and `show this step` is stored as that text; it
stays on the request after the owner grants it. A reason of `approved` is
stored as a pending request and mints nothing, and an undeclared ask with
reason `approved` stores nothing. A pending or granted status body is the
status word alone, and a live grant entry has no `reason`. The once grant of
the read request is spent by one use while the request reason stays
`show this step`. `shown_request_reason_is_not_the_grant` drives two sessions
through `running_agent`, submits three reasons through `request`, reads the
lists through `read_shown_requests` and `read_shown_grants`, reads the status
through `read_shown_request`, and grants and spends through `approve` and
`execute`. This crate stores no copy of `request_body`. Every earlier submit
still passes `""`. `preview`, `plan_sha256`, `approve`, `execute`,
`deny_shown_plan`, `age_shown_plan`, `stop_shown_session`,
`read_shown_request`, `read_shown_grants`, `read_shown_requests` and
`running_agent` are unchanged by this slice. The crate does not copy the
stand-in, and it names no planner. A passing run gives the Runtime no A15
credit.

A shown grant rationale is text the owner states with the decision, not the
grant. The Non-negotiable boundaries state:

> A visible approval card is not the grant authority.

`approve` is the only grant call. It passes the rationale it is given unchanged
as the route's `rationale` key, so the route stores that string on the shown
request as `decision_reason` with `settled_by` `shell`; the request's own
reason stays as `request` stored it. A rationale of `show this grant` is the
decision reason while the request reason stays `show this step`. A rationale of
`session` with duration `once` stores `decision_reason` `session` and grant
duration `once`. `""` is stored as `""`. A rationale of `approved` on a client
caller, on duration `standing`, on a mismatched plan hash and on an unknown
request id stores nothing and mints nothing. A second approve of a granted
request is `request is not pending: ` plus that id and leaves the first
`decision_reason`. A granted status body is the status word alone, and a live
grant entry has no rationale. One use spends the once grant while
`decision_reason` stays `show this grant`. `shown_grant_rationale_is_not_the_grant`
drives two sessions through `running_agent`, submits three requests through
`request`, grants through `approve`, reads the lists and the status through
`read_shown_requests`, `read_shown_grants` and `read_shown_request`, and spends
through `execute`. This crate stores no copy of `grant_body`. Every earlier
approve still passes `owner approved`. `preview`, `plan_sha256`, `execute`,
`deny_shown_plan`, `age_shown_plan`, `stop_shown_session`,
`read_shown_request`, `read_shown_grants`, `read_shown_requests`,
`running_agent` and `request` are unchanged by this slice. The crate does not
copy the stand-in, and it names no planner. A passing run gives the Runtime no
A15 credit.

A shown deny reason is the settlement record, not the grant. The design keeps
the settlement in the Runtime:

> The UI does not mint the grant itself.

`deny_shown_plan` is the only deny call. It passes the caller and the reason it
is given unchanged, so the route's own shell check and its own store decide the
answer; this helper judges neither. A shell deny of `request-1` with reason
`do not run this` stores that text as `decision_reason` while the request's own
reason stays `show this step`, and the sibling `request-2` with reason
`approved` stays pending. A reason of `granted` stores status `denied` with
`decision_reason` `granted` and mints nothing. The empty reason is stored as
`""`, which is not the route's missing-value default `Denied by user`. A
reason of `approved` on a client caller, on an unknown id and on a request that
is not pending stores nothing and mints nothing, because the client refusal
runs before the body and the settlement refusal runs before the reason is
stored. A denied status body is the status word plus that decision reason:
`{"status":"denied","reason":"do not run this"}`. A deny of a request that is
already granted is `request is not pending: ` plus that id and leaves
`decision_reason` `show this grant` and the live `once` grant, and one use then
spends that grant while `decision_reason` stays `show this grant`.

`shown_deny_reason_is_not_the_grant` drives two sessions through
`running_agent`, submits four requests through `request`, denies and grants
through `deny_shown_plan` and `approve`, reads every request list and status
through `read_shown_requests` and `read_shown_request`, reads every live list
through `read_shown_grants`, and spends through `execute`. This crate stores no
copy of `deny_body`. Every earlier deny still passes `deny the shown plan`.
`preview`, `plan_sha256`, `approve`, `execute`, `age_shown_plan`,
`stop_shown_session`, `read_shown_request`, `read_shown_grants`,
`read_shown_requests`, `running_agent` and `request` are unchanged by this
slice. The crate does not copy the stand-in, and it names no planner. A passing
run gives the Runtime no A15 credit.

A shown stop reason is the settlement record, not the grant. The session
contract states:

> an explicit interrupt or cancel operation that reports its settlement

`stop_shown_session` is the only stop call, and it passes the reason it is
given unchanged as the route's only body key. The stated reason `cancel this
session` is stored as the capsule cause `stopped: cancel this session` and as
the pending step's `decision_reason` with `settled_by` `runtime`, while the
granted step keeps `decision_reason` `show this grant`. The other session's
pending step and its live grant stay. The empty reason is `stop needs a
reason`, which runs before the instance lookup and stores nothing. A later
reason of `granted` on that stopped session is `instance is not live: stopped`
and leaves the first cause. A reason of `granted` on a running session stores
the cause `stopped: granted`, denies that session's pending step with that
cause, revokes its live grant and mints nothing. A use of either stopped
session's once grant is `grant is not live: Revoked`.

`shown_stop_reason_is_not_the_grant` drives two sessions through
`running_agent`, submits four requests through `request`, grants through
`approve`, stops through `stop_shown_session`, reads every request list and
status through `read_shown_requests` and `read_shown_request`, reads every live
list through `read_shown_grants`, reads the capsule list through `get_capsules`
and spends through `execute`. This crate stores no copy of `stop_reason`.
Every earlier stop still passes `stop the shown session`. `preview`,
`plan_sha256`, `approve`, `execute`, `deny_shown_plan`, `age_shown_plan`,
`read_shown_request`, `read_shown_grants`, `read_shown_requests`,
`running_agent` and `request` are unchanged by this slice. The crate does not
copy the stand-in, and it names no planner. A passing run gives the Runtime no
A15 credit.

A shown worker exit is the Runtime's own reap, not the grant. The Harness
conformance section states:

> accept Runtime denial, expiry, revocation, and unknown settlement as
> authoritative outcomes.

`shown_worker_exited` is the only reap call and passes only the session id to
the stand-in's own reap seam. It takes no caller and no reason, and the cause is
the stand-in's fixed cause `worker exited`, not text this crate states. That
cause is stored as the capsule cause `worker exited` and as the pending step's
`decision_reason` with `settled_by` `runtime`, while the granted step keeps
`decision_reason` `show this grant`. The other session's pending step and its
live grant stay. A second reap is `instance is not live: failed` and leaves the
first cause. A later shell stop with reason `granted` is that same refusal and
does not store `stopped: granted`. A later submit on the failed session is
`instance is not live: failed` and stores nothing. A use of either failed
session's once grant is `grant is not live: Revoked`.

`shown_worker_exit_is_not_the_grant` drives two sessions through
`running_agent`, submits four requests through `request`, grants through
`approve`, reaps through `shown_worker_exited`, attempts a stop through
`stop_shown_session`, reads every request list and status through
`read_shown_requests` and `read_shown_request`, reads every live list through
`read_shown_grants`, reads the capsule list through `get_capsules` and spends
through `execute`. This crate stores no copy of `end_instance`. `preview`,
`plan_sha256`, `approve`, `execute`, `deny_shown_plan`, `age_shown_plan`,
`stop_shown_session`, `read_shown_request`, `read_shown_grants`,
`read_shown_requests`, `running_agent` and `request` are unchanged by this
slice. The crate does not copy the stand-in, and it names no planner. A passing
run gives the Runtime no A15 credit.

A shown run pair is a read, not the grant. The request flow states:

> The result returns to the Agent Host and Home without exposing provider
> credentials or broader authority

`read_shown_run` is the only pair read. It passes the caller and the request id
to the stand-in's own pair route unchanged and does not judge either, so that
route's lookup, life check and caller check decide the answer. A pending
request is `unknown grant`, whoever asks. A live pair is `run_id` of `run-` plus
the request id, and `request_id` is that same id; the body carries no plan, no
token, no status and no session. The shell and another session are refused
while the grant is live: the shell gets the expected session alone, and another
session gets the expected session and its own. A second read spends nothing and
mints nothing, so the once grant stays live. `execute` of that once grant then
makes the read `grant is not live: Exhausted` for the owner and for the shell.
A session grant stays readable after one `execute`. A stop revokes that
session's grant, so its read is `grant is not live: Revoked`. The grant answer,
the status body and the live grant omit `run_id`.

`shown_run_pair_is_not_the_grant` drives two sessions through `running_agent`,
submits two requests through `request`, grants through `approve`, reads the pair
through `read_shown_run`, reads the status through `read_shown_request`, reads
every live list through `read_shown_grants`, reads the capsule list through
`get_capsules`, stops through `stop_shown_session` and spends through
`execute`. This crate stores no copy of `run_id_for` or `mint_run_binding`, and
its pair helper holds no `run-` text. `preview`, `plan_sha256`, `approve`,
`execute`, `deny_shown_plan`, `age_shown_plan`, `stop_shown_session`,
`read_shown_request`, `read_shown_grants`, `read_shown_requests`,
`shown_worker_exited`, `read_shown_run`, `running_agent` and `request` are
unchanged by that slice. The crate does not copy the stand-in, and it names no
planner. A passing run gives the Runtime no A15 credit.

A shown use names the minted run pair. The request flow states:

> Runtime dispatches an approved operation to the owning provider and records
> the result in the same audit path used for a human action

`execute` is the only use call. It passes the caller it is given and the body
`request_id` and `plan_sha256` of the plan bytes to the stand-in's own validate
route, and it adds a `run_id` key only when one is given; every earlier call
passes `None`, so its body has no `run_id` key. The helper judges neither the
caller nor the run id text and returns that route's result.

A use with no grant is `unknown grant` even when it presents a run id, and that
refusal spends nothing. The run compare runs before the session check and
before the plan check. A shell that presents the minted pair is `capability
validate needs an instance session`, and the once grant stays live. Another
session that presents a different run id is `effect run ` plus that id plus
` is not bound to request ` plus the request id; another session that presents
the minted pair is `wrong capsule`. The ids `run-other`, `""`, `granted` and
`run-request-2` leave the once grant live. The minted pair with `PLAN_B` is
`grant is not bound to this plan` and leaves that grant live. The minted pair
with `PLAN_A` is `{"valid": true}` and the grant is then `grant is not live:
Exhausted`; a later different run id on that spent grant is `Exhausted`, not the
unminted reason. An omitted run id and then the minted pair each succeed on a
session grant and leave it live. After a stop, a presented run id is `grant is
not live: Revoked`.

`shown_use_names_the_minted_run` drives two sessions through `running_agent`,
submits through `request`, grants through `approve`, reads the pair through
`read_shown_run`, reads the status through `read_shown_request`, reads every
live list through `read_shown_grants`, reads the capsule list through
`get_capsules`, stops through `stop_shown_session` and spends through `execute`.
This crate stores no copy of `run_accepts` or `unminted_run`, and it does not
call `post_hosted_effect`. `preview`, `plan_sha256`, `approve`,
`deny_shown_plan`, `age_shown_plan`, `stop_shown_session`, `read_shown_request`,
`read_shown_grants`, `read_shown_requests`, `shown_worker_exited`,
`read_shown_run`, `running_agent` and `request` are unchanged by this slice. The
crate does not copy the stand-in, and it names no planner. A passing run gives
the Runtime no A15 credit.

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md), Request flow step 3:

> Runtime launches the isolated Agent Host instance with only its initial scoped resources

Step 3 gives the Runtime the launch and its start outcome. `running_agent` is
the only launch: it passes the `Start` it is given to `admit_resident` unchanged
and calls no finish. `shown_finish_start(stand_in, id)` is the only finish call:
it passes the id alone to the stand-in's own `finish_start` and returns that
result. A launched session is `starting` with cause `""` until that finish.

`shown_failed_start_is_not_the_grant` proves the stored start outcome settles
the shown session. A finish of `component-1` before any launch is `unknown
instance: component-1`, not `start already returned`, and stores nothing. The
shell launches `component-1` with `Start::Error("start refused")`; the capsule
is `starting` with cause `""`, which is not `start refused`, and the live list
stays empty. The starting session submits `request-1` (read of `PLAN_A`, reason
`show this step`) and `request-2` (read of `PLAN_B`, reason `approved`); the
owner grants `request-1` once with rationale `show this grant`. The one finish
stores `failed` with cause `start refused`, which is not `stopped: start
refused` and not `worker exited`; it revokes the live once grant and denies
`request-2` with `decision_reason` `start refused` and `settled_by` `runtime`.
`request-1` stays `granted` with `decision_reason` `show this grant`, and its
once use is `grant is not live: Revoked`, not `grant is not live: Exhausted`. A
second finish is `start already returned`, not `instance is not live: failed`,
and leaves the cause and the request rows.

The shell then launches `component-2` with `Start::Ok`; it stays `starting` with
cause `""` until its finish, and `component-1` stays failed. `component-2`
submits `request-3` (write of `PLAN_A`) and the owner grants it for the
session; it submits `request-4` (read of `PLAN_B`, reason `show this step`). The
one finish stores `running` with cause `""` and leaves `request-4` pending. The
shell launches `component-3` with `Start::Trap("start trapped")`, and the owner
grants its `request-5` once; the finish stores cause `start trapped`, denies
`request-6` with that cause, and makes the once use `grant is not live: Revoked`.
The shell launches `component-4` with `Start::Error("granted")`; the finish
denies `request-7` with `decision_reason` `granted` and mints nothing, so its
status is `denied` with reason `granted`, not `{"status":"granted"}`.

A later submit and a later shell stop of the failed `component-1` are each
`instance is not live: failed`; neither stores `stopped: granted`, and the
capsule keeps cause `start refused`. The sibling session's grant for `request-3`
stays live, and its `PLAN_A` use still returns `{"valid": true}`.

This crate stores no copy of `apply_start`: the one start application is the
stand-in's own `finish_start`, reached only through `shown_finish_start`.
`preview`, `plan_sha256`, `approve`, `execute`, `deny_shown_plan`,
`age_shown_plan`, `stop_shown_session`, `read_shown_request`, `read_shown_grants`,
`read_shown_requests`, `shown_worker_exited`, `read_shown_run` and `request` are
unchanged. This crate does not copy the stand-in and it names no planner. A
passing run gives the Runtime no A15 credit.

An ended shown session leaves the shell list at the stand-in's own keep window.
The interaction contract requires:

> visible current state, progress, selected provider and model, and last durable
> event

`get_capsules` is the only list and `age_shown_plan` is the only clock. This
crate stores no keep constant, does not copy `keeps_instance` and adds no
function. `shown_ended_session_leaves_the_list` drives four sessions through
`running_agent`: `component-1` fails its start with cause `start refused`,
`component-2` runs with one granted `session` step (`request-3`) and one pending
step (`request-4`), `component-3` runs and is then stopped with cause
`stopped: stop the shown session`, and `component-4` stays `starting`. Before
any `age_shown_plan`, the shell list holds all four capsules and the live list
holds that one `request-3` entry, which carries no `run_id`.

The test finds the instant with `age_shown_plan` alone and calls no
`set_instant`, so it stores no keep number. Probing up to twenty-four steps, it
doubles the instant while `component-1` is still listed, then walks one instant
at a time to the first instant where `component-1` is absent. One instant
earlier, the failed session and the stopped session are both listed with their
causes, `component-2` stays `running`, `component-4` stays `starting`, and both
pending steps are still `pending`, because the keep instant is earlier than the
request timeout. At that instant the failed session and the stopped session
leave the shell list together, while the running session and the starting
session stay listed. The request records stay: `component-1` keeps its granted
and denied rows, and `component-3` keeps `request-5` granted and `request-6`
denied with the stop cause. The live list still holds that one `request-3`
entry, and the sibling session grant still validates, so `execute` returns
`{"valid": true}` and the entry stays live.

Moving the instant back one step lists the ended sessions again, and a submit
from `component-1` is still status 400 `instance is not live: failed`, not
`unknown instance: component-1`, so it stores nothing and the two rows stay.
The first submit from `component-3` at that instant was `instance is not live:
stopped`. The revoked once grants stay `grant is not live: Revoked`, which is
neither `{"valid": true}` nor `grant is not live: Exhausted`. The test calls no
`watch_ended`, `finish_start`, `delete_capsule`, `worker_exited` or
`seed_request`. `preview`, `plan_sha256`, `approve`, `execute`,
`deny_shown_plan`, `age_shown_plan`, `stop_shown_session`,
`read_shown_request`, `read_shown_grants`, `read_shown_requests`,
`shown_worker_exited`, `read_shown_run`, `shown_finish_start`, `running_agent`
and `request` are unchanged by this slice. This crate does not copy the
stand-in, and it names no planner. A passing run gives the Runtime no A15
credit.

## Layout

- `src/lib.rs`: `Preview`, `preview`, `plan_sha256`, `approve`,
  `age_shown_plan`, `deny_shown_plan`, `stop_shown_session`,
  `shown_worker_exited`, `shown_finish_start`, `read_shown_request`,
  `read_shown_grants`, `read_shown_requests`, `read_shown_run`, `execute`,
  `preview_makes_no_effect`, `plan_sha256_hashes_the_exact_bytes`,
  `deny_one_shown_step`, `unanswered_shown_step_expires`,
  `stop_settles_that_sessions_shown_steps`, `shown_allow_once_expires`,
  `shown_session_lasts_until_stop`, `shown_grant_authorises_only_its_session`,
  `owner_approves_only_the_shown_hash`,
  `agent_cannot_approve_its_own_shown_plan`,
  `agent_cannot_deny_its_own_shown_plan`,
  `shell_cannot_spend_a_shown_grant`, `shell_cannot_submit_a_shown_plan`,
  `only_a_live_session_submits_a_shown_plan`,
  `agent_cannot_stop_a_shown_session`, `agent_cannot_launch_a_shown_session`,
  `shown_request_status_is_not_the_grant`,
  `shown_live_list_is_not_another_sessions_grant`,
  `shown_submit_names_a_declared_ask`,
  `shown_request_list_does_not_submit_again`,
  `shown_request_reason_is_not_the_grant`,
  `shown_grant_rationale_is_not_the_grant`,
  `shown_deny_reason_is_not_the_grant`,
  `shown_stop_reason_is_not_the_grant`,
  `shown_worker_exit_is_not_the_grant`,
  `shown_run_pair_is_not_the_grant`,
  `shown_failed_start_is_not_the_grant`,
  `shown_use_names_the_minted_run`, `shown_ended_session_leaves_the_list`
  and the bound-plan journey.

## Checks

```bash
cargo fmt --manifest-path lab/plan-approval/Cargo.toml -- --check
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_ended_session_leaves_the_list -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_failed_start_is_not_the_grant -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_use_names_the_minted_run -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_run_pair_is_not_the_grant -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_worker_exit_is_not_the_grant -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_stop_reason_is_not_the_grant -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_deny_reason_is_not_the_grant -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_grant_rationale_is_not_the_grant -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_request_reason_is_not_the_grant -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_submit_names_a_declared_ask -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_request_list_does_not_submit_again -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_live_list_is_not_another_sessions_grant -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shown_request_status_is_not_the_grant -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib agent_cannot_launch_a_shown_session -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib agent_cannot_stop_a_shown_session -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib agent_cannot_deny_its_own_shown_plan -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib only_a_live_session_submits_a_shown_plan -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib shell_cannot_submit_a_shown_plan -- --exact
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
