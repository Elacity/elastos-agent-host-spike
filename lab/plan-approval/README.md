# plan-approval lab: preview, approve, deny or leave a shown step pending

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

`preview`, `plan_sha256`, `approve`, `execute` and `deny_shown_plan` are
unchanged by this slice. This crate calls `agent_conformance::standin_runtime`
and does not copy it. There is one stand-in and one hasher. The June planner
path is an open question with Sash via Flint; this crate names no planner and
guesses no path.

A passing run gives the Runtime no A15 credit. Approval binding (step 8, where
an allow-once decision authorises one exact operation, and principle 16, "A
visible approval card is not the grant authority") is a later slice; RA-4 and
RA-5 stay open.

## Layout

- `src/lib.rs`: `Preview`, `preview`, `plan_sha256`, `approve`,
  `age_shown_plan`, `deny_shown_plan`, `execute`, `preview_makes_no_effect`,
  `plan_sha256_hashes_the_exact_bytes`, `deny_one_shown_step`,
  `unanswered_shown_step_expires` and the bound-plan journey.

## Checks

```bash
cargo fmt --manifest-path lab/plan-approval/Cargo.toml -- --check
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib unanswered_shown_step_expires -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib deny_one_shown_step -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib preview_makes_no_effect -- --exact
```

The hand-run plants are recorded in `LOG.md`; this lane has no
`falsifiers.json`.
