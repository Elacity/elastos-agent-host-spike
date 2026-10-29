# plan-approval lab: the preview hash, and the shell grant that binds it

This crate is the plan approval half of the agent plan slice. It follows
[`docs/AGENT_ARCHITECTURE.md`](../../docs/AGENT_ARCHITECTURE.md), Request flow
step 8:

> If additional consent is required, Runtime records a pending request and
> Home or Inbox presents it. The UI does not mint the grant itself.

And the Delegation and mandates section:

> **Allow once** authorizes one exact operation.

And the non-negotiable boundaries:

> A visible approval card is not the grant authority.

`preview` is unchanged: it returns the plan bytes and
`agent_conformance::identity::sha256` of those bytes, and it calls no `StandIn`
method. A proposal carries no authority. A hand-run plant that makes `preview`
call `authorise` on the seeded `req-preview` grant is caught: `authorise` spends
the seeded once grant, stores `Exhausted`, the live list drops it, and
`preview_makes_no_effect` fails.

`submit_shown_plan` recomputes the hash, refuses a hash that does not name the
bytes, refuses a step the bytes do not contain, and then only calls
`seed_request` with the preview hash as the request `reason`.

`grant_shown_plan` only calls `post_capability_grant` as the shell, with the
duration `once`. It takes no approved flag.

`perform_shown_plan` ignores `approved` and reads the request through
`get_capability_requests`. It calls `authorise` only when the recomputed hash
matches that request's `reason`, so a later byte change is refused. A `once`
grant stores `Exhausted`, so a second perform is refused.

This crate calls `agent_conformance::standin_runtime` and does not copy it.
There is one stand-in and one hasher. The June planner path is an open question
with Sash via Flint; this crate names no planner and guesses no path.

A passing run gives the Runtime no A15 credit. RA-4 and RA-5 stay open.

## Layout

- `src/lib.rs`: `Preview`, `preview`, `preview_makes_no_effect`,
  `submit_shown_plan`, `grant_shown_plan`, `perform_shown_plan` and
  `approval_binds_to_the_previewed_plan_hash`.

## Checks

```bash
cargo fmt --manifest-path lab/plan-approval/Cargo.toml -- --check
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib approval_binds_to_the_previewed_plan_hash -- --exact
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib preview_makes_no_effect -- --exact
```

The plants for this slice are hand-run and recorded in `LOG.md`; this lane has
no `falsifiers.json`.
