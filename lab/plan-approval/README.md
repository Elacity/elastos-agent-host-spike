# plan-approval lab: preview returns the plan hash and writes nothing

This crate is the preview half of the agent plan approval slice. It follows
[`docs/AGENT_ARCHITECTURE.md`](../../docs/AGENT_ARCHITECTURE.md), Request flow
step 5:

> A proposal carries no authority.

`preview` returns the plan bytes and `agent_conformance::identity::sha256` of
those bytes. It calls no `StandIn` method, takes no path, parses no fixture and
reads no clock, directory or planner. The test reads the stand-in only through
`get_capability_list` and `get_capsules`, so the live grant list and the
capsule list stay as they were.

This crate calls `agent_conformance::standin_runtime` and does not copy it.
There is one stand-in and one hasher. The June planner path is an open question
with Sash via Flint; this crate names no planner and guesses no path.

A passing run gives the Runtime no A15 credit. Approval binding (step 8, where
an allow-once decision authorises one exact operation, and principle 16, "A
visible approval card is not the grant authority") is a later slice; RA-4 and
RA-5 stay open.

## Layout

- `src/lib.rs`: `Preview`, `preview` and `preview_makes_no_effect`.

## Checks

```bash
cargo fmt --manifest-path lab/plan-approval/Cargo.toml -- --check
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib preview_makes_no_effect -- --exact
```

The two plants for this slice are hand-run and recorded in `LOG.md`; this lane
has no `falsifiers.json`.
