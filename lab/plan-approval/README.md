# plan-approval lab: preview and plan-bound approval

This crate models preview, owner approval and execution against the agent
conformance stand-in (M1 check A15a). It follows
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

`approve` sends the plan hash shown to the owner through the stand-in's
owner-only grant route. `execute` sends the hash of the exact plan bytes to the
stand-in's validate route. A grant for plan B refuses plan A and spends nothing;
an approved allow-once grant spends on its matching plan. The binding test
proves this stand-in behavior and its falsifier removes the binding compare.
The Runtime earns no A15 credit from this lab result. RA-4 and RA-5 remain open.

## Layout

- `src/lib.rs`: `Preview`, `preview`, `plan_sha256`, `approve`, `execute` and their journey tests.
- `falsifiers.json`: the binding-compare plant and its named failing test.

## Checks

From `lab/plan-approval`, run:

```bash
cargo fmt -- --check
cargo test --locked
python3 -I falsify.py
```

The two preview plants were hand-run and recorded in `LOG.md`. The binding
plant runs from this lane's falsifier list and restores the source after its
named test fails.
