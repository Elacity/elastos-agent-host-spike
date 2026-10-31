# grant-binding lab: one verifier stand-in for grant binding

This crate is the pure-Rust reference model for Bus v2 grade point A5 and for
Rong's GB-1 and GB-2. One `Verifier` owns the instance registry, the grant store
and the ledger. The host registers an instance with its identity and session,
binds a `UsersAI/<agent>/...` owned root and the append, overwrite and
child-journal rights to an opaque `Handle`, and gives the guest only that
handle. The guest may carry claims; `use_grant` reads the handle and nothing
else. The stored binding and the registry record for the call's instance decide
every use.

reference model, not the Runtime; counts toward no M1 check; the Runtime half is Anders's (#464, #463, #181)

`Verifier::bind_grant` is the stand-in entry for a capability ask, and the stand-in's `seed_bound_grant` calls it too. The asker is the registered instance principal. A Home principal is refused and does not mint. An app principal stores the binding. A caller claim is not the principal and no caller names the asker. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::revoke_grant` ends one handle through the one `end_grant`. The store keeps the record. Another app's grant stays. The next effect on an ended handle is `Refuse::UnknownHandle`. This mirrors `end_live_grant`. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::revoke_grant` also ends every child journal minted from that grant, through the same `end_grant`. The store keeps those records. A journal revoked on its own leaves the grant that minted it. A grant asked on its own stays. This mirrors `end_live_grant`. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::admit_ask` caps one agent's budget ask and stores the granted amount through the one `admit`. This is a lab stand-in for that admission. It is not the Runtime. It does not count toward A7 or M1-R.

A forged identity, session, instance, usage, ceiling or set of rights changes
nothing. A host call whose identity, session or instance differs from the
stored binding is refused with a typed reason, and an unknown handle is refused
with its own. The one name check accepts `UsersAI/<agent>/<rest>` under the
bound agent with at least one further plain segment. It refuses a host-shaped
path and a root under another agent.

This crate is the one home for the later A7 and B2 slices. It adds no second
verifier, no second name parser and no second plant runner.

## Layout

- `src/lib.rs`: the verifier, the registry, the grant store and the decisions.
- `src/ledger.rs`: the ledger (`Ledger::new()`), one store for holds, ceilings
  and ended bindings.
- `src/ops.rs`: operation checks; this stub holds none yet.
- `src/link.rs`: the one detector for a path dependency on this crate.
- `src/plant.rs`: the plant grammar and the one falsifier runner.
- `plants/`: one planted bug per file; `model_planted_bugs_are_caught` proves
  every named test fails for each plant.

## Checks

```bash
cargo fmt --manifest-path lab/grant-binding/Cargo.toml -- --check
cargo test --locked --offline --manifest-path lab/grant-binding/Cargo.toml
```
