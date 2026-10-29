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

`Verifier::ask_capability` is the stand-in entry for a capability ask. The asker is the registered instance principal. A Home principal is refused and does not mint. An app principal stores through the one `bind_grant`. A caller claim is not the principal. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::revoke_grant` removes one handle from the one grant store. That app's next effect is refused and another app's grant stays. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::revoke_grant` also removes every child journal minted from that grant. A grant asked on its own stays. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::revoke_grant` on a child journal removes that journal and leaves the grant it was minted from. A sibling journal minted from that grant stays. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::revoke_grant` on a handle that is not in the store is refused and removes nothing. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::ask_once` stores an allow-once grant through the one `bind_grant`. One successful append or overwrite ends that grant through the one `revoke_grant`. A later effect is refused. `ask_capability` stays reusable. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

The issuing allow-once grant owns the allowance shared by its child journals.
Creating a child preserves that allowance. The first successful append or
overwrite through the parent or any child ends the parent and all of its child
journals. Separately asked grants keep their own lifetimes.

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
- `src/ledger.rs`: the ledger stub (`Ledger::new()`), so later slices fill one
  store instead of a second record.
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
