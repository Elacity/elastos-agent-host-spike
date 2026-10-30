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

`Verifier::bind_grant` is the stand-in entry for a capability ask. The asker is the registered instance principal. A Home principal is refused and does not mint. An app principal stores the binding. A caller claim is not the principal and no caller names the asker. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::bind_once` and `Verifier::bind_until` store an allow-once grant and an expiry through the one `bind_grant`. One successful append or overwrite removes an allow-once grant. `resolve` refuses a grant when `verifier_now` is at or after its expiry. An unset expiry is not due. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::set_effect_limit` stores an effect limit on that grant. One successful append or overwrite counts toward that limit. The next append or overwrite is refused when the count has reached it, and the grant stays in the store. An unset limit does not refuse. A child-journal operate does not count. This mirrors the stand-in ceiling in `model_admitted_ask_sets_the_ceiling`. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::set_effect_limit` on a derived child journal is refused. An append or overwrite on that journal counts against the issuing grant's effect limit. The child keeps no limit of its own. This is the same one counter `model_second_agent_does_not_raise_the_ceiling` keeps for one identity. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::revoke_grant` removes that handle from the one grant store and every child journal minted from it. A grant asked on its own stays. The next effect on a removed handle is `Refuse::UnknownHandle`. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::set_rate` stores a rate and a window on that grant. One successful append or overwrite counts toward that rate through the one `note_effect`. The next append or overwrite is refused when the count has reached the rate inside the window, and the grant stays in the store. A verifier instant at or after the window end starts a new count. An unset rate does not refuse. A set rate of 0 stops the first effect. A child-journal operate does not count. `Verifier::set_rate` on a derived child journal is refused. This mirrors `model_early_timeout_is_refused`: the verifier clock decides. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::bind_for_session` stores an allow-for-this-session grant through the one `bind_grant`. `Verifier::host_set_session` removes those grants through the one `revoke_grant` when the session string changes. A child journal minted from that grant is removed with it. Setting the same session string removes nothing. A standing grant stays, and restoring the old session makes that standing grant usable again. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`resolve` reads the issuing grant's expiry for a derived journal. The child keeps no expiry of its own. A use of that journal is refused when `verifier_now` is at or after the issuing expiry. An unset issuing expiry is not due. This is the same one expiry check `model_expired_grant_is_refused` already uses. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::operate` on a derived journal ends an allow-once issuing grant through the one `revoke_grant`. The journals minted from that grant end with it. A direct append or overwrite on the issuing grant still removes only that handle. A child-journal mint does not end the grant. A standing grant stays. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::admit_ask` caps one agent's budget ask and stores the granted amount through the one `admit`. This is a lab stand-in for that admission. It is not the Runtime. It does not count toward A7 or M1-R.

`Verifier::admit_ask` stores that grant's allowance on the one ledger. `Verifier::settle` adds the charged figure to that same grant. `Verifier::reserve` refuses a hold past the unspent remainder. A release does not charge the allowance. Another grant keeps its own remainder. This mirrors `Life::Exhausted`. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

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
