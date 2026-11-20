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

`Verifier::end_grant` ends that handle and every child journal minted from it. `Verifier::revoke_grant` only calls `end_grant`. The store keeps the records. A journal ended on its own leaves the grant that minted it and leaves a sibling journal. A grant asked on its own stays. Another app's grant stays. This mirrors `end_live_grant`. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::bind_once` and `Verifier::bind_until` store an allow-once grant and an expiry through the one `bind_grant`. One successful append or overwrite ends an allow-once grant through the one `revoke_grant`. The store keeps the record. `resolve` refuses a grant when `verifier_now` is at or after its expiry. An unset expiry is not due. This mirrors `Life::Exhausted` and `is_due`. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::set_effect_limit` stores an effect count limit on that grant, not the A7 per-session ceiling. One successful append or overwrite counts toward it, and an append or overwrite on a child journal minted from that grant counts against the issuing grant. The next effect is refused when the count has reached the limit. The grant stays in the store. An unset limit does not refuse. An append or overwrite while that limit is unset does not count, including a rate-only effect and including an effect on a child journal. A set limit of 0 stops the first effect. A child-journal operate does not count. A derived journal keeps no limit of its own. This mirrors `admit_effect`. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::operate` checks an append or overwrite path with the one `resource_name` against that grant's stored root. A path outside that root is `Refuse::OutsideRoot`. A child journal's append or overwrite uses that journal's root. A child-journal operate does not use this check. The mint already checks its path. A path outside the root does not spend an effect limit and does not end an allow-once grant. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::set_rate` stores a rate and a window on that grant. One successful append or overwrite counts toward that rate through the one `note_effect`. The next append or overwrite is refused when the count has reached the rate inside the window, and the grant stays in the store. A verifier instant at or after the window end starts a new count on the issuing grant, including when the effect is on a child journal. An unset rate does not refuse. A set rate of 0 stops the first effect. A child-journal operate does not count. A path outside the stored root does not count. `Verifier::set_rate` on a derived journal is refused, and an ended handle, a revoked journal included, is `Refuse::UnknownHandle` before that derived-journal refusal, so it stores no rate. A derived journal keeps no rate of its own. This mirrors `is_due`. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::bind_for_session` stores an allow-for-this-session grant through the one `bind_grant`. `Verifier::host_set_session` ends those grants of that instance through the one `revoke_grant` when the session string changes. The store keeps the record. A child journal minted from that grant ends with it. Another instance's allow-for-this-session grant stays. Setting the same session string ends nothing. A standing grant stays, and restoring the old session makes that standing grant usable again. This mirrors `revoke_live`. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`resolve` reads the issuing grant's expiry for a derived journal through the one expiry check. The child keeps no expiry of its own. A `use_grant` or `use_path` of that journal is refused when `verifier_now` is at or after the issuing expiry. An unset issuing expiry is not due. A standing grant with no expiry leaves its child usable. This mirrors `is_due`. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::operate` on a derived journal ends an allow-once issuing grant through the one `revoke_grant`. The journals minted from that grant end with it. The store keeps the record. A direct append or overwrite on that grant ends it through the same call. A child-journal mint does not end the grant. A refused effect does not end the grant. A standing grant stays. This mirrors `Life::Exhausted`. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`resolve_for_hold` closes a hold after `resolve` would refuse the grant as expired. The live binding is the one `resolve_live`. The expiry walk stays in `resolve`. A new reserve, a new effect, and `use_grant` stay `Refuse::Expired`. The store keeps the record. A hold opened on a derived journal follows the issuing expiry the same way. Settle, release, and timeout still run, and the ceiling room returns when the hold closes. This mirrors `is_due`. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::live_journal_overlap` is the one overlap rule against the live journals a grant minted: a path on a journal root, under it, or around it. The child-journal mint refuses a path on a live sibling as `JournalSame` and any other overlap as `JournalCover`. `Verifier::operate` and `Verifier::use_path` refuse any overlap as `JournalHeld`, except that the issuing root itself stays allowed. A journal refusal spends no rate. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`open_rate_window` rolls a window of 0 through the one elapsed-time compare. The instant that stored the window has no elapsed time, so the window of 0 is already at its end and the next append or overwrite starts a new count, including when the effect is on a child journal. A set rate of 0 still stops the first effect. A window above 0 still rolls only at that same compare, which reads the elapsed time rather than a sum, so a window that starts at the largest instant still stops the next effect. This mirrors `is_due`. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::create_child_journal` refuses a path equal to the issuing grant's own root. The one `resource_name` still allows an append or overwrite on that root. A path under the root still mints. A refused mint stores no grant, and the next ask is an issuing grant. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::create_child_journal` refuses a path equal to a live journal minted from that same grant. An ended journal frees that path. A path beside a live journal still mints. Another issuing grant still mints that path. A refused mint stores no grant. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::create_child_journal` refuses a path that sits inside a live journal minted from that same grant, and a path that contains one. The check calls the one `resource_name`. An ended journal frees that path. A path that only shares a string prefix still mints. Another issuing grant still mints a path inside that journal. A refused mint stores no grant. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::operate` refuses an append or overwrite on the issuing grant when that path sits inside a live journal minted from that grant, or is that journal's path. The check calls the one `resource_name` and follows the owned-root check. A refused path spends no rate and no effect count, and it does not end an allow-once grant. An effect on the issuing root stays allowed. A path beside that journal stays allowed. A path that only shares a string prefix stays allowed. The journal's own append or overwrite stays allowed. An ended journal frees that path. Another issuing grant still effects a path inside that journal. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::use_path` refuses a path a live journal minted from that grant holds, including that journal's own path. The check is the one `live_journal_holds` that `Verifier::operate` calls. A use of the issuing root stays allowed. A path beside that journal stays allowed. A path that only shares a string prefix stays allowed. The journal's own use stays allowed. An ended journal frees that path. Another issuing grant still uses a path inside that journal. A refused use spends nothing and does not end an allow-once grant. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::operate` and `Verifier::use_path` refuse a path that contains a live journal minted from that grant, unless that path is the issuing root. The check is the same `live_journal_holds`. An effect or a use of the issuing root stays allowed. A path beside that journal stays allowed. A path that only shares a string prefix stays allowed. The journal's own append, overwrite, and use stay allowed. An ended journal frees that path. Another issuing grant still effects and uses that path. A refused effect spends no rate and no effect count, and it does not end an allow-once grant. A refused use spends nothing and does not end an allow-once grant. This is a lab stand-in. It is not the Runtime. It does not count toward an M1 check.

`Verifier::admit_ask` caps one agent's budget ask and records the granted amount as the ceiling of the grant the ask was admitted for. An ask on a child journal records the issuing grant's ceiling. Two grants of one identity keep separate ceilings, so each instance admitted with its own grant keeps its own allowance. `Verifier::reserve` compares the open holds of that grant, including a hold on a child journal minted from it, and refuses a grant with no stored ceiling as `ReserveRefuse::NoCeiling` ("grant has no ceiling"). `Verifier::admit` sets no grant's ceiling: it lowers every stored grant ceiling above its figure and leaves a grant with no ceiling without one. This is a lab stand-in for that admission. It is not the Runtime. It does not count toward A7 or M1-R.

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
