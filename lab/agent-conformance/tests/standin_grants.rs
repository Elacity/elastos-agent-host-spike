//! M1 check A6: each agent's grant is its own.
//!
//! Two agent bundles launch as two residents through `post_capsules` and
//! `finish_start`. Each asks for one capability through
//! `post_capability_request` and receives its own grant through
//! `post_capability_grant`; the grant route mints the pair `(run_id,
//! request_id)` that a hosted effect presents. The journey presents agent A's
//! pair as agent B: the stand-in refuses it with the one reason that names
//! both sessions, agent A's grant stays listed live, and only agent A's own
//! use spends it. A pair the route never minted is refused the same way.
//!
//! Every call enters through a stand-in route; no grant, run pair or request
//! id comes from a literal.

#[path = "common/signed_bundle.rs"]
mod signed_bundle;

use agent_conformance::standin_runtime::{Caller, Life, StandIn, Start};
use serde_json::{json, Value};
use signed_bundle::SignedBundle;

const ASK_RESOURCE: &str = "localhost://Public/resident-instances/shared.txt";
/// The one shell live-grant scope `get_capability_list` accepts
/// (`standin-runtime/mod.rs:57`).
const SHELL_LIVE_SCOPE: &str = "all_sessions_live";
/// The offer and effect every hosted effect presents.
const OFFER: &str = "offer:journey";
const EFFECT: &str = "read";

/// The pair a hosted effect presents, as its own session read it back.
struct MintedRun {
    run_id: String,
    request_id: String,
}

/// Launches one admitted bundle through `post_capsules` and applies
/// `Start::Ok` through `finish_start`. Returns the instance id the launch
/// answered with, so no test assumes one.
fn launch(standin: &mut StandIn, bundle: &SignedBundle) -> String {
    let launched = standin
        .post_capsules(Caller::Shell, &bundle.launch_body())
        .expect("the stand-in launches the admitted CID");
    let id = launched["id"]
        .as_str()
        .expect("the launch answer names the instance")
        .to_owned();
    standin
        .finish_start(&id)
        .expect("the stand-in applies Start::Ok");
    id
}

/// One resident asks for `ASK_RESOURCE`, the shell grants it, and the grant's
/// own session reads the minted pair back from the route answer.
fn own_grant(standin: &mut StandIn, session: &str) -> MintedRun {
    own_grant_of(standin, session, "once")
}

/// The same, for a grant of the named duration.
fn own_grant_of(standin: &mut StandIn, session: &str, duration: &str) -> MintedRun {
    let owner = Caller::Client {
        session_id: session,
    };
    standin
        .post_capability_request(
            owner,
            &json!({ "resource": ASK_RESOURCE, "action": "read", "reason": "journey" }),
        )
        .expect("the resident stores its one request");
    let listed = standin
        .get_capability_requests(Caller::Shell, Some(session))
        .expect("the stand-in lists the session's requests");
    let pending = listed["requests"]
        .as_array()
        .expect("the request list is an array")
        .iter()
        .filter(|request| request["status"] == json!("pending"))
        .map(|request| {
            request["request_id"]
                .as_str()
                .expect("the request names its id")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        pending.len(),
        1,
        "{session} holds exactly one pending request"
    );
    let request_id = pending[0].to_string();
    // The grant route's answer stays exactly `{"success": true}`, so the
    // agent reads the pair back from its own grant read route.
    assert_eq!(
        standin
            .post_capability_grant(
                Caller::Shell,
                &json!({ "request_id": request_id, "duration": duration, "rationale": "journey" }),
            )
            .expect("the shell grants the resident's request"),
        json!({ "success": true }),
        "the grant route answers success and no token"
    );
    let bound = standin
        .get_run_binding(owner, &request_id)
        .expect("the grant's own session reads back the pair the grant route minted");
    assert_eq!(bound["request_id"], json!(request_id));
    let run_id = bound["run_id"]
        .as_str()
        .expect("the read returns the run id the grant route minted")
        .to_owned();
    assert_ne!(
        run_id, request_id,
        "the minted run id is the route's own value, not the request id the agent chose"
    );
    MintedRun { run_id, request_id }
}

/// One hosted effect with no ask, so its amount is the route's default.
fn present(
    standin: &mut StandIn,
    session: &str,
    run_id: &str,
    request_id: &str,
) -> Result<Value, (u16, String)> {
    present_ask(standin, session, run_id, request_id, &json!({}))
}

/// One hosted effect whose body names `body`, the ask.
fn present_ask(
    standin: &mut StandIn,
    session: &str,
    run_id: &str,
    request_id: &str,
    body: &Value,
) -> Result<Value, (u16, String)> {
    standin.post_hosted_effect(
        Caller::Client {
            session_id: session,
        },
        OFFER,
        EFFECT,
        run_id,
        request_id,
        body,
    )
}

/// True when the shell live view lists one grant for `request_id`.
fn listed_live(standin: &StandIn, request_id: &str) -> bool {
    let view = standin
        .get_capability_list(Caller::Shell, Some(SHELL_LIVE_SCOPE))
        .expect("the stand-in lists the shell's live grants");
    view["capabilities"]
        .as_array()
        .expect("the live view lists capabilities")
        .iter()
        .any(|entry| entry["request_id"] == json!(request_id))
}

/// Admits one signed agent bundle through `admit_resident`. The bundle stays
/// alive: `post_capsules` walks its bytes on disk.
fn admit(standin: &mut StandIn, bundle: &SignedBundle) {
    standin
        .admit_resident(
            bundle.path(),
            &bundle.signature(),
            bundle.accepted(),
            Start::Ok,
        )
        .expect("the stand-in admits the signed agent bundle");
}

#[test]
fn an_agent_cannot_present_another_agents_grant_pair() {
    let mut standin = StandIn::new();
    let bundles = [
        SignedBundle::distinct("agent-a"),
        SignedBundle::distinct("agent-b"),
    ];
    for bundle in &bundles {
        admit(&mut standin, bundle);
    }
    let agent_a = launch(&mut standin, &bundles[0]);
    let agent_b = launch(&mut standin, &bundles[1]);
    assert_ne!(
        agent_a, agent_b,
        "the two agents are two resident instances"
    );
    let victim = own_grant(&mut standin, &agent_a);
    // A seeded grant stores no run pair, so an empty presented run id must
    // find it and still be refused, live afterwards. The id is a journey
    // literal because no route seeds one.
    standin.seed_grant(
        "request-seeded",
        &agent_a,
        ASK_RESOURCE,
        "read",
        "once",
        0,
        Life::Live,
        false,
    );
    let refused = (
        403u16,
        format!("wrong capsule: expected {agent_a}, got {agent_b}"),
    );
    let reason = |run_id: &str, request_id: &str| {
        (
            403u16,
            format!("effect run {run_id} is not bound to request {request_id}"),
        )
    };

    // A pair the route never minted is refused with the one pair reason, and
    // agent A's grant stays live. Its request id still exists and is live, so
    // only the run half can refuse.
    assert_eq!(
        present(
            &mut standin,
            &agent_a,
            "run-never-minted",
            &victim.request_id
        ),
        Err(reason("run-never-minted", &victim.request_id)),
        "an unminted run id is refused with the one pair reason"
    );
    assert!(
        listed_live(&standin, &victim.request_id),
        "an unminted pair spends nothing"
    );

    // An empty presented run id is a pair nothing minted, even for the grant's
    // own session: the stand-in refuses it and spends nothing (a seeded grant
    // stores an empty run id, so no presented pair reaches it).
    assert_eq!(
        present(&mut standin, &agent_a, "", &victim.request_id),
        Err(reason("", &victim.request_id)),
        "an empty presented run id is refused with the one pair reason"
    );
    assert!(
        listed_live(&standin, &victim.request_id),
        "an empty pair leaves agent A's grant live and unspent"
    );
    assert_eq!(
        present(&mut standin, &agent_a, "", "request-seeded"),
        Err(reason("", "request-seeded")),
        "a seeded grant is refused an empty pair with the one pair reason"
    );
    assert!(
        listed_live(&standin, "request-seeded"),
        "the seeded grant stays live and unspent"
    );

    // Agent B cannot read agent A's pair, and cannot present it.
    assert_eq!(
        standin.get_run_binding(
            Caller::Client {
                session_id: &agent_b
            },
            &victim.request_id
        ),
        Err(refused.clone()),
        "agent B reads no pair it does not own"
    );
    assert_eq!(
        present(&mut standin, &agent_b, &victim.run_id, &victim.request_id),
        Err(refused),
        "agent B's presentation of agent A's pair is refused, naming both sessions"
    );
    assert!(
        listed_live(&standin, &victim.request_id),
        "agent A's grant {} stays live after agent B's refusal",
        victim.request_id
    );

    // The refusal spent nothing: agent A's own pair still works, and that one
    // use is what spends the `once` grant.
    assert_eq!(
        present(&mut standin, &agent_a, &victim.run_id, &victim.request_id),
        Ok(json!({ "valid": true })),
        "agent A's own pair still authorises the effect after agent B's refusal"
    );
    assert!(
        !listed_live(&standin, &victim.request_id),
        "agent A's own use spends its once grant"
    );
    assert_eq!(
        standin
            .get_capability_requests(Caller::Shell, Some(&agent_b))
            .expect("the stand-in lists agent B's requests"),
        json!({ "requests": [] }),
        "agent B made no request and gained no grant"
    );
}

/// M1 check A6: a grant the lab seam binds is admitted; a plain seeded grant is
/// not.
///
/// Both agents are admitted and launched through `admit_resident`,
/// `post_capsules` and `finish_start`. Agent A's grant is stored through
/// `seed_bound_grant`, which runs the grant route's own `bind_on_ledger` step,
/// so A's hosted effect through `post_hosted_effect` is admitted and spends
/// the `once` grant. Agent B's grant is a plain `seed_grant`, which stores no
/// ledger handle and no run pair, so B's effect is refused status 403 with the
/// route's pair reason before any admission, and B's grant stays live and
/// unspent. Removing only the bind in `seed_bound_grant` turns this test red at
/// the bound agent's admission line.
#[test]
fn a_bound_seeded_grant_is_admitted_at_a_hosted_use_and_an_unbound_one_is_refused() {
    let mut standin = StandIn::new();
    let bundles = [
        SignedBundle::distinct("agent-bound"),
        SignedBundle::distinct("agent-unbound"),
    ];
    for bundle in &bundles {
        admit(&mut standin, bundle);
    }
    let bound = launch(&mut standin, &bundles[0]);
    let unbound = launch(&mut standin, &bundles[1]);
    standin
        .seed_bound_grant(
            "request-seeded-bound",
            &bound,
            ASK_RESOURCE,
            "read",
            "once",
            1_800_000_000,
            Life::Live,
            false,
        )
        .expect("the bound seam binds on the ledger");
    standin.seed_grant(
        "request-seeded-unbound",
        &unbound,
        ASK_RESOURCE,
        "read",
        "once",
        1_800_000_000,
        Life::Live,
        false,
    );
    let pair = standin
        .get_run_binding(
            Caller::Client { session_id: &bound },
            "request-seeded-bound",
        )
        .expect("the bound grant's own session reads the minted pair");
    let run_id = pair["run_id"]
        .as_str()
        .expect("the read returns the run id the bind minted")
        .to_owned();
    assert_eq!(pair["request_id"], json!("request-seeded-bound"));

    assert_eq!(
        present(&mut standin, &bound, &run_id, "request-seeded-bound"),
        Ok(json!({ "valid": true })),
        "the hosted effect admits the pair of the grant the seam bound"
    );
    assert!(
        !listed_live(&standin, "request-seeded-bound"),
        "the admitted hosted effect spends the bound once grant"
    );

    // The plain seed stores no ledger handle. `admit_effect` refuses that
    // before any ledger call with the `unknown handle` text; a hosted effect
    // presents a run id, so the route's pair check answers first with its own
    // reason.
    assert_eq!(
        present(&mut standin, &unbound, "", "request-seeded-unbound"),
        Err((
            403,
            "effect run  is not bound to request request-seeded-unbound".to_owned()
        )),
        "the hosted effect refuses the grant the plain seed left unbound"
    );
    assert!(
        listed_live(&standin, "request-seeded-unbound"),
        "the refused use leaves the unbound grant live and unspent"
    );
}

/// M1 check A7: a hosted effect is one use, so the same budget cap refuses it.
///
/// The journey enters only through `admit_resident` for setup, `post_capsules`,
/// `finish_start`, `post_capability_request`, `post_capability_grant`,
/// `get_run_binding` and `post_hosted_effect`. Both grants are route-minted
/// and bound, so the grant's life, pair and ledger binding all pass and the
/// admission is the one check that can refuse. The ask one above the cap is
/// refused on `over`, which stays live and unspent; the ask at the cap is
/// admitted on `at_cap`, which then spends.
#[test]
fn a_hosted_effect_above_the_budget_cap_is_refused_on_the_granted_pair() {
    let mut standin = StandIn::new();
    let bundle = SignedBundle::distinct("agent-budget");
    admit(&mut standin, &bundle);
    let session = launch(&mut standin, &bundle);
    let over = own_grant(&mut standin, &session);
    let at_cap = own_grant(&mut standin, &session);

    // One above the cap: refused by the admission, with its one text.
    assert_eq!(
        present_ask(
            &mut standin,
            &session,
            &over.run_id,
            &over.request_id,
            &json!({ "amount": 4097 }),
        ),
        Err((
            403u16,
            "budget ask exceeds the admission cap: asked 4097, cap 4096".to_owned()
        )),
        "the hosted effect refuses an ask one above the cap on its granted pair"
    );
    assert!(
        listed_live(&standin, &over.request_id),
        "the refused hosted effect leaves that grant live and unspent"
    );

    // At the cap on a second granted pair: admitted, and that use spends the
    // once grant.
    assert_eq!(
        present_ask(
            &mut standin,
            &session,
            &at_cap.run_id,
            &at_cap.request_id,
            &json!({ "amount": 4096 }),
        ),
        Ok(json!({ "valid": true })),
        "the hosted effect admits an ask at the cap"
    );
    assert!(
        !listed_live(&standin, &at_cap.request_id),
        "the admitted hosted effect spends the once grant"
    );

    // A second resident on its own identity admits the cap on its own grant,
    // because each identity's ceiling is its own.
    let other = SignedBundle::distinct("agent-budget-b");
    admit(&mut standin, &other);
    let other_session = launch(&mut standin, &other);
    let own = own_grant(&mut standin, &other_session);
    assert_eq!(
        present_ask(
            &mut standin,
            &other_session,
            &own.run_id,
            &own.request_id,
            &json!({ "amount": 4096 }),
        ),
        Ok(json!({ "valid": true })),
        "a second identity admits the cap on its own grant"
    );

    // A malformed ask is status 400 with the validate route's own text, before
    // the grant is read, so `over` stays live and unspent.
    assert_eq!(
        present_ask(
            &mut standin,
            &session,
            &over.run_id,
            &over.request_id,
            &json!({ "amount": "4097" }),
        ),
        Err((
            400u16,
            "budget ask needs a non-negative integer amount".to_owned()
        )),
        "a hosted effect reads the amount with the validate route's one rule"
    );
    assert!(
        listed_live(&standin, &over.request_id),
        "the malformed ask leaves the grant live and unspent"
    );
}

/// M1 check A7: a grant with no ledger binding is refused at use.
///
/// A seeded grant is the one grant no ledger bind reaches. It exists, it is
/// live and it is authored by its own session, so the binding is the only
/// check that can refuse. The ask is within the cap and the run id is the
/// grant's own, so the pair check passes too.
#[test]
fn an_unbound_grant_is_refused_at_use_and_spends_nothing() {
    let mut standin = StandIn::new();
    let bundle = SignedBundle::distinct("agent-unbound");
    admit(&mut standin, &bundle);
    let session = launch(&mut standin, &bundle);
    standin.seed_grant(
        "request-unbound",
        &session,
        ASK_RESOURCE,
        "read",
        "once",
        0,
        Life::Live,
        false,
    );
    let refused = (403u16, "unknown handle".to_owned());
    let reason = (
        403u16,
        "effect run  is not bound to request request-unbound".to_owned(),
    );

    // Its stored run id is empty, which the pair check refuses first.
    assert_eq!(
        present(&mut standin, &session, "", "request-unbound"),
        Err(reason),
        "the seeded grant stores no run pair"
    );

    // The one bind site is the grant route, so the seeded grant has no handle
    // and the admission refuses it before any spend.
    assert_eq!(
        standin.post_capability_validate(
            Caller::Client {
                session_id: &session
            },
            &json!({ "request_id": "request-unbound", "amount": 1 }),
        ),
        Err(refused),
        "an ask within the cap on an unbound grant is refused with the ledger's text"
    );
    assert!(
        listed_live(&standin, "request-unbound"),
        "the unbound refusal leaves the grant live and unspent"
    );
}

/// M1 check A7 condition (c): a stop ends the ledger binding of each grant it
/// revokes, and the use path still refuses the stopped grant.
///
/// The journey enters through `admit_resident`, `post_capsules`,
/// `finish_start`, `post_capability_request`, `post_capability_grant`,
/// `get_run_binding` and `delete_capsule`. `authorise` refuses the revoked
/// grant before the admission runs, so this route asserts the use refusal and
/// the unspent grant; `model_end_grant_refuses_the_ended_handle` pins the
/// ledger half directly.
#[test]
fn a_stop_ends_the_ledger_binding_of_its_revoked_grant() {
    let mut standin = StandIn::new();
    let bundle = SignedBundle::distinct("agent-stop");
    admit(&mut standin, &bundle);
    let session = launch(&mut standin, &bundle);
    let victim = own_grant(&mut standin, &session);

    assert_eq!(
        standin.delete_capsule(Caller::Shell, &session, &json!({ "reason": "done" })),
        Ok(Value::Null),
        "the shell stops the resident"
    );
    assert!(
        !listed_live(&standin, &victim.request_id),
        "the stop revokes the grant"
    );

    assert_eq!(
        standin.post_capability_validate(
            Caller::Client {
                session_id: &session
            },
            &json!({ "request_id": victim.request_id, "amount": 1 }),
        ),
        Err((400u16, "grant is not live: Revoked".to_owned())),
        "the stopped grant no longer authorises a use"
    );
    assert!(
        !listed_live(&standin, &victim.request_id),
        "the refused use spends nothing after the stop"
    );
}

/// The allowance is a held budget per grant, on the use routes.
///
/// On A's `session` grant, 4096 is admitted and holds the ceiling; 4096 and 1
/// on that same grant are then 403 with the ledger's own text and the grant
/// stays live. Session B admits 4096 on its own ceiling. On C's grant two asks
/// of 2048 are both admitted, so the budget is held, not spent by one use.
#[test]
fn a_session_grants_allowance_is_held_across_its_uses() {
    let mut standin = StandIn::new();
    let names = ["a", "b", "c"].map(|n| SignedBundle::distinct(&format!("agent-allowance-{n}")));
    for bundle in &names {
        admit(&mut standin, bundle);
    }
    let [agent_a, agent_b, agent_c] = names.each_ref().map(|b| launch(&mut standin, b));
    let a = own_grant_of(&mut standin, &agent_a, "session");
    let b = own_grant_of(&mut standin, &agent_b, "session");
    let held = Err((403u16, "reservation exceeds the ceiling".to_owned()));
    let use_grant = |standin: &mut StandIn, session: &str, grant: &MintedRun, amount: Value| {
        standin.post_capability_validate(
            Caller::Client {
                session_id: session,
            },
            &json!({ "request_id": grant.request_id, "amount": amount }),
        )
    };

    assert_eq!(
        use_grant(&mut standin, &agent_a, &a, json!(4096)),
        Ok(json!({ "valid": true })),
        "the first ask at the cap is admitted and holds the ceiling"
    );
    for amount in [4096, 1] {
        assert_eq!(
            use_grant(&mut standin, &agent_a, &a, json!(amount)),
            held,
            "the ask of {amount} is refused on the same grant"
        );
        assert!(
            listed_live(&standin, &a.request_id),
            "the refused ask leaves the grant live and unspent"
        );
    }
    assert_eq!(
        use_grant(&mut standin, &agent_b, &b, json!(4096)),
        Ok(json!({ "valid": true })),
        "a separate session has its own ceiling and admits the cap"
    );
    let c = own_grant_of(&mut standin, &agent_c, "session");
    // The first ask of 2048 fits C's whole budget, and the second fits its
    // rest, so both are admitted. The third ask of 1 finds C's budget spent
    // and is refused.
    for _ in 0..2 {
        assert_eq!(
            use_grant(&mut standin, &agent_c, &c, json!(2048)),
            Ok(json!({ "valid": true })),
            "each ask of 2048 is admitted while the budget still covers it"
        );
    }
    assert_eq!(
        use_grant(&mut standin, &agent_c, &c, json!(1)),
        held,
        "the third ask of 1 is refused once C's budget is spent"
    );
}

/// F-1253-2, at the routes: a stopped grant's open hold still counts.
///
/// Agent A holds the cap (4096) through the use route. B is a second route
/// grant on A's own identity, minted before the stop through
/// `post_capability_grant` on A's second request. A whole-session stop would
/// revoke B too, so A alone is ended through `end_one_live_grant`, the seam
/// whose body is the `end_live_grant` step `revoke_live` runs: the grant
/// becomes `Revoked` and its ledger binding ends through `end_grant`, which
/// keeps A's open hold. B is a `session` grant, so nothing revokes it, and its
/// ask of 1 is refused only because A's held 4096 still counts against the
/// identity ceiling. B stays live and unspent.
///
/// F1 in Rong's table: asking 1, not 4096, proves the shared ceiling. F6
/// (Rong's table): this journey pins that ending a grant keeps its hold
/// (`end_grant`), rather than removing the binding. Dropping the `end_grant`
/// call from `end_live_grant` keeps this test green because the grant stays
/// live; a `held_for_identity` that skips ended grants turns it red.
#[test]
fn an_ended_grants_open_hold_still_blocks_a_sibling_grant() {
    let mut standin = StandIn::new();
    let bundle = SignedBundle::distinct("agent-ceiling-a");
    admit(&mut standin, &bundle);
    let agent = launch(&mut standin, &bundle);
    let a = own_grant_of(&mut standin, &agent, "session");
    let b = own_grant_of(&mut standin, &agent, "session");
    assert_ne!(a.request_id, b.request_id, "the two grants are distinct");
    assert_eq!(
        present(&mut standin, &agent, &a.run_id, &a.request_id),
        Ok(json!({ "valid": true })),
        "A's default use holds the whole ceiling"
    );
    assert_eq!(
        present_ask(
            &mut standin,
            &agent,
            &b.run_id,
            &b.request_id,
            &json!({ "amount": 1 })
        ),
        Err((403u16, "reservation exceeds the ceiling".to_owned())),
        "A's open hold refuses B's ask of 1 before the stop"
    );
    standin.end_one_live_grant(&a.request_id);
    assert!(
        !listed_live(&standin, &a.request_id),
        "the ended grant leaves the live view"
    );
    assert!(
        listed_live(&standin, &b.request_id),
        "the sibling grant stays live"
    );
    assert_eq!(
        standin.post_capability_validate(
            Caller::Client { session_id: &agent },
            &json!({ "request_id": b.request_id, "amount": 1 }),
        ),
        Err((403u16, "reservation exceeds the ceiling".to_owned())),
        "the ended grant's open hold still counts at the routes"
    );
    assert!(
        listed_live(&standin, &b.request_id),
        "the refused ask leaves B live and unspent"
    );
}

/// F1: a second grant is refused while the first grant's hold is open.
///
/// Session S asks twice and the shell grants both through `post_capability_grant`,
/// so A and B are both route-minted `session` grants. A's use asks 4096 and is
/// admitted; B's use asks 1 and is refused at `Verifier::reserve`, because
/// the ledger sums the open holds of S's identity, not of one handle.
#[test]
fn a_second_grant_is_refused_while_the_first_grants_hold_is_open() {
    let mut standin = StandIn::new();
    let bundle = SignedBundle::distinct("agent-two-grants");
    admit(&mut standin, &bundle);
    let session = launch(&mut standin, &bundle);
    let a = own_grant_of(&mut standin, &session, "session");
    let b = own_grant_of(&mut standin, &session, "session");
    assert_ne!(a.request_id, b.request_id, "the two grants are distinct");
    assert_eq!(
        present(&mut standin, &session, &a.run_id, &a.request_id),
        Ok(json!({ "valid": true })),
        "A's use at the cap is admitted"
    );
    assert_eq!(
        present_ask(
            &mut standin,
            &session,
            &b.run_id,
            &b.request_id,
            &json!({ "amount": 1 })
        ),
        Err((403u16, "reservation exceeds the ceiling".to_owned())),
        "B's ask of 1 is refused by A's open hold, so the ceiling is shared"
    );
    assert!(
        listed_live(&standin, &a.request_id) && listed_live(&standin, &b.request_id),
        "both grants stay live after the refusal"
    );
}

/// F2: a different identity admits the same ask.
///
/// After the same setup as F1, a session T with a grant C asks 4096 and is
/// admitted: the ceiling is per identity, so S's hold covers T's grant.
#[test]
fn a_second_identities_grant_admits_the_cap_while_the_first_identity_holds_it() {
    let mut standin = StandIn::new();
    let first = SignedBundle::distinct("agent-identity-s");
    let second = SignedBundle::distinct("agent-identity-t");
    admit(&mut standin, &first);
    admit(&mut standin, &second);
    let s = launch(&mut standin, &first);
    let t = launch(&mut standin, &second);
    let a = own_grant_of(&mut standin, &s, "session");
    let c = own_grant_of(&mut standin, &t, "session");
    assert_eq!(
        present(&mut standin, &s, &a.run_id, &a.request_id),
        Ok(json!({ "valid": true })),
        "S's grant holds S's ceiling"
    );
    assert_eq!(
        present(&mut standin, &t, &c.run_id, &c.request_id),
        Ok(json!({ "valid": true })),
        "T's grant still admits the cap on its own ceiling"
    );
}

/// F4: a refused use holds nothing.
///
/// On session S, A's 1000 is admitted, then B's 4096 is refused at
/// `Verifier::reserve`, then B's 1 is admitted. A and B are two route-minted
/// grants of S. The 1 fits under the ceiling only when the refused 4096
/// recorded no hold, so the refused ask left the identity's held sum at
/// exactly A's 1000.
#[test]
fn a_refused_use_holds_nothing() {
    let mut standin = StandIn::new();
    let bundle = SignedBundle::distinct("agent-refused-holds");
    admit(&mut standin, &bundle);
    let session = launch(&mut standin, &bundle);
    let a = own_grant_of(&mut standin, &session, "session");
    let b = own_grant_of(&mut standin, &session, "session");
    assert_ne!(a.request_id, b.request_id, "the two grants are distinct");
    assert_eq!(
        present_ask(
            &mut standin,
            &session,
            &a.run_id,
            &a.request_id,
            &json!({ "amount": 1000 })
        ),
        Ok(json!({ "valid": true })),
        "A's 1000 is admitted"
    );
    assert_eq!(
        present_ask(
            &mut standin,
            &session,
            &b.run_id,
            &b.request_id,
            &json!({ "amount": 4096 })
        ),
        Err((403u16, "reservation exceeds the ceiling".to_owned())),
        "B's 4096 is refused by A's hold"
    );
    assert!(
        listed_live(&standin, &b.request_id),
        "the refused ask leaves B live and unspent"
    );
    assert_eq!(
        present_ask(
            &mut standin,
            &session,
            &b.run_id,
            &b.request_id,
            &json!({ "amount": 1 })
        ),
        Ok(json!({ "valid": true })),
        "B's 1 fits, so the refused 4096 held nothing"
    );
}

/// True when the shell request view lists `request_id` as pending with no
/// reason.
fn still_pending(standin: &StandIn, session: &str, request_id: &str) -> bool {
    let listed = standin
        .get_capability_requests(Caller::Shell, Some(session))
        .expect("the shell reads the session's requests");
    listed["requests"]
        .as_array()
        .expect("the request list is an array")
        .iter()
        .find(|record| record["request_id"] == json!(request_id))
        .is_some_and(|record| {
            record["status"] == json!("pending") && record["decision_reason"] == json!("")
        })
}

/// N4: a blank deny reason is refused and the request stays pending.
///
/// The resident asks through `post_capability_request` and the shell denies
/// through `post_capability_deny`. Each refused call names an existing pending
/// request and passes every rule before the blank check.
#[test]
fn a_blank_deny_reason_is_refused_and_an_absent_one_defaults() {
    let mut standin = StandIn::new();
    let bundle = SignedBundle::distinct("agent-blank");
    admit(&mut standin, &bundle);
    let session = launch(&mut standin, &bundle);
    let ask = |standin: &mut StandIn, session: &str| {
        standin
            .post_capability_request(
                Caller::Client {
                    session_id: session,
                },
                &json!({ "resource": ASK_RESOURCE, "action": "read", "reason": "journey" }),
            )
            .expect("the resident stores its request")["request_id"]
            .as_str()
            .expect("the request route names its id")
            .to_owned()
    };
    let blank_id = ask(&mut standin, &session);
    let ws_id = ask(&mut standin, &session);
    let absent_id = ask(&mut standin, &session);
    for (id, reason) in [(&blank_id, ""), (&ws_id, "  ")] {
        assert_eq!(
            standin.post_capability_deny(
                Caller::Shell,
                &json!({ "request_id": id, "reason": reason }),
            ),
            Err((400u16, "deny reason must not be blank".to_owned())),
            "a blank deny reason is refused"
        );
    }
    assert!(
        still_pending(&standin, &session, &blank_id),
        "the refused deny leaves the request pending with no reason"
    );
    assert!(
        still_pending(&standin, &session, &ws_id),
        "the whitespace refusal leaves its request pending"
    );
    assert_eq!(
        standin.post_capability_deny(Caller::Shell, &json!({ "request_id": absent_id })),
        Ok(json!({ "success": true })),
        "an absent deny reason is accepted"
    );
    let read = standin
        .get_capability_request(
            Caller::Client {
                session_id: &session,
            },
            &absent_id,
        )
        .expect("the owning client reads its denied request");
    assert_eq!(
        read,
        json!({ "status": "denied", "reason": "Denied by user" }),
        "an absent deny reason is stored as the one default"
    );
}
