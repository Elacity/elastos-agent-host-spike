#![forbid(unsafe_code)]

//! Plan preview: the bytes and their hash, and nothing else.
//!
//! A proposal carries no authority, so a preview reads no grant and no
//! capsule list and writes neither. Runtime authorisation is a separate step.

use agent_conformance::standin_runtime::StandIn;

/// One plan preview. The hash names the exact fixture bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preview {
    pub plan: Vec<u8>,
    pub sha256: String,
}

/// Return the plan bytes and their SHA-256. The stand-in stays untouched.
pub fn preview(stand_in: &mut StandIn, plan: &[u8]) -> Preview {
    let _ = stand_in;
    Preview {
        plan: plan.to_vec(),
        sha256: agent_conformance::identity::sha256(plan),
    }
}

#[cfg(test)]
mod fixtures {
    pub const PLAN_A: &[u8] =
        br#"{"steps":[{"resource":"localhost://Public/plan-approval/a.txt","action":"read"}]}"#;
    pub const PLAN_B: &[u8] =
        br#"{"steps":[{"resource":"localhost://Public/plan-approval/b.txt","action":"read"}]}"#;
    pub const UNCHANGED: &str = "the preview returned the plan bytes, the hash is sha256 of those bytes, and the live grants and the capsule list are unchanged";
}

#[cfg(test)]
#[test]
fn preview_makes_no_effect() {
    use agent_conformance::identity::sha256;
    use agent_conformance::standin_runtime::Caller;
    use fixtures::{PLAN_A, PLAN_B, UNCHANGED};
    use serde_json::json;

    assert_ne!(sha256(PLAN_A), sha256(PLAN_B), "fixtures differ");

    let mut stand_in = StandIn::new();
    let grants_before = stand_in
        .get_capability_list(Caller::Shell, Some("all_sessions_live"))
        .expect("fresh shell live list");
    let empty_capsules = stand_in
        .get_capsules(Caller::Shell)
        .expect("fresh shell capsules");

    let fixture = launches::Fixture::new();
    let session_id = launches::launch(&mut stand_in, &fixture);
    let resident_capsules = stand_in
        .get_capsules(Caller::Shell)
        .expect("shell capsules with the resident launched");
    assert_ne!(
        resident_capsules, empty_capsules,
        "the launch routes add the resident entry, so the baseline is not the empty list"
    );

    let mut previews = Vec::new();
    previews.push(preview(&mut stand_in, PLAN_A));
    previews.push(preview(&mut stand_in, PLAN_B));

    assert_eq!(
        stand_in
            .get_capability_list(Caller::Shell, Some("all_sessions_live"))
            .expect("shell live list"),
        grants_before,
        "{UNCHANGED} on a fresh stand-in"
    );
    assert_eq!(
        stand_in
            .get_capsules(Caller::Shell)
            .expect("shell capsules"),
        resident_capsules,
        "{UNCHANGED} with the resident launched and no grant"
    );
    assert_eq!(
        previews[0].plan, PLAN_A,
        "the preview returned the plan bytes"
    );
    assert_eq!(
        previews[0].sha256,
        sha256(PLAN_A),
        "the hash is sha256 of those bytes"
    );
    assert_eq!(
        previews[1].plan, PLAN_B,
        "the preview returned the plan bytes"
    );
    assert_eq!(
        previews[1].sha256,
        sha256(PLAN_B),
        "the hash is sha256 of those bytes"
    );

    let posted = stand_in
        .post_capability_request(
            Caller::Client {
                session_id: &session_id,
            },
            &json!({
                "resource": "localhost://Public/plan-approval/a.txt",
                "action": "read",
                "reason": "read the plan resource",
            }),
        )
        .expect("the agent's own route stores one pending request");
    let request_id = posted["request_id"]
        .as_str()
        .expect("the request route names the request it stored")
        .to_owned();
    stand_in
        .post_capability_grant(
            Caller::Shell,
            &json!({
                "request_id": request_id,
                "duration": "once",
                "rationale": "shell approves the plan read",
            }),
        )
        .expect("the shell grants the agent's request");

    let grants_seeded = stand_in
        .get_capability_list(Caller::Shell, Some("all_sessions_live"))
        .expect("seeded shell live list");
    assert_ne!(grants_seeded, grants_before, "the seeded grant is live");
    assert_eq!(
        grants_seeded["capabilities"]
            .as_array()
            .map(|grants| grants.len()),
        Some(1),
        "the routes leave exactly the one live grant for the launched session"
    );
    let capsules_seeded = stand_in
        .get_capsules(Caller::Shell)
        .expect("seeded shell capsules");

    previews.clear();
    previews.push(preview(&mut stand_in, PLAN_A));
    previews.push(preview(&mut stand_in, PLAN_B));

    assert_eq!(
        stand_in
            .get_capability_list(Caller::Shell, Some("all_sessions_live"))
            .expect("shell live list"),
        grants_seeded,
        "{UNCHANGED} after the seeded grant"
    );
    assert_eq!(
        stand_in
            .get_capsules(Caller::Shell)
            .expect("shell capsules"),
        capsules_seeded,
        "{UNCHANGED} after the seeded grant"
    );
    assert_eq!(
        capsules_seeded, resident_capsules,
        "the route grant leaves the capsule list alone"
    );
    assert_eq!(
        previews[0].plan, PLAN_A,
        "the preview returned the plan bytes"
    );
    assert_eq!(
        previews[0].sha256,
        sha256(PLAN_A),
        "the hash is sha256 of those bytes"
    );
    assert_eq!(
        previews[1].plan, PLAN_B,
        "the preview returned the plan bytes"
    );
    assert_eq!(
        previews[1].sha256,
        sha256(PLAN_B),
        "the hash is sha256 of those bytes"
    );
}

#[cfg(test)]
mod launches {
    use agent_conformance::standin_runtime::{Caller, StandIn, Start};
    use serde_json::json;

    /// The one signed fixture bundle the stand-in admits, in a fresh tempdir
    /// that lives as long as `Fixture`.
    pub struct Fixture {
        bundle: tempfile::TempDir,
        accepted: Vec<String>,
        key: ed25519_dalek::SigningKey,
    }

    impl Fixture {
        pub fn new() -> Self {
            let bundle = tempfile::TempDir::new().expect("make a bundle tempdir");
            for name in ["capsule.json", "asks.json"] {
                let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../capsule-identity/fixtures/agent-host")
                    .join(name);
                let bytes = std::fs::read(&source).expect("read the agent-host fixture");
                std::fs::write(bundle.path().join(name), bytes).expect("write the fixture file");
            }
            let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
            let accepted = vec![elastos_identity::encode_signing_key_did(&key)];
            Fixture {
                bundle,
                accepted,
                key,
            }
        }
    }

    /// Admits the fixture bundle and launches it once, so the stand-in names
    /// one live session.
    pub fn launch(stand_in: &mut StandIn, fixture: &Fixture) -> String {
        let signature =
            capsule_identity::sign_bundle(&fixture.key, fixture.bundle.path()).expect("sign");
        stand_in
            .admit_resident(
                fixture.bundle.path(),
                &signature,
                &fixture.accepted,
                Start::Ok,
            )
            .expect("the stand-in admits the fixture bundle");
        let cid = capsule_identity::checked_bundle(fixture.bundle.path())
            .expect("the walk names the fixture bundle")
            .cid()
            .to_string();
        let launch = stand_in
            .post_capsules(Caller::Shell, &json!({ "cid": cid }))
            .expect("the stand-in launches the admitted CID");
        let id = launch["id"]
            .as_str()
            .expect("the launch route names the session")
            .to_owned();
        stand_in
            .finish_start(&id)
            .expect("the stand-in applies the admitted Start::Ok");
        id
    }
}
