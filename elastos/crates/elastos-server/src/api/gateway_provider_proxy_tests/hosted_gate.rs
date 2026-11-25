//! Rows for the owner's proof, the approval's proof, and the approval's time.
//! Each row refuses. Removing the matching check admits the run.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use super::super::model_provider_egress_decision::{approved_for_owner, plant_offer_approval};

const OFFER: &str = "model:openrouter";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn enroll_owner(dir: &Path) -> (String, String) {
    let mut identity = elastos_identity::IdentityManager::new(dir.to_path_buf()).unwrap();
    let secret = crate::auth::random_secret_hex();
    let owner = crate::auth::OwnerAdmission {
        origin: "http://localhost:61971",
        rp_id: "localhost",
        claimant: &secret,
        loopback: true,
    };
    let (_, options) = crate::auth::begin_owner_enrollment(
        dir,
        &mut identity,
        &owner,
        "owner",
        crate::auth::now_ts(),
    )
    .unwrap()
    .unwrap();
    let attestation = crate::auth::owner_attestation_for_test(
        &options.unwrap().public_key.challenge,
        owner.rp_id,
        owner.origin,
    );
    crate::auth::complete_owner_enrollment(
        dir,
        &mut identity,
        &owner,
        "owner",
        Some(&attestation),
        None,
        crate::auth::now_ts(),
    )
    .unwrap()
    .unwrap();
    let principal = crate::auth::active_passkey_principals(dir)
        .unwrap()
        .into_iter()
        .find(crate::auth::is_admin)
        .unwrap();
    (principal.principal_id, principal.proof_binding_id)
}

fn passkey_agent(dir: &Path) -> (String, String, String) {
    let (owner_id, owner_proof) = enroll_owner(dir);
    let agent_id = crate::agents::tests::plant_for_dispatch(dir, &owner_id, &owner_id);
    (owner_id, owner_proof, agent_id)
}

/// The owner's proof is revoked. The agent run is refused.
#[test]
fn a_revoked_owner_proof_refuses_the_agent_run() {
    let dir = tempfile::tempdir().unwrap();
    let (_owner_id, owner_proof, agent_id) = passkey_agent(dir.path());
    plant_offer_approval(dir.path(), OFFER, &owner_proof, now_ms() + 60_000);
    let agent = crate::auth::stored_principal_record(dir.path(), &agent_id)
        .unwrap()
        .unwrap();
    assert!(
        super::gateway_provider_proxy::agent_owner_approved(dir.path(), &agent, OFFER),
        "the current owner approval admits the agent"
    );
    crate::auth::revoke_passkey_binding(dir.path(), &owner_proof, crate::auth::now_ts()).unwrap();
    assert!(
        !super::gateway_provider_proxy::agent_owner_approved(dir.path(), &agent, OFFER),
        "owner proof revoked"
    );
}

/// The approval names another proof. This owner's proof is not approved.
#[test]
fn an_approval_under_another_proof_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    plant_offer_approval(dir.path(), OFFER, "proof-owner", now_ms() + 60_000);
    assert!(approved_for_owner(dir.path(), OFFER, "proof-owner"));
    assert!(!approved_for_owner(dir.path(), OFFER, "proof-other"));
}

/// The approval's time has ended. The same proof is not approved.
#[test]
fn an_approval_already_ended_by_time_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    plant_offer_approval(dir.path(), OFFER, "proof-owner", now_ms() + 60_000);
    assert!(approved_for_owner(dir.path(), OFFER, "proof-owner"));
    plant_offer_approval(dir.path(), OFFER, "proof-owner", now_ms().saturating_sub(1));
    assert!(!approved_for_owner(dir.path(), OFFER, "proof-owner"));
}
