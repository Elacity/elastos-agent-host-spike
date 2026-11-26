//! Rows for the owner's proof, the approval's proof, and the approval's time.
//! Each row refuses. Removing the matching check admits the run.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use super::super::model_provider_egress_decision::{
    approved_for_owner, plant_offer_approval, plant_offer_decision, reseed_text_offer_model,
};

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

/// The Bus admits the agent. The owner then loses admin. The charge refuses
/// and the spent total stays zero. Restoring admin lets the same charge proceed.
#[test]
fn an_owner_who_loses_admin_between_the_gate_and_the_charge_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (owner_id, _owner_proof, agent_id) = passkey_agent(dir.path());
    let owner = crate::auth::stored_principal_record(dir.path(), &owner_id)
        .unwrap()
        .unwrap();
    plant_offer_approval(
        dir.path(),
        OFFER,
        &owner.proof_binding_id,
        now_ms() + 60_000,
    );
    let request = serde_json::json!({
        "offer_id": OFFER,
        "operation": "text.generate",
        "input": {"prompt": "hi"},
        "request_id": "model-v1:1700000000000:s9",
    });
    let bus = crate::api::gateway::bus_model_provider_request(
        "runs_create",
        &request,
        Some(dir.path()),
        Some(&agent_id),
        "s9-session",
        "capability:s9",
        "s9-capsule",
    );
    assert!(bus.is_ok(), "{bus:?}");
    let mut state = crate::auth::load_auth_state(dir.path()).unwrap();
    for principal in &mut state.principals {
        if principal.principal_id == owner_id {
            principal.role = crate::auth::RuntimePrincipalRole::Guest;
        }
    }
    crate::auth::save_auth_state(dir.path(), &state, None).unwrap();
    let refused = crate::agents::charge_model_spend(
        dir.path(),
        &owner_id,
        &agent_id,
        (0, 0),
        1,
        64,
        Some(OFFER),
    );
    match refused {
        Err(crate::agents::SpendRefusal::HostedRun) => {}
        other => panic!("{other:?}"),
    }
    assert_eq!(
        crate::agents::model_spend(dir.path(), &agent_id).unwrap().1,
        0
    );
    crate::api::routes::tests::make_admin(dir.path(), &owner_id);
    crate::agents::charge_model_spend(dir.path(), &owner_id, &agent_id, (0, 0), 1, 64, Some(OFFER))
        .unwrap();
    assert!(crate::agents::model_spend(dir.path(), &agent_id).unwrap().1 > 0);
}

fn assert_refused_before_the_charge(dir: &Path, owner_id: &str, agent_id: &str) {
    let request = serde_json::json!({
        "offer_id": OFFER,
        "operation": "text.generate",
        "input": {"prompt": "hi"},
        "request_id": "model-v1:1700000000000:s10",
    });
    let bus = crate::api::gateway::bus_model_provider_request(
        "runs_create",
        &request,
        Some(dir),
        Some(agent_id),
        "s10-session",
        "capability:s10",
        "s10-capsule",
    );
    match bus {
        Err((_code, message)) => {
            assert_eq!(message, crate::api::gateway::HOSTED_AGENT_RUN_SENTENCE);
        }
        Ok(value) => panic!("the run was admitted: {value}"),
    }
    assert_eq!(crate::agents::model_spend(dir, agent_id).unwrap().1, 0);
    let refused =
        crate::agents::charge_model_spend(dir, owner_id, agent_id, (0, 0), 1, 64, Some(OFFER));
    assert!(
        matches!(refused, Err(crate::agents::SpendRefusal::HostedRun)),
        "{refused:?}"
    );
    assert_eq!(crate::agents::model_spend(dir, agent_id).unwrap().1, 0);
}

/// The approval names an effect this offer cannot run. No tokens are charged.
#[test]
fn an_approval_for_another_effect_is_refused_before_the_charge() {
    let dir = tempfile::tempdir().unwrap();
    let (owner_id, owner_proof, agent_id) = passkey_agent(dir.path());
    plant_offer_decision(
        dir.path(),
        OFFER,
        &owner_proof,
        now_ms() + 60_000,
        "validate_models",
    );
    assert_refused_before_the_charge(dir.path(), &owner_id, &agent_id);
}

/// The approval names this offer's previous configuration. No tokens are charged.
#[test]
fn an_approval_for_an_older_configuration_is_refused_before_the_charge() {
    let dir = tempfile::tempdir().unwrap();
    let (owner_id, owner_proof, agent_id) = passkey_agent(dir.path());
    plant_offer_approval(dir.path(), OFFER, &owner_proof, now_ms() + 60_000);
    assert!(approved_for_owner(dir.path(), OFFER, &owner_proof));
    reseed_text_offer_model(dir.path(), OFFER, "fixture/model-2");
    assert!(!approved_for_owner(dir.path(), OFFER, &owner_proof));
    assert_refused_before_the_charge(dir.path(), &owner_id, &agent_id);
}

/// The approval is under the owner's second passkey. The first passkey is revoked.
#[test]
fn an_approval_under_the_second_passkey_counts_when_the_first_is_revoked() {
    let dir = tempfile::tempdir().unwrap();
    let (_owner_id, first_proof, agent_id) = passkey_agent(dir.path());
    let mut state = crate::auth::load_auth_state(dir.path()).unwrap();
    let mut second = state
        .principals
        .iter()
        .find(|principal| principal.proof_binding_id == first_proof)
        .unwrap()
        .clone();
    let mut passkey = second.proof_binding.passkey.clone().unwrap();
    passkey.credential_id = format!("{}-second", passkey.credential_id);
    second.proof_binding = elastos_runtime::auth::ProofBinding::passkey_webauthn(passkey);
    second.proof_binding_id = second.proof_binding.id();
    let second_proof = second.proof_binding_id.clone();
    state.principals.push(second);
    crate::auth::save_auth_state(dir.path(), &state, None).unwrap();
    plant_offer_approval(dir.path(), OFFER, &second_proof, now_ms() + 60_000);
    crate::auth::revoke_passkey_binding(dir.path(), &first_proof, crate::auth::now_ts()).unwrap();
    let agent = crate::auth::stored_principal_record(dir.path(), &agent_id)
        .unwrap()
        .unwrap();
    assert!(
        super::gateway_provider_proxy::agent_owner_approved(dir.path(), &agent, OFFER),
        "the second passkey's approval admits the agent"
    );
    assert_eq!(
        crate::agents::model_spend(dir.path(), &agent_id).unwrap().1,
        0
    );
}
