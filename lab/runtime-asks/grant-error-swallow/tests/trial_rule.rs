//! The trial rule, not the Runtime. A plant that sets `SWALLOW_INTERNAL`
//! makes `trial_propagates_internal_and_keeps_deny` fail.

use grant_error_swallow::{
    trial_ask, trial_caller, trial_run, BusFailure, CallerOutcome, SWALLOW_INTERNAL,
};

const INTERNAL_CODE: &str = "manifest_capability_denied";
const DENY_CODE: &str = "denied";

#[test]
fn trial_propagates_internal_and_keeps_deny() {
    assert!(
        !SWALLOW_INTERNAL,
        "SWALLOW_INTERNAL must stay false; the plant sets it"
    );
    let internal = trial_caller(INTERNAL_CODE);
    let deny = trial_caller(DENY_CODE);
    println!("trial Internal={internal:?} Denied={deny:?}");
    assert_eq!(
        internal,
        CallerOutcome::Err,
        "an Internal grant request must not be an ordinary deny"
    );
    assert_eq!(
        deny,
        CallerOutcome::OkDeny,
        "a genuine deny must stay Ok so the two outcomes stay distinguishable"
    );
    assert_ne!(internal, deny);
}

#[test]
fn trial_ask_keeps_a_granted_id() {
    assert_eq!(
        trial_ask(Ok("grant-1".to_string())),
        Ok(Some("grant-1".to_string()))
    );
    assert_eq!(trial_ask(Ok(String::new())), Ok(None));
    assert_eq!(trial_ask(Err(BusFailure::Denied)), Ok(None));
    assert_eq!(trial_ask(Err(BusFailure::Other)), Err(BusFailure::Other));
    assert_eq!(
        trial_ask(Err(BusFailure::Invalid)),
        Err(BusFailure::Invalid)
    );
}

#[test]
fn trial_run_maps_ask_to_caller() {
    assert_eq!(trial_run(Ok(None)), CallerOutcome::OkDeny);
    assert_eq!(trial_run(Err(BusFailure::Other)), CallerOutcome::Err);
}

#[test]
fn trial_patch_checks_clean() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let patch = repo.join("lab/runtime-asks/grant-error-swallow/trial.patch");
    let status = std::process::Command::new("git")
        .args(["apply", "--check", patch.to_str().expect("patch path")])
        .current_dir(&repo)
        .status()
        .expect("git apply --check");
    assert!(status.success(), "trial.patch must apply to this tree");
}
