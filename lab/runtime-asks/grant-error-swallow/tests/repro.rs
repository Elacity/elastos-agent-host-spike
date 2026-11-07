//! Reproduction: inject Internal at the grant-request point and show the
//! caller sees the same `Ok` deny as a genuine Denied.
//!
//! The injection is the Runtime `bus_error` mapping. A8's undeclared resource
//! uses code `manifest_capability_denied`, which is not in the Denied list, so
//! it becomes `BusError::Internal`. A genuine operator deny uses code
//! `denied` and becomes `BusError::Denied`. Both then pass through WasmBus
//! and `request_journal_grants` `.ok()`, and `run()` returns `Ok(())`.

use grant_error_swallow::{
    bus_error, shipped_ask, shipped_caller, wasm_bus_map, BusErrorKind, BusFailure, CallerOutcome,
};

const INTERNAL_CODE: &str = "manifest_capability_denied";
const DENY_CODE: &str = "denied";

#[test]
fn runtime_maps_undeclared_authority_to_internal() {
    assert_eq!(bus_error(INTERNAL_CODE), BusErrorKind::Internal);
    assert_eq!(bus_error("internal"), BusErrorKind::Internal);
    assert_eq!(bus_error("write_failed"), BusErrorKind::Internal);
}

#[test]
fn runtime_maps_a_genuine_deny_to_denied() {
    assert_eq!(bus_error(DENY_CODE), BusErrorKind::Denied);
    assert_eq!(bus_error("capability_denied"), BusErrorKind::Denied);
}

#[test]
fn wasm_bus_maps_internal_to_other() {
    assert_eq!(wasm_bus_map(BusErrorKind::Internal), BusFailure::Other);
    assert_eq!(wasm_bus_map(BusErrorKind::Denied), BusFailure::Denied);
}

#[test]
fn request_journal_grants_ok_swallows_other_and_denied() {
    assert_eq!(shipped_ask(Err(BusFailure::Other)), None);
    assert_eq!(shipped_ask(Err(BusFailure::Denied)), None);
    assert_eq!(shipped_ask(Err(BusFailure::Invalid)), None);
}

#[test]
fn injected_internal_is_reported_as_ordinary_deny() {
    let outcome = shipped_caller(INTERNAL_CODE);
    println!("inject {INTERNAL_CODE} → {outcome:?}");
    assert_eq!(
        outcome,
        CallerOutcome::OkDeny,
        "Internal at the grant request must be a deny (Ok) on the shipped path"
    );
}

#[test]
fn genuine_deny_is_also_ok() {
    let outcome = shipped_caller(DENY_CODE);
    println!("control {DENY_CODE} → {outcome:?}");
    assert_eq!(outcome, CallerOutcome::OkDeny);
}

#[test]
fn caller_cannot_tell_internal_from_deny() {
    let internal = shipped_caller(INTERNAL_CODE);
    let deny = shipped_caller(DENY_CODE);
    println!("shipped Internal={internal:?} Denied={deny:?}");
    assert_eq!(
        internal, deny,
        "the shipped caller must report Internal and Denied the same way"
    );
    assert_eq!(internal, CallerOutcome::OkDeny);
}

#[test]
fn shipped_mapping_fails_the_trial_property() {
    assert_eq!(
        shipped_caller(INTERNAL_CODE),
        CallerOutcome::OkDeny,
        "unpatched: Internal is a deny, so the trial property fails"
    );
    assert_ne!(
        shipped_caller(INTERNAL_CODE),
        CallerOutcome::Err,
        "unpatched must not already fail loudly"
    );
}
