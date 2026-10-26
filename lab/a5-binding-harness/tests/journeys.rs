//! Harness self-tests: each journey against the reference double. The honest
//! double passes every journey; each fault is refused for its own reason.
//! These rows prove the harness, not the Runtime, and count toward no M1 check.

mod common;

use a5_binding_harness::capability::Check;
use a5_binding_harness::contract::PUBLIC_RESOURCE;
use a5_binding_harness::journey::Outcome;
use common::double::{Double, Faults};

fn run(check: Check, faults: Faults) -> Outcome {
    let mut double = Double::new(faults);
    check.run(&mut double)
}

fn refused(check: Check, faults: Faults, reason: &str) {
    let failure = run(check, faults).expect_err("the journey must refuse this Runtime");
    assert!(
        failure.contains(reason),
        "{} refused for another reason.\nexpected: {reason}\nactual:   {failure}",
        check.id()
    );
}

#[test]
fn honest_double_passes_every_journey() {
    for check in Check::ALL {
        let evidence = run(check, Faults::default())
            .unwrap_or_else(|reason| panic!("{}: {reason}", check.id()));
        assert!(
            evidence.starts_with(&format!("{}:", check.id())),
            "{evidence}"
        );
    }
}

#[test]
fn fake_refusal_is_rejected() {
    let faults = Faults {
        fake_refusal: true,
        ..Faults::default()
    };
    for check in Check::ALL {
        if check == Check::PublicNotBinding {
            // Public row reads Public first; fake_refusal still hits use_grant.
        }
        refused(check, faults, "fixture refusal is not Runtime evidence");
    }
}

#[test]
fn public_read_as_binding_is_rejected() {
    let faults = Faults {
        public_as_binding: true,
        ..Faults::default()
    };
    refused(
        Check::PublicNotBinding,
        faults,
        "public storage read counted as binding",
    );
}

#[test]
fn identity_replay_allowed_is_rejected() {
    let faults = Faults {
        identity_replay_allowed: true,
        sibling_allowed: true,
        session_survives_end: true,
        other_root_allowed: true,
        ..Faults::default()
    };
    refused(
        Check::IdentityReplay,
        faults,
        "expected Runtime refusal containing \"identity\"",
    );
}

#[test]
fn session_survives_end_is_rejected() {
    let faults = Faults {
        session_survives_end: true,
        ..Faults::default()
    };
    refused(
        Check::SessionEnded,
        faults,
        "expected Runtime refusal containing \"session\"",
    );
}

#[test]
fn sibling_allowed_is_rejected() {
    let faults = Faults {
        sibling_allowed: true,
        session_survives_end: true,
        ..Faults::default()
    };
    refused(
        Check::InstanceSibling,
        faults,
        "expected Runtime refusal containing \"instance\"",
    );
}

#[test]
fn other_root_allowed_is_rejected() {
    let faults = Faults {
        other_root_allowed: true,
        ..Faults::default()
    };
    refused(
        Check::StorageOtherRoot,
        faults,
        "expected Runtime refusal containing \"owned root\"",
    );
}

#[test]
fn shared_session_is_rejected() {
    let faults = Faults {
        shared_session: true,
        ..Faults::default()
    };
    refused(
        Check::IdentityUse,
        faults,
        "two principals, two sessions and two instances",
    );
}

#[test]
fn blind_grant_view_is_rejected() {
    let faults = Faults {
        blind_grant_view: true,
        ..Faults::default()
    };
    refused(Check::IdentityUse, faults, "live-grant view missing grant");
}

#[test]
fn public_resource_constant_is_public() {
    assert!(PUBLIC_RESOURCE.starts_with("localhost://Public/"));
}
