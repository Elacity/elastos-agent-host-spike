//! Harness self-tests: each journey against the reference double. The honest
//! double passes every journey; each fault is refused for its own reason.
//! These rows prove the harness, not the Runtime, and count toward no M1 check.

mod common;

use a5_binding_harness::capability::{asks_required_by, Check, RuntimeCall};
use a5_binding_harness::contract::{
    refusal_matches, RuntimeEvidence, IDENTITY_REFUSAL, INSTANCE_REFUSAL, OWNED_ROOT_REFUSAL,
    PUBLIC_RESOURCE,
};
use a5_binding_harness::journey::Outcome;
use common::double::{Double, Faults};
use common::record::Recording;

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

/// Each journey is run once. The recorded Runtime calls are mapped to asks.
/// `needs()` must list every ask those calls require. Dropping one is CAUGHT.
#[test]
fn needs_cover_every_runtime_call_the_journey_makes() {
    for check in Check::ALL {
        let mut recording = Recording::new(Double::new(Faults::default()));
        check.run(&mut recording).unwrap_or_else(|reason| {
            panic!(
                "{} journey failed on the honest double: {reason}",
                check.id()
            )
        });
        let required = asks_required_by(recording.calls());
        assert!(
            !required.is_empty(),
            "{} recorded no Runtime asks; journey called {:?}",
            check.id(),
            recording.calls()
        );
        for ask in &required {
            assert!(
                check.needs().contains(ask),
                "{} needs() omitted {} (id {}); journey called {:?}",
                check.id(),
                ask.title(),
                ask.id(),
                recording.calls()
            );
        }
        if check == Check::PublicNotBinding {
            assert!(
                recording.calls().contains(&RuntimeCall::HostRecord),
                "A5-PUB must call host_record through launch"
            );
            assert!(
                check.needs().iter().any(|c| c.id() == "RA-1"),
                "A5-PUB calls host_record so needs() must list RA-1"
            );
            assert!(
                check.needs().iter().any(|c| c.id() == "#463"),
                "A5-PUB calls host_record so needs() must list guest-handle use (#463)"
            );
        }
    }
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
fn positive_rows_are_different_journeys() {
    let id = run(Check::IdentityUse, Faults::default()).unwrap();
    let sess = run(Check::SessionUse, Faults::default()).unwrap();
    let inst = run(Check::InstanceUse, Faults::default()).unwrap();
    let stor = run(Check::StorageUse, Faults::default()).unwrap();
    assert!(id.contains("bytes from A's root"), "{id}");
    assert!(sess.contains("host session"), "{sess}");
    assert!(inst.contains("sibling activation"), "{inst}");
    assert!(stor.contains(".. / symlink / prefix refused"), "{stor}");
    assert_ne!(id, sess);
    assert_ne!(sess, inst);
    assert_ne!(inst, stor);
}

#[test]
fn fake_refusal_is_rejected() {
    let faults = Faults {
        fake_refusal: true,
        ..Faults::default()
    };
    for check in Check::ALL {
        if check == Check::PublicNotBinding {
            continue;
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
        "expected Runtime refusal identity",
    );
}

#[test]
fn session_end_without_settled_by_is_rejected() {
    let faults = Faults {
        omit_settled_by: true,
        ..Faults::default()
    };
    refused(Check::SessionEnded, faults, "settled_by=runtime");
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
        "expected Runtime refusal session",
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
        "expected Runtime refusal instance",
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
        "expected Runtime refusal owned_root",
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
fn empty_grant_id_is_rejected_on_the_journey() {
    let faults = Faults {
        empty_grant_id: true,
        ..Faults::default()
    };
    refused(Check::IdentityUse, faults, "empty grant id is refused");
}

#[test]
fn public_resource_constant_is_public() {
    assert!(PUBLIC_RESOURCE.starts_with("localhost://Public/"));
}

#[test]
fn substring_reasons_are_not_structured_matches() {
    let evidence = RuntimeEvidence::from_double(
        a5_binding_harness::contract::EvidenceKind::Refused,
        Some(403),
        Some("r1".to_owned()),
        "no identity check".to_owned(),
        None,
        a5_binding_harness::contract::Actor::Runtime,
        PUBLIC_RESOURCE.to_owned(),
    );
    assert!(!refusal_matches(&evidence, IDENTITY_REFUSAL));
    assert!(!refusal_matches(&evidence, INSTANCE_REFUSAL));
    assert!(!refusal_matches(&evidence, OWNED_ROOT_REFUSAL));
}
