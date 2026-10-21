//! Proof 4: the guest checks a credential against the key pinned in its own
//! manifest, after the read and before any frame. It can only refuse.
mod common;

use std::time::Duration;

use bus2_host::{
    run_resident, BusError, Credential, Ending, Event, HostState, Limits, Outcome, StubObject,
    Ticker,
};
use common::{
    credential, key, message, sha256_hex, KIND, OTHER_DID, OTHER_LABEL, PUBLISHER_DID,
    PUBLISHER_LABEL, TAG,
};
use wasmtime::component::Component;

const PHOTO: &str = "localhost://Users/self/Pictures/a.png";
const PNG: &[u8] = b"\x89PNG\r\n\x1a\nthe photo";

fn show(credentials: Vec<Credential>, policy: bool) -> Outcome {
    let mut state = HostState::default();
    if policy {
        state
            .policy
            .push((PHOTO.to_string(), vec!["read".to_string()]));
    }
    state
        .objects
        .insert(PHOTO.to_string(), StubObject::new(PNG.to_vec()));
    state.credentials = credentials;
    common::within(Duration::from_secs(30), async move {
        let engine = bus2_host::engine().unwrap();
        let _ticker = Ticker::start(&engine, Duration::from_millis(10));
        let component = Component::new(&engine, common::guest("bus2_photo_guest")).unwrap();
        run_resident(
            &engine,
            &component,
            state,
            Limits::default(),
            async |events| {
                events.send(Event::Message(PHOTO.as_bytes().to_vec()));
                tokio::time::sleep(Duration::from_millis(200)).await;
            },
        )
        .await
        .unwrap()
    })
}

/// Refused with `denied(why)`, after the read, with no frame drawn.
fn refused(credentials: Vec<Credential>) -> String {
    let outcome = show(credentials, true);
    assert_eq!(
        outcome.state.reads.len(),
        1,
        "the check runs after the read"
    );
    assert!(
        outcome.state.frames.is_empty(),
        "no frame before the check passes"
    );
    match outcome.ending {
        Ending::ReturnedError(BusError::Denied(why)) => why,
        other => panic!("expected denied, got {other:?}"),
    }
}

fn subject() -> String {
    sha256_hex(PNG)
}

#[test]
fn a_credential_from_the_pinned_key_for_these_bytes_lets_the_photo_show() {
    let outcome = show(vec![common::licence(PNG)], true);
    assert_eq!(outcome.ending.reason(), "stopped");
    assert_eq!(outcome.state.frames.len(), 1);
}

#[test]
fn the_manifest_pins_the_test_publisher() {
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(common::root().join("guests/photo/capsule.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["credential"]["signer"], PUBLISHER_DID);
    assert_eq!(manifest["credential"]["kind"], KIND);
}

#[test]
fn no_credential_or_another_kind_is_refused() {
    assert_eq!(
        refused(vec![]),
        format!("no {KIND} credential was presented")
    );
    let other_kind = "elastos.bus2-proof.badge/v1";
    let signed = message(TAG, other_kind, &subject());
    let badge = credential(
        other_kind,
        PUBLISHER_DID,
        &subject(),
        &key(PUBLISHER_LABEL),
        &signed,
    );
    assert_eq!(
        refused(vec![badge]),
        format!("no {KIND} credential was presented")
    );
    assert_eq!(
        refused(vec![common::licence(PNG), common::licence(PNG)]),
        format!("more than one {KIND} credential was presented")
    );
}

#[test]
fn another_signer_or_another_key_is_refused() {
    // Another publisher's name, even with a signature by the pinned key.
    let signed = message(TAG, KIND, &subject());
    let renamed = credential(KIND, OTHER_DID, &subject(), &key(PUBLISHER_LABEL), &signed);
    assert_eq!(
        refused(vec![renamed]),
        format!("the credential's signer {OTHER_DID} is not the pinned publisher")
    );
    // The pinned publisher's name on a signature by another key.
    let forged = credential(KIND, PUBLISHER_DID, &subject(), &key(OTHER_LABEL), &signed);
    assert_eq!(
        refused(vec![forged]),
        "the credential is not signed by the pinned key"
    );
    // Not a signature at all.
    let mut empty = common::licence(PNG);
    empty.body = vec![0; 10];
    assert_eq!(
        refused(vec![empty]),
        "the credential's body is not a signature"
    );
}

#[test]
fn a_credential_for_other_bytes_is_refused() {
    let other = sha256_hex(b"another photo");
    let signed = message(TAG, KIND, &other);
    let for_other = credential(KIND, PUBLISHER_DID, &other, &key(PUBLISHER_LABEL), &signed);
    assert_eq!(
        refused(vec![for_other]),
        "the credential is for other bytes than were read"
    );
}

/// Review change 1: the signature covers the tag, the kind and the hash.
#[test]
fn a_pinned_key_signature_over_the_same_hash_without_this_tag_and_kind_is_refused() {
    let pinned = key(PUBLISHER_LABEL);
    let not_signed = "the credential is not signed by the pinned key";
    for (what, signed) in [
        (
            "another kind",
            message(TAG, "elastos.bus2-proof.badge/v1", &subject()),
        ),
        (
            "another tag",
            message("elastos:bus2-proof:credential:v2", KIND, &subject()),
        ),
        (
            "another protocol's tag",
            message("elastos:other:credential:v1", KIND, &subject()),
        ),
        ("no kind", format!("{TAG}\n{}", subject()).into_bytes()),
        ("the bare hash in hex", subject().into_bytes()),
        ("the bare hash", {
            use sha2::Digest as _;
            sha2::Sha256::digest(PNG).to_vec()
        }),
    ] {
        let replayed = credential(KIND, PUBLISHER_DID, &subject(), &pinned, &signed);
        assert_eq!(refused(vec![replayed]), not_signed, "{what}");
    }
}

#[test]
fn a_good_credential_grants_nothing() {
    // With no policy for the photo, a good licence does not get it a grant.
    let outcome = show(vec![common::licence(PNG)], false);
    assert_eq!(
        outcome.ending,
        Ending::ReturnedError(BusError::Denied(format!(
            "no policy allows [\"read\"] on {PHOTO}"
        )))
    );
    assert!(outcome.state.grants.is_empty());
    assert!(outcome.state.frames.is_empty());
}
