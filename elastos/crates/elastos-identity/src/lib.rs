//! Identity management for ElastOS
//!
//! Two identity primitives:
//! - **Device DID** (`did:key:z6Mk...`) — the local Carrier/node identity.
//!   Derived from device key via `derive_did()`. Used for node signing and
//!   peer transport, not as the human account root.
//! - **WebAuthn/Passkey** — local user authentication. Credentials encrypted
//!   with device key via AES-256-GCM.

pub mod store;
pub mod webauthn;

#[cfg(unix)]
pub use store::install_object_helper_runtime_did;
pub use store::{
    decode_did_key, derive_did, derive_did_seed, derive_storage_key, device_key_path,
    encode_did_key, encode_signing_key_did, load_existing_did, load_nickname,
    load_nickname_with_device_key, load_nickname_with_storage_key, load_or_create_device_key,
    load_or_create_did, save_nickname, save_nickname_with_device_key,
    save_nickname_with_storage_key, validate_canonical_ed25519_verifying_key_bytes,
    validate_nickname, IdentityData, IdentityStore, StoredCredential,
};
/// Nickname files stay under the expanded storage key.
///
/// `#[cfg(unix)]` comes before `#[cfg(test)]` because
/// `save_nickname_with_device_key` writes only on Unix. The test name is the
/// function name, so `--exact` selects this test and no other.
#[cfg(unix)]
#[cfg(test)]
#[test]
fn nickname_roundtrip_uses_storage_key_not_raw_device_key() {
    let dir = tempfile::tempdir().unwrap();
    let device_key = [0x5a; 32];
    save_nickname_with_device_key(dir.path(), &device_key, "ada").unwrap();
    let encrypted = std::fs::read(store::nickname_path(dir.path())).unwrap();
    let storage_key = derive_storage_key(&device_key);
    assert_ne!(storage_key, device_key);
    assert_eq!(
        store::decrypt_data(&storage_key, &encrypted).unwrap(),
        b"ada"
    );
    assert!(
        store::decrypt_data(&device_key, &encrypted).is_err(),
        "the raw device key is not the nickname AES key"
    );
}

pub use webauthn::{
    AuthenticationOutcome, AuthenticationResponse, AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse, AuthenticatorSelection, CreationOptions,
    CredentialDescriptor, IdentityManager, IdentityStatus, PubKeyCredParam,
    PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions, RegistrationOutcome,
    RegistrationResponse, RelyingParty, RequestOptions, UserEntity,
};
