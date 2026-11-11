//! Domain-separated Ed25519 signatures by did:key, the same construction as
//! `elastos-server/src/crypto.rs` (`domain_separated_sign`,
//! `verify_domain_separated_signature`): `Ed25519(SHA256(domain || 0x00 || payload))`.
//! The DID codec is elastos-identity's own.

use ed25519_dalek::{Signature, Signer, SigningKey};
use sha2::{Digest, Sha256};

fn digest(domain: &str, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(b"\0");
    hasher.update(payload);
    hasher.finalize().into()
}

/// Returns `(signature_hex, signer_did)`.
pub fn sign(key: &SigningKey, domain: &str, payload: &[u8]) -> (String, String) {
    let signature = key.sign(&digest(domain, payload));
    (
        hex::encode(signature.to_bytes()),
        elastos_identity::encode_signing_key_did(key),
    )
}

/// Verifies with `verify_strict`, which also refuses small-order keys and
/// non-canonical signatures.
pub fn verify(
    signer_did: &str,
    domain: &str,
    payload: &[u8],
    signature_hex: &str,
) -> Result<(), String> {
    let key = elastos_identity::decode_did_key(signer_did)
        .map_err(|err| format!("{signer_did}: {err}"))?;
    let bytes = hex::decode(signature_hex).map_err(|err| format!("signature hex: {err}"))?;
    let signature = Signature::from_slice(&bytes).map_err(|err| format!("signature: {err}"))?;
    key.verify_strict(&digest(domain, payload), &signature)
        .map_err(|_| format!("the signature does not verify for {signer_did}"))
}

pub fn generate() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

pub fn did(key: &SigningKey) -> String {
    elastos_identity::encode_signing_key_did(key)
}
