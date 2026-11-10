pub(crate) const HOME_LAUNCH_TOKEN_DOMAIN: &str = "elastos.home.launch.v4";

/// In production, only this module builds a signer witness, after the launch
/// token's domain-separated signature check accepts its DID.
#[derive(Debug)]
pub(crate) struct VerifiedLaunchTokenSigner {
    did: String,
}

impl VerifiedLaunchTokenSigner {
    pub(crate) fn verify(bytes: &[u8], expected_dids: &[String]) -> anyhow::Result<Self> {
        if expected_dids.is_empty() {
            anyhow::bail!("home launch token has no expected signer");
        }
        let (_, did) = crate::crypto::verify_signed_json_envelope_against_dids(
            bytes,
            HOME_LAUNCH_TOKEN_DOMAIN,
            expected_dids,
        )?;
        Ok(Self { did })
    }

    pub(crate) fn did(&self) -> &str {
        &self.did
    }
}

#[cfg(test)]
pub(super) fn fixture_unverified_for_tests(did: &str) -> VerifiedLaunchTokenSigner {
    VerifiedLaunchTokenSigner {
        did: did.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_refuses_bad_signature_and_unexpected_signer() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[43; 32]);
        let payload = serde_json::json!({"body": "original"});
        let canonical = serde_json::to_vec(&payload).unwrap();
        let (signature, did) =
            crate::crypto::domain_separated_sign(&key, HOME_LAUNCH_TOKEN_DOMAIN, &canonical);
        let bad_signature = serde_json::json!({
            "payload": {"body": "changed"}, "signature": signature, "signer_did": did,
        });
        let bytes = serde_json::to_vec(&bad_signature).unwrap();
        assert_eq!(
            VerifiedLaunchTokenSigner::verify(&bytes, std::slice::from_ref(&did))
                .expect_err("bad signature must return Err")
                .to_string(),
            "Signed envelope signature verification failed"
        );

        let valid = serde_json::json!({
            "payload": payload, "signature": signature, "signer_did": did,
        });
        let bytes = serde_json::to_vec(&valid).unwrap();
        let other = crate::crypto::encode_signing_key_did(&ed25519_dalek::SigningKey::from_bytes(
            &[44; 32],
        ));
        assert!(VerifiedLaunchTokenSigner::verify(&bytes, &[other])
            .expect_err("unexpected signer must return Err")
            .to_string()
            .contains("Signer DID mismatch"));
    }
}
