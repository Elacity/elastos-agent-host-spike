pub(crate) const HOME_LAUNCH_TOKEN_DOMAIN: &str = "elastos.home.launch.v4";

/// This witness proves that its DID signed an envelope in the Home launch-token
/// domain. The caller checks expiry and the other launch-token fields.
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
mod tests {
    use super::*;

    fn fixture_unverified_for_tests(did: &str) -> VerifiedLaunchTokenSigner {
        VerifiedLaunchTokenSigner {
            did: did.to_string(),
        }
    }

    #[test]
    fn verify_refuses_an_empty_expected_signer_list() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[43; 32]);
        let payload = serde_json::json!({"body": "original"});
        let canonical = serde_json::to_vec(&payload).unwrap();
        let (signature, did) =
            crate::crypto::domain_separated_sign(&key, HOME_LAUNCH_TOKEN_DOMAIN, &canonical);
        let envelope = serde_json::json!({
            "payload": payload, "signature": signature, "signer_did": did,
        });
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let error = VerifiedLaunchTokenSigner::verify(&bytes, &[]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "home launch token has no expected signer"
        );
    }

    #[test]
    fn r8_verified_device_signer_uses_the_device_root() {
        let signer = fixture_unverified_for_tests("did:key:z6MkR8Device");
        let resolved = crate::auth::ResolvedPrincipalRoot::verified_device_signer(&signer);
        assert_eq!(
            resolved.localhost_root(),
            "localhost://Users/af179fa6924299eea2520df3"
        );
    }

    #[test]
    fn verified_device_object_binding_uses_typed_root() {
        use crate::auth::{
            read_principal_root_object_resolved, write_principal_root_object_resolved,
            ResolvedPrincipalRoot,
        };
        use elastos_common::localhost::rooted_localhost_fs_path;

        let data_dir = tempfile::tempdir().unwrap();
        let signer = fixture_unverified_for_tests("did:key:z6MkParentSignedDevice");
        let resolved = ResolvedPrincipalRoot::verified_device_signer(&signer);
        let root = "localhost://Users/45c2b381a3e1d3ed5e2a5ede";
        assert_eq!(resolved.localhost_root(), root);
        let uri = format!("{root}/notes.md");
        let path = rooted_localhost_fs_path(data_dir.path(), &uri).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        write_principal_root_object_resolved(data_dir.path(), &resolved, &uri, &path, b"verified")
            .unwrap();
        assert_eq!(
            read_principal_root_object_resolved(data_dir.path(), &resolved, &uri, &path).unwrap(),
            b"verified"
        );
        let wrong_uri = "localhost://UsersAI/45c2b381a3e1d3ed5e2a5ede/notes.md";
        let wrong_path = rooted_localhost_fs_path(data_dir.path(), wrong_uri).unwrap();
        assert_eq!(
            write_principal_root_object_resolved(
                data_dir.path(),
                &resolved,
                wrong_uri,
                &wrong_path,
                b"no"
            )
            .unwrap_err()
            .to_string(),
            "principal-root object URI is outside the resolved root"
        );
    }

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
