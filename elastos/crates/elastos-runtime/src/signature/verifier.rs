//! Signature verification for capsules
use std::path::Path;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use sha2::{Digest, Sha256};

use elastos_common::{CapsuleManifest, ElastosError, Result};

/// Re-export for use by CLI
pub use ed25519_dalek::SigningKey;

/// Verifies capsule signatures
pub struct SignatureVerifier {
    /// Trusted public keys for verification
    trusted_keys: Vec<VerifyingKey>,
}

impl SignatureVerifier {
    /// Create a new signature verifier with no trusted keys
    pub fn new() -> Self {
        Self {
            trusted_keys: Vec::new(),
        }
    }

    /// Add a trusted public key. Weak (small-order) keys are refused.
    pub fn add_trusted_key(&mut self, key: VerifyingKey) -> Result<()> {
        if key.is_weak() {
            return Err(ElastosError::InvalidManifest(
                "Invalid public key: weak key".into(),
            ));
        }
        if !self.trusted_keys.iter().any(|k| k == &key) {
            self.trusted_keys.push(key);
        }
        Ok(())
    }

    /// Add a trusted key from hex-encoded bytes
    pub fn add_trusted_key_hex(&mut self, hex_key: &str) -> Result<()> {
        let bytes = hex::decode(hex_key.trim())
            .map_err(|e| ElastosError::InvalidManifest(format!("Invalid hex key: {}", e)))?;

        let key_bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ElastosError::InvalidManifest("Key must be 32 bytes".into()))?;

        let key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| ElastosError::InvalidManifest(format!("Invalid public key: {}", e)))?;

        self.add_trusted_key(key)
    }

    /// Load trusted keys from a file (one hex-encoded key per line)
    pub fn load_trusted_keys(&mut self, path: &Path) -> Result<usize> {
        let content = std::fs::read_to_string(path)?;
        let mut count = 0;

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            self.add_trusted_key_hex(line)?;
            count += 1;
        }

        tracing::info!("Loaded {} trusted keys from {:?}", count, path);
        Ok(count)
    }

    /// Get the number of trusted keys
    pub fn trusted_key_count(&self) -> usize {
        self.trusted_keys.len()
    }

    /// Verify a capsule's signature and name the trusted key that verified it
    ///
    /// The signature covers: SHA256(manifest_json_without_signature) || SHA256(content).
    /// `Some(key)` is the matched trusted key; `None` means no trusted key matched.
    pub fn verify_capsule(
        &self,
        manifest: &CapsuleManifest,
        content_hash: &[u8],
    ) -> Result<Option<VerifyingKey>> {
        let signature_b64 = manifest
            .signature
            .as_ref()
            .ok_or_else(|| ElastosError::InvalidManifest("Missing signature".into()))?;

        let sig_bytes = BASE64.decode(signature_b64).map_err(|e| {
            ElastosError::InvalidManifest(format!("Invalid signature encoding: {}", e))
        })?;

        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| ElastosError::InvalidManifest(format!("Invalid signature: {}", e)))?;

        // Build the message that was signed
        let message = build_signing_message(manifest, content_hash)?;

        // Try each trusted key
        for key in &self.trusted_keys {
            if key.verify_strict(&message, &signature).is_ok() {
                return Ok(Some(*key));
            }
        }

        Ok(None)
    }

    /// Check if verification is enabled (has trusted keys)
    pub fn is_enabled(&self) -> bool {
        !self.trusted_keys.is_empty()
    }
}

impl Default for SignatureVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the message to sign/verify
///
/// Format: SHA256(manifest_json_without_signature) || content_hash
fn build_signing_message(manifest: &CapsuleManifest, content_hash: &[u8]) -> Result<Vec<u8>> {
    // Create a copy of manifest without the signature for hashing
    let mut manifest_for_hash = manifest.clone();
    manifest_for_hash.signature = None;

    let manifest_json = serde_json::to_string(&manifest_for_hash).map_err(|e| {
        ElastosError::InvalidManifest(format!("Failed to serialize manifest: {}", e))
    })?;

    let manifest_hash = Sha256::digest(manifest_json.as_bytes());

    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(&manifest_hash);
    message.extend_from_slice(content_hash);

    Ok(message)
}

/// Sign a capsule manifest and content
pub fn sign_capsule(
    signing_key: &SigningKey,
    manifest: &mut CapsuleManifest,
    content_hash: &[u8],
) -> Result<()> {
    // Clear any existing signature before signing
    manifest.signature = None;

    let message = build_signing_message(manifest, content_hash)?;
    let signature = signing_key.sign(&message);

    manifest.signature = Some(BASE64.encode(signature.to_bytes()));

    Ok(())
}

/// Generate a new signing keypair
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Hash content using SHA-256
pub fn hash_content(content: &[u8]) -> Vec<u8> {
    Sha256::digest(content).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use elastos_common::{CapsuleType, Permissions, ResourceLimits};

    fn create_test_manifest() -> CapsuleManifest {
        CapsuleManifest {
            schema: elastos_common::SCHEMA_V1.into(),
            version: "0.1.0".into(),
            name: "test-capsule".into(),
            description: Some("Test".into()),
            author: Some("Test Author".into()),
            role: elastos_common::CapsuleRole::App,
            capsule_type: CapsuleType::Wasm,
            runtime_abi: None,
            bus_contract: None,
            wit_world_sha256: None,
            execution: None,
            projections: Vec::new(),
            entrypoint: "main.wasm".into(),
            requires: Vec::new(),
            provides: None,
            authority: None,
            capabilities: Vec::new(),
            interfaces: Vec::new(),
            resources: ResourceLimits::default(),
            permissions: Permissions::default(),
            microvm: None,
            providers: None,
            icon: None,
            viewer: None,
            window_policy: None,
            model_content: None,
            agent: None,
            asks: Vec::new(),
            signature: None,
        }
    }

    #[test]
    fn test_generate_keypair() {
        let (signing_key, verifying_key) = generate_keypair();
        assert_eq!(signing_key.verifying_key(), verifying_key);
    }

    #[test]
    fn test_sign_and_verify() {
        let (signing_key, verifying_key) = generate_keypair();

        let mut manifest = create_test_manifest();
        let content = b"test content";
        let content_hash = hash_content(content);

        // Sign
        sign_capsule(&signing_key, &mut manifest, &content_hash).unwrap();
        assert!(manifest.signature.is_some());

        // Verify
        let mut verifier = SignatureVerifier::new();
        verifier.add_trusted_key(verifying_key).unwrap();

        let result = verifier.verify_capsule(&manifest, &content_hash).unwrap();
        assert_eq!(result, Some(verifying_key));
    }

    #[test]
    fn verify_capsule_returns_the_matched_trusted_key() {
        let first = SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        let second = SigningKey::from_bytes(&[6u8; 32]).verifying_key();
        assert_ne!(first, second);
        let mut manifest = create_test_manifest();
        let content_hash = hash_content(b"test content");
        sign_capsule(
            &SigningKey::from_bytes(&[6u8; 32]),
            &mut manifest,
            &content_hash,
        )
        .unwrap();

        let mut verifier = SignatureVerifier::new();
        verifier.add_trusted_key(first).unwrap();
        verifier.add_trusted_key(second).unwrap();

        assert_eq!(
            verifier.verify_capsule(&manifest, &content_hash).unwrap(),
            Some(second)
        );
    }

    /// The agent declaration is under the signature: adding it to a signed
    /// manifest fails verification.
    #[test]
    fn agent_declaration_added_after_signing_fails_verification() {
        let (signing_key, verifying_key) = generate_keypair();
        let mut manifest = create_test_manifest();
        let content_hash = hash_content(b"test content");
        sign_capsule(&signing_key, &mut manifest, &content_hash).unwrap();
        let mut verifier = SignatureVerifier::new();
        verifier.add_trusted_key(verifying_key).unwrap();
        assert!(verifier
            .verify_capsule(&manifest, &content_hash)
            .unwrap()
            .is_some());
        manifest.agent = Some(elastos_common::AgentDeclaration {
            kind: elastos_common::AgentKind::Agent,
        });
        assert_eq!(
            verifier.verify_capsule(&manifest, &content_hash).unwrap(),
            None
        );
    }

    #[test]
    fn test_verify_with_wrong_key() {
        let (signing_key, _) = generate_keypair();
        let (_, wrong_verifying_key) = generate_keypair();

        let mut manifest = create_test_manifest();
        let content = b"test content";
        let content_hash = hash_content(content);

        sign_capsule(&signing_key, &mut manifest, &content_hash).unwrap();

        let mut verifier = SignatureVerifier::new();
        verifier.add_trusted_key(wrong_verifying_key).unwrap();

        let result = verifier.verify_capsule(&manifest, &content_hash).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_verify_tampered_content() {
        let (signing_key, verifying_key) = generate_keypair();

        let mut manifest = create_test_manifest();
        let content = b"original content";
        let content_hash = hash_content(content);

        sign_capsule(&signing_key, &mut manifest, &content_hash).unwrap();

        // Try to verify with different content
        let tampered_hash = hash_content(b"tampered content");

        let mut verifier = SignatureVerifier::new();
        verifier.add_trusted_key(verifying_key).unwrap();

        let result = verifier.verify_capsule(&manifest, &tampered_hash).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_verify_tampered_manifest() {
        let (signing_key, verifying_key) = generate_keypair();

        let mut manifest = create_test_manifest();
        let content = b"test content";
        let content_hash = hash_content(content);

        sign_capsule(&signing_key, &mut manifest, &content_hash).unwrap();

        // Tamper with manifest
        manifest.name = "tampered-name".into();

        let mut verifier = SignatureVerifier::new();
        verifier.add_trusted_key(verifying_key).unwrap();

        let result = verifier.verify_capsule(&manifest, &content_hash).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_add_trusted_key_hex() {
        let (_, verifying_key) = generate_keypair();
        let hex_key = hex::encode(verifying_key.as_bytes());

        let mut verifier = SignatureVerifier::new();
        verifier.add_trusted_key_hex(&hex_key).unwrap();

        assert_eq!(verifier.trusted_key_count(), 1);
    }

    #[test]
    fn test_verify_without_trusted_keys() {
        let (signing_key, _) = generate_keypair();

        let mut manifest = create_test_manifest();
        let content_hash = hash_content(b"test");

        sign_capsule(&signing_key, &mut manifest, &content_hash).unwrap();

        let verifier = SignatureVerifier::new();
        let result = verifier.verify_capsule(&manifest, &content_hash).unwrap();
        assert_eq!(result, None); // No trusted keys, so verification fails
    }

    #[test]
    fn test_verify_missing_signature() {
        let manifest = create_test_manifest(); // No signature

        let verifier = SignatureVerifier::new();
        let result = verifier.verify_capsule(&manifest, &[]);

        assert!(result.is_err());
    }

    fn identity_point_key() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        bytes
    }

    #[test]
    fn weak_trusted_key_does_not_verify_arbitrary_capsule() {
        let key = VerifyingKey::from_bytes(&identity_point_key()).unwrap();
        let mut manifest = create_test_manifest();
        manifest.name = "arbitrary".into();
        let mut sig = [0u8; 64];
        sig[0] = 1;
        manifest.signature = Some(BASE64.encode(sig));
        let verifier = SignatureVerifier {
            trusted_keys: vec![key],
        };
        let result = verifier
            .verify_capsule(&manifest, &hash_content(b"any entrypoint"))
            .unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn weak_trusted_key_is_refused_when_added() {
        let mut verifier = SignatureVerifier::new();
        assert!(verifier
            .add_trusted_key_hex(&hex::encode(identity_point_key()))
            .is_err());
        let key = VerifyingKey::from_bytes(&identity_point_key()).unwrap();
        assert!(verifier.add_trusted_key(key).is_err());
        assert_eq!(verifier.trusted_key_count(), 0);
    }

    #[test]
    fn real_key_signature_still_verifies_strictly() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let mut manifest = create_test_manifest();
        let content_hash = hash_content(b"entrypoint");
        sign_capsule(&signing_key, &mut manifest, &content_hash).unwrap();
        let mut verifier = SignatureVerifier::new();
        verifier
            .add_trusted_key_hex(&hex::encode(signing_key.verifying_key().as_bytes()))
            .unwrap();
        assert!(verifier
            .verify_capsule(&manifest, &content_hash)
            .unwrap()
            .is_some());
    }

    /// S0-compat: a one-entry map signed at the parent commit still verifies.
    #[test]
    fn pre_s0_one_entry_provider_signature_still_verifies() {
        const SIGNED: &str = r#"{"schema":"elastos.capsule/v1","version":"0.1.0","name":"legacy-one-provider","description":null,"author":null,"role":"app","type":"wasm","runtime_abi":null,"bus_contract":null,"wit_world_sha256":null,"execution":null,"projections":[],"entrypoint":"main.wasm","requires":[],"provides":null,"authority":null,"capabilities":[],"interfaces":[],"resources":{"memory_mb":64,"cpu_shares":100,"gpu":false},"permissions":{"host_process":false,"guest_network":false,"storage":[],"messaging":[]},"microvm":null,"providers":{"local":"built-in"},"icon":null,"viewer":null,"signature":"UbUqTHh5HA7mIWlILZ29Em9IG6wrJ21gmZ6il57cSHPcjFOYm7AwM5qeiXYi/5WHaRIh/28ozMxP9I4C9MwxBQ=="}"#;
        const KEY_HEX: &str = "0d7550754e0800a5d237eef5826035766b9b3e5a15868a940ab289958788e3b0";
        let manifest: CapsuleManifest = serde_json::from_str(SIGNED).unwrap();
        let mut verifier = SignatureVerifier::new();
        verifier.add_trusted_key_hex(KEY_HEX).unwrap();
        assert!(verifier
            .verify_capsule(&manifest, &hash_content(b"legacy entrypoint"))
            .unwrap()
            .is_some());
    }

    fn provider_manifest(pairs: &[(&str, &str)]) -> CapsuleManifest {
        let mut manifest = create_test_manifest();
        manifest.providers = Some(
            pairs
                .iter()
                .map(|(scheme, source)| (scheme.to_string(), source.to_string()))
                .collect(),
        );
        manifest
    }

    /// S0: the signing bytes put provider keys in map order.
    #[test]
    fn signed_multi_provider_manifest_verifies_after_a_parse() {
        let content = b"multi provider content";
        let manifest = provider_manifest(&[
            ("zeta", "z"),
            ("mu", "m"),
            ("beta", "b"),
            ("alpha", "a"),
            ("eta", "e"),
            ("kappa", "k"),
        ]);
        let signed_bytes = serde_json::to_string(&manifest).unwrap();
        assert!(signed_bytes.contains(
            r#""providers":{"alpha":"a","beta":"b","eta":"e","kappa":"k","mu":"m","zeta":"z"}"#
        ));
        let key = SigningKey::from_bytes(&[0x33; 32]);
        let mut message = Sha256::digest(signed_bytes.as_bytes()).to_vec();
        message.extend_from_slice(&hash_content(content));
        let mut parsed: CapsuleManifest = serde_json::from_str(&signed_bytes).unwrap();
        parsed.signature = Some(BASE64.encode(key.sign(&message).to_bytes()));
        let mut verifier = SignatureVerifier::new();
        verifier.add_trusted_key(key.verifying_key()).unwrap();
        assert!(verifier
            .verify_capsule(&parsed, &hash_content(content))
            .unwrap()
            .is_some());
    }

    /// S0-multi: a signature over a legacy hash order is refused; re-signing verifies.
    #[test]
    fn legacy_order_multi_provider_signature_is_refused_and_re_signs() {
        let content = b"legacy order content";
        let sorted =
            r#""providers":{"alpha":"a","beta":"b","eta":"e","kappa":"k","mu":"m","zeta":"z"}"#;
        let unsorted =
            r#""providers":{"zeta":"z","mu":"m","beta":"b","alpha":"a","eta":"e","kappa":"k"}"#;
        let manifest = provider_manifest(&[
            ("alpha", "a"),
            ("beta", "b"),
            ("eta", "e"),
            ("kappa", "k"),
            ("mu", "m"),
            ("zeta", "z"),
        ]);
        let legacy_bytes = serde_json::to_string(&manifest)
            .unwrap()
            .replace(sorted, unsorted);
        let key = SigningKey::from_bytes(&[0x34; 32]);
        let mut message = Sha256::digest(legacy_bytes.as_bytes()).to_vec();
        message.extend_from_slice(&hash_content(content));
        let mut parsed: CapsuleManifest = serde_json::from_str(&legacy_bytes).unwrap();
        parsed.signature = Some(BASE64.encode(key.sign(&message).to_bytes()));
        let mut verifier = SignatureVerifier::new();
        verifier.add_trusted_key(key.verifying_key()).unwrap();
        assert_eq!(
            verifier
                .verify_capsule(&parsed, &hash_content(content))
                .unwrap(),
            None
        );
        sign_capsule(&key, &mut parsed, &hash_content(content)).unwrap();
        assert!(verifier
            .verify_capsule(&parsed, &hash_content(content))
            .unwrap()
            .is_some());
    }
}
