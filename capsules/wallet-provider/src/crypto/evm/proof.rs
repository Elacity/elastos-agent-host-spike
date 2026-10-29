use super::super::*;
use super::payload::hex_prefixed_bytes;
use elastos_auth::{
    ethereum_signed_message_hash, normalize_evm_address, validate_evm_address, AuthChallengeV1,
    SiweMessage,
};
use serde_json::Value;

pub(crate) fn validate_siwe_challenge_message(
    challenge: &AuthChallengeV1,
    parsed: &SiweMessage,
    message: &str,
    now: u64,
) -> Result<[u8; 32], String> {
    if challenge.schema != AuthChallengeV1::SCHEMA {
        return Err("unsupported auth challenge schema".to_string());
    }
    if challenge.expires_at <= now {
        return Err("auth challenge expired".to_string());
    }
    if parsed.domain != challenge.domain {
        return Err("SIWE domain does not match challenge".to_string());
    }
    if parsed.uri != challenge.uri {
        return Err("SIWE URI does not match challenge".to_string());
    }
    if parsed.version != "1" {
        return Err("unsupported SIWE version".to_string());
    }
    if parsed.chain_id != challenge.chain_id {
        return Err("SIWE chain ID does not match challenge".to_string());
    }
    if parsed.nonce != challenge.nonce {
        return Err("SIWE nonce does not match challenge".to_string());
    }
    if normalize_evm_address(&parsed.address) != normalize_evm_address(&challenge.address) {
        return Err("SIWE address does not match challenge".to_string());
    }
    if parsed.issued_at > now.saturating_add(300) {
        return Err("SIWE issued-at is in the future".to_string());
    }
    let Some(expires_at) = parsed.expires_at else {
        return Err("SIWE expiration-time is required".to_string());
    };
    if expires_at <= now {
        return Err("SIWE proof expired".to_string());
    }
    if expires_at > challenge.expires_at {
        return Err("SIWE proof outlives challenge".to_string());
    }
    if parsed.resources != challenge.resources {
        return Err("SIWE resources do not match challenge".to_string());
    }
    if !parsed
        .resources
        .iter()
        .any(|resource| resource == &challenge.challenge_resource())
    {
        return Err("SIWE resources missing challenge binding".to_string());
    }
    if message != challenge.siwe_message() {
        return Err("SIWE message does not match challenge".to_string());
    }
    Ok(ethereum_signed_message_hash(message.as_bytes()))
}

pub(crate) fn validate_erc1271_chain_proof(
    proof: &Value,
    parsed: &SiweMessage,
    message_hash: &[u8; 32],
    signature: &str,
) -> Result<(), String> {
    if proof.get("schema").and_then(Value::as_str) != Some("elastos.chain.erc1271_proof/v1") {
        return Err("unsupported ERC-1271 proof schema".to_string());
    }
    if proof.get("valid").and_then(Value::as_bool) != Some(true) {
        return Err("ERC-1271 signature was not accepted by the contract".to_string());
    }
    let chain_id = proof
        .get("chain_id")
        .and_then(Value::as_u64)
        .ok_or_else(|| "ERC-1271 proof missing chain_id".to_string())?;
    if chain_id != parsed.chain_id {
        return Err("ERC-1271 proof chain_id does not match SIWE message".to_string());
    }
    let contract = proof
        .get("contract")
        .and_then(Value::as_str)
        .ok_or_else(|| "ERC-1271 proof missing contract".to_string())?;
    validate_evm_address(contract)?;
    if normalize_evm_address(contract) != parsed.address {
        return Err("ERC-1271 proof contract does not match SIWE address".to_string());
    }
    let expected_message_hash = format!("0x{}", hex::encode(message_hash));
    if proof.get("message_hash").and_then(Value::as_str) != Some(expected_message_hash.as_str()) {
        return Err("ERC-1271 proof message_hash mismatch".to_string());
    }
    let signature_bytes = hex_prefixed_bytes(signature, None, "signature")?;
    if signature_bytes.is_empty() {
        return Err("signature must not be empty".to_string());
    }
    let expected_signature_hash = bytes_hash(&signature_bytes);
    if proof.get("signature_hash").and_then(Value::as_str) != Some(expected_signature_hash.as_str())
    {
        return Err("ERC-1271 proof signature_hash mismatch".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod uf_evm_proof_tests {
    use super::*;
    use elastos_auth::AuthChallengeInput;
    use k256::ecdsa::SigningKey;
    use serde_json::json;

    /// The moment the validators read as "now" in every case below.
    const NOW: u64 = 1_800_000_000;

    /// A challenge both validators accept: issued one minute before `NOW`,
    /// expiring four minutes after it, with its own challenge resource.
    fn base_challenge() -> AuthChallengeV1 {
        AuthChallengeV1::new(AuthChallengeInput {
            challenge_id: "challenge-1".to_string(),
            domain: "https://elastos.local".to_string(),
            uri: "https://elastos.local/apps/home/".to_string(),
            address: "0x00000000000000000000000000000000000000a1".to_string(),
            chain_id: 20,
            nonce: "abc123".to_string(),
            issued_at: NOW - 60,
            ttl_secs: 300,
            resources: vec!["elastos://auth/challenge/challenge-1".to_string()],
        })
    }

    /// The challenge and the parsed message a case starts from.
    fn binding() -> (AuthChallengeV1, SiweMessage, String) {
        let challenge = base_challenge();
        let message = challenge.siwe_message();
        let parsed = elastos_auth::parse_siwe_message(&message).expect("the challenge text parses");
        (challenge, parsed, message)
    }

    fn refuse_siwe(
        challenge: &AuthChallengeV1,
        parsed: &SiweMessage,
        message: &str,
        now: u64,
    ) -> String {
        validate_siwe_challenge_message(challenge, parsed, message, now).unwrap_err()
    }

    /// The parsed message, message hash and signature an ERC-1271 case starts
    /// from, with the hash taken from the function the caller uses.
    fn erc1271_binding() -> (SiweMessage, [u8; 32], String) {
        let (challenge, parsed, message) = binding();
        let message_hash = validate_siwe_challenge_message(&challenge, &parsed, &message, NOW)
            .expect("the base challenge binds");
        let signing_key = SigningKey::from_bytes((&[11u8; 32]).into()).expect("a valid key");
        let signature = sign_evm_message(&signing_key, message.as_bytes()).expect("a signature");
        (parsed, message_hash, signature)
    }

    /// An ERC-1271 proof the validator accepts, built from the field names of
    /// the shape `verify_contract_proof` receives.
    fn erc1271_proof(message_hash: &[u8; 32], contract: &str, signature: &str) -> Value {
        let signature_bytes =
            hex_prefixed_bytes(signature, None, "signature").expect("the signature is hex");
        json!({
            "schema": "elastos.chain.erc1271_proof/v1",
            "chain_id": 20,
            "contract": contract,
            "message_hash": format!("0x{}", hex::encode(message_hash)),
            "signature_hash": bytes_hash(&signature_bytes),
            "valid": true,
        })
    }

    fn refuse_erc1271(proof: &Value, parsed: &SiweMessage, hash: &[u8; 32], sig: &str) -> String {
        validate_erc1271_chain_proof(proof, parsed, hash, sig).unwrap_err()
    }

    /// Pins `unsupported auth challenge schema` (`:16`).
    #[test]
    fn siwe_refuses_unsupported_challenge_schema() {
        let (challenge, parsed, message) = binding();
        let mut tampered = challenge.clone();
        tampered.schema = "elastos.auth.challenge/v0".to_string();
        assert_eq!(
            refuse_siwe(&tampered, &parsed, &message, NOW),
            "unsupported auth challenge schema"
        );
    }

    /// Pins `auth challenge expired` (`:19`).
    #[test]
    fn siwe_refuses_expired_challenge() {
        let (challenge, parsed, message) = binding();
        assert_eq!(
            refuse_siwe(&challenge, &parsed, &message, challenge.expires_at),
            "auth challenge expired"
        );
    }

    /// Pins `SIWE domain does not match challenge` (`:22`).
    #[test]
    fn siwe_refuses_domain_mismatch() {
        let (challenge, mut parsed, message) = binding();
        parsed.domain = "https://other.local".to_string();
        assert_eq!(
            refuse_siwe(&challenge, &parsed, &message, NOW),
            "SIWE domain does not match challenge"
        );
    }

    /// Pins `SIWE URI does not match challenge` (`:25`).
    #[test]
    fn siwe_refuses_uri_mismatch() {
        let (challenge, mut parsed, message) = binding();
        parsed.uri = "https://elastos.local/other/".to_string();
        assert_eq!(
            refuse_siwe(&challenge, &parsed, &message, NOW),
            "SIWE URI does not match challenge"
        );
    }

    /// Pins `unsupported SIWE version` (`:28`).
    #[test]
    fn siwe_refuses_unsupported_version() {
        let (challenge, mut parsed, message) = binding();
        parsed.version = "2".to_string();
        assert_eq!(
            refuse_siwe(&challenge, &parsed, &message, NOW),
            "unsupported SIWE version"
        );
    }

    /// Pins `SIWE chain ID does not match challenge` (`:31`).
    #[test]
    fn siwe_refuses_chain_id_mismatch() {
        let (challenge, mut parsed, message) = binding();
        parsed.chain_id = 21;
        assert_eq!(
            refuse_siwe(&challenge, &parsed, &message, NOW),
            "SIWE chain ID does not match challenge"
        );
    }

    /// Pins `SIWE nonce does not match challenge` (`:34`).
    #[test]
    fn siwe_refuses_nonce_mismatch() {
        let (challenge, mut parsed, message) = binding();
        parsed.nonce = "abc124".to_string();
        assert_eq!(
            refuse_siwe(&challenge, &parsed, &message, NOW),
            "SIWE nonce does not match challenge"
        );
    }

    /// Pins `SIWE address does not match challenge` (`:37`).
    #[test]
    fn siwe_refuses_address_mismatch() {
        let (challenge, mut parsed, message) = binding();
        parsed.address = "0x00000000000000000000000000000000000000b2".to_string();
        assert_eq!(
            refuse_siwe(&challenge, &parsed, &message, NOW),
            "SIWE address does not match challenge"
        );
    }

    /// Pins `SIWE issued-at is in the future` (`:40`).
    #[test]
    fn siwe_refuses_future_issued_at() {
        let (challenge, mut parsed, message) = binding();
        parsed.issued_at = NOW + 301;
        assert_eq!(
            refuse_siwe(&challenge, &parsed, &message, NOW),
            "SIWE issued-at is in the future"
        );
    }

    /// Pins `SIWE expiration-time is required` (`:43`).
    #[test]
    fn siwe_refuses_missing_expiration_time() {
        let (challenge, mut parsed, message) = binding();
        parsed.expires_at = None;
        assert_eq!(
            refuse_siwe(&challenge, &parsed, &message, NOW),
            "SIWE expiration-time is required"
        );
    }

    /// Pins `SIWE proof expired` (`:46`).
    #[test]
    fn siwe_refuses_expired_proof() {
        let (challenge, mut parsed, message) = binding();
        parsed.expires_at = Some(NOW - 1);
        assert_eq!(
            refuse_siwe(&challenge, &parsed, &message, NOW),
            "SIWE proof expired"
        );
    }

    /// Pins `SIWE proof outlives challenge` (`:49`).
    #[test]
    fn siwe_refuses_proof_outliving_challenge() {
        let (challenge, mut parsed, message) = binding();
        parsed.expires_at = Some(challenge.expires_at + 1);
        assert_eq!(
            refuse_siwe(&challenge, &parsed, &message, NOW),
            "SIWE proof outlives challenge"
        );
    }

    /// Pins `SIWE resources do not match challenge` (`:52`).
    #[test]
    fn siwe_refuses_resource_mismatch() {
        let (challenge, mut parsed, message) = binding();
        parsed.resources = vec!["elastos://auth/resource/other".to_string()];
        assert_eq!(
            refuse_siwe(&challenge, &parsed, &message, NOW),
            "SIWE resources do not match challenge"
        );
    }

    /// Pins `SIWE resources missing challenge binding` (`:59`): the challenge
    /// and the message carry the same resource list, and none of it is the
    /// challenge's own binding.
    #[test]
    fn siwe_refuses_resources_without_challenge_binding() {
        let mut challenge = base_challenge();
        challenge.resources = vec!["elastos://auth/resource/other".to_string()];
        let message = challenge.siwe_message();
        let parsed = elastos_auth::parse_siwe_message(&message).expect("the challenge text parses");
        assert_eq!(
            refuse_siwe(&challenge, &parsed, &message, NOW),
            "SIWE resources missing challenge binding"
        );
    }

    /// Pins `SIWE message does not match challenge` (`:62`): the statement is
    /// not a parsed field, so the parsed value still binds and only the text
    /// comparison refuses.
    #[test]
    fn siwe_refuses_message_text_mismatch() {
        let (challenge, parsed, message) = binding();
        let resaid = message.replace("Sign in to ElastOS Runtime.", "Sign in to ElastOS Runtime!");
        assert_ne!(resaid, challenge.siwe_message());
        assert_eq!(
            refuse_siwe(&challenge, &parsed, &resaid, NOW),
            "SIWE message does not match challenge"
        );
    }

    /// Pins `unsupported ERC-1271 proof schema` (`:74`).
    #[test]
    fn erc1271_refuses_unsupported_schema() {
        let (parsed, hash, signature) = erc1271_binding();
        let mut proof = erc1271_proof(&hash, &parsed.address, &signature);
        proof["schema"] = json!("elastos.chain.erc1271_proof/v0");
        assert_eq!(
            refuse_erc1271(&proof, &parsed, &hash, &signature),
            "unsupported ERC-1271 proof schema"
        );
    }

    /// Pins `ERC-1271 signature was not accepted by the contract` (`:77`).
    #[test]
    fn erc1271_refuses_contract_rejection() {
        let (parsed, hash, signature) = erc1271_binding();
        let mut proof = erc1271_proof(&hash, &parsed.address, &signature);
        proof["valid"] = json!(false);
        assert_eq!(
            refuse_erc1271(&proof, &parsed, &hash, &signature),
            "ERC-1271 signature was not accepted by the contract"
        );
    }

    /// Pins `ERC-1271 proof missing chain_id` (`:82`).
    #[test]
    fn erc1271_refuses_missing_chain_id() {
        let (parsed, hash, signature) = erc1271_binding();
        let mut proof = erc1271_proof(&hash, &parsed.address, &signature);
        proof
            .as_object_mut()
            .expect("proof is an object")
            .remove("chain_id");
        assert_eq!(
            refuse_erc1271(&proof, &parsed, &hash, &signature),
            "ERC-1271 proof missing chain_id"
        );
    }

    /// Pins `ERC-1271 proof chain_id does not match SIWE message` (`:84`).
    #[test]
    fn erc1271_refuses_chain_id_mismatch() {
        let (parsed, hash, signature) = erc1271_binding();
        let mut proof = erc1271_proof(&hash, &parsed.address, &signature);
        proof["chain_id"] = json!(parsed.chain_id + 1);
        assert_eq!(
            refuse_erc1271(&proof, &parsed, &hash, &signature),
            "ERC-1271 proof chain_id does not match SIWE message"
        );
    }

    /// Pins `ERC-1271 proof missing contract` (`:89`).
    #[test]
    fn erc1271_refuses_missing_contract() {
        let (parsed, hash, signature) = erc1271_binding();
        let mut proof = erc1271_proof(&hash, &parsed.address, &signature);
        proof
            .as_object_mut()
            .expect("proof is an object")
            .remove("contract");
        assert_eq!(
            refuse_erc1271(&proof, &parsed, &hash, &signature),
            "ERC-1271 proof missing contract"
        );
    }

    /// Pins `ERC-1271 proof contract does not match SIWE address` (`:92`).
    #[test]
    fn erc1271_refuses_contract_mismatch() {
        let (parsed, hash, signature) = erc1271_binding();
        let mut proof = erc1271_proof(&hash, &parsed.address, &signature);
        proof["contract"] = json!("0x00000000000000000000000000000000000000b2");
        assert_eq!(
            refuse_erc1271(&proof, &parsed, &hash, &signature),
            "ERC-1271 proof contract does not match SIWE address"
        );
    }

    /// Pins `ERC-1271 proof message_hash mismatch` (`:96`).
    #[test]
    fn erc1271_refuses_message_hash_mismatch() {
        let (parsed, hash, signature) = erc1271_binding();
        let mut proof = erc1271_proof(&hash, &parsed.address, &signature);
        proof["message_hash"] = json!(format!("0x{}", "00".repeat(32)));
        assert_ne!(
            proof["message_hash"],
            json!(format!("0x{}", hex::encode(hash)))
        );
        assert_eq!(
            refuse_erc1271(&proof, &parsed, &hash, &signature),
            "ERC-1271 proof message_hash mismatch"
        );
    }

    /// Pins `signature must not be empty` (`:100`).
    #[test]
    fn erc1271_refuses_empty_signature() {
        let (parsed, hash, _) = erc1271_binding();
        let proof = erc1271_proof(&hash, &parsed.address, "0x");
        assert_eq!(
            refuse_erc1271(&proof, &parsed, &hash, "0x"),
            "signature must not be empty"
        );
    }

    /// Pins `ERC-1271 proof signature_hash mismatch` (`:105`).
    #[test]
    fn erc1271_refuses_signature_hash_mismatch() {
        let (parsed, hash, signature) = erc1271_binding();
        let mut proof = erc1271_proof(&hash, &parsed.address, &signature);
        proof["signature_hash"] = json!(format!("0x{}", "00".repeat(32)));
        assert_ne!(
            proof["signature_hash"],
            json!(bytes_hash(
                &hex_prefixed_bytes(&signature, None, "signature").expect("the signature is hex")
            ))
        );
        assert_eq!(
            refuse_erc1271(&proof, &parsed, &hash, &signature),
            "ERC-1271 proof signature_hash mismatch"
        );
    }
}
