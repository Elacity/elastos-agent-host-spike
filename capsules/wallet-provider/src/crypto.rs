use super::*;
use k256::ecdsa::SigningKey;

mod bitcoin;
mod evm;

pub(super) use bitcoin::*;
pub(super) use evm::*;

const PROTECTED_CONTENT_RIGHTS_APPROVAL_PAYLOAD_SCHEMA: &str =
    "elastos.wallet.protected-content-rights-approval/v1";

pub(super) fn account_id(chain_namespace: &str, address: &str) -> String {
    format!("wallet:{chain_namespace}:{address}")
}

pub(super) fn managed_address_for_signing_key(
    signing_key: &SigningKey,
    chain_namespace: &str,
) -> Result<String, String> {
    match managed_proof_type(chain_namespace)? {
        MANAGED_EVM_PROOF_TYPE => Ok(evm_address_for_signing_key(signing_key)),
        MANAGED_BTC_P2WPKH_PROOF_TYPE => btc_p2wpkh_address_for_signing_key(signing_key),
        _ => Err("unsupported managed wallet proof type".to_string()),
    }
}

pub(super) fn managed_signature_envelope(request: &WalletApprovalRequest) -> Value {
    json!({
        "schema": "elastos.wallet.managed_signature_payload/v1",
        "request_id": request.request_id.clone(),
        "principal_id": request.principal_id.clone(),
        "account_id": request.account_id.clone(),
        "chain_namespace": request.chain_namespace.clone(),
        "address": request.address.clone(),
        "intent": request.intent.clone(),
        "capsule_id": request.requested_by_actor.clone(),
        "resource": request.resource.clone(),
        "reason": request.reason.clone(),
        "payload_hash": request.payload_hash.clone(),
        "payload": request.payload.clone(),
    })
}

fn browser_account_access_attestation(request: &WalletApprovalRequest) -> Value {
    json!({
        "schema": "elastos.browser.account-access-attestation/v1",
        "request_id": request.request_id,
        "principal_id": request.principal_id,
        "account_id": request.account_id,
        "chain_namespace": request.chain_namespace,
        "address": request.address,
        "intent": request.intent,
        "requested_by_actor": request.requested_by_actor,
        "resource": request.resource,
        "reason": request.reason,
        "payload_hash": request.payload_hash,
        "payload": request.payload,
    })
}

pub(super) struct ManagedSignatureOutput {
    pub(super) kind: ManagedSignatureKind,
    pub(super) authority: String,
    pub(super) payload: Value,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ManagedSignatureKind {
    Message,
    Transaction,
}

pub(super) fn sign_managed_approval(
    signing_key: &SigningKey,
    request: &WalletApprovalRequest,
) -> Result<ManagedSignatureOutput, String> {
    if request.intent == PROTECTED_CONTENT_RIGHTS_SIGNATURE_INTENT {
        let (rights_request, canonical_bytes) =
            protected_content_rights_request_from_payload(&request.payload)?;
        let signature = sign_evm_message(signing_key, &canonical_bytes)?;
        let signed_request = WalletSignedRightsRequestV1::new(
            rights_request,
            canonicalize_evm_signature(&signature)
                .map_err(|err| format!("invalid managed rights signature: {err}"))?,
        )
        .map_err(|err| err.to_string())?;
        let payload = serde_json::to_value(
            ProtectedContentRightsSignatureResultV1::new(
                request.account_id.clone(),
                request.address.clone(),
                hex::encode(
                    signed_request
                        .canonical_bytes()
                        .map_err(|err| err.to_string())?,
                ),
            )
            .map_err(|err| err.to_string())?,
        )
        .map_err(|err| err.to_string())?;
        return Ok(ManagedSignatureOutput {
            kind: ManagedSignatureKind::Message,
            authority: signature,
            payload,
        });
    }
    if request.intent == "bitcoin_bip322_proof" {
        let (signature, payload) = sign_bip322_simple_p2wpkh_approval(signing_key, request)?;
        return Ok(ManagedSignatureOutput {
            kind: ManagedSignatureKind::Message,
            authority: signature,
            payload,
        });
    }
    if request.chain_namespace.starts_with("bip122:") {
        return Err(
            "managed Bitcoin accounts only support bitcoin_bip322_proof signing".to_string(),
        );
    }
    if request.intent == "browser_account_access" {
        let payload = browser_account_access_attestation(request);
        let payload_bytes = serde_json::to_vec(&payload).map_err(|err| err.to_string())?;
        let signature = sign_evm_message(signing_key, &payload_bytes)?;
        return Ok(ManagedSignatureOutput {
            kind: ManagedSignatureKind::Message,
            authority: signature,
            payload,
        });
    }
    if request.intent == "browser_personal_sign" {
        let (signature, payload) = sign_browser_personal_sign_approval(signing_key, request)?;
        return Ok(ManagedSignatureOutput {
            kind: ManagedSignatureKind::Message,
            authority: signature,
            payload,
        });
    }
    if request.intent == "browser_typed_data_sign" {
        let (signature, payload) = sign_browser_typed_data_approval(signing_key, request)?;
        return Ok(ManagedSignatureOutput {
            kind: ManagedSignatureKind::Message,
            authority: signature,
            payload,
        });
    }
    if request.intent == "transaction_intent" {
        let (signed_transaction, payload) = sign_eip155_legacy_transaction(signing_key, request)?;
        return Ok(ManagedSignatureOutput {
            kind: ManagedSignatureKind::Transaction,
            authority: signed_transaction,
            payload,
        });
    }

    let envelope = managed_signature_envelope(request);
    let envelope_bytes = serde_json::to_vec(&envelope).map_err(|err| err.to_string())?;
    let signature = sign_evm_message(signing_key, &envelope_bytes)?;
    Ok(ManagedSignatureOutput {
        kind: ManagedSignatureKind::Message,
        authority: signature,
        payload: envelope,
    })
}

pub(super) fn external_wallet_handoff(request: &WalletApprovalRequest) -> Result<Value, String> {
    if request.intent == "transaction_intent" {
        let chain_id = payload_u64(&request.payload, "chain_id")?;
        let transaction = json!({
            "from": payload_str(&request.payload, "from")?,
            "to": payload_str(&request.payload, "to")?,
            "value": payload_str(&request.payload, "value")?,
            "data": payload_str(&request.payload, "data")?,
            "gas": payload_str(&request.payload, "gas_limit")?,
            "gasPrice": payload_str(&request.payload, "gas_price")?,
            "nonce": payload_str(&request.payload, "nonce")?,
            "chainId": format!("0x{chain_id:x}"),
        });
        return Ok(json!({
            "schema": "elastos.wallet.webconnect_handoff/v1",
            "request_id": request.request_id,
            "intent": request.intent,
            "payload_hash": request.payload_hash,
            "signer": request.address,
            "transaction": transaction,
            "status": "awaiting_wallet_transaction"
        }));
    }
    if request.intent == PROTECTED_CONTENT_RIGHTS_SIGNATURE_INTENT {
        let (_, canonical_bytes) = protected_content_rights_request_from_payload(&request.payload)?;
        return Ok(json!({
            "schema": "elastos.wallet.webconnect_handoff/v1",
            "request_id": request.request_id,
            "intent": request.intent,
            "payload_hash": request.payload_hash,
            "signer": request.address,
            "message": format!("0x{}", hex::encode(canonical_bytes)),
            "signature_type": "personal_sign",
            "status": "awaiting_wallet_signature"
        }));
    }
    let message = external_signature_message(request)?;
    Ok(json!({
        "schema": "elastos.wallet.webconnect_handoff/v1",
        "request_id": request.request_id,
        "intent": request.intent,
        "payload_hash": request.payload_hash,
        "signer": request.address,
        "message": message,
        "signature_type": if request.intent == "bitcoin_bip322_proof" {
            bitcoin_signature_type_for_proof_type(&request.proof_type)
        } else {
            "personal_sign"
        },
        "status": "awaiting_wallet_signature"
    }))
}

pub(super) fn managed_signed_result(
    request: &WalletApprovalRequest,
    signed: &ManagedSignatureOutput,
) -> Option<Value> {
    if request.intent == "browser_account_access" {
        return Some(json!({
            "schema": "elastos.browser.account-access-result/v1",
            "request_id": request.request_id,
            "permission": "eth_accounts",
            "principal_id": request.payload.get("principal_id").cloned().unwrap_or(Value::Null),
            "session_id": request.payload.get("session_id").cloned().unwrap_or(Value::Null),
            "launch_id": request.payload.get("launch_id").cloned().unwrap_or(Value::Null),
            "proof_binding_id": request.payload.get("proof_binding_id").cloned().unwrap_or(Value::Null),
            "origin": request.payload.get("origin").cloned().unwrap_or(Value::Null),
            "page_url": request.payload.get("page_url").cloned().unwrap_or(Value::Null),
            "account_id": request.account_id,
            "requested_chain_namespace": request.payload.get("requested_chain_namespace").cloned().unwrap_or(Value::Null),
            "chain_namespaces": request.payload.get("chain_namespaces").cloned().unwrap_or(Value::Null),
            "address": request.address,
            "grant_expires_at": request.payload.get("grant_expires_at").cloned().unwrap_or(Value::Null),
            "payload_hash": request.payload_hash,
        }));
    }
    if request.intent == "browser_personal_sign" {
        return browser_personal_sign_result(request, &signed.authority);
    }
    if request.intent == "browser_typed_data_sign" {
        return browser_typed_data_sign_result(request, &signed.authority);
    }
    if request.intent == "transaction_intent" && signed.kind == ManagedSignatureKind::Transaction {
        return Some(json!({
            "schema": "elastos.wallet.signed-transaction-result/v1",
            "request_id": request.request_id,
            "method": "eth_sendTransaction",
            "signed_transaction": signed.authority,
            "transaction_hash": signed.payload.get("transaction_hash").cloned().unwrap_or(Value::Null),
            "signer": request.address,
            "chain_namespace": request.chain_namespace,
            "payload_hash": request.payload_hash,
            "page_url": request.payload.get("page_url").cloned().unwrap_or(Value::Null),
            "origin": request.payload.get("origin").cloned().unwrap_or(Value::Null),
        }));
    }
    if request.intent == PROTECTED_CONTENT_RIGHTS_SIGNATURE_INTENT {
        return Some(signed.payload.clone());
    }
    None
}

pub(super) fn protected_content_rights_approval_payload(
    canonical_rights_request_hex: &str,
) -> Value {
    json!({
        "schema": PROTECTED_CONTENT_RIGHTS_APPROVAL_PAYLOAD_SCHEMA,
        "canonical_rights_request_hex": canonical_rights_request_hex,
    })
}

pub(super) fn protected_content_rights_request_from_hex(
    canonical_rights_request_hex: &str,
) -> Result<(RightsRequestV1, Vec<u8>), String> {
    let canonical_rights_request_hex = canonical_rights_request_hex.trim();
    if canonical_rights_request_hex.is_empty() {
        return Err("protected-content rights request hex is required".to_string());
    }
    if canonical_rights_request_hex.len() > MAX_PROTECTED_CONTENT_RIGHTS_WIRE_BYTES * 2 {
        return Err(format!(
            "protected-content rights request exceeds the Wallet wire limit of {MAX_PROTECTED_CONTENT_RIGHTS_WIRE_BYTES} bytes"
        ));
    }
    if !canonical_rights_request_hex.len().is_multiple_of(2)
        || !canonical_rights_request_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(
            "protected-content rights request must be lowercase hex without a prefix".to_string(),
        );
    }
    let canonical_bytes = hex::decode(canonical_rights_request_hex)
        .map_err(|err| format!("invalid protected-content rights request hex: {err}"))?;
    if canonical_bytes.is_empty() {
        return Err("protected-content rights request hex is required".to_string());
    }
    if canonical_bytes.len() > MAX_PROTECTED_CONTENT_RIGHTS_WIRE_BYTES {
        return Err(format!(
            "protected-content rights request exceeds the Wallet wire limit of {MAX_PROTECTED_CONTENT_RIGHTS_WIRE_BYTES} bytes"
        ));
    }
    let request = RightsRequestV1::from_canonical_bytes(&canonical_bytes)
        .map_err(|err| format!("invalid protected-content rights request: {err}"))?;
    Ok((request, canonical_bytes))
}

pub(super) fn protected_content_rights_request_from_payload(
    payload: &Value,
) -> Result<(RightsRequestV1, Vec<u8>), String> {
    let object = payload.as_object().ok_or_else(|| {
        "protected-content rights approval payload must be a JSON object".to_string()
    })?;
    if object.len() != 2
        || !object.contains_key("schema")
        || !object.contains_key("canonical_rights_request_hex")
    {
        return Err("protected-content rights approval payload has unsupported fields".to_string());
    }
    if object.get("schema").and_then(Value::as_str)
        != Some(PROTECTED_CONTENT_RIGHTS_APPROVAL_PAYLOAD_SCHEMA)
    {
        return Err("protected-content rights approval payload has unsupported schema".to_string());
    }
    let canonical_rights_request_hex = object
        .get("canonical_rights_request_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            "protected-content rights approval payload missing canonical_rights_request_hex"
                .to_string()
        })?;
    protected_content_rights_request_from_hex(canonical_rights_request_hex)
}

pub(super) fn validate_protected_content_rights_request_account(
    rights_request: &RightsRequestV1,
    account: &LinkedAccount,
    now: u64,
) -> Result<(), String> {
    if !account.chain_namespace.starts_with("eip155:") {
        return Err("protected-content rights signing requires an EVM account".to_string());
    }
    if now.saturating_add(RIGHTS_CLOCK_SKEW_SECS) < rights_request.issued_at() {
        return Err("protected-content rights request is not yet valid".to_string());
    }
    if now >= rights_request.expires_at() {
        return Err("protected-content rights request expired".to_string());
    }
    let bound_wallet = wallet_address_hex(rights_request.binding().wallet());
    if normalize_evm_address(&bound_wallet) != normalize_evm_address(&account.address) {
        return Err(
            "protected-content rights request Wallet does not match the selected account"
                .to_string(),
        );
    }
    Ok(())
}

fn wallet_address_hex(wallet: WalletAddress) -> String {
    format!("0x{}", hex::encode(wallet.as_bytes()))
}

pub(super) fn validate_protected_content_rights_result_for_request(
    result: &ProtectedContentRightsSignatureResultV1,
    request: &WalletApprovalRequest,
) -> Result<(), String> {
    result.validate().map_err(|err| err.to_string())?;
    if result.account_id != request.account_id {
        return Err(
            "protected-content rights signature result account_id does not match the approval"
                .to_string(),
        );
    }
    if !result.signer.eq_ignore_ascii_case(&request.address) {
        return Err(
            "protected-content rights signature result signer does not match the approval"
                .to_string(),
        );
    }
    let signed_bytes = hex::decode(&result.wallet_signed_rights_request_hex)
        .map_err(|err| format!("invalid stored protected-content rights result hex: {err}"))?;
    let signed = WalletSignedRightsRequestV1::from_canonical_bytes(&signed_bytes)
        .map_err(|err| format!("invalid stored protected-content signed request: {err}"))?;
    let (expected_request, expected_bytes) =
        protected_content_rights_request_from_payload(&request.payload)?;
    if signed.request() != &expected_request {
        return Err(
            "protected-content rights signed request does not match the approved request"
                .to_string(),
        );
    }
    if !result
        .signer
        .eq_ignore_ascii_case(&wallet_address_hex(signed.request().binding().wallet()))
    {
        return Err(
            "protected-content rights signature result signer does not match the bound Wallet"
                .to_string(),
        );
    }
    if signed
        .request()
        .canonical_bytes()
        .map_err(|err| err.to_string())?
        != expected_bytes
    {
        return Err(
            "protected-content rights signed request bytes do not match the approved request"
                .to_string(),
        );
    }
    let mut replay_check = ProtectedContentRightsResultReplayCheck;
    signed
        .verify(
            &RightsVerificationContextV1::new(
                expected_request.binding().clone(),
                expected_request.action(),
                expected_request.recipient().clone(),
                expected_request.issued_at(),
            ),
            &mut replay_check,
        )
        .map_err(|err| format!("invalid stored protected-content signed request: {err}"))?;
    Ok(())
}

struct ProtectedContentRightsResultReplayCheck;

impl AtomicReplayClaimer for ProtectedContentRightsResultReplayCheck {
    fn claim(
        &mut self,
        _key: ReplayClaimKeyV1,
        _expires_at: u64,
        _now: u64,
    ) -> Result<(), ReplayClaimError> {
        Ok(())
    }
}

pub(super) fn external_signature_message(
    request: &WalletApprovalRequest,
) -> Result<String, String> {
    if request.intent == "browser_personal_sign" {
        return request
            .payload
            .get("message")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or_else(|| "Browser wallet signature payload missing message".to_string());
    }
    if request.intent == "browser_typed_data_sign" {
        return request
            .payload
            .get("typed_data_canonical")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or_else(|| "Browser typed-data payload missing canonical typed data".to_string());
    }
    if request.intent == "bitcoin_bip322_proof" {
        return request
            .payload
            .get("message")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or_else(|| "Bitcoin BIP-322 payload missing message".to_string());
    }
    Ok(format!(
        "ElastOS Wallet Approval\n\nRequest: {}\nIntent: {}\nCapsule: {}\nResource: {}\nReason: {}\nPayload SHA-256: {}\nAccount: {}\nExpires At: {}",
        request.request_id,
        request.intent,
        request.requested_by_actor,
        request.resource,
        request.reason,
        request.payload_hash,
        request.address,
        request.expires_at
    ))
}

/// One test per refusal string the two protected-content rights wire readers
/// raise, each asserting the whole `Err` value. They pin answers the readers
/// already give: they add no rule and register no falsifier. They prove what
/// the wallet provider refuses to sign, not confinement: the Runtime decides
/// whether the provider runs at all.
///
/// `protected-content rights request hex is required` stands at `:280` and
/// `:300`, and `protected-content rights request exceeds the Wallet wire limit
/// of {MAX_PROTECTED_CONTENT_RIGHTS_WIRE_BYTES} bytes` at `:283` and `:302`, so
/// one test each holds its two sites.
///
/// `invalid protected-content rights request hex: {err}` (`:297`) is recorded
/// as unreachable instead of tested. `hex::decode` follows the length and
/// all-lowercase-hex-digit checks above it, which accept exactly the strings
/// `hex::decode` decodes, so that mapping never produces an error.
///
/// Two further lines are unreachable. `hex is required` at `:300` follows a
/// non-empty, even-length, all-hex-digit string, which decodes to a non-empty
/// byte vector, so `:280` already refused. The `wire limit` string at `:302`
/// follows a decode of half the character length, so `:283` already refused at
/// twice that length.
#[cfg(test)]
mod uf_crypto_wire_refusal_tests {
    use super::*;
    use elastos_protected_content_contracts::ContractError;
    use serde_json::json;

    /// The schema string every `protected_content_rights_request_from_payload`
    /// case either carries or deliberately changes, read from this file rather
    /// than pasted.
    const SCHEMA: &str = PROTECTED_CONTENT_RIGHTS_APPROVAL_PAYLOAD_SCHEMA;

    /// Catches removal of the empty-hex refusal in
    /// `protected_content_rights_request_from_hex`. `hex is required` stands
    /// twice, at `:280` on the trimmed string and at `:300` on the decoded
    /// bytes. The second site cannot refuse on its own: a non-empty,
    /// even-length, all-hex-digit string decodes to a non-empty byte vector, so
    /// `:280` already refused. The mutation this test pins is therefore the
    /// pair, because removing either guard alone still answers this string from
    /// the other one.
    ///
    /// The second case is whitespace only, so the reader reaches :280 through
    /// its trim; a missing trim leaves a non-hex character and the case fails
    /// on the reason rather than on the guard.
    #[test]
    fn rejects_empty_hex() {
        let reason = "protected-content rights request hex is required";
        for input in ["", "  \t\n "] {
            assert_eq!(
                protected_content_rights_request_from_hex(input).unwrap_err(),
                reason
            );
        }
    }

    /// Catches removal of the wire-limit refusal in
    /// `protected_content_rights_request_from_hex`. The same string is raised
    /// at `:283` on the character length and at `:302` on the decoded byte
    /// length. The second site cannot refuse on its own: the decoded length is
    /// half the character length, so `:283` already refused at twice that
    /// length. The mutation this test pins is therefore the pair, because
    /// removing `:283` alone still answers this string from `:302`.
    ///
    /// The input is one byte past the limit, is otherwise canonical lowercase
    /// hex, and carries the limit formatted from the crate's constant.
    #[test]
    fn rejects_hex_over_the_wire_limit() {
        let reason = format!(
            "protected-content rights request exceeds the Wallet wire limit of {MAX_PROTECTED_CONTENT_RIGHTS_WIRE_BYTES} bytes"
        );
        let oversized = "aa".repeat(MAX_PROTECTED_CONTENT_RIGHTS_WIRE_BYTES + 1);
        assert_eq!(
            protected_content_rights_request_from_hex(&oversized).unwrap_err(),
            reason
        );
    }

    /// Catches removal of the lowercase, unprefixed hex refusal in
    /// `protected_content_rights_request_from_hex` at `:293`. The guard has two
    /// conditions, an odd length and an uppercase digit, and both raise this
    /// string, so this one test drives both. The uppercase case is even-length
    /// and every character is a hex digit, so only the case rule refuses it.
    #[test]
    fn rejects_odd_or_uppercase_hex() {
        let reason = "protected-content rights request must be lowercase hex without a prefix";
        for input in ["a", "AA"] {
            assert_eq!(
                protected_content_rights_request_from_hex(input).unwrap_err(),
                reason
            );
        }
    }

    /// Catches removal of the decode refusal in
    /// `protected_content_rights_request_from_hex` at `:309`. `"00"` is
    /// canonical lowercase hex of even length and one byte, so it passes every
    /// check above and reaches the contract reader, which refuses it as the
    /// wrong canonical domain because it is shorter than the domain prefix.
    #[test]
    fn rejects_hex_that_is_not_a_canonical_request() {
        let reason = format!(
            "invalid protected-content rights request: {}",
            ContractError::WrongDomain
        );
        assert_eq!(
            protected_content_rights_request_from_hex("00").unwrap_err(),
            reason
        );
    }

    /// Catches removal of the object refusal in
    /// `protected_content_rights_request_from_payload` at `:315`. Both a JSON
    /// string and a JSON array are valid JSON that is not an object, so a
    /// reader that fell through would reach the field-set check with no keys.
    #[test]
    fn rejects_a_payload_that_is_not_a_json_object() {
        let reason = "protected-content rights approval payload must be a JSON object";
        for payload in [json!("canonical_rights_request_hex"), json!([SCHEMA])] {
            assert_eq!(
                protected_content_rights_request_from_payload(&payload).unwrap_err(),
                reason
            );
        }
    }

    /// Catches removal of the field-set refusal in
    /// `protected_content_rights_request_from_payload` at `:322`. The guard has
    /// three refusals, a key count other than two, a missing `schema`, and a
    /// missing `canonical_rights_request_hex`, and all three raise this string.
    /// The first case carries a third key, so the count refuses it. The second
    /// carries two keys of which the second is not the allowed name, so the
    /// `canonical_rights_request_hex` rule refuses it. Both carry the right
    /// schema, so the schema check below the field-set check would accept them.
    #[test]
    fn rejects_unsupported_fields() {
        let reason = "protected-content rights approval payload has unsupported fields";
        let third_key = json!({
            "schema": SCHEMA,
            "canonical_rights_request_hex": "00",
            "canonical_rights_request_hex_v2": "00",
        });
        let wrong_second_key = json!({
            "schema": SCHEMA,
            "canonical_rights_request_hex_v2": "00",
        });
        for payload in [third_key, wrong_second_key] {
            assert_eq!(
                protected_content_rights_request_from_payload(&payload).unwrap_err(),
                reason
            );
        }
    }

    /// Catches removal of the schema refusal in
    /// `protected_content_rights_request_from_payload` at `:326`. The case
    /// carries exactly the two allowed keys and only a second schema string, so
    /// the field-set check above it passes and this test pins the schema rule
    /// alone.
    #[test]
    fn rejects_an_unsupported_schema() {
        let payload = json!({
            "schema": "elastos.wallet.protected-content-rights-approval/v2",
            "canonical_rights_request_hex": "00",
        });
        assert_eq!(
            protected_content_rights_request_from_payload(&payload).unwrap_err(),
            "protected-content rights approval payload has unsupported schema"
        );
    }

    /// Catches removal of the text-field refusal in
    /// `protected_content_rights_request_from_payload` at `:330`. The case
    /// carries exactly the two allowed keys and the right schema, and its
    /// `canonical_rights_request_hex` is a number rather than a string, so the
    /// checks above it pass and this test pins the reader's type rule alone.
    #[test]
    fn rejects_a_missing_canonical_rights_request_hex() {
        let payload = json!({
            "schema": SCHEMA,
            "canonical_rights_request_hex": 0,
        });
        assert_eq!(
            protected_content_rights_request_from_payload(&payload).unwrap_err(),
            "protected-content rights approval payload missing canonical_rights_request_hex"
        );
    }
}

/// One test per refusal string the managed-signing path and the external
/// handoff signature readers raise, each asserting the whole `Err` value. They
/// pin answers the signer already gives: they add no rule and register no
/// falsifier. They prove what the wallet provider agrees to sign and why it
/// refuses the rest, not confinement: the Runtime decides whether the provider
/// runs at all.
///
/// `managed Bitcoin accounts only support bitcoin_bip322_proof signing` (`:117`)
/// is a different string from `Bitcoin accounts only support
/// bitcoin_bip322_proof signing` at `approval.rs:192`, which
/// `approval_refuses_non_bitcoin_intent_for_bitcoin_account` pins: that one
/// refuses when the approval request is recorded, this one when the recorded
/// request is signed.
///
/// `Browser wallet signature payload missing message` (`:453`) and `Browser
/// typed-data payload missing canonical typed data` (`:461`) have sibling sites
/// that task 128 pins: `crypto/evm/validation.rs:92` through
/// `personal_sign_missing_message_is_refused`, and `crypto/evm/validation.rs:163`
/// through `typed_data_missing_canonical_is_refused`. The `crypto/evm/browser.rs:33`
/// copy sits behind that same validator and is reached by no test.
///
/// Three lines are recorded as unreachable instead of tested. `unsupported
/// managed wallet proof type` (`:24`) is the `_` arm over `managed_proof_type`,
/// which returns only `MANAGED_EVM_PROOF_TYPE` or `MANAGED_BTC_P2WPKH_PROOF_TYPE`
/// (`validation.rs:242` to `:252`), as task 129 recorded. `invalid managed
/// rights signature: {err}` (`:85`) canonicalises the signature `sign_evm_message`
/// produced one line above at `:81`, whose output `canonicalize_evm_signature`
/// accepts, so a rejection would need a fault in k256 itself. `Bitcoin BIP-322
/// payload missing message` (`:469`) is reached only from
/// `external_signature_message` callers that already refused a payload without
/// `message`: `approval.rs:666` in `complete_connector_handoff` after
/// `validate_bitcoin_challenge_for_signing` at `:659`, which refuses at
/// `crypto/bitcoin.rs:482`, and `approval.rs:479` in `approve_connector_handoff`,
/// which that handoff reaches at `crypto.rs:201` with no validator of its own.
#[cfg(test)]
mod uf_signing_path_refusal_tests {
    use super::*;
    use serde_json::json;

    /// A managed request every earlier branch of the signing path accepts, so
    /// each case reaches the guard it pins. The two fields a case changes are
    /// `chain_namespace` for `:117` and `intent` plus `payload` for the two
    /// readers; the rest is one valid value in the shape `request_approval`
    /// stores (`approval.rs:262` to `:294`).
    fn request() -> WalletApprovalRequest {
        serde_json::from_value(json!({
            "schema": "elastos.wallet.approval_request/v1",
            "request_id": "req-signing-path",
            "kind": "signature",
            "status": "pending",
            "principal_id": "person:local:alice",
            "account_id": "wallet:eip155:20:0x1111111111111111111111111111111111111111",
            "proof_binding_id": "proof:eip155:20:0x1111111111111111111111111111111111111111",
            "chain_namespace": "eip155:20",
            "address": "0x1111111111111111111111111111111111111111",
            "intent": "browser_personal_sign",
            "requested_by_actor": "browser",
            "resource": "elastos://wallet/eip155:20/sign/browser_personal_sign",
            "reason": "unit test signing path",
            "payload": { "message": "hello" },
            "payload_hash": "hash-signing-path",
            "created_at": 0,
            "expires_at": 1_000,
        }))
        .expect("the signing-path request fixture is a valid approval request")
    }

    /// Catches removal of the Bitcoin chain guard in `sign_managed_approval` at
    /// `:115`, which raises `:117`. The request carries the Bitcoin mainnet
    /// chain namespace and the `browser_account_access` intent, so every intent
    /// branch above the guard misses and every branch below it would sign an
    /// EVM attestation with the account's EVM key. `approve_and_sign_managed`
    /// (`approval.rs:923`) is the production caller that reaches the guard.
    ///
    /// The `Ok` type carries no `Debug`, so the case maps it to `()` and
    /// compares the whole result against the whole refusal.
    #[test]
    fn signing_path_refuses_bitcoin_chain_for_a_non_bitcoin_intent() {
        let signing_key = SigningKey::from_slice(&[0x11; 32]).expect("the fixed test key is valid");
        let mut request = request();
        request.chain_namespace = BITCOIN_MAINNET_CHAIN_NAMESPACE.to_string();
        request.intent = "browser_account_access".to_string();
        assert_eq!(
            sign_managed_approval(&signing_key, &request).map(|_| ()),
            Err("managed Bitcoin accounts only support bitcoin_bip322_proof signing".to_string())
        );
    }

    /// Catches removal of the `message` reader in `external_signature_message`
    /// at `:451`, which raises `:453`. The payload carries no `message` and one
    /// number under that key, because a non-string `message` is the case a
    /// reader that stopped reading the value would still refuse. The route is
    /// `complete_connector_handoff` at `approval.rs:771`, after the request was
    /// handed to the page at `crypto.rs:201`.
    #[test]
    fn signing_path_refuses_personal_sign_without_a_message() {
        let mut request = request();
        request.intent = "browser_personal_sign".to_string();
        for payload in [json!({}), json!({ "message": 0 })] {
            request.payload = payload;
            assert_eq!(
                external_signature_message(&request).unwrap_err(),
                "Browser wallet signature payload missing message"
            );
        }
    }

    /// Catches removal of the `typed_data_canonical` reader in
    /// `external_signature_message` at `:459`, which raises `:461`. The payload
    /// carries no canonical typed data and one number under that key, so a
    /// reader that stopped reading the value still refuses. The route is
    /// `approve_connector_handoff` at `approval.rs:479`, which reaches the
    /// reader at `crypto.rs:201`; the completion path hashes typed data itself
    /// at `approval.rs:764` and never calls this reader.
    #[test]
    fn signing_path_refuses_typed_data_without_canonical_data() {
        let mut request = request();
        request.intent = "browser_typed_data_sign".to_string();
        for payload in [json!({}), json!({ "typed_data_canonical": 0 })] {
            request.payload = payload;
            assert_eq!(
                external_signature_message(&request).unwrap_err(),
                "Browser typed-data payload missing canonical typed data"
            );
        }
    }
}
