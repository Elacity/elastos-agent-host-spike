use super::super::*;
use super::payload::{
    payload_evm_address_bytes, payload_hex_bytes, payload_quantity_bytes, payload_u64,
    trim_integer_bytes,
};
use super::validation::validate_eip155_transaction_intent_payload;
use k256::ecdsa::SigningKey;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

pub(crate) fn external_transaction_result(
    request: &WalletApprovalRequest,
    transaction_hash: &str,
) -> Value {
    json!({
        "schema": "elastos.wallet.external-transaction-result/v1",
        "request_id": request.request_id,
        "method": "eth_sendTransaction",
        "transaction_hash": transaction_hash,
        "signer": request.address,
        "chain_namespace": request.chain_namespace,
        "payload_hash": request.payload_hash,
        "page_url": request.payload.get("page_url").cloned().unwrap_or(Value::Null),
        "origin": request.payload.get("origin").cloned().unwrap_or(Value::Null),
    })
}

pub(crate) fn sign_eip155_legacy_transaction(
    signing_key: &SigningKey,
    request: &WalletApprovalRequest,
) -> Result<(String, Value), String> {
    validate_eip155_transaction_intent_payload(
        &request.payload,
        &LinkedAccount {
            account_id: request.account_id.clone(),
            principal_id: request.principal_id.clone(),
            proof_binding_id: request.proof_binding_id.clone(),
            chain_namespace: request.chain_namespace.clone(),
            address: request.address.clone(),
            proof_type: request.proof_type.clone(),
            connector_id: request.connector_id.clone(),
            label: None,
            linked_at: request.created_at,
            revoked_at: None,
        },
    )?;
    let chain_id = payload_u64(&request.payload, "chain_id")?;
    let nonce = payload_quantity_bytes(&request.payload, "nonce")?;
    let gas_price = payload_quantity_bytes(&request.payload, "gas_price")?;
    let gas_limit = payload_quantity_bytes(&request.payload, "gas_limit")?;
    let to = payload_evm_address_bytes(&request.payload, "to")?;
    let value = payload_quantity_bytes(&request.payload, "value")?;
    let data = payload_hex_bytes(&request.payload, "data")?;
    let signing_items = vec![
        rlp_bytes(&nonce),
        rlp_bytes(&gas_price),
        rlp_bytes(&gas_limit),
        rlp_bytes(&to),
        rlp_bytes(&value),
        rlp_bytes(&data),
        rlp_u64(chain_id),
        rlp_bytes(&[]),
        rlp_bytes(&[]),
    ];
    let signing_payload = rlp_list(&signing_items);
    let signing_hash = Keccak256::digest(&signing_payload);
    let (signature, recovery_id) = signing_key
        .sign_prehash_recoverable(&signing_hash)
        .map_err(|err| err.to_string())?;
    let signature_bytes = signature.to_bytes();
    let v = chain_id
        .checked_mul(2)
        .and_then(|value| value.checked_add(35))
        .and_then(|value| value.checked_add(u64::from(recovery_id.to_byte())))
        .ok_or_else(|| "transaction chain_id is too large".to_string())?;
    let signed_items = vec![
        rlp_bytes(&nonce),
        rlp_bytes(&gas_price),
        rlp_bytes(&gas_limit),
        rlp_bytes(&to),
        rlp_bytes(&value),
        rlp_bytes(&data),
        rlp_u64(v),
        rlp_bytes(trim_integer_bytes(&signature_bytes[..32])),
        rlp_bytes(trim_integer_bytes(&signature_bytes[32..])),
    ];
    let signed_transaction_bytes = rlp_list(&signed_items);
    let signed_transaction = format!("0x{}", hex::encode(&signed_transaction_bytes));
    let transaction_hash = format!(
        "0x{}",
        hex::encode(Keccak256::digest(&signed_transaction_bytes))
    );
    Ok((
        signed_transaction,
        json!({
            "schema": "elastos.wallet.signed_transaction/v1",
            "transaction_type": "eip155_legacy",
            "request_id": request.request_id.clone(),
            "chain_namespace": request.chain_namespace.clone(),
            "signer": request.address.clone(),
            "payload_hash": request.payload_hash.clone(),
            "transaction_hash": transaction_hash,
        }),
    ))
}

pub(crate) fn rlp_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return rlp_bytes(&[]);
    }
    rlp_bytes(trim_integer_bytes(&value.to_be_bytes()))
}

pub(crate) fn rlp_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return vec![bytes[0]];
    }
    let mut encoded = rlp_length_prefix(bytes.len(), 0x80);
    encoded.extend_from_slice(bytes);
    encoded
}

pub(crate) fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload_len = items.iter().map(Vec::len).sum::<usize>();
    let mut encoded = rlp_length_prefix(payload_len, 0xc0);
    for item in items {
        encoded.extend_from_slice(item);
    }
    encoded
}

pub(crate) fn rlp_length_prefix(len: usize, offset: u8) -> Vec<u8> {
    if len < 56 {
        return vec![offset + len as u8];
    }
    let raw_len = len.to_be_bytes();
    let len_bytes = trim_integer_bytes(&raw_len);
    let mut encoded = vec![offset + 55 + len_bytes.len() as u8];
    encoded.extend_from_slice(len_bytes);
    encoded
}

/// One test per refusal the legacy EIP-155 signer raises, asserting the whole
/// `Err` value. It pins an answer the signer already gives: it adds no rule and
/// registers no falsifier. It proves what the wallet provider answers a
/// transaction intent, not confinement: the Runtime decides whether the
/// provider runs.
#[cfg(test)]
mod uf_transaction_refusal_tests {
    use super::*;

    const ADDRESS: &str = "0x1111111111111111111111111111111111111111";

    /// A transaction intent every earlier check accepts, so the case reaches
    /// the `v` computation. The validator in `validation.rs` bounds `chain_id`
    /// only by `u64` and by non-zero, so a payload carrying a chain id near
    /// the top of that range arrives here.
    fn request(chain_id: u64) -> WalletApprovalRequest {
        WalletApprovalRequest {
            schema: "elastos.wallet.approval_request/v1".to_string(),
            request_id: "req-1".to_string(),
            wallet_request_sha256: String::new(),
            authority_binding: String::new(),
            kind: "signature".to_string(),
            status: ApprovalStatus::Pending,
            principal_id: "person:local:alice".to_string(),
            account_id: format!("wallet:eip155:20:{ADDRESS}"),
            proof_binding_id: format!("proof:eip155:20:{ADDRESS}"),
            chain_namespace: "eip155:20".to_string(),
            address: ADDRESS.to_string(),
            proof_type: MANAGED_EVM_PROOF_TYPE.to_string(),
            connector_id: None,
            intent: "transaction_intent".to_string(),
            session_id: String::new(),
            launch_id: String::new(),
            requested_by_actor: "browser".to_string(),
            resource: "elastos://wallet/eip155:20/sign/transaction_intent".to_string(),
            reason: "unit test transaction".to_string(),
            payload: json!({
                "schema": "elastos.chain.unsigned_transaction_intent/v1",
                "transaction_type": "eip155_legacy",
                "wallet_intent": "transaction_intent",
                "requires_wallet_approval": true,
                "chain_id": chain_id,
                "from": ADDRESS,
                "to": ADDRESS,
                "nonce": "0x0",
                "gas_price": "0x1",
                "gas_limit": "0x5208",
                "value": "0x0",
                "data": "0x"
            }),
            payload_hash: "hash-1".to_string(),
            created_at: 0,
            expires_at: 1_000,
            resolved_at: None,
            rejection_reason: None,
            approved_at: None,
            approval_reason: None,
            completed_at: None,
            signature_receipt: None,
            signed_result: None,
            validated_chain_outcome: None,
        }
    }

    /// The `v` computation has three arms that can carry out, and this test
    /// drives all three. `1 << 63` and `u64::MAX` carry out of the multiply by
    /// two; `u64::MAX / 2` carries out of the add of 35; and
    /// `(u64::MAX - 35) / 2` leaves `2 * chain_id + 35` exactly `u64::MAX`, so
    /// the add of the recovery id carries out when the signature's recovery id
    /// is one, which the second key below produces for that chain id.
    ///
    /// `1 << 63` is the case that proves the multiply is checked rather than
    /// wrapped: a wrapping multiply turns it into zero, and the adds that
    /// follow then fit.
    ///
    /// Falsifier: compute `v` with wrapping arithmetic, so a chain id near the
    /// top of `u64` signs as a small chain id and the transaction replays on
    /// another chain.
    #[test]
    fn overflowing_chain_id_is_refused() {
        let reason = "transaction chain_id is too large";
        let signing_key = SigningKey::from_bytes((&[9u8; 32]).into()).expect("a valid key");
        for chain_id in [1u64 << 63, u64::MAX, u64::MAX / 2] {
            assert_eq!(
                sign_eip155_legacy_transaction(&signing_key, &request(chain_id)).unwrap_err(),
                reason
            );
        }
        // This key signs with recovery id one for this chain id, so `v` reaches
        // `u64::MAX + 1` on the third arm alone.
        let mut seed = [7u8; 32];
        seed[31] = 1;
        let last_arm_key = SigningKey::from_bytes((&seed).into()).expect("a valid key");
        assert_eq!(
            sign_eip155_legacy_transaction(&last_arm_key, &request((u64::MAX - 35) / 2))
                .unwrap_err(),
            reason
        );
    }
}
