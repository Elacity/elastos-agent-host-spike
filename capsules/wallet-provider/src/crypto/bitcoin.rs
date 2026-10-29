use super::*;
use ::bitcoin::{
    absolute,
    consensus::encode::{deserialize, serialize},
    hashes::hash160,
    hashes::sha256,
    hashes::sha256d,
    hashes::Hash,
    hashes::HashEngine,
    opcodes::all::OP_RETURN,
    script::Builder,
    secp256k1::{Message, Secp256k1, XOnlyPublicKey},
    sighash::{EcdsaSighashType, Prevouts, SighashCache},
    taproot::Signature as TaprootSignature,
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use k256::ecdsa::{
    signature::hazmat::PrehashVerifier, Signature as EcdsaSignature, SigningKey, VerifyingKey,
};
use std::str::FromStr;

pub(crate) const BITCOIN_PROOF_BIP322_SIMPLE: &str = "bip322_simple";
pub(crate) const BITCOIN_PROOF_SIGNED_MESSAGE: &str = "bitcoin_signed_message";

pub(crate) fn btc_p2wpkh_address_for_signing_key(
    signing_key: &SigningKey,
) -> Result<String, String> {
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(true);
    let secp_pubkey = ::bitcoin::secp256k1::PublicKey::from_slice(encoded.as_bytes())
        .map_err(|err| format!("invalid managed Bitcoin public key: {err}"))?;
    Ok(::bitcoin::Address::p2wpkh(
        &::bitcoin::CompressedPublicKey(secp_pubkey),
        ::bitcoin::KnownHrp::Mainnet,
    )
    .to_string())
}

pub(crate) fn sign_bip322_simple_p2wpkh_approval(
    signing_key: &SigningKey,
    request: &WalletApprovalRequest,
) -> Result<(String, Value), String> {
    validate_bitcoin_bip322_proof_payload(
        &request.payload,
        &LinkedAccount {
            account_id: request.account_id.clone(),
            principal_id: request.principal_id.clone(),
            proof_binding_id: request.proof_binding_id.clone(),
            chain_namespace: request.chain_namespace.clone(),
            address: request.address.clone(),
            proof_type: MANAGED_BTC_P2WPKH_PROOF_TYPE.to_string(),
            connector_id: None,
            label: None,
            linked_at: 0,
            revoked_at: None,
        },
    )?;
    let message = request
        .payload
        .get("message")
        .and_then(Value::as_str)
        .ok_or_else(|| "Bitcoin BIP-322 payload missing message".to_string())?;
    let address = bitcoin_address(&request.address, Network::Bitcoin)?;
    let script_pubkey = address.script_pubkey();
    let script_bytes = script_pubkey.as_bytes();
    if script_bytes.len() != 22 || script_bytes[0] != 0x00 || script_bytes[1] != 0x14 {
        return Err("managed Bitcoin account must be native P2WPKH".to_string());
    }

    let message_hash = bip322_message_hash(message.as_bytes());
    let to_spend = bip322_to_spend_tx(&message_hash, script_pubkey.clone());
    let mut to_sign = bip322_to_sign_tx(to_spend.compute_txid(), Witness::new());
    let sighash = SighashCache::new(&mut to_sign)
        .p2wpkh_signature_hash(0, &script_pubkey, Amount::ZERO, EcdsaSighashType::All)
        .map_err(|err| format!("BIP-322 sighash failed: {err}"))?;
    let (signature, _) = signing_key
        .sign_prehash_recoverable(sighash.as_byte_array())
        .map_err(|err| format!("BIP-322 signing failed: {err}"))?;
    let mut signature_der = signature.to_der().as_bytes().to_vec();
    signature_der.push(EcdsaSighashType::All as u8);
    let pubkey = signing_key.verifying_key().to_encoded_point(true);
    let mut witness = Witness::new();
    witness.push(signature_der);
    witness.push(pubkey.as_bytes());
    let signature = BASE64_STANDARD.encode(serialize(&witness));
    let payload = json!({
        "schema": "elastos.wallet.bip322_signature_payload/v1",
        "request_id": request.request_id.clone(),
        "principal_id": request.principal_id.clone(),
        "account_id": request.account_id.clone(),
        "chain_namespace": request.chain_namespace.clone(),
        "address": request.address.clone(),
        "intent": request.intent.clone(),
        "capsule_id": request.requested_by_actor.clone(),
        "resource": request.resource.clone(),
        "reason": request.reason.clone(),
        "message_hash": format!("0x{}", hex::encode(message_hash)),
        "signature_type": "bip322_simple",
    });
    Ok((signature, payload))
}

#[derive(Debug)]
pub(crate) struct BitcoinProofResult {
    pub(crate) chain_namespace: String,
    pub(crate) address: String,
    pub(crate) proof_type: &'static str,
    pub(crate) proof_strength: &'static str,
    pub(crate) message_hash: [u8; 32],
}

pub(crate) fn verify_bip322_simple(
    network: &str,
    address: &str,
    message: &str,
    signature: &str,
) -> Result<BitcoinProofResult, String> {
    let network = bitcoin_network(network)?;
    let address = bitcoin_address(address, network)?;
    let script_pubkey = address.script_pubkey();
    let script_bytes = script_pubkey.as_bytes();
    let message_hash = bip322_message_hash(message.as_bytes());
    let witness = bip322_simple_witness(signature)?;
    if script_bytes.len() == 22 && script_bytes[0] == 0x00 && script_bytes[1] == 0x14 {
        return verify_bip322_simple_p2wpkh(network, address, script_pubkey, message_hash, witness);
    }
    if script_bytes.len() == 34 && script_bytes[0] == 0x51 && script_bytes[1] == 0x20 {
        return verify_bip322_simple_p2tr(network, address, script_pubkey, message_hash, witness);
    }
    Err(
        "BIP-322 simple verification supports Native SegWit P2WPKH and Taproot P2TR accounts only; Legacy and Nested SegWit require bitcoin_signed_message proof"
            .to_string(),
    )
}

pub(crate) fn verify_bitcoin_signed_message(
    network: &str,
    address: &str,
    message: &str,
    signature: &str,
    public_key: &str,
) -> Result<BitcoinProofResult, String> {
    let network = bitcoin_network(network)?;
    let address = bitcoin_address(address, network)?;
    let script_pubkey = address.script_pubkey();
    if !script_pubkey.is_p2pkh() && !script_pubkey.is_p2sh() {
        return Err(
            "Bitcoin signed-message proof supports Legacy P2PKH and Nested SegWit P2SH-P2WPKH accounts only".to_string(),
        );
    }
    let public_key_bytes = hex::decode(public_key.trim())
        .map_err(|err| format!("invalid Bitcoin public key: {err}"))?;
    let compressed_key = ::bitcoin::CompressedPublicKey::from_slice(&public_key_bytes)
        .map_err(|err| format!("invalid compressed Bitcoin public key: {err}"))?;
    let expected_address = if script_pubkey.is_p2pkh() {
        ::bitcoin::Address::p2pkh(compressed_key, network)
    } else {
        ::bitcoin::Address::p2shwpkh(&compressed_key, network)
    };
    if expected_address.to_string() != address.to_string() {
        return Err("Bitcoin public key does not match selected address".to_string());
    }

    let message_hash = bitcoin_signed_message_hash(message.as_bytes());
    let signature = bitcoin_compact_signature(signature)?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key_bytes)
        .map_err(|err| format!("invalid Bitcoin public key: {err}"))?;
    verifying_key
        .verify_prehash(&message_hash, &signature)
        .map_err(|_| "invalid Bitcoin signed-message signature".to_string())?;

    Ok(BitcoinProofResult {
        chain_namespace: bitcoin_chain_namespace(network),
        address: address.to_string(),
        proof_type: BITCOIN_PROOF_SIGNED_MESSAGE,
        proof_strength: "standard",
        message_hash,
    })
}

pub(crate) fn verify_bitcoin_proof_for_type(
    expected_proof_type: &str,
    requested_signature_type: &str,
    network: &str,
    address: &str,
    message: &str,
    signature: &str,
    public_key: Option<&str>,
) -> Result<BitcoinProofResult, String> {
    match (expected_proof_type, requested_signature_type) {
        (BITCOIN_PROOF_BIP322_SIMPLE, BITCOIN_PROOF_BIP322_SIMPLE)
        | (BITCOIN_PROOF_BIP322_SIMPLE, "bip322-simple") => {
            verify_bip322_simple(network, address, message, signature)
        }
        (BITCOIN_PROOF_SIGNED_MESSAGE, BITCOIN_PROOF_SIGNED_MESSAGE)
        | (BITCOIN_PROOF_SIGNED_MESSAGE, "ecdsa") => verify_bitcoin_signed_message(
            network,
            address,
            message,
            signature,
            public_key.ok_or_else(|| "Bitcoin signed-message proof missing public key".to_string())?,
        ),
        _ => Err(format!(
            "Bitcoin signature type {requested_signature_type} does not match required proof type {expected_proof_type}"
        )),
    }
}

pub(crate) fn bitcoin_signature_type_for_proof_type(proof_type: &str) -> &'static str {
    match proof_type {
        BITCOIN_PROOF_SIGNED_MESSAGE => "ecdsa",
        _ => BITCOIN_PROOF_BIP322_SIMPLE,
    }
}

fn bitcoin_compact_signature(signature: &str) -> Result<EcdsaSignature, String> {
    let signature_bytes = BASE64_STANDARD
        .decode(signature)
        .map_err(|err| format!("invalid Bitcoin signed-message base64 signature: {err}"))?;
    let compact = match signature_bytes.len() {
        65 => &signature_bytes[1..65],
        64 => signature_bytes.as_slice(),
        _ => return Err("Bitcoin signed-message signature must be 64 or 65 bytes".to_string()),
    };
    EcdsaSignature::try_from(compact)
        .map_err(|err| format!("invalid Bitcoin signed-message signature: {err}"))
}

pub(crate) fn bitcoin_signed_message_hash(message: &[u8]) -> [u8; 32] {
    let mut bytes = b"\x18Bitcoin Signed Message:\n".to_vec();
    push_compact_size(message.len() as u64, &mut bytes);
    bytes.extend_from_slice(message);
    sha256d::Hash::hash(&bytes).to_byte_array()
}

fn push_compact_size(value: u64, bytes: &mut Vec<u8>) {
    if value < 253 {
        bytes.push(value as u8);
    } else if value <= 0xffff {
        bytes.push(253);
        bytes.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xffff_ffff {
        bytes.push(254);
        bytes.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        bytes.push(255);
        bytes.extend_from_slice(&value.to_le_bytes());
    }
}

pub(crate) fn bitcoin_proof_type_for_address(
    network: &str,
    address: &str,
) -> Result<&'static str, String> {
    let network = bitcoin_network(network)?;
    let address = bitcoin_address(address, network)?;
    let script_pubkey = address.script_pubkey();
    let script_bytes = script_pubkey.as_bytes();
    if (script_bytes.len() == 22 && script_bytes[0] == 0x00 && script_bytes[1] == 0x14)
        || (script_bytes.len() == 34 && script_bytes[0] == 0x51 && script_bytes[1] == 0x20)
    {
        return Ok(BITCOIN_PROOF_BIP322_SIMPLE);
    }
    if script_pubkey.is_p2pkh() || script_pubkey.is_p2sh() {
        return Ok(BITCOIN_PROOF_SIGNED_MESSAGE);
    }
    Err("unsupported Bitcoin address type".to_string())
}

fn bip322_simple_witness(signature: &str) -> Result<Witness, String> {
    let witness_bytes = BASE64_STANDARD
        .decode(signature)
        .map_err(|err| format!("invalid BIP-322 base64 signature: {err}"))?;
    deserialize(&witness_bytes).map_err(|err| format!("invalid BIP-322 simple witness: {err}"))
}

fn verify_bip322_simple_p2wpkh(
    network: Network,
    address: ::bitcoin::Address,
    script_pubkey: ScriptBuf,
    message_hash: [u8; 32],
    witness: Witness,
) -> Result<BitcoinProofResult, String> {
    let script_bytes = script_pubkey.as_bytes();
    let pubkey_hash = &script_bytes[2..22];
    if witness.len() != 2 {
        return Err("BIP-322 P2WPKH proof must contain signature and public key".to_string());
    }
    let signature_with_hash_type = witness
        .iter()
        .next()
        .ok_or_else(|| "BIP-322 signature witness is missing".to_string())?;
    if signature_with_hash_type.len() < 2 {
        return Err("BIP-322 signature witness is too short".to_string());
    }
    let sighash_type = *signature_with_hash_type
        .last()
        .ok_or_else(|| "BIP-322 signature sighash flag is missing".to_string())?;
    if sighash_type != EcdsaSighashType::All as u8 {
        return Err("BIP-322 P2WPKH proof must use SIGHASH_ALL".to_string());
    }
    let signature_der = signature_with_hash_type[..signature_with_hash_type.len() - 1].to_vec();
    let pubkey = witness
        .iter()
        .nth(1)
        .ok_or_else(|| "BIP-322 public key witness is missing".to_string())?;
    let pubkey = pubkey.to_vec();
    let actual_pubkey_hash = hash160::Hash::hash(&pubkey);
    if actual_pubkey_hash.as_byte_array().as_slice() != pubkey_hash {
        return Err("BIP-322 public key does not match Bitcoin address".to_string());
    }

    let to_spend = bip322_to_spend_tx(&message_hash, script_pubkey.clone());
    let mut to_sign = bip322_to_sign_tx(to_spend.compute_txid(), witness);
    let sighash = SighashCache::new(&mut to_sign)
        .p2wpkh_signature_hash(0, &script_pubkey, Amount::ZERO, EcdsaSighashType::All)
        .map_err(|err| format!("BIP-322 sighash failed: {err}"))?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&pubkey)
        .map_err(|err| format!("invalid BIP-322 public key: {err}"))?;
    let signature = EcdsaSignature::from_der(&signature_der)
        .map_err(|err| format!("invalid BIP-322 DER signature: {err}"))?;
    verifying_key
        .verify_prehash(sighash.as_byte_array(), &signature)
        .map_err(|_| "invalid BIP-322 signature".to_string())?;

    Ok(BitcoinProofResult {
        chain_namespace: bitcoin_chain_namespace(network),
        address: address.to_string(),
        proof_type: "bip322_simple",
        proof_strength: "standard",
        message_hash,
    })
}

fn verify_bip322_simple_p2tr(
    network: Network,
    address: ::bitcoin::Address,
    script_pubkey: ScriptBuf,
    message_hash: [u8; 32],
    witness: Witness,
) -> Result<BitcoinProofResult, String> {
    if witness.len() != 1 {
        return Err("BIP-322 P2TR proof must contain one Schnorr signature".to_string());
    }
    let signature_bytes = witness
        .iter()
        .next()
        .ok_or_else(|| "BIP-322 Taproot signature witness is missing".to_string())?;
    let signature = TaprootSignature::from_slice(signature_bytes)
        .map_err(|err| format!("invalid BIP-322 Taproot signature: {err}"))?;
    let script_bytes = script_pubkey.as_bytes();
    let output_key = XOnlyPublicKey::from_slice(&script_bytes[2..34])
        .map_err(|err| format!("invalid Taproot output key: {err}"))?;
    let to_spend = bip322_to_spend_tx(&message_hash, script_pubkey.clone());
    let mut to_sign = bip322_to_sign_tx(to_spend.compute_txid(), witness);
    let prevouts = vec![TxOut {
        value: Amount::ZERO,
        script_pubkey,
    }];
    let sighash = SighashCache::new(&mut to_sign)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), signature.sighash_type)
        .map_err(|err| format!("BIP-322 Taproot sighash failed: {err}"))?;
    let message = Message::from_digest(sighash.to_byte_array());
    Secp256k1::verification_only()
        .verify_schnorr(&signature.signature, &message, &output_key)
        .map_err(|_| "invalid BIP-322 Taproot signature".to_string())?;

    Ok(BitcoinProofResult {
        chain_namespace: bitcoin_chain_namespace(network),
        address: address.to_string(),
        proof_type: "bip322_simple",
        proof_strength: "standard",
        message_hash,
    })
}

pub(crate) fn bip322_message_hash(message: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(b"BIP0322-signed-message");
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    engine.input(message);
    sha256::Hash::from_engine(engine).to_byte_array()
}

pub(crate) fn bip322_to_spend_tx(message_hash: &[u8; 32], script_pubkey: ScriptBuf) -> Transaction {
    let mut script_sig = Vec::with_capacity(34);
    script_sig.push(0x00);
    script_sig.push(0x20);
    script_sig.extend_from_slice(message_hash);
    Transaction {
        version: ::bitcoin::transaction::Version(0),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(script_sig),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey,
        }],
    }
}

pub(crate) fn bip322_to_sign_tx(previous_txid: ::bitcoin::Txid, witness: Witness) -> Transaction {
    Transaction {
        version: ::bitcoin::transaction::Version(0),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: previous_txid,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: Builder::new().push_opcode(OP_RETURN).into_script(),
        }],
    }
}

pub(crate) fn validate_bitcoin_address(address: &str, network: &str) -> Result<(), String> {
    bitcoin_address(address, bitcoin_network(network)?).map(|_| ())
}

pub(crate) fn validate_bitcoin_network(network: &str) -> Result<(), String> {
    bitcoin_network(network).map(|_| ())
}

pub(crate) fn bitcoin_address(
    address: &str,
    network: Network,
) -> Result<::bitcoin::Address, String> {
    ::bitcoin::Address::from_str(address)
        .map_err(|err| format!("invalid Bitcoin address: {err}"))?
        .require_network(network)
        .map_err(|err| format!("Bitcoin address network mismatch: {err}"))
}

pub(crate) fn bitcoin_network(network: &str) -> Result<Network, String> {
    match network {
        "bitcoin" | "mainnet" | "btc-mainnet" => Ok(Network::Bitcoin),
        _ => Err("unsupported Bitcoin proof network".to_string()),
    }
}

pub(crate) fn bitcoin_chain_namespace(network: Network) -> String {
    match network {
        Network::Bitcoin => format!("bip122:{BITCOIN_MAINNET_BIP122}"),
        _ => "bip122:unsupported".to_string(),
    }
}

pub(crate) fn validate_bitcoin_bip322_proof_payload(
    payload: &Value,
    account: &LinkedAccount,
) -> Result<(), String> {
    if payload.get("schema").and_then(Value::as_str)
        != Some("elastos.wallet.bitcoin_bip322_request/v1")
    {
        return Err("Bitcoin BIP-322 payload has unsupported schema".to_string());
    }
    if payload.get("wallet_intent").and_then(Value::as_str) != Some("bitcoin_bip322_proof") {
        return Err("Bitcoin BIP-322 payload has mismatched wallet_intent".to_string());
    }
    if payload.get("chain_namespace").and_then(Value::as_str)
        != Some(account.chain_namespace.as_str())
    {
        return Err("Bitcoin BIP-322 payload chain does not match account".to_string());
    }
    if payload.get("address").and_then(Value::as_str) != Some(account.address.as_str()) {
        return Err("Bitcoin BIP-322 payload address does not match account".to_string());
    }
    let message = payload
        .get("message")
        .and_then(Value::as_str)
        .ok_or_else(|| "Bitcoin BIP-322 payload missing message".to_string())?;
    if message.is_empty() || message.len() > MAX_APPROVAL_PAYLOAD_BYTES {
        return Err("Bitcoin BIP-322 message size is invalid".to_string());
    }
    if !message.contains("wants you to prove Bitcoin account ownership") {
        return Err("Bitcoin BIP-322 message must be a Runtime account proof".to_string());
    }
    if !message.contains(&account.address) {
        return Err("Bitcoin BIP-322 message address does not match account".to_string());
    }
    if !message.lines().any(|line| {
        line.trim()
            .starts_with("- elastos://auth/bitcoin-challenge/")
    }) {
        return Err("Bitcoin BIP-322 message must bind a Runtime bitcoin challenge".to_string());
    }
    Ok(())
}

pub(crate) fn bitcoin_challenge_id_from_message(message: &str) -> Option<&str> {
    message.lines().find_map(|line| {
        line.trim()
            .strip_prefix("- elastos://auth/bitcoin-challenge/")
            .filter(|challenge_id| !challenge_id.trim().is_empty())
    })
}

#[cfg(test)]
mod uf_tests {
    use super::*;
    use crate::tests::support::{
        bip322_test_taproot_address, bip322_test_taproot_secret_key, sign_bip322_simple_p2tr,
    };
    use ::bitcoin::consensus::encode::{deserialize, serialize};
    use ::bitcoin::{Network, Witness};
    use serde_json::json;

    /// Mainnet native P2WPKH address from the BIP-322 vector in
    /// `src/tests/proofs.rs`, with the witness that vector verifies.
    const BIP322_P2WPKH_ADDRESS: &str = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";
    const BIP322_P2WPKH_WITNESS: &str = "AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=";

    /// Mainnet Legacy P2PKH address, so the signed-message path runs.
    const SIGNED_MESSAGE_P2PKH_ADDRESS: &str = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";

    fn bip322_request_message(address: &str) -> String {
        format!(
            "elastos.local wants you to prove Bitcoin account ownership:\n{address}\n\nURI: http://elastos.local/apps/home/\nVersion: 1\nNetwork: bitcoin\nResources:\n- elastos://auth/bitcoin-challenge/abc123"
        )
    }

    fn bip322_request_payload(address: &str, message: &str) -> Value {
        json!({
            "schema": "elastos.wallet.bitcoin_bip322_request/v1",
            "wallet_intent": "bitcoin_bip322_proof",
            "chain_namespace": bitcoin_chain_namespace(Network::Bitcoin),
            "address": address,
            "message": message,
        })
    }

    fn bip322_account() -> LinkedAccount {
        LinkedAccount {
            account_id: "wallet:bip122:mainnet:link".to_string(),
            principal_id: "person:local:alice".to_string(),
            proof_binding_id: "proof:wallet:bip122:mainnet".to_string(),
            chain_namespace: bitcoin_chain_namespace(Network::Bitcoin),
            address: BIP322_P2WPKH_ADDRESS.to_string(),
            proof_type: MANAGED_BTC_P2WPKH_PROOF_TYPE.to_string(),
            connector_id: None,
            label: None,
            linked_at: 0,
            revoked_at: None,
        }
    }

    #[test]
    fn bitcoin_network_rejects_unknown() {
        assert_eq!(
            bitcoin_network("testnet").unwrap_err(),
            "unsupported Bitcoin proof network"
        );
    }

    #[test]
    fn bitcoin_address_rejects_garbage() {
        let err = bitcoin_address("not-an-address", Network::Bitcoin).unwrap_err();
        assert!(err.starts_with("invalid Bitcoin address"), "got {err}");
    }

    #[test]
    fn bitcoin_address_rejects_network_mismatch() {
        let err = bitcoin_address(BIP322_P2WPKH_ADDRESS, Network::Testnet).unwrap_err();
        assert!(
            err.starts_with("Bitcoin address network mismatch"),
            "got {err}"
        );
    }

    #[test]
    fn bip322_verify_rejects_bad_base64() {
        let err = verify_bip322_simple(
            "bitcoin",
            BIP322_P2WPKH_ADDRESS,
            "Hello World",
            "not*base64",
        )
        .unwrap_err();
        assert!(
            err.starts_with("invalid BIP-322 base64 signature"),
            "got {err}"
        );
    }

    #[test]
    fn bip322_verify_rejects_corrupt_witness() {
        let witness_bytes = BASE64_STANDARD
            .decode(BIP322_P2WPKH_WITNESS)
            .expect("the vector signature is base64");
        let witness: Witness = deserialize(&witness_bytes).expect("the vector holds a witness");
        let mut reduced = Witness::new();
        reduced.push(witness.iter().next().expect("the vector witness has items"));
        let signature = BASE64_STANDARD.encode(serialize(&reduced));
        let err = verify_bip322_simple("bitcoin", BIP322_P2WPKH_ADDRESS, "Hello World", &signature)
            .unwrap_err();
        assert_eq!(
            err,
            "BIP-322 P2WPKH proof must contain signature and public key"
        );
    }

    #[test]
    fn validate_payload_rejects_bad_schema() {
        let account = bip322_account();
        let address = account.address.clone();
        let mut payload = bip322_request_payload(&address, &bip322_request_message(&address));
        payload["schema"] = json!("wrong");
        assert_eq!(
            validate_bitcoin_bip322_proof_payload(&payload, &account).unwrap_err(),
            "Bitcoin BIP-322 payload has unsupported schema"
        );
    }

    #[test]
    fn validate_payload_rejects_wallet_intent_mismatch() {
        let account = bip322_account();
        let address = account.address.clone();
        let mut payload = bip322_request_payload(&address, &bip322_request_message(&address));
        payload["wallet_intent"] = json!("something_else");
        assert_eq!(
            validate_bitcoin_bip322_proof_payload(&payload, &account).unwrap_err(),
            "Bitcoin BIP-322 payload has mismatched wallet_intent"
        );
    }

    #[test]
    fn validate_payload_rejects_chain_mismatch() {
        let account = bip322_account();
        let address = account.address.clone();
        let mut payload = bip322_request_payload(&address, &bip322_request_message(&address));
        payload["chain_namespace"] = json!("bip122:other");
        assert_eq!(
            validate_bitcoin_bip322_proof_payload(&payload, &account).unwrap_err(),
            "Bitcoin BIP-322 payload chain does not match account"
        );
    }

    #[test]
    fn validate_payload_rejects_address_mismatch() {
        let account = bip322_account();
        let message = bip322_request_message(&account.address);
        let mut payload = bip322_request_payload(&account.address, &message);
        payload["address"] = json!("bc1qother");
        assert_eq!(
            validate_bitcoin_bip322_proof_payload(&payload, &account).unwrap_err(),
            "Bitcoin BIP-322 payload address does not match account"
        );
    }

    #[test]
    fn validate_payload_rejects_missing_message_field() {
        let account = bip322_account();
        let address = account.address.clone();
        let mut payload = bip322_request_payload(&address, &bip322_request_message(&address));
        payload
            .as_object_mut()
            .expect("the payload is a JSON object")
            .remove("message");
        assert_eq!(
            validate_bitcoin_bip322_proof_payload(&payload, &account).unwrap_err(),
            "Bitcoin BIP-322 payload missing message"
        );
    }

    #[test]
    fn validate_payload_rejects_message_without_challenge_binding() {
        let account = bip322_account();
        let message = format!(
            "wants you to prove Bitcoin account ownership {}",
            account.address
        );
        let payload = bip322_request_payload(&account.address, &message);
        assert_eq!(
            validate_bitcoin_bip322_proof_payload(&payload, &account).unwrap_err(),
            "Bitcoin BIP-322 message must bind a Runtime bitcoin challenge"
        );
    }

    #[test]
    fn proof_for_type_rejects_signature_type_mismatch() {
        let err = verify_bitcoin_proof_for_type(
            BITCOIN_PROOF_BIP322_SIMPLE,
            "ecdsa",
            "bitcoin",
            BIP322_P2WPKH_ADDRESS,
            "Hello World",
            BIP322_P2WPKH_WITNESS,
            None,
        )
        .unwrap_err();
        assert_eq!(
            err,
            "Bitcoin signature type ecdsa does not match required proof type bip322_simple"
        );
    }

    #[test]
    fn proof_for_type_rejects_missing_signed_message_public_key() {
        let err = verify_bitcoin_proof_for_type(
            BITCOIN_PROOF_SIGNED_MESSAGE,
            BITCOIN_PROOF_SIGNED_MESSAGE,
            "bitcoin",
            SIGNED_MESSAGE_P2PKH_ADDRESS,
            "Hello Legacy",
            "AAAA",
            None,
        )
        .unwrap_err();
        assert_eq!(err, "Bitcoin signed-message proof missing public key");
    }

    #[test]
    fn signed_message_rejects_unsupported_address_type() {
        let err = verify_bitcoin_signed_message(
            "bitcoin",
            BIP322_P2WPKH_ADDRESS,
            "Hello World",
            "AAAA",
            "00",
        )
        .unwrap_err();
        assert_eq!(
            err,
            "Bitcoin signed-message proof supports Legacy P2PKH and Nested SegWit P2SH-P2WPKH accounts only"
        );
    }

    #[test]
    fn signed_message_rejects_bad_public_key_hex() {
        let err = verify_bitcoin_signed_message(
            "bitcoin",
            SIGNED_MESSAGE_P2PKH_ADDRESS,
            "Hello Legacy",
            "AAAA",
            "zz",
        )
        .unwrap_err();
        assert!(err.starts_with("invalid Bitcoin public key"), "got {err}");
    }

    /// A managed Bitcoin proof request every payload check accepts for
    /// `address`, in the shape `request_approval` stores (`approval.rs:262`).
    fn bip322_signing_request(address: &str) -> WalletApprovalRequest {
        serde_json::from_value(json!({
            "schema": "elastos.wallet.approval_request/v1",
            "request_id": "req-bitcoin-proof",
            "kind": "signature",
            "status": "pending",
            "principal_id": "person:local:alice",
            "account_id": "wallet:bip122:mainnet:link",
            "proof_binding_id": "proof:wallet:bip122:mainnet",
            "chain_namespace": bitcoin_chain_namespace(Network::Bitcoin),
            "address": address,
            "intent": "bitcoin_bip322_proof",
            "requested_by_actor": "browser",
            "resource": "elastos://wallet/bip122:mainnet/sign/bitcoin_bip322_proof",
            "reason": "unit test Bitcoin proof",
            "payload": bip322_request_payload(address, &bip322_request_message(address)),
            "payload_hash": "hash-bitcoin-proof",
            "created_at": 0,
            "expires_at": 1_000,
        }))
        .expect("the Bitcoin proof request fixture is a valid approval request")
    }

    /// The base64 witness `verify_bip322_simple` reads, built from the two
    /// items a P2WPKH proof carries.
    fn bip322_witness(signature_item: Vec<u8>, pubkey_item: Vec<u8>) -> String {
        BASE64_STANDARD.encode(serialize(&Witness::from_slice(&[
            signature_item,
            pubkey_item,
        ])))
    }

    /// The signature and public key items of `BIP322_P2WPKH_WITNESS`, so a
    /// case can change one item and keep the other one valid.
    fn bip322_vector_witness_items() -> (Vec<u8>, Vec<u8>) {
        let bytes = BASE64_STANDARD
            .decode(BIP322_P2WPKH_WITNESS)
            .expect("the vector signature is base64");
        let witness: Witness = deserialize(&bytes).expect("the vector holds a witness");
        let mut items = witness.iter();
        let signature = items.next().expect("the vector has a signature").to_vec();
        let pubkey = items.next().expect("the vector has a public key").to_vec();
        (signature, pubkey)
    }

    /// Catches removal of the native-P2WPKH script guard in
    /// `sign_bip322_simple_p2wpkh_approval` at `:66`, which raises `:67`.
    /// `sign_managed_approval` (`crypto.rs:108`) is the production caller.
    #[test]
    fn signing_non_native_p2wpkh_account_is_refused() {
        let signing_key = SigningKey::from_slice(&[7_u8; 32]).expect("the fixed test key is valid");
        let request = bip322_signing_request(SIGNED_MESSAGE_P2PKH_ADDRESS);
        assert_eq!(
            sign_bip322_simple_p2wpkh_approval(&signing_key, &request),
            Err("managed Bitcoin account must be native P2WPKH".to_string())
        );
    }

    /// Catches removal of the address-shape guard in `verify_bip322_simple`
    /// at `:124`, which raises `:131`. `verify_bitcoin_proof_for_type`
    /// (`main.rs:640`) is the production caller.
    #[test]
    fn bitcoin_bip322_simple_legacy_address_is_refused() {
        let err = verify_bip322_simple(
            "bitcoin",
            SIGNED_MESSAGE_P2PKH_ADDRESS,
            "Hello World",
            BIP322_P2WPKH_WITNESS,
        )
        .unwrap_err();
        assert_eq!(
            err,
            "BIP-322 simple verification supports Native SegWit P2WPKH and Taproot P2TR accounts only; Legacy and Nested SegWit require bitcoin_signed_message proof"
        );
    }

    /// Catches removal of the compressed-key parse in
    /// `verify_bitcoin_signed_message` at `:153`, which raises `:154`.
    /// `verify_bitcoin_proof_for_type` (`main.rs:640`) is the caller.
    #[test]
    fn bitcoin_signed_message_malformed_compressed_key_is_refused() {
        let err = verify_bitcoin_signed_message(
            "bitcoin",
            SIGNED_MESSAGE_P2PKH_ADDRESS,
            "Hello Legacy",
            "AAAA",
            "00",
        )
        .unwrap_err();
        assert_eq!(
            err,
            "invalid compressed Bitcoin public key: malformed public key"
        );
    }

    /// Catches removal of the signature-verification guard in
    /// `verify_bitcoin_signed_message` at `:169`, which raises `:170`.
    /// `verify_bitcoin_proof_for_type` (`main.rs:640`) is the caller.
    #[test]
    fn bitcoin_signed_message_wrong_key_signature_is_refused() {
        let signing_key = SigningKey::from_slice(&[7_u8; 32]).expect("the fixed test key is valid");
        let other_key = SigningKey::from_slice(&[9_u8; 32]).expect("the second test key is valid");
        let pubkey = signing_key.verifying_key().to_encoded_point(true);
        let compressed = ::bitcoin::CompressedPublicKey::from_slice(pubkey.as_bytes())
            .expect("a k256 verifying key is a valid compressed Bitcoin key");
        let address = ::bitcoin::Address::p2pkh(compressed, Network::Bitcoin).to_string();
        let hash = bitcoin_signed_message_hash(b"Hello Legacy");
        let (signature, recovery_id) = other_key
            .sign_prehash_recoverable(&hash)
            .expect("the second test key signs a digest");
        let mut compact = vec![27 + recovery_id.to_byte()];
        compact.extend_from_slice(signature.to_bytes().as_ref());
        let err = verify_bitcoin_signed_message(
            "bitcoin",
            &address,
            "Hello Legacy",
            &BASE64_STANDARD.encode(compact),
            &hex::encode(pubkey.as_bytes()),
        )
        .unwrap_err();
        assert_eq!(err, "invalid Bitcoin signed-message signature");
    }

    /// Catches removal of the base64 decode in `bitcoin_compact_signature` at
    /// `:217`, which raises `:219`. `verify_bitcoin_signed_message` (`:167`)
    /// reaches it, called from `main.rs:640`.
    #[test]
    fn bitcoin_signed_message_non_base64_signature_is_refused() {
        let err = bitcoin_compact_signature("{not*base64").unwrap_err();
        assert_eq!(
            err,
            "invalid Bitcoin signed-message base64 signature: Invalid symbol 123, offset 0."
        );
    }

    /// Catches removal of the length arm in `bitcoin_compact_signature` at
    /// `:220`, which raises `:223`. `verify_bitcoin_signed_message` (`:167`)
    /// reaches it, called from `main.rs:640`.
    #[test]
    fn bitcoin_signed_message_wrong_signature_length_is_refused() {
        let err = bitcoin_compact_signature(&BASE64_STANDARD.encode([0_u8, 0, 0])).unwrap_err();
        assert_eq!(
            err,
            "Bitcoin signed-message signature must be 64 or 65 bytes"
        );
    }

    /// Catches removal of the compact-signature parse in
    /// `bitcoin_compact_signature` at `:225`, which raises `:226`.
    /// `verify_bitcoin_signed_message` (`:167`) reaches it, called from
    /// `main.rs:640`.
    #[test]
    fn bitcoin_signed_message_invalid_compact_signature_is_refused() {
        let signature = BASE64_STANDARD.encode([0xff_u8; 64]);
        let err = bitcoin_compact_signature(&signature).unwrap_err();
        assert_eq!(
            err,
            "invalid Bitcoin signed-message signature: signature error"
        );
    }

    /// Catches removal of the witness-length guard in
    /// `verify_bip322_simple_p2wpkh` at `:293`, which raises `:294`.
    /// `verify_bitcoin_proof_for_type` (`main.rs:640`) is the caller.
    #[test]
    fn bitcoin_bip322_simple_short_signature_witness_is_refused() {
        let (_, pubkey) = bip322_vector_witness_items();
        let signature = bip322_witness(vec![0x01], pubkey);
        let err = verify_bip322_simple("bitcoin", BIP322_P2WPKH_ADDRESS, "Hello World", &signature)
            .unwrap_err();
        assert_eq!(err, "BIP-322 signature witness is too short");
    }

    /// Catches removal of the sighash-type guard in
    /// `verify_bip322_simple_p2wpkh` at `:299`, which raises `:300`.
    /// `verify_bitcoin_proof_for_type` (`main.rs:640`) is the caller.
    #[test]
    fn bitcoin_bip322_simple_non_sighash_all_witness_is_refused() {
        let (mut signature_item, pubkey) = bip322_vector_witness_items();
        let sighash_byte = signature_item
            .last_mut()
            .expect("the vector signature carries a sighash byte");
        *sighash_byte = EcdsaSighashType::None as u8;
        let signature = bip322_witness(signature_item, pubkey);
        let err = verify_bip322_simple("bitcoin", BIP322_P2WPKH_ADDRESS, "Hello World", &signature)
            .unwrap_err();
        assert_eq!(err, "BIP-322 P2WPKH proof must use SIGHASH_ALL");
    }

    /// Catches removal of the public-key-hash guard in
    /// `verify_bip322_simple_p2wpkh` at `:309`, which raises `:310`.
    /// `verify_bitcoin_proof_for_type` (`main.rs:640`) is the caller.
    #[test]
    fn bitcoin_bip322_simple_foreign_public_key_is_refused() {
        let (signature_item, _) = bip322_vector_witness_items();
        let other_key = SigningKey::from_slice(&[9_u8; 32]).expect("the second test key is valid");
        let other_pubkey = other_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let signature = bip322_witness(signature_item, other_pubkey);
        let err = verify_bip322_simple("bitcoin", BIP322_P2WPKH_ADDRESS, "Hello World", &signature)
            .unwrap_err();
        assert_eq!(err, "BIP-322 public key does not match Bitcoin address");
    }

    /// Catches removal of the DER parse in `verify_bip322_simple_p2wpkh` at
    /// `:320`, which raises `:321`. `verify_bitcoin_proof_for_type`
    /// (`main.rs:640`) is the caller.
    #[test]
    fn bitcoin_bip322_simple_malformed_der_signature_is_refused() {
        let (_, pubkey) = bip322_vector_witness_items();
        let signature = bip322_witness(vec![0x00, EcdsaSighashType::All as u8], pubkey);
        let err = verify_bip322_simple("bitcoin", BIP322_P2WPKH_ADDRESS, "Hello World", &signature)
            .unwrap_err();
        assert_eq!(err, "invalid BIP-322 DER signature: signature error");
    }

    /// An invalid compressed public key, and the P2WPKH address built over its
    /// own hash, so the key passes the address check and reaches its parse.
    fn bip322_address_over_foreign_key(pubkey: &[u8]) -> String {
        let program = hash160::Hash::hash(pubkey);
        let witness_program =
            ::bitcoin::WitnessProgram::new(::bitcoin::WitnessVersion::V0, program.as_byte_array())
                .expect("a 20-byte V0 program is a valid witness program");
        ::bitcoin::Address::from_witness_program(witness_program, ::bitcoin::KnownHrp::Mainnet)
            .to_string()
    }

    /// Catches removal of the public-key parse in
    /// `verify_bip322_simple_p2wpkh` at `:318`, which raises `:319`, by
    /// carrying a 33-byte key the address was built over and secp256k1
    /// rejects. `verify_bitcoin_proof_for_type` (`main.rs:640`) is the caller.
    #[test]
    fn bitcoin_bip322_simple_malformed_public_key_is_refused() {
        let malformed_pubkey = vec![0x05_u8; 33];
        let address = bip322_address_over_foreign_key(&malformed_pubkey);
        let signature = bip322_witness(vec![0x00, EcdsaSighashType::All as u8], malformed_pubkey);
        let err = verify_bip322_simple("bitcoin", &address, "Hello World", &signature).unwrap_err();
        assert_eq!(err, "invalid BIP-322 public key: signature error");
    }

    /// A mainnet P2TR address whose 32-byte program is not a curve point, so
    /// `XOnlyPublicKey::from_slice` on it fails.
    fn bip322_address_over_invalid_output_key() -> String {
        let program = ::bitcoin::WitnessProgram::new(::bitcoin::WitnessVersion::V1, &[0xff_u8; 32])
            .expect("a 32-byte V1 program is a valid witness program");
        ::bitcoin::Address::from_witness_program(program, ::bitcoin::KnownHrp::Mainnet).to_string()
    }

    /// Catches removal of the output-key parse in `verify_bip322_simple_p2tr`
    /// at `:352`, which raises `:353`. `verify_bitcoin_proof_for_type`
    /// (`main.rs:640`) is the caller.
    #[test]
    fn bitcoin_invalid_taproot_output_key_is_refused() {
        let address = bip322_address_over_invalid_output_key();
        let signature = BASE64_STANDARD.encode(serialize(&Witness::from_slice(&[vec![0_u8; 64]])));
        let err = verify_bip322_simple("bitcoin", &address, "Hello World", &signature).unwrap_err();
        assert_eq!(err, "invalid Taproot output key: malformed public key");
    }

    /// Catches removal of the single-item witness guard in
    /// `verify_bip322_simple_p2tr` at `:342`, which raises `:343`.
    /// `verify_bitcoin_proof_for_type` (`main.rs:640`) is the caller.
    #[test]
    fn bitcoin_bip322_simple_two_item_taproot_witness_is_refused() {
        let secret_key = bip322_test_taproot_secret_key();
        let address = bip322_test_taproot_address(&secret_key);
        let signature = BASE64_STANDARD.encode(serialize(&Witness::from_slice(&[
            vec![0_u8; 64],
            vec![0_u8; 33],
        ])));
        let err = verify_bip322_simple("bitcoin", &address, "Hello World", &signature).unwrap_err();
        assert_eq!(err, "BIP-322 P2TR proof must contain one Schnorr signature");
    }

    /// Catches removal of the Schnorr parse in `verify_bip322_simple_p2tr` at
    /// `:349`, which raises `:350`. `verify_bitcoin_proof_for_type`
    /// (`main.rs:640`) is the caller.
    #[test]
    fn bitcoin_bip322_simple_malformed_taproot_signature_is_refused() {
        let secret_key = bip322_test_taproot_secret_key();
        let address = bip322_test_taproot_address(&secret_key);
        let signature = BASE64_STANDARD.encode(serialize(&Witness::from_slice(&[vec![0x01]])));
        let err = verify_bip322_simple("bitcoin", &address, "Hello World", &signature).unwrap_err();
        assert_eq!(
            err,
            "invalid BIP-322 Taproot signature: invalid taproot signature size: 1"
        );
    }

    /// Catches removal of the Schnorr verification in
    /// `verify_bip322_simple_p2tr` at `:365`, which raises `:366`, by carrying
    /// a well-formed 64-byte signature from a second Taproot key.
    /// `verify_bitcoin_proof_for_type` (`main.rs:640`) is the caller.
    #[test]
    fn bitcoin_bip322_simple_foreign_taproot_signature_is_refused() {
        let address = bip322_test_taproot_address(&bip322_test_taproot_secret_key());
        let other_key = ::bitcoin::secp256k1::SecretKey::from_slice(&[9_u8; 32])
            .expect("the second Taproot key is valid");
        let signature = sign_bip322_simple_p2tr(
            &other_key,
            &bip322_test_taproot_address(&other_key),
            "Hello",
        );
        let err = verify_bip322_simple("bitcoin", &address, "Hello World", &signature).unwrap_err();
        assert_eq!(err, "invalid BIP-322 Taproot signature");
    }

    /// Catches removal of the message-size guard in
    /// `validate_bitcoin_bip322_proof_payload` at `:483`, which raises `:484`.
    /// `main.rs:957` is the caller, through the Bitcoin challenge for signing.
    #[test]
    fn bitcoin_bip322_payload_empty_message_is_refused() {
        let account = bip322_account();
        let payload = bip322_request_payload(&account.address, "");
        assert_eq!(
            validate_bitcoin_bip322_proof_payload(&payload, &account).unwrap_err(),
            "Bitcoin BIP-322 message size is invalid"
        );
    }

    /// Catches removal of the address-binding guard in
    /// `validate_bitcoin_bip322_proof_payload` at `:489`, which raises `:490`.
    /// `main.rs:957` is the caller, through the Bitcoin challenge for signing.
    #[test]
    fn bitcoin_bip322_payload_foreign_address_message_is_refused() {
        let account = bip322_account();
        let message = bip322_request_message(SIGNED_MESSAGE_P2PKH_ADDRESS);
        let payload = bip322_request_payload(&account.address, &message);
        assert_eq!(
            validate_bitcoin_bip322_proof_payload(&payload, &account).unwrap_err(),
            "Bitcoin BIP-322 message address does not match account"
        );
    }
}
