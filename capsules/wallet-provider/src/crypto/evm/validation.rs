use super::super::*;
use super::payload::{
    payload_evm_address_bytes, payload_hex_bytes, payload_quantity_bytes, payload_str, payload_u64,
};
use super::typed_data::validate_eip712_typed_data_shape;
use elastos_auth::{normalize_evm_address, validate_evm_address};
use serde_json::Value;

fn parse_eip712_domain_chain_id(value: &Value) -> Result<u64, String> {
    if let Some(chain_id) = value.as_u64() {
        return Ok(chain_id);
    }
    let invalid = || {
        "EIP-712 domain.chainId must be an unsigned u64 integer or an exact decimal/0x-prefixed string"
            .to_string()
    };
    let raw = value.as_str().ok_or_else(invalid)?;
    if let Some(hex) = raw.strip_prefix("0x") {
        if hex.is_empty()
            || !hex
                .chars()
                .all(|ch| ch.is_ascii_digit() || ('a'..='f').contains(&ch))
        {
            return Err(invalid());
        }
        return u64::from_str_radix(hex, 16).map_err(|_| invalid());
    }
    if raw.is_empty() || !raw.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(invalid());
    }
    raw.parse::<u64>().map_err(|_| invalid())
}

pub(crate) fn validate_eip712_domain_chain_id(
    typed_data: &Value,
    requested_chain_namespace: &str,
) -> Result<(), String> {
    let requested_chain_id = eip155_chain_id(requested_chain_namespace)?;
    let Some(domain_chain_id) = typed_data
        .get("domain")
        .and_then(Value::as_object)
        .and_then(|domain| domain.get("chainId"))
    else {
        return Ok(());
    };
    if parse_eip712_domain_chain_id(domain_chain_id)? != requested_chain_id {
        return Err("EIP-712 domain.chainId does not match requested chain namespace".to_string());
    }
    Ok(())
}

pub(crate) fn validate_browser_personal_sign_payload(
    payload: &Value,
    account: &LinkedAccount,
) -> Result<(), String> {
    if payload.get("schema").and_then(Value::as_str)
        != Some("elastos.browser.wallet-signature-request/v1")
    {
        return Err("Browser wallet signature payload has unsupported schema".to_string());
    }
    if payload.get("method").and_then(Value::as_str) != Some("personal_sign") {
        return Err("Browser wallet signature method must be personal_sign".to_string());
    }
    let chain_namespace = payload
        .get("chain_namespace")
        .and_then(Value::as_str)
        .ok_or_else(|| "Browser wallet signature payload missing chain_namespace".to_string())?;
    if !chain_namespaces_compatible(&account.chain_namespace, chain_namespace) {
        return Err("Browser wallet signature chain does not match account".to_string());
    }
    if !account.chain_namespace.starts_with("eip155:") || !chain_namespace.starts_with("eip155:") {
        return Err("Browser personal_sign requires an EVM account".to_string());
    }
    let address = payload
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| "Browser wallet signature payload missing address".to_string())?;
    validate_evm_address(address)?;
    if normalize_evm_address(address) != normalize_evm_address(&account.address) {
        return Err("Browser wallet signature address does not match account".to_string());
    }
    let account_id = payload
        .get("account_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "Browser wallet signature payload missing account_id".to_string())?;
    if account_id != account.account_id {
        return Err("Browser wallet signature account_id does not match account".to_string());
    }
    let message = payload
        .get("message")
        .and_then(Value::as_str)
        .ok_or_else(|| "Browser wallet signature payload missing message".to_string())?;
    if message.is_empty() || message.len() > MAX_APPROVAL_PAYLOAD_BYTES {
        return Err("Browser wallet signature message size is invalid".to_string());
    }
    if message.chars().any(char::is_control) {
        return Err("Browser wallet signature message contains control characters".to_string());
    }
    let page_url = payload
        .get("page_url")
        .and_then(Value::as_str)
        .ok_or_else(|| "Browser wallet signature payload missing page_url".to_string())?;
    if !(page_url.starts_with("https://") || page_url.starts_with("http://")) {
        return Err("Browser wallet signature page_url must be http or https".to_string());
    }
    if payload
        .get("requires_wallet_approval")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err("Browser wallet signature must require wallet approval".to_string());
    }
    Ok(())
}

pub(crate) fn validate_browser_typed_data_sign_payload(
    payload: &Value,
    account: &LinkedAccount,
) -> Result<(), String> {
    if payload.get("schema").and_then(Value::as_str)
        != Some("elastos.browser.wallet-signature-request/v1")
    {
        return Err("Browser typed-data payload has unsupported schema".to_string());
    }
    let method = payload
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| "Browser typed-data payload missing method".to_string())?;
    if !matches!(
        method,
        "eth_signTypedData" | "eth_signTypedData_v3" | "eth_signTypedData_v4"
    ) {
        return Err("Browser typed-data method is unsupported".to_string());
    }
    let chain_namespace = payload
        .get("chain_namespace")
        .and_then(Value::as_str)
        .ok_or_else(|| "Browser typed-data payload missing chain_namespace".to_string())?;
    if !chain_namespaces_compatible(&account.chain_namespace, chain_namespace) {
        return Err("Browser typed-data chain does not match account".to_string());
    }
    if !account.chain_namespace.starts_with("eip155:") || !chain_namespace.starts_with("eip155:") {
        return Err("Browser typed-data signatures require an EVM account".to_string());
    }
    let address = payload
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| "Browser typed-data payload missing address".to_string())?;
    validate_evm_address(address)?;
    if normalize_evm_address(address) != normalize_evm_address(&account.address) {
        return Err("Browser typed-data address does not match account".to_string());
    }
    let account_id = payload
        .get("account_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "Browser typed-data payload missing account_id".to_string())?;
    if account_id != account.account_id {
        return Err("Browser typed-data account_id does not match account".to_string());
    }
    let canonical = payload
        .get("typed_data_canonical")
        .and_then(Value::as_str)
        .ok_or_else(|| "Browser typed-data payload missing canonical typed data".to_string())?;
    if canonical.is_empty() || canonical.len() > MAX_APPROVAL_PAYLOAD_BYTES {
        return Err("Browser typed-data payload size is invalid".to_string());
    }
    let typed_data: Value =
        serde_json::from_str(canonical).map_err(|err| format!("invalid typed data: {err}"))?;
    validate_eip712_typed_data_shape(&typed_data)?;
    validate_eip712_domain_chain_id(&typed_data, chain_namespace)?;
    let page_url = payload
        .get("page_url")
        .and_then(Value::as_str)
        .ok_or_else(|| "Browser typed-data payload missing page_url".to_string())?;
    if !(page_url.starts_with("https://") || page_url.starts_with("http://")) {
        return Err("Browser typed-data page_url must be http or https".to_string());
    }
    if payload
        .get("requires_wallet_approval")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err("Browser typed-data signature must require wallet approval".to_string());
    }
    Ok(())
}

pub(crate) fn validate_eip155_transaction_intent_payload(
    payload: &Value,
    account: &LinkedAccount,
) -> Result<(), String> {
    if payload.get("schema").and_then(Value::as_str)
        != Some("elastos.chain.unsigned_transaction_intent/v1")
    {
        return Err("transaction intent payload has unsupported schema".to_string());
    }
    if payload.get("transaction_type").and_then(Value::as_str) != Some("eip155_legacy") {
        return Err("transaction intent payload must be eip155_legacy".to_string());
    }
    if payload.get("wallet_intent").and_then(Value::as_str) != Some("transaction_intent") {
        return Err("transaction intent payload has mismatched wallet_intent".to_string());
    }
    if payload
        .get("requires_wallet_approval")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err("transaction intent must require wallet approval".to_string());
    }
    let chain_id = payload_u64(payload, "chain_id")?;
    if !account.chain_namespace.starts_with("eip155:") {
        return Err("transaction intent requires an EVM account".to_string());
    }
    if chain_id == 0 {
        return Err("transaction intent chain_id must be non-zero".to_string());
    }
    let from = payload_str(payload, "from")?;
    validate_evm_address(from)?;
    if normalize_evm_address(from) != normalize_evm_address(&account.address) {
        return Err("transaction intent from address does not match account".to_string());
    }
    payload_evm_address_bytes(payload, "to")?;
    payload_quantity_bytes(payload, "nonce")?;
    payload_quantity_bytes(payload, "gas_price")?;
    payload_quantity_bytes(payload, "gas_limit")?;
    payload_quantity_bytes(payload, "value")?;
    payload_hex_bytes(payload, "data")?;
    Ok(())
}

/// One test per refusal this validator raises, each asserting the whole `Err`
/// value. They pin answers the validator already gives: they add no rule and
/// register no falsifier. They prove what the wallet provider answers a page's
/// payload, not confinement: the Runtime decides whether the provider runs.
///
/// Where the text carries a format argument, the test names the text this
/// input makes the code produce, not the template.
///
/// Two strings stand at more than one site.
/// `EIP-712 domain.chainId must be an unsigned u64 integer or an exact
/// decimal/0x-prefixed string` is one closure (`:13`) raised at `:17`, `:24`,
/// `:26`, `:29` and `:31`, so its test drives all five. `invalid typed data:
/// {err}` is raised here at `:168` and again in `typed_data.rs`; this test
/// pins the copy this validator raises, and the `typed_data.rs` copy belongs to
/// that file's tests.
#[cfg(test)]
mod uf_validation_refusal_tests {
    use super::*;
    use serde_json::json;

    const ADDRESS: &str = "0x1111111111111111111111111111111111111111";
    const OTHER_ADDRESS: &str = "0x2222222222222222222222222222222222222222";
    const ACCOUNT_ID: &str = "wallet:eip155:20:0x1111111111111111111111111111111111111111";
    const BITCOIN_CHAIN_NAMESPACE: &str = "bip122:000000000019d6689c085ae165831e93";

    /// The account every case starts from: an EVM account on `eip155:20` whose
    /// address and id are the ones `personal_sign_payload` and
    /// `typed_data_payload` carry.
    fn account() -> LinkedAccount {
        LinkedAccount {
            account_id: ACCOUNT_ID.to_string(),
            principal_id: "person:local:alice".to_string(),
            proof_binding_id: format!("proof:eip155:20:{ADDRESS}"),
            chain_namespace: "eip155:20".to_string(),
            address: ADDRESS.to_string(),
            proof_type: MANAGED_EVM_PROOF_TYPE.to_string(),
            connector_id: None,
            label: None,
            linked_at: 0,
            revoked_at: None,
        }
    }

    /// An account on a chain that is not `eip155`, so the EVM-only checks of
    /// all three validators refuse it before any of their other checks run.
    fn bitcoin_account() -> LinkedAccount {
        LinkedAccount {
            chain_namespace: BITCOIN_CHAIN_NAMESPACE.to_string(),
            ..account()
        }
    }

    /// A personal_sign payload the validator accepts, so a case changes one
    /// field and meets the check it names.
    fn personal_sign_payload() -> Value {
        json!({
            "schema": "elastos.browser.wallet-signature-request/v1",
            "method": "personal_sign",
            "chain_namespace": "eip155:20",
            "address": ADDRESS,
            "account_id": ACCOUNT_ID,
            "message": "Sign in to Glide",
            "page_url": "https://glidefinance.io/",
            "requires_wallet_approval": true
        })
    }

    /// A typed-data payload the validator accepts: its canonical text parses,
    /// passes the shape check, and names no `domain.chainId`.
    fn typed_data_payload() -> Value {
        let canonical = json!({
            "types": {
                "EIP712Domain": [],
                "Message": [{ "name": "field", "type": "string" }]
            },
            "primaryType": "Message",
            "domain": {},
            "message": { "field": "hello" }
        })
        .to_string();
        json!({
            "schema": "elastos.browser.wallet-signature-request/v1",
            "method": "eth_signTypedData_v4",
            "chain_namespace": "eip155:20",
            "address": ADDRESS,
            "account_id": ACCOUNT_ID,
            "typed_data_canonical": canonical,
            "page_url": "https://glidefinance.io/",
            "requires_wallet_approval": true
        })
    }

    /// A legacy transaction intent the validator accepts, so a case changes
    /// one field and meets the check it names.
    fn transaction_payload() -> Value {
        json!({
            "schema": "elastos.chain.unsigned_transaction_intent/v1",
            "transaction_type": "eip155_legacy",
            "wallet_intent": "transaction_intent",
            "requires_wallet_approval": true,
            "chain_id": 20,
            "from": ADDRESS,
            "to": "0x3333333333333333333333333333333333333333",
            "nonce": "0x0",
            "gas_price": "0x1",
            "gas_limit": "0x5208",
            "value": "0x0",
            "data": "0x"
        })
    }

    fn refuse_personal_sign(payload: Value, account: &LinkedAccount) -> String {
        validate_browser_personal_sign_payload(&payload, account).unwrap_err()
    }

    fn refuse_typed_data(payload: Value, account: &LinkedAccount) -> String {
        validate_browser_typed_data_sign_payload(&payload, account).unwrap_err()
    }

    fn refuse_transaction(payload: Value, account: &LinkedAccount) -> String {
        validate_eip155_transaction_intent_payload(&payload, account).unwrap_err()
    }

    /// The closure (`:13`) raises this string at five points, and this test
    /// drives each: `:17` a value that is neither an unsigned integer nor a
    /// string, `:24` an empty `0x` body, `:26` a `0x` body that is not lower
    /// hex or overflows a `u64`, `:29` an empty decimal or one with a
    /// non-digit, and `:31` a decimal that overflows a `u64`.
    ///
    /// `:29` is redundant with `:31`: `str::parse::<u64>` refuses the same
    /// empty and non-digit text, and both answer the same string, so removing
    /// `:29` changes no answer a caller can see. The test still drives the
    /// text through it, which is what pins the refusal.
    ///
    /// Falsifier: read any string as a chain id through `parse().unwrap_or(1)`,
    /// so a malformed `domain.chainId` passes as chain 1.
    #[test]
    fn domain_chain_id_text_is_refused() {
        let reason = "EIP-712 domain.chainId must be an unsigned u64 integer or an exact decimal/0x-prefixed string";
        for value in [
            json!(null),
            json!("0x"),
            json!("0xABCDEF"),
            json!("0x10000000000000000"),
            json!(""),
            json!("12a"),
            json!("18446744073709551616"),
        ] {
            assert_eq!(parse_eip712_domain_chain_id(&value).unwrap_err(), reason);
        }
    }

    /// Falsifier: drop the comparison and answer `Ok`, so a typed-data page
    /// signs for a chain the account is not bound to.
    #[test]
    fn domain_chain_id_mismatch_is_refused() {
        assert_eq!(
            validate_eip712_domain_chain_id(&json!({ "domain": { "chainId": 21 } }), "eip155:20")
                .unwrap_err(),
            "EIP-712 domain.chainId does not match requested chain namespace"
        );
    }

    /// Falsifier: accept any `schema` string, so a payload written for another
    /// contract reaches the personal_sign path.
    #[test]
    fn personal_sign_schema_is_refused() {
        let mut payload = personal_sign_payload();
        payload["schema"] = json!("elastos.browser.wallet-signature-request/v2");
        assert_eq!(
            refuse_personal_sign(payload, &account()),
            "Browser wallet signature payload has unsupported schema"
        );
    }

    /// Falsifier: read the method as informational, so an `eth_sign` request
    /// signs through the personal_sign path.
    #[test]
    fn personal_sign_method_is_refused() {
        let mut payload = personal_sign_payload();
        payload["method"] = json!("eth_sign");
        assert_eq!(
            refuse_personal_sign(payload, &account()),
            "Browser wallet signature method must be personal_sign"
        );
    }

    /// Falsifier: default a missing `chain_namespace` to the account's chain,
    /// so a payload that names no chain signs on the account's.
    #[test]
    fn personal_sign_missing_chain_namespace_is_refused() {
        let mut payload = personal_sign_payload();
        payload.as_object_mut().unwrap().remove("chain_namespace");
        assert_eq!(
            refuse_personal_sign(payload, &account()),
            "Browser wallet signature payload missing chain_namespace"
        );
    }

    /// Falsifier: compare only the `eip155` family, so a request from another
    /// chain passes for an EVM account.
    #[test]
    fn personal_sign_chain_mismatch_is_refused() {
        let mut payload = personal_sign_payload();
        payload["chain_namespace"] = json!(BITCOIN_CHAIN_NAMESPACE);
        assert_eq!(
            refuse_personal_sign(payload, &account()),
            "Browser wallet signature chain does not match account"
        );
    }

    /// Falsifier: run personal_sign for any account, so a Bitcoin account
    /// reaches the EVM signer.
    #[test]
    fn personal_sign_requires_evm_account() {
        let mut payload = personal_sign_payload();
        payload["chain_namespace"] = json!(BITCOIN_CHAIN_NAMESPACE);
        assert_eq!(
            refuse_personal_sign(payload, &bitcoin_account()),
            "Browser personal_sign requires an EVM account"
        );
    }

    /// Falsifier: default a missing `address` to the account's address, so the
    /// payload never states which account it signs for.
    #[test]
    fn personal_sign_missing_address_is_refused() {
        let mut payload = personal_sign_payload();
        payload.as_object_mut().unwrap().remove("address");
        assert_eq!(
            refuse_personal_sign(payload, &account()),
            "Browser wallet signature payload missing address"
        );
    }

    /// Falsifier: sign with the account's key while the payload names another
    /// address, so the page receives a signature for a different account.
    #[test]
    fn personal_sign_address_mismatch_is_refused() {
        let mut payload = personal_sign_payload();
        payload["address"] = json!(OTHER_ADDRESS);
        assert_eq!(
            refuse_personal_sign(payload, &account()),
            "Browser wallet signature address does not match account"
        );
    }

    /// Falsifier: default a missing `account_id` to the account's id, so the
    /// payload does not bind the id it signs under.
    #[test]
    fn personal_sign_missing_account_id_is_refused() {
        let mut payload = personal_sign_payload();
        payload.as_object_mut().unwrap().remove("account_id");
        assert_eq!(
            refuse_personal_sign(payload, &account()),
            "Browser wallet signature payload missing account_id"
        );
    }

    /// Falsifier: compare addresses only, so an approval for one account id
    /// completes against another account with the same address.
    #[test]
    fn personal_sign_account_id_mismatch_is_refused() {
        let mut payload = personal_sign_payload();
        payload["account_id"] =
            json!("wallet:eip155:20:0x2222222222222222222222222222222222222222");
        assert_eq!(
            refuse_personal_sign(payload, &account()),
            "Browser wallet signature account_id does not match account"
        );
    }

    /// Falsifier: sign the empty message when the payload omits `message`, so
    /// the page receives a signature over text it never sent.
    #[test]
    fn personal_sign_missing_message_is_refused() {
        let mut payload = personal_sign_payload();
        payload.as_object_mut().unwrap().remove("message");
        assert_eq!(
            refuse_personal_sign(payload, &account()),
            "Browser wallet signature payload missing message"
        );
    }

    /// Falsifier: sign any message length, so an empty or oversized message
    /// reaches the signer.
    #[test]
    fn personal_sign_message_size_is_refused() {
        let reason = "Browser wallet signature message size is invalid";
        let mut empty = personal_sign_payload();
        empty["message"] = json!("");
        assert_eq!(refuse_personal_sign(empty, &account()), reason);
        let mut oversized = personal_sign_payload();
        oversized["message"] = json!("a".repeat(MAX_APPROVAL_PAYLOAD_BYTES + 1));
        assert_eq!(refuse_personal_sign(oversized, &account()), reason);
    }

    /// Falsifier: sign text that carries control characters, so a message a
    /// prompt shows as one line reaches the signer as several.
    #[test]
    fn personal_sign_control_characters_are_refused() {
        let mut payload = personal_sign_payload();
        payload["message"] = json!("Sign in\u{7}to Glide");
        assert_eq!(
            refuse_personal_sign(payload, &account()),
            "Browser wallet signature message contains control characters"
        );
    }

    /// Falsifier: default a missing `page_url` to the account's origin, so the
    /// signature records a page the payload never named.
    #[test]
    fn personal_sign_missing_page_url_is_refused() {
        let mut payload = personal_sign_payload();
        payload.as_object_mut().unwrap().remove("page_url");
        assert_eq!(
            refuse_personal_sign(payload, &account()),
            "Browser wallet signature payload missing page_url"
        );
    }

    /// Falsifier: accept any scheme, so a page served from `file:` or `ftp:`
    /// makes the wallet sign.
    #[test]
    fn personal_sign_page_url_scheme_is_refused() {
        let mut payload = personal_sign_payload();
        payload["page_url"] = json!("ftp://glidefinance.io/");
        assert_eq!(
            refuse_personal_sign(payload, &account()),
            "Browser wallet signature page_url must be http or https"
        );
    }

    /// Falsifier: treat a payload without the approval flag as approved, so a
    /// page's request signs without the user's approval step.
    #[test]
    fn personal_sign_without_required_approval_is_refused() {
        let mut payload = personal_sign_payload();
        payload["requires_wallet_approval"] = json!(false);
        assert_eq!(
            refuse_personal_sign(payload, &account()),
            "Browser wallet signature must require wallet approval"
        );
    }

    /// Falsifier: accept any `schema` string, so a payload written for another
    /// contract reaches the typed-data path.
    #[test]
    fn typed_data_schema_is_refused() {
        let mut payload = typed_data_payload();
        payload["schema"] = json!("elastos.browser.wallet-signature-request/v2");
        assert_eq!(
            refuse_typed_data(payload, &account()),
            "Browser typed-data payload has unsupported schema"
        );
    }

    /// Falsifier: hash with `eth_signTypedData_v4` when the payload names no
    /// method, so the page's method is replaced by a default.
    #[test]
    fn typed_data_missing_method_is_refused() {
        let mut payload = typed_data_payload();
        payload.as_object_mut().unwrap().remove("method");
        assert_eq!(
            refuse_typed_data(payload, &account()),
            "Browser typed-data payload missing method"
        );
    }

    /// Falsifier: accept any method string, so `eth_signTypedData_v1`, whose
    /// hashing rule this provider does not implement, reaches the v4 hasher.
    #[test]
    fn typed_data_method_is_refused() {
        let mut payload = typed_data_payload();
        payload["method"] = json!("eth_signTypedData_v1");
        assert_eq!(
            refuse_typed_data(payload, &account()),
            "Browser typed-data method is unsupported"
        );
    }

    /// Falsifier: default a missing `chain_namespace` to the account's chain,
    /// so a payload that names no chain signs on the account's.
    #[test]
    fn typed_data_missing_chain_namespace_is_refused() {
        let mut payload = typed_data_payload();
        payload.as_object_mut().unwrap().remove("chain_namespace");
        assert_eq!(
            refuse_typed_data(payload, &account()),
            "Browser typed-data payload missing chain_namespace"
        );
    }

    /// Falsifier: compare only the `eip155` family, so a request from another
    /// chain passes for an EVM account.
    #[test]
    fn typed_data_chain_mismatch_is_refused() {
        let mut payload = typed_data_payload();
        payload["chain_namespace"] = json!(BITCOIN_CHAIN_NAMESPACE);
        assert_eq!(
            refuse_typed_data(payload, &account()),
            "Browser typed-data chain does not match account"
        );
    }

    /// Falsifier: run typed-data signing for any account, so a Bitcoin account
    /// reaches the EIP-712 hasher.
    #[test]
    fn typed_data_requires_evm_account() {
        let mut payload = typed_data_payload();
        payload["chain_namespace"] = json!(BITCOIN_CHAIN_NAMESPACE);
        assert_eq!(
            refuse_typed_data(payload, &bitcoin_account()),
            "Browser typed-data signatures require an EVM account"
        );
    }

    /// Falsifier: default a missing `address` to the account's address, so the
    /// payload never states which account it signs for.
    #[test]
    fn typed_data_missing_address_is_refused() {
        let mut payload = typed_data_payload();
        payload.as_object_mut().unwrap().remove("address");
        assert_eq!(
            refuse_typed_data(payload, &account()),
            "Browser typed-data payload missing address"
        );
    }

    /// Falsifier: sign with the account's key while the payload names another
    /// address, so the page receives a signature for a different account.
    #[test]
    fn typed_data_address_mismatch_is_refused() {
        let mut payload = typed_data_payload();
        payload["address"] = json!(OTHER_ADDRESS);
        assert_eq!(
            refuse_typed_data(payload, &account()),
            "Browser typed-data address does not match account"
        );
    }

    /// Falsifier: default a missing `account_id` to the account's id, so the
    /// payload does not bind the id it signs under.
    #[test]
    fn typed_data_missing_account_id_is_refused() {
        let mut payload = typed_data_payload();
        payload.as_object_mut().unwrap().remove("account_id");
        assert_eq!(
            refuse_typed_data(payload, &account()),
            "Browser typed-data payload missing account_id"
        );
    }

    /// Falsifier: compare addresses only, so an approval for one account id
    /// completes against another account with the same address.
    #[test]
    fn typed_data_account_id_mismatch_is_refused() {
        let mut payload = typed_data_payload();
        payload["account_id"] =
            json!("wallet:eip155:20:0x2222222222222222222222222222222222222222");
        assert_eq!(
            refuse_typed_data(payload, &account()),
            "Browser typed-data account_id does not match account"
        );
    }

    /// Falsifier: hash the empty typed data when the payload omits canonical
    /// text, so the page receives a signature over a document it never sent.
    #[test]
    fn typed_data_missing_canonical_is_refused() {
        let mut payload = typed_data_payload();
        payload
            .as_object_mut()
            .unwrap()
            .remove("typed_data_canonical");
        assert_eq!(
            refuse_typed_data(payload, &account()),
            "Browser typed-data payload missing canonical typed data"
        );
    }

    /// Falsifier: hash any canonical length, so an empty or oversized document
    /// reaches the EIP-712 hasher.
    #[test]
    fn typed_data_payload_size_is_refused() {
        let reason = "Browser typed-data payload size is invalid";
        let mut empty = typed_data_payload();
        empty["typed_data_canonical"] = json!("");
        assert_eq!(refuse_typed_data(empty, &account()), reason);
        let mut oversized = typed_data_payload();
        oversized["typed_data_canonical"] = json!("a".repeat(MAX_APPROVAL_PAYLOAD_BYTES + 1));
        assert_eq!(refuse_typed_data(oversized, &account()), reason);
    }

    /// The `typed_data.rs` hasher raises this same template through
    /// `typed_data_from_payload`, for the payload form it reads. This test
    /// pins the copy the browser validator raises for malformed canonical
    /// text; the other copy belongs to that file's tests.
    ///
    /// Falsifier: answer `Ok` on canonical text that does not parse, so an
    /// unreadable document signs as the empty hash.
    #[test]
    fn typed_data_canonical_json_is_refused() {
        let mut payload = typed_data_payload();
        payload["typed_data_canonical"] = json!("{");
        assert_eq!(
            refuse_typed_data(payload, &account()),
            "invalid typed data: EOF while parsing an object at line 1 column 1"
        );
    }

    /// Falsifier: default a missing `page_url` to the account's origin, so the
    /// signature records a page the payload never named.
    #[test]
    fn typed_data_missing_page_url_is_refused() {
        let mut payload = typed_data_payload();
        payload.as_object_mut().unwrap().remove("page_url");
        assert_eq!(
            refuse_typed_data(payload, &account()),
            "Browser typed-data payload missing page_url"
        );
    }

    /// Falsifier: accept any scheme, so a page served from `file:` or `ftp:`
    /// makes the wallet sign.
    #[test]
    fn typed_data_page_url_scheme_is_refused() {
        let mut payload = typed_data_payload();
        payload["page_url"] = json!("ftp://glidefinance.io/");
        assert_eq!(
            refuse_typed_data(payload, &account()),
            "Browser typed-data page_url must be http or https"
        );
    }

    /// Falsifier: treat a payload without the approval flag as approved, so a
    /// page's request signs without the user's approval step.
    #[test]
    fn typed_data_without_required_approval_is_refused() {
        let mut payload = typed_data_payload();
        payload["requires_wallet_approval"] = json!(false);
        assert_eq!(
            refuse_typed_data(payload, &account()),
            "Browser typed-data signature must require wallet approval"
        );
    }

    /// Falsifier: accept any `schema` string, so a payload written for another
    /// contract reaches the transaction path.
    #[test]
    fn transaction_schema_is_refused() {
        let mut payload = transaction_payload();
        payload["schema"] = json!("elastos.chain.unsigned_transaction_intent/v2");
        assert_eq!(
            refuse_transaction(payload, &account()),
            "transaction intent payload has unsupported schema"
        );
    }

    /// Falsifier: sign a transaction of any type through the legacy encoder,
    /// so a typed (EIP-1559) intent receives a legacy signature.
    #[test]
    fn transaction_type_is_refused() {
        let mut payload = transaction_payload();
        payload["transaction_type"] = json!("eip155_1559");
        assert_eq!(
            refuse_transaction(payload, &account()),
            "transaction intent payload must be eip155_legacy"
        );
    }

    /// Falsifier: sign an intent whose declared wallet intent is another one,
    /// so an approval for one intent completes against the transaction path.
    #[test]
    fn transaction_wallet_intent_is_refused() {
        let mut payload = transaction_payload();
        payload["wallet_intent"] = json!("browser_personal_sign");
        assert_eq!(
            refuse_transaction(payload, &account()),
            "transaction intent payload has mismatched wallet_intent"
        );
    }

    /// Falsifier: treat an intent without the approval flag as approved, so a
    /// capsule's request signs without the user's approval step.
    #[test]
    fn transaction_without_required_approval_is_refused() {
        let mut payload = transaction_payload();
        payload
            .as_object_mut()
            .unwrap()
            .remove("requires_wallet_approval");
        assert_eq!(
            refuse_transaction(payload, &account()),
            "transaction intent must require wallet approval"
        );
    }

    /// Falsifier: sign a transaction for a Bitcoin account, so EIP-155 bytes
    /// are produced from a key bound to another chain family.
    #[test]
    fn transaction_requires_evm_account() {
        assert_eq!(
            refuse_transaction(transaction_payload(), &bitcoin_account()),
            "transaction intent requires an EVM account"
        );
    }

    /// Falsifier: sign chain id 0, which EIP-155 does not define, so the
    /// signature replays on every chain that accepts it.
    #[test]
    fn transaction_zero_chain_id_is_refused() {
        let mut payload = transaction_payload();
        payload["chain_id"] = json!(0);
        assert_eq!(
            refuse_transaction(payload, &account()),
            "transaction intent chain_id must be non-zero"
        );
    }

    /// Falsifier: sign with the account's key while the payload names another
    /// sender, so the page receives a transaction from a different account.
    #[test]
    fn transaction_from_mismatch_is_refused() {
        let mut payload = transaction_payload();
        payload["from"] = json!(OTHER_ADDRESS);
        assert_eq!(
            refuse_transaction(payload, &account()),
            "transaction intent from address does not match account"
        );
    }
}
