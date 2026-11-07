use super::*;
use elastos_auth::{normalize_evm_address, validate_evm_address, validate_siwe_origin_binding};
use sha2::Digest;

pub(super) struct LinkAccountInput {
    pub(super) principal_id: String,
    pub(super) proof_binding_id: String,
    pub(super) chain_namespace: String,
    pub(super) address: String,
    pub(super) proof_type: String,
    pub(super) connector_id: Option<String>,
    pub(super) label: Option<String>,
}

pub(super) struct CreateManagedAccountInput {
    pub(super) principal_id: String,
    pub(super) chain_namespace: String,
    pub(super) label: Option<String>,
    pub(super) create_new: bool,
}

pub(super) struct SetDefaultAccountInput {
    pub(super) principal_id: String,
    pub(super) chain_namespace: String,
    pub(super) intent: String,
    pub(super) account_id: String,
}

pub(super) struct ImportManagedRecoveryKeyInput {
    pub(super) principal_id: String,
    pub(super) recovery_key: Value,
    pub(super) label: Option<String>,
}

pub(super) struct ChallengeInput {
    pub(super) domain: String,
    pub(super) uri: String,
    pub(super) address: String,
    pub(super) chain_id: u64,
    pub(super) resources: Vec<String>,
}

pub(super) struct BitcoinChallengeInput {
    pub(super) domain: String,
    pub(super) uri: String,
    pub(super) address: String,
    pub(super) network: String,
    pub(super) resources: Vec<String>,
}

pub(super) struct SignatureRequestInput {
    pub(super) request_id: String,
    pub(super) wallet_request_sha256: String,
    pub(super) authority_binding: String,
    pub(super) principal_id: String,
    pub(super) session_id: String,
    pub(super) launch_id: String,
    pub(super) proof_binding_id: Option<String>,
    pub(super) account_id: String,
    pub(super) chain_namespace: String,
    pub(super) intent: String,
    pub(super) requested_by_actor: String,
    pub(super) resource: String,
    pub(super) reason: String,
    pub(super) payload: Value,
    pub(super) expires_at: u64,
}

impl ChallengeInput {
    pub(super) fn validate(&self) -> Result<(), String> {
        validate_siwe_origin_binding(&self.domain, &self.uri)?;
        validate_evm_address(&self.address)?;
        if self.chain_id == 0 {
            return Err("chain_id must be non-zero".to_string());
        }
        for resource in &self.resources {
            validate_resource(resource)?;
        }
        Ok(())
    }
}

impl BitcoinChallengeInput {
    pub(super) fn validate(&self) -> Result<(), String> {
        validate_domain(&self.domain)?;
        validate_uri(&self.uri)?;
        validate_bitcoin_network(&self.network)?;
        validate_bitcoin_address(&self.address, &self.network)?;
        for resource in &self.resources {
            validate_resource(resource)?;
        }
        Ok(())
    }
}

impl SignatureRequestInput {
    pub(super) fn validate(&self, now: u64) -> Result<(), String> {
        validate_opaque_id(&self.request_id, "request_id")?;
        validate_opaque_id(&self.wallet_request_sha256, "wallet_request_sha256")?;
        validate_hash(&self.authority_binding, "authority_binding")?;
        validate_opaque_id(&self.principal_id, "principal_id")?;
        validate_opaque_id(&self.session_id, "session_id")?;
        validate_opaque_id(&self.launch_id, "launch_id")?;
        if let Some(proof_binding_id) = &self.proof_binding_id {
            validate_opaque_id(proof_binding_id, "proof_binding_id")?;
        }
        validate_opaque_id(&self.account_id, "account_id")?;
        validate_opaque_id(&self.chain_namespace, "chain_namespace")?;
        validate_signing_intent(&self.intent)?;
        validate_opaque_id(&self.requested_by_actor, "requested_by_actor")?;
        validate_resource(&self.resource)?;
        validate_reason(&self.reason)?;
        let payload =
            serde_json::to_vec(&self.payload).map_err(|err| format!("invalid payload: {err}"))?;
        if payload.is_empty() || payload.len() > MAX_APPROVAL_PAYLOAD_BYTES {
            return Err(format!(
                "payload must be 1-{MAX_APPROVAL_PAYLOAD_BYTES} bytes"
            ));
        }
        if self.expires_at <= now {
            return Err("approval expires_at must be in the future".to_string());
        }
        if self.expires_at > now.saturating_add(MAX_APPROVAL_REQUEST_TTL_SECS) {
            return Err(format!(
                "approval lifetime exceeds {MAX_APPROVAL_REQUEST_TTL_SECS} seconds"
            ));
        }
        Ok(())
    }
}

impl LinkAccountInput {
    pub(super) fn validate(&self) -> Result<(), String> {
        validate_opaque_id(&self.principal_id, "principal_id")?;
        validate_opaque_id(&self.proof_binding_id, "proof_binding_id")?;
        validate_opaque_id(&self.chain_namespace, "chain_namespace")?;
        validate_opaque_id(&self.address, "address")?;
        validate_opaque_id(&self.proof_type, "proof_type")?;
        if is_managed_proof_type(&self.proof_type) {
            return Err(
                "managed accounts must be created through create_managed_account".to_string(),
            );
        }
        let Some(connector_id) = self.connector_id.as_deref() else {
            return Err("external wallet links require a connector_id".to_string());
        };
        validate_opaque_id(connector_id, "connector_id")?;
        if let Some(label) = &self.label {
            validate_label(label)?;
        }
        Ok(())
    }
}

impl CreateManagedAccountInput {
    pub(super) fn validate(&self) -> Result<(), String> {
        validate_opaque_id(&self.principal_id, "principal_id")?;
        validate_managed_chain_namespace(&self.chain_namespace)?;
        if let Some(label) = &self.label {
            validate_label(label)?;
        }
        Ok(())
    }
}

impl SetDefaultAccountInput {
    pub(super) fn validate(&self) -> Result<(), String> {
        validate_opaque_id(&self.principal_id, "principal_id")?;
        validate_opaque_id(&self.chain_namespace, "chain_namespace")?;
        validate_signing_intent(&self.intent)?;
        validate_opaque_id(&self.account_id, "account_id")?;
        Ok(())
    }
}

impl ImportManagedRecoveryKeyInput {
    pub(super) fn validate(&self) -> Result<(), String> {
        validate_opaque_id(&self.principal_id, "principal_id")?;
        if let Some(label) = &self.label {
            validate_label(label)?;
        }
        Ok(())
    }
}

pub(super) fn validate_default_account_lookup(
    principal_id: &str,
    chain_namespace: &str,
    intent: &str,
) -> Result<(), String> {
    validate_opaque_id(principal_id, "principal_id")?;
    validate_opaque_id(chain_namespace, "chain_namespace")?;
    validate_signing_intent(intent)?;
    Ok(())
}

pub(super) fn validate_opaque_id(value: &str, label: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 256 {
        return Err(format!("{label} must be 1-256 characters"));
    }
    if value == "." || value == ".." {
        return Err(format!("{label} must be opaque"));
    }
    if value.chars().any(|ch| {
        ch.is_control() || ch == '/' || ch == '\\' || ch == '"' || ch == '\'' || ch.is_whitespace()
    }) {
        return Err(format!("{label} contains unsupported characters"));
    }
    Ok(())
}

pub(super) fn eip155_chain_id(value: &str) -> Result<u64, String> {
    validate_opaque_id(value, "chain_namespace")?;
    let chain_id = value
        .strip_prefix("eip155:")
        .ok_or_else(|| "managed EVM wallets require an eip155 chain namespace".to_string())?;
    let chain_id = chain_id
        .parse::<u64>()
        .map_err(|_| "managed wallet chain ID must be numeric".to_string())?;
    if chain_id == 0 {
        return Err("managed wallet chain ID must be non-zero".to_string());
    }
    Ok(chain_id)
}

pub(super) fn validate_evm_chain_namespace(value: &str) -> Result<(), String> {
    eip155_chain_id(value).map(|_| ())
}

pub(super) fn validate_managed_chain_namespace(value: &str) -> Result<(), String> {
    managed_proof_type(value).map(|_| ())
}

pub(super) fn is_managed_proof_type(value: &str) -> bool {
    matches!(
        value,
        MANAGED_EVM_PROOF_TYPE | MANAGED_BTC_P2WPKH_PROOF_TYPE
    )
}

pub(super) fn managed_proof_type(chain_namespace: &str) -> Result<&'static str, String> {
    validate_opaque_id(chain_namespace, "chain_namespace")?;
    if chain_namespace.starts_with("eip155:") {
        validate_evm_chain_namespace(chain_namespace)?;
        return Ok(MANAGED_EVM_PROOF_TYPE);
    }
    if chain_namespace == BITCOIN_MAINNET_CHAIN_NAMESPACE {
        return Ok(MANAGED_BTC_P2WPKH_PROOF_TYPE);
    }
    Err("managed wallets support EVM chains and Bitcoin mainnet P2WPKH".to_string())
}

pub(super) fn managed_key_scope(chain_namespace: &str) -> Result<&'static str, String> {
    match managed_proof_type(chain_namespace)? {
        MANAGED_EVM_PROOF_TYPE => Ok("eip155"),
        MANAGED_BTC_P2WPKH_PROOF_TYPE => Ok("bitcoin:p2wpkh"),
        _ => Err("unsupported managed wallet proof type".to_string()),
    }
}

pub(super) fn chain_namespaces_compatible(
    account_chain_namespace: &str,
    requested_chain_namespace: &str,
) -> bool {
    account_chain_namespace == requested_chain_namespace
        || (account_chain_namespace.starts_with("eip155:")
            && requested_chain_namespace.starts_with("eip155:"))
}

pub(super) fn validate_label(value: &str) -> Result<(), String> {
    if value.len() > 80 || value.chars().any(char::is_control) {
        return Err(
            "label must be 80 characters or fewer and contain no control characters".into(),
        );
    }
    Ok(())
}

pub(super) fn validate_reason(value: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 160 || value.chars().any(char::is_control) {
        return Err("reason must be 1-160 characters and contain no control characters".into());
    }
    Ok(())
}

pub(super) fn validate_signing_intent(value: &str) -> Result<(), String> {
    match value {
        "auth_challenge"
        | "capability_grant"
        | "credential"
        | "publish_envelope"
        | "transaction_intent"
        | "browser_connect"
        | "browser_account_access"
        | "browser_personal_sign"
        | "browser_typed_data_sign"
        | "bitcoin_bip322_proof"
        | PROTECTED_CONTENT_RIGHTS_SIGNATURE_INTENT
        | "revocation" => Ok(()),
        _ => Err("unsupported signing intent".to_string()),
    }
}

pub(super) fn managed_signing_intent_is_supported(value: &str) -> bool {
    matches!(
        value,
        "transaction_intent"
            | "browser_account_access"
            | "browser_personal_sign"
            | "browser_typed_data_sign"
            | "bitcoin_bip322_proof"
            | PROTECTED_CONTENT_RIGHTS_SIGNATURE_INTENT
    )
}

pub(super) fn validate_domain(value: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 253
        || value.contains('/')
        || value.contains('@')
        || value
            .chars()
            .any(|ch| ch.is_ascii_control() || ch.is_ascii_whitespace())
    {
        return Err("invalid SIWE domain".to_string());
    }
    Ok(())
}

pub(super) fn validate_uri(value: &str) -> Result<(), String> {
    let value = value.trim();
    if value.len() > 512
        || !(value.starts_with("https://") || value.starts_with("http://"))
        || value
            .chars()
            .any(|ch| ch.is_ascii_control() || ch.is_ascii_whitespace())
    {
        return Err("invalid SIWE URI".to_string());
    }
    Ok(())
}

pub(super) fn validate_resource(value: &str) -> Result<(), String> {
    let value = value.trim();
    if value.len() > 512
        || !value.starts_with("elastos://")
        || value
            .chars()
            .any(|ch| ch.is_ascii_control() || ch.is_ascii_whitespace())
    {
        return Err("invalid wallet proof resource".to_string());
    }
    Ok(())
}

pub(super) fn validate_hash(value: &str, label: &str) -> Result<(), String> {
    let raw = value
        .strip_prefix("0x")
        .ok_or_else(|| format!("{label} must start with 0x"))?;
    if raw.len() != 64 || !raw.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!("{label} must be a 32-byte hex digest"));
    }
    Ok(())
}

pub(super) fn validate_signature(value: &str) -> Result<(), String> {
    let value = value.trim();
    if value.len() < 8 || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err("signature must be 8-4096 characters and contain no control characters".into());
    }
    Ok(())
}

pub(super) fn value_hash(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    bytes_hash(&bytes)
}

pub(super) fn wallet_authority_binding(authority: &WalletAuthorityV2) -> String {
    value_hash(&json!({
        "principal_id": authority.principal_id,
        "session_id": authority.session_id,
        "proof_binding_id": authority.proof_binding_id,
        "grant_id": authority.grant_id,
        "actor": authority.actor,
        "launch_id": authority.launch_id,
    }))
}

pub(super) fn bytes_hash(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(sha2::Sha256::digest(bytes)))
}

pub(super) fn managed_key_aad(
    account_id: &str,
    principal_id: &str,
    chain_namespace: &str,
    address: &str,
) -> String {
    format!(
        "elastos.wallet.managed_secret/v1\n{account_id}\n{principal_id}\n{chain_namespace}\n{}",
        normalize_evm_address(address)
    )
}

pub(super) fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(super) fn random_hex(bytes_len: usize) -> String {
    let mut bytes = vec![0u8; bytes_len];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// One test per refusal these request validators raise, each asserting the
/// whole `Err` value. They pin answers the validators already give: they add no
/// rule and register no falsifier. They prove what the wallet provider answers
/// an account, approval, challenge or signing call, not confinement: the
/// Runtime decides whether the provider runs.
///
/// Two strings of this file are asserted by `src/tests/accounts.rs`
/// (`managed EVM wallets require an eip155 chain namespace` at `:929` and
/// `managed wallets support EVM chains and Bitcoin mainnet P2WPKH` at `:935`,
/// by `managed_namespace_errors_are_current`), so they are not repeated here.
///
/// Two strings are recorded as unreachable instead of tested. `invalid
/// payload: {err}` (`:114`) follows `serde_json::to_vec` on a `Value`, which
/// always serialises: it fails only for a non-string map key, which `Value`
/// cannot hold. `unsupported managed wallet proof type` (`:258`) is the `_` arm
/// of `managed_key_scope`'s `match`, and `managed_proof_type` answers only
/// `MANAGED_EVM_PROOF_TYPE` or `MANAGED_BTC_P2WPKH_PROOF_TYPE`, which the two
/// earlier arms take.
///
/// A `{label}` string is one string raised from many call sites, so it gets one
/// test that drives the sites its doc comment names.
#[cfg(test)]
mod uf_validation_refusal_tests {
    use super::*;
    use serde_json::json;

    const ADDRESS: &str = "0x1111111111111111111111111111111111111111";
    const DOMAIN: &str = "http://elastos.local";
    const URI: &str = "http://elastos.local/apps/home/";

    /// A challenge the validator accepts, so one case changes one field and
    /// meets the check it names.
    fn challenge_input() -> ChallengeInput {
        ChallengeInput {
            domain: DOMAIN.to_string(),
            uri: URI.to_string(),
            address: ADDRESS.to_string(),
            chain_id: 20,
            resources: Vec::new(),
        }
    }

    /// A signing request the validator accepts at `now`, so one case changes
    /// one field and meets the check it names.
    fn signature_request_input(now: u64) -> SignatureRequestInput {
        SignatureRequestInput {
            request_id: "request-1".to_string(),
            wallet_request_sha256: "request-sha-1".to_string(),
            authority_binding: format!("0x{}", "11".repeat(32)),
            principal_id: "person:local:test".to_string(),
            session_id: "session-1".to_string(),
            launch_id: "launch-1".to_string(),
            proof_binding_id: None,
            account_id: format!("wallet:eip155:20:{ADDRESS}"),
            chain_namespace: "eip155:20".to_string(),
            intent: "browser_personal_sign".to_string(),
            requested_by_actor: "browser".to_string(),
            resource: "elastos://wallet/eip155:20/sign/browser_personal_sign".to_string(),
            reason: "unit test request".to_string(),
            payload: json!({ "message": "ElastOS unit test" }),
            expires_at: now + 60,
        }
    }

    /// A link request the validator accepts, so one case changes one field and
    /// meets the check it names.
    fn link_account_input() -> LinkAccountInput {
        LinkAccountInput {
            principal_id: "person:local:test".to_string(),
            proof_binding_id: format!("proof:eip155:20:{ADDRESS}"),
            chain_namespace: "eip155:20".to_string(),
            address: ADDRESS.to_string(),
            proof_type: "external_evm".to_string(),
            connector_id: Some("walletconnect".to_string()),
            label: None,
        }
    }

    /// Catches removal of the `chain_id == 0` refusal in
    /// `ChallengeInput::validate`: without it a challenge is issued for chain
    /// zero, which no account is on. The domain, URI and address are the
    /// accepted ones, so only that guard can answer.
    #[test]
    fn challenge_with_zero_chain_id_is_refused() {
        let input = ChallengeInput {
            chain_id: 0,
            ..challenge_input()
        };
        assert_eq!(input.validate().unwrap_err(), "chain_id must be non-zero");
    }

    /// Catches removal of the upper payload bound in
    /// `SignatureRequestInput::validate`: without it a signing request carries
    /// a payload of any size into the approval record and the prompt.
    ///
    /// The lower bound has no reachable case: a serialised `Value` is never
    /// empty, so the size string is raised only from this side.
    #[test]
    fn oversized_approval_payload_is_refused() {
        let now = 1_000;
        let input = SignatureRequestInput {
            payload: json!("a".repeat(MAX_APPROVAL_PAYLOAD_BYTES + 1)),
            ..signature_request_input(now)
        };
        assert_eq!(
            input.validate(now).unwrap_err(),
            "payload must be 1-32768 bytes"
        );
    }

    /// Catches removal of the expiry refusal in
    /// `SignatureRequestInput::validate`: without it an approval that has
    /// already expired is recorded as pending, so the prompt offers an effect
    /// the Runtime will refuse when it settles.
    #[test]
    fn approval_expiring_now_is_refused() {
        let now = 1_000;
        let input = SignatureRequestInput {
            expires_at: now,
            ..signature_request_input(now)
        };
        assert_eq!(
            input.validate(now).unwrap_err(),
            "approval expires_at must be in the future"
        );
    }

    /// Catches removal of the lifetime cap in
    /// `SignatureRequestInput::validate`: without it one approval stays
    /// requestable for longer than the provider's accepted window.
    #[test]
    fn approval_lifetime_over_the_cap_is_refused() {
        let now = 1_000;
        let input = SignatureRequestInput {
            expires_at: now + MAX_APPROVAL_REQUEST_TTL_SECS + 1,
            ..signature_request_input(now)
        };
        assert_eq!(
            input.validate(now).unwrap_err(),
            "approval lifetime exceeds 1800 seconds"
        );
    }

    /// Catches removal of the managed-type refusal in
    /// `LinkAccountInput::validate`: without it a caller links a managed proof
    /// type through the external path, so the key is never created by
    /// `create_managed_account` and no recovery key is stored with it.
    #[test]
    fn link_with_a_managed_proof_type_is_refused() {
        let input = LinkAccountInput {
            proof_type: MANAGED_EVM_PROOF_TYPE.to_string(),
            ..link_account_input()
        };
        assert_eq!(
            input.validate().unwrap_err(),
            "managed accounts must be created through create_managed_account"
        );
    }

    /// Catches removal of the connector refusal in
    /// `LinkAccountInput::validate`: without it an external link arrives with
    /// no connector, so the record names no wallet the user approved.
    #[test]
    fn link_without_a_connector_id_is_refused() {
        let input = LinkAccountInput {
            connector_id: None,
            ..link_account_input()
        };
        assert_eq!(
            input.validate().unwrap_err(),
            "external wallet links require a connector_id"
        );
    }

    /// One string, raised by `validate_opaque_id` for a value whose length the
    /// guard refuses. This test drives both conditions and two labels: an empty
    /// `request_id`, the first check of `SignatureRequestInput::validate`, and
    /// a 257-character `chain_namespace` through
    /// `validate_managed_chain_namespace`, which
    /// `CreateManagedAccountInput::validate` calls.
    ///
    /// Catches removal of the length refusal in `validate_opaque_id`: without
    /// it an empty or oversized id is stored and compared as if it were one the
    /// provider had issued.
    #[test]
    fn opaque_id_outside_the_length_range_is_refused() {
        let now = 1_000;
        let request = SignatureRequestInput {
            request_id: String::new(),
            ..signature_request_input(now)
        };
        assert_eq!(
            request.validate(now).unwrap_err(),
            "request_id must be 1-256 characters"
        );
        assert_eq!(
            validate_managed_chain_namespace(&"x".repeat(257)).unwrap_err(),
            "chain_namespace must be 1-256 characters"
        );
    }

    /// One string, raised by `validate_opaque_id` for a value of `.` or `..`
    /// that passes the length check. This test drives both conditions and two
    /// sites: `account_id` through `SetDefaultAccountInput::validate`, and
    /// `proof_binding_id` through the helper directly.
    ///
    /// Catches removal of the opaque refusal in `validate_opaque_id`: without
    /// it a dot value reaches a path join as a directory step instead of an
    /// id.
    #[test]
    fn dot_shaped_opaque_id_is_refused() {
        let default_account = SetDefaultAccountInput {
            principal_id: "person:local:test".to_string(),
            chain_namespace: "eip155:20".to_string(),
            intent: "browser_personal_sign".to_string(),
            account_id: "..".to_string(),
        };
        assert_eq!(
            default_account.validate().unwrap_err(),
            "account_id must be opaque"
        );
        assert_eq!(
            validate_opaque_id(".", "proof_binding_id").unwrap_err(),
            "proof_binding_id must be opaque"
        );
    }

    /// One string, raised by `validate_opaque_id` for a value that passes the
    /// length and dot checks and holds a character an id cannot carry. This
    /// test drives two sites: `session_id` through
    /// `SignatureRequestInput::validate`, and `connector_id` through the helper
    /// directly, with a separator and with an inner space.
    ///
    /// Catches removal of the character refusal in `validate_opaque_id`:
    /// without it an id carries a path separator or a space into a stored
    /// record and into a path join.
    #[test]
    fn opaque_id_with_unsupported_characters_is_refused() {
        let now = 1_000;
        let request = SignatureRequestInput {
            session_id: "session/1".to_string(),
            ..signature_request_input(now)
        };
        assert_eq!(
            request.validate(now).unwrap_err(),
            "session_id contains unsupported characters"
        );
        assert_eq!(
            validate_opaque_id("wallet connect", "connector_id").unwrap_err(),
            "connector_id contains unsupported characters"
        );
    }

    /// Catches removal of the numeric refusal in `eip155_chain_id`: without it
    /// a non-numeric chain id is read as some other chain, and an approval is
    /// bound to the wrong network.
    #[test]
    fn non_numeric_managed_chain_id_is_refused() {
        assert_eq!(
            eip155_chain_id("eip155:twenty").unwrap_err(),
            "managed wallet chain ID must be numeric"
        );
    }

    /// Catches removal of the zero refusal in `eip155_chain_id`: without it a
    /// managed wallet is created on chain zero, which no network answers.
    #[test]
    fn zero_managed_chain_id_is_refused() {
        assert_eq!(
            eip155_chain_id("eip155:0").unwrap_err(),
            "managed wallet chain ID must be non-zero"
        );
    }

    /// Catches removal of either label refusal in `validate_label`: without the
    /// length side a long label fills the account record, and without the
    /// control side a label carries a newline into the Home display.
    ///
    /// Its call sites are the three input structs above that carry a label
    /// (`LinkAccountInput`, `CreateManagedAccountInput`,
    /// `ImportManagedRecoveryKeyInput`), and the recovery-set read and the
    /// rename check in `src/account.rs`.
    #[test]
    fn label_over_the_limit_or_with_control_characters_is_refused() {
        let reason = "label must be 80 characters or fewer and contain no control characters";
        assert_eq!(validate_label(&"a".repeat(81)).unwrap_err(), reason);
        assert_eq!(validate_label("unit\ntest").unwrap_err(), reason);
    }

    /// Catches removal of any of the three reason refusals in
    /// `validate_reason`: an empty reason leaves the prompt with nothing to
    /// show why the effect was asked for, a long one fills the record, and a
    /// control character breaks the line the Home shows.
    ///
    /// Its call sites are `SignatureRequestInput::validate` and three approval
    /// checks in `src/approval.rs`.
    #[test]
    fn empty_long_or_control_reason_is_refused() {
        let reason = "reason must be 1-160 characters and contain no control characters";
        assert_eq!(validate_reason("").unwrap_err(), reason);
        assert_eq!(validate_reason(&"a".repeat(161)).unwrap_err(), reason);
        assert_eq!(validate_reason("unit\u{1}test").unwrap_err(), reason);
    }

    /// Catches removal of the intent refusal in `validate_signing_intent`:
    /// without it an approval records an intent no signer path answers, and the
    /// prompt offers an effect the provider cannot complete.
    ///
    /// Its call sites are all in this file: `SignatureRequestInput::validate`,
    /// `SetDefaultAccountInput::validate` and
    /// `validate_default_account_lookup`.
    #[test]
    fn unsupported_signing_intent_is_refused() {
        assert_eq!(
            validate_signing_intent("wallet_connect").unwrap_err(),
            "unsupported signing intent"
        );
    }

    /// Catches removal of the domain refusal in `validate_domain`: without it a
    /// challenge names an empty or path-bearing SIWE domain, so the message a
    /// wallet signs does not name the origin it was issued for.
    ///
    /// Its only call site is `BitcoinChallengeInput::validate`;
    /// `ChallengeInput::validate` reaches `elastos_auth`'s own origin check
    /// instead, which this file's tests do not own.
    #[test]
    fn invalid_siwe_domain_is_refused() {
        assert_eq!(validate_domain("").unwrap_err(), "invalid SIWE domain");
        assert_eq!(
            validate_domain("elastos.local/apps/home").unwrap_err(),
            "invalid SIWE domain"
        );
    }

    /// Catches removal of the URI refusal in `validate_uri`: without it a
    /// challenge names no web URI, so the wallet signs a message whose origin
    /// it cannot check.
    ///
    /// Its call site is `BitcoinChallengeInput::validate`.
    #[test]
    fn invalid_siwe_uri_is_refused() {
        assert_eq!(validate_uri("").unwrap_err(), "invalid SIWE URI");
        assert_eq!(
            validate_uri("ftp://elastos.local/apps/home/").unwrap_err(),
            "invalid SIWE URI"
        );
    }

    /// Catches removal of the resource refusal in `validate_resource`: without
    /// it an approval names a resource outside the `elastos://` namespace, so
    /// the granted effect is not the one the provider records.
    ///
    /// Its call sites are `ChallengeInput::validate`,
    /// `BitcoinChallengeInput::validate` and `SignatureRequestInput::validate`.
    #[test]
    fn invalid_wallet_proof_resource_is_refused() {
        assert_eq!(
            validate_resource("").unwrap_err(),
            "invalid wallet proof resource"
        );
        assert_eq!(
            validate_resource("https://elastos.local/apps/home").unwrap_err(),
            "invalid wallet proof resource"
        );
    }

    /// One string, raised by `validate_hash` for a value with no `0x` prefix.
    /// This test drives two of its labels: `authority_binding`, the site in
    /// `SignatureRequestInput::validate`, and `payload_hash`, one of the two
    /// sites in `src/approval.rs`.
    ///
    /// Catches removal of the prefix refusal in `validate_hash`: without it a
    /// decimal or bare hex binding is read as a digest, so two different
    /// bindings compare equal.
    #[test]
    fn hash_without_the_prefix_is_refused() {
        assert_eq!(
            validate_hash("1234", "authority_binding").unwrap_err(),
            "authority_binding must start with 0x"
        );
        assert_eq!(
            validate_hash("abcd", "payload_hash").unwrap_err(),
            "payload_hash must start with 0x"
        );
    }

    /// One string, raised by `validate_hash` when the prefixed body is not one
    /// 32-byte digest. This test drives both conditions and two labels: a short
    /// body as `authority_binding` and a long non-hex body as `payload_hash`.
    ///
    /// Catches removal of the digest refusal in `validate_hash`: without it a
    /// truncated or partly non-hex digest is stored as the binding an approval
    /// settles against.
    #[test]
    fn hash_that_is_not_a_digest_is_refused() {
        assert_eq!(
            validate_hash("0x1234", "authority_binding").unwrap_err(),
            "authority_binding must be a 32-byte hex digest"
        );
        assert_eq!(
            validate_hash(&format!("0x{}", "z".repeat(64)), "payload_hash").unwrap_err(),
            "payload_hash must be a 32-byte hex digest"
        );
    }

    /// Catches removal of any of the three signature refusals in
    /// `validate_signature`: a short value is not a signature, a long one fills
    /// the approval record, and a control character breaks the record the
    /// settlement reads.
    ///
    /// Its three call sites are all in `src/approval.rs`.
    #[test]
    fn signature_outside_the_length_range_or_with_control_is_refused() {
        let reason = "signature must be 8-4096 characters and contain no control characters";
        assert_eq!(validate_signature("abc").unwrap_err(), reason);
        assert_eq!(validate_signature(&"a".repeat(4_097)).unwrap_err(), reason);
        assert_eq!(validate_signature("abcd\u{1}efgh").unwrap_err(), reason);
    }
}
