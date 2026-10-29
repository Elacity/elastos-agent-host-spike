use super::*;
use k256::ecdsa::SigningKey;
use rand::rngs::OsRng;
use serde_json::{json, Value};

impl WalletProvider {
    pub(super) fn accounts(&self, principal_id: &str, include_revoked: bool) -> Response {
        if let Err(response) = self.ensure_initialized() {
            return response;
        }
        if let Err(err) = validate_opaque_id(principal_id, "principal_id") {
            return Response::error("invalid_request", err);
        }
        let accounts = self
            .store
            .accounts
            .iter()
            .filter(|account| account.principal_id == principal_id)
            .filter(|account| include_revoked || account.revoked_at.is_none())
            .map(|account| self.account_summary(account))
            .collect::<Vec<_>>();
        let default_accounts = self
            .store
            .default_accounts
            .iter()
            .filter(|default| default.principal_id == principal_id)
            .filter(|default| {
                self.active_account(&default.principal_id, &default.account_id)
                    .map(|account| account.chain_namespace == default.chain_namespace)
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        Response::ok(json!({
            "accounts": accounts,
            "default_accounts": default_accounts,
        }))
    }

    fn account_summary(&self, account: &LinkedAccount) -> Value {
        let (signing_available, signing_status) = self.account_signing_status(account);
        json!({
            "account_id": account.account_id,
            "principal_id": account.principal_id,
            "proof_binding_id": account.proof_binding_id,
            "chain_namespace": account.chain_namespace,
            "address": account.address,
            "proof_type": account.proof_type,
            "connector_id": account.connector_id,
            "label": account.label,
            "linked_at": account.linked_at,
            "revoked_at": account.revoked_at,
            "signing_available": signing_available,
            "signing_status": signing_status,
        })
    }

    fn account_signing_status(&self, account: &LinkedAccount) -> (bool, &'static str) {
        if !is_managed_proof_type(&account.proof_type) {
            return if account.connector_id.is_some() {
                (true, "external_connector_available")
            } else {
                (false, "external_connector_required")
            };
        }
        match self.managed_signing_key_for_account(account) {
            Ok(_) => (true, "managed_key_available"),
            Err(err) if err == "managed wallet key not found" => (false, "managed_key_missing"),
            Err(_) => (false, "managed_key_unavailable"),
        }
    }

    pub(super) fn create_managed_account(&mut self, input: CreateManagedAccountInput) -> Response {
        if let Err(response) = self.ensure_initialized() {
            return response;
        }
        if let Err(err) = input.validate() {
            return Response::error("invalid_request", err);
        }
        if self.storage_key.is_none() {
            return Response::error(
                "not_initialized",
                "wallet-provider managed wallet storage is not initialized",
            );
        }
        let proof_type = match managed_proof_type(&input.chain_namespace) {
            Ok(proof_type) => proof_type,
            Err(err) => return Response::error("invalid_request", err),
        };
        let key_scope = match managed_key_scope(&input.chain_namespace) {
            Ok(scope) => scope,
            Err(err) => return Response::error("invalid_request", err),
        };
        let reusable_signing_key = if input.create_new {
            None
        } else {
            let mut exact_account = None;
            let mut distinct_keys = Vec::<SigningKey>::new();
            for account in self.store.accounts.iter().filter(|account| {
                account.principal_id == input.principal_id
                    && account.revoked_at.is_none()
                    && managed_key_scope(&account.chain_namespace)
                        .map(|scope| scope == key_scope)
                        .unwrap_or(false)
            }) {
                let Ok(signing_key) = self.managed_signing_key_for_account(account) else {
                    continue;
                };
                if account.chain_namespace == input.chain_namespace
                    && account.proof_type == proof_type
                    && exact_account.is_none()
                {
                    exact_account = Some(account.clone());
                }
                let key_bytes = signing_key.to_bytes();
                if distinct_keys
                    .iter()
                    .all(|existing| existing.to_bytes() != key_bytes)
                {
                    distinct_keys.push(signing_key);
                }
            }
            if distinct_keys.len() > 1 {
                return Response::error(
                    "managed_key_ambiguous",
                    "multiple distinct active managed wallet keys are eligible for reuse; create_new is required",
                );
            }
            if let Some(existing) = exact_account {
                return Response::ok(json!({ "account": existing, "created": false }));
            }
            distinct_keys.pop()
        };

        let previous = self.store.clone();
        let now = now_ts();
        let mut signing_key =
            reusable_signing_key.unwrap_or_else(|| SigningKey::random(&mut OsRng));
        let (address, new_account_id) = loop {
            let address =
                match managed_address_for_signing_key(&signing_key, &input.chain_namespace) {
                    Ok(address) => address,
                    Err(err) => return Response::error("invalid_request", err),
                };
            let new_account_id = account_id(&input.chain_namespace, &address);
            let authority_exists =
                self.store.accounts.iter().any(|account| {
                    account.revoked_at.is_none() && account.account_id == new_account_id
                }) || self.store.managed_wallets.iter().any(|secret| {
                    secret.revoked_at.is_none() && secret.account_id == new_account_id
                });
            if !authority_exists {
                break (address, new_account_id);
            }
            signing_key = SigningKey::random(&mut OsRng);
        };
        let private_key_bytes = signing_key.to_bytes();
        let secret = match self.encrypt_managed_key(
            &new_account_id,
            &input.principal_id,
            &input.chain_namespace,
            &address,
            private_key_bytes.as_ref(),
            now,
        ) {
            Ok(secret) => secret,
            Err(err) => return Response::error("storage_error", err),
        };
        let account = LinkedAccount {
            account_id: new_account_id,
            principal_id: input.principal_id,
            proof_binding_id: format!("proof:wallet:managed:{}:{}", input.chain_namespace, address),
            chain_namespace: input.chain_namespace,
            address,
            proof_type: proof_type.to_string(),
            connector_id: None,
            label: input.label.filter(|label| !label.trim().is_empty()),
            linked_at: now,
            revoked_at: None,
        };
        self.store.managed_wallets.push(secret);
        self.store.accounts.push(account.clone());
        if let Err(err) = self.save() {
            self.recover_store_after_save_failure(previous);
            return Response::error("storage_error", err);
        }
        Response::ok(json!({ "account": account, "created": true }))
    }

    pub(super) fn import_managed_recovery_key(
        &mut self,
        input: ImportManagedRecoveryKeyInput,
    ) -> Response {
        if let Err(response) = self.ensure_initialized() {
            return response;
        }
        if let Err(err) = input.validate() {
            return Response::error("invalid_request", err);
        }
        if self.storage_key.is_none() {
            return Response::error(
                "not_initialized",
                "wallet-provider managed wallet storage is not initialized",
            );
        }

        let recovery_key = input.recovery_key;
        let schema = recovery_key
            .get("schema")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if schema != "elastos.wallet.recovery-key/v1" {
            return Response::error("invalid_request", "expected elastos.wallet.recovery-key/v1");
        }
        let account_id_value = match recovery_key.get("account_id").and_then(Value::as_str) {
            Some(value) => value,
            None => return Response::error("invalid_request", "recovery key missing account_id"),
        };
        let chain_namespace = match recovery_key.get("chain_namespace").and_then(Value::as_str) {
            Some(value) => value,
            None => {
                return Response::error("invalid_request", "recovery key missing chain_namespace")
            }
        };
        let address = match recovery_key.get("address").and_then(Value::as_str) {
            Some(value) => value,
            None => return Response::error("invalid_request", "recovery key missing address"),
        };
        let secret_type = recovery_key
            .get("secret_type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if secret_type != "secp256k1_private_key_hex" {
            return Response::error("invalid_request", "unsupported wallet recovery key type");
        }
        if let Err(err) = validate_managed_chain_namespace(chain_namespace) {
            return Response::error("invalid_request", err);
        }
        if let Err(err) = validate_opaque_id(account_id_value, "account_id") {
            return Response::error("invalid_request", err);
        }
        let normalized_address = if chain_namespace.starts_with("eip155:") {
            normalize_evm_address(address)
        } else {
            address.to_string()
        };
        let expected_account_id = account_id(chain_namespace, &normalized_address);
        if account_id_value != expected_account_id {
            return Response::error(
                "invalid_request",
                "recovery key account_id does not match chain and address",
            );
        }
        let private_key_hex = match recovery_key.get("private_key_hex").and_then(Value::as_str) {
            Some(value) => value.trim(),
            None => {
                return Response::error("invalid_request", "recovery key missing private_key_hex")
            }
        };
        let private_key = match hex::decode(private_key_hex) {
            Ok(value) if value.len() == 32 => value,
            _ => return Response::error("invalid_request", "private_key_hex must be 32 bytes"),
        };
        let signing_key = match SigningKey::from_slice(&private_key) {
            Ok(signing_key) => signing_key,
            Err(_) => return Response::error("invalid_request", "invalid secp256k1 private key"),
        };
        let derived_address = match managed_address_for_signing_key(&signing_key, chain_namespace) {
            Ok(value) => value,
            Err(err) => return Response::error("invalid_request", err),
        };
        if !derived_address.eq_ignore_ascii_case(&normalized_address) {
            return Response::error(
                "invalid_request",
                "private key does not match recovery key address",
            );
        }

        let now = now_ts();
        let proof_type = match managed_proof_type(chain_namespace) {
            Ok(proof_type) => proof_type,
            Err(err) => return Response::error("invalid_request", err),
        };
        let secret = match self.encrypt_managed_key(
            &expected_account_id,
            &input.principal_id,
            chain_namespace,
            &normalized_address,
            signing_key.to_bytes().as_ref(),
            now,
        ) {
            Ok(secret) => secret,
            Err(err) => return Response::error("storage_error", err),
        };
        for secret in self.store.managed_wallets.iter_mut().filter(|secret| {
            secret.principal_id == input.principal_id
                && secret.account_id == expected_account_id
                && secret.revoked_at.is_none()
        }) {
            secret.revoked_at = Some(now);
        }
        self.store.managed_wallets.push(secret);

        let label = input.label.filter(|label| !label.trim().is_empty());
        let linked_at = self
            .store
            .accounts
            .iter()
            .find(|account| {
                account.principal_id == input.principal_id
                    && account.account_id == expected_account_id
            })
            .map(|account| account.linked_at)
            .unwrap_or(now);
        let account = LinkedAccount {
            account_id: expected_account_id.clone(),
            principal_id: input.principal_id,
            proof_binding_id: format!(
                "proof:wallet:managed:{}:{}",
                chain_namespace, normalized_address
            ),
            chain_namespace: chain_namespace.to_string(),
            address: normalized_address,
            proof_type: proof_type.to_string(),
            connector_id: None,
            label,
            linked_at,
            revoked_at: None,
        };
        if let Some(existing) = self.store.accounts.iter_mut().find(|existing| {
            existing.principal_id == account.principal_id
                && existing.account_id == expected_account_id
        }) {
            *existing = account.clone();
        } else {
            self.store.accounts.push(account.clone());
        }
        if let Err(err) = self.save() {
            return Response::error("storage_error", err);
        }
        Response::ok(json!({ "account": account, "imported": true }))
    }

    pub(super) fn import_managed_recovery_set(
        &mut self,
        principal_id: &str,
        recovery_set: &ManagedRecoverySetV1,
    ) -> Response {
        if let Err(response) = self.ensure_initialized() {
            return response;
        }
        if let Err(err) = validate_opaque_id(principal_id, "principal_id") {
            return Response::error("invalid_request", err);
        }
        if let Err(err) = recovery_set.validate() {
            return Response::error("invalid_request", err.to_string());
        }
        if self.storage_key.is_none() {
            return Response::error(
                "not_initialized",
                "wallet-provider managed wallet storage is not initialized",
            );
        }

        for entry in &recovery_set.keys {
            if entry.recovery_key.get("account_id").and_then(Value::as_str)
                != Some(entry.account_id.as_str())
            {
                return Response::error(
                    "invalid_request",
                    "managed recovery set account_id does not match its opaque recovery key",
                );
            }
            if let Some(label) = entry.label.as_deref() {
                if let Err(err) = validate_label(label) {
                    return Response::error("invalid_request", err);
                }
            }
        }

        let mut accounts = Vec::with_capacity(recovery_set.keys.len());
        for entry in &recovery_set.keys {
            match self.import_managed_recovery_key(ImportManagedRecoveryKeyInput {
                principal_id: principal_id.to_string(),
                recovery_key: entry.recovery_key.clone(),
                label: entry.label.clone(),
            }) {
                Response::Ok { data: Some(data) } => accounts.push(data["account"].clone()),
                Response::Ok { data: None } => {
                    return Response::error(
                        "invalid_response",
                        "managed recovery key import returned no account",
                    )
                }
                Response::Error { code, message } => return Response::Error { code, message },
            }
        }
        Response::ok(json!({
            "imported": true,
            "account_count": accounts.len(),
            "accounts": accounts,
        }))
    }

    pub(super) fn link_account(&mut self, input: LinkAccountInput) -> Response {
        if let Err(response) = self.ensure_initialized() {
            return response;
        }
        if let Err(err) = input.validate() {
            return Response::error("invalid_request", err);
        }
        let now = now_ts();
        let account_id = account_id(&input.chain_namespace, &input.address);
        let account = LinkedAccount {
            account_id: account_id.clone(),
            principal_id: input.principal_id,
            proof_binding_id: input.proof_binding_id,
            chain_namespace: input.chain_namespace,
            address: input.address,
            proof_type: input.proof_type,
            connector_id: input.connector_id,
            label: input.label.filter(|label| !label.trim().is_empty()),
            linked_at: now,
            revoked_at: None,
        };

        if let Some(existing) = self.store.accounts.iter_mut().find(|existing| {
            existing.principal_id == account.principal_id && existing.account_id == account_id
        }) {
            *existing = account.clone();
        } else {
            self.store.accounts.push(account.clone());
        }
        if let Err(err) = self.save() {
            return Response::error("storage_error", err);
        }
        Response::ok(json!({ "account": account }))
    }

    pub(super) fn revoke_account(&mut self, principal_id: &str, account_id: &str) -> Response {
        if let Err(response) = self.ensure_initialized() {
            return response;
        }
        if let Err(err) = validate_opaque_id(principal_id, "principal_id") {
            return Response::error("invalid_request", err);
        }
        if let Err(err) = validate_opaque_id(account_id, "account_id") {
            return Response::error("invalid_request", err);
        }
        let now = now_ts();
        let Some(account) = self.store.accounts.iter_mut().find(|account| {
            account.principal_id == principal_id && account.account_id == account_id
        }) else {
            return Response::error("not_found", "linked account not found");
        };
        account.revoked_at = Some(now);
        let account = account.clone();
        for secret in
            self.store.managed_wallets.iter_mut().filter(|secret| {
                secret.account_id == account_id && secret.principal_id == principal_id
            })
        {
            secret.revoked_at = Some(now);
        }
        self.store.default_accounts.retain(|default| {
            !(default.principal_id == principal_id && default.account_id == account_id)
        });
        if let Err(err) = self.save() {
            return Response::error("storage_error", err);
        }
        Response::ok(json!({ "account": account }))
    }

    pub(super) fn rename_account(
        &mut self,
        principal_id: &str,
        account_id: &str,
        label: &str,
    ) -> Response {
        if let Err(response) = self.ensure_initialized() {
            return response;
        }
        if let Err(err) = validate_opaque_id(principal_id, "principal_id") {
            return Response::error("invalid_request", err);
        }
        if let Err(err) = validate_opaque_id(account_id, "account_id") {
            return Response::error("invalid_request", err);
        }
        let label = label.trim();
        if label.is_empty() {
            return Response::error("invalid_request", "label is required");
        }
        if let Err(err) = validate_label(label) {
            return Response::error("invalid_request", err);
        }
        let Some(account) = self.store.accounts.iter_mut().find(|account| {
            account.principal_id == principal_id
                && account.account_id == account_id
                && account.revoked_at.is_none()
        }) else {
            return Response::error("not_found", "active linked account not found");
        };
        account.label = Some(label.to_string());
        let account = account.clone();
        if let Err(err) = self.save() {
            return Response::error("storage_error", err);
        }
        Response::ok(json!({ "account": account }))
    }

    pub(super) fn export_managed_recovery_key(
        &self,
        principal_id: &str,
        account_id: &str,
    ) -> Response {
        if let Err(response) = self.ensure_initialized() {
            return response;
        }
        if let Err(err) = validate_opaque_id(principal_id, "principal_id") {
            return Response::error("invalid_request", err);
        }
        if let Err(err) = validate_opaque_id(account_id, "account_id") {
            return Response::error("invalid_request", err);
        }
        let Some(account) = self.store.accounts.iter().find(|account| {
            account.principal_id == principal_id
                && account.account_id == account_id
                && account.revoked_at.is_none()
        }) else {
            return Response::error("not_found", "active linked account not found");
        };
        if !is_managed_proof_type(&account.proof_type) {
            return Response::error(
                "external_wallet_required",
                "recovery key is available only for passkey-managed accounts",
            );
        }
        let signing_key = match self.managed_signing_key_for_account(account) {
            Ok(signing_key) => signing_key,
            Err(err) => return Response::error("storage_error", err),
        };
        Response::ok(json!({
            "schema": "elastos.wallet.recovery-key/v1",
            "account_id": account.account_id,
            "chain_namespace": account.chain_namespace,
            "address": account.address,
            "secret_type": "secp256k1_private_key_hex",
            "private_key_hex": hex::encode(signing_key.to_bytes()),
            "note": "This account was created as an encrypted signing key, not a BIP39 seed phrase."
        }))
    }

    pub(super) fn export_managed_recovery_set(&self, principal_id: &str) -> Response {
        if let Err(response) = self.ensure_initialized() {
            return response;
        }
        if let Err(err) = validate_opaque_id(principal_id, "principal_id") {
            return Response::error("invalid_request", err);
        }
        let managed_accounts = self
            .store
            .accounts
            .iter()
            .filter(|account| {
                account.principal_id == principal_id
                    && account.revoked_at.is_none()
                    && account.connector_id.is_none()
                    && is_managed_proof_type(&account.proof_type)
            })
            .map(|account| (account.account_id.clone(), account.label.clone()))
            .collect::<Vec<_>>();
        let mut keys = Vec::with_capacity(managed_accounts.len());
        for (account_id, label) in managed_accounts {
            let recovery_key = match self.export_managed_recovery_key(principal_id, &account_id) {
                Response::Ok { data: Some(data) } => data,
                Response::Ok { data: None } => {
                    return Response::error(
                        "invalid_response",
                        "managed recovery key export returned no key",
                    )
                }
                Response::Error { code, message } => return Response::Error { code, message },
            };
            keys.push(ManagedRecoveryKeyEntryV1 {
                account_id,
                recovery_key,
                label,
            });
        }
        let recovery_set = match ManagedRecoverySetV1::new(keys) {
            Ok(recovery_set) => recovery_set,
            Err(err) => return Response::error("invalid_recovery_set", err.to_string()),
        };
        match serde_json::to_value(recovery_set) {
            Ok(recovery_set) => Response::ok(recovery_set),
            Err(err) => Response::error("invalid_recovery_set", err.to_string()),
        }
    }

    pub(super) fn set_default_account(&mut self, input: SetDefaultAccountInput) -> Response {
        if let Err(response) = self.ensure_initialized() {
            return response;
        }
        if let Err(err) = input.validate() {
            return Response::error("invalid_request", err);
        }
        let Some(account) = self
            .active_account(&input.principal_id, &input.account_id)
            .cloned()
        else {
            return Response::error("not_found", "active linked account not found");
        };
        if account.chain_namespace != input.chain_namespace {
            return Response::error(
                "invalid_request",
                "default wallet chain must match the linked account",
            );
        }
        let now = now_ts();
        let default_account = DefaultWalletAccount {
            schema: "elastos.wallet.default_account/v1".to_string(),
            principal_id: input.principal_id,
            chain_namespace: input.chain_namespace,
            intent: input.intent,
            account_id: input.account_id,
            set_at: now,
        };
        self.store.default_accounts.retain(|existing| {
            if existing.principal_id != default_account.principal_id
                || existing.intent != default_account.intent
            {
                return true;
            }
            if is_eip155_namespace(&default_account.chain_namespace)
                && is_eip155_namespace(&existing.chain_namespace)
            {
                return false;
            }
            existing.chain_namespace != default_account.chain_namespace
        });
        self.store.default_accounts.push(default_account.clone());
        if let Err(err) = self.save() {
            return Response::error("storage_error", err);
        }
        Response::ok(json!({
            "default_account": default_account,
            "account": account,
        }))
    }

    pub(super) fn default_account(
        &self,
        principal_id: &str,
        chain_namespace: &str,
        intent: &str,
    ) -> Response {
        if let Err(response) = self.ensure_initialized() {
            return response;
        }
        if let Err(err) = validate_default_account_lookup(principal_id, chain_namespace, intent) {
            return Response::error("invalid_request", err);
        }
        let Some(default) = self.default_account_record(principal_id, chain_namespace, intent)
        else {
            return Response::error("not_found", "default linked account not set");
        };
        let Some(account) = self.active_account(principal_id, &default.account_id) else {
            return Response::error("not_found", "default linked account is not active");
        };
        Response::ok(json!({
            "default_account": default,
            "account": account,
        }))
    }

    pub(super) fn active_account(
        &self,
        principal_id: &str,
        account_id: &str,
    ) -> Option<&LinkedAccount> {
        self.store.accounts.iter().find(|account| {
            account.principal_id == principal_id
                && account.account_id == account_id
                && account.revoked_at.is_none()
        })
    }

    pub(super) fn default_account_record(
        &self,
        principal_id: &str,
        chain_namespace: &str,
        intent: &str,
    ) -> Option<&DefaultWalletAccount> {
        if is_eip155_namespace(chain_namespace) {
            return self
                .store
                .default_accounts
                .iter()
                .filter(|default| {
                    default.principal_id == principal_id
                        && default.intent == intent
                        && is_eip155_namespace(&default.chain_namespace)
                })
                .filter(|default| {
                    self.active_account(principal_id, &default.account_id)
                        .map(|account| {
                            chain_namespaces_compatible(&account.chain_namespace, chain_namespace)
                        })
                        .unwrap_or(false)
                })
                .max_by_key(|default| default.set_at);
        }
        self.store.default_accounts.iter().find(|default| {
            default.principal_id == principal_id
                && default.chain_namespace == chain_namespace
                && default.intent == intent
        })
    }
}

fn is_eip155_namespace(value: &str) -> bool {
    value.starts_with("eip155:")
}

/// Unit tests for the refusals of the account, recovery-key and default-account
/// calls in this file.
///
/// They pin answers the provider already gives; they add no rule and register no
/// falsifier. They prove what the wallet provider answers, not confinement: the
/// Runtime decides whether the provider runs at all, and no test here speaks for
/// that decision.
///
/// Three strings across five sites are not reachable from a call, so none has a
/// test. `managed recovery key import returned no account` and `managed recovery
/// key export returned no key` sit in `Response::Ok { data: None }` arms of
/// calls that always answer `data: Some(..)`. `wallet-provider managed wallet
/// storage is not initialized` is guarded by `self.storage_key.is_none()`, and
/// `ensure_initialized` already refuses with `wallet-provider is not
/// initialized` when either field is `None`, while `init` sets both together.
#[cfg(test)]
mod uf_account_refusal_tests {
    use super::*;
    use elastos_wallet_contract::MANAGED_RECOVERY_SET_SCHEMA;

    const PRINCIPAL: &str = "person:local:alice";
    const EVM_CHAIN: &str = "eip155:20";
    const ADDRESS: &str = "0x1111111111111111111111111111111111111111";
    const OTHER_ADDRESS: &str = "0x2222222222222222222222222222222222222222";
    /// An account id of ordinary characters that was never linked, so the opaque
    /// id checks pass and only the record lookup can answer.
    const UNLINKED_ACCOUNT_ID: &str = "wallet:eip155:20:0x9999999999999999999999999999999999999999";

    /// Links an external account on `eip155:20` and answers its account id.
    fn link_external_account(provider: &mut WalletProvider) -> String {
        let response = provider.link_account(LinkAccountInput {
            principal_id: PRINCIPAL.to_string(),
            proof_binding_id: format!("proof:eip155:20:{ADDRESS}"),
            chain_namespace: EVM_CHAIN.to_string(),
            address: ADDRESS.to_string(),
            proof_type: "siwe".to_string(),
            connector_id: Some("walletconnect".to_string()),
            label: None,
        });
        assert!(
            matches!(response, Response::Ok { .. }),
            "link must succeed, got {response:?}"
        );
        account_id(EVM_CHAIN, ADDRESS)
    }

    fn create_managed_account(provider: &mut WalletProvider, create_new: bool) -> Response {
        provider.create_managed_account(CreateManagedAccountInput {
            principal_id: PRINCIPAL.to_string(),
            chain_namespace: EVM_CHAIN.to_string(),
            label: None,
            create_new,
        })
    }

    /// The deterministic signing key every recovery-key case starts from.
    fn recovery_signing_key() -> SigningKey {
        SigningKey::from_slice(&[7_u8; 32]).expect("deterministic recovery key")
    }

    /// A recovery key the importer accepts, so one case changes one field and
    /// meets every check ahead of the one it names.
    fn recovery_key_value() -> Value {
        let signing_key = recovery_signing_key();
        let address = managed_address_for_signing_key(&signing_key, EVM_CHAIN)
            .expect("eip155:20 is a managed chain");
        json!({
            "schema": "elastos.wallet.recovery-key/v1",
            "account_id": account_id(EVM_CHAIN, &address),
            "chain_namespace": EVM_CHAIN,
            "address": address,
            "secret_type": "secp256k1_private_key_hex",
            "private_key_hex": hex::encode(signing_key.to_bytes()),
        })
    }

    fn import_recovery_key(provider: &mut WalletProvider, recovery_key: Value) -> Response {
        provider.import_managed_recovery_key(ImportManagedRecoveryKeyInput {
            principal_id: PRINCIPAL.to_string(),
            recovery_key,
            label: None,
        })
    }

    fn error(code: &str, message: &str) -> Response {
        Response::Error {
            code: code.to_string(),
            message: message.to_string(),
        }
    }

    /// Catches removal of the active-account guard in `rename_account` (:500),
    /// `export_managed_recovery_key` (:529) and `set_default_account` (:610):
    /// without any of them the call reaches a record that was never linked.
    ///
    /// One string is raised from three sites, so this test drives all three.
    #[test]
    fn account_refuses_missing_active_account() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = WalletProvider::new();
        let response = provider.init(json!({ "base_path": dir.path().display().to_string() }));
        assert!(
            matches!(response, Response::Ok { .. }),
            "init must succeed, got {response:?}"
        );

        assert_eq!(
            provider.rename_account(PRINCIPAL, UNLINKED_ACCOUNT_ID, "Spending"),
            error("not_found", "active linked account not found")
        );
        assert_eq!(
            provider.export_managed_recovery_key(PRINCIPAL, UNLINKED_ACCOUNT_ID),
            error("not_found", "active linked account not found")
        );
        assert_eq!(
            provider.set_default_account(SetDefaultAccountInput {
                principal_id: PRINCIPAL.to_string(),
                chain_namespace: EVM_CHAIN.to_string(),
                intent: "browser_personal_sign".to_string(),
                account_id: UNLINKED_ACCOUNT_ID.to_string(),
            }),
            error("not_found", "active linked account not found")
        );
    }

    /// Catches removal of the record lookup in `revoke_account` (:455): without
    /// it a revocation of an account that was never linked answers as if the
    /// account had been revoked.
    #[test]
    fn account_refuses_missing_linked_account() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = WalletProvider::new();
        let response = provider.init(json!({ "base_path": dir.path().display().to_string() }));
        assert!(
            matches!(response, Response::Ok { .. }),
            "init must succeed, got {response:?}"
        );
        assert_eq!(
            provider.revoke_account(PRINCIPAL, UNLINKED_ACCOUNT_ID),
            error("not_found", "linked account not found")
        );
    }

    /// Catches removal of the empty-label guard in `rename_account` (:490):
    /// without it a blank label clears the account's name.
    #[test]
    fn account_refuses_empty_label() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = WalletProvider::new();
        let response = provider.init(json!({ "base_path": dir.path().display().to_string() }));
        assert!(
            matches!(response, Response::Ok { .. }),
            "init must succeed, got {response:?}"
        );
        assert_eq!(
            provider.rename_account(PRINCIPAL, UNLINKED_ACCOUNT_ID, "   "),
            error("invalid_request", "label is required")
        );
    }

    /// Catches removal of the managed-account guard in
    /// `export_managed_recovery_key` (:533): without it the provider exports a
    /// recovery key answer for an account whose key an external connector holds.
    #[test]
    fn account_refuses_export_of_external_account() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = WalletProvider::new();
        let response = provider.init(json!({ "base_path": dir.path().display().to_string() }));
        assert!(
            matches!(response, Response::Ok { .. }),
            "init must succeed, got {response:?}"
        );
        let linked_account_id = link_external_account(&mut provider);
        assert_eq!(
            provider.export_managed_recovery_key(PRINCIPAL, &linked_account_id),
            error(
                "external_wallet_required",
                "recovery key is available only for passkey-managed accounts"
            )
        );
    }

    /// Catches removal of the chain-match guard in `set_default_account` (:614):
    /// without it an `eip155:1` default points at an `eip155:20` account.
    #[test]
    fn account_refuses_default_chain_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = WalletProvider::new();
        let response = provider.init(json!({ "base_path": dir.path().display().to_string() }));
        assert!(
            matches!(response, Response::Ok { .. }),
            "init must succeed, got {response:?}"
        );
        let linked_account_id = link_external_account(&mut provider);
        assert_eq!(
            provider.set_default_account(SetDefaultAccountInput {
                principal_id: PRINCIPAL.to_string(),
                chain_namespace: "eip155:1".to_string(),
                intent: "browser_personal_sign".to_string(),
                account_id: linked_account_id,
            }),
            error(
                "invalid_request",
                "default wallet chain must match the linked account"
            )
        );
    }

    /// Catches removal of the missing-record guard in `default_account` (:665):
    /// without it an unset default answers as an account.
    #[test]
    fn account_refuses_default_account_not_set() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = WalletProvider::new();
        let response = provider.init(json!({ "base_path": dir.path().display().to_string() }));
        assert!(
            matches!(response, Response::Ok { .. }),
            "init must succeed, got {response:?}"
        );
        assert_eq!(
            provider.default_account(PRINCIPAL, EVM_CHAIN, "browser_personal_sign"),
            error("not_found", "default linked account not set")
        );
    }

    /// Catches removal of the active-account guard in `default_account` (:667):
    /// without it a default record whose account is gone answers as an account.
    ///
    /// This case needs provider state, not a plain input: the store fields are
    /// declared in the crate root, so the test pushes one `DefaultWalletAccount`
    /// for an account id that was never linked. That is provider state, not a
    /// copy of a check.
    ///
    /// The record is on a non-EVM namespace because `default_account_record`
    /// runs the active-account filter inside its `eip155` lookup, which would
    /// answer `default linked account not set` instead.
    #[test]
    fn account_refuses_default_account_not_active() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = WalletProvider::new();
        let response = provider.init(json!({ "base_path": dir.path().display().to_string() }));
        assert!(
            matches!(response, Response::Ok { .. }),
            "init must succeed, got {response:?}"
        );
        provider.store.default_accounts.push(DefaultWalletAccount {
            schema: "elastos.wallet.default_account/v1".to_string(),
            principal_id: PRINCIPAL.to_string(),
            chain_namespace: BITCOIN_MAINNET_CHAIN_NAMESPACE.to_string(),
            intent: "bitcoin_bip322_proof".to_string(),
            account_id: account_id(BITCOIN_MAINNET_CHAIN_NAMESPACE, "bc1q-never-linked"),
            set_at: 1,
        });
        assert_eq!(
            provider.default_account(
                PRINCIPAL,
                BITCOIN_MAINNET_CHAIN_NAMESPACE,
                "bitcoin_bip322_proof"
            ),
            error("not_found", "default linked account is not active")
        );
    }

    /// Catches removal of the ambiguous-key guard in `create_managed_account`
    /// (:126): without it a reuse request silently picks one of two distinct
    /// active keys in the same scope, so the account it answers was chosen by
    /// iteration order.
    ///
    /// This case needs the account state, not a plain input: two managed
    /// `eip155:20` accounts are created with `create_new: true`, so both keys
    /// stay active in one scope.
    #[test]
    fn account_refuses_ambiguous_managed_key_reuse() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = WalletProvider::new();
        let response = provider.init(json!({ "base_path": dir.path().display().to_string() }));
        assert!(
            matches!(response, Response::Ok { .. }),
            "init must succeed, got {response:?}"
        );
        assert!(matches!(
            create_managed_account(&mut provider, true),
            Response::Ok { .. }
        ));
        assert!(matches!(
            create_managed_account(&mut provider, true),
            Response::Ok { .. }
        ));
        assert_eq!(
            create_managed_account(&mut provider, false),
            error(
                "managed_key_ambiguous",
                "multiple distinct active managed wallet keys are eligible for reuse; create_new is required"
            )
        );
    }

    /// Catches removal of the schema check in `import_managed_recovery_key`
    /// (:212): without it a recovery key of another schema is imported.
    #[test]
    fn account_refuses_recovery_key_schema() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = WalletProvider::new();
        let response = provider.init(json!({ "base_path": dir.path().display().to_string() }));
        assert!(
            matches!(response, Response::Ok { .. }),
            "init must succeed, got {response:?}"
        );
        let mut recovery_key = recovery_key_value();
        recovery_key["schema"] = json!("elastos.wallet.recovery-key/v2");
        assert_eq!(
            import_recovery_key(&mut provider, recovery_key),
            error("invalid_request", "expected elastos.wallet.recovery-key/v1")
        );
    }

    /// Catches removal of the `account_id` presence check (:218): without it a
    /// recovery key with no account id reaches the match against its chain and
    /// address.
    #[test]
    fn account_refuses_recovery_key_missing_account_id() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = WalletProvider::new();
        let response = provider.init(json!({ "base_path": dir.path().display().to_string() }));
        assert!(
            matches!(response, Response::Ok { .. }),
            "init must succeed, got {response:?}"
        );
        let mut recovery_key = recovery_key_value();
        recovery_key.as_object_mut().unwrap().remove("account_id");
        assert_eq!(
            import_recovery_key(&mut provider, recovery_key),
            error("invalid_request", "recovery key missing account_id")
        );
    }

    /// Catches removal of the `chain_namespace` presence check (:221): without
    /// it a recovery key with no chain reaches the address checks.
    #[test]
    fn account_refuses_recovery_key_missing_chain_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = WalletProvider::new();
        let response = provider.init(json!({ "base_path": dir.path().display().to_string() }));
        assert!(
            matches!(response, Response::Ok { .. }),
            "init must succeed, got {response:?}"
        );
        let mut recovery_key = recovery_key_value();
        recovery_key
            .as_object_mut()
            .unwrap()
            .remove("chain_namespace");
        assert_eq!(
            import_recovery_key(&mut provider, recovery_key),
            error("invalid_request", "recovery key missing chain_namespace")
        );
    }

    /// Catches removal of the `address` presence check (:226): without it a
    /// recovery key with no address reaches the account-id match.
    #[test]
    fn account_refuses_recovery_key_missing_address() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = WalletProvider::new();
        let response = provider.init(json!({ "base_path": dir.path().display().to_string() }));
        assert!(
            matches!(response, Response::Ok { .. }),
            "init must succeed, got {response:?}"
        );
        let mut recovery_key = recovery_key_value();
        recovery_key.as_object_mut().unwrap().remove("address");
        assert_eq!(
            import_recovery_key(&mut provider, recovery_key),
            error("invalid_request", "recovery key missing address")
        );
    }

    /// Catches removal of the `secret_type` check (:234): without it a key of a
    /// kind the provider cannot decrypt is imported as a secp256k1 key.
    #[test]
    fn account_refuses_recovery_key_secret_type() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = WalletProvider::new();
        let response = provider.init(json!({ "base_path": dir.path().display().to_string() }));
        assert!(
            matches!(response, Response::Ok { .. }),
            "init must succeed, got {response:?}"
        );
        let mut recovery_key = recovery_key_value();
        recovery_key["secret_type"] = json!("bip39_seed_phrase");
        assert_eq!(
            import_recovery_key(&mut provider, recovery_key),
            error("invalid_request", "unsupported wallet recovery key type")
        );
    }

    /// Catches removal of the account-id match (:251): without it a key is
    /// imported under an id that names another chain and address.
    #[test]
    fn account_refuses_recovery_key_account_id_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = WalletProvider::new();
        let response = provider.init(json!({ "base_path": dir.path().display().to_string() }));
        assert!(
            matches!(response, Response::Ok { .. }),
            "init must succeed, got {response:?}"
        );
        let mut recovery_key = recovery_key_value();
        recovery_key["account_id"] = json!(account_id(EVM_CHAIN, OTHER_ADDRESS));
        assert_eq!(
            import_recovery_key(&mut provider, recovery_key),
            error(
                "invalid_request",
                "recovery key account_id does not match chain and address"
            )
        );
    }

    /// Catches removal of the private-key presence check (:257): without it a
    /// recovery key with no private key reaches the length check.
    #[test]
    fn account_refuses_recovery_key_missing_private_key_hex() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = WalletProvider::new();
        let response = provider.init(json!({ "base_path": dir.path().display().to_string() }));
        assert!(
            matches!(response, Response::Ok { .. }),
            "init must succeed, got {response:?}"
        );
        let mut recovery_key = recovery_key_value();
        recovery_key
            .as_object_mut()
            .unwrap()
            .remove("private_key_hex");
        assert_eq!(
            import_recovery_key(&mut provider, recovery_key),
            error("invalid_request", "recovery key missing private_key_hex")
        );
    }

    /// Catches removal of the 32-byte length check (:261): without it a short
    /// private key reaches the curve parser instead of the length answer.
    #[test]
    fn account_refuses_recovery_key_private_key_length() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = WalletProvider::new();
        let response = provider.init(json!({ "base_path": dir.path().display().to_string() }));
        assert!(
            matches!(response, Response::Ok { .. }),
            "init must succeed, got {response:?}"
        );
        let mut recovery_key = recovery_key_value();
        recovery_key["private_key_hex"] = json!(hex::encode([1_u8; 31]));
        assert_eq!(
            import_recovery_key(&mut provider, recovery_key),
            error("invalid_request", "private_key_hex must be 32 bytes")
        );
    }

    /// Catches removal of the curve check (:265): without it a 32-byte value
    /// that is not a secp256k1 scalar reaches the address derivation.
    #[test]
    fn account_refuses_recovery_key_invalid_private_key() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = WalletProvider::new();
        let response = provider.init(json!({ "base_path": dir.path().display().to_string() }));
        assert!(
            matches!(response, Response::Ok { .. }),
            "init must succeed, got {response:?}"
        );
        let mut recovery_key = recovery_key_value();
        recovery_key["private_key_hex"] = json!(hex::encode([0_u8; 32]));
        assert_eq!(
            import_recovery_key(&mut provider, recovery_key),
            error("invalid_request", "invalid secp256k1 private key")
        );
    }

    /// Catches removal of the address-match check (:272): without it a private
    /// key is imported for an address a different key controls.
    #[test]
    fn account_refuses_recovery_key_private_key_address_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = WalletProvider::new();
        let response = provider.init(json!({ "base_path": dir.path().display().to_string() }));
        assert!(
            matches!(response, Response::Ok { .. }),
            "init must succeed, got {response:?}"
        );
        let mut recovery_key = recovery_key_value();
        recovery_key["private_key_hex"] = json!(hex::encode([9_u8; 32]));
        assert_eq!(
            import_recovery_key(&mut provider, recovery_key),
            error(
                "invalid_request",
                "private key does not match recovery key address"
            )
        );
    }

    /// Catches removal of the entry match in `import_managed_recovery_set`
    /// (:370): without it a set entry is imported under an account id that
    /// differs from the id inside its own recovery key.
    ///
    /// The set's own `validate` passes first, so the entry's key is a non-empty
    /// JSON object of the recovery-key schema and only the entry match can
    /// answer.
    #[test]
    fn account_refuses_recovery_set_account_id_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = WalletProvider::new();
        let response = provider.init(json!({ "base_path": dir.path().display().to_string() }));
        assert!(
            matches!(response, Response::Ok { .. }),
            "init must succeed, got {response:?}"
        );
        let recovery_set = ManagedRecoverySetV1 {
            schema: MANAGED_RECOVERY_SET_SCHEMA.to_string(),
            keys: vec![ManagedRecoveryKeyEntryV1 {
                account_id: account_id(EVM_CHAIN, OTHER_ADDRESS),
                recovery_key: recovery_key_value(),
                label: None,
            }],
        };
        assert_eq!(
            provider.import_managed_recovery_set(PRINCIPAL, &recovery_set),
            error(
                "invalid_request",
                "managed recovery set account_id does not match its opaque recovery key"
            )
        );
    }
}
