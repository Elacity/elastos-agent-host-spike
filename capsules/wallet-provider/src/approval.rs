use super::*;

pub(super) struct ConnectorHandoffCompletion<'a> {
    pub(super) principal_id: &'a str,
    pub(super) session_id: &'a str,
    pub(super) request_id: &'a str,
    pub(super) connector_id: &'a str,
    pub(super) payload_hash: &'a str,
    pub(super) signature: Option<&'a str>,
    pub(super) signature_type: Option<&'a str>,
    pub(super) public_key: Option<&'a str>,
    pub(super) signer: &'a str,
    pub(super) transaction_hash: Option<&'a str>,
}

impl WalletProvider {
    pub(super) fn idempotent_transaction_effect_replay(
        &self,
        wallet_request: &WalletProviderRequestV2,
    ) -> Option<Response> {
        match &wallet_request.operation {
            WalletProviderOperationV2::RequestApproval { .. } => {
                let existing = self
                    .store
                    .approval_requests
                    .iter()
                    .find(|request| request.request_id == wallet_request.request_id)?;
                let authority_binding = wallet_authority_binding(&wallet_request.authority);
                if existing.principal_id != wallet_request.authority.principal_id
                    || existing.wallet_request_sha256 != wallet_request.request_sha256
                    || existing.authority_binding != authority_binding
                {
                    return Some(Response::error(
                        "approval_identity_conflict",
                        "Wallet approval identity was reused with substituted semantics or authority",
                    ));
                }
                Some(Response::ok(json!({
                    "approval_request": existing,
                    "requires_approval": existing.status == ApprovalStatus::Pending,
                    "signature": Value::Null,
                })))
            }
            WalletProviderOperationV2::RequestProtectedContentRightsSignature { .. } => {
                let existing = self
                    .store
                    .approval_requests
                    .iter()
                    .find(|request| request.request_id == wallet_request.request_id)?;
                let authority_binding = wallet_authority_binding(&wallet_request.authority);
                if existing.principal_id != wallet_request.authority.principal_id
                    || existing.wallet_request_sha256 != wallet_request.request_sha256
                    || existing.authority_binding != authority_binding
                {
                    return Some(Response::error(
                        "approval_identity_conflict",
                        "Wallet approval identity was reused with substituted semantics or authority",
                    ));
                }
                let mut response = json!({
                    "approval_request": existing,
                    "requires_approval": existing.status == ApprovalStatus::Pending,
                    "signature": Value::Null,
                });
                if let Some(stored) = existing.signed_result.as_ref() {
                    let Ok(result) = serde_json::from_value::<
                        ProtectedContentRightsSignatureResultV1,
                    >(stored.clone()) else {
                        return Some(Response::error(
                            "signing_error",
                            "stored protected-content rights result is invalid",
                        ));
                    };
                    if let Err(err) =
                        validate_protected_content_rights_result_for_request(&result, existing)
                    {
                        return Some(Response::error("signing_error", err));
                    }
                    response["signed_result"] = stored.clone();
                }
                if let Some(receipt) = existing.signature_receipt.as_ref() {
                    response["signature_receipt"] =
                        serde_json::to_value(receipt).unwrap_or(Value::Null);
                }
                Some(Response::ok(response))
            }
            WalletProviderOperationV2::AttachValidatedChainOutcome { outcome } => {
                let existing = self
                    .store
                    .approval_requests
                    .iter()
                    .find(|request| request.request_id == outcome.approval_request_id)?;
                if let Err(err) =
                    validate_chain_outcome_target(existing, &wallet_request.authority, outcome)
                {
                    return Some(Response::error("chain_outcome_conflict", err));
                }
                existing.validated_chain_outcome.as_ref().map(|stored| {
                    if stored != outcome {
                        Response::error(
                            "chain_outcome_conflict",
                            "validated Chain outcome substitution was rejected",
                        )
                    } else {
                        Response::ok(json!({ "approval_request": existing }))
                    }
                })
            }
            _ => None,
        }
    }

    pub(super) fn request_protected_content_rights_signature(
        &mut self,
        request: &WalletProviderRequestV2,
        account_id: &str,
        canonical_rights_request_hex: &str,
        reason: &str,
    ) -> Response {
        if let Err(response) = self.ensure_initialized() {
            return response;
        }
        let now = now_ts();
        let (rights_request, _) =
            match protected_content_rights_request_from_hex(canonical_rights_request_hex) {
                Ok(value) => value,
                Err(err) => return Response::error("invalid_request", err),
            };
        let Some(account) = self
            .active_account(&request.authority.principal_id, account_id)
            .cloned()
        else {
            return Response::error("not_found", "active linked account not found");
        };
        if let Err(err) =
            validate_protected_content_rights_request_account(&rights_request, &account, now)
        {
            return Response::error("invalid_request", err);
        }
        let expires_at = rights_request
            .expires_at()
            .min(now.saturating_add(MAX_APPROVAL_REQUEST_TTL_SECS));
        self.request_approval(SignatureRequestInput {
            request_id: request.request_id.clone(),
            wallet_request_sha256: request.request_sha256.clone(),
            authority_binding: wallet_authority_binding(&request.authority),
            principal_id: request.authority.principal_id.clone(),
            session_id: request.authority.session_id.clone(),
            launch_id: request.authority.launch_id.clone(),
            proof_binding_id: request.authority.proof_binding_id.clone(),
            account_id: account_id.to_string(),
            chain_namespace: account.chain_namespace,
            intent: PROTECTED_CONTENT_RIGHTS_SIGNATURE_INTENT.to_string(),
            requested_by_actor: request.authority.actor.clone(),
            resource: PROTECTED_CONTENT_RIGHTS_SIGNATURE_RESOURCE.to_string(),
            reason: reason.to_string(),
            payload: protected_content_rights_approval_payload(canonical_rights_request_hex),
            expires_at,
        })
    }

    pub(super) fn request_approval(&mut self, input: SignatureRequestInput) -> Response {
        if let Err(response) = self.ensure_initialized() {
            return response;
        }
        let now = now_ts();
        if let Err(err) = input.validate(now) {
            return Response::error("invalid_request", err);
        }
        let previous_store = self.store.clone();
        self.store = prune_store(std::mem::take(&mut self.store), now);
        let account = match self.account_for_signature(&input) {
            Ok(account) => account,
            Err(response) => return response,
        };
        if let Err(response) = self.ensure_managed_account_can_sign(&account) {
            return response;
        }
        if is_managed_proof_type(&account.proof_type)
            && !managed_signing_intent_is_supported(&input.intent)
        {
            return Response::error(
                "unsupported_managed_signing_intent",
                "managed signing is implemented only for Browser account access, personal_sign, typed data, transaction, and Bitcoin BIP-322 intents",
            );
        }
        if account.chain_namespace == BITCOIN_MAINNET_CHAIN_NAMESPACE
            && input.intent != "bitcoin_bip322_proof"
        {
            return Response::error(
                "invalid_request",
                "Bitcoin accounts only support bitcoin_bip322_proof signing",
            );
        }
        if input.intent == "transaction_intent" {
            if let Err(err) = validate_eip155_transaction_intent_payload(&input.payload, &account) {
                return Response::error("invalid_transaction_intent", err);
            }
        }
        if input.intent == "browser_personal_sign" {
            if let Err(err) = validate_browser_personal_sign_payload(&input.payload, &account) {
                return Response::error("invalid_browser_personal_sign", err);
            }
        }
        if input.intent == "browser_typed_data_sign" {
            if let Err(err) = validate_browser_typed_data_sign_payload(&input.payload, &account) {
                return Response::error("invalid_browser_typed_data_sign", err);
            }
        }
        if input.intent == "browser_account_access" {
            if let Err(err) =
                validate_browser_account_access_payload(&input.payload, &account, &input, now)
            {
                return Response::error("invalid_browser_account_access", err);
            }
        }
        if input.intent == PROTECTED_CONTENT_RIGHTS_SIGNATURE_INTENT {
            let (rights_request, _) =
                match protected_content_rights_request_from_payload(&input.payload) {
                    Ok(value) => value,
                    Err(err) => return Response::error("invalid_request", err),
                };
            if let Err(err) =
                validate_protected_content_rights_request_account(&rights_request, &account, now)
            {
                return Response::error("invalid_request", err);
            }
        }
        if input.intent == "bitcoin_bip322_proof" {
            if account.chain_namespace != BITCOIN_MAINNET_CHAIN_NAMESPACE
                || !matches!(
                    account.proof_type.as_str(),
                    MANAGED_BTC_P2WPKH_PROOF_TYPE | "bip322_simple" | "bitcoin_signed_message"
                )
            {
                return Response::error(
                    "invalid_request",
                    "Bitcoin proof signing requires a supported Bitcoin account",
                );
            }
            if let Err(err) =
                self.validate_bitcoin_challenge_for_signing(&input.payload, &account, now)
            {
                return Response::error("invalid_bitcoin_bip322_proof", err);
            }
        }

        let active_request_count = self
            .store
            .approval_requests
            .iter()
            .filter(|request| request.principal_id == input.principal_id)
            .filter(|request| approval_authority_is_active(request, now))
            .count();
        if active_request_count >= MAX_ACTIVE_APPROVAL_REQUESTS_PER_PRINCIPAL {
            return Response::error(
                "approval_limit_reached",
                "too many active wallet approval requests for this principal",
            );
        }

        let request = WalletApprovalRequest {
            schema: "elastos.wallet.approval_request/v1".to_string(),
            request_id: input.request_id,
            wallet_request_sha256: input.wallet_request_sha256,
            authority_binding: input.authority_binding,
            kind: "signature".to_string(),
            status: ApprovalStatus::Pending,
            principal_id: input.principal_id,
            account_id: account.account_id,
            proof_binding_id: account.proof_binding_id,
            chain_namespace: input.chain_namespace,
            address: account.address,
            proof_type: account.proof_type,
            connector_id: account.connector_id,
            intent: input.intent,
            session_id: input.session_id,
            launch_id: input.launch_id,
            requested_by_actor: input.requested_by_actor,
            resource: input.resource,
            reason: input.reason,
            payload_hash: value_hash(&input.payload),
            payload: input.payload,
            created_at: now,
            expires_at: input.expires_at,
            resolved_at: None,
            rejection_reason: None,
            approved_at: None,
            approval_reason: None,
            completed_at: None,
            signature_receipt: None,
            signed_result: None,
            validated_chain_outcome: None,
        };
        self.store.approval_requests.push(request.clone());
        if let Err(err) = self.save() {
            self.recover_store_after_save_failure(previous_store);
            return Response::error("storage_error", err);
        }
        Response::ok(json!({
            "approval_request": request,
            "requires_approval": true,
            "signature": Value::Null,
        }))
    }

    pub(super) fn attach_validated_chain_outcome(
        &mut self,
        authority: &WalletAuthorityV2,
        outcome: &ValidatedChainOutcomeV1,
    ) -> Response {
        if let Err(response) = self.ensure_initialized() {
            return response;
        }
        let Some(request_index) = self
            .store
            .approval_requests
            .iter()
            .position(|request| request.request_id == outcome.approval_request_id)
        else {
            return Response::error("not_found", "wallet approval request not found");
        };
        let request = self.store.approval_requests[request_index].clone();
        if let Err(err) = validate_chain_outcome_target(&request, authority, outcome) {
            return Response::error("chain_outcome_conflict", err);
        }
        if let Some(stored) = request.validated_chain_outcome.as_ref() {
            return if stored == outcome {
                Response::ok(json!({ "approval_request": request }))
            } else {
                Response::error(
                    "chain_outcome_conflict",
                    "validated Chain outcome substitution was rejected",
                )
            };
        }
        self.store.approval_requests[request_index].validated_chain_outcome = Some(outcome.clone());
        let request = self.store.approval_requests[request_index].clone();
        if let Err(err) = self.save() {
            return Response::error("storage_error", err);
        }
        Response::ok(json!({ "approval_request": request }))
    }

    pub(super) fn approval_requests(
        &mut self,
        principal_id: &str,
        include_resolved: bool,
    ) -> Response {
        if let Err(response) = self.ensure_initialized() {
            return response;
        }
        if let Err(err) = validate_opaque_id(principal_id, "principal_id") {
            return Response::error("invalid_request", err);
        }
        let now = now_ts();
        let store = prune_store(self.store.clone(), now);
        let requests = store
            .approval_requests
            .iter()
            .filter(|request| request.principal_id == principal_id)
            .filter(|request| include_resolved || request.status == ApprovalStatus::Pending)
            .collect::<Vec<_>>();
        Response::ok(json!({ "approval_requests": requests }))
    }

    pub(super) fn reject_approval(
        &mut self,
        principal_id: &str,
        session_id: &str,
        actor: &str,
        request_id: &str,
        reason: &str,
    ) -> Response {
        if let Err(response) = self.ensure_initialized() {
            return response;
        }
        if let Err(err) = validate_opaque_id(principal_id, "principal_id") {
            return Response::error("invalid_request", err);
        }
        if let Err(err) = validate_opaque_id(session_id, "session_id") {
            return Response::error("invalid_request", err);
        }
        if let Err(err) = validate_opaque_id(actor, "actor") {
            return Response::error("invalid_request", err);
        }
        if let Err(err) = validate_opaque_id(request_id, "request_id") {
            return Response::error("invalid_request", err);
        }
        if let Err(err) = validate_reason(reason) {
            return Response::error("invalid_request", err);
        }
        let now = now_ts();
        self.store = prune_store(std::mem::take(&mut self.store), now);
        let Some(request) = self.store.approval_requests.iter_mut().find(|request| {
            request.principal_id == principal_id && request.request_id == request_id
        }) else {
            return Response::error("not_found", "wallet approval request not found");
        };
        if request.session_id != session_id {
            return Response::error(
                "invalid_request",
                "wallet approval request belongs to a different Runtime session",
            );
        }
        if actor.starts_with("wallet-") && request.connector_id.as_deref() != Some(actor) {
            return Response::error(
                "invalid_request",
                "wallet approval request belongs to a different connector",
            );
        }
        if request.status != ApprovalStatus::Pending {
            return Response::error("invalid_request", "wallet approval request is not pending");
        }
        request.status = ApprovalStatus::Rejected;
        request.resolved_at = Some(now);
        request.rejection_reason = Some(reason.trim().to_string());
        let request = request.clone();
        if let Err(err) = self.save() {
            return Response::error("storage_error", err);
        }
        Response::ok(json!({ "approval_request": request }))
    }

    pub(super) fn approve_connector_handoff(
        &mut self,
        principal_id: &str,
        session_id: &str,
        actor: &str,
        request_id: &str,
        reason: &str,
    ) -> Response {
        if let Err(response) = self.ensure_initialized() {
            return response;
        }
        if let Err(err) = validate_opaque_id(principal_id, "principal_id") {
            return Response::error("invalid_request", err);
        }
        if let Err(err) = validate_opaque_id(session_id, "session_id") {
            return Response::error("invalid_request", err);
        }
        if let Err(err) = validate_opaque_id(actor, "actor") {
            return Response::error("invalid_request", err);
        }
        if let Err(err) = validate_opaque_id(request_id, "request_id") {
            return Response::error("invalid_request", err);
        }
        if let Err(err) = validate_reason(reason) {
            return Response::error("invalid_request", err);
        }
        let now = now_ts();
        self.store = prune_store(std::mem::take(&mut self.store), now);
        let Some(request) = self.store.approval_requests.iter_mut().find(|request| {
            request.principal_id == principal_id && request.request_id == request_id
        }) else {
            return Response::error("not_found", "wallet approval request not found");
        };
        if request.session_id != session_id {
            return Response::error(
                "invalid_request",
                "wallet approval request belongs to a different Runtime session",
            );
        }
        if request.connector_id.as_deref() != Some(actor)
            || is_managed_proof_type(&request.proof_type)
        {
            return Response::error(
                "invalid_request",
                "wallet connector handoff authority does not match the approval",
            );
        }
        if request.status != ApprovalStatus::Pending {
            return Response::error("invalid_request", "wallet approval request is not pending");
        }
        request.status = ApprovalStatus::Approved;
        request.approved_at = Some(now);
        request.approval_reason = Some(reason.trim().to_string());
        let request = request.clone();
        let handoff = match external_wallet_handoff(&request) {
            Ok(handoff) => handoff,
            Err(err) => return Response::error("invalid_request", err),
        };
        if let Err(err) = self.save() {
            return Response::error("storage_error", err);
        }
        Response::ok(json!({
            "approval_request": request,
            "handoff": handoff,
            "signature": Value::Null,
        }))
    }

    pub(super) fn approve_and_sign_managed(
        &mut self,
        principal_id: &str,
        session_id: &str,
        request_id: &str,
        reason: &str,
    ) -> Response {
        if let Err(response) = self.ensure_initialized() {
            return response;
        }
        if let Err(err) = validate_opaque_id(principal_id, "principal_id") {
            return Response::error("invalid_request", err);
        }
        if let Err(err) = validate_opaque_id(session_id, "session_id") {
            return Response::error("invalid_request", err);
        }
        if let Err(err) = validate_opaque_id(request_id, "request_id") {
            return Response::error("invalid_request", err);
        }
        if let Err(err) = validate_reason(reason) {
            return Response::error("invalid_request", err);
        }
        let now = now_ts();
        self.store = prune_store(std::mem::take(&mut self.store), now);
        let Some(request) = self.store.approval_requests.iter_mut().find(|request| {
            request.principal_id == principal_id && request.request_id == request_id
        }) else {
            return Response::error("not_found", "wallet approval request not found");
        };
        expire_approval_if_elapsed(request, now);
        if request.status == ApprovalStatus::Expired {
            return Response::error("invalid_request", "wallet approval request expired");
        }
        if request.status != ApprovalStatus::Pending {
            return Response::error("invalid_request", "wallet approval request is not pending");
        }
        if request.session_id != session_id {
            return Response::error(
                "invalid_request",
                "managed Wallet approval belongs to a different Runtime session",
            );
        }
        if !is_managed_proof_type(&request.proof_type) || request.connector_id.is_some() {
            return Response::error(
                "external_wallet_required",
                "connector approvals require a typed connector handoff",
            );
        }
        request.status = ApprovalStatus::Approved;
        request.approved_at = Some(now);
        request.approval_reason = Some(reason.trim().to_string());
        self.sign_managed_approval(principal_id, request_id)
    }

    pub(super) fn complete_connector_handoff(
        &mut self,
        completion: ConnectorHandoffCompletion<'_>,
    ) -> Response {
        if let Err(response) = self.ensure_initialized() {
            return response;
        }
        if let Err(err) = validate_opaque_id(completion.principal_id, "principal_id") {
            return Response::error("invalid_request", err);
        }
        if let Err(err) = validate_opaque_id(completion.session_id, "session_id") {
            return Response::error("invalid_request", err);
        }
        if let Err(err) = validate_opaque_id(completion.request_id, "request_id") {
            return Response::error("invalid_request", err);
        }
        if let Err(err) = validate_opaque_id(completion.connector_id, "connector_id") {
            return Response::error("invalid_request", err);
        }
        if let Err(err) = validate_hash(completion.payload_hash, "payload_hash") {
            return Response::error("invalid_request", err);
        }
        if let Err(err) = validate_opaque_id(completion.signer, "signer") {
            return Response::error("invalid_request", err);
        }
        let now = now_ts();
        self.store = prune_store(std::mem::take(&mut self.store), now);
        let Some(request_index) = self.store.approval_requests.iter().position(|request| {
            request.principal_id == completion.principal_id
                && request.request_id == completion.request_id
        }) else {
            return Response::error("not_found", "wallet approval request not found");
        };
        {
            let request = &mut self.store.approval_requests[request_index];
            expire_approval_if_elapsed(request, now);
            if request.status == ApprovalStatus::Expired {
                return Response::error("invalid_request", "wallet approval request expired");
            }
            if request.status != ApprovalStatus::Approved {
                return Response::error(
                    "invalid_request",
                    "wallet approval request must be approved before completion",
                );
            }
            if request.session_id != completion.session_id {
                return Response::error(
                    "invalid_request",
                    "wallet approval request belongs to a different Runtime session",
                );
            }
            if request.connector_id.as_deref() != Some(completion.connector_id) {
                return Response::error(
                    "invalid_request",
                    "wallet approval request belongs to a different connector",
                );
            }
            if request.payload_hash != completion.payload_hash {
                return Response::error("invalid_request", "wallet approval payload hash mismatch");
            }
            if !request.address.eq_ignore_ascii_case(completion.signer)
                && request.account_id != completion.signer
            {
                return Response::error("invalid_request", "wallet signature signer mismatch");
            }
        }
        let request_snapshot = self.store.approval_requests[request_index].clone();
        let (signature_hash, signed_result) = if request_snapshot.intent == "transaction_intent" {
            if completion.signature.is_some() {
                return Response::error(
                    "invalid_request",
                    "external transaction completion must not include signature",
                );
            }
            let Some(transaction_hash) = completion.transaction_hash else {
                return Response::error(
                    "invalid_request",
                    "external transaction completion requires transaction_hash",
                );
            };
            if let Err(err) = validate_hash(transaction_hash, "transaction_hash") {
                return Response::error("invalid_request", err);
            }
            (
                bytes_hash(transaction_hash.as_bytes()),
                Some(external_transaction_result(
                    &request_snapshot,
                    transaction_hash,
                )),
            )
        } else if request_snapshot.intent == "bitcoin_bip322_proof" {
            let Some(signature) = completion.signature else {
                return Response::error(
                    "invalid_request",
                    "external signature completion requires signature",
                );
            };
            if let Err(err) = validate_signature(signature) {
                return Response::error("invalid_request", err);
            }
            let account = LinkedAccount {
                account_id: request_snapshot.account_id.clone(),
                principal_id: request_snapshot.principal_id.clone(),
                proof_binding_id: request_snapshot.proof_binding_id.clone(),
                chain_namespace: request_snapshot.chain_namespace.clone(),
                address: request_snapshot.address.clone(),
                proof_type: request_snapshot.proof_type.clone(),
                connector_id: request_snapshot.connector_id.clone(),
                label: None,
                linked_at: request_snapshot.created_at,
                revoked_at: None,
            };
            if let Err(err) = self.validate_bitcoin_challenge_for_signing(
                &request_snapshot.payload,
                &account,
                now,
            ) {
                return Response::error("invalid_bitcoin_bip322_proof", err);
            }
            let message = match external_signature_message(&request_snapshot) {
                Ok(message) => message,
                Err(err) => return Response::error("invalid_bitcoin_bip322_proof", err),
            };
            let signature_type = completion.signature_type.unwrap_or_else(|| {
                bitcoin_signature_type_for_proof_type(&request_snapshot.proof_type)
            });
            if let Err(err) = verify_bitcoin_proof_for_type(
                request_snapshot.proof_type.as_str(),
                signature_type,
                "bitcoin",
                &request_snapshot.address,
                &message,
                signature,
                completion.public_key,
            ) {
                return Response::error("invalid_bitcoin_proof", err);
            }
            (bytes_hash(signature.as_bytes()), None)
        } else if request_snapshot.intent == PROTECTED_CONTENT_RIGHTS_SIGNATURE_INTENT {
            let Some(signature) = completion.signature else {
                return Response::error(
                    "invalid_request",
                    "external protected-content rights completion requires signature",
                );
            };
            if let Err(err) = validate_signature(signature) {
                return Response::error("invalid_request", err);
            }
            if completion.signature_type != Some("personal_sign") {
                return Response::error(
                    "invalid_request",
                    "protected-content rights completion requires personal_sign",
                );
            }
            let Some(account) = self.store.accounts.iter().find(|account| {
                account.principal_id == request_snapshot.principal_id
                    && account.account_id == request_snapshot.account_id
                    && account.revoked_at.is_none()
            }) else {
                return Response::error("not_found", "active linked account not found");
            };
            let (rights_request, canonical_bytes) =
                match protected_content_rights_request_from_payload(&request_snapshot.payload) {
                    Ok(value) => value,
                    Err(err) => return Response::error("invalid_request", err),
                };
            if let Err(err) =
                validate_protected_content_rights_request_account(&rights_request, account, now)
            {
                return Response::error("invalid_request", err);
            }
            let hash = ethereum_signed_message_hash(&canonical_bytes);
            let recovered = match recover_evm_address_from_hash(&hash, signature) {
                Ok(recovered) => recovered,
                Err(err) => return Response::error("invalid_signature", err),
            };
            if normalize_evm_address(&recovered) != normalize_evm_address(&request_snapshot.address)
            {
                return Response::error("invalid_signature", "wallet signature signer mismatch");
            }
            let canonical_signature = match canonicalize_evm_signature(signature) {
                Ok(signature) => signature,
                Err(err) => return Response::error("invalid_signature", err),
            };
            let signed_request =
                match WalletSignedRightsRequestV1::new(rights_request, canonical_signature) {
                    Ok(value) => value,
                    Err(err) => return Response::error("invalid_signature", err.to_string()),
                };
            let signed_request_hex = match signed_request.canonical_bytes() {
                Ok(bytes) => hex::encode(bytes),
                Err(err) => return Response::error("invalid_signature", err.to_string()),
            };
            let signed_result = match ProtectedContentRightsSignatureResultV1::new(
                request_snapshot.account_id.clone(),
                recovered.clone(),
                signed_request_hex,
            ) {
                Ok(value) => value,
                Err(err) => return Response::error("invalid_signature", err.to_string()),
            };
            let signed_result = match serde_json::to_value(signed_result) {
                Ok(value) => Some(value),
                Err(err) => return Response::error("invalid_signature", err.to_string()),
            };
            (bytes_hash(signature.as_bytes()), signed_result)
        } else {
            let Some(signature) = completion.signature else {
                return Response::error(
                    "invalid_request",
                    "external signature completion requires signature",
                );
            };
            if let Err(err) = validate_signature(signature) {
                return Response::error("invalid_request", err);
            }
            let recovered = if request_snapshot.intent == "browser_typed_data_sign" {
                match eip712_payload_hash(&request_snapshot.payload)
                    .and_then(|hash| recover_evm_address_from_hash(&hash, signature))
                {
                    Ok(recovered) => recovered,
                    Err(err) => return Response::error("invalid_signature", err),
                }
            } else {
                let message = match external_signature_message(&request_snapshot) {
                    Ok(message) => message,
                    Err(err) => return Response::error("invalid_request", err),
                };
                if request_snapshot.intent == "browser_personal_sign" {
                    let message = match browser_personal_sign_message_bytes(&message) {
                        Ok(message) => message,
                        Err(err) => return Response::error("invalid_request", err),
                    };
                    let hash = ethereum_signed_message_hash(&message);
                    match recover_evm_address_from_hash(&hash, signature) {
                        Ok(recovered) => recovered,
                        Err(err) => return Response::error("invalid_signature", err),
                    }
                } else {
                    match recover_evm_address(&message, signature) {
                        Ok((recovered, _)) => recovered,
                        Err(err) => return Response::error("invalid_signature", err),
                    }
                }
            };
            if normalize_evm_address(&recovered) != normalize_evm_address(&request_snapshot.address)
            {
                return Response::error("invalid_signature", "wallet signature signer mismatch");
            }
            (
                bytes_hash(signature.as_bytes()),
                if request_snapshot.intent == "browser_typed_data_sign" {
                    browser_typed_data_sign_result(&request_snapshot, signature)
                } else {
                    browser_personal_sign_result(&request_snapshot, signature)
                },
            )
        };
        let receipt = WalletSignatureReceipt {
            schema: "elastos.wallet.signature_receipt/v1".to_string(),
            request_id: request_snapshot.request_id.clone(),
            signer: completion.signer.to_string(),
            payload_hash: completion.payload_hash.to_string(),
            signature_hash,
            completed_at: now,
        };
        let request = &mut self.store.approval_requests[request_index];
        request.status = ApprovalStatus::Completed;
        request.resolved_at = Some(now);
        request.completed_at = Some(now);
        request.signature_receipt = Some(receipt.clone());
        request.signed_result = signed_result;
        let request = request.clone();
        if let Err(err) = self.save() {
            return Response::error("storage_error", err);
        }
        Response::ok(json!({
            "approval_request": request,
            "signature_receipt": receipt,
        }))
    }

    fn sign_managed_approval(&mut self, principal_id: &str, request_id: &str) -> Response {
        if let Err(response) = self.ensure_initialized() {
            return response;
        }
        if let Err(err) = validate_opaque_id(principal_id, "principal_id") {
            return Response::error("invalid_request", err);
        }
        if let Err(err) = validate_opaque_id(request_id, "request_id") {
            return Response::error("invalid_request", err);
        }
        let previous_store = self.store.clone();
        let now = now_ts();
        self.store = prune_store(std::mem::take(&mut self.store), now);
        let request = match self.store.approval_requests.iter_mut().find(|request| {
            request.principal_id == principal_id && request.request_id == request_id
        }) {
            Some(request) => {
                expire_approval_if_elapsed(request, now);
                request.clone()
            }
            None => return Response::error("not_found", "wallet approval request not found"),
        };
        if request.status == ApprovalStatus::Expired {
            return Response::error("invalid_request", "wallet approval request expired");
        }
        if request.status != ApprovalStatus::Approved {
            return Response::error(
                "invalid_request",
                "wallet approval request must be approved before managed signing",
            );
        }
        if value_hash(&request.payload) != request.payload_hash {
            return Response::error(
                "signing_error",
                "wallet approval payload no longer matches the reviewed payload hash",
            );
        }
        if !managed_signing_intent_is_supported(&request.intent) {
            return Response::error(
                "unsupported_managed_signing_intent",
                "managed signing is implemented only for Browser account access, personal_sign, typed data, transaction, and Bitcoin BIP-322 intents",
            );
        }
        let Some(account) = self.store.accounts.iter().find(|account| {
            account.principal_id == principal_id
                && account.account_id == request.account_id
                && account.revoked_at.is_none()
        }) else {
            return Response::error("not_found", "active linked account not found");
        };
        if !is_managed_proof_type(&account.proof_type) {
            return Response::error(
                "external_wallet_required",
                "approved request requires an external wallet signature handoff",
            );
        }
        if request.proof_binding_id != account.proof_binding_id
            || request.chain_namespace != account.chain_namespace
            || request.address != account.address
            || request.proof_type != account.proof_type
            || request.connector_id != account.connector_id
        {
            return Response::error(
                "signing_error",
                "wallet approval authority no longer matches its managed account",
            );
        }
        if request.intent == "browser_personal_sign" {
            if let Err(err) = validate_browser_personal_sign_payload(&request.payload, account) {
                return Response::error("invalid_browser_personal_sign", err);
            }
        }
        if request.intent == "browser_typed_data_sign" {
            if let Err(err) = validate_browser_typed_data_sign_payload(&request.payload, account) {
                return Response::error("invalid_browser_typed_data_sign", err);
            }
        }
        if request.intent == "transaction_intent" {
            if let Err(err) = validate_eip155_transaction_intent_payload(&request.payload, account)
            {
                return Response::error("invalid_transaction_intent", err);
            }
        }
        if request.intent == "bitcoin_bip322_proof" {
            if let Err(err) =
                self.validate_bitcoin_challenge_for_signing(&request.payload, account, now)
            {
                return Response::error("invalid_bitcoin_bip322_proof", err);
            }
        }
        let signing_key = match self.managed_signing_key_for_account(account) {
            Ok(signing_key) => signing_key,
            Err(err) => return Response::error("managed_key_unavailable", err),
        };
        let signed = match sign_managed_approval(&signing_key, &request) {
            Ok(signed) => signed,
            Err(err) => return Response::error("signing_error", err),
        };
        let signature_receipt = WalletSignatureReceipt {
            schema: "elastos.wallet.signature_receipt/v1".to_string(),
            request_id: request.request_id.clone(),
            signer: request.address.clone(),
            payload_hash: request.payload_hash.clone(),
            signature_hash: bytes_hash(signed.authority.as_bytes()),
            completed_at: now,
        };
        let Some(stored_request) =
            self.store.approval_requests.iter_mut().find(|stored| {
                stored.principal_id == principal_id && stored.request_id == request_id
            })
        else {
            return Response::error("not_found", "wallet approval request not found");
        };
        stored_request.status = ApprovalStatus::Completed;
        stored_request.resolved_at = Some(now);
        stored_request.completed_at = Some(now);
        stored_request.signature_receipt = Some(signature_receipt.clone());
        stored_request.signed_result = managed_signed_result(&stored_request.clone(), &signed);
        let stored_request = stored_request.clone();
        if let Err(err) = self.save() {
            self.recover_store_after_save_failure(previous_store);
            return Response::error("storage_error", err);
        }
        let mut response = json!({
            "approval_request": stored_request,
            "signature_receipt": signature_receipt,
            "signed_payload": signed.payload,
        });
        match signed.kind {
            ManagedSignatureKind::Message
                if request.intent != PROTECTED_CONTENT_RIGHTS_SIGNATURE_INTENT =>
            {
                response["signature"] = Value::String(signed.authority);
            }
            ManagedSignatureKind::Message => {}
            ManagedSignatureKind::Transaction => {
                response["signed_transaction"] = Value::String(signed.authority);
            }
        }
        Response::ok(response)
    }
}

fn validate_browser_account_access_payload(
    payload: &Value,
    account: &LinkedAccount,
    input: &SignatureRequestInput,
    now: u64,
) -> Result<(), String> {
    const FIELDS: &[&str] = &[
        "schema",
        "permission",
        "principal_id",
        "session_id",
        "launch_id",
        "proof_binding_id",
        "origin",
        "page_url",
        "account_id",
        "requested_chain_namespace",
        "chain_namespaces",
        "address",
        "grant_expires_at",
        "requires_wallet_approval",
    ];
    const SUPPORTED_CHAIN_NAMESPACES: &[&str] = &["eip155:20", "eip155:8453"];

    let object = payload
        .as_object()
        .ok_or_else(|| "Browser account access payload must be an object".to_string())?;
    if object.len() != FIELDS.len() || !object.keys().all(|key| FIELDS.contains(&key.as_str())) {
        return Err("Browser account access payload fields are invalid".to_string());
    }
    let text = |field: &str| {
        object
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| format!("Browser account access payload missing {field}"))
    };
    if text("schema")? != "elastos.browser.account-access-request/v1" {
        return Err("Browser account access payload schema is invalid".to_string());
    }
    if text("permission")? != "eth_accounts" {
        return Err("Browser account access permission must be eth_accounts".to_string());
    }
    if input.requested_by_actor != "browser" {
        return Err("Browser account access must be requested by Browser".to_string());
    }
    if !is_managed_proof_type(&account.proof_type) || account.connector_id.is_some() {
        return Err("Browser account access requires a Runtime-managed account".to_string());
    }
    if text("principal_id")? != account.principal_id {
        return Err("Browser account access principal does not match selected account".to_string());
    }
    if text("session_id")? != input.session_id || text("launch_id")? != input.launch_id {
        return Err(
            "Browser account access session or launch authority does not match".to_string(),
        );
    }
    let proof_binding_id = text("proof_binding_id")?;
    validate_opaque_id(proof_binding_id, "proof_binding_id")?;
    if Some(proof_binding_id) != input.proof_binding_id.as_deref() {
        return Err("Browser account access proof binding does not match authority".to_string());
    }
    if text("account_id")? != account.account_id {
        return Err("Browser account access account does not match selected account".to_string());
    }
    let requested_payload_chain = text("requested_chain_namespace")?;
    if requested_payload_chain != input.chain_namespace
        || !chain_namespaces_compatible(&account.chain_namespace, requested_payload_chain)
    {
        return Err("Browser account access chain does not match selected account".to_string());
    }
    let chain_namespaces = object
        .get("chain_namespaces")
        .and_then(Value::as_array)
        .ok_or_else(|| "Browser account access chain_namespaces are missing".to_string())?;
    if chain_namespaces.len() != SUPPORTED_CHAIN_NAMESPACES.len()
        || !chain_namespaces
            .iter()
            .zip(SUPPORTED_CHAIN_NAMESPACES)
            .all(|(actual, expected)| actual.as_str() == Some(*expected))
        || !SUPPORTED_CHAIN_NAMESPACES.contains(&requested_payload_chain)
        || !SUPPORTED_CHAIN_NAMESPACES
            .iter()
            .all(|namespace| chain_namespaces_compatible(&account.chain_namespace, namespace))
    {
        return Err(
            "Browser account access chain_namespaces do not match the supported network set"
                .to_string(),
        );
    }
    if !text("address")?.eq_ignore_ascii_case(&account.address) {
        return Err("Browser account access address does not match selected account".to_string());
    }
    let origin = text("origin")?;
    let page_url = text("page_url")?;
    if origin.len() > 512
        || page_url.len() > 4096
        || !(origin.starts_with("https://") || origin.starts_with("http://"))
        || !(page_url.starts_with("https://") || page_url.starts_with("http://"))
        || origin.ends_with('/')
        || origin.chars().any(char::is_whitespace)
        || page_url.chars().any(char::is_whitespace)
        || !page_url.strip_prefix(origin).is_some_and(|suffix| {
            suffix.is_empty()
                || suffix.starts_with('/')
                || suffix.starts_with('?')
                || suffix.starts_with('#')
        })
    {
        return Err("Browser account access page URL or origin is invalid".to_string());
    }
    if object
        .get("requires_wallet_approval")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err("Browser account access must require wallet approval".to_string());
    }
    let grant_expires_at = object
        .get("grant_expires_at")
        .and_then(Value::as_u64)
        .ok_or_else(|| "Browser account access grant expiry is missing".to_string())?;
    if grant_expires_at <= now
        || grant_expires_at > now.saturating_add(MAX_BROWSER_ACCOUNT_ACCESS_TTL_SECS)
    {
        return Err(
            "Browser account access grant expiry is outside the allowed window".to_string(),
        );
    }
    Ok(())
}

fn validate_chain_outcome_target(
    request: &WalletApprovalRequest,
    authority: &WalletAuthorityV2,
    outcome: &ValidatedChainOutcomeV1,
) -> Result<(), String> {
    if request.principal_id != authority.principal_id
        || request.authority_binding != wallet_authority_binding(authority)
    {
        return Err("validated Chain outcome authority does not match the approval".to_string());
    }
    if request.request_id != outcome.approval_request_id
        || request.account_id != outcome.account_id
        || request.chain_namespace != outcome.chain_namespace
    {
        return Err("validated Chain outcome approval binding mismatch".to_string());
    }
    if request.status != ApprovalStatus::Completed || request.intent != "transaction_intent" {
        return Err(
            "validated Chain outcome requires a completed transaction approval".to_string(),
        );
    }
    let signed_result = request
        .signed_result
        .as_ref()
        .and_then(Value::as_object)
        .ok_or_else(|| "completed approval is missing its signed transaction result".to_string())?;
    if signed_result
        .get("transaction_hash")
        .and_then(Value::as_str)
        != Some(outcome.transaction_hash.as_str())
    {
        return Err("validated Chain outcome transaction hash mismatch".to_string());
    }
    if request
        .payload
        .get("network")
        .and_then(|network| network.get("id"))
        .and_then(Value::as_str)
        != Some(outcome.network.as_str())
    {
        return Err("validated Chain outcome network mismatch".to_string());
    }
    match &outcome.binding {
        ValidatedChainOutcomeBindingV1::ManagedSigned {
            signed_transaction_sha256,
        } => {
            if !is_managed_proof_type(&request.proof_type)
                || request.connector_id.is_some()
                || signed_result.get("schema").and_then(Value::as_str)
                    != Some("elastos.wallet.signed-transaction-result/v1")
            {
                return Err(
                    "validated managed Chain outcome requires a managed signed result".to_string(),
                );
            }
            let signed_transaction = signed_result
                .get("signed_transaction")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    "completed approval is missing its signed transaction".to_string()
                })?;
            if canonical_signed_transaction_sha256(signed_transaction)?
                != *signed_transaction_sha256
            {
                return Err(
                    "validated Chain outcome signed transaction digest mismatch".to_string()
                );
            }
        }
        ValidatedChainOutcomeBindingV1::ExternalConnector {
            connector_id,
            originating_address,
        } => {
            if request.connector_id.as_deref() != Some(connector_id.as_str())
                || !request.address.eq_ignore_ascii_case(originating_address)
                || signed_result.get("schema").and_then(Value::as_str)
                    != Some("elastos.wallet.external-transaction-result/v1")
                || signed_result.get("signed_transaction").is_some()
            {
                return Err(
                    "validated external Chain outcome connector binding mismatch".to_string(),
                );
            }
        }
    }
    if signed_result.get("request_id").and_then(Value::as_str) != Some(request.request_id.as_str())
        || signed_result.get("method").and_then(Value::as_str) != Some("eth_sendTransaction")
        || signed_result.get("chain_namespace").and_then(Value::as_str)
            != Some(request.chain_namespace.as_str())
        || !signed_result
            .get("signer")
            .and_then(Value::as_str)
            .is_some_and(|signer| signer.eq_ignore_ascii_case(&request.address))
        || signed_result.get("payload_hash").and_then(Value::as_str)
            != Some(request.payload_hash.as_str())
    {
        return Err("validated Chain outcome signed result binding mismatch".to_string());
    }
    validate_chain_observation_binding(outcome)
}

fn canonical_signed_transaction_sha256(signed_transaction: &str) -> Result<String, String> {
    let encoded = signed_transaction
        .strip_prefix("0x")
        .ok_or_else(|| "signed transaction must be 0x-prefixed".to_string())?;
    let bytes =
        hex::decode(encoded).map_err(|_| "signed transaction must be hexadecimal".to_string())?;
    if bytes.is_empty() {
        return Err("signed transaction must not be empty".to_string());
    }
    Ok(format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(bytes))
    ))
}

fn validate_chain_observation_binding(outcome: &ValidatedChainOutcomeV1) -> Result<(), String> {
    let observation = outcome
        .chain_observation
        .as_object()
        .ok_or_else(|| "validated Chain observation must be an object".to_string())?;
    if observation.get("network").and_then(Value::as_str) != Some(outcome.network.as_str()) {
        return Err("validated Chain observation network mismatch".to_string());
    }
    let outer_hash = observation
        .get("transaction_hash")
        .or_else(|| observation.get("hash"))
        .and_then(Value::as_str)
        .ok_or_else(|| "validated Chain observation is missing its transaction hash".to_string())?;
    if outer_hash != outcome.transaction_hash {
        return Err("validated Chain observation transaction hash mismatch".to_string());
    }
    if let Some(nested_hash) = observation
        .get("receipt")
        .and_then(|receipt| receipt.get("transactionHash"))
        .and_then(Value::as_str)
    {
        if nested_hash != outcome.transaction_hash {
            return Err("validated Chain receipt payload hash mismatch".to_string());
        }
    }
    if let Some(nested_hash) = observation
        .get("transaction")
        .and_then(|transaction| transaction.get("hash"))
        .and_then(Value::as_str)
    {
        if nested_hash != outcome.transaction_hash {
            return Err("validated Chain transaction payload hash mismatch".to_string());
        }
    }
    if let ValidatedChainOutcomeBindingV1::ExternalConnector {
        originating_address,
        ..
    } = &outcome.binding
    {
        let observed_from = observation
            .get("transaction")
            .and_then(Value::as_object)
            .and_then(|transaction| transaction.get("from"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                "validated external Chain observation is missing originating account".to_string()
            })?;
        if !observed_from.eq_ignore_ascii_case(originating_address) {
            return Err(
                "validated external Chain observation originating account mismatch".to_string(),
            );
        }
    }
    Ok(())
}

/// One unit test per refusal the approval state machine raises with a literal
/// message, each asserting the whole `Response::Error` value. They pin answers
/// the provider already gives: they add no rule, change no production line and
/// register no falsifier. They prove what the wallet provider answers an
/// approval call, not confinement: the Runtime decides whether the provider
/// runs.
///
/// Two strings this file raises are left out because an existing test already
/// scores the same rule by its code, so a second test would test one rule
/// twice: `Wallet approval identity was reused with substituted semantics or
/// authority` (`:35`, `:57`, `approval_identity_conflict`), held by
/// `request_approval_uses_the_runtime_request_identity_and_replays_exactly`
/// (`src/tests/v2_contract.rs:69`) and
/// `protected_content_rights_replays_exact_result_and_rejects_substitutions`
/// (`src/tests/approvals/protected_content.rs:583`); and `managed signing is
/// implemented only for Browser account access, personal_sign, typed data,
/// transaction, and Bitcoin BIP-322 intents` (`:184`, `:869`), held by
/// `managed_accounts_reject_unimplemented_intents_before_recording_authority`
/// (`src/tests/approvals/managed.rs:590`) and
/// `persisted_unsupported_managed_intent_cannot_reach_signing`
/// (`src/tests/approvals/managed.rs:628`).
#[cfg(test)]
mod uf_approval_refusal_tests {
    use super::*;
    use elastos_wallet_contract::{PublicNetwork, VerifiedWalletInvocationContext};
    use std::sync::atomic::{AtomicU64, Ordering};

    const PRINCIPAL: &str = "person:local:alice";
    const SESSION: &str = "session:alice";
    const EVM_CHAIN: &str = "eip155:20";
    const BITCOIN_CHAIN: &str = BITCOIN_MAINNET_CHAIN_NAMESPACE;
    /// A mainnet P2WPKH address, so this account is a Bitcoin account that
    /// signs with the `bip322_simple` proof type.
    const BITCOIN_ADDRESS: &str = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l";
    const EXTERNAL_ADDRESS: &str = "0x1111111111111111111111111111111111111111";
    const OTHER_ADDRESS: &str = "0x3333333333333333333333333333333333333333";
    const CONNECTOR: &str = "wallet-metamask";
    const OTHER_CONNECTOR: &str = "wallet-unisat";
    const OTHER_SESSION: &str = "session:other";
    /// An ordinary opaque id that names no stored approval.
    const MISSING_REQUEST_ID: &str = "wallet-request:ffffffffffffffffffffffffffffffff";
    const PAYLOAD_HASH: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
    const REASON: &str = "Review the exact request";

    static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

    fn request_id() -> String {
        format!(
            "wallet-request:{:032x}",
            NEXT_REQUEST.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn init_provider() -> (tempfile::TempDir, WalletProvider) {
        let dir = tempfile::tempdir().expect("test storage root");
        let mut provider = WalletProvider::new();
        let response = provider.init(json!({ "base_path": dir.path().display().to_string() }));
        assert!(
            matches!(response, Response::Ok { .. }),
            "init must succeed, got {response:?}"
        );
        (dir, provider)
    }

    fn error(code: &str, message: &str) -> Response {
        Response::Error {
            code: code.to_string(),
            message: message.to_string(),
        }
    }

    fn managed_account(provider: &mut WalletProvider) -> (String, String) {
        match provider.create_managed_account(CreateManagedAccountInput {
            principal_id: PRINCIPAL.to_string(),
            chain_namespace: EVM_CHAIN.to_string(),
            label: None,
            create_new: false,
        }) {
            Response::Ok { data: Some(data) } => (
                data["account"]["account_id"]
                    .as_str()
                    .expect("managed account id")
                    .to_string(),
                data["account"]["address"]
                    .as_str()
                    .expect("managed account address")
                    .to_string(),
            ),
            other => panic!("expected a managed account, got {other:?}"),
        }
    }

    /// Links an external EVM account under the test connector, so an approval
    /// on it needs a typed connector handoff rather than managed signing.
    fn linked_external_account(provider: &mut WalletProvider) -> (String, String) {
        let response = provider.link_account(LinkAccountInput {
            principal_id: PRINCIPAL.to_string(),
            proof_binding_id: format!("proof:{EVM_CHAIN}:{EXTERNAL_ADDRESS}"),
            chain_namespace: EVM_CHAIN.to_string(),
            address: EXTERNAL_ADDRESS.to_string(),
            proof_type: "siwe".to_string(),
            connector_id: Some(CONNECTOR.to_string()),
            label: None,
        });
        assert!(
            matches!(response, Response::Ok { .. }),
            "link must succeed, got {response:?}"
        );
        (
            account_id(EVM_CHAIN, EXTERNAL_ADDRESS),
            EXTERNAL_ADDRESS.to_string(),
        )
    }

    fn personal_sign_payload(account_id: &str, address: &str) -> Value {
        json!({
            "schema": "elastos.browser.wallet-signature-request/v1",
            "method": "personal_sign",
            "params": [REASON, address],
            "message": REASON,
            "address": address,
            "account_id": account_id,
            "chain_namespace": EVM_CHAIN,
            "page_url": "https://dapp.example/sign",
            "origin": "https://dapp.example",
            "requires_wallet_approval": true
        })
    }

    fn transaction_payload(from: &str) -> Value {
        json!({
            "schema": "elastos.chain.unsigned_transaction_intent/v1",
            "transaction_type": "eip155_legacy",
            "from": from,
            "to": "0x2222222222222222222222222222222222222222",
            "value": "0x0",
            "data": "0x",
            "chain_id": 20,
            "nonce": "0x7",
            "gas_price": "0x3b9aca00",
            "gas_limit": "0x5208",
            "requires_wallet_approval": true,
            "wallet_intent": "transaction_intent"
        })
    }

    fn signature_request(
        request_id: &str,
        account_id: &str,
        chain_namespace: &str,
        intent: &str,
        payload: Value,
    ) -> SignatureRequestInput {
        SignatureRequestInput {
            request_id: request_id.to_string(),
            wallet_request_sha256: "wallet-request-sha256:test".to_string(),
            authority_binding: format!("0x{}", "11".repeat(32)),
            principal_id: PRINCIPAL.to_string(),
            session_id: SESSION.to_string(),
            launch_id: "launch:browser".to_string(),
            proof_binding_id: None,
            account_id: account_id.to_string(),
            chain_namespace: chain_namespace.to_string(),
            intent: intent.to_string(),
            requested_by_actor: "browser".to_string(),
            resource: "elastos://wallet/eip155:20/sign/browser_personal_sign".to_string(),
            reason: REASON.to_string(),
            payload,
            expires_at: now_ts().saturating_add(APPROVAL_REQUEST_TTL_SECS),
        }
    }

    /// Records one approval through the provider's own call and answers its id.
    fn stored_approval(provider: &mut WalletProvider, account_id: &str, address: &str) -> String {
        let request_id = request_id();
        let response = provider.request_approval(signature_request(
            &request_id,
            account_id,
            EVM_CHAIN,
            "browser_personal_sign",
            personal_sign_payload(account_id, address),
        ));
        assert!(
            matches!(response, Response::Ok { .. }),
            "the approval must be recorded, got {response:?}"
        );
        request_id
    }

    fn index_of(provider: &WalletProvider, request_id: &str) -> usize {
        provider
            .store
            .approval_requests
            .iter()
            .position(|request| request.request_id == request_id)
            .unwrap_or_else(|| panic!("approval {request_id} must be stored"))
    }

    fn stored_payload_hash(provider: &WalletProvider, request_id: &str) -> String {
        provider.store.approval_requests[index_of(provider, request_id)]
            .payload_hash
            .clone()
    }

    fn approve_handoff(provider: &mut WalletProvider, request_id: &str) {
        let response = provider
            .approve_connector_handoff(PRINCIPAL, SESSION, CONNECTOR, request_id, "Approve");
        assert!(
            matches!(response, Response::Ok { .. }),
            "the connector handoff must be approved, got {response:?}"
        );
    }

    fn completion<'a>(
        request_id: &'a str,
        payload_hash: &'a str,
        signer: &'a str,
    ) -> ConnectorHandoffCompletion<'a> {
        ConnectorHandoffCompletion {
            principal_id: PRINCIPAL,
            session_id: SESSION,
            request_id,
            connector_id: CONNECTOR,
            payload_hash,
            signature: Some("0x1234abcd"),
            signature_type: Some("personal_sign"),
            public_key: None,
            signer,
            transaction_hash: None,
        }
    }

    /// One string, raised by the protected-content replay arm (`:69`) when the
    /// stored `signed_result` does not parse as
    /// `ProtectedContentRightsSignatureResultV1`. It is driven through
    /// `idempotent_transaction_effect_replay` (`:17`), because repeating
    /// `request_approval` appends a second record and never reaches the replay.
    ///
    /// The record is the provider's own: `request_approval` wrote it, and only
    /// its identity fields name the later rights request, so the replay's
    /// identity checks pass and the stored-result reader is the guard under
    /// test.
    ///
    /// Catches removal of that reader: without it a stored result of any shape
    /// is replayed to the caller as the signed rights result.
    #[test]
    fn approval_refuses_invalid_stored_rights_result() {
        let (_dir, mut provider) = init_provider();
        let (account_id, address) = managed_account(&mut provider);
        let context = VerifiedWalletInvocationContext::new(
            PRINCIPAL,
            SESSION,
            None,
            "grant:test",
            "library",
            "launch:library",
        )
        .expect("test Wallet authority must be valid");
        let now = now_ts();
        let request = WalletProviderRequestV2::new(
            &context,
            request_id(),
            now,
            now.saturating_add(120),
            WalletProviderOperationV2::RequestProtectedContentRightsSignature {
                account_id: account_id.clone(),
                canonical_rights_request_hex: "00".to_string(),
                reason: REASON.to_string(),
            },
        )
        .expect("test rights request must build");
        let recorded = provider.request_approval(SignatureRequestInput {
            request_id: request.request_id.clone(),
            wallet_request_sha256: request.request_sha256.clone(),
            authority_binding: wallet_authority_binding(&request.authority),
            principal_id: request.authority.principal_id.clone(),
            session_id: request.authority.session_id.clone(),
            launch_id: request.authority.launch_id.clone(),
            proof_binding_id: request.authority.proof_binding_id.clone(),
            account_id: account_id.clone(),
            chain_namespace: EVM_CHAIN.to_string(),
            intent: "browser_personal_sign".to_string(),
            requested_by_actor: "library".to_string(),
            resource: "elastos://wallet/protected-content/rights/sign".to_string(),
            reason: REASON.to_string(),
            payload: personal_sign_payload(&account_id, &address),
            expires_at: now.saturating_add(APPROVAL_REQUEST_TTL_SECS),
        });
        assert!(
            matches!(recorded, Response::Ok { .. }),
            "the approval must be recorded, got {recorded:?}"
        );
        provider.store.approval_requests[0].signed_result =
            Some(json!({ "schema": "elastos.wallet.unrelated/v1" }));

        assert_eq!(
            provider.idempotent_transaction_effect_replay(&request),
            Some(error(
                "signing_error",
                "stored protected-content rights result is invalid"
            ))
        );
    }

    /// Catches removal of the Bitcoin intent guard (`:192`): without it a
    /// Bitcoin account records an approval for an intent it cannot sign.
    #[test]
    fn approval_refuses_non_bitcoin_intent_for_bitcoin_account() {
        let (_dir, mut provider) = init_provider();
        let response = provider.link_account(LinkAccountInput {
            principal_id: PRINCIPAL.to_string(),
            proof_binding_id: format!("proof:{BITCOIN_CHAIN}:{BITCOIN_ADDRESS}"),
            chain_namespace: BITCOIN_CHAIN.to_string(),
            address: BITCOIN_ADDRESS.to_string(),
            proof_type: "bip322_simple".to_string(),
            connector_id: Some(OTHER_CONNECTOR.to_string()),
            label: None,
        });
        assert!(
            matches!(response, Response::Ok { .. }),
            "link must succeed, got {response:?}"
        );
        let account_id = account_id(BITCOIN_CHAIN, BITCOIN_ADDRESS);
        assert_eq!(
            provider.request_approval(signature_request(
                &request_id(),
                &account_id,
                BITCOIN_CHAIN,
                "browser_personal_sign",
                json!({ "message": REASON }),
            )),
            error(
                "invalid_request",
                "Bitcoin accounts only support bitcoin_bip322_proof signing"
            )
        );
    }

    /// Catches removal of the Bitcoin account guard (`:238`): without it a
    /// Bitcoin proof approval is recorded against an EVM account, whose key
    /// cannot produce the proof.
    #[test]
    fn approval_refuses_bitcoin_proof_without_a_bitcoin_account() {
        let (_dir, mut provider) = init_provider();
        let (account_id, _) = managed_account(&mut provider);
        assert_eq!(
            provider.request_approval(signature_request(
                &request_id(),
                &account_id,
                EVM_CHAIN,
                "bitcoin_bip322_proof",
                json!({ "message": REASON }),
            )),
            error(
                "invalid_request",
                "Bitcoin proof signing requires a supported Bitcoin account"
            )
        );
    }

    /// One string, raised at six reachable sites: `attach_validated_chain_outcome`
    /// (`:321`), `reject_approval` (`:398`), `approve_connector_handoff`
    /// (`:456`), `approve_and_sign_managed` (`:520`),
    /// `complete_connector_handoff` (`:578`) and `sign_managed_approval`
    /// (`:849`). This test drives all six, so no site is left to a caller.
    ///
    /// The seventh site, `:940`, is a second lookup inside
    /// `sign_managed_approval` after it found the same record at `:842`.
    /// Nothing between those two reads changes the store, and `prune_store`
    /// retains a record whose status is `Approved` and whose `expires_at` is
    /// ahead (`src/storage.rs:233`), so no call can reach it. It is recorded
    /// here rather than forced.
    ///
    /// Catches removal of any of the six lookups: without one, a call answers a
    /// request id that was never recorded as if it had been.
    #[test]
    fn approval_refuses_missing_request() {
        let (_dir, mut provider) = init_provider();
        let expected = error("not_found", "wallet approval request not found");
        let authority = WalletAuthorityV2 {
            principal_id: PRINCIPAL.to_string(),
            session_id: SESSION.to_string(),
            proof_binding_id: None,
            grant_id: "grant:test".to_string(),
            actor: CONNECTOR.to_string(),
            launch_id: "launch:browser".to_string(),
            capability: "wallet:transaction:project-chain-outcome".to_string(),
            intent: "wallet.transaction.chain-outcome.attach".to_string(),
        };
        let outcome = ValidatedChainOutcomeV1 {
            schema: "elastos.wallet.validated-chain-outcome/v1".to_string(),
            approval_request_id: MISSING_REQUEST_ID.to_string(),
            account_id: account_id(EVM_CHAIN, EXTERNAL_ADDRESS),
            chain_namespace: EVM_CHAIN.to_string(),
            network: PublicNetwork::new("esc-local").expect("test network"),
            binding: ValidatedChainOutcomeBindingV1::ManagedSigned {
                signed_transaction_sha256: format!("0x{}", "22".repeat(32)),
            },
            transaction_hash: format!("0x{}", "33".repeat(32)),
            chain_observation: json!({}),
            confirmed_at: now_ts(),
        };

        assert_eq!(
            provider.attach_validated_chain_outcome(&authority, &outcome),
            expected
        );
        assert_eq!(
            provider.reject_approval(PRINCIPAL, SESSION, "library", MISSING_REQUEST_ID, "No"),
            expected
        );
        assert_eq!(
            provider.approve_connector_handoff(
                PRINCIPAL,
                SESSION,
                CONNECTOR,
                MISSING_REQUEST_ID,
                "Approve"
            ),
            expected
        );
        assert_eq!(
            provider.approve_and_sign_managed(PRINCIPAL, SESSION, MISSING_REQUEST_ID, "Approve"),
            expected
        );
        assert_eq!(
            provider.complete_connector_handoff(completion(
                MISSING_REQUEST_ID,
                PAYLOAD_HASH,
                OTHER_ADDRESS
            )),
            expected
        );
        assert_eq!(
            provider.sign_managed_approval(PRINCIPAL, MISSING_REQUEST_ID),
            expected
        );
    }

    /// One string, raised at three sites: `reject_approval` (`:403`),
    /// `approve_connector_handoff` (`:461`) and `complete_connector_handoff`
    /// (`:595`). This test drives all three with an approval the provider
    /// recorded in this session and a call from another session.
    ///
    /// Catches removal of any of the three session checks: without one, a
    /// Runtime session settles an approval another session recorded.
    #[test]
    fn approval_refuses_request_from_another_runtime_session() {
        let (_dir, mut provider) = init_provider();
        let (account_id, address) = linked_external_account(&mut provider);
        let expected = error(
            "invalid_request",
            "wallet approval request belongs to a different Runtime session",
        );

        let rejected = stored_approval(&mut provider, &account_id, &address);
        assert_eq!(
            provider.reject_approval(PRINCIPAL, OTHER_SESSION, "library", &rejected, "No"),
            expected
        );

        let approved = stored_approval(&mut provider, &account_id, &address);
        assert_eq!(
            provider.approve_connector_handoff(
                PRINCIPAL,
                OTHER_SESSION,
                CONNECTOR,
                &approved,
                "Approve"
            ),
            expected
        );

        let completed = stored_approval(&mut provider, &account_id, &address);
        approve_handoff(&mut provider, &completed);
        let payload_hash = stored_payload_hash(&provider, &completed);
        let mut handoff = completion(&completed, &payload_hash, &address);
        handoff.session_id = OTHER_SESSION;
        assert_eq!(provider.complete_connector_handoff(handoff), expected);
    }

    /// One string, raised at two sites: `reject_approval` (`:409`) and
    /// `complete_connector_handoff` (`:601`). This test drives both with an
    /// approval the provider bound to one connector and a call from another.
    ///
    /// Catches removal of either connector check: without one, a second wallet
    /// connector settles an approval the first connector requested.
    #[test]
    fn approval_refuses_request_from_another_connector() {
        let (_dir, mut provider) = init_provider();
        let (account_id, address) = linked_external_account(&mut provider);
        let expected = error(
            "invalid_request",
            "wallet approval request belongs to a different connector",
        );

        let rejected = stored_approval(&mut provider, &account_id, &address);
        assert_eq!(
            provider.reject_approval(PRINCIPAL, SESSION, OTHER_CONNECTOR, &rejected, "No"),
            expected
        );

        let completed = stored_approval(&mut provider, &account_id, &address);
        approve_handoff(&mut provider, &completed);
        let payload_hash = stored_payload_hash(&provider, &completed);
        let mut handoff = completion(&completed, &payload_hash, &address);
        handoff.connector_id = OTHER_CONNECTOR;
        assert_eq!(provider.complete_connector_handoff(handoff), expected);
    }

    /// Catches removal of the managed session check (`:532`): without it a
    /// second Runtime session approves and signs a managed wallet approval the
    /// first session requested.
    #[test]
    fn approval_refuses_managed_request_from_another_runtime_session() {
        let (_dir, mut provider) = init_provider();
        let (account_id, address) = managed_account(&mut provider);
        let request_id = stored_approval(&mut provider, &account_id, &address);
        assert_eq!(
            provider.approve_and_sign_managed(PRINCIPAL, OTHER_SESSION, &request_id, "Approve"),
            error(
                "invalid_request",
                "managed Wallet approval belongs to a different Runtime session"
            )
        );
    }

    /// Catches removal of the connector handoff guard (`:536`): without it the
    /// managed approve-and-sign path signs for a connector account, so the
    /// connector never supplies the signature that account requires.
    #[test]
    fn approval_refuses_managed_signing_for_connector_request() {
        let (_dir, mut provider) = init_provider();
        let (account_id, address) = linked_external_account(&mut provider);
        let request_id = stored_approval(&mut provider, &account_id, &address);
        assert_eq!(
            provider.approve_and_sign_managed(PRINCIPAL, SESSION, &request_id, "Approve"),
            error(
                "external_wallet_required",
                "connector approvals require a typed connector handoff"
            )
        );
    }

    /// `:610`, the `invalid_request` site. The `invalid_signature` sites at
    /// `:725` and `:794` raise the same text under a different code and are
    /// held by `src/tests/approvals/external.rs:462`, so they are not repeated
    /// here.
    ///
    /// Catches removal of the signer check: without it a connector completes an
    /// approval with a signature from an address the review never named.
    #[test]
    fn approval_refuses_connector_completion_with_another_signer() {
        let (_dir, mut provider) = init_provider();
        let (account_id, address) = linked_external_account(&mut provider);
        let request_id = stored_approval(&mut provider, &account_id, &address);
        approve_handoff(&mut provider, &request_id);
        let payload_hash = stored_payload_hash(&provider, &request_id);
        assert_eq!(
            provider.complete_connector_handoff(completion(
                &request_id,
                &payload_hash,
                OTHER_ADDRESS
            )),
            error("invalid_request", "wallet signature signer mismatch")
        );
    }

    /// Catches removal of the transaction signature exclusion (`:615`): without
    /// it a connector reports a signature for a transaction approval, so the
    /// settlement reads a signature the chain never produced.
    #[test]
    fn approval_refuses_transaction_completion_with_signature() {
        let (_dir, mut provider) = init_provider();
        let (account_id, address) = linked_external_account(&mut provider);
        let request_id = request_id();
        let recorded = provider.request_approval(signature_request(
            &request_id,
            &account_id,
            EVM_CHAIN,
            "transaction_intent",
            transaction_payload(&address),
        ));
        assert!(
            matches!(recorded, Response::Ok { .. }),
            "the approval must be recorded, got {recorded:?}"
        );
        approve_handoff(&mut provider, &request_id);
        let payload_hash = stored_payload_hash(&provider, &request_id);
        assert_eq!(
            provider.complete_connector_handoff(completion(&request_id, &payload_hash, &address)),
            error(
                "invalid_request",
                "external transaction completion must not include signature"
            )
        );
    }

    /// Catches removal of the transaction hash guard (`:621`): without it a
    /// transaction approval completes with no transaction, so the record names
    /// a broadcast that no hash identifies.
    #[test]
    fn approval_refuses_transaction_completion_without_hash() {
        let (_dir, mut provider) = init_provider();
        let (account_id, address) = linked_external_account(&mut provider);
        let request_id = request_id();
        let recorded = provider.request_approval(signature_request(
            &request_id,
            &account_id,
            EVM_CHAIN,
            "transaction_intent",
            transaction_payload(&address),
        ));
        assert!(
            matches!(recorded, Response::Ok { .. }),
            "the approval must be recorded, got {recorded:?}"
        );
        approve_handoff(&mut provider, &request_id);
        let payload_hash = stored_payload_hash(&provider, &request_id);
        let mut handoff = completion(&request_id, &payload_hash, &address);
        handoff.signature = None;
        handoff.signature_type = None;
        assert_eq!(
            provider.complete_connector_handoff(handoff),
            error(
                "invalid_request",
                "external transaction completion requires transaction_hash"
            )
        );
    }

    /// One string, raised at two sites: the Bitcoin proof branch (`:641`) and
    /// the signature branch every other intent takes (`:757`). This test drives
    /// both. The Bitcoin case reaches its branch by moving the recorded intent
    /// after approval, because a Bitcoin approval at request time needs a stored
    /// challenge this test does not own.
    ///
    /// Catches removal of either signature guard: without one a connector
    /// completes an approval that names a signature while carrying none.
    #[test]
    fn approval_refuses_signature_completion_without_signature() {
        let (_dir, mut provider) = init_provider();
        let (account_id, address) = linked_external_account(&mut provider);
        let expected = error(
            "invalid_request",
            "external signature completion requires signature",
        );

        let bitcoin = stored_approval(&mut provider, &account_id, &address);
        approve_handoff(&mut provider, &bitcoin);
        let bitcoin_index = index_of(&provider, &bitcoin);
        provider.store.approval_requests[bitcoin_index].intent = "bitcoin_bip322_proof".to_string();
        let bitcoin_hash = stored_payload_hash(&provider, &bitcoin);
        let mut handoff = completion(&bitcoin, &bitcoin_hash, &address);
        handoff.signature = None;
        handoff.signature_type = None;
        assert_eq!(provider.complete_connector_handoff(handoff), expected);

        let generic = request_id();
        let recorded = provider.request_approval(signature_request(
            &generic,
            &account_id,
            EVM_CHAIN,
            "auth_challenge",
            json!({ "challenge": REASON }),
        ));
        assert!(
            matches!(recorded, Response::Ok { .. }),
            "the approval must be recorded, got {recorded:?}"
        );
        approve_handoff(&mut provider, &generic);
        let generic_hash = stored_payload_hash(&provider, &generic);
        let mut handoff = completion(&generic, &generic_hash, &address);
        handoff.signature = None;
        handoff.signature_type = None;
        assert_eq!(provider.complete_connector_handoff(handoff), expected);
    }

    /// Catches removal of the rights signature guard (`:686`): without it a
    /// protected-content rights approval completes with no signature, so the
    /// content is released against a record that proves nothing.
    ///
    /// The recorded intent is moved after approval, because a rights approval
    /// at request time needs a canonical rights request this test does not own.
    #[test]
    fn approval_refuses_rights_completion_without_signature() {
        let (_dir, mut provider) = init_provider();
        let (account_id, address) = linked_external_account(&mut provider);
        let request_id = stored_approval(&mut provider, &account_id, &address);
        approve_handoff(&mut provider, &request_id);
        let index = index_of(&provider, &request_id);
        provider.store.approval_requests[index].intent =
            PROTECTED_CONTENT_RIGHTS_SIGNATURE_INTENT.to_string();
        let payload_hash = stored_payload_hash(&provider, &request_id);
        let mut handoff = completion(&request_id, &payload_hash, &address);
        handoff.signature = None;
        handoff.signature_type = None;
        assert_eq!(
            provider.complete_connector_handoff(handoff),
            error(
                "invalid_request",
                "external protected-content rights completion requires signature"
            )
        );
    }

    /// Catches removal of the personal_sign requirement (`:695`): without it a
    /// rights approval completes with another signature type, so the bytes the
    /// signer signed are not the canonical rights request.
    ///
    /// The recorded intent is moved after approval, as in
    /// `approval_refuses_rights_completion_without_signature`.
    #[test]
    fn approval_refuses_rights_completion_with_another_signature_type() {
        let (_dir, mut provider) = init_provider();
        let (account_id, address) = linked_external_account(&mut provider);
        let request_id = stored_approval(&mut provider, &account_id, &address);
        approve_handoff(&mut provider, &request_id);
        let index = index_of(&provider, &request_id);
        provider.store.approval_requests[index].intent =
            PROTECTED_CONTENT_RIGHTS_SIGNATURE_INTENT.to_string();
        let payload_hash = stored_payload_hash(&provider, &request_id);
        let mut handoff = completion(&request_id, &payload_hash, &address);
        handoff.signature_type = Some("eth_sign");
        assert_eq!(
            provider.complete_connector_handoff(handoff),
            error(
                "invalid_request",
                "protected-content rights completion requires personal_sign"
            )
        );
    }

    /// Catches removal of the approved-state guard (`:854`): without it managed
    /// signing runs on a pending approval, so the key signs a request the user
    /// never reviewed.
    #[test]
    fn approval_refuses_managed_signing_before_approval() {
        let (_dir, mut provider) = init_provider();
        let (account_id, address) = managed_account(&mut provider);
        let request_id = stored_approval(&mut provider, &account_id, &address);
        assert_eq!(
            provider.sign_managed_approval(PRINCIPAL, &request_id),
            error(
                "invalid_request",
                "wallet approval request must be approved before managed signing"
            )
        );
    }

    /// Catches removal of the reviewed-payload check (`:860`): without it the
    /// key signs whatever the record holds now, not the payload the approval
    /// hash covers.
    #[test]
    fn approval_refuses_managed_signing_after_payload_change() {
        let (_dir, mut provider) = init_provider();
        let (account_id, address) = managed_account(&mut provider);
        let request_id = stored_approval(&mut provider, &account_id, &address);
        let index = index_of(&provider, &request_id);
        provider.store.approval_requests[index].status = ApprovalStatus::Approved;
        provider.store.approval_requests[index].approved_at = Some(now_ts());
        provider.store.approval_requests[index].payload = json!({ "message": "substituted" });
        assert_eq!(
            provider.sign_managed_approval(PRINCIPAL, &request_id),
            error(
                "signing_error",
                "wallet approval payload no longer matches the reviewed payload hash"
            )
        );
    }

    /// Catches removal of the managed proof type guard (`:879`): without it the
    /// managed path signs for an account that requires an external wallet, so
    /// the external signer never supplies the signature.
    #[test]
    fn approval_refuses_managed_signing_for_external_account() {
        let (_dir, mut provider) = init_provider();
        let (account_id, address) = managed_account(&mut provider);
        let request_id = stored_approval(&mut provider, &account_id, &address);
        let index = index_of(&provider, &request_id);
        provider.store.approval_requests[index].status = ApprovalStatus::Approved;
        provider.store.approval_requests[index].approved_at = Some(now_ts());
        let account_index = provider
            .store
            .accounts
            .iter()
            .position(|account| account.account_id == account_id)
            .expect("the account must be stored");
        provider.store.accounts[account_index].proof_type = "siwe".to_string();
        assert_eq!(
            provider.sign_managed_approval(PRINCIPAL, &request_id),
            error(
                "external_wallet_required",
                "approved request requires an external wallet signature handoff"
            )
        );
    }

    /// Catches removal of the managed authority comparison (`:885`): without it
    /// the key signs for the account record while the approval names another
    /// address, so the signature settles under authority the review never saw.
    #[test]
    fn approval_refuses_managed_signing_after_authority_change() {
        let (_dir, mut provider) = init_provider();
        let (account_id, address) = managed_account(&mut provider);
        let request_id = stored_approval(&mut provider, &account_id, &address);
        let index = index_of(&provider, &request_id);
        provider.store.approval_requests[index].status = ApprovalStatus::Approved;
        provider.store.approval_requests[index].approved_at = Some(now_ts());
        provider.store.approval_requests[index].address = OTHER_ADDRESS.to_string();
        assert_eq!(
            provider.sign_managed_approval(PRINCIPAL, &request_id),
            error(
                "signing_error",
                "wallet approval authority no longer matches its managed account"
            )
        );
    }
}
