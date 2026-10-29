use super::super::support::*;
use super::super::*;

#[test]
fn managed_account_signs_eip155_transaction_intent_after_runtime_approval() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let principal_id = "person:local:alice";
    let (account_id, address) = match invoke_wallet(
        &mut provider,
        principal_id,
        "wallet",
        WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".into(),
            label: None,
            create_new: false,
        },
    ) {
        Response::Ok { data: Some(data) } => (
            data["account"]["account_id"].as_str().unwrap().to_string(),
            data["account"]["address"].as_str().unwrap().to_string(),
        ),
        other => panic!("expected managed account, got {other:?}"),
    };
    let mut payload = transaction_intent_payload(&address);
    payload["page_url"] = json!("https://ela.city/cinema/view/test");
    payload["origin"] = json!("https://ela.city");
    payload["network"] = json!({ "id": "esc-mainnet" });
    let request_id = match invoke_wallet(
        &mut provider,
        principal_id,
        "system",
        WalletProviderOperationV2::RequestApproval {
            account_id,
            chain_namespace: "eip155:20".into(),
            intent: "transaction_intent".into(),
            resource: "elastos://chain/esc-mainnet/broadcast_transaction".into(),
            reason: "Send EVM transaction".into(),
            payload,
            expires_at: now_ts().saturating_add(APPROVAL_REQUEST_TTL_SECS),
        },
    ) {
        Response::Ok { data: Some(data) } => {
            let approval = &data["approval_request"];
            assert_eq!(approval["intent"], "transaction_intent");
            assert_eq!(approval["status"], "pending");
            approval["request_id"].as_str().unwrap().to_string()
        }
        other => panic!("expected transaction approval request, got {other:?}"),
    };
    let signed_transaction_hash = match invoke_wallet(
        &mut provider,
        principal_id,
        "system",
        WalletProviderOperationV2::ApproveAndSignManaged {
            request_id: request_id.clone(),
            reason: "Approved transaction".to_string(),
        },
    ) {
        Response::Ok { data: Some(data) } => {
            assert_eq!(data["approval_request"]["status"], "completed");
            assert!(data["signed_transaction"]
                .as_str()
                .is_some_and(|value| value.starts_with("0x")));
            assert_eq!(
                data["approval_request"]["signed_result"]["page_url"],
                "https://ela.city/cinema/view/test"
            );
            assert_eq!(
                data["approval_request"]["signed_result"]["origin"],
                "https://ela.city"
            );
            assert!(data["approval_request"]["signed_result"]
                .get("broadcast_recorded_at")
                .is_none());
            data["approval_request"]["signed_result"]["transaction_hash"]
                .as_str()
                .expect("signed transaction hash")
                .to_string()
        }
        other => panic!("expected atomic managed transaction signature, got {other:?}"),
    };
    match invoke_wallet(
        &mut provider,
        principal_id,
        "wallet",
        WalletProviderOperationV2::ListApprovals {
            include_resolved: true,
        },
    ) {
        Response::Ok { data: Some(data) } => {
            let requests = data["approval_requests"].as_array().unwrap();
            assert!(requests.iter().any(|request| {
                request["request_id"] == request_id
                    && request["status"] == "completed"
                    && request["signed_result"]["transaction_hash"] == signed_transaction_hash
            }));
        }
        other => panic!("expected approval history with signed transaction hash, got {other:?}"),
    }
}

/// Completes one managed `eip155:20` transaction approval through the
/// provider's own calls — create the account, request the approval, sign it —
/// and returns the exact `ValidatedChainOutcomeV1` those records accept, plus
/// the signer address. The outcome carries the account id, approval request
/// id, transaction hash and signed-transaction digest, so the Chain-outcome
/// tests clone one value and change one field instead of repeating this setup
/// (P10).
fn completed_managed_transaction_approval(
    provider: &mut WalletProvider,
) -> (ValidatedChainOutcomeV1, String) {
    let principal_id = "person:local:alice";
    let (account_id, address) = match invoke_wallet(
        provider,
        principal_id,
        "wallet",
        WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".into(),
            label: None,
            create_new: false,
        },
    ) {
        Response::Ok { data: Some(data) } => (
            data["account"]["account_id"].as_str().unwrap().to_string(),
            data["account"]["address"].as_str().unwrap().to_string(),
        ),
        other => panic!("expected managed account, got {other:?}"),
    };
    let mut payload = transaction_intent_payload(&address);
    payload["network"] = json!({ "id": "esc-mainnet" });
    let request_id = match invoke_wallet(
        provider,
        principal_id,
        "system",
        WalletProviderOperationV2::RequestApproval {
            account_id: account_id.clone(),
            chain_namespace: "eip155:20".into(),
            intent: "transaction_intent".into(),
            resource: "elastos://chain/esc-mainnet/broadcast_transaction".into(),
            reason: "Send EVM transaction".into(),
            payload,
            expires_at: now_ts().saturating_add(APPROVAL_REQUEST_TTL_SECS),
        },
    ) {
        Response::Ok { data: Some(data) } => data["approval_request"]["request_id"]
            .as_str()
            .unwrap()
            .to_string(),
        other => panic!("expected transaction approval request, got {other:?}"),
    };
    let (signed_transaction, transaction_hash) = match invoke_wallet(
        provider,
        principal_id,
        "system",
        WalletProviderOperationV2::ApproveAndSignManaged {
            request_id: request_id.clone(),
            reason: "Approved transaction".into(),
        },
    ) {
        Response::Ok { data: Some(data) } => (
            data["signed_transaction"].as_str().unwrap().to_string(),
            data["approval_request"]["signed_result"]["transaction_hash"]
                .as_str()
                .unwrap()
                .to_string(),
        ),
        other => panic!("expected managed transaction signature, got {other:?}"),
    };
    let signed_bytes = hex::decode(signed_transaction.trim_start_matches("0x")).unwrap();
    let outcome = ValidatedChainOutcomeV1 {
        schema: elastos_wallet_contract::VALIDATED_CHAIN_OUTCOME_SCHEMA.to_string(),
        approval_request_id: request_id,
        account_id,
        chain_namespace: "eip155:20".into(),
        network: elastos_wallet_contract::PublicNetwork::new("esc-mainnet").unwrap(),
        binding: ValidatedChainOutcomeBindingV1::ManagedSigned {
            signed_transaction_sha256: format!(
                "sha256:{}",
                hex::encode(sha2::Sha256::digest(signed_bytes))
            ),
        },
        transaction_hash: transaction_hash.clone(),
        chain_observation: json!({
            "schema": "elastos.chain.broadcast_receipt/v1",
            "network": "esc-mainnet",
            "transaction_hash": transaction_hash,
        }),
        confirmed_at: now_ts(),
    };
    (outcome, address)
}

#[test]
fn validated_chain_outcome_projection_is_exact_and_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let principal_id = "person:local:alice";
    let (outcome, _address) = completed_managed_transaction_approval(&mut provider);

    for _ in 0..2 {
        match invoke_wallet(
            &mut provider,
            principal_id,
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome {
                outcome: outcome.clone(),
            },
        ) {
            Response::Ok { data: Some(data) } => {
                assert_eq!(
                    data["approval_request"]["validated_chain_outcome"],
                    serde_json::to_value(&outcome).unwrap()
                );
            }
            other => panic!("expected idempotent Chain outcome projection, got {other:?}"),
        }
    }

    let mut substituted = outcome.clone();
    substituted.chain_observation["status"] = json!("substituted");
    assert!(matches!(
        invoke_wallet(
            &mut provider,
            principal_id,
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome {
                outcome: substituted,
            },
        ),
        Response::Error { ref code, .. } if code == "chain_outcome_conflict"
    ));

    let mut substituted = outcome;
    substituted.account_id = "wallet-account:substituted".into();
    assert!(matches!(
        invoke_wallet(
            &mut provider,
            principal_id,
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome {
                outcome: substituted,
            },
        ),
        Response::Error { ref code, .. } if code == "chain_outcome_conflict"
    ));
}

/// Completes one external `wallet-metamask` `eip155:20` transaction approval
/// through the provider's own calls — link the verified account, request the
/// approval, approve the connector handoff, complete it — and returns the exact
/// `ValidatedChainOutcomeV1` those records accept. The assertions of the
/// external sequence stay here, so the Chain-outcome tests reuse one way to
/// reach a completed external approval (P10).
fn completed_external_transaction_approval(
    provider: &mut WalletProvider,
) -> ValidatedChainOutcomeV1 {
    let principal_id = "person:local:alice";
    let external_address = "0x3333333333333333333333333333333333333333";
    let external_account_id = format!("wallet:eip155:20:{external_address}");
    assert!(matches!(
        invoke_wallet(
            provider,
            principal_id,
            "wallet-metamask",
            WalletProviderOperationV2::LinkVerifiedAccount {
                proof_binding_id: format!("proof:eip155:20:{external_address}"),
                chain_namespace: "eip155:20".into(),
                address: external_address.into(),
                proof_type: "siwe".into(),
                label: None,
            },
        ),
        Response::Ok { .. }
    ));
    let mut external_payload = transaction_intent_payload(external_address);
    external_payload["page_url"] = json!("https://ela.city/cinema/view/test");
    external_payload["origin"] = json!("https://ela.city");
    external_payload["network"] = json!({ "id": "esc-mainnet" });
    let (request_id, payload_hash) = match invoke_wallet(
        provider,
        principal_id,
        "system",
        WalletProviderOperationV2::RequestApproval {
            account_id: external_account_id.clone(),
            chain_namespace: "eip155:20".into(),
            intent: "transaction_intent".into(),
            resource: "elastos://chain/esc-mainnet/broadcast_transaction".into(),
            reason: "Send EVM transaction".into(),
            payload: external_payload,
            expires_at: now_ts().saturating_add(APPROVAL_REQUEST_TTL_SECS),
        },
    ) {
        Response::Ok { data: Some(data) } => {
            assert_eq!(data["approval_request"]["intent"], "transaction_intent");
            assert_eq!(data["approval_request"]["connector_id"], "wallet-metamask");
            assert_eq!(
                data["approval_request"]["payload"]["schema"],
                "elastos.chain.unsigned_transaction_intent/v1"
            );
            (
                data["approval_request"]["request_id"]
                    .as_str()
                    .unwrap()
                    .to_string(),
                data["approval_request"]["payload_hash"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            )
        }
        other => panic!("expected external transaction approval request, got {other:?}"),
    };
    let transaction = match invoke_wallet(
        provider,
        principal_id,
        "wallet-metamask",
        WalletProviderOperationV2::ApproveConnectorHandoff {
            request_id: request_id.clone(),
            reason: "Approved transaction".into(),
        },
    ) {
        Response::Ok { data: Some(data) } => {
            assert_eq!(data["handoff"]["intent"], "transaction_intent");
            data["handoff"]["transaction"].clone()
        }
        other => panic!("expected external transaction handoff, got {other:?}"),
    };
    assert_eq!(transaction["from"], external_address);
    assert_eq!(transaction["chainId"], "0x14");
    let transaction_hash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let context = wallet_context(principal_id, "wallet-metamask");
    let invalid_completion = wallet_request(
        &context,
        WalletProviderOperationV2::CompleteConnectorHandoff {
            request_id: request_id.clone(),
            payload_hash: payload_hash.clone(),
            signature: None,
            signature_type: None,
            public_key: None,
            signer: external_address.into(),
            transaction_hash: Some(transaction_hash.into()),
        },
    );
    let mut invalid_completion = serde_json::to_value(invalid_completion).unwrap();
    invalid_completion["operation"]["params"]["signature"] =
        json!("0xsigned-transaction-should-not-be-here");
    invalid_completion["operation"]["params"]["signature_type"] = json!("personal_sign");
    match decode_and_handle_outer(
        provider,
        json!({
            "op": "wallet_contract",
            "request": invalid_completion,
            "_runtime_invocation": runtime_invocation_envelope(),
        }),
    ) {
        Response::Error { code, message } => {
            assert_eq!(code, "invalid_wallet_contract");
            assert!(message.contains("exactly one signature or transaction_hash"));
        }
        other => panic!("expected transaction signature rejection, got {other:?}"),
    }
    match invoke_wallet(
        provider,
        principal_id,
        "wallet-metamask",
        WalletProviderOperationV2::CompleteConnectorHandoff {
            request_id: request_id.clone(),
            payload_hash: payload_hash.clone(),
            signature: None,
            signature_type: None,
            public_key: None,
            signer: external_address.into(),
            transaction_hash: Some(transaction_hash.into()),
        },
    ) {
        Response::Ok { data: Some(data) } => {
            assert_eq!(data["approval_request"]["status"], "completed");
            assert_eq!(
                data["approval_request"]["signed_result"]["schema"],
                "elastos.wallet.external-transaction-result/v1"
            );
            assert_eq!(
                data["approval_request"]["signed_result"]["transaction_hash"],
                transaction_hash
            );
            assert_eq!(
                data["approval_request"]["signed_result"]["page_url"],
                "https://ela.city/cinema/view/test"
            );
            assert_eq!(
                data["approval_request"]["signed_result"]["origin"],
                "https://ela.city"
            );
        }
        other => panic!("expected external transaction completion, got {other:?}"),
    };
    ValidatedChainOutcomeV1 {
        schema: elastos_wallet_contract::VALIDATED_CHAIN_OUTCOME_SCHEMA.to_string(),
        approval_request_id: request_id,
        account_id: external_account_id,
        chain_namespace: "eip155:20".into(),
        network: elastos_wallet_contract::PublicNetwork::new("esc-mainnet").unwrap(),
        binding: ValidatedChainOutcomeBindingV1::ExternalConnector {
            connector_id: "wallet-metamask".into(),
            originating_address: external_address.to_string(),
        },
        transaction_hash: transaction_hash.to_string(),
        chain_observation: json!({
            "network": "esc-mainnet",
            "hash": transaction_hash,
            "transaction": {
                "hash": transaction_hash,
                "from": external_address,
                "blockNumber": "0x2a"
            }
        }),
        confirmed_at: now_ts(),
    }
}

#[test]
fn transaction_intent_validates_payload_and_allows_external_handoff() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let principal_id = "person:local:alice";
    let managed = match invoke_wallet(
        &mut provider,
        principal_id,
        "wallet",
        WalletProviderOperationV2::CreateManagedAccount {
            chain_namespace: "eip155:20".into(),
            label: None,
            create_new: false,
        },
    ) {
        Response::Ok { data: Some(data) } => {
            data["account"]["account_id"].as_str().unwrap().to_string()
        }
        other => panic!("expected managed account, got {other:?}"),
    };

    match invoke_wallet(
        &mut provider,
        principal_id,
        "system",
        WalletProviderOperationV2::RequestApproval {
            account_id: managed,
            chain_namespace: "eip155:20".into(),
            intent: "transaction_intent".into(),
            resource: "elastos://chain/esc-mainnet/broadcast_transaction".into(),
            reason: "Send EVM transaction".into(),
            payload: json!({
                "schema": "elastos.chain.unsigned_transaction_intent/v1",
                "transaction_type": "eip155_legacy",
                "chain_id": 20
            }),
            expires_at: now_ts().saturating_add(APPROVAL_REQUEST_TTL_SECS),
        },
    ) {
        Response::Error { code, message } => {
            assert_eq!(code, "invalid_transaction_intent");
            assert!(message.contains("wallet_intent") || message.contains("missing"));
        }
        other => panic!("expected invalid transaction payload, got {other:?}"),
    }

    let outcome = completed_external_transaction_approval(&mut provider);
    for _ in 0..2 {
        match invoke_wallet(
            &mut provider,
            principal_id,
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome {
                outcome: outcome.clone(),
            },
        ) {
            Response::Ok { .. } => {}
            other => panic!("expected external Chain outcome projection, got {other:?}"),
        }
    }

    let mut substituted = outcome;
    substituted.chain_observation["transaction"]["from"] =
        json!("0x4444444444444444444444444444444444444444");
    assert!(matches!(
        invoke_wallet(
            &mut provider,
            principal_id,
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome {
                outcome: substituted,
            },
        ),
        Response::Error { ref code, .. } if code == "chain_outcome_conflict"
    ));
}

/// Catches removal of the principal comparison at `src/approval.rs:1109`:
/// without it an approval written for one principal accepts a Chain outcome
/// from another.
///
/// The lookup at `:89` keys on `outcome.approval_request_id` alone, so
/// `person:local:mallory` reaches alice's completed approval and only the
/// authority comparison refuses it.
#[test]
fn chain_outcome_refuses_a_different_principal() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let (outcome, _address) = completed_managed_transaction_approval(&mut provider);

    assert_eq!(
        invoke_wallet(
            &mut provider,
            "person:local:mallory",
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome { outcome },
        ),
        Response::Error {
            code: "chain_outcome_conflict".to_string(),
            message: "validated Chain outcome authority does not match the approval".to_string(),
        }
    );
}

/// Catches removal of the `account_id` comparison at `src/approval.rs:1115`.
///
/// Strengthens the `account_id` substitution at `:234` to `:246`, which reads
/// the code only. `approval_request_id` is the lookup key at `:89`, so this
/// case changes `account_id` instead: the request is still found and the
/// authority comparison still passes.
#[test]
fn chain_outcome_refuses_a_different_account() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let (mut outcome, _address) = completed_managed_transaction_approval(&mut provider);
    outcome.account_id = "wallet-account:substituted".to_string();

    assert_eq!(
        invoke_wallet(
            &mut provider,
            "person:local:alice",
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome { outcome },
        ),
        Response::Error {
            code: "chain_outcome_conflict".to_string(),
            message: "validated Chain outcome approval binding mismatch".to_string(),
        }
    );
}

/// Catches removal of the `status` and `intent` comparisons at
/// `src/approval.rs:1120`: without them a pending approval accepts a Chain
/// outcome and reports a broadcast that never happened.
///
/// The pending approval this attaches to passes the authority and approval
/// binding checks, so only the completed-transaction check refuses it.
#[test]
fn chain_outcome_refuses_a_pending_approval() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let (mut outcome, address) = completed_managed_transaction_approval(&mut provider);
    let pending_request_id = match invoke_wallet(
        &mut provider,
        "person:local:alice",
        "system",
        WalletProviderOperationV2::RequestApproval {
            account_id: outcome.account_id.clone(),
            chain_namespace: "eip155:20".into(),
            intent: "transaction_intent".into(),
            resource: "elastos://chain/esc-mainnet/broadcast_transaction".into(),
            reason: "Send EVM transaction".into(),
            payload: transaction_intent_payload(&address),
            expires_at: now_ts().saturating_add(APPROVAL_REQUEST_TTL_SECS),
        },
    ) {
        Response::Ok { data: Some(data) } => data["approval_request"]["request_id"]
            .as_str()
            .unwrap()
            .to_string(),
        other => panic!("expected a second transaction approval request, got {other:?}"),
    };
    outcome.approval_request_id = pending_request_id;

    assert_eq!(
        invoke_wallet(
            &mut provider,
            "person:local:alice",
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome { outcome },
        ),
        Response::Error {
            code: "chain_outcome_conflict".to_string(),
            message: "validated Chain outcome requires a completed transaction approval"
                .to_string(),
        }
    );
}

/// Catches removal of the signed-result object check at
/// `src/approval.rs:1125`: without it a completed approval with no signed
/// result accepts a Chain outcome.
///
/// The record keeps its `Completed` status and `transaction_intent`, so the
/// completed-transaction check passes and only this one refuses.
#[test]
fn chain_outcome_refuses_a_completed_approval_without_a_signed_result() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let (outcome, _address) = completed_managed_transaction_approval(&mut provider);
    provider.store.approval_requests[0].signed_result = None;

    assert_eq!(
        invoke_wallet(
            &mut provider,
            "person:local:alice",
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome { outcome },
        ),
        Response::Error {
            code: "chain_outcome_conflict".to_string(),
            message: "completed approval is missing its signed transaction result".to_string(),
        }
    );
}

/// Catches removal of the stored transaction-hash comparison at
/// `src/approval.rs:1130`: without it an outcome naming another broadcast is
/// projected onto this approval.
#[test]
fn chain_outcome_refuses_a_different_transaction_hash() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let (mut outcome, _address) = completed_managed_transaction_approval(&mut provider);
    outcome.transaction_hash = format!("0x{}", "b".repeat(64));

    assert_eq!(
        invoke_wallet(
            &mut provider,
            "person:local:alice",
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome { outcome },
        ),
        Response::Error {
            code: "chain_outcome_conflict".to_string(),
            message: "validated Chain outcome transaction hash mismatch".to_string(),
        }
    );
}

/// Catches removal of the reviewed-payload network comparison at
/// `src/approval.rs:1137`: without it an outcome for another network is
/// projected onto this approval.
///
/// The observation still names `esc-mainnet`, so the observation check at
/// `:1226` is not the guard that answers here.
#[test]
fn chain_outcome_refuses_a_different_network() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let (mut outcome, _address) = completed_managed_transaction_approval(&mut provider);
    outcome.network = elastos_wallet_contract::PublicNetwork::new("esc-testnet").unwrap();

    assert_eq!(
        invoke_wallet(
            &mut provider,
            "person:local:alice",
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome { outcome },
        ),
        Response::Error {
            code: "chain_outcome_conflict".to_string(),
            message: "validated Chain outcome network mismatch".to_string(),
        }
    );
}

/// Catches removal of the signed-result schema comparison at
/// `src/approval.rs:1152`: without it a managed outcome is projected onto a
/// non-managed result.
#[test]
fn chain_outcome_refuses_a_managed_outcome_without_a_managed_result() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let (outcome, _address) = completed_managed_transaction_approval(&mut provider);
    provider.store.approval_requests[0]
        .signed_result
        .as_mut()
        .unwrap()["schema"] = json!("elastos.wallet.substituted-result/v1");

    assert_eq!(
        invoke_wallet(
            &mut provider,
            "person:local:alice",
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome { outcome },
        ),
        Response::Error {
            code: "chain_outcome_conflict".to_string(),
            message: "validated managed Chain outcome requires a managed signed result".to_string(),
        }
    );
}

/// Catches removal of the stored signed-transaction lookup at
/// `src/approval.rs:1160`: without it an approval whose signed transaction was
/// dropped reaches the digest comparison with no bytes to hash.
#[test]
fn chain_outcome_refuses_a_missing_signed_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let (outcome, _address) = completed_managed_transaction_approval(&mut provider);
    provider.store.approval_requests[0]
        .signed_result
        .as_mut()
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("signed_transaction");

    assert_eq!(
        invoke_wallet(
            &mut provider,
            "person:local:alice",
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome { outcome },
        ),
        Response::Error {
            code: "chain_outcome_conflict".to_string(),
            message: "completed approval is missing its signed transaction".to_string(),
        }
    );
}

/// Catches removal of the digest comparison at `src/approval.rs:1165`:
/// without it an outcome naming another signed transaction is projected onto
/// this approval.
#[test]
fn chain_outcome_refuses_a_different_signed_transaction_digest() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let (mut outcome, _address) = completed_managed_transaction_approval(&mut provider);
    outcome.binding = ValidatedChainOutcomeBindingV1::ManagedSigned {
        signed_transaction_sha256: format!("sha256:{}", "b".repeat(64)),
    };

    assert_eq!(
        invoke_wallet(
            &mut provider,
            "person:local:alice",
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome { outcome },
        ),
        Response::Error {
            code: "chain_outcome_conflict".to_string(),
            message: "validated Chain outcome signed transaction digest mismatch".to_string(),
        }
    );
}

/// Catches removal of the `0x` prefix requirement at `src/approval.rs:1207`:
/// without it a bare hex string is hashed as if it were a signed transaction.
#[test]
fn chain_outcome_refuses_a_signed_transaction_without_a_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let (outcome, _address) = completed_managed_transaction_approval(&mut provider);
    provider.store.approval_requests[0]
        .signed_result
        .as_mut()
        .unwrap()["signed_transaction"] = json!("aabbccdd");

    assert_eq!(
        invoke_wallet(
            &mut provider,
            "person:local:alice",
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome { outcome },
        ),
        Response::Error {
            code: "chain_outcome_conflict".to_string(),
            message: "signed transaction must be 0x-prefixed".to_string(),
        }
    );
}

/// Catches removal of the hex decoding at `src/approval.rs:1209`: without it
/// non-hexadecimal bytes are silently skipped and a wrong digest is computed.
#[test]
fn chain_outcome_refuses_a_signed_transaction_that_is_not_hexadecimal() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let (outcome, _address) = completed_managed_transaction_approval(&mut provider);
    provider.store.approval_requests[0]
        .signed_result
        .as_mut()
        .unwrap()["signed_transaction"] = json!("0xzzzz");

    assert_eq!(
        invoke_wallet(
            &mut provider,
            "person:local:alice",
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome { outcome },
        ),
        Response::Error {
            code: "chain_outcome_conflict".to_string(),
            message: "signed transaction must be hexadecimal".to_string(),
        }
    );
}

/// Catches removal of the empty-bytes check at `src/approval.rs:1211`:
/// without it `0x` hashes to the empty digest and matches an outcome that
/// names no signed transaction.
#[test]
fn chain_outcome_refuses_an_empty_signed_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let (outcome, _address) = completed_managed_transaction_approval(&mut provider);
    provider.store.approval_requests[0]
        .signed_result
        .as_mut()
        .unwrap()["signed_transaction"] = json!("0x");

    assert_eq!(
        invoke_wallet(
            &mut provider,
            "person:local:alice",
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome { outcome },
        ),
        Response::Error {
            code: "chain_outcome_conflict".to_string(),
            message: "signed transaction must not be empty".to_string(),
        }
    );
}

/// Catches removal of the signed-result binding comparisons at
/// `src/approval.rs:1189` to `:1198`: without them a result carrying another
/// reviewed payload hash is projected onto this approval.
#[test]
fn chain_outcome_refuses_a_different_signed_result_payload_hash() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let (outcome, _address) = completed_managed_transaction_approval(&mut provider);
    provider.store.approval_requests[0]
        .signed_result
        .as_mut()
        .unwrap()["payload_hash"] = json!(format!("0x{}", "b".repeat(64)));

    assert_eq!(
        invoke_wallet(
            &mut provider,
            "person:local:alice",
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome { outcome },
        ),
        Response::Error {
            code: "chain_outcome_conflict".to_string(),
            message: "validated Chain outcome signed result binding mismatch".to_string(),
        }
    );
}

/// Catches removal of the `connector_id` and address comparisons at
/// `src/approval.rs:1177`: without them an external outcome naming another
/// connector is projected onto this approval.
#[test]
fn chain_outcome_refuses_a_different_external_connector() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let mut outcome = completed_external_transaction_approval(&mut provider);
    outcome.binding = ValidatedChainOutcomeBindingV1::ExternalConnector {
        connector_id: "wallet-unisat".to_string(),
        originating_address: "0x3333333333333333333333333333333333333333".to_string(),
    };

    assert_eq!(
        invoke_wallet(
            &mut provider,
            "person:local:alice",
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome { outcome },
        ),
        Response::Error {
            code: "chain_outcome_conflict".to_string(),
            message: "validated external Chain outcome connector binding mismatch".to_string(),
        }
    );
}

/// Catches removal of the observation network comparison at
/// `src/approval.rs:1225`: without it a receipt from another network is
/// projected onto this approval.
#[test]
fn chain_outcome_refuses_an_observation_for_another_network() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let (mut outcome, _address) = completed_managed_transaction_approval(&mut provider);
    outcome.chain_observation["network"] = json!("esc-testnet");

    assert_eq!(
        invoke_wallet(
            &mut provider,
            "person:local:alice",
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome { outcome },
        ),
        Response::Error {
            code: "chain_outcome_conflict".to_string(),
            message: "validated Chain observation network mismatch".to_string(),
        }
    );
}

/// Catches removal of the observation hash lookup at `src/approval.rs:1229`:
/// without it an observation that names no transaction is accepted as proof of
/// one.
#[test]
fn chain_outcome_refuses_an_observation_without_a_transaction_hash() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let (mut outcome, _address) = completed_managed_transaction_approval(&mut provider);
    let observation = outcome.chain_observation.as_object_mut().unwrap();
    observation.remove("transaction_hash");
    observation.remove("hash");

    assert_eq!(
        invoke_wallet(
            &mut provider,
            "person:local:alice",
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome { outcome },
        ),
        Response::Error {
            code: "chain_outcome_conflict".to_string(),
            message: "validated Chain observation is missing its transaction hash".to_string(),
        }
    );
}

/// Catches removal of the observation hash comparison at
/// `src/approval.rs:1233`: without it a receipt for another transaction is
/// projected onto this approval.
#[test]
fn chain_outcome_refuses_an_observation_for_another_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let (mut outcome, _address) = completed_managed_transaction_approval(&mut provider);
    outcome.chain_observation["transaction_hash"] = json!(format!("0x{}", "b".repeat(64)));

    assert_eq!(
        invoke_wallet(
            &mut provider,
            "person:local:alice",
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome { outcome },
        ),
        Response::Error {
            code: "chain_outcome_conflict".to_string(),
            message: "validated Chain observation transaction hash mismatch".to_string(),
        }
    );
}

/// Catches removal of the receipt subtree comparison at
/// `src/approval.rs:1241`: without it a receipt whose `transactionHash` names
/// another transaction is projected onto this approval.
#[test]
fn chain_outcome_refuses_a_receipt_hash_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let (mut outcome, _address) = completed_managed_transaction_approval(&mut provider);
    outcome.chain_observation["receipt"] = json!({
        "transactionHash": format!("0x{}", "b".repeat(64)),
    });

    assert_eq!(
        invoke_wallet(
            &mut provider,
            "person:local:alice",
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome { outcome },
        ),
        Response::Error {
            code: "chain_outcome_conflict".to_string(),
            message: "validated Chain receipt payload hash mismatch".to_string(),
        }
    );
}

/// Catches removal of the transaction subtree comparison at
/// `src/approval.rs:1250`: without it an observation whose `transaction.hash`
/// names another transaction is projected onto this approval.
///
/// The outer `transactionHash` stays correct, so the clause at `:1241` is not
/// the guard that answers here.
#[test]
fn chain_outcome_refuses_a_transaction_subtree_hash_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let (mut outcome, _address) = completed_managed_transaction_approval(&mut provider);
    outcome.chain_observation["transaction"] = json!({
        "hash": format!("0x{}", "b".repeat(64)),
    });

    assert_eq!(
        invoke_wallet(
            &mut provider,
            "person:local:alice",
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome { outcome },
        ),
        Response::Error {
            code: "chain_outcome_conflict".to_string(),
            message: "validated Chain transaction payload hash mismatch".to_string(),
        }
    );
}

/// Catches removal of the originating-account lookup at
/// `src/approval.rs:1260`: without it an external observation that names no
/// sender is accepted as proof that the linked account sent it.
#[test]
fn chain_outcome_refuses_an_external_observation_without_an_originating_account() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let mut outcome = completed_external_transaction_approval(&mut provider);
    outcome.chain_observation["transaction"]
        .as_object_mut()
        .unwrap()
        .remove("from");

    assert_eq!(
        invoke_wallet(
            &mut provider,
            "person:local:alice",
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome { outcome },
        ),
        Response::Error {
            code: "chain_outcome_conflict".to_string(),
            message: "validated external Chain observation is missing originating account"
                .to_string(),
        }
    );
}

/// Catches removal of the originating-account comparison at
/// `src/approval.rs:1267`: without it an external observation naming another
/// sender is projected onto this approval.
///
/// Strengthens the `transaction.from` substitution at `:483` to `:496`, which
/// reads the code only.
#[test]
fn chain_outcome_refuses_a_different_originating_account() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let mut outcome = completed_external_transaction_approval(&mut provider);
    outcome.chain_observation["transaction"]["from"] =
        json!("0x4444444444444444444444444444444444444444");

    assert_eq!(
        invoke_wallet(
            &mut provider,
            "person:local:alice",
            "system",
            WalletProviderOperationV2::AttachValidatedChainOutcome { outcome },
        ),
        Response::Error {
            code: "chain_outcome_conflict".to_string(),
            message: "validated external Chain observation originating account mismatch"
                .to_string(),
        }
    );
}
