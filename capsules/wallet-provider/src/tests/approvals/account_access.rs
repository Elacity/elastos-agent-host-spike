use super::super::support::*;
use super::super::*;

fn access_payload(
    context: &VerifiedWalletInvocationContext,
    account_id: &str,
    address: &str,
    grant_expires_at: u64,
) -> Value {
    json!({
        "schema": "elastos.browser.account-access-request/v1",
        "permission": "eth_accounts",
        "principal_id": context.principal_id(),
        "session_id": context.session_id(),
        "launch_id": context.launch_id(),
        "proof_binding_id": context.proof_binding_id(),
        "origin": "https://dapp.example",
        "page_url": "https://dapp.example/connect",
        "account_id": account_id,
        "requested_chain_namespace": "eip155:20",
        "chain_namespaces": ["eip155:20", "eip155:8453"],
        "address": address,
        "grant_expires_at": grant_expires_at,
        "requires_wallet_approval": true
    })
}

fn managed_account(
    provider: &mut WalletProvider,
    context: &VerifiedWalletInvocationContext,
) -> (String, String) {
    match invoke_wallet_with_context(
        provider,
        context,
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
    }
}

#[test]
fn browser_account_access_is_disclosed_only_after_exact_managed_approval() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let context = wallet_context("person:local:account-access", "browser");
    let (account_id, address) = managed_account(&mut provider, &context);
    let request_id = match invoke_wallet_with_context(
        &mut provider,
        &context,
        WalletProviderOperationV2::RequestApproval {
            account_id: account_id.clone(),
            chain_namespace: "eip155:20".into(),
            intent: "browser_account_access".into(),
            resource: format!("elastos://wallet/account/{account_id}/permission/eth_accounts"),
            reason: "Browser origin requests exact account access".into(),
            payload: access_payload(
                &context,
                &account_id,
                &address,
                now_ts().saturating_add(600),
            ),
            expires_at: now_ts().saturating_add(APPROVAL_REQUEST_TTL_SECS),
        },
    ) {
        Response::Ok { data: Some(data) } => {
            assert_eq!(data["signature"], Value::Null);
            assert_eq!(data["approval_request"]["status"], "pending");
            data["approval_request"]["request_id"]
                .as_str()
                .unwrap()
                .to_string()
        }
        other => panic!("expected account-access approval, got {other:?}"),
    };

    match invoke_wallet_with_context(
        &mut provider,
        &context,
        WalletProviderOperationV2::ApproveAndSignManaged {
            request_id,
            reason: "Exact request reviewed in Wallet".into(),
        },
    ) {
        Response::Ok { data: Some(data) } => {
            let result = &data["approval_request"]["signed_result"];
            assert_eq!(result["schema"], "elastos.browser.account-access-result/v1");
            assert_eq!(result["permission"], "eth_accounts");
            assert_eq!(result["origin"], "https://dapp.example");
            assert_eq!(
                result["chain_namespaces"],
                json!(["eip155:20", "eip155:8453"])
            );
            assert_eq!(result["address"], address);
            assert!(result.get("signature").is_none());
            assert!(data["signature"]
                .as_str()
                .is_some_and(|value| value.starts_with("0x")));
        }
        other => panic!("expected completed account-access approval, got {other:?}"),
    }
}

#[test]
fn browser_account_access_rejects_substituted_authority_and_networks() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let context = wallet_context("person:local:account-access-reject", "browser");
    let (account_id, address) = managed_account(&mut provider, &context);

    for (field, replacement) in [
        ("session_id", json!("session:substituted")),
        ("launch_id", json!("launch:substituted")),
        ("proof_binding_id", json!("proof:substituted")),
        ("origin", json!("https://attacker.example")),
        ("chain_namespaces", json!(["eip155:20", "eip155:1"])),
        ("grant_expires_at", json!(now_ts().saturating_sub(1))),
    ] {
        let mut payload = access_payload(
            &context,
            &account_id,
            &address,
            now_ts().saturating_add(600),
        );
        payload[field] = replacement;
        match invoke_wallet_with_context(
            &mut provider,
            &context,
            WalletProviderOperationV2::RequestApproval {
                account_id: account_id.clone(),
                chain_namespace: "eip155:20".into(),
                intent: "browser_account_access".into(),
                resource: format!("elastos://wallet/account/{account_id}/permission/eth_accounts"),
                reason: "Browser origin requests exact account access".into(),
                payload,
                expires_at: now_ts().saturating_add(APPROVAL_REQUEST_TTL_SECS),
            },
        ) {
            Response::Error { code, .. } => assert_eq!(code, "invalid_browser_account_access"),
            other => panic!("expected {field} substitution rejection, got {other:?}"),
        }
    }
}

// `validate_browser_account_access_payload` (`src/approval.rs:972`) decides
// which Browser account-access request the Wallet records and with which
// reason it refuses the rest. One refusal string, one test below, so a dropped
// session, launch, origin, network-set, address or expiry-window guard fails a
// named test instead of only the code check the two tests above assert.
//
// The two tests above reach this validator and read
// `code == "invalid_browser_account_access"` only. The test at `:112` to
// `:148` substitutes `session_id`, `launch_id`, `proof_binding_id`, `origin`,
// `chain_namespaces` and a past `grant_expires_at`; the test at `:50` runs the
// happy path. Both stay byte-identical. The tests here name the reason each of
// those six substitutions produces, so they strengthen that test rather than
// open a second path to the same rule: every case drives the public
// `RequestApproval` operation through `invoke_wallet_with_context`, one field
// changed on a payload `access_payload` already builds.
//
// Ordering is the risk. This validator is reached only after
// `input.validate(now)`, `account_for_signature`,
// `ensure_managed_account_can_sign` and the managed-intent check, and inside it
// the guards run in the order below. Each case passes every check ahead of the
// one it names:
//
// - the object check (`:998`) reads the JSON type only;
// - the field check (`:1000`) reads the key count and key set only, so a
//   `null` or empty value under an unchanged key set passes it and reaches the
//   `missing {field}` string at `:1007`, while a removed key fails the count
//   and reaches `:1000`;
// - `:1024` compares `session_id` and `launch_id` under one shared reason;
// - the element-wise comparison at `:1050` is the clause a reordered set fails,
//   because the requested namespace already satisfies the containment clause
//   at `:1052`;
// - `:1094` bounds the grant window at both ends under one shared reason.

fn account_access_response(
    provider: &mut WalletProvider,
    context: &VerifiedWalletInvocationContext,
    account_id: &str,
    payload: Value,
) -> Response {
    invoke_wallet_with_context(
        provider,
        context,
        WalletProviderOperationV2::RequestApproval {
            account_id: account_id.to_string(),
            chain_namespace: "eip155:20".into(),
            intent: "browser_account_access".into(),
            resource: format!("elastos://wallet/account/{account_id}/permission/eth_accounts"),
            reason: "Browser origin requests exact account access".into(),
            payload,
            expires_at: now_ts().saturating_add(APPROVAL_REQUEST_TTL_SECS),
        },
    )
}

fn account_access_refusal(message: &str) -> Response {
    Response::Error {
        code: "invalid_browser_account_access".to_string(),
        message: message.to_string(),
    }
}

/// Catches removal of the object check at `src/approval.rs:997`: without it a
/// payload that is not a JSON object reaches the field check and answers the
/// wrong reason.
///
/// The array payload passes `SignatureRequestInput::validate`, the account
/// lookup and the managed checks, which read the operation and not the
/// payload.
#[test]
fn access_refuses_a_non_object_payload() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let context = wallet_context("person:local:account-access-not-object", "browser");
    let (account_id, _) = managed_account(&mut provider, &context);

    assert_eq!(
        account_access_response(
            &mut provider,
            &context,
            &account_id,
            json!(["elastos.browser.account-access-request/v1"]),
        ),
        account_access_refusal("Browser account access payload must be an object")
    );
}

/// Catches removal of the key count and key set check at `src/approval.rs:999`:
/// without it a payload missing one field reaches `missing origin` at `:1007`
/// instead of naming the field set.
///
/// A removed key fails the count at `:999`; a value made `null` or empty would
/// keep all fourteen keys and pass this check, which is why the case below
/// removes a key rather than clearing one.
#[test]
fn access_refuses_an_unknown_field_set() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let context = wallet_context("person:local:account-access-field-set", "browser");
    let (account_id, address) = managed_account(&mut provider, &context);
    let mut payload = access_payload(
        &context,
        &account_id,
        &address,
        now_ts().saturating_add(600),
    );
    payload.as_object_mut().unwrap().remove("origin");

    assert_eq!(
        account_access_response(&mut provider, &context, &account_id, payload),
        account_access_refusal("Browser account access payload fields are invalid")
    );
}

/// Catches removal of the `text()` helper's non-empty string check at
/// `src/approval.rs:1006`: without it a `null` value under an unchanged key set
/// reaches the schema comparison at `:1009` and answers the wrong reason.
///
/// The format argument is `schema`, so the asserted text is
/// `Browser account access payload missing schema`. All fourteen keys stay
/// present, so the key count and key set check at `:999` passes.
#[test]
fn access_refuses_a_missing_field_value() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let context = wallet_context("person:local:account-access-missing-value", "browser");
    let (account_id, address) = managed_account(&mut provider, &context);
    let mut payload = access_payload(
        &context,
        &account_id,
        &address,
        now_ts().saturating_add(600),
    );
    payload["schema"] = Value::Null;

    assert_eq!(
        account_access_response(&mut provider, &context, &account_id, payload),
        account_access_refusal("Browser account access payload missing schema")
    );
}

/// Catches removal of the schema comparison at `src/approval.rs:1009`: without
/// it a request written to another schema is recorded as pending.
#[test]
fn access_refuses_a_substituted_schema() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let context = wallet_context("person:local:account-access-schema", "browser");
    let (account_id, address) = managed_account(&mut provider, &context);
    let mut payload = access_payload(
        &context,
        &account_id,
        &address,
        now_ts().saturating_add(600),
    );
    payload["schema"] = json!("elastos.browser.account-access-request/v2");

    assert_eq!(
        account_access_response(&mut provider, &context, &account_id, payload),
        account_access_refusal("Browser account access payload schema is invalid")
    );
}

/// Catches removal of the permission comparison at `src/approval.rs:1012`:
/// without it a request for another permission is recorded as account access.
#[test]
fn access_refuses_a_substituted_permission() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let context = wallet_context("person:local:account-access-permission", "browser");
    let (account_id, address) = managed_account(&mut provider, &context);
    let mut payload = access_payload(
        &context,
        &account_id,
        &address,
        now_ts().saturating_add(600),
    );
    payload["permission"] = json!("eth_requestAccounts");

    assert_eq!(
        account_access_response(&mut provider, &context, &account_id, payload),
        account_access_refusal("Browser account access permission must be eth_accounts")
    );
}

/// Catches removal of the requesting-actor check at `src/approval.rs:1015`:
/// without it any actor reaches an intent that only Browser may request.
///
/// The context's actor is the input's `requested_by_actor`, so the case builds
/// it with `wallet` and keeps every other field from that same context. A
/// managed account is created under the same principal, so the account lookup
/// and the managed checks ahead of `:1015` pass.
#[test]
fn access_refuses_a_non_browser_actor() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let context = wallet_context("person:local:account-access-actor", "wallet");
    let (account_id, address) = managed_account(&mut provider, &context);
    let payload = access_payload(
        &context,
        &account_id,
        &address,
        now_ts().saturating_add(600),
    );

    assert_eq!(
        account_access_response(&mut provider, &context, &account_id, payload),
        account_access_refusal("Browser account access must be requested by Browser")
    );
}

/// Catches removal of the managed-account check at `src/approval.rs:1018`:
/// without it account access is recorded for a signer the Runtime does not
/// hold, so the effect cannot be completed.
///
/// The guard refuses both an unmanaged proof type and any account with a
/// `connector_id`. `link_account` sets `connector_id` from the linking actor,
/// so a `siwe` account linked from the file's existing `browser` context is
/// refused here, and no second context is needed.
#[test]
fn access_refuses_an_unmanaged_account() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let context = wallet_context("person:local:account-access-unmanaged", "browser");
    let signing_key = SigningKey::from_slice(&[0x51; 32]).unwrap();
    let address = test_address(&signing_key);
    let account_id = format!("wallet:eip155:20:{address}");
    match invoke_wallet_with_context(
        &mut provider,
        &context,
        WalletProviderOperationV2::LinkVerifiedAccount {
            proof_binding_id: format!("proof:eip155:20:{address}"),
            chain_namespace: "eip155:20".into(),
            address: address.clone(),
            proof_type: "siwe".into(),
            label: None,
        },
    ) {
        Response::Ok { .. } => {}
        other => panic!("expected linked external account, got {other:?}"),
    }
    let payload = access_payload(
        &context,
        &account_id,
        &address,
        now_ts().saturating_add(600),
    );

    assert_eq!(
        account_access_response(&mut provider, &context, &account_id, payload),
        account_access_refusal("Browser account access requires a Runtime-managed account")
    );
}

/// Catches removal of the principal comparison at `src/approval.rs:1021`:
/// without it a request naming another principal is recorded against the
/// selected account.
#[test]
fn access_refuses_a_substituted_principal() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let context = wallet_context("person:local:account-access-principal", "browser");
    let (account_id, address) = managed_account(&mut provider, &context);
    let mut payload = access_payload(
        &context,
        &account_id,
        &address,
        now_ts().saturating_add(600),
    );
    payload["principal_id"] = json!("person:local:someone-else");

    assert_eq!(
        account_access_response(&mut provider, &context, &account_id, payload),
        account_access_refusal("Browser account access principal does not match selected account")
    );
}

/// Catches removal of the `session_id` comparison and of the `launch_id`
/// comparison at `src/approval.rs:1024`, which raise one shared reason.
///
/// Strengthens the `session_id` and `launch_id` substitutions at `:112` to
/// `:148`, which read the code only. Each substitution keeps all fourteen
/// keys, a non-empty string value and every check ahead of `:1024` passing, so
/// each one alone pins the whole shared reason and catches the removal of its
/// own comparison.
#[test]
fn access_refuses_a_substituted_session_or_launch() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let context = wallet_context("person:local:account-access-authority", "browser");
    let (account_id, address) = managed_account(&mut provider, &context);

    for (field, substitution) in [
        ("session_id", "session:substituted"),
        ("launch_id", "launch:substituted"),
    ] {
        let mut payload = access_payload(
            &context,
            &account_id,
            &address,
            now_ts().saturating_add(600),
        );
        payload[field] = json!(substitution);
        assert_eq!(
            account_access_response(&mut provider, &context, &account_id, payload),
            account_access_refusal(
                "Browser account access session or launch authority does not match"
            ),
            "{field} substitution"
        );
    }
}

/// Catches removal of the proof-binding comparison at `src/approval.rs:1031`:
/// without it a request bound to another proof is recorded.
///
/// Strengthens the `proof_binding_id` substitution at `:112` to `:148`, which
/// reads the code only. The substitute is an opaque id, so the
/// `validate_opaque_id` call at `:1030` passes and only the comparison
/// refuses.
#[test]
fn access_refuses_substituted_proof_binding() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let context = wallet_context("person:local:account-access-proof", "browser");
    let (account_id, address) = managed_account(&mut provider, &context);
    let mut payload = access_payload(
        &context,
        &account_id,
        &address,
        now_ts().saturating_add(600),
    );
    payload["proof_binding_id"] = json!("proof:substituted");

    assert_eq!(
        account_access_response(&mut provider, &context, &account_id, payload),
        account_access_refusal("Browser account access proof binding does not match authority")
    );
}

/// Catches removal of the `validate_opaque_id` call at `src/approval.rs:1030`:
/// without it a proof binding longer than the provider's id limit reaches the
/// equality comparison at `:1031` and answers the wrong reason.
#[test]
fn access_refuses_an_overlong_proof_binding() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let context = wallet_context("person:local:account-access-overlong-proof", "browser");
    let (account_id, address) = managed_account(&mut provider, &context);
    let mut payload = access_payload(
        &context,
        &account_id,
        &address,
        now_ts().saturating_add(600),
    );
    payload["proof_binding_id"] = json!("p".repeat(257));

    assert_eq!(
        account_access_response(&mut provider, &context, &account_id, payload),
        account_access_refusal("proof_binding_id must be 1-256 characters")
    );
}

/// Catches removal of the `validate_opaque_id` call at `src/approval.rs:1030`:
/// without it a relative path segment as a proof binding reaches the equality
/// comparison at `:1031` and answers the wrong reason.
#[test]
fn access_refuses_a_dot_proof_binding() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let context = wallet_context("person:local:account-access-dot-proof", "browser");
    let (account_id, address) = managed_account(&mut provider, &context);
    let mut payload = access_payload(
        &context,
        &account_id,
        &address,
        now_ts().saturating_add(600),
    );
    payload["proof_binding_id"] = json!(".");

    assert_eq!(
        account_access_response(&mut provider, &context, &account_id, payload),
        account_access_refusal("proof_binding_id must be opaque")
    );
}

/// Catches removal of the `validate_opaque_id` call at `src/approval.rs:1030`:
/// without it a proof binding with a path separator reaches the equality
/// comparison at `:1031` and answers the wrong reason.
#[test]
fn access_refuses_invalid_proof_binding_characters() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let context = wallet_context("person:local:account-access-proof-characters", "browser");
    let (account_id, address) = managed_account(&mut provider, &context);
    let mut payload = access_payload(
        &context,
        &account_id,
        &address,
        now_ts().saturating_add(600),
    );
    payload["proof_binding_id"] = json!("proof/sibling");

    assert_eq!(
        account_access_response(&mut provider, &context, &account_id, payload),
        account_access_refusal("proof_binding_id contains unsupported characters")
    );
}

/// Catches removal of the payload account comparison at
/// `src/approval.rs:1034`: without it a payload that names another account is
/// recorded against the selected one.
///
/// The operation's `account_id` stays the managed account, so the account
/// lookup passes and only the payload field is substituted.
#[test]
fn access_refuses_a_substituted_account_id() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let context = wallet_context("person:local:account-access-account", "browser");
    let (account_id, address) = managed_account(&mut provider, &context);
    let mut payload = access_payload(
        &context,
        &account_id,
        &address,
        now_ts().saturating_add(600),
    );
    payload["account_id"] = json!("wallet:eip155:20:0x1111111111111111111111111111111111111111");

    assert_eq!(
        account_access_response(&mut provider, &context, &account_id, payload),
        account_access_refusal("Browser account access account does not match selected account")
    );
}

/// Catches removal of the `requested_chain_namespace` comparison at
/// `src/approval.rs:1038`: without it a payload may name a network the request
/// did not ask for.
///
/// The payload namespace stays compatible with the account's `eip155:20`, so
/// only the comparison against the request's own `chain_namespace` refuses.
#[test]
fn access_refuses_a_substituted_requested_chain() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let context = wallet_context("person:local:account-access-chain", "browser");
    let (account_id, address) = managed_account(&mut provider, &context);
    let mut payload = access_payload(
        &context,
        &account_id,
        &address,
        now_ts().saturating_add(600),
    );
    payload["requested_chain_namespace"] = json!("eip155:8453");

    assert_eq!(
        account_access_response(&mut provider, &context, &account_id, payload),
        account_access_refusal("Browser account access chain does not match selected account")
    );
}

/// Catches removal of the array check at `src/approval.rs:1045`: without it a
/// non-array under the unchanged key reaches the set comparison at `:1047`
/// and answers the wrong reason.
#[test]
fn access_refuses_missing_chain_namespaces() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let context = wallet_context("person:local:account-access-networks-missing", "browser");
    let (account_id, address) = managed_account(&mut provider, &context);
    let mut payload = access_payload(
        &context,
        &account_id,
        &address,
        now_ts().saturating_add(600),
    );
    payload["chain_namespaces"] = json!("eip155:20");

    assert_eq!(
        account_access_response(&mut provider, &context, &account_id, payload),
        account_access_refusal("Browser account access chain_namespaces are missing")
    );
}

/// Catches removal of the element-wise comparison at `src/approval.rs:1050`:
/// without it any two-entry set passes, so a dapp may ask for access to a
/// network pair the provider never offers.
///
/// Strengthens the `chain_namespaces` substitution at `:112` to `:148`, which
/// reads the code only. The set is reordered, so its length is right, the
/// requested namespace is still contained at `:1052` and both entries stay
/// compatible with the account: the clause this case fails is the one at
/// `:1050`, not its neighbour.
#[test]
fn access_refuses_an_unsupported_network_set() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let context = wallet_context("person:local:account-access-networks", "browser");
    let (account_id, address) = managed_account(&mut provider, &context);
    let mut payload = access_payload(
        &context,
        &account_id,
        &address,
        now_ts().saturating_add(600),
    );
    payload["chain_namespaces"] = json!(["eip155:8453", "eip155:20"]);

    assert_eq!(
        account_access_response(&mut provider, &context, &account_id, payload),
        account_access_refusal(
            "Browser account access chain_namespaces do not match the supported network set"
        )
    );
}

/// Catches removal of the address comparison at `src/approval.rs:1062`:
/// without it the grant names an address the selected account does not hold.
#[test]
fn access_refuses_a_substituted_address() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let context = wallet_context("person:local:account-access-address", "browser");
    let (account_id, address) = managed_account(&mut provider, &context);
    let mut payload = access_payload(
        &context,
        &account_id,
        &address,
        now_ts().saturating_add(600),
    );
    payload["address"] = json!("0x2222222222222222222222222222222222222222");

    assert_eq!(
        account_access_response(&mut provider, &context, &account_id, payload),
        account_access_refusal("Browser account access address does not match selected account")
    );
}

/// Catches removal of the page-URL binding check at `src/approval.rs:1074`:
/// without it a page on another origin is granted access as the origin it
/// names.
///
/// Strengthens the `origin` substitution at `:112` to `:148`, which reads the
/// code only. Both substitutions keep every check ahead of the binding
/// passing: each origin and page URL is a well-formed `https://` URL with no
/// trailing slash and no whitespace, and both stay under the length caps. A
/// different origin, and a page URL under a different origin, each reach the
/// one shared reason.
#[test]
fn access_refuses_an_unbound_origin_or_page_url() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let context = wallet_context("person:local:account-access-page", "browser");
    let (account_id, address) = managed_account(&mut provider, &context);

    for (field, substitution) in [
        ("origin", "https://attacker.example"),
        ("page_url", "https://other.example/connect"),
    ] {
        let mut payload = access_payload(
            &context,
            &account_id,
            &address,
            now_ts().saturating_add(600),
        );
        payload[field] = json!(substitution);
        assert_eq!(
            account_access_response(&mut provider, &context, &account_id, payload),
            account_access_refusal("Browser account access page URL or origin is invalid"),
            "{field} substitution"
        );
    }
}

/// Catches removal of the approval-requirement check at
/// `src/approval.rs:1083`: without it a payload may record account access the
/// Wallet is never asked to review.
#[test]
fn access_refuses_a_missing_wallet_approval_requirement() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let context = wallet_context("person:local:account-access-approval", "browser");
    let (account_id, address) = managed_account(&mut provider, &context);
    let mut payload = access_payload(
        &context,
        &account_id,
        &address,
        now_ts().saturating_add(600),
    );
    payload["requires_wallet_approval"] = json!(false);

    assert_eq!(
        account_access_response(&mut provider, &context, &account_id, payload),
        account_access_refusal("Browser account access must require wallet approval")
    );
}

/// Catches removal of the integer check at `src/approval.rs:1092`: without it a
/// grant expiry that is not a number reaches the window comparison and answers
/// the wrong reason.
#[test]
fn access_refuses_a_non_numeric_grant_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let context = wallet_context("person:local:account-access-expiry-shape", "browser");
    let (account_id, address) = managed_account(&mut provider, &context);
    let mut payload = access_payload(
        &context,
        &account_id,
        &address,
        now_ts().saturating_add(600),
    );
    payload["grant_expires_at"] = json!("tomorrow");

    assert_eq!(
        account_access_response(&mut provider, &context, &account_id, payload),
        account_access_refusal("Browser account access grant expiry is missing")
    );
}

/// Catches removal of the expiry window at `src/approval.rs:1094`: without it a
/// grant is recorded that is already over or that outlives the provider's cap.
///
/// Strengthens the past `grant_expires_at` substitution at `:112` to `:148`,
/// which reads the code only. One test drives both ends, which share one
/// reason: a value one second in the past fails the lower comparison, and the
/// sampled second plus the cap plus one fails the upper one. A clock tick
/// between that sample and the provider's own `now_ts()` would make the upper
/// value valid, so the case retries until one attempt reads the same second
/// before it and after it, then asserts the refusal of that attempt.
#[test]
fn access_refuses_an_out_of_window_grant() {
    let dir = tempfile::tempdir().unwrap();
    let mut provider = init_provider(dir.path());
    let context = wallet_context("person:local:account-access-window", "browser");
    let (account_id, address) = managed_account(&mut provider, &context);

    let past = access_payload(&context, &account_id, &address, now_ts().saturating_sub(1));
    assert_eq!(
        account_access_response(&mut provider, &context, &account_id, past),
        account_access_refusal("Browser account access grant expiry is outside the allowed window")
    );

    loop {
        let sampled = now_ts();
        let upper = sampled
            .saturating_add(MAX_BROWSER_ACCOUNT_ACCESS_TTL_SECS)
            .saturating_add(1);
        let payload = access_payload(&context, &account_id, &address, upper);
        let response = account_access_response(&mut provider, &context, &account_id, payload);
        if now_ts() != sampled {
            continue;
        }
        assert_eq!(
            response,
            account_access_refusal(
                "Browser account access grant expiry is outside the allowed window"
            )
        );
        break;
    }
}
