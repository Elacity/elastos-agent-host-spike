//! Passkey approval and one-time delivery of an exported Home CLI grant. These
//! tests use the real routes. The software passkey is the same in-process p256
//! authenticator the identity crate uses. The request table is process memory.
// Twelve tests here write auth state, which Windows refuses (P2-11 step 6), so they
// are cfg(unix); the helpers only they use are unused on Windows.
#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

const SECRET: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg";
const ORIGIN: &str = "http://localhost:61180";
const RP_ID: &str = "localhost";
const CREDENTIAL_ID: &str = "cli-mint-owner";
const REQUEST_SCHEMA: &str = "elastos.home.cli-mint.request/v1";
const BEGIN_SCHEMA: &str = "elastos.home.cli-mint.begin/v1";
const APPROVE_SCHEMA: &str = "elastos.home.cli-mint.approve/v1";
const CLAIM_SCHEMA: &str = "elastos.home.cli-mint.claim/v1";
const CANCEL_SCHEMA: &str = "elastos.home.cli-mint.cancel/v1";
const OPERATION: &str = "home-cli.export-grant";
const LAUNCH_TOKEN: &str = "elastos.home.launch-token";
const WRONG_SECRET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRS";
const EXPORT_TTL_SECS: u64 = 5 * 60;

struct EnvGuard {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
    }
}

fn cose_es256_public_key() -> String {
    let signing_key = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
    let point = signing_key.verifying_key().to_encoded_point(false);
    let x = point.x().unwrap();
    let y = point.y().unwrap();
    let mut cose = Vec::with_capacity(77);
    cose.push(0xa5);
    cose.extend_from_slice(&[0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
    cose.extend_from_slice(x);
    cose.extend_from_slice(&[0x22, 0x58, 0x20]);
    cose.extend_from_slice(y);
    URL_SAFE_NO_PAD.encode(cose)
}

fn install_owner_credential(data_dir: &std::path::Path, public_key: &str) {
    let mut store = elastos_identity::IdentityStore::new(data_dir).unwrap();
    store.load().unwrap();
    store.add_credential(elastos_identity::StoredCredential {
        credential_id: CREDENTIAL_ID.to_string(),
        public_key: public_key.to_string(),
        sign_count: 0,
        rp_id: RP_ID.to_string(),
    });
    store.save().unwrap();
}

fn software_owner(data_dir: &std::path::Path) -> TestPasskeyAuthority {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let public_key = cose_es256_public_key();
    install_owner_credential(data_dir, &public_key);
    let now = crate::auth::now_ts();
    let binding = ProofBinding::passkey_webauthn(PasskeyWebAuthnBinding {
        credential_id: CREDENTIAL_ID.to_string(),
        public_key,
        sign_count: 0,
        user_verified: true,
        origin: ORIGIN.to_string(),
        rp_id: RP_ID.to_string(),
        created_at: now,
        last_used_at: now,
        revoked_at: None,
    });
    let principal_id = crate::auth::passkey_credential_principal_id(RP_ID, CREDENTIAL_ID).unwrap();
    let principal = crate::auth::upsert_principal_for_binding_as_role_named(
        data_dir,
        binding,
        principal_id,
        crate::auth::RuntimePrincipalRole::Admin,
        Some("cli mint owner"),
        now,
    )
    .unwrap();
    let grant = AuthSessionGrantV1 {
        schema: AuthSessionGrantV1::SCHEMA.to_string(),
        grant_id: format!("grant:{}", uuid_like_token()),
        session_id: format!("auth:{}", uuid_like_token()),
        principal_id: principal.principal_id.clone(),
        proof_binding_id: principal.proof_binding_id.clone(),
        issued_at: now,
        expires_at: now + 12 * 60 * 60,
        apps: vec![HOME_CAPSULE_ID.to_string()],
    };
    crate::auth::store_session_grant(data_dir, grant.clone()).unwrap();
    TestPasskeyAuthority {
        home_token: issue_home_launch_token_for_auth_grant(data_dir, HOME_CAPSULE_ID, &grant)
            .unwrap(),
        people_token: String::new(),
        system_token: String::new(),
        principal_id: principal.principal_id,
        proof_binding_id: principal.proof_binding_id,
        session_id: grant.session_id,
        grant_id: grant.grant_id,
    }
}

fn app(data_dir: &std::path::Path) -> Router {
    gateway_router(test_state(data_dir))
}

async fn post_json(
    app: &Router,
    request: axum::http::request::Builder,
    body: Value,
) -> (StatusCode, String) {
    let request = request
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

fn terminal_request() -> axum::http::request::Builder {
    Request::builder()
        .method("POST")
        .uri("/api/home/cli-mint/request")
        .header(HOST, "localhost:61180")
}

fn admin_post(uri: &str, token: &str) -> axum::http::request::Builder {
    test_browser_request("localhost:61180", ORIGIN)
        .method("POST")
        .uri(uri)
        .header("x-elastos-home-token", token)
}

async fn register(app: &Router, secret: &str) -> (StatusCode, String) {
    post_json(
        app,
        terminal_request(),
        json!({
            "schema": REQUEST_SCHEMA,
            "requester_secret": secret,
        }),
    )
    .await
}

async fn mint_test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    let guard = LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    super::super::gateway_home_cli_mint::clear_cli_mint_for_test();
    guard
}

fn record_text(request_id: &str) -> String {
    super::super::gateway_home_cli_mint::cli_mint_record_json_for_test(request_id)
        .unwrap_or_else(|| panic!("missing cli mint request {request_id}"))
}

fn rewrite_record(request_id: &str, field: &str, value: &str) {
    super::super::gateway_home_cli_mint::cli_mint_rewrite_for_test(request_id, field, value);
}

fn assertion(challenge: &str, signature_ok: bool) -> Value {
    let client = serde_json::json!({
        "challenge": challenge,
        "origin": ORIGIN,
        "type": "webauthn.get",
    });
    let client_bytes = serde_json::to_vec(&client).unwrap();
    let mut auth = Sha256::digest(RP_ID.as_bytes()).to_vec();
    auth.push(0x05);
    auth.extend_from_slice(&1u32.to_be_bytes());
    let mut signed = auth.clone();
    signed.extend_from_slice(&Sha256::digest(&client_bytes));
    let signature = if signature_ok {
        let signature: p256::ecdsa::Signature = p256::ecdsa::SigningKey::from_slice(&[7u8; 32])
            .unwrap()
            .sign(&signed);
        URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())
    } else {
        URL_SAFE_NO_PAD.encode(b"not-a-der-signature")
    };
    json!({
        "id": CREDENTIAL_ID,
        "rawId": CREDENTIAL_ID,
        "type": "public-key",
        "response": {
            "clientDataJson": URL_SAFE_NO_PAD.encode(client_bytes),
            "authenticatorData": URL_SAFE_NO_PAD.encode(auth),
            "signature": signature,
            "userHandle": null,
        }
    })
}

async fn begin(app: &Router, token: &str, request_id: &str) -> (StatusCode, String) {
    post_json(
        app,
        admin_post("/api/home/cli-mint/begin", token),
        json!({
            "schema": BEGIN_SCHEMA,
            "request_id": request_id,
        }),
    )
    .await
}

async fn approve(
    app: &Router,
    token: &str,
    request_id: &str,
    response: Value,
) -> (StatusCode, String) {
    post_json(
        app,
        admin_post("/api/home/cli-mint/approve", token),
        json!({
            "schema": APPROVE_SCHEMA,
            "request_id": request_id,
            "response": response,
        }),
    )
    .await
}

fn dummy_assertion() -> Value {
    json!({
        "id": "x",
        "rawId": "x",
        "type": "public-key",
        "response": {
            "clientDataJson": "e30",
            "authenticatorData": "e30",
            "signature": "e30",
            "userHandle": null,
        }
    })
}

fn terminal_claim() -> axum::http::request::Builder {
    Request::builder()
        .method("POST")
        .uri("/api/home/cli-mint/claim")
        .header(HOST, "localhost:61180")
}

async fn claim(app: &Router, request_id: &str, secret: &str) -> (StatusCode, String) {
    post_json(
        app,
        terminal_claim(),
        json!({
            "schema": CLAIM_SCHEMA,
            "request_id": request_id,
            "requester_secret": secret,
        }),
    )
    .await
}

async fn cancel(app: &Router, token: &str, request_id: &str) -> (StatusCode, String) {
    post_json(
        app,
        admin_post("/api/home/cli-mint/cancel", token),
        json!({
            "schema": CANCEL_SCHEMA,
            "request_id": request_id,
        }),
    )
    .await
}

async fn approved_request(app: &Router, token: &str) -> String {
    let (status, body) = register(app, SECRET).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let request_id = serde_json::from_str::<Value>(&body).unwrap()["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, body) = begin(app, token, &request_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let challenge = serde_json::from_str::<Value>(&body).unwrap()["options"]["publicKey"]
        ["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, body) = approve(app, token, &request_id, assertion(&challenge, true)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    request_id
}

fn token_life(token: &str) -> (u64, u64) {
    let bytes = URL_SAFE_NO_PAD.decode(token).unwrap();
    let envelope: Value = serde_json::from_slice(&bytes).unwrap();
    (
        envelope["payload"]["iat"].as_u64().unwrap(),
        envelope["payload"]["exp"].as_u64().unwrap(),
    )
}

fn grant_text(body: &str) -> String {
    serde_json::from_str::<Value>(body).unwrap()["grant"]
        .as_str()
        .unwrap()
        .to_string()
}

fn signature_calls(dir: &std::path::Path) -> u64 {
    super::super::gateway_home_token::home_launch_signature_calls_for_test(dir)
}

#[cfg(unix)]
#[tokio::test]
async fn exported_grant_refuses_environment_mint() {
    let _lock = super::home_system::HOME_GATEWAY_TEST_ENV_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let owner = passkey_authority(dir.path());
    let _terminal = EnvGuard::set(crate::runtime_control::GATEWAY_OWNED_HOME_TERMINAL_ENV, "1");
    let _principal = EnvGuard::set(HOME_CLI_AUTH_CONTEXT_PRINCIPAL_ID_ENV, &owner.principal_id);
    let _session = EnvGuard::set(HOME_CLI_AUTH_CONTEXT_SESSION_ID_ENV, &owner.session_id);
    let _proof = EnvGuard::set(
        HOME_CLI_AUTH_CONTEXT_PROOF_BINDING_ID_ENV,
        &owner.proof_binding_id,
    );
    let _grant = EnvGuard::set(HOME_CLI_AUTH_CONTEXT_GRANT_ID_ENV, &owner.grant_id);
    let error = issue_gateway_owned_home_cli_launch_grant(dir.path())
        .expect_err("environment is not a mint");
    assert_eq!(
        error.to_string(),
        "exported home cli grant requires a fresh passkey approval"
    );
}

#[tokio::test]
async fn request_stores_the_secret_hash_only() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let app = app(dir.path());
    let (status, body) = register(&app, SECRET).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).unwrap();
    let request_id = parsed["request_id"].as_str().unwrap();
    let record = record_text(request_id);
    let hash = hex::encode(Sha256::digest(SECRET.as_bytes()));
    assert!(
        record.contains(OPERATION)
            && record.contains(&hash)
            && !record.contains(SECRET)
            && !body.contains(SECRET)
    );
    assert!(!dir.path().join("home-cli-mint").exists());
}

#[tokio::test]
async fn request_refuses_a_short_secret() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let app = app(dir.path());
    let (status, body) = register(&app, "shortkey").await;
    assert_eq!(
        body,
        "cli mint requester secret is not a 43 to 128 character base64url value"
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg(unix)]
#[tokio::test]
async fn begin_refuses_a_guest() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let guest = passkey_authority_with_name_role(
        dir.path(),
        Some("guest"),
        crate::auth::RuntimePrincipalRole::Guest,
    );
    let app = app(dir.path());
    let (registered, body) = register(&app, SECRET).await;
    assert_eq!(registered, StatusCode::OK, "{body}");
    let request_id = serde_json::from_str::<Value>(&body).unwrap()["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, body) = begin(&app, &guest.home_token, &request_id).await;
    assert_eq!(body, "admin passkey required");
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[cfg(unix)]
#[tokio::test]
async fn begin_refuses_an_agent_home_token() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let token = agent_home_token(dir.path());
    let app = app(dir.path());
    let (registered, body) = register(&app, SECRET).await;
    assert_eq!(registered, StatusCode::OK, "{body}");
    let request_id = serde_json::from_str::<Value>(&body).unwrap()["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, body) = begin(&app, &token, &request_id).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, "Gateway request requires an admitted host and caller");
}

#[cfg(unix)]
#[tokio::test]
async fn approve_refuses_a_different_owner_session() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let owner = software_owner(dir.path());
    let other = passkey_authority(dir.path());
    let app = app(dir.path());
    let (registered, body) = register(&app, SECRET).await;
    assert_eq!(registered, StatusCode::OK, "{body}");
    let request_id = serde_json::from_str::<Value>(&body).unwrap()["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, body) = begin(&app, &owner.home_token, &request_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = approve(&app, &other.home_token, &request_id, dummy_assertion()).await;
    assert_eq!(body, "cli mint owner session mismatch");
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[cfg(unix)]
#[tokio::test]
async fn bad_signature_does_not_approve() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let owner = software_owner(dir.path());
    let app = app(dir.path());
    let (registered, body) = register(&app, SECRET).await;
    assert_eq!(registered, StatusCode::OK, "{body}");
    let request_id = serde_json::from_str::<Value>(&body).unwrap()["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, body) = begin(&app, &owner.home_token, &request_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let challenge = serde_json::from_str::<Value>(&body).unwrap()["options"]["publicKey"]
        ["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, body) = approve(
        &app,
        &owner.home_token,
        &request_id,
        assertion(&challenge, false),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("Signature verification failed"), "{body}");
    let record: Value = serde_json::from_str(&record_text(&request_id)).unwrap();
    assert_eq!(record["state"], "refused");
}

#[cfg(unix)]
#[tokio::test]
async fn fresh_assertion_approves_without_a_launch_grant() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let owner = software_owner(dir.path());
    let app = app(dir.path());
    let (registered, body) = register(&app, SECRET).await;
    assert_eq!(registered, StatusCode::OK, "{body}");
    let request_id = serde_json::from_str::<Value>(&body).unwrap()["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, body) = begin(&app, &owner.home_token, &request_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let challenge = serde_json::from_str::<Value>(&body).unwrap()["options"]["publicKey"]
        ["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, body) = approve(
        &app,
        &owner.home_token,
        &request_id,
        assertion(&challenge, true),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["status"], "approved");
    let record = record_text(&request_id);
    assert!(!body.contains(LAUNCH_TOKEN) && !record.contains(LAUNCH_TOKEN));
}

#[test]
fn cli_mint_source_calls_the_existing_signer_once() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/api/gateway_home_cli_mint.rs"),
    )
    .unwrap();
    assert_eq!(source.matches("issue_home_launch_token_at(").count(), 1);
    let hash_fn = source
        .split_once("fn secret_hash_matches")
        .expect("secret hash compare")
        .1
        .split_once("\nstruct ")
        .expect("secret hash compare ends")
        .0;
    assert!(
        hash_fn.contains(".ct_eq("),
        "secret hash compare is not constant time"
    );
    assert!(
        !hash_fn.contains("!="),
        "secret hash compare uses a variable-time operator"
    );
    assert!(!source.contains("issue_home_cli_launch_grant"));
    assert!(!source.contains("issue_home_projection_launch_token"));
    assert!(!source.contains("issue_home_launch_token_with_context"));
    assert!(!source.contains("issue_home_launch_token_for_"));
    assert!(!source.contains("issue_local_runtime_home_launch_token"));
}

#[cfg(unix)]
#[tokio::test]
async fn second_approve_is_already_decided() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let owner = software_owner(dir.path());
    let app = app(dir.path());
    let (registered, body) = register(&app, SECRET).await;
    assert_eq!(registered, StatusCode::OK, "{body}");
    let request_id = serde_json::from_str::<Value>(&body).unwrap()["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, body) = begin(&app, &owner.home_token, &request_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let challenge = serde_json::from_str::<Value>(&body).unwrap()["options"]["publicKey"]
        ["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let response = assertion(&challenge, true);
    let (status, body) = approve(&app, &owner.home_token, &request_id, response.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = approve(&app, &owner.home_token, &request_id, response).await;
    assert_eq!(body, "cli mint request is already decided");
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg(unix)]
#[tokio::test]
async fn begin_refuses_an_expired_request() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let owner = software_owner(dir.path());
    let app = app(dir.path());
    let (registered, body) = register(&app, SECRET).await;
    assert_eq!(registered, StatusCode::OK, "{body}");
    let request_id = serde_json::from_str::<Value>(&body).unwrap()["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    super::super::gateway_home_cli_mint::cli_mint_expire_for_test(&request_id);
    let (status, body) = begin(&app, &owner.home_token, &request_id).await;
    assert_eq!(body, "cli mint request expired");
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn request_refuses_a_null_origin() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let app = app(dir.path());
    let request = Request::builder()
        .method("POST")
        .uri("/api/home/cli-mint/request")
        .header(HOST, "localhost:61180")
        .header("origin", "null");
    let (status, body) = post_json(
        &app,
        request,
        json!({
            "schema": REQUEST_SCHEMA,
            "requester_secret": SECRET,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn request_refuses_past_capacity() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let app = app(dir.path());
    for index in 0..32 {
        let (status, body) = register(&app, SECRET).await;
        assert_eq!(status, StatusCode::OK, "{index} {body}");
    }
    let (status, body) = register(&app, SECRET).await;
    assert!(status == StatusCode::TOO_MANY_REQUESTS && body.contains("capacity"));
}

#[cfg(unix)]
#[tokio::test]
async fn approve_before_begin_is_not_waiting() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let owner = software_owner(dir.path());
    let app = app(dir.path());
    let (registered, body) = register(&app, SECRET).await;
    assert_eq!(registered, StatusCode::OK, "{body}");
    let request_id = serde_json::from_str::<Value>(&body).unwrap()["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, body) = approve(&app, &owner.home_token, &request_id, dummy_assertion()).await;
    assert_eq!(body, "cli mint request is not waiting for approval");
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg(unix)]
#[tokio::test]
async fn second_begin_is_already_waiting() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let owner = software_owner(dir.path());
    let app = app(dir.path());
    let (registered, body) = register(&app, SECRET).await;
    assert_eq!(registered, StatusCode::OK, "{body}");
    let request_id = serde_json::from_str::<Value>(&body).unwrap()["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, body) = begin(&app, &owner.home_token, &request_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = begin(&app, &owner.home_token, &request_id).await;
    assert_eq!(body, "cli mint request is already waiting for approval");
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[cfg(unix)]
#[tokio::test]
async fn disk_record_cannot_make_a_request_approved() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let owner = software_owner(dir.path());
    let app = app(dir.path());
    let (status, body) = register(&app, SECRET).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let request_id = serde_json::from_str::<Value>(&body).unwrap()["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    let root = dir.path().join("home-cli-mint");
    assert!(!root.exists(), "cli mint state must not be a directory");
    let now = crate::auth::now_ts();
    let forged_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let record = |id: &str| {
        json!({
            "schema": "elastos.home.cli-mint.record/v1",
            "request_id": id,
            "secret_sha256": hex::encode(Sha256::digest(SECRET.as_bytes())),
            "operation": OPERATION,
            "created_at": now,
            "expires_at": now.saturating_add(120),
            "principal_id": owner.principal_id,
            "session_id": owner.session_id,
            "proof_binding_id": owner.proof_binding_id,
            "grant_id": owner.grant_id,
            "ceremony_id": "cli-mint:forged",
            "state": "approved",
        })
    };
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join(format!("{request_id}.json")),
        serde_json::to_vec(&record(&request_id)).unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.join(format!("{forged_id}.json")),
        serde_json::to_vec(&record(forged_id)).unwrap(),
    )
    .unwrap();
    let stored: Value = serde_json::from_str(&record_text(&request_id)).unwrap();
    assert_eq!(stored["state"], "pending");
    let (status, body) = begin(&app, &owner.home_token, &request_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let stored: Value = serde_json::from_str(&record_text(&request_id)).unwrap();
    assert_eq!(stored["state"], "begun");
    let (status, body) = begin(&app, &owner.home_token, forged_id).await;
    assert_eq!(body, "cli mint request is not waiting for approval");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = claim(&app, forged_id, SECRET).await;
    assert_eq!(body, "cli mint request is not waiting for approval");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!body.contains(LAUNCH_TOKEN));
}

#[cfg(unix)]
#[tokio::test]
async fn request_refuses_a_capsule_token_with_a_null_origin() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let app = app(dir.path());
    let token = issue_home_launch_token(dir.path(), "assistant").unwrap();
    let request = test_browser_request("localhost:61180", "null")
        .method("POST")
        .uri("/api/home/cli-mint/request")
        .header("x-elastos-home-token", token);
    let (status, body) = post_json(
        &app,
        request,
        json!({
            "schema": REQUEST_SCHEMA,
            "requester_secret": SECRET,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body, "cli mint request origin is refused");
    assert!(!dir.path().join("home-cli-mint").exists());
}

#[tokio::test]
async fn claim_after_approve_returns_a_grant_that_verifies() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let owner = software_owner(dir.path());
    let app = app(dir.path());
    let request_id = approved_request(&app, &owner.home_token).await;
    let before = signature_calls(dir.path());
    let (status, body) = claim(&app, &request_id, SECRET).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(signature_calls(dir.path()), before + 1);
    let parsed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["status"], "delivered");
    assert!(!body.contains(SECRET));
    let grant = grant_text(&body);
    let verified = require_carried_home_launch_token(dir.path(), &grant, &["home-cli"]).unwrap();
    assert_eq!(verified.launch_context.selected_resource, "home-launch");
    assert_eq!(verified.launch_context.executable_actor, "home-cli");
    assert_eq!(verified.context.principal_id(), owner.principal_id.as_str());
    let (iat, exp) = token_life(&grant);
    assert_eq!(verified.expires_at, exp);
    assert!(
        exp > iat && exp - iat <= EXPORT_TTL_SECS,
        "grant lifetime {} seconds",
        exp - iat
    );
    let record = record_text(&request_id);
    assert!(record.contains("delivered") && !record.contains(SECRET) && !record.contains(&grant));
    assert!(!dir.path().join("home-cli-mint").exists());
}

#[tokio::test]
async fn second_claim_fails() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let owner = software_owner(dir.path());
    let app = app(dir.path());
    let request_id = approved_request(&app, &owner.home_token).await;
    let (status, body) = claim(&app, &request_id, SECRET).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let before = signature_calls(dir.path());
    let (status, body) = claim(&app, &request_id, SECRET).await;
    assert_eq!(body, "cli mint grant was already delivered");
    assert_eq!(signature_calls(dir.path()), before);
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn claim_refuses_a_wrong_secret() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let owner = software_owner(dir.path());
    let app = app(dir.path());
    let request_id = approved_request(&app, &owner.home_token).await;
    let before = signature_calls(dir.path());
    let (status, body) = claim(&app, &request_id, WRONG_SECRET).await;
    assert_eq!(body, "cli mint requester secret does not match");
    assert_eq!(signature_calls(dir.path()), before);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let record: Value = serde_json::from_str(&record_text(&request_id)).unwrap();
    assert_eq!(record["state"], "approved");
}

#[tokio::test]
async fn claim_refuses_a_mismatched_session() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let owner = software_owner(dir.path());
    let app = app(dir.path());
    let request_id = approved_request(&app, &owner.home_token).await;
    rewrite_record(&request_id, "session_id", "auth:mismatched-session");
    let before = signature_calls(dir.path());
    let (status, body) = claim(&app, &request_id, SECRET).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, "cli mint owner session mismatch");
    assert_eq!(
        signature_calls(dir.path()),
        before,
        "signer ran before the bound session match"
    );
    let record: Value = serde_json::from_str(&record_text(&request_id)).unwrap();
    assert_eq!(record["state"], "approved");
}

#[tokio::test]
async fn claim_before_approve_fails() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let owner = software_owner(dir.path());
    let app = app(dir.path());
    let request_id = approved_request(&app, &owner.home_token).await;
    rewrite_record(&request_id, "state", "pending");
    let before = signature_calls(dir.path());
    let (status, body) = claim(&app, &request_id, SECRET).await;
    assert_eq!(body, "cli mint request is not approved");
    assert_eq!(signature_calls(dir.path()), before);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (registered, body) = register(&app, SECRET).await;
    assert_eq!(registered, StatusCode::OK, "{body}");
    let pending = serde_json::from_str::<Value>(&body).unwrap()["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, body) = claim(&app, &pending, SECRET).await;
    assert_eq!(body, "cli mint request is not approved");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = begin(&app, &owner.home_token, &pending).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = claim(&app, &pending, SECRET).await;
    assert_eq!(body, "cli mint request is not approved");
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn grant_older_than_five_minutes_fails_the_existing_expiry_check() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let owner = software_owner(dir.path());
    let app = app(dir.path());
    let request_id = approved_request(&app, &owner.home_token).await;
    let _skew = super::super::gateway_home_cli_mint::set_cli_mint_signature_skew_for_test(
        dir.path(),
        -((EXPORT_TTL_SECS + 1) as i64),
    );
    let (status, body) = claim(&app, &request_id, SECRET).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let grant = grant_text(&body);
    let (iat, exp) = token_life(&grant);
    assert!(exp > iat && exp - iat <= EXPORT_TTL_SECS);
    assert!(crate::auth::now_ts().saturating_sub(iat) > EXPORT_TTL_SECS);
    let error = require_carried_home_launch_token(dir.path(), &grant, &["home-cli"])
        .expect_err("a grant older than 5 minutes is expired");
    assert_eq!(error.to_string(), "home launch token expired");
}

#[tokio::test]
async fn cancel_then_claim_fails() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let owner = software_owner(dir.path());
    let app = app(dir.path());
    let request_id = approved_request(&app, &owner.home_token).await;
    let before = signature_calls(dir.path());
    let (status, body) = cancel(&app, &owner.home_token, &request_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["status"], "cancelled");
    assert!(!body.contains(LAUNCH_TOKEN));
    let (status, body) = claim(&app, &request_id, SECRET).await;
    assert_eq!(body, "cli mint request was cancelled");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(signature_calls(dir.path()), before);
    let record = record_text(&request_id);
    assert!(record.contains("cancelled") && !record.contains(LAUNCH_TOKEN));
}

#[tokio::test]
async fn claim_refuses_an_expired_request() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let owner = software_owner(dir.path());
    let app = app(dir.path());
    let request_id = approved_request(&app, &owner.home_token).await;
    super::super::gateway_home_cli_mint::cli_mint_expire_for_test(&request_id);
    let before = signature_calls(dir.path());
    let (status, body) = claim(&app, &request_id, SECRET).await;
    assert_eq!(body, "cli mint request expired");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(signature_calls(dir.path()), before);
    let record: Value = serde_json::from_str(&record_text(&request_id)).unwrap();
    assert_eq!(record["state"], "approved");
}

#[tokio::test]
async fn claim_refuses_a_mismatched_principal_proof_or_grant() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let owner = software_owner(dir.path());
    let other = passkey_authority(dir.path());
    let app = app(dir.path());
    let request_id = approved_request(&app, &owner.home_token).await;
    let saved: Value = serde_json::from_str(&record_text(&request_id)).unwrap();
    let replacements = [
        (
            "principal_id",
            other.principal_id.as_str(),
            saved["principal_id"].as_str().unwrap(),
        ),
        (
            "proof_binding_id",
            other.proof_binding_id.as_str(),
            saved["proof_binding_id"].as_str().unwrap(),
        ),
        (
            "grant_id",
            other.grant_id.as_str(),
            saved["grant_id"].as_str().unwrap(),
        ),
    ];
    for (field, value, original) in replacements {
        rewrite_record(&request_id, field, value);
        let before = signature_calls(dir.path());
        let (status, body) = claim(&app, &request_id, SECRET).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{field} {body}");
        assert_eq!(body, "cli mint owner session mismatch", "{field}");
        assert_eq!(signature_calls(dir.path()), before, "{field}");
        let record: Value = serde_json::from_str(&record_text(&request_id)).unwrap();
        assert_eq!(record["state"], "approved", "{field}");
        rewrite_record(&request_id, field, original);
    }
}

#[tokio::test]
async fn claim_checks_the_secret_before_the_state() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let owner = software_owner(dir.path());
    let app = app(dir.path());
    let (status, body) = register(&app, SECRET).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let pending = serde_json::from_str::<Value>(&body).unwrap()["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, body) = claim(&app, &pending, WRONG_SECRET).await;
    assert_eq!(body, "cli mint requester secret does not match");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    super::super::gateway_home_cli_mint::cli_mint_expire_for_test(&pending);
    let (status, body) = claim(&app, &pending, WRONG_SECRET).await;
    assert_eq!(body, "cli mint requester secret does not match");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let request_id = approved_request(&app, &owner.home_token).await;
    let (status, body) = claim(&app, &request_id, SECRET).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let before = signature_calls(dir.path());
    let (status, body) = claim(&app, &request_id, WRONG_SECRET).await;
    assert_eq!(body, "cli mint requester secret does not match");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(signature_calls(dir.path()), before);
}

#[tokio::test]
async fn cancel_by_another_admin_session_is_refused() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let owner = software_owner(dir.path());
    let other = passkey_authority(dir.path());
    let app = app(dir.path());
    let approved = approved_request(&app, &owner.home_token).await;
    let before = signature_calls(dir.path());
    let (status, body) = cancel(&app, &other.home_token, &approved).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body, "cli mint owner session mismatch");
    assert_eq!(signature_calls(dir.path()), before);
    let record: Value = serde_json::from_str(&record_text(&approved)).unwrap();
    assert_eq!(record["state"], "approved");
    let (status, body) = register(&app, SECRET).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let begun = serde_json::from_str::<Value>(&body).unwrap()["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, body) = begin(&app, &owner.home_token, &begun).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = cancel(&app, &other.home_token, &begun).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body, "cli mint owner session mismatch");
    let record: Value = serde_json::from_str(&record_text(&begun)).unwrap();
    assert_eq!(record["state"], "begun");
}

#[tokio::test]
async fn claim_refuses_a_null_origin_with_a_launch_token() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let owner = software_owner(dir.path());
    let app = app(dir.path());
    let request_id = approved_request(&app, &owner.home_token).await;
    let token = issue_home_launch_token(dir.path(), "assistant").unwrap();
    let before = signature_calls(dir.path());
    let request = test_browser_request("localhost:61180", "null")
        .method("POST")
        .uri("/api/home/cli-mint/claim")
        .header("x-elastos-home-token", token);
    let (status, body) = post_json(
        &app,
        request,
        json!({
            "schema": CLAIM_SCHEMA,
            "request_id": request_id,
            "requester_secret": SECRET,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body, "cli mint request origin is refused");
    assert_eq!(signature_calls(dir.path()), before);
    let record: Value = serde_json::from_str(&record_text(&request_id)).unwrap();
    assert_eq!(record["state"], "approved");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_concurrent_claims_sign_once() {
    let _mint = mint_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let owner = software_owner(dir.path());
    let app = app(dir.path());
    let request_id = approved_request(&app, &owner.home_token).await;
    let before = signature_calls(dir.path());
    let _overlap = super::super::gateway_home_cli_mint::arm_cli_mint_overlap_for_test(&request_id);
    let app_left = app.clone();
    let app_right = app.clone();
    let id_left = request_id.clone();
    let id_right = request_id.clone();
    let mut left = tokio::spawn(async move { claim(&app_left, &id_left, SECRET).await });
    let mut right = tokio::spawn(async move { claim(&app_right, &id_right, SECRET).await });
    let started = std::time::Instant::now();
    loop {
        let arrived = super::super::gateway_home_cli_mint::cli_mint_overlap_arrived_for_test();
        assert!(arrived < 2, "two claims reached the signer");
        if arrived == 1 || started.elapsed() > std::time::Duration::from_secs(5) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        super::super::gateway_home_cli_mint::cli_mint_overlap_arrived_for_test(),
        1,
        "one claim should be waiting at the signer"
    );
    let (which, loser) = tokio::select! {
        result = &mut left => ("left", result.expect("left claim")),
        result = &mut right => ("right", result.expect("right claim")),
        _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
            panic!("the second claim did not finish while the first waited at the signer");
        }
    };
    assert_eq!(
        super::super::gateway_home_cli_mint::cli_mint_overlap_arrived_for_test(),
        1,
        "two claims reached the signer"
    );
    assert_ne!(loser.0, StatusCode::OK, "{}", loser.1);
    assert!(!loser.1.contains(LAUNCH_TOKEN), "{}", loser.1);
    super::super::gateway_home_cli_mint::release_cli_mint_overlap_for_test();
    let winner = if which == "left" {
        right.await.expect("winning claim")
    } else {
        left.await.expect("winning claim")
    };
    assert_eq!(winner.0, StatusCode::OK, "{}", winner.1);
    assert_eq!(signature_calls(dir.path()), before + 1);
    let record: Value = serde_json::from_str(&record_text(&request_id)).unwrap();
    assert_eq!(record["state"], "delivered");
}
