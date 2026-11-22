//! Passkey approval for an exported Home CLI grant. These tests use the real
//! routes. The software passkey is the same in-process p256 authenticator the
//! identity crate uses. Slice 1 records the approval and does not sign a grant.

use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

const SECRET: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg";
const ORIGIN: &str = "http://localhost:61180";
const RP_ID: &str = "localhost";
const CREDENTIAL_ID: &str = "cli-mint-owner";
const REQUEST_SCHEMA: &str = "elastos.home.cli-mint.request/v1";
const BEGIN_SCHEMA: &str = "elastos.home.cli-mint.begin/v1";
const APPROVE_SCHEMA: &str = "elastos.home.cli-mint.approve/v1";
const OPERATION: &str = "home-cli.export-grant";
const LAUNCH_TOKEN: &str = "elastos.home.launch-token";

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

fn record_text(dir: &std::path::Path, request_id: &str) -> String {
    std::fs::read_to_string(
        super::super::gateway_home_cli_mint::cli_mint_record_path_for_test(dir, request_id),
    )
    .unwrap()
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
    let dir = tempfile::tempdir().unwrap();
    let app = app(dir.path());
    let (status, body) = register(&app, SECRET).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).unwrap();
    let request_id = parsed["request_id"].as_str().unwrap();
    let record = record_text(dir.path(), request_id);
    let hash = hex::encode(Sha256::digest(SECRET.as_bytes()));
    assert!(
        record.contains(OPERATION)
            && record.contains(&hash)
            && !record.contains(SECRET)
            && !body.contains(SECRET)
    );
}

#[tokio::test]
async fn request_refuses_a_short_secret() {
    let dir = tempfile::tempdir().unwrap();
    let app = app(dir.path());
    let (status, body) = register(&app, "shortkey").await;
    assert_eq!(
        body,
        "cli mint requester secret is not a 43 to 128 character base64url value"
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn begin_refuses_a_guest() {
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

#[tokio::test]
async fn begin_refuses_an_agent_home_token() {
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

#[tokio::test]
async fn approve_refuses_a_different_owner_session() {
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

#[tokio::test]
async fn bad_signature_does_not_approve() {
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
    let record: Value = serde_json::from_str(&record_text(dir.path(), &request_id)).unwrap();
    assert!(body.contains("Signature verification failed") && record["state"] != "approved");
}

#[tokio::test]
async fn fresh_assertion_approves_without_a_launch_grant() {
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
    let record = record_text(dir.path(), &request_id);
    assert!(!body.contains(LAUNCH_TOKEN) && !record.contains(LAUNCH_TOKEN));
}

#[test]
fn cli_mint_source_does_not_name_an_issuer() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/api/gateway_home_cli_mint.rs"),
    )
    .unwrap();
    assert!(
        !source.contains("issue_home_cli_launch_grant")
            && !source.contains("issue_home_projection_launch_token")
            && !source.contains("issue_home_launch_token")
    );
}

#[tokio::test]
async fn second_approve_is_already_decided() {
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

#[tokio::test]
async fn begin_refuses_an_expired_request() {
    let dir = tempfile::tempdir().unwrap();
    let owner = software_owner(dir.path());
    let app = app(dir.path());
    let (registered, body) = register(&app, SECRET).await;
    assert_eq!(registered, StatusCode::OK, "{body}");
    let request_id = serde_json::from_str::<Value>(&body).unwrap()["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    let path =
        super::super::gateway_home_cli_mint::cli_mint_record_path_for_test(dir.path(), &request_id);
    let mut record: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    record["created_at"] = json!(1);
    record["expires_at"] = json!(2);
    std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    let (status, body) = begin(&app, &owner.home_token, &request_id).await;
    assert_eq!(body, "cli mint request expired");
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn request_refuses_a_null_origin() {
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
    let dir = tempfile::tempdir().unwrap();
    let app = app(dir.path());
    for index in 0..32 {
        let (status, body) = register(&app, SECRET).await;
        assert_eq!(status, StatusCode::OK, "{index} {body}");
    }
    let (status, body) = register(&app, SECRET).await;
    assert!(status == StatusCode::TOO_MANY_REQUESTS && body.contains("capacity"));
}

#[tokio::test]
async fn approve_before_begin_is_not_waiting() {
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

#[tokio::test]
async fn second_begin_is_already_waiting() {
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
