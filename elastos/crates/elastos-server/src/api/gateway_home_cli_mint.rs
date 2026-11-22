//! Bound request and passkey approval for an exported Home CLI grant.
//!
//! A terminal registers a request. The signed-in human admin approves it with
//! a fresh passkey assertion. This module does not sign a launch grant.
//!
//! The request table lives only in this process. A same-user process can write
//! the data directory, so a file there is not an approval. A gateway restart
//! drops every waiting request. The table holds 32 live requests for 120 seconds.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use elastos_identity::{AuthenticationResponse, CredentialDescriptor, RequestOptions};
use sha2::{Digest, Sha256};

use super::*;

const REQUEST_SCHEMA: &str = "elastos.home.cli-mint.request/v1";
const BEGIN_SCHEMA: &str = "elastos.home.cli-mint.begin/v1";
const APPROVE_SCHEMA: &str = "elastos.home.cli-mint.approve/v1";
const RECORD_SCHEMA: &str = "elastos.home.cli-mint.record/v1";
const REQUEST_RESULT_SCHEMA: &str = "elastos.home.cli-mint.request.result/v1";
const BEGIN_RESULT_SCHEMA: &str = "elastos.home.cli-mint.begin.result/v1";
const APPROVE_RESULT_SCHEMA: &str = "elastos.home.cli-mint.approve.result/v1";
const OPERATION: &str = "home-cli.export-grant";
const REQUEST_TTL_SECS: u64 = 120;
const CAPACITY: usize = 32;
const STATE_PENDING: &str = "pending";
const STATE_BEGUN: &str = "begun";
const STATE_APPROVED: &str = "approved";
const STATE_REFUSED: &str = "refused";

const HUMAN_REQUIRED: &str = "a human Home owner is required";
const SESSION_MISMATCH: &str = "cli mint owner session mismatch";
const NOT_WAITING: &str = "cli mint request is not waiting for approval";
const ALREADY_DECIDED: &str = "cli mint request is already decided";
const ALREADY_WAITING: &str = "cli mint request is already waiting for approval";
const EXPIRED: &str = "cli mint request expired";
const MISMATCH: &str = "cli mint request mismatch";
const ORIGIN_MISMATCH: &str = "cli mint passkey origin mismatch";
const REQUEST_ORIGIN_REFUSED: &str = "cli mint request origin is refused";
const CREDENTIAL_UNAVAILABLE: &str = "cli mint passkey credential is unavailable";
const DIFFERENT_PASSKEY: &str = "cli mint used a different registered passkey";
const CAPACITY_ERROR: &str = "cli mint request capacity";

struct MintTable {
    records: HashMap<String, MintRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RequestBody {
    schema: String,
    requester_secret: String,
}

#[derive(Debug, Serialize)]
struct RequestResult {
    schema: String,
    request_id: String,
    expires_at: u64,
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BeginBody {
    schema: String,
    request_id: String,
}

#[derive(Debug, Serialize)]
struct BeginResult {
    schema: String,
    request_id: String,
    options: RequestOptions,
    expires_at: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApproveBody {
    schema: String,
    request_id: String,
    response: AuthenticationResponse,
}

#[derive(Debug, Serialize)]
struct ApproveResult {
    schema: String,
    request_id: String,
    status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MintRecord {
    schema: String,
    request_id: String,
    secret_sha256: String,
    operation: String,
    created_at: u64,
    expires_at: u64,
    principal_id: Option<String>,
    session_id: Option<String>,
    proof_binding_id: Option<String>,
    grant_id: Option<String>,
    ceremony_id: Option<String>,
    state: String,
}

pub(super) async fn home_cli_mint_request(
    headers: HeaderMap,
    Json(input): Json<RequestBody>,
) -> Response {
    if !super::gateway_frontdoor::cli_mint_request_origin_allowed(&headers) {
        return mint_error(anyhow::anyhow!(REQUEST_ORIGIN_REFUSED));
    }
    match create_request(input) {
        Ok(body) => Json(body).into_response(),
        Err(err) => mint_error(err),
    }
}

pub(super) async fn home_cli_mint_begin(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(input): Json<BeginBody>,
) -> Response {
    match begin_request(&state, &headers, input).await {
        Ok(body) => Json(body).into_response(),
        Err(err) => mint_error(err),
    }
}

pub(super) async fn home_cli_mint_approve(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(input): Json<ApproveBody>,
) -> Response {
    match approve_request(&state, &headers, input).await {
        Ok(body) => Json(body).into_response(),
        Err(err) => mint_error(err),
    }
}

fn home_admin_context(
    data_dir: &Path,
    headers: &HeaderMap,
) -> anyhow::Result<HomeLaunchTokenContext> {
    let context = require_home_token_context(data_dir, headers)?;
    if context.root().kind() != Some(crate::auth::PrincipalKind::Human) {
        anyhow::bail!(HUMAN_REQUIRED);
    }
    require_admin_principal(&home_launch_auth_data_dir(data_dir), &context)?;
    Ok(context)
}

fn create_request(input: RequestBody) -> anyhow::Result<RequestResult> {
    if input.schema != REQUEST_SCHEMA {
        anyhow::bail!("unsupported cli mint request schema");
    }
    valid_secret(&input.requester_secret)?;
    let mut table = mint_table()?;
    let now = now_ts();
    table.records.retain(|_, record| now < record.expires_at);
    if table.records.len() >= CAPACITY {
        anyhow::bail!(CAPACITY_ERROR);
    }
    let request_id = gateway_home_token::uuid_like_token();
    let record = MintRecord {
        schema: RECORD_SCHEMA.to_string(),
        request_id: request_id.clone(),
        secret_sha256: hex::encode(Sha256::digest(input.requester_secret.as_bytes())),
        operation: OPERATION.to_string(),
        created_at: now,
        expires_at: now.saturating_add(REQUEST_TTL_SECS),
        principal_id: None,
        session_id: None,
        proof_binding_id: None,
        grant_id: None,
        ceremony_id: None,
        state: STATE_PENDING.to_string(),
    };
    let expires_at = record.expires_at;
    table.records.insert(request_id.clone(), record);
    Ok(RequestResult {
        schema: REQUEST_RESULT_SCHEMA.to_string(),
        request_id,
        expires_at,
        status: STATE_PENDING.to_string(),
    })
}

async fn begin_request(
    state: &GatewayState,
    headers: &HeaderMap,
    input: BeginBody,
) -> anyhow::Result<BeginResult> {
    if input.schema != BEGIN_SCHEMA {
        anyhow::bail!("unsupported cli mint begin schema");
    }
    let context = home_admin_context(&state.data_dir, headers)?;
    let passkey = passkey_for_context(&state.data_dir, &context)?;
    let rp = super::super::handlers::identity::derive_rp(headers)?;
    if passkey.rp_id != rp.id
        || passkey.origin.trim_end_matches('/') != rp.origin.trim_end_matches('/')
    {
        anyhow::bail!(ORIGIN_MISMATCH);
    }
    let manager = state.identity_manager()?;
    let mut manager = manager.lock().await;
    let mut table = mint_table()?;
    let now = now_ts();
    let mut record = load_record(&table, &input.request_id, now)?;
    if record.state != STATE_PENDING {
        anyhow::bail!(if record.state == STATE_BEGUN {
            ALREADY_WAITING
        } else {
            ALREADY_DECIDED
        });
    }
    let matches = manager
        .credentials()
        .into_iter()
        .filter(|credential| {
            credential.credential_id == passkey.credential_id
                && credential.rp_id == passkey.rp_id
                && credential.public_key == passkey.public_key
        })
        .count();
    if matches != 1 {
        anyhow::bail!(CREDENTIAL_UNAVAILABLE);
    }
    let ceremony_id = format!("cli-mint:{}", gateway_home_token::uuid_like_token());
    let mut options = manager.begin_authentication(&ceremony_id, &rp.id)?;
    options.public_key.allow_credentials = vec![CredentialDescriptor {
        type_: "public-key".to_string(),
        id: passkey.credential_id,
    }];
    options.public_key.timeout = REQUEST_TTL_SECS * 1000;
    options.public_key.user_verification = "required".to_string();
    record.principal_id = Some(context.principal_id().to_string());
    record.session_id = Some(context.session_id().to_string());
    record.proof_binding_id = context.proof_binding_id().map(str::to_string);
    record.grant_id = Some(context.grant_id().to_string());
    record.ceremony_id = Some(ceremony_id);
    record.state = STATE_BEGUN.to_string();
    let request_id = record.request_id.clone();
    let expires_at = record.expires_at;
    table.records.insert(request_id.clone(), record);
    Ok(BeginResult {
        schema: BEGIN_RESULT_SCHEMA.to_string(),
        request_id,
        options,
        expires_at,
    })
}

async fn approve_request(
    state: &GatewayState,
    headers: &HeaderMap,
    input: ApproveBody,
) -> anyhow::Result<ApproveResult> {
    if input.schema != APPROVE_SCHEMA {
        anyhow::bail!("unsupported cli mint approve schema");
    }
    let context = home_admin_context(&state.data_dir, headers)?;
    let passkey = passkey_for_context(&state.data_dir, &context)?;
    let rp = super::super::handlers::identity::derive_rp(headers)?;
    let manager = state.identity_manager()?;
    let mut manager = manager.lock().await;
    let mut table = mint_table()?;
    let now = now_ts();
    let mut record = load_record(&table, &input.request_id, now)?;
    if record.state != STATE_BEGUN {
        anyhow::bail!(if record.state == STATE_PENDING {
            NOT_WAITING
        } else {
            ALREADY_DECIDED
        });
    }
    if record.principal_id.as_deref() != Some(context.principal_id())
        || record.session_id.as_deref() != Some(context.session_id())
        || record.proof_binding_id.as_deref() != context.proof_binding_id()
        || record.grant_id.as_deref() != Some(context.grant_id())
    {
        anyhow::bail!(SESSION_MISMATCH);
    }
    if passkey.rp_id != rp.id
        || passkey.origin.trim_end_matches('/') != rp.origin.trim_end_matches('/')
    {
        anyhow::bail!(ORIGIN_MISMATCH);
    }
    let ceremony_id = record
        .ceremony_id
        .clone()
        .filter(|value| value.starts_with("cli-mint:"))
        .ok_or_else(|| anyhow::anyhow!(MISMATCH))?;
    if input.response.raw_id != passkey.credential_id {
        mark_refused(&mut table, &mut record);
        anyhow::bail!(DIFFERENT_PASSKEY);
    }
    let outcome = match manager.complete_authentication(
        &ceremony_id,
        &input.response,
        &passkey.rp_id,
        &passkey.origin,
    ) {
        Ok(outcome) => outcome,
        Err(err) => {
            mark_refused(&mut table, &mut record);
            return Err(err);
        }
    };
    if !outcome.user_verified
        || outcome.credential.credential_id != passkey.credential_id
        || outcome.credential.rp_id != passkey.rp_id
        || outcome.credential.public_key != passkey.public_key
    {
        mark_refused(&mut table, &mut record);
        anyhow::bail!(DIFFERENT_PASSKEY);
    }
    record.state = STATE_APPROVED.to_string();
    let request_id = record.request_id.clone();
    table.records.insert(request_id.clone(), record);
    Ok(ApproveResult {
        schema: APPROVE_RESULT_SCHEMA.to_string(),
        request_id,
        status: STATE_APPROVED.to_string(),
    })
}

fn mark_refused(table: &mut MintTable, record: &mut MintRecord) {
    record.state = STATE_REFUSED.to_string();
    table
        .records
        .insert(record.request_id.clone(), record.clone());
}

fn passkey_for_context(
    data_dir: &Path,
    context: &HomeLaunchTokenContext,
) -> anyhow::Result<elastos_runtime::auth::PasskeyWebAuthnBinding> {
    let proof_binding_id = context
        .proof_binding_id()
        .ok_or_else(|| anyhow::anyhow!("admin passkey required"))?;
    let principal = crate::auth::load_principal_for_proof_binding(
        &home_launch_auth_data_dir(data_dir),
        proof_binding_id,
    )?;
    principal
        .proof_binding
        .passkey
        .clone()
        .ok_or_else(|| anyhow::anyhow!("admin passkey required"))
}

fn load_record(table: &MintTable, request_id: &str, now: u64) -> anyhow::Result<MintRecord> {
    valid_request_id(request_id)?;
    let record = table
        .records
        .get(request_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!(NOT_WAITING))?;
    if record.schema != RECORD_SCHEMA
        || record.request_id != request_id
        || record.operation != OPERATION
        || record.secret_sha256.len() != 64
        || record.expires_at <= record.created_at
        || !matches!(
            record.state.as_str(),
            STATE_PENDING | STATE_BEGUN | STATE_APPROVED | STATE_REFUSED
        )
    {
        anyhow::bail!(MISMATCH);
    }
    if now >= record.expires_at {
        anyhow::bail!(EXPIRED);
    }
    Ok(record)
}

fn mint_table() -> anyhow::Result<std::sync::MutexGuard<'static, MintTable>> {
    static TABLE: OnceLock<Mutex<MintTable>> = OnceLock::new();
    TABLE
        .get_or_init(|| {
            Mutex::new(MintTable {
                records: HashMap::new(),
            })
        })
        .lock()
        .map_err(|_| anyhow::anyhow!("cli mint state lock is poisoned"))
}

fn valid_request_id(value: &str) -> anyhow::Result<()> {
    if value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Ok(());
    }
    anyhow::bail!(MISMATCH);
}

fn valid_secret(value: &str) -> anyhow::Result<()> {
    if (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Ok(());
    }
    anyhow::bail!("cli mint requester secret is not a 43 to 128 character base64url value");
}

fn mint_error(err: anyhow::Error) -> Response {
    let text = err.to_string();
    let status = if text == HUMAN_REQUIRED
        || text == SESSION_MISMATCH
        || text == REQUEST_ORIGIN_REFUSED
        || text.contains("admin passkey required")
        || text.contains("missing home launch token")
    {
        StatusCode::FORBIDDEN
    } else if text == CAPACITY_ERROR {
        StatusCode::TOO_MANY_REQUESTS
    } else {
        StatusCode::BAD_REQUEST
    };
    (status, text).into_response()
}

#[cfg(test)]
pub(super) fn clear_cli_mint_for_test() {
    mint_table().expect("cli mint state lock").records.clear();
}

#[cfg(test)]
pub(super) fn cli_mint_record_json_for_test(request_id: &str) -> Option<String> {
    mint_table()
        .expect("cli mint state lock")
        .records
        .get(request_id)
        .map(|record| serde_json::to_string(record).expect("cli mint record json"))
}

#[cfg(test)]
pub(super) fn cli_mint_expire_for_test(request_id: &str) {
    let mut table = mint_table().expect("cli mint state lock");
    let record = table.records.get_mut(request_id).expect("cli mint request");
    record.created_at = 1;
    record.expires_at = 2;
}
