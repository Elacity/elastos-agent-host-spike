//! Bound request, passkey approval, and one-time delivery of an exported Home CLI grant.
//!
//! A terminal registers a request. The signed-in human admin approves it with
//! a fresh passkey assertion. The waiting terminal claims the grant once.
//! The claim signs only after that approved record matches the request id,
//! the secret hash, the bound owner, session, proof, grant, and operation.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

use elastos_identity::{AuthenticationResponse, CredentialDescriptor, RequestOptions};
use sha2::{Digest, Sha256};

use super::*;

const REQUEST_SCHEMA: &str = "elastos.home.cli-mint.request/v1";
const BEGIN_SCHEMA: &str = "elastos.home.cli-mint.begin/v1";
const APPROVE_SCHEMA: &str = "elastos.home.cli-mint.approve/v1";
const CLAIM_SCHEMA: &str = "elastos.home.cli-mint.claim/v1";
const CANCEL_SCHEMA: &str = "elastos.home.cli-mint.cancel/v1";
const RECORD_SCHEMA: &str = "elastos.home.cli-mint.record/v1";
const REQUEST_RESULT_SCHEMA: &str = "elastos.home.cli-mint.request.result/v1";
const BEGIN_RESULT_SCHEMA: &str = "elastos.home.cli-mint.begin.result/v1";
const APPROVE_RESULT_SCHEMA: &str = "elastos.home.cli-mint.approve.result/v1";
const CLAIM_RESULT_SCHEMA: &str = "elastos.home.cli-mint.claim.result/v1";
const CANCEL_RESULT_SCHEMA: &str = "elastos.home.cli-mint.cancel.result/v1";
const OPERATION: &str = "home-cli.export-grant";
const DIRECTORY: &str = "home-cli-mint";
const REQUEST_TTL_SECS: u64 = 120;
/// Exported grant lifetime, measured from the signature.
const EXPORT_TTL_SECS: u64 = 5 * 60;
const CAPACITY: usize = 32;
const STATE_PENDING: &str = "pending";
const STATE_BEGUN: &str = "begun";
const STATE_APPROVED: &str = "approved";
const STATE_REFUSED: &str = "refused";
const STATE_CANCELLED: &str = "cancelled";
const STATE_DELIVERED: &str = "delivered";

const HUMAN_REQUIRED: &str = "a human Home owner is required";
const SESSION_MISMATCH: &str = "cli mint owner session mismatch";
const NOT_WAITING: &str = "cli mint request is not waiting for approval";
const ALREADY_DECIDED: &str = "cli mint request is already decided";
const ALREADY_WAITING: &str = "cli mint request is already waiting for approval";
const NOT_APPROVED: &str = "cli mint request is not approved";
const ALREADY_DELIVERED: &str = "cli mint grant was already delivered";
const CANCELLED: &str = "cli mint request was cancelled";
const SECRET_MISMATCH: &str = "cli mint requester secret does not match";
const EXPIRED: &str = "cli mint request expired";
const MISMATCH: &str = "cli mint request mismatch";
const ORIGIN_MISMATCH: &str = "cli mint passkey origin mismatch";
const CREDENTIAL_UNAVAILABLE: &str = "cli mint passkey credential is unavailable";
const DIFFERENT_PASSKEY: &str = "cli mint used a different registered passkey";
const CAPACITY_ERROR: &str = "cli mint request capacity";

static MINT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClaimBody {
    schema: String,
    request_id: String,
    requester_secret: String,
}

#[derive(Debug, Serialize)]
struct ClaimResult {
    schema: String,
    request_id: String,
    status: String,
    grant: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CancelBody {
    schema: String,
    request_id: String,
}

#[derive(Debug, Serialize)]
struct CancelResult {
    schema: String,
    request_id: String,
    status: String,
}

#[derive(Debug, Serialize, Deserialize)]
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
    State(state): State<GatewayState>,
    Json(input): Json<RequestBody>,
) -> Response {
    match create_request(&state.data_dir, input) {
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

pub(super) async fn home_cli_mint_claim(
    State(state): State<GatewayState>,
    Json(input): Json<ClaimBody>,
) -> Response {
    match claim_request(&state.data_dir, input) {
        Ok(body) => Json(body).into_response(),
        Err(err) => mint_error(err),
    }
}

pub(super) async fn home_cli_mint_cancel(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(input): Json<CancelBody>,
) -> Response {
    match cancel_request(&state.data_dir, &headers, input) {
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

fn create_request(data_dir: &Path, input: RequestBody) -> anyhow::Result<RequestResult> {
    if input.schema != REQUEST_SCHEMA {
        anyhow::bail!("unsupported cli mint request schema");
    }
    valid_secret(&input.requester_secret)?;
    let _guard = mint_lock()?;
    let now = now_ts();
    prepare_capacity(data_dir, now)?;
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
    store_record(data_dir, &record)?;
    Ok(RequestResult {
        schema: REQUEST_RESULT_SCHEMA.to_string(),
        request_id,
        expires_at: record.expires_at,
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
    let _guard = mint_lock()?;
    let now = now_ts();
    let mut record = load_record(&state.data_dir, &input.request_id, now)?;
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
    record.ceremony_id = Some(ceremony_id.clone());
    record.state = STATE_BEGUN.to_string();
    if let Err(err) = store_record(&state.data_dir, &record) {
        manager.cancel_challenge(&ceremony_id);
        return Err(err);
    }
    Ok(BeginResult {
        schema: BEGIN_RESULT_SCHEMA.to_string(),
        request_id: record.request_id,
        options,
        expires_at: record.expires_at,
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
    let _guard = mint_lock()?;
    let now = now_ts();
    let mut record = load_record(&state.data_dir, &input.request_id, now)?;
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
        record.state = STATE_REFUSED.to_string();
        store_record(&state.data_dir, &record)?;
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
            record.state = STATE_REFUSED.to_string();
            store_record(&state.data_dir, &record)?;
            return Err(err);
        }
    };
    if !outcome.user_verified
        || outcome.credential.credential_id != passkey.credential_id
        || outcome.credential.rp_id != passkey.rp_id
        || outcome.credential.public_key != passkey.public_key
    {
        record.state = STATE_REFUSED.to_string();
        store_record(&state.data_dir, &record)?;
        anyhow::bail!(DIFFERENT_PASSKEY);
    }
    record.state = STATE_APPROVED.to_string();
    store_record(&state.data_dir, &record)?;
    Ok(ApproveResult {
        schema: APPROVE_RESULT_SCHEMA.to_string(),
        request_id: record.request_id,
        status: STATE_APPROVED.to_string(),
    })
}

fn claim_request(data_dir: &Path, input: ClaimBody) -> anyhow::Result<ClaimResult> {
    if input.schema != CLAIM_SCHEMA {
        anyhow::bail!("unsupported cli mint claim schema");
    }
    valid_secret(&input.requester_secret)?;
    let _guard = mint_lock()?;
    let now = now_ts();
    let mut record = load_record(data_dir, &input.request_id, now)?;
    if record.state != STATE_APPROVED {
        anyhow::bail!(claim_state_error(&record.state));
    }
    if hex::encode(Sha256::digest(input.requester_secret.as_bytes())) != record.secret_sha256 {
        anyhow::bail!(SECRET_MISMATCH);
    }
    if record.request_id != input.request_id {
        anyhow::bail!(MISMATCH);
    }
    bound_export_matches(data_dir, &record)?;
    let context = signing_context(data_dir, &record)?;
    let issued_at = signature_issued_at(data_dir);
    // The existing signer stays after the approved-state, secret, request-id,
    // and bound owner, session, proof, grant, and operation checks.
    let grant = gateway_home_token::issue_home_launch_token_at(
        data_dir,
        &gateway_home_token::HomeLaunchContext::projection("home-launch", HOME_CLI_SHELL_ID),
        &context,
        issued_at,
        Some(issued_at.saturating_add(EXPORT_TTL_SECS)),
    )?;
    record.state = STATE_DELIVERED.to_string();
    store_record(data_dir, &record)?;
    Ok(ClaimResult {
        schema: CLAIM_RESULT_SCHEMA.to_string(),
        request_id: record.request_id,
        status: STATE_DELIVERED.to_string(),
        grant,
    })
}

fn cancel_request(
    data_dir: &Path,
    headers: &HeaderMap,
    input: CancelBody,
) -> anyhow::Result<CancelResult> {
    if input.schema != CANCEL_SCHEMA {
        anyhow::bail!("unsupported cli mint cancel schema");
    }
    let context = home_admin_context(data_dir, headers)?;
    let _guard = mint_lock()?;
    let now = now_ts();
    let mut record = load_record(data_dir, &input.request_id, now)?;
    if matches!(record.state.as_str(), STATE_BEGUN | STATE_APPROVED)
        && !binding_matches_context(&record, &context)
    {
        anyhow::bail!(SESSION_MISMATCH);
    }
    if !matches!(
        record.state.as_str(),
        STATE_PENDING | STATE_BEGUN | STATE_APPROVED
    ) {
        anyhow::bail!(ALREADY_DECIDED);
    }
    record.state = STATE_CANCELLED.to_string();
    store_record(data_dir, &record)?;
    Ok(CancelResult {
        schema: CANCEL_RESULT_SCHEMA.to_string(),
        request_id: record.request_id,
        status: STATE_CANCELLED.to_string(),
    })
}

fn claim_state_error(state: &str) -> &'static str {
    match state {
        STATE_DELIVERED => ALREADY_DELIVERED,
        STATE_CANCELLED => CANCELLED,
        _ => NOT_APPROVED,
    }
}

fn binding_matches_context(record: &MintRecord, context: &HomeLaunchTokenContext) -> bool {
    record.principal_id.as_deref() == Some(context.principal_id())
        && record.session_id.as_deref() == Some(context.session_id())
        && record.proof_binding_id.as_deref() == context.proof_binding_id()
        && record.grant_id.as_deref() == Some(context.grant_id())
}

/// The bound owner, session, proof, grant, and operation still name one live
/// admin session. This is the match that stays in front of the signer.
fn bound_export_matches(data_dir: &Path, record: &MintRecord) -> anyhow::Result<()> {
    if record.operation != OPERATION {
        anyhow::bail!(MISMATCH);
    }
    let context = signing_context(data_dir, record)?;
    if context.root().kind() != Some(crate::auth::PrincipalKind::Human) {
        anyhow::bail!(HUMAN_REQUIRED);
    }
    let auth_data_dir = home_launch_auth_data_dir(data_dir);
    require_admin_principal(&auth_data_dir, &context)?;
    let proof = context
        .proof_binding_id()
        .ok_or_else(|| anyhow::anyhow!(SESSION_MISMATCH))?;
    let live =
        crate::auth::load_active_session_grant(&auth_data_dir, context.session_id(), now_ts())
            .map_err(|_| anyhow::anyhow!(SESSION_MISMATCH))?;
    if live.principal_id != context.principal_id()
        || live.session_id != context.session_id()
        || live.proof_binding_id != proof
        || live.grant_id != context.grant_id()
    {
        anyhow::bail!(SESSION_MISMATCH);
    }
    Ok(())
}

fn signing_context(data_dir: &Path, record: &MintRecord) -> anyhow::Result<HomeLaunchTokenContext> {
    let principal_id = required_bound(record.principal_id.as_deref())?;
    let session_id = required_bound(record.session_id.as_deref())?;
    let grant_id = required_bound(record.grant_id.as_deref())?;
    let proof = required_bound(record.proof_binding_id.as_deref())?;
    let auth_data_dir = home_launch_auth_data_dir(data_dir);
    let root = crate::auth::ResolvedPrincipalRoot::resolve(data_dir, &auth_data_dir, principal_id)?;
    Ok(HomeLaunchTokenContext::resolved(
        root,
        session_id.to_string(),
        Some(proof.to_string()),
        grant_id.to_string(),
    ))
}

fn required_bound(value: Option<&str>) -> anyhow::Result<&str> {
    value
        .filter(|item| !item.is_empty())
        .ok_or_else(|| anyhow::anyhow!(SESSION_MISMATCH))
}

fn signature_issued_at(data_dir: &Path) -> u64 {
    let now = now_ts();
    #[cfg(test)]
    {
        apply_signature_skew(data_dir, now)
    }
    #[cfg(not(test))]
    {
        let _ = data_dir;
        now
    }
}

#[cfg(test)]
static SIGNATURE_SKEW: Mutex<Vec<(PathBuf, i64)>> = Mutex::new(Vec::new());

#[cfg(test)]
fn apply_signature_skew(data_dir: &Path, now: u64) -> u64 {
    let skew = SIGNATURE_SKEW
        .lock()
        .map(|guard| {
            guard
                .iter()
                .find(|(path, _)| path == data_dir)
                .map(|(_, skew)| *skew)
                .unwrap_or(0)
        })
        .unwrap_or(0);
    if skew < 0 {
        now.saturating_sub(skew.unsigned_abs())
    } else {
        now.saturating_add(skew as u64)
    }
}

#[cfg(test)]
pub(super) struct CliMintSignatureSkewGuard {
    data_dir: PathBuf,
}

#[cfg(test)]
impl Drop for CliMintSignatureSkewGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = SIGNATURE_SKEW.lock() {
            guard.retain(|(path, _)| path != &self.data_dir);
        }
    }
}

#[cfg(test)]
pub(super) fn set_cli_mint_signature_skew_for_test(
    data_dir: &Path,
    skew_secs: i64,
) -> CliMintSignatureSkewGuard {
    let mut guard = SIGNATURE_SKEW
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(entry) = guard.iter_mut().find(|(path, _)| path == data_dir) {
        entry.1 = skew_secs;
    } else {
        guard.push((data_dir.to_path_buf(), skew_secs));
    }
    CliMintSignatureSkewGuard {
        data_dir: data_dir.to_path_buf(),
    }
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

fn load_record(data_dir: &Path, request_id: &str, now: u64) -> anyhow::Result<MintRecord> {
    valid_request_id(request_id)?;
    let path = record_path(data_dir, request_id)?;
    let meta = fs::symlink_metadata(&path).map_err(|_| anyhow::anyhow!(NOT_WAITING))?;
    if !meta.file_type().is_file() {
        anyhow::bail!(MISMATCH);
    }
    let record: MintRecord =
        serde_json::from_slice(&fs::read(&path)?).map_err(|_| anyhow::anyhow!(MISMATCH))?;
    if record.schema != RECORD_SCHEMA
        || record.request_id != request_id
        || record.operation != OPERATION
        || record.secret_sha256.len() != 64
        || record.expires_at <= record.created_at
        || !matches!(
            record.state.as_str(),
            STATE_PENDING
                | STATE_BEGUN
                | STATE_APPROVED
                | STATE_REFUSED
                | STATE_CANCELLED
                | STATE_DELIVERED
        )
    {
        anyhow::bail!(MISMATCH);
    }
    if now >= record.expires_at {
        anyhow::bail!(EXPIRED);
    }
    Ok(record)
}

fn prepare_capacity(data_dir: &Path, now: u64) -> anyhow::Result<()> {
    let root = data_dir.join(DIRECTORY);
    if !root.exists() {
        return Ok(());
    }
    let mut kept = 0usize;
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(id) = name.strip_suffix(".json") else {
            continue;
        };
        if valid_request_id(id).is_err() {
            continue;
        }
        let path = entry.path();
        let expired = fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<MintRecord>(&bytes).ok())
            .is_some_and(|record| now >= record.expires_at);
        if expired {
            let _ = fs::remove_file(path);
        } else {
            kept += 1;
        }
    }
    if kept >= CAPACITY {
        anyhow::bail!(CAPACITY_ERROR);
    }
    Ok(())
}

fn store_record(data_dir: &Path, record: &MintRecord) -> anyhow::Result<()> {
    let path = record_path(data_dir, &record.request_id)?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("cli mint state root is unavailable"))?;
    ensure_private_dir(parent)?;
    if fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_symlink()) {
        anyhow::bail!(MISMATCH);
    }
    let bytes = serde_json::to_vec(record)?;
    let temporary = parent.join(format!(".{}.tmp", record.request_id));
    let _ = fs::remove_file(&temporary);
    let write_result = (|| -> anyhow::Result<()> {
        let mut file = {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            options.open(&temporary)?
        };
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(err) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(err);
    }
    fs::rename(&temporary, &path)?;
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    sync_dir(parent)
}

fn record_path(data_dir: &Path, request_id: &str) -> anyhow::Result<PathBuf> {
    valid_request_id(request_id)?;
    Ok(data_dir.join(DIRECTORY).join(format!("{request_id}.json")))
}

fn ensure_private_dir(path: &Path) -> anyhow::Result<()> {
    if path.symlink_metadata().is_ok() {
        let meta = fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            anyhow::bail!("cli mint state root is not a directory");
        }
        return Ok(());
    }
    #[cfg(unix)]
    {
        fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(path)?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

fn sync_dir(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
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

fn mint_lock() -> anyhow::Result<std::sync::MutexGuard<'static, ()>> {
    MINT_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| anyhow::anyhow!("cli mint state lock is poisoned"))
}

fn mint_error(err: anyhow::Error) -> Response {
    let text = err.to_string();
    let status = if text == HUMAN_REQUIRED
        || text == SESSION_MISMATCH
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
pub(super) fn cli_mint_record_path_for_test(data_dir: &Path, request_id: &str) -> PathBuf {
    data_dir.join(DIRECTORY).join(format!("{request_id}.json"))
}
