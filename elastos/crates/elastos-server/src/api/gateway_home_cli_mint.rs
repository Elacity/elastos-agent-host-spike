//! Bound request, passkey approval, and one-time delivery of an exported Home CLI grant.
//!
//! A terminal registers a request. The signed-in human admin approves it with
//! a fresh passkey assertion. The waiting terminal claims the grant once.
//! The claim signs only after that approved record matches the request id,
//! the secret hash, the bound owner, session, proof, grant, and operation.
//!
//! The request table lives only in this process. A same-user process can write
//! the data directory, so a file there is not an approval and cannot deliver a
//! grant. A gateway restart drops every waiting request. The table holds 32
//! live requests for 120 seconds. The claim compares the secret before it
//! reports the request state, and it does not hold the table lock while it
//! reads the session or signs.

use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
#[cfg(test)]
use std::sync::Condvar;
use std::sync::{Mutex, OnceLock};

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
const REQUEST_ORIGIN_REFUSED: &str = "cli mint request origin is refused";
const CREDENTIAL_UNAVAILABLE: &str = "cli mint passkey credential is unavailable";
const DIFFERENT_PASSKEY: &str = "cli mint used a different registered passkey";
const CAPACITY_ERROR: &str = "cli mint request capacity";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClaimHold {
    Checking,
    Committed,
}

struct MintTable {
    records: HashMap<String, MintRecord>,
    claim_held: HashMap<String, ClaimHold>,
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

pub(super) async fn home_cli_mint_claim(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(input): Json<ClaimBody>,
) -> Response {
    match claim_request(&state.data_dir, &headers, input) {
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

fn claim_request(
    data_dir: &Path,
    headers: &HeaderMap,
    input: ClaimBody,
) -> anyhow::Result<ClaimResult> {
    if input.schema != CLAIM_SCHEMA {
        anyhow::bail!("unsupported cli mint claim schema");
    }
    if !super::gateway_frontdoor::cli_mint_request_origin_allowed(headers) {
        anyhow::bail!(REQUEST_ORIGIN_REFUSED);
    }
    valid_secret(&input.requester_secret)?;
    valid_request_id(&input.request_id)?;
    let record = {
        let mut table = mint_table()?;
        reserve_claim(&mut table, &input, now_ts())?
    };
    let mut ticket = ClaimTicket::arm(record.request_id.clone());
    bound_export_matches(data_dir, &record)?;
    let context = signing_context(data_dir, &record)?;
    commit_claim(&record, &input.requester_secret)?;
    #[cfg(test)]
    {
        assert!(
            !table_lock_held_on_this_thread(),
            "claim holds the table lock across the signer"
        );
        overlap_before_sign(&record.request_id);
    }
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
    let request_id = mark_delivered(&record.request_id)?;
    ticket.disarm();
    Ok(ClaimResult {
        schema: CLAIM_RESULT_SCHEMA.to_string(),
        request_id,
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
    let mut table = mint_table()?;
    if table.claim_held.get(&input.request_id) == Some(&ClaimHold::Committed) {
        anyhow::bail!(ALREADY_DECIDED);
    }
    table.claim_held.remove(&input.request_id);
    let now = now_ts();
    let mut record = load_record(&table, &input.request_id, now)?;
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
    let request_id = record.request_id.clone();
    table.records.insert(request_id.clone(), record);
    Ok(CancelResult {
        schema: CANCEL_RESULT_SCHEMA.to_string(),
        request_id,
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

fn mark_refused(table: &mut MintTable, record: &mut MintRecord) {
    record.state = STATE_REFUSED.to_string();
    table
        .records
        .insert(record.request_id.clone(), record.clone());
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
    if live.principal_id != context.principal_id() {
        anyhow::bail!(SESSION_MISMATCH);
    }
    if live.session_id != context.session_id() {
        anyhow::bail!(SESSION_MISMATCH);
    }
    if live.proof_binding_id != proof {
        anyhow::bail!(SESSION_MISMATCH);
    }
    if live.grant_id != context.grant_id() {
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

fn reserve_claim(table: &mut MintTable, input: &ClaimBody, now: u64) -> anyhow::Result<MintRecord> {
    let Some(record) = table.records.get(&input.request_id).cloned() else {
        anyhow::bail!(NOT_WAITING);
    };
    if record.schema != RECORD_SCHEMA
        || record.request_id != input.request_id
        || record.secret_sha256.len() != 64
        || record.expires_at <= record.created_at
    {
        anyhow::bail!(MISMATCH);
    }
    refuse_wrong_secret(&input.requester_secret, &record)?;
    refuse_if_expired(&record, now)?;
    if record.operation != OPERATION {
        anyhow::bail!(MISMATCH);
    }
    refuse_unless_approved(&record)?;
    if table.claim_held.contains_key(&record.request_id) {
        anyhow::bail!(ALREADY_DELIVERED);
    }
    table
        .claim_held
        .insert(record.request_id.clone(), ClaimHold::Checking);
    Ok(record)
}

fn commit_claim(expected: &MintRecord, secret: &str) -> anyhow::Result<()> {
    let mut table = mint_table()?;
    let Some(live) = table.records.get(&expected.request_id).cloned() else {
        anyhow::bail!(NOT_WAITING);
    };
    if table.claim_held.get(&expected.request_id) != Some(&ClaimHold::Checking) {
        if live.state == STATE_CANCELLED {
            anyhow::bail!(CANCELLED);
        }
        anyhow::bail!(ALREADY_DELIVERED);
    }
    refuse_wrong_secret(secret, &live)?;
    refuse_if_expired(&live, now_ts())?;
    if live.operation != OPERATION || live.operation != expected.operation {
        anyhow::bail!(MISMATCH);
    }
    refuse_unless_approved(&live)?;
    if live.principal_id != expected.principal_id
        || live.session_id != expected.session_id
        || live.proof_binding_id != expected.proof_binding_id
        || live.grant_id != expected.grant_id
    {
        anyhow::bail!(SESSION_MISMATCH);
    }
    table
        .claim_held
        .insert(expected.request_id.clone(), ClaimHold::Committed);
    Ok(())
}

fn mark_delivered(request_id: &str) -> anyhow::Result<String> {
    let mut table = mint_table()?;
    let hold = table.claim_held.get(request_id).copied();
    let Some(mut record) = table.records.get(request_id).cloned() else {
        anyhow::bail!(NOT_WAITING);
    };
    if hold != Some(ClaimHold::Committed) || record.state != STATE_APPROVED {
        table.claim_held.remove(request_id);
        if record.state == STATE_CANCELLED {
            anyhow::bail!(CANCELLED);
        }
        anyhow::bail!(claim_state_error(&record.state));
    }
    record.state = STATE_DELIVERED.to_string();
    let id = record.request_id.clone();
    table.records.insert(id.clone(), record);
    table.claim_held.remove(request_id);
    Ok(id)
}

fn refuse_wrong_secret(secret: &str, record: &MintRecord) -> anyhow::Result<()> {
    if !secret_hash_matches(secret, &record.secret_sha256) {
        anyhow::bail!(SECRET_MISMATCH);
    }
    Ok(())
}

fn refuse_if_expired(record: &MintRecord, now: u64) -> anyhow::Result<()> {
    if now >= record.expires_at {
        anyhow::bail!(EXPIRED);
    }
    Ok(())
}

fn refuse_unless_approved(record: &MintRecord) -> anyhow::Result<()> {
    if !matches!(
        record.state.as_str(),
        STATE_PENDING
            | STATE_BEGUN
            | STATE_APPROVED
            | STATE_REFUSED
            | STATE_CANCELLED
            | STATE_DELIVERED
    ) {
        anyhow::bail!(MISMATCH);
    }
    if record.state != STATE_APPROVED {
        anyhow::bail!(claim_state_error(&record.state));
    }
    Ok(())
}

fn secret_hash_matches(secret: &str, stored_hex: &str) -> bool {
    use subtle::ConstantTimeEq as _;
    let digest = Sha256::digest(secret.as_bytes());
    let decoded = hex::decode(stored_hex).unwrap_or_default();
    let mut stored = [0u8; 32];
    let same_len = decoded.len() == digest.len();
    if same_len {
        stored.copy_from_slice(&decoded);
    }
    bool::from(stored.as_slice().ct_eq(digest.as_slice())) & same_len
}

struct ClaimTicket {
    request_id: String,
    armed: bool,
}

impl ClaimTicket {
    fn arm(request_id: String) -> Self {
        Self {
            request_id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ClaimTicket {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(mut table) = mint_table() {
            table.claim_held.remove(&self.request_id);
        }
    }
}

struct TableGuard {
    guard: std::sync::MutexGuard<'static, MintTable>,
}

impl Drop for TableGuard {
    fn drop(&mut self) {
        if let Ok(mut owner) = TABLE_OWNER.lock() {
            *owner = None;
        }
    }
}

impl Deref for TableGuard {
    type Target = MintTable;

    fn deref(&self) -> &MintTable {
        &self.guard
    }
}

impl DerefMut for TableGuard {
    fn deref_mut(&mut self) -> &mut MintTable {
        &mut self.guard
    }
}

static TABLE_OWNER: Mutex<Option<std::thread::ThreadId>> = Mutex::new(None);

#[cfg(test)]
fn table_lock_held_on_this_thread() -> bool {
    TABLE_OWNER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        == Some(&std::thread::current().id())
}

fn mint_table() -> anyhow::Result<TableGuard> {
    static TABLE: OnceLock<Mutex<MintTable>> = OnceLock::new();
    let guard = TABLE
        .get_or_init(|| {
            Mutex::new(MintTable {
                records: HashMap::new(),
                claim_held: HashMap::new(),
            })
        })
        .lock()
        .map_err(|_| anyhow::anyhow!("cli mint state lock is poisoned"))?;
    if let Ok(mut owner) = TABLE_OWNER.lock() {
        *owner = Some(std::thread::current().id());
    }
    Ok(TableGuard { guard })
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
    let mut table = mint_table().expect("cli mint state lock");
    table.records.clear();
    table.claim_held.clear();
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

#[cfg(test)]
pub(super) fn cli_mint_rewrite_for_test(request_id: &str, field: &str, value: &str) {
    let mut table = mint_table().expect("cli mint state lock");
    let record = table.records.get_mut(request_id).expect("cli mint request");
    match field {
        "state" => record.state = value.to_string(),
        "operation" => record.operation = value.to_string(),
        "session_id" => record.session_id = Some(value.to_string()),
        "principal_id" => record.principal_id = Some(value.to_string()),
        "proof_binding_id" => record.proof_binding_id = Some(value.to_string()),
        "grant_id" => record.grant_id = Some(value.to_string()),
        "secret_sha256" => record.secret_sha256 = value.to_string(),
        other => panic!("cli mint test cannot rewrite {other}"),
    }
}

#[cfg(test)]
struct OverlapGate {
    request_id: String,
    arrived: usize,
    release: bool,
}

#[cfg(test)]
static OVERLAP: Mutex<Option<OverlapGate>> = Mutex::new(None);

#[cfg(test)]
static OVERLAP_CV: Condvar = Condvar::new();

#[cfg(test)]
pub(super) struct CliMintOverlapGuard;

#[cfg(test)]
impl Drop for CliMintOverlapGuard {
    fn drop(&mut self) {
        let mut guard = OVERLAP
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(gate) = guard.as_mut() {
            gate.release = true;
        }
        OVERLAP_CV.notify_all();
    }
}

#[cfg(test)]
pub(super) fn arm_cli_mint_overlap_for_test(request_id: &str) -> CliMintOverlapGuard {
    let mut guard = OVERLAP
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = Some(OverlapGate {
        request_id: request_id.to_string(),
        arrived: 0,
        release: false,
    });
    CliMintOverlapGuard
}

#[cfg(test)]
pub(super) fn cli_mint_overlap_arrived_for_test() -> usize {
    OVERLAP
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .map(|gate| gate.arrived)
        .unwrap_or(0)
}

#[cfg(test)]
pub(super) fn release_cli_mint_overlap_for_test() {
    let mut guard = OVERLAP
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(gate) = guard.as_mut() {
        gate.release = true;
    }
    OVERLAP_CV.notify_all();
}

#[cfg(test)]
fn overlap_before_sign(request_id: &str) {
    let mut guard = OVERLAP
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut counted = false;
    loop {
        match guard.as_mut() {
            Some(gate) if gate.request_id == request_id && !gate.release => {
                if !counted {
                    gate.arrived += 1;
                    counted = true;
                    OVERLAP_CV.notify_all();
                }
            }
            _ => return,
        }
        guard = OVERLAP_CV
            .wait(guard)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
    }
}
