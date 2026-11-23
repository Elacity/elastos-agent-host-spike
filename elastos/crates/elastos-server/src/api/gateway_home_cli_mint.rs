//! Bound request, passkey approval, and one-time delivery of an exported Home CLI grant.
//!
//! `elastos home --cli-launch-token` registers a request with a fresh secret and
//! polls the claim route. While it waits, it prints a request code on stderr.
//! That code is the first eight hex characters of the request id. Home shows the
//! same code to the signed-in human admin and, when several requests are waiting,
//! asks the admin to choose. Home begins the chosen request and then sends a
//! fresh passkey assertion. The claim signs only after that approved record
//! matches the request id, the secret hash, the bound owner, session, proof,
//! grant, and operation. A refused passkey and a cancelled request stop the wait.
//!
//! The request table lives only in this process. A same-user process can write
//! the data directory, so a file there is not an approval and cannot deliver a
//! grant. A gateway restart drops every waiting request. The table holds 32
//! live requests for 120 seconds. The claim compares the secret before it
//! reports the request state, and it does not hold the table lock while it
//! reads the session or signs. Each claim hold carries a nonce. A refused cancel
//! leaves that hold in place, and a claim drops only the hold with its own nonce.

use std::collections::HashMap;
use std::io::Write;
use std::ops::{Deref, DerefMut};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
#[cfg(test)]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
use std::sync::Condvar;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use base64::Engine;
use elastos_identity::{AuthenticationResponse, CredentialDescriptor, RequestOptions};
use sha2::{Digest, Sha256};

use super::*;

const REQUEST_SCHEMA: &str = "elastos.home.cli-mint.request/v1";
const BEGIN_SCHEMA: &str = "elastos.home.cli-mint.begin/v1";
const APPROVE_SCHEMA: &str = "elastos.home.cli-mint.approve/v1";
const CLAIM_SCHEMA: &str = "elastos.home.cli-mint.claim/v1";
const CANCEL_SCHEMA: &str = "elastos.home.cli-mint.cancel/v1";
const WAITING_SCHEMA: &str = "elastos.home.cli-mint.waiting/v1";
const RECORD_SCHEMA: &str = "elastos.home.cli-mint.record/v1";
const REQUEST_RESULT_SCHEMA: &str = "elastos.home.cli-mint.request.result/v1";
const BEGIN_RESULT_SCHEMA: &str = "elastos.home.cli-mint.begin.result/v1";
const APPROVE_RESULT_SCHEMA: &str = "elastos.home.cli-mint.approve.result/v1";
const CLAIM_RESULT_SCHEMA: &str = "elastos.home.cli-mint.claim.result/v1";
const CANCEL_RESULT_SCHEMA: &str = "elastos.home.cli-mint.cancel.result/v1";
const WAITING_RESULT_SCHEMA: &str = "elastos.home.cli-mint.waiting.result/v1";
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
const REFUSED: &str = "cli mint request was refused";
const SECRET_MISMATCH: &str = "cli mint requester secret does not match";
const EXPIRED: &str = "cli mint request expired";
const MISMATCH: &str = "cli mint request mismatch";
const ORIGIN_MISMATCH: &str = "cli mint passkey origin mismatch";
const REQUEST_ORIGIN_REFUSED: &str = "cli mint request origin is refused";
const CREDENTIAL_UNAVAILABLE: &str = "cli mint passkey credential is unavailable";
const DIFFERENT_PASSKEY: &str = "cli mint used a different registered passkey";
const CAPACITY_ERROR: &str = "cli mint request capacity";
const WAIT_POLL: Duration = Duration::from_secs(1);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);
const WAIT_DEADLINE_SLACK_SECS: u64 = 180;
const WAIT_TIMEOUT: &str = "cli mint request timed out";
const WAIT_UNAVAILABLE: &str =
    "Home is not running. Start Home, then request the terminal grant again.";
const WAIT_UNANSWERED: &str = "Home did not answer. Request the terminal grant again.";
const WAIT_LOST_REPLY: &str = "Home did not answer the terminal. A grant may already have been delivered. Do not approve again.";
const WAIT_NOTICE_PREFIX: &str = "Approve terminal request ";
const WAIT_NOTICE_SUFFIX: &str = " in Home";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClaimPhase {
    Checking,
    Committed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ClaimHold {
    phase: ClaimPhase,
    nonce: u64,
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WaitingBody {
    schema: String,
}

#[derive(Debug, Serialize)]
struct WaitingRequest {
    request_id: String,
    operation: String,
    expires_at: u64,
    status: String,
}

#[derive(Debug, Serialize)]
struct WaitingResult {
    schema: String,
    requests: Vec<WaitingRequest>,
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
    #[serde(default)]
    pending_cancel: bool,
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

pub(super) async fn home_cli_mint_waiting(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(input): Json<WaitingBody>,
) -> Response {
    match list_waiting(&state.data_dir, &headers, input) {
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
        pending_cancel: false,
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
    let (record, nonce) = {
        let mut table = mint_table()?;
        reserve_claim(&mut table, &input, now_ts())?
    };
    let mut ticket = ClaimTicket::arm(record.request_id.clone(), nonce);
    #[cfg(test)]
    pause_while_checking(&record.request_id);
    let context = bound_export_matches(data_dir, &record)?;
    commit_claim(&record, &input.requester_secret, nonce)?;
    #[cfg(test)]
    {
        assert!(
            !table_lock_held_on_this_thread(),
            "claim holds the table lock across the signer"
        );
        overlap_before_sign(&record.request_id);
    }
    if let Some(message) = signer_failure() {
        anyhow::bail!(message);
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
    let request_id = mark_delivered(&record.request_id, nonce)?;
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
    let now = now_ts();
    let mut record = load_record(&table, &input.request_id, now)?;
    if matches!(record.state.as_str(), STATE_BEGUN | STATE_APPROVED)
        && !binding_matches_context(&record, &context)
    {
        anyhow::bail!(SESSION_MISMATCH);
    }
    let hold = table.claim_held.get(&input.request_id).copied();
    if hold.is_some_and(|held| held.phase == ClaimPhase::Committed) {
        record.pending_cancel = true;
        let request_id = record.request_id.clone();
        table.records.insert(request_id, record);
        anyhow::bail!(ALREADY_DECIDED);
    }
    if !matches!(
        record.state.as_str(),
        STATE_PENDING | STATE_BEGUN | STATE_APPROVED
    ) {
        anyhow::bail!(ALREADY_DECIDED);
    }
    record.state = STATE_CANCELLED.to_string();
    record.pending_cancel = false;
    let request_id = record.request_id.clone();
    table.records.insert(request_id.clone(), record);
    if hold.is_some_and(|held| held.phase == ClaimPhase::Checking) {
        table.claim_held.remove(&request_id);
    }
    Ok(CancelResult {
        schema: CANCEL_RESULT_SCHEMA.to_string(),
        request_id,
        status: STATE_CANCELLED.to_string(),
    })
}

fn list_waiting(
    data_dir: &Path,
    headers: &HeaderMap,
    input: WaitingBody,
) -> anyhow::Result<WaitingResult> {
    if input.schema != WAITING_SCHEMA {
        anyhow::bail!("unsupported cli mint waiting schema");
    }
    let _admin = home_admin_context(data_dir, headers)?;
    let table = mint_table()?;
    let now = now_ts();
    let mut requests: Vec<WaitingRequest> = table
        .records
        .values()
        .filter(|record| record.state == STATE_PENDING && now < record.expires_at)
        .map(|record| WaitingRequest {
            request_id: record.request_id.clone(),
            operation: record.operation.clone(),
            expires_at: record.expires_at,
            status: record.state.clone(),
        })
        .collect();
    requests.sort_by(|left, right| left.request_id.cmp(&right.request_id));
    Ok(WaitingResult {
        schema: WAITING_RESULT_SCHEMA.to_string(),
        requests,
    })
}

fn claim_state_error(state: &str) -> &'static str {
    match state {
        STATE_DELIVERED => ALREADY_DELIVERED,
        STATE_CANCELLED => CANCELLED,
        STATE_REFUSED => REFUSED,
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
fn bound_export_matches(
    data_dir: &Path,
    record: &MintRecord,
) -> anyhow::Result<HomeLaunchTokenContext> {
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
    Ok(context)
}

fn signing_context(data_dir: &Path, record: &MintRecord) -> anyhow::Result<HomeLaunchTokenContext> {
    let principal_id = required_bound(record.principal_id.as_deref())?;
    let session_id = required_bound(record.session_id.as_deref())?;
    let grant_id = required_bound(record.grant_id.as_deref())?;
    let proof = required_bound(record.proof_binding_id.as_deref())?;
    let auth_data_dir = home_launch_auth_data_dir(data_dir);
    #[cfg(test)]
    note_principal_root_read();
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
static PRINCIPAL_ROOT_READS: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
fn note_principal_root_read() {
    PRINCIPAL_ROOT_READS.fetch_add(1, Ordering::SeqCst);
}

#[cfg(test)]
pub(super) fn principal_root_reads_for_test() -> u64 {
    PRINCIPAL_ROOT_READS.load(Ordering::SeqCst)
}

#[cfg(test)]
static FAIL_SIGNER: AtomicBool = AtomicBool::new(false);

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

fn reserve_claim(
    table: &mut MintTable,
    input: &ClaimBody,
    now: u64,
) -> anyhow::Result<(MintRecord, u64)> {
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
    let nonce = next_claim_nonce();
    table.claim_held.insert(
        record.request_id.clone(),
        ClaimHold {
            phase: ClaimPhase::Checking,
            nonce,
        },
    );
    Ok((record, nonce))
}

fn commit_claim(expected: &MintRecord, secret: &str, nonce: u64) -> anyhow::Result<()> {
    let mut table = mint_table()?;
    let Some(live) = table.records.get(&expected.request_id).cloned() else {
        anyhow::bail!(NOT_WAITING);
    };
    let own = ClaimHold {
        phase: ClaimPhase::Checking,
        nonce,
    };
    if table.claim_held.get(&expected.request_id) != Some(&own) {
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
    table.claim_held.insert(
        expected.request_id.clone(),
        ClaimHold {
            phase: ClaimPhase::Committed,
            nonce,
        },
    );
    Ok(())
}

fn mark_delivered(request_id: &str, nonce: u64) -> anyhow::Result<String> {
    let mut table = mint_table()?;
    let hold = table.claim_held.get(request_id).copied();
    let Some(mut record) = table.records.get(request_id).cloned() else {
        anyhow::bail!(NOT_WAITING);
    };
    let own = ClaimHold {
        phase: ClaimPhase::Committed,
        nonce,
    };
    if hold != Some(own) || record.state != STATE_APPROVED {
        if hold.is_some_and(|held| held.nonce == nonce) {
            table.claim_held.remove(request_id);
        }
        if record.state == STATE_CANCELLED {
            anyhow::bail!(CANCELLED);
        }
        anyhow::bail!(claim_state_error(&record.state));
    }
    record.state = STATE_DELIVERED.to_string();
    record.pending_cancel = false;
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
    nonce: u64,
    armed: bool,
}

impl ClaimTicket {
    fn arm(request_id: String, nonce: u64) -> Self {
        Self {
            request_id,
            nonce,
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
        let Ok(mut table) = mint_table() else {
            return;
        };
        let matches = table
            .claim_held
            .get(&self.request_id)
            .is_some_and(|held| held.nonce == self.nonce);
        if !matches {
            return;
        }
        table.claim_held.remove(&self.request_id);
        if let Some(record) = table.records.get_mut(&self.request_id) {
            if record.pending_cancel && record.state == STATE_APPROVED {
                record.state = STATE_CANCELLED.to_string();
                record.pending_cancel = false;
            }
        }
    }
}

fn next_claim_nonce() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    loop {
        let nonce = NEXT.fetch_add(1, Ordering::Relaxed);
        if nonce != 0 {
            return nonce;
        }
    }
}

fn signer_failure() -> Option<&'static str> {
    #[cfg(test)]
    {
        if FAIL_SIGNER.swap(false, Ordering::SeqCst) {
            return Some("cli mint signer failed");
        }
    }
    None
}

struct TableGuard {
    guard: std::sync::MutexGuard<'static, MintTable>,
}

#[cfg(test)]
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

#[cfg(test)]
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
    #[cfg(test)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WaitKind {
    Cancelled,
    Timeout,
    Mismatch,
    Unavailable,
    Unanswered,
    LostReply,
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CliMintWaitError {
    kind: WaitKind,
}

impl CliMintWaitError {
    fn cancelled() -> Self {
        Self {
            kind: WaitKind::Cancelled,
        }
    }

    fn timeout() -> Self {
        Self {
            kind: WaitKind::Timeout,
        }
    }

    fn mismatch() -> Self {
        Self {
            kind: WaitKind::Mismatch,
        }
    }

    fn unavailable() -> Self {
        Self {
            kind: WaitKind::Unavailable,
        }
    }

    fn unanswered() -> Self {
        Self {
            kind: WaitKind::Unanswered,
        }
    }

    fn lost_reply() -> Self {
        Self {
            kind: WaitKind::LostReply,
        }
    }

    fn refused() -> Self {
        Self {
            kind: WaitKind::Refused,
        }
    }
}

impl std::fmt::Display for CliMintWaitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self.kind {
            WaitKind::Cancelled => CANCELLED,
            WaitKind::Timeout => WAIT_TIMEOUT,
            WaitKind::Mismatch => MISMATCH,
            WaitKind::Unavailable => WAIT_UNAVAILABLE,
            WaitKind::Unanswered => WAIT_UNANSWERED,
            WaitKind::LostReply => WAIT_LOST_REPLY,
            WaitKind::Refused => REFUSED,
        })
    }
}

impl std::error::Error for CliMintWaitError {}

enum ClaimPoll {
    Grant(String),
    Pending,
    Cancel,
    Timeout,
    Mismatch,
    Refused,
}

/// The code Home shows for this request. Eight hex characters, upper case,
/// grouped as `ABCD-EFGH`. It is not the requester secret.
pub(super) fn terminal_request_code(request_id: &str) -> Option<String> {
    if valid_request_id(request_id).is_err() {
        return None;
    }
    let head = request_id[..8].to_ascii_uppercase();
    Some(format!("{}-{}", &head[..4], &head[4..8]))
}

fn write_wait_notice(request_id: &str, notice: &mut dyn Write) -> Result<(), CliMintWaitError> {
    let code = terminal_request_code(request_id).ok_or_else(CliMintWaitError::mismatch)?;
    writeln!(notice, "{WAIT_NOTICE_PREFIX}{code}{WAIT_NOTICE_SUFFIX}")
        .map_err(|_| CliMintWaitError::mismatch())
}

fn fresh_requester_secret() -> Result<String, CliMintWaitError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| CliMintWaitError::unavailable())?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

fn printable_grant(grant: &str) -> bool {
    !grant.is_empty()
        && grant.len() <= 16 * 1024
        && grant
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn outcome_from_claim(status: StatusCode, body: &str, request_id: &str) -> ClaimPoll {
    if status == StatusCode::OK {
        let Ok(parsed) = serde_json::from_str::<ClaimResult>(body) else {
            return ClaimPoll::Mismatch;
        };
        if parsed.schema == CLAIM_RESULT_SCHEMA
            && parsed.status == STATE_DELIVERED
            && parsed.request_id == request_id
            && printable_grant(&parsed.grant)
        {
            return ClaimPoll::Grant(parsed.grant);
        }
        return ClaimPoll::Mismatch;
    }
    match body.trim() {
        CANCELLED => ClaimPoll::Cancel,
        EXPIRED => ClaimPoll::Timeout,
        NOT_APPROVED => ClaimPoll::Pending,
        REFUSED => ClaimPoll::Refused,
        _ => ClaimPoll::Mismatch,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransportClass {
    /// The attempt never connected, so this attempt delivered nothing.
    Unreachable,
    /// The attempt connected or the reply was lost. A grant may already exist.
    Interrupted,
}

fn transport_class(err: &reqwest::Error) -> TransportClass {
    if err.is_connect() {
        TransportClass::Unreachable
    } else {
        TransportClass::Interrupted
    }
}

async fn post_mint(
    client: &reqwest::Client,
    url: &str,
    body: serde_json::Value,
) -> Result<(StatusCode, String), TransportClass> {
    let response = client
        .post(url)
        .json(&body)
        .send()
        .await
        .map_err(|err| transport_class(&err))?;
    let status = response.status();
    let text = response.text().await.map_err(|err| transport_class(&err))?;
    Ok((status, text))
}

fn deadline_without_grant(
    possible_delivery: bool,
    saw_reply: bool,
    saw_unreachable: bool,
) -> CliMintWaitError {
    if possible_delivery {
        CliMintWaitError::lost_reply()
    } else if saw_unreachable && !saw_reply {
        CliMintWaitError::unavailable()
    } else {
        CliMintWaitError::timeout()
    }
}

async fn request_and_wait<F, Fut, W>(
    api_url: &str,
    poll: Duration,
    http_timeout: Duration,
    notice: &mut W,
    on_registered: F,
) -> Result<String, CliMintWaitError>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = ()>,
    W: Write + Send,
{
    let api_url = api_url.trim().trim_end_matches('/');
    crate::local_http::LoopbackHttpBaseUrl::parse(api_url)
        .map_err(|_| CliMintWaitError::mismatch())?;
    let secret = fresh_requester_secret()?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(http_timeout)
        .build()
        .map_err(|_| CliMintWaitError::unavailable())?;
    let (status, body) = match post_mint(
        &client,
        &format!("{api_url}/api/home/cli-mint/request"),
        serde_json::json!({
            "schema": REQUEST_SCHEMA,
            "requester_secret": secret,
        }),
    )
    .await
    {
        Ok(response) => response,
        // No claim has been sent, so no grant was received.
        Err(TransportClass::Unreachable) => return Err(CliMintWaitError::unavailable()),
        Err(TransportClass::Interrupted) => return Err(CliMintWaitError::unanswered()),
    };
    if body.contains(&secret) || status != StatusCode::OK {
        return Err(CliMintWaitError::mismatch());
    }
    let parsed: serde_json::Value =
        serde_json::from_str(&body).map_err(|_| CliMintWaitError::mismatch())?;
    if parsed["schema"] != REQUEST_RESULT_SCHEMA || parsed["status"] != STATE_PENDING {
        return Err(CliMintWaitError::mismatch());
    }
    let request_id = parsed["request_id"]
        .as_str()
        .filter(|value| valid_request_id(value).is_ok())
        .ok_or_else(CliMintWaitError::mismatch)?
        .to_string();
    let expires_at = parsed["expires_at"]
        .as_u64()
        .ok_or_else(CliMintWaitError::mismatch)?;
    let now = now_ts();
    if expires_at <= now {
        return Err(CliMintWaitError::timeout());
    }
    if expires_at > now.saturating_add(WAIT_DEADLINE_SLACK_SECS) {
        return Err(CliMintWaitError::mismatch());
    }
    write_wait_notice(&request_id, notice)?;
    on_registered(request_id.clone()).await;
    let mut possible_delivery = false;
    let mut saw_reply = false;
    let mut saw_unreachable = false;
    loop {
        if now_ts() >= expires_at {
            return Err(deadline_without_grant(
                possible_delivery,
                saw_reply,
                saw_unreachable,
            ));
        }
        match post_mint(
            &client,
            &format!("{api_url}/api/home/cli-mint/claim"),
            serde_json::json!({
                "schema": CLAIM_SCHEMA,
                "request_id": request_id,
                "requester_secret": secret,
            }),
        )
        .await
        {
            Ok((status, body)) => {
                if body.contains(&secret) {
                    return Err(CliMintWaitError::mismatch());
                }
                match outcome_from_claim(status, &body, &request_id) {
                    ClaimPoll::Grant(grant) => return Ok(grant),
                    ClaimPoll::Pending => {
                        saw_reply = true;
                        possible_delivery = false;
                        tokio::time::sleep(poll).await;
                    }
                    ClaimPoll::Cancel => return Err(CliMintWaitError::cancelled()),
                    ClaimPoll::Timeout => return Err(CliMintWaitError::timeout()),
                    ClaimPoll::Mismatch => return Err(CliMintWaitError::mismatch()),
                    ClaimPoll::Refused => return Err(CliMintWaitError::refused()),
                }
            }
            Err(TransportClass::Unreachable) => {
                saw_unreachable = true;
                tokio::time::sleep(poll).await;
            }
            Err(TransportClass::Interrupted) => {
                possible_delivery = true;
                tokio::time::sleep(poll).await;
            }
        }
    }
}

pub(super) fn cli_mint_api_url(data_dir: &Path) -> Result<String, CliMintWaitError> {
    let path = crate::runtime_control::runtime_coord_path(data_dir);
    let bytes = std::fs::read(&path).map_err(|_| CliMintWaitError::unavailable())?;
    let coords: crate::runtime_control::RuntimeCoords =
        serde_json::from_slice(&bytes).map_err(|_| CliMintWaitError::unavailable())?;
    let base = crate::local_http::LoopbackHttpBaseUrl::parse(&coords.api_url)
        .map_err(|_| CliMintWaitError::mismatch())?;
    let url = base.as_str().trim_end_matches('/').to_string();
    if url.is_empty() {
        return Err(CliMintWaitError::unavailable());
    }
    Ok(url)
}

pub async fn request_and_wait_for_exported_home_cli_grant(
    api_url: &str,
) -> Result<String, CliMintWaitError> {
    let mut stderr = std::io::stderr();
    request_and_wait(api_url, WAIT_POLL, CLIENT_TIMEOUT, &mut stderr, |_| async {
    })
    .await
}

pub fn write_cli_launch_token_command(
    result: Result<String, CliMintWaitError>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    match result {
        Ok(grant) if printable_grant(&grant) => {
            if writeln!(stdout, "{grant}").is_err() {
                return 1;
            }
            0
        }
        Ok(_) => {
            let _ = writeln!(stderr, "{MISMATCH}");
            1
        }
        Err(err) => {
            let _ = writeln!(stderr, "{err}");
            1
        }
    }
}

pub fn finish_cli_launch_token_command(
    result: Result<String, CliMintWaitError>,
) -> anyhow::Result<()> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = write_cli_launch_token_command(result, &mut stdout, &mut stderr);
    if code == 0 {
        std::io::stdout().write_all(&stdout)?;
        return Ok(());
    }
    anyhow::bail!("{}", String::from_utf8_lossy(&stderr).trim_end())
}

pub async fn run_exported_home_cli_launch_grant(data_dir: &Path) -> anyhow::Result<()> {
    let api_url = cli_mint_api_url(data_dir)?;
    let waited = request_and_wait_for_exported_home_cli_grant(&api_url).await;
    finish_cli_launch_token_command(waited)
}

#[cfg(test)]
pub(super) async fn request_and_wait_for_exported_home_cli_grant_for_test<F, Fut>(
    api_url: &str,
    poll: Duration,
    on_registered: F,
) -> Result<String, CliMintWaitError>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut notice = Vec::new();
    request_and_wait(api_url, poll, CLIENT_TIMEOUT, &mut notice, on_registered).await
}

#[cfg(test)]
pub(super) async fn request_and_wait_observed_for_test<F, Fut>(
    api_url: &str,
    poll: Duration,
    http_timeout: Duration,
    notice: &mut Vec<u8>,
    on_registered: F,
) -> Result<String, CliMintWaitError>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    request_and_wait(api_url, poll, http_timeout, notice, on_registered).await
}

#[cfg(test)]
pub(super) fn clear_cli_mint_for_test() {
    let mut table = mint_table().expect("cli mint state lock");
    table.records.clear();
    table.claim_held.clear();
}

#[cfg(test)]
pub(super) fn cli_mint_records_json_for_test() -> Vec<String> {
    mint_table()
        .expect("cli mint state lock")
        .records
        .values()
        .map(|record| serde_json::to_string(record).expect("cli mint record json"))
        .collect()
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
#[cfg_attr(not(unix), allow(dead_code))]
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
pub(super) struct CliMintSignerFailGuard;

#[cfg(test)]
impl Drop for CliMintSignerFailGuard {
    fn drop(&mut self) {
        FAIL_SIGNER.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
pub(super) fn fail_next_cli_mint_signature_for_test() -> CliMintSignerFailGuard {
    FAIL_SIGNER.store(true, Ordering::SeqCst);
    CliMintSignerFailGuard
}

#[cfg(test)]
pub(super) fn cli_mint_claim_hold_for_test(request_id: &str) -> Option<u64> {
    mint_table()
        .expect("cli mint state lock")
        .claim_held
        .get(request_id)
        .map(|held| held.nonce)
}

#[cfg(test)]
pub(super) fn drop_foreign_claim_ticket_for_test(request_id: &str) {
    drop(ClaimTicket {
        request_id: request_id.to_string(),
        nonce: 0,
        armed: true,
    });
}

#[cfg(test)]
struct CheckingPause {
    request_id: String,
    arrived: usize,
    release: bool,
}

#[cfg(test)]
static CHECKING_PAUSE: Mutex<Option<CheckingPause>> = Mutex::new(None);

#[cfg(test)]
static CHECKING_PAUSE_CV: Condvar = Condvar::new();

#[cfg(test)]
pub(super) struct CliMintCheckingPauseGuard;

#[cfg(test)]
impl Drop for CliMintCheckingPauseGuard {
    fn drop(&mut self) {
        let mut guard = CHECKING_PAUSE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(gate) = guard.as_mut() {
            gate.release = true;
        }
        CHECKING_PAUSE_CV.notify_all();
    }
}

#[cfg(test)]
pub(super) fn arm_cli_mint_checking_pause_for_test(request_id: &str) -> CliMintCheckingPauseGuard {
    let mut guard = CHECKING_PAUSE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = Some(CheckingPause {
        request_id: request_id.to_string(),
        arrived: 0,
        release: false,
    });
    CliMintCheckingPauseGuard
}

#[cfg(test)]
pub(super) fn cli_mint_checking_pause_arrived_for_test() -> usize {
    CHECKING_PAUSE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .map(|gate| gate.arrived)
        .unwrap_or(0)
}

#[cfg(test)]
pub(super) fn release_cli_mint_checking_pause_for_test() {
    let mut guard = CHECKING_PAUSE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(gate) = guard.as_mut() {
        gate.release = true;
    }
    CHECKING_PAUSE_CV.notify_all();
}

#[cfg(test)]
fn pause_while_checking(request_id: &str) {
    let mut guard = CHECKING_PAUSE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut counted = false;
    loop {
        match guard.as_mut() {
            Some(gate) if gate.request_id == request_id && !gate.release => {
                if !counted {
                    gate.arrived += 1;
                    counted = true;
                    CHECKING_PAUSE_CV.notify_all();
                }
            }
            _ => return,
        }
        guard = CHECKING_PAUSE_CV
            .wait(guard)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
    }
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
