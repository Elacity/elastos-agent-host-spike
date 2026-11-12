//! A frozen copy of the audit event and the audit chain check as they are at
//! commit `bde18c7b`. Test code only. Do not edit it to follow later changes:
//! its job is to show that an audit chain holding agent events still checks
//! with that code.
//!
//! Copied from that commit:
//! - `RuntimeAuditEventV1` from `elastos-auth/src/lib.rs`;
//! - `AuditChainLinkV1`, `AuditChainStateV1`, `AuditChainAnchorV1`, the audit
//!   constants, `audit_chain_hash`, the three payload builders,
//!   `verify_audit_event_signature`, `require_runtime_audit_signer` and
//!   `verify_audit_chain_from` from `elastos-server/src/auth.rs`.
//!
//! Changed in the copy, and nothing else:
//! - `FrozenAuditState` stands for the four audit fields of the stored state;
//! - the Runtime DID is passed in, where the original read it from disk;
//! - the baseline that lets the original skip entries it has already checked
//!   is left out, so every entry is checked;
//! - the test-only counters are left out.
//!
//! The signature primitive is today's `crate::crypto` function.

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const AUDIT_EVENT_DOMAIN: &str = "elastos.audit.event.v1";
const AUDIT_CHAIN_SCHEMA: &str = "elastos.audit.chain-link/v1";
const AUDIT_CHAIN_DOMAIN: &str = "elastos.audit.chain-link.v1";
const AUDIT_CHAIN_GENESIS: &str = "sha256:genesis";
const AUDIT_CHAIN_STATE_SCHEMA: &str = "elastos.audit.chain-state/v1";
const AUDIT_CHAIN_STATE_DOMAIN: &str = "elastos.audit.chain-state.v1";
const AUDIT_CHAIN_ANCHOR_SCHEMA: &str = "elastos.audit.chain-anchor/v1";
const AUDIT_CHAIN_ANCHOR_DOMAIN: &str = "elastos.audit.chain-anchor.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RuntimeAuditEventV1 {
    pub schema: String,
    pub event_id: String,
    pub event_type: String,
    pub principal_id: Option<String>,
    pub proof_binding_id: Option<String>,
    pub session_id: Option<String>,
    pub challenge_id: Option<String>,
    pub capsule_id: Option<String>,
    pub result: String,
    pub reason: String,
    pub occurred_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl RuntimeAuditEventV1 {
    pub const SCHEMA: &'static str = "elastos.audit.event/v1";
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct AuditChainLinkV1 {
    pub schema: String,
    pub sequence: u64,
    pub event_id: String,
    pub previous_hash: String,
    pub event_hash: String,
    pub chain_hash: String,
    pub signer_did: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct AuditChainStateV1 {
    pub schema: String,
    pub activated_at: u64,
    pub head_sequence: u64,
    pub head_hash: String,
    pub signer_did: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct AuditChainAnchorV1 {
    pub schema: String,
    pub sequence: u64,
    pub chain_hash: String,
    pub signer_did: String,
    pub signature: String,
}

/// The four audit fields of the stored state, with that commit's defaults.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct FrozenAuditState {
    #[serde(default)]
    pub audit: Vec<RuntimeAuditEventV1>,
    #[serde(default)]
    pub audit_chain: Vec<AuditChainLinkV1>,
    #[serde(default)]
    pub audit_chain_state: Option<AuditChainStateV1>,
    #[serde(default)]
    pub audit_chain_anchor: Option<AuditChainAnchorV1>,
}

fn audit_chain_hash(
    sequence: u64,
    event_id: &str,
    previous_hash: &str,
    event_hash: &str,
) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schema": AUDIT_CHAIN_SCHEMA,
        "sequence": sequence,
        "event_id": event_id,
        "previous_hash": previous_hash,
        "event_hash": event_hash,
    }))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn audit_chain_signature_payload(
    sequence: u64,
    event_id: &str,
    previous_hash: &str,
    event_hash: &str,
    chain_hash: &str,
) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(&serde_json::json!({
        "schema": AUDIT_CHAIN_SCHEMA,
        "sequence": sequence,
        "event_id": event_id,
        "previous_hash": previous_hash,
        "event_hash": event_hash,
        "chain_hash": chain_hash,
    }))?)
}

fn audit_chain_state_payload(
    activated_at: u64,
    head_sequence: u64,
    head_hash: &str,
) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(&serde_json::json!({
        "schema": AUDIT_CHAIN_STATE_SCHEMA,
        "activated_at": activated_at,
        "head_sequence": head_sequence,
        "head_hash": head_hash,
    }))?)
}

fn audit_chain_anchor_payload(sequence: u64, chain_hash: &str) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(&serde_json::json!({
        "schema": AUDIT_CHAIN_ANCHOR_SCHEMA,
        "sequence": sequence,
        "chain_hash": chain_hash,
    }))?)
}

fn verify_audit_event_signature(
    event: &RuntimeAuditEventV1,
    expected_runtime_did: &str,
) -> anyhow::Result<()> {
    if event.schema != RuntimeAuditEventV1::SCHEMA {
        anyhow::bail!("unsupported audit event schema");
    }
    let signer_did = event
        .signer_did
        .as_deref()
        .ok_or_else(|| anyhow!("audit event is missing its signer DID"))?;
    if signer_did != expected_runtime_did {
        anyhow::bail!("audit event signer is not the Runtime identity");
    }
    let signature = event
        .signature
        .as_deref()
        .ok_or_else(|| anyhow!("audit event is missing its signature"))?;
    let mut unsigned = event.clone();
    unsigned.signature = None;
    crate::crypto::verify_domain_separated_signature(
        expected_runtime_did,
        AUDIT_EVENT_DOMAIN,
        &serde_json::to_vec(&unsigned)?,
        signature,
    )
    .context("audit event signature is invalid")
}

fn require_runtime_audit_signer(
    actual: &str,
    expected_runtime_did: &str,
    artifact: &str,
) -> anyhow::Result<()> {
    if actual != expected_runtime_did {
        anyhow::bail!("{artifact} signer is not the Runtime identity");
    }
    Ok(())
}

pub(crate) fn verify_audit_chain_from(
    expected_runtime_did: &str,
    state: &FrozenAuditState,
) -> anyhow::Result<()> {
    if state.audit.is_empty()
        && state.audit_chain.is_empty()
        && state.audit_chain_state.is_none()
        && state.audit_chain_anchor.is_none()
    {
        return Ok(());
    }
    if let Some(chain_state) = state.audit_chain_state.as_ref() {
        if chain_state.schema != AUDIT_CHAIN_STATE_SCHEMA {
            anyhow::bail!("unsupported audit chain state schema");
        }
        require_runtime_audit_signer(
            &chain_state.signer_did,
            expected_runtime_did,
            "audit chain state",
        )?;
        let payload = audit_chain_state_payload(
            chain_state.activated_at,
            chain_state.head_sequence,
            &chain_state.head_hash,
        )?;
        crate::crypto::verify_domain_separated_signature(
            expected_runtime_did,
            AUDIT_CHAIN_STATE_DOMAIN,
            &payload,
            &chain_state.signature,
        )
        .context("audit chain state signature is invalid")?;
        let (head_sequence, head_hash) = state
            .audit_chain
            .last()
            .map(|link| (link.sequence, link.chain_hash.as_str()))
            .unwrap_or((0, AUDIT_CHAIN_GENESIS));
        if chain_state.head_sequence != head_sequence || chain_state.head_hash != head_hash {
            anyhow::bail!("audit chain state does not match the persisted chain head");
        }
    } else if state.audit_chain_anchor.is_some() {
        anyhow::bail!("audit chain anchor requires explicit chain state");
    }
    if state.audit_chain.is_empty() {
        if !state.audit.is_empty() && state.audit_chain_state.is_some() {
            anyhow::bail!("audit chain is required after activation");
        }
        return Ok(());
    }
    if state.audit_chain.len() != state.audit.len() {
        anyhow::bail!("audit chain length does not match persisted audit events");
    }
    let protected_chain = state.audit_chain_state.is_some();
    let anchor = state.audit_chain_anchor.as_ref();
    if let Some(anchor) = anchor {
        if anchor.schema != AUDIT_CHAIN_ANCHOR_SCHEMA {
            anyhow::bail!("unsupported audit chain anchor schema");
        }
        require_runtime_audit_signer(
            &anchor.signer_did,
            expected_runtime_did,
            "audit chain anchor",
        )?;
        let payload = audit_chain_anchor_payload(anchor.sequence, &anchor.chain_hash)?;
        crate::crypto::verify_domain_separated_signature(
            expected_runtime_did,
            AUDIT_CHAIN_ANCHOR_DOMAIN,
            &payload,
            &anchor.signature,
        )
        .context("audit chain anchor signature is invalid")?;
    }
    let mut previous: Option<&AuditChainLinkV1> = None;
    for (event, link) in state.audit.iter().zip(&state.audit_chain) {
        if link.schema != AUDIT_CHAIN_SCHEMA || link.event_id != event.event_id {
            anyhow::bail!("audit chain event binding is invalid");
        }
        require_runtime_audit_signer(&link.signer_did, expected_runtime_did, "audit chain link")?;
        if let Some(previous) = previous {
            if link.sequence != previous.sequence.saturating_add(1)
                || link.previous_hash != previous.chain_hash
            {
                anyhow::bail!("audit chain sequence is invalid");
            }
        } else if let Some(anchor) = anchor {
            if link.sequence != anchor.sequence.saturating_add(1)
                || link.previous_hash != anchor.chain_hash
            {
                anyhow::bail!("audit chain does not continue from its retained anchor");
            }
        } else if protected_chain
            && (link.sequence != 1 || link.previous_hash != AUDIT_CHAIN_GENESIS)
        {
            anyhow::bail!("protected audit chain is missing its retained anchor");
        } else if link.sequence == 1 && link.previous_hash != AUDIT_CHAIN_GENESIS {
            anyhow::bail!("audit chain genesis is invalid");
        }
        verify_audit_event_signature(event, expected_runtime_did)?;
        let event_hash = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(serde_json::to_vec(event)?))
        );
        if link.event_hash != event_hash
            || link.chain_hash
                != audit_chain_hash(
                    link.sequence,
                    &link.event_id,
                    &link.previous_hash,
                    &link.event_hash,
                )?
        {
            anyhow::bail!("audit chain hash is invalid");
        }
        let payload = audit_chain_signature_payload(
            link.sequence,
            &link.event_id,
            &link.previous_hash,
            &link.event_hash,
            &link.chain_hash,
        )?;
        crate::crypto::verify_domain_separated_signature(
            expected_runtime_did,
            AUDIT_CHAIN_DOMAIN,
            &payload,
            &link.signature,
        )
        .context("audit chain signature is invalid")?;
        previous = Some(link);
    }
    Ok(())
}
