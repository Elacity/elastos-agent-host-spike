//! The detached publisher claim, `elastos.capsule.claim/v1`.
//!
//! Minimal on purpose (review answer 8): the CID, what the capsule says it is,
//! and who says so. Provenance is a separate record ([`crate::provenance`]).

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::{sign, Refusal};

pub const CLAIM_SCHEMA: &str = "elastos.capsule.claim/v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub cid: String,
    pub name: String,
    pub version: String,
    pub role: String,
    pub publisher_did: String,
}

/// `{"schema", "claim", "signature"}`. The signer is `claim.publisher_did`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedClaim {
    pub schema: String,
    pub claim: Claim,
    pub signature: String,
}

/// Canonical bytes: sorted keys, no whitespace.
pub(crate) fn canonical<T: Serialize>(value: &T) -> Vec<u8> {
    // Through `Value`, whose map is sorted, so field order does not matter.
    serde_json::to_vec(&serde_json::to_value(value).unwrap()).unwrap()
}

impl Claim {
    pub fn sign(self, key: &SigningKey) -> SignedClaim {
        let (signature, _) = sign::sign(key, CLAIM_SCHEMA, &canonical(&self));
        SignedClaim {
            schema: CLAIM_SCHEMA.to_string(),
            claim: self,
            signature,
        }
    }
}

impl SignedClaim {
    /// Strict parse: unknown fields and another schema are refused.
    pub fn parse(bytes: &[u8]) -> Result<SignedClaim, Refusal> {
        let claim: SignedClaim = serde_json::from_slice(bytes)
            .map_err(|err| Refusal::ClaimMalformed(format!("claim: {err}")))?;
        if claim.schema != CLAIM_SCHEMA {
            return Err(Refusal::ClaimMalformed(format!(
                "claim schema {:?}, expected {CLAIM_SCHEMA}",
                claim.schema
            )));
        }
        Ok(claim)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        canonical(self)
    }

    pub fn verify(&self) -> Result<(), Refusal> {
        sign::verify(
            &self.claim.publisher_did,
            CLAIM_SCHEMA,
            &canonical(&self.claim),
            &self.signature,
        )
        .map_err(Refusal::SignatureInvalid)
    }
}
