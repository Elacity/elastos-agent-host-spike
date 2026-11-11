//! Provenance, `elastos.capsule.provenance/v1`: a rebuilder's signed statement
//! that a source commit and recipe rebuild to a CID (review answer 8).
//!
//! It is separate from the publisher claim and names the CID. Anyone who
//! rebuilds can add their own. Admission does not read it.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::claim::canonical;
use crate::{sign, Refusal};

pub const PROVENANCE_SCHEMA: &str = "elastos.capsule.provenance/v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub cid: String,
    pub source_commit: String,
    pub recipe: String,
    pub image_digest: String,
    pub rebuilder_did: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedProvenance {
    pub schema: String,
    pub provenance: Provenance,
    pub signature: String,
}

impl Provenance {
    pub fn sign(self, key: &SigningKey) -> SignedProvenance {
        let (signature, _) = sign::sign(key, PROVENANCE_SCHEMA, &canonical(&self));
        SignedProvenance {
            schema: PROVENANCE_SCHEMA.to_string(),
            provenance: self,
            signature,
        }
    }
}

impl SignedProvenance {
    pub fn parse(bytes: &[u8]) -> Result<SignedProvenance, Refusal> {
        let record: SignedProvenance = serde_json::from_slice(bytes)
            .map_err(|err| Refusal::ClaimMalformed(format!("provenance: {err}")))?;
        if record.schema != PROVENANCE_SCHEMA {
            return Err(Refusal::ClaimMalformed(format!(
                "provenance schema {:?}, expected {PROVENANCE_SCHEMA}",
                record.schema
            )));
        }
        Ok(record)
    }

    /// The record must name `cid` and be signed by its rebuilder.
    pub fn verify_for(&self, cid: &str) -> Result<(), Refusal> {
        if self.provenance.cid != cid {
            return Err(Refusal::ProvenanceCidMismatch {
                expected: cid.to_string(),
                named: self.provenance.cid.clone(),
            });
        }
        sign::verify(
            &self.provenance.rebuilder_did,
            PROVENANCE_SCHEMA,
            &canonical(&self.provenance),
            &self.signature,
        )
        .map_err(Refusal::SignatureInvalid)
    }
}
