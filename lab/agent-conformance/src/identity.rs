//! Safe identity observations shared by the builders, staging and report.

use crate::harness::ThrowawayHome;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

pub const PREFIX: &str = "version identity: ";
pub const ENTRYPOINT: &str = "agent-conformance-probe.component.wasm";
pub const MANIFEST: &[u8] = include_bytes!("../probe/capsule.json");

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProbeIdentity {
    pub effect: String,
    pub component_sha256: String,
    pub bundle_lab_cid: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Observation {
    Native { role: String, sha256: String },
    BuildOnly { probe: ProbeIdentity },
    Launched { probe: ProbeIdentity },
}

impl Observation {
    pub fn line(&self) -> String {
        format!("{PREFIX}{}", serde_json::to_string(self).unwrap())
    }

    pub fn emit(&self) {
        println!("{}", self.line());
    }
}

pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub struct StagedProbe {
    pub path: PathBuf,
    pub identity: ProbeIdentity,
}

/// Stage once, then name the exact manifest and payload through the sibling
/// library. Further byte consumption uses its checked entries, not a second read.
/// The path locates a fixture; the lab CID supplies identity, never admission.
pub fn stage_probe(
    home: &ThrowawayHome,
    bytes: &[u8],
    manifest: &[u8],
    effect: &str,
) -> Result<StagedProbe, String> {
    home.guard(home.home(), home.data())
        .map_err(str::to_owned)?;
    let path = home.root().join(format!("sha256-{}", sha256(bytes)));
    fs::create_dir(&path).map_err(|_| "probe staging: create bundle directory")?;
    fs::write(path.join("capsule.json"), manifest).map_err(|_| "probe staging: write manifest")?;
    fs::write(path.join(ENTRYPOINT), bytes).map_err(|_| "probe staging: write component")?;
    let checked = capsule_identity::checked_bundle(&path)
        .map_err(|_| "probe staging: bundle identity refused")?;
    let component = checked
        .entries()
        .iter()
        .find(|entry| entry.path == ENTRYPOINT)
        .ok_or("probe staging: missing checked component")?;
    Ok(StagedProbe {
        path,
        identity: ProbeIdentity {
            effect: effect.into(),
            component_sha256: sha256(&component.content),
            bundle_lab_cid: checked.cid().to_string(),
        },
    })
}
