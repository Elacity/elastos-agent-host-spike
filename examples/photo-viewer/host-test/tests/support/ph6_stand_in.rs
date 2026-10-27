//! This test code stands in for the Runtime's launch by CID, which does not exist yet.

use std::collections::BTreeMap;
use std::path::Path;

use capsule_bundle::{
    admit_staged_for_stand_in, bind_content_stand_in, load, select_stand_in_dependencies,
    Installed, Refusal, SignedClaim, TrustPolicy,
};
use capsule_v1_host_test::{admission, Bridge};
use elastos_common::CapsuleManifest;
use serde_json::Value;

pub const ALBUM: &str = "localhost://Users/self/.AppData/App/photo-viewer/album.json";
const PLAYLIST: &str = "localhost://Users/self/.AppData/App/photo-viewer/playlist.json";

#[derive(Debug)]
pub struct StandInEvidence {
    pub content_cid: String,
    pub viewer_cid: String,
    pub core_cid: String,
    pub playlist: Value,
    pub lines: Vec<Value>,
    pub bytes_served: BTreeMap<String, usize>,
}

#[derive(Debug)]
pub enum StandInLaunchError {
    Bundle(Refusal),
    Launch {
        stage: &'static str,
        reason: String,
        wrote_playlist: bool,
    },
}

impl From<Refusal> for StandInLaunchError {
    fn from(refusal: Refusal) -> Self {
        Self::Bundle(refusal)
    }
}

impl std::fmt::Display for StandInLaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bundle(refusal) => refusal.fmt(f),
            Self::Launch {
                stage,
                reason,
                wrote_playlist,
            } => write!(f, "{stage}: {reason} (wrote playlist: {wrote_playlist})"),
        }
    }
}

fn before_run(stage: &'static str, reason: impl ToString) -> StandInLaunchError {
    StandInLaunchError::Launch {
        stage,
        reason: reason.to_string(),
        wrote_playlist: false,
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn open_content_stand_in(
    store: &Path,
    content_cid: &str,
    selected_viewer: &str,
    selected_core: &str,
    claims: &BTreeMap<String, SignedClaim>,
    policy: &TrustPolicy,
    installed: &[Installed],
    now: u64,
    source_core: &Path,
    denied_read: Option<&str>,
) -> Result<StandInEvidence, StandInLaunchError> {
    let content = load(store, content_cid)?;
    admit_staged_for_stand_in(&content, claims, policy, installed, store, now)?;
    let dependencies = select_stand_in_dependencies(
        &content,
        selected_viewer,
        selected_core,
        claims,
        policy,
        installed,
        store,
        now,
    )?;
    let objects: Vec<_> = bind_content_stand_in(&content)?.into_iter().collect();
    let mut bridge = Bridge::with_list(ALBUM, "elastos.photo-viewer.album/v1", PLAYLIST, &objects);
    if let Some(denied_read) = denied_read {
        bridge.deny(denied_read, "read");
    }

    let core = load(store, &dependencies.core.cid)?;
    let entrypoint = core.manifest["entrypoint"]
        .as_str()
        .ok_or_else(|| before_run("manifest", "core entrypoint must be a string"))?;
    let wasm = core
        .bytes
        .get(entrypoint)
        .ok_or_else(|| before_run("imports", format!("staged core has no {entrypoint}")))?;
    admission::validate_component_imports(wasm).map_err(|reason| before_run("imports", reason))?;
    let manifest: CapsuleManifest = serde_json::from_slice(&core.bytes["capsule.json"])
        .map_err(|reason| before_run("manifest", reason))?;
    manifest
        .validate()
        .map_err(|reason| before_run("manifest", reason))?;
    std::fs::remove_dir_all(source_core).map_err(|reason| before_run("source", reason))?;
    #[rustfmt::skip]
    let (result, bridge) = capsule_v1_host_test::run(dependencies.core.path.as_path(), manifest, bridge).await;
    result.map_err(|reason: String| StandInLaunchError::Launch {
        stage: "run",
        reason,
        wrote_playlist: bridge.written.contains_key(PLAYLIST),
    })?;
    let playlist = bridge
        .written
        .get(PLAYLIST)
        .ok_or_else(|| before_run("playlist", "core did not write the playlist"))?;
    let playlist = serde_json::from_str(playlist).map_err(|reason: serde_json::Error| {
        StandInLaunchError::Launch {
            stage: "playlist",
            reason: reason.to_string(),
            wrote_playlist: true,
        }
    })?;
    Ok(StandInEvidence {
        content_cid: content.cid,
        viewer_cid: dependencies.viewer.cid,
        core_cid: dependencies.core.cid,
        playlist,
        lines: bridge.lines,
        bytes_served: bridge.bytes_served,
    })
}
