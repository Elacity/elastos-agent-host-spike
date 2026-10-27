//! This test code stands in for the Runtime's launch by CID, which does not exist yet.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use capsule_bundle::{
    admit_staged_for_stand_in, bind_content_stand_in, load, select_stand_in_dependencies,
    Installed, Loaded, Refusal, SignedClaim, TrustPolicy,
};
use capsule_v1_host_test::{admission, Bridge, StandInBinding, STAND_IN_TEST_PRINCIPAL};
use elastos_common::CapsuleManifest;
use serde_json::Value;

pub const ALBUM: &str = "localhost://Users/self/.AppData/App/photo-viewer/album.json";
pub const PLAYLIST: &str = "localhost://Users/self/.AppData/App/photo-viewer/playlist.json";

pub fn launch_members(
    album: &str,
    playlist: &str,
    images: &BTreeMap<String, Vec<u8>>,
) -> BTreeSet<String> {
    let mut members: BTreeSet<_> = images.keys().cloned().collect();
    members.insert(album.into());
    members.insert(playlist.into());
    members
}

pub fn arm_content_stand_in(
    bridge: &mut Bridge,
    binding_id: String,
    content_cid: String,
    members: BTreeSet<String>,
    readmit: Box<dyn FnMut() -> Result<(), String> + Send>,
) {
    let binding = StandInBinding {
        binding_id,
        content_cid,
        instance_id: "".into(),
        principal: STAND_IN_TEST_PRINCIPAL.into(),
        members,
        active: false,
        readmit,
    };
    bridge.arm_stand_in(binding);
}

pub fn close_content_stand_in(bridge: &mut Bridge) {
    bridge.close_stand_in();
}

pub fn content_readmit(
    packages: [Loaded; 3],
    claims: BTreeMap<String, SignedClaim>,
    policy: Arc<Mutex<TrustPolicy>>,
    installed: Vec<Installed>,
    store: PathBuf,
    now: u64,
) -> Box<dyn FnMut() -> Result<(), String> + Send> {
    Box::new(move || {
        let policy = policy.lock().unwrap().clone();
        for package in &packages {
            admit_staged_for_stand_in(package, &claims, &policy, &installed, &store, now)
                .map_err(|refusal| match refusal {
                    Refusal::CidRevoked(cid) => format!(
                        "Content CID {cid} is revoked by the current policy; this launch is stopped."
                    ),
                    Refusal::PolicyStale { .. } =>
                        "The held policy is older than the accepted policy; use the current policy."
                            .into(),
                    refusal => refusal.to_string(),
                })?;
        }
        Ok(())
    })
}

#[derive(Debug)]
pub struct StandInEvidence {
    pub content_cid: String,
    pub viewer_cid: String,
    pub core_cid: String,
    pub playlist: Value,
    pub lines: Vec<Value>,
    pub bytes_served: BTreeMap<String, usize>,
    pub armed: bool,
    pub binding_active: bool,
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
    let images = bind_content_stand_in(&content)?;
    let members = launch_members(ALBUM, PLAYLIST, &images);
    let objects: Vec<_> = images.into_iter().collect();
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
    let viewer = load(store, &dependencies.viewer.cid)?;
    std::fs::remove_dir_all(source_core).map_err(|reason| before_run("source", reason))?;
    arm_content_stand_in(
        &mut bridge,
        format!("stand-in-{content_cid}"),
        content_cid.into(),
        members,
        content_readmit(
            [content.clone(), viewer, core],
            claims.clone(),
            Arc::new(Mutex::new(policy.clone())),
            installed.to_vec(),
            store.into(),
            now,
        ),
    );
    #[rustfmt::skip]
    let (result, bridge) = capsule_v1_host_test::run(dependencies.core.path.as_path(), manifest, bridge).await;
    let mut bridge = bridge;
    close_content_stand_in(&mut bridge);
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
        armed: bridge.stand_in.is_some(),
        binding_active: bridge
            .stand_in
            .as_ref()
            .is_some_and(|binding| binding.active),
        playlist,
        lines: bridge.lines,
        bytes_served: bridge.bytes_served,
    })
}
