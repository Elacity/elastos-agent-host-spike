use super::*;
use std::{
    env, fs, io,
    path::{Path, PathBuf},
};

pub(super) fn data_dir() -> PathBuf {
    if let Ok(dir) = env::var("ELASTOS_DATA_DIR") {
        PathBuf::from(dir)
    } else if let Ok(dir) = env::var("XDG_DATA_HOME") {
        PathBuf::from(dir).join("elastos")
    } else if let Some(home) = env::var_os("HOME") {
        PathBuf::from(home).join(".local/share/elastos")
    } else {
        PathBuf::from("/tmp/elastos")
    }
}

pub(super) fn node_lifecycle_state_path(data_dir: &Path) -> PathBuf {
    data_dir
        .join("chain-provider")
        .join("node-lifecycle-state.json")
}

pub(super) fn read_node_lifecycle_state_file(
    path: &Path,
) -> Result<NodeLifecycleStateFile, String> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(NodeLifecycleStateFile::default())
        }
        Err(err) => return Err(format!("read node lifecycle state: {err}")),
    };
    let state: NodeLifecycleStateFile = serde_json::from_str(&content)
        .map_err(|err| format!("parse node lifecycle state: {err}"))?;
    if state.schema != NODE_LIFECYCLE_STATE_SCHEMA {
        return Err("unsupported node lifecycle state schema".to_string());
    }
    for network_id in state.networks.keys() {
        validate_network_id(network_id)
            .map_err(|err| format!("invalid persisted network id {network_id}: {err}"))?;
    }
    Ok(state)
}

pub(super) fn write_node_lifecycle_state_file(
    path: &Path,
    state: &NodeLifecycleStateFile,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create state directory: {err}"))?;
    }
    let json = serde_json::to_vec_pretty(state)
        .map_err(|err| format!("serialize node lifecycle state: {err}"))?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, json).map_err(|err| format!("write node lifecycle state: {err}"))?;
    fs::rename(&tmp, path).map_err(|err| format!("commit node lifecycle state: {err}"))?;
    Ok(())
}
