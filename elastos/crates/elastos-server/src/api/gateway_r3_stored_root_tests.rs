use super::*;
use std::path::{Path, PathBuf};

pub(super) const AGENT_ID: &str = crate::auth::valid_agent::ID;
pub(super) const AGENT_ROOT: &str = crate::auth::valid_agent::ROOT;
pub(super) const HUMAN_ROOT: &str = "localhost://Users/9a4eeb39460adc93f6028346";
pub(super) const NEEDS_PROTECTION: &str =
    "protected principal-root object requires active principal-root protection";

pub(super) fn fixture(agent: bool) -> (tempfile::TempDir, HomeLaunchTokenContext) {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let id = if agent {
        AGENT_ID
    } else {
        "person:local:r3-human"
    };
    if agent {
        let record = crate::auth::valid_agent::plant(dir.path());
        assert_eq!(record.principal_id, AGENT_ID);
        assert_eq!(record.localhost_root, AGENT_ROOT);
    } else {
        crate::auth::store_test_human_principal(dir.path(), id);
        crate::auth::store_test_principal_root_protection(dir.path(), id);
    }
    let root = crate::auth::ResolvedPrincipalRoot::resolve(dir.path(), dir.path(), id).unwrap();
    assert_eq!(
        root.localhost_root(),
        if agent { AGENT_ROOT } else { HUMAN_ROOT }
    );
    let context =
        HomeLaunchTokenContext::resolved(root, "session:r3".into(), None, "grant:r3".into());
    (dir, context)
}

pub(super) fn seed(dir: &Path, relative: &str, bytes: &[u8]) -> PathBuf {
    let path = dir
        .join(AGENT_ROOT.strip_prefix("localhost://").unwrap())
        .join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, bytes).unwrap();
    path
}

pub(in crate::api) fn verified_parent_device_context(
    child_data_dir: &Path,
    app: &str,
) -> (HomeLaunchTokenContext, String, String, String) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(child_data_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let (_, child_did) = elastos_identity::load_or_create_did(child_data_dir).unwrap();
    let parent = tempfile::tempdir().unwrap();
    let (_, parent_did) = elastos_identity::load_or_create_did(parent.path()).unwrap();
    let parent_context =
        super::gateway_home_token::local_home_launch_token_context(parent.path()).unwrap();
    let token = super::gateway_home_token::issue_home_launch_token_with_context(
        parent.path(),
        app,
        &parent_context,
    )
    .unwrap();
    let verified =
        super::gateway_home_token::require_home_launch_token_value_from_expected_did_for_test(
            child_data_dir,
            &token,
            &[app],
            parent_did.clone(),
            parent.path(),
        )
        .unwrap();
    let root_for = |did: String| {
        let digest = sha2::Sha256::digest(format!("device:{did}").as_bytes());
        format!("localhost://Users/{}", hex::encode(&digest[..12]))
    };
    use sha2::Digest;
    let parent_root = root_for(parent_did);
    let child_root = root_for(child_did);
    assert_eq!(verified.context.root().localhost_root(), parent_root);
    (verified.context, parent_root, child_root, token)
}
