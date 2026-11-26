//! Canonical localhost:// roots for the WCI-aligned local Home model.

use std::path::{Path, PathBuf};

pub const MY_WEBSITE_URI: &str = "localhost://MyWebSite";
pub const PUBLISHER_ROOT_URI: &str = "localhost://ElastOS/SystemServices/Publisher";
pub const EDGE_ROOT_URI: &str = "localhost://ElastOS/SystemServices/Edge";

pub const FILE_BACKED_ROOTS: &[&str] = &[
    "AppCapsules",
    "ElastOS",
    "Local",
    "MyWebSite",
    "Public",
    "Users",
    "UsersAI",
];

pub const DYNAMIC_ROOTS: &[&str] = &["WebSpaces"];

pub const ALL_ROOTS: &[&str] = &[
    "AppCapsules",
    "ElastOS",
    "Local",
    "MyWebSite",
    "Public",
    "Users",
    "UsersAI",
    "WebSpaces",
];

pub fn is_supported_resource_scheme(uri: &str) -> bool {
    uri.starts_with("elastos://") || uri.starts_with("localhost://")
}

pub fn is_system_only_backend_resource(uri: &str) -> bool {
    let Some(rest) = uri.strip_prefix("elastos://") else {
        return false;
    };

    matches!(
        rest.split(['/', '?', '#']).next(),
        Some(
            "elacity"
                | "elacity-sdk"
                | "exit"
                | "net"
                | "gateway"
                | "ipfs"
                | "ipfs-cluster"
                | "ipfs-provider"
                | "kubo"
        )
    )
}

pub fn is_runtime_system_service_resource(uri: &str) -> bool {
    uri.strip_prefix("localhost://").is_some_and(|rest| {
        rest == "ElastOS/SystemServices" || rest.starts_with("ElastOS/SystemServices/")
    })
}

pub fn parse_localhost_uri(uri: &str) -> Option<(&str, &str)> {
    let rest = uri.strip_prefix("localhost://")?;
    parse_localhost_path(rest)
}

pub fn parse_localhost_path(path: &str) -> Option<(&str, &str)> {
    let trimmed = path.trim().trim_start_matches('/').trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }

    match trimmed.find('/') {
        Some(idx) => {
            let root = &trimmed[..idx];
            let remainder = &trimmed[idx + 1..];
            ALL_ROOTS.contains(&root).then_some((root, remainder))
        }
        None => ALL_ROOTS.contains(&trimmed).then_some((trimmed, "")),
    }
}

pub fn rooted_localhost_uri(path_or_uri: &str) -> Option<String> {
    if let Some((root, rest)) = parse_localhost_uri(path_or_uri) {
        return Some(if rest.is_empty() {
            format!("localhost://{}", root)
        } else {
            format!("localhost://{}/{}", root, rest)
        });
    }

    let (root, rest) = parse_localhost_path(path_or_uri)?;
    Some(if rest.is_empty() {
        format!("localhost://{}", root)
    } else {
        format!("localhost://{}/{}", root, rest)
    })
}

pub fn is_file_backed_root(root: &str) -> bool {
    FILE_BACKED_ROOTS.contains(&root)
}

pub fn is_plaintext_root(root: &str) -> bool {
    matches!(root, "MyWebSite" | "Public")
}

pub fn file_backed_prefixes() -> Vec<String> {
    FILE_BACKED_ROOTS
        .iter()
        .map(|root| (*root).to_string())
        .collect()
}

/// Roots holding per-person protected data. Protected writes refuse a parent
/// anyone else can read, so these must be owner-only from the moment they
/// exist — and healed if an earlier boot created them with the process umask,
/// or no one on that Home can ever save protected state.
#[cfg(unix)]
const OWNER_ONLY_ROOTS: &[&str] = &["Users", "UsersAI"];

#[cfg(windows)]
pub fn ensure_file_backed_roots(_base_dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "protected localhost roots require owner-only Windows ACL support",
    ))
}

#[cfg(all(test, windows))]
#[test]
fn windows_refuses_roots_without_owner_only_acl() {
    let error = ensure_file_backed_roots(Path::new("unused-windows-root")).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
}

#[cfg(unix)]
pub fn ensure_file_backed_roots(base_dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut created = Vec::new();
    for root in FILE_BACKED_ROOTS {
        let path = base_dir.join(root);
        std::fs::create_dir_all(&path)?;
        #[cfg(unix)]
        if OWNER_ONLY_ROOTS.contains(root) {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.is_dir() && metadata.permissions().mode() & 0o077 != 0 {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        created.push(path);
    }
    Ok(created)
}

pub fn rooted_localhost_fs_path(base_dir: &Path, path_or_uri: &str) -> Option<PathBuf> {
    let (root, rest) = if path_or_uri.starts_with("localhost://") {
        parse_localhost_uri(path_or_uri)?
    } else {
        parse_localhost_path(path_or_uri)?
    };
    if !is_file_backed_root(root) {
        return None;
    }

    let mut path = base_dir.join(root);
    if !rest.is_empty() {
        for segment in rest.split('/') {
            if segment.is_empty() {
                continue;
            }
            if segment == "." || segment == ".." || segment.contains('\\') {
                return None;
            }
            path.push(segment);
        }
    }
    Some(path)
}

pub fn my_website_root_path(base_dir: &Path) -> PathBuf {
    rooted_localhost_fs_path(base_dir, MY_WEBSITE_URI).expect("MyWebSite must be file-backed")
}

pub fn publisher_root_path(base_dir: &Path) -> PathBuf {
    rooted_localhost_fs_path(base_dir, PUBLISHER_ROOT_URI).expect("Publisher root must exist")
}

pub fn publisher_artifacts_path(base_dir: &Path) -> PathBuf {
    publisher_root_path(base_dir).join("artifacts")
}

pub fn publisher_site_releases_root_path(base_dir: &Path) -> PathBuf {
    publisher_root_path(base_dir).join("SiteReleases")
}

pub fn publisher_release_head_path(base_dir: &Path) -> PathBuf {
    publisher_root_path(base_dir).join("release-head.json")
}

pub fn publisher_release_manifest_path(base_dir: &Path) -> PathBuf {
    publisher_root_path(base_dir).join("release.json")
}

/// Installed signed inputs belong to Runtime, independently of Publisher output.
pub fn installation_release_head_path(base_dir: &Path) -> PathBuf {
    base_dir.join("installation/release-head.json")
}

pub fn installation_release_manifest_path(base_dir: &Path) -> PathBuf {
    base_dir.join("installation/release.json")
}

pub fn publisher_install_script_path(base_dir: &Path) -> PathBuf {
    publisher_root_path(base_dir).join("install.sh")
}

pub fn publisher_publish_state_path(base_dir: &Path) -> PathBuf {
    publisher_root_path(base_dir).join("publish-state.json")
}

pub fn publisher_site_releases_dir(base_dir: &Path, target_uri: &str) -> PathBuf {
    publisher_site_releases_root_path(base_dir).join(sanitize_edge_state_name(target_uri))
}

pub fn publisher_site_release_path(
    base_dir: &Path,
    target_uri: &str,
    release_name: &str,
) -> PathBuf {
    publisher_site_releases_dir(base_dir, target_uri)
        .join(format!("{}.json", sanitize_edge_state_name(release_name)))
}

pub fn edge_root_path(base_dir: &Path) -> PathBuf {
    rooted_localhost_fs_path(base_dir, EDGE_ROOT_URI).expect("Edge root must exist")
}

pub fn edge_bindings_path(base_dir: &Path) -> PathBuf {
    edge_root_path(base_dir).join("Bindings")
}

pub fn edge_site_heads_path(base_dir: &Path) -> PathBuf {
    edge_root_path(base_dir).join("SiteHeads")
}

pub fn edge_release_channels_root_path(base_dir: &Path) -> PathBuf {
    edge_root_path(base_dir).join("ReleaseChannels")
}

pub fn edge_site_history_root_path(base_dir: &Path) -> PathBuf {
    edge_root_path(base_dir).join("SiteHistory")
}

pub fn edge_browser_apps_root_path(base_dir: &Path) -> PathBuf {
    edge_root_path(base_dir).join("BrowserApps")
}

pub fn sanitize_edge_state_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

pub fn sanitize_edge_binding_name(domain: &str) -> String {
    sanitize_edge_state_name(domain.trim().trim_end_matches('.'))
}

pub fn edge_binding_path(base_dir: &Path, domain: &str) -> PathBuf {
    edge_bindings_path(base_dir).join(format!("{}.json", sanitize_edge_binding_name(domain)))
}

pub fn edge_site_head_path(base_dir: &Path, target_uri: &str) -> PathBuf {
    edge_site_heads_path(base_dir).join(format!("{}.json", sanitize_edge_state_name(target_uri)))
}

pub fn edge_site_history_dir(base_dir: &Path, target_uri: &str) -> PathBuf {
    edge_site_history_root_path(base_dir).join(sanitize_edge_state_name(target_uri))
}

pub fn edge_release_channels_dir(base_dir: &Path, target_uri: &str) -> PathBuf {
    edge_release_channels_root_path(base_dir).join(sanitize_edge_state_name(target_uri))
}

pub fn edge_release_channel_path(base_dir: &Path, target_uri: &str, channel_name: &str) -> PathBuf {
    edge_release_channels_dir(base_dir, target_uri)
        .join(format!("{}.json", sanitize_edge_state_name(channel_name)))
}

pub fn edge_browser_app_path(base_dir: &Path, app_name: &str) -> PathBuf {
    edge_browser_apps_root_path(base_dir)
        .join(format!("{}.json", sanitize_edge_state_name(app_name)))
}

pub fn ensure_system_service_roots(base_dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut created = ensure_file_backed_roots(base_dir)?;
    for path in [
        publisher_artifacts_path(base_dir),
        publisher_site_releases_root_path(base_dir),
        edge_bindings_path(base_dir),
        edge_browser_apps_root_path(base_dir),
        edge_site_heads_path(base_dir),
        edge_release_channels_root_path(base_dir),
        edge_site_history_root_path(base_dir),
        my_website_root_path(base_dir),
    ] {
        std::fs::create_dir_all(&path)?;
        created.push(path);
    }
    Ok(created)
}

#[cfg(unix)]
pub fn private_dir(path: &Path, relative: &str, create: bool) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let refuse = |err: std::io::Error| {
        format!("provider start is refused: {relative} could not be created: {err}")
    };
    if create {
        if let Err(err) = std::fs::DirBuilder::new().mode(0o700).create(path) {
            if err.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(refuse(err));
            }
        }
    }
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(refuse)?;
    if unsafe { libc::fchmod(dir.as_raw_fd(), 0o700) } < 0 {
        return Err(refuse(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_localhost_uri() {
        assert_eq!(
            parse_localhost_uri("localhost://Users/self/Documents"),
            Some(("Users", "self/Documents"))
        );
        assert_eq!(
            parse_localhost_uri("localhost://MyWebSite"),
            Some(("MyWebSite", ""))
        );
        assert_eq!(parse_localhost_uri("localhost://UnknownRoot/test"), None);
    }

    #[test]
    fn test_rooted_localhost_uri() {
        assert_eq!(
            rooted_localhost_uri("Users/self/.AppData/LocalHost/Chat/history.json"),
            Some("localhost://Users/self/.AppData/LocalHost/Chat/history.json".to_string())
        );
        assert_eq!(
            rooted_localhost_uri("localhost://Public/demo.txt"),
            Some("localhost://Public/demo.txt".to_string())
        );
        assert_eq!(rooted_localhost_uri("chat/history.json"), None);
    }

    #[test]
    fn test_rooted_localhost_fs_path() {
        let base = Path::new("/tmp/elastos");
        assert_eq!(
            rooted_localhost_fs_path(base, "localhost://ElastOS/SystemServices/Publisher").unwrap(),
            PathBuf::from("/tmp/elastos/ElastOS/SystemServices/Publisher")
        );
        assert_eq!(
            rooted_localhost_fs_path(base, "Users/self/Documents").unwrap(),
            PathBuf::from("/tmp/elastos/Users/self/Documents")
        );
        assert!(rooted_localhost_fs_path(base, "localhost://Public/../Users").is_none());
    }

    #[test]
    fn test_edge_binding_path() {
        let base = Path::new("/tmp/elastos");
        assert_eq!(
            edge_binding_path(base, "Elastos.ElacityLabs.com:443"),
            PathBuf::from(
                "/tmp/elastos/ElastOS/SystemServices/Edge/Bindings/elastos.elacitylabs.com_443.json"
            )
        );
    }

    #[test]
    fn test_edge_site_head_path() {
        let base = Path::new("/tmp/elastos");
        assert_eq!(
            edge_site_head_path(base, "localhost://MyWebSite"),
            PathBuf::from(
                "/tmp/elastos/ElastOS/SystemServices/Edge/SiteHeads/localhost___mywebsite.json"
            )
        );
    }

    #[test]
    fn test_edge_site_history_dir() {
        let base = Path::new("/tmp/elastos");
        assert_eq!(
            edge_site_history_dir(base, "localhost://MyWebSite"),
            PathBuf::from(
                "/tmp/elastos/ElastOS/SystemServices/Edge/SiteHistory/localhost___mywebsite"
            )
        );
    }

    #[test]
    fn test_edge_release_channel_path() {
        let base = Path::new("/tmp/elastos");
        assert_eq!(
            edge_release_channel_path(base, "localhost://MyWebSite", "live"),
            PathBuf::from(
                "/tmp/elastos/ElastOS/SystemServices/Edge/ReleaseChannels/localhost___mywebsite/live.json"
            )
        );
    }

    #[test]
    fn test_edge_browser_app_path() {
        let base = Path::new("/tmp/elastos");
        assert_eq!(
            edge_browser_app_path(base, "demo-app"),
            PathBuf::from("/tmp/elastos/ElastOS/SystemServices/Edge/BrowserApps/demo-app.json")
        );
    }

    #[cfg(unix)]
    #[test]
    fn ensure_private_directory_is_0700_and_does_not_follow_a_link() {
        use std::os::unix::fs::PermissionsExt;
        let held = tempfile::tempdir().unwrap();
        let mode = |path: &Path| {
            std::fs::symlink_metadata(path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        let existing = held.path().join("existing");
        std::fs::create_dir(&existing).unwrap();
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o755)).unwrap();
        private_dir(&existing, "ElastOS/System", false).unwrap();
        assert_eq!(mode(&existing), 0o700);
        let fresh = held.path().join("fresh");
        private_dir(&fresh, "ElastOS/System", true).unwrap();
        assert_eq!(mode(&fresh), 0o700);
        std::fs::set_permissions(&fresh, std::fs::Permissions::from_mode(0o755)).unwrap();
        private_dir(&fresh, "ElastOS/System", true).unwrap();
        assert_eq!(mode(&fresh), 0o700);
        let target = held.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = held.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let refused = private_dir(&link, "ElastOS/System", false).unwrap_err();
        assert!(
            refused.contains("provider start is refused"),
            "a link was followed or accepted: {refused}"
        );
        assert_eq!(mode(&target), 0o755);
    }

    #[test]
    fn test_publisher_site_release_path() {
        let base = Path::new("/tmp/elastos");
        assert_eq!(
            publisher_site_release_path(base, "localhost://MyWebSite", "weekend-demo"),
            PathBuf::from(
                "/tmp/elastos/ElastOS/SystemServices/Publisher/SiteReleases/localhost___mywebsite/weekend-demo.json"
            )
        );
    }
}
