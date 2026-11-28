//! Owned-name walk for A5 storage rows.
//!
//! A use path stays inside the owned root only when it is the root or a child
//! after a `/`. `..`, a symlink-shaped segment, and a prefix collision
//! (`instance-1` vs `instance-1-evil`) are refused. This is the harness walk;
//! the Runtime must refuse the same paths on a live operator.

use crate::contract::is_public_resource;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalkRefuse {
    HostPath,
    PublicRead,
    OutsidePrincipal,
    SymlinkShaped,
    OutsideRoot,
    PrefixCollision,
}

impl WalkRefuse {
    pub fn code(self) -> &'static str {
        match self {
            WalkRefuse::HostPath => "host_path",
            WalkRefuse::PublicRead => "public",
            WalkRefuse::OutsidePrincipal => "outside",
            WalkRefuse::SymlinkShaped => "symlink",
            WalkRefuse::OutsideRoot => "owned_root",
            WalkRefuse::PrefixCollision => "prefix",
        }
    }

    pub fn reason(self) -> &'static str {
        match self {
            WalkRefuse::HostPath => "owned root is a host path",
            WalkRefuse::PublicRead => "public storage read does not bind",
            WalkRefuse::OutsidePrincipal => "owned root is outside the agent principal",
            WalkRefuse::SymlinkShaped => "use path has a symlink-shaped segment",
            WalkRefuse::OutsideRoot => "use path leaves the owned root",
            WalkRefuse::PrefixCollision => "use path is a prefix collision",
        }
    }
}

fn strip_localhost(name: &str) -> &str {
    name.strip_prefix("localhost://").unwrap_or(name)
}

fn plain_segment(part: &str) -> bool {
    !part.is_empty()
        && part
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

/// True when `name` is `root` or a child of `root` after a `/`.
/// `root-evil` is a prefix collision, not a child.
pub fn is_child_of_root(root: &str, name: &str) -> bool {
    let root = strip_localhost(root);
    let name = strip_localhost(name);
    name == root
        || name
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
}

pub fn walk_owned(agent: &str, name: &str, owned_root: Option<&str>) -> Result<(), WalkRefuse> {
    let name = strip_localhost(name);
    if name.contains('\\') || name.starts_with('/') {
        return Err(WalkRefuse::HostPath);
    }
    let parts: Vec<&str> = name.split('/').collect();
    if parts
        .iter()
        .any(|part| part.is_empty() || *part == "." || *part == "..")
    {
        return Err(WalkRefuse::HostPath);
    }
    if is_public_resource(name) {
        return Err(WalkRefuse::PublicRead);
    }
    if parts.len() < 3 || parts[0] != "UsersAI" || parts[1] != agent {
        return Err(WalkRefuse::OutsidePrincipal);
    }
    if !parts.iter().skip(2).all(|part| plain_segment(part)) {
        return Err(WalkRefuse::SymlinkShaped);
    }
    if let Some(root) = owned_root {
        let root = strip_localhost(root);
        if !is_child_of_root(root, name) {
            if name.strip_prefix(root).is_some() {
                return Err(WalkRefuse::PrefixCollision);
            }
            return Err(WalkRefuse::OutsideRoot);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_of_root_requires_a_slash() {
        assert!(is_child_of_root(
            "UsersAI/a/s/instance-1",
            "UsersAI/a/s/instance-1"
        ));
        assert!(is_child_of_root(
            "UsersAI/a/s/instance-1",
            "UsersAI/a/s/instance-1/notes"
        ));
        assert!(!is_child_of_root(
            "UsersAI/a/s/instance-1",
            "UsersAI/a/s/instance-1-evil"
        ));
        assert!(!is_child_of_root(
            "UsersAI/a/s/instance-1",
            "UsersAI/a/s/instance-1-evil/notes"
        ));
    }

    #[test]
    fn walk_refuses_dotdot_symlink_and_prefix() {
        let root = "UsersAI/agent-a/sess/instance-1";
        assert_eq!(
            walk_owned("agent-a", &format!("{root}/notes"), Some(root)).unwrap(),
            ()
        );
        assert_eq!(
            walk_owned("agent-a", &format!("{root}/../notes"), Some(root)).unwrap_err(),
            WalkRefuse::HostPath
        );
        assert_eq!(
            walk_owned("agent-a", &format!("{root}/notes/foo/.."), Some(root)).unwrap_err(),
            WalkRefuse::HostPath
        );
        assert_eq!(
            walk_owned("agent-a", &format!("{root}/notes/link@x"), Some(root)).unwrap_err(),
            WalkRefuse::SymlinkShaped
        );
        assert_eq!(
            walk_owned(
                "agent-a",
                "UsersAI/agent-a/sess/instance-1-evil/notes",
                Some(root)
            )
            .unwrap_err(),
            WalkRefuse::PrefixCollision
        );
        assert_eq!(
            walk_owned("agent-a", "Public/a5-binding/notes", Some(root)).unwrap_err(),
            WalkRefuse::PublicRead
        );
    }
}
