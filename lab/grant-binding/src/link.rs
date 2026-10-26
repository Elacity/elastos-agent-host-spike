//! The one detector for a path dependency on this crate.

/// True only when the text names `grant-binding` and carries a `path` key.
///
/// A manifest that names the crate without a path dependency is not a link
/// to this crate's source.
pub fn cargo_toml_path_depends_on_grant_binding(cargo_toml: &str) -> bool {
    cargo_toml.contains("grant-binding") && cargo_toml.contains("path")
}
