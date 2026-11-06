//! Offline builds keep the developer's toolchain and lane-owned outputs.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

pub fn lane() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn repository() -> PathBuf {
    lane().parent().unwrap().parent().unwrap().to_path_buf()
}

/// Copy the capsule and its relative Bus contract into a fresh build tree.
/// Both locations stay in this checkout; all inputs are checked before creation.
pub fn copy_agent_host(source: &Path, destination: &Path) -> Result<PathBuf, String> {
    checked_directories(source, &repository())?;
    if destination.file_name().is_none()
        || destination
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err(format!(
            "copy destination {}: requires a normal path with a file name",
            destination.display()
        ));
    }
    checked_directories(
        destination
            .parent()
            .ok_or_else(|| format!("copy destination {}: needs a parent", destination.display()))?,
        &lane().join("target"),
    )?;
    let mut files = Vec::new();
    for (name, kind) in [
        ("examples/agent-host/Cargo.toml", InputKind::File),
        ("examples/agent-host/Cargo.lock", InputKind::File),
        ("examples/agent-host/capsule.json", InputKind::File),
        ("examples/agent-host/src", InputKind::Tree),
        ("elastos/wit/elastos-bus-v1.wit", InputKind::File),
    ] {
        let path = source.join(name);
        checked_directories(path.parent().unwrap(), source)?;
        copy_inputs(&path, kind, &mut files)?;
    }
    fs::create_dir(destination)
        .map_err(|error| format!("copy destination {}: {error}", destination.display()))?;
    for path in files {
        let target = destination.join(path.strip_prefix(source).unwrap());
        fs::create_dir_all(target.parent().unwrap())
            .and_then(|()| fs::copy(&path, &target).map(|_| ()))
            .map_err(|error| format!("copy input {}: {error}", path.display()))?;
    }
    Ok(destination.join("examples/agent-host"))
}

fn checked_directories(path: &Path, root: &Path) -> Result<(), String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| format!("copy path outside {}: {}", root.display(), path.display()))?;
    let mut cursor = root.to_path_buf();
    for component in std::iter::once(None).chain(relative.components().map(Some)) {
        if let Some(component) = component {
            if !matches!(component, Component::Normal(_)) {
                return Err(format!("copy path refused: {}", path.display()));
            }
            cursor.push(component);
        }
        let metadata = fs::symlink_metadata(&cursor)
            .map_err(|error| format!("copy directory {}: {error}", cursor.display()))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(format!(
                "copy requires a directory without symlinks: {}",
                cursor.display()
            ));
        }
    }
    Ok(())
}

enum InputKind {
    File,
    Tree,
    Any,
}

fn copy_inputs(path: &Path, kind: InputKind, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("copy input {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("copy refuses symlink: {}", path.display()));
    }
    match kind {
        InputKind::File if !metadata.is_file() => {
            return Err(format!("copy requires a regular input: {}", path.display()));
        }
        InputKind::Tree if !metadata.is_dir() => {
            return Err(format!(
                "copy requires an input directory: {}",
                path.display()
            ));
        }
        _ => {}
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path)
            .map_err(|error| format!("copy directory {}: {error}", path.display()))?
        {
            let entry =
                entry.map_err(|error| format!("copy directory {}: {error}", path.display()))?;
            copy_inputs(&entry.path(), InputKind::Any, files)?;
        }
    } else if metadata.is_file() {
        files.push(path.to_path_buf());
    } else {
        return Err(format!("copy requires a regular input: {}", path.display()));
    }
    Ok(())
}

/// Shared by the probe and Runtime builds; this is not a Runtime launch.
pub fn offline_build(program: &str, target: &Path) -> io::Result<Command> {
    fs::create_dir_all(target.join("tmp"))?;
    let mut command = Command::new(program);
    command
        .current_dir(repository())
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TARGET_DIR", target)
        .env("CARGO_BUILD_BUILD_DIR", target.join("build"))
        .env("TMPDIR", target.join("tmp"))
        .env("CARGO_INCREMENTAL", "0");
    Ok(command)
}
