//! The one detector for a dependency on this crate.

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

/// True when one cargo metadata parse names a dependency grant-binding.
///
/// The package's own name is not a dependency. A manifest cargo cannot parse
/// is not a link.
/// Operational failures stop the check with a reason.
pub fn cargo_toml_path_depends_on_grant_binding(cargo_toml: &str) -> bool {
    dependency_names(cargo_toml)
}

/// Writes one manifest and a dummy source file, then checks that file.
///
/// Cargo is spawned by `metadata_names`, once, from the check below.
/// An unsuccessful Cargo exit is not a link. Operational failures still stop
/// this check with their own reasons.
fn dependency_names(cargo_toml: &str) -> bool {
    with_manifest_dir(&std::env::temp_dir(), |dir| {
        stage_manifest(dir, cargo_toml)?;
        let manifest = dir.join("Cargo.toml");
        Ok(manifest_depends_on_grant_binding(&manifest))
    })
    .unwrap_or_else(|error| panic!("dependency check failed: {error}"))
}

#[rustfmt::skip]
pub fn manifest_depends_on_grant_binding(manifest: &std::path::Path) -> bool {
    let cargo_toml = std::fs::read_to_string(manifest).unwrap_or_default();
    let _text = cargo_toml.as_str();
    metadata_names(manifest).iter().any(|name| name == "grant-binding")
}

#[derive(Debug)]
enum MetadataRefuse {
    CreateDirectory,
    CreateSourceDirectory,
    WriteManifest,
    WriteSource,
    LaunchCargo,
    DecodeOutput,
    ResolveManifest,
    ManifestParent,
    WorkspaceRoot,
    ResolveWorkspaceRoot,
    ResolvePackageManifest,
    RemoveDirectory,
    CleanupAfter(Box<MetadataRefuse>),
    CleanupAfterPanic(String),
}

impl fmt::Display for MetadataRefuse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CreateDirectory => "cannot create temporary manifest directory",
            Self::CreateSourceDirectory => "cannot create temporary source directory",
            Self::WriteManifest => "cannot write temporary Cargo.toml",
            Self::WriteSource => "cannot write temporary src/lib.rs",
            Self::LaunchCargo => "cannot launch cargo metadata",
            Self::DecodeOutput => "cargo metadata output is not UTF-8",
            Self::ResolveManifest => "cannot resolve input manifest path",
            Self::ManifestParent => "input manifest path has no parent directory",
            Self::WorkspaceRoot => "cargo metadata has no workspace root",
            Self::ResolveWorkspaceRoot => "cannot resolve metadata workspace root",
            Self::ResolvePackageManifest => "cannot resolve metadata package manifest path",
            Self::RemoveDirectory => "cannot remove temporary manifest directory",
            Self::CleanupAfter(error) => {
                return write!(f, "{error}; {}", Self::RemoveDirectory);
            }
            Self::CleanupAfterPanic(reason) => {
                return write!(
                    f,
                    "metadata operation panicked: {reason}; {}",
                    Self::RemoveDirectory
                );
            }
        })
    }
}

/// This is the shared ownership boundary for all metadata files and cleanup.
/// Cleanup runs once, including after a panic, and preserves both failures.
fn with_manifest_dir<T>(
    parent: &Path,
    operation: impl FnOnce(&Path) -> Result<T, MetadataRefuse>,
) -> Result<T, MetadataRefuse> {
    let dir = fresh_manifest_dir(parent)?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| operation(&dir)));
    match (result, fs::remove_dir_all(&dir)) {
        (Ok(result), Ok(())) => result,
        (Ok(result), Err(_)) => Err(match result {
            Ok(_) => MetadataRefuse::RemoveDirectory,
            Err(error) => MetadataRefuse::CleanupAfter(Box::new(error)),
        }),
        (Err(panic), Ok(())) => std::panic::resume_unwind(panic),
        (Err(panic), Err(_)) => Err(MetadataRefuse::CleanupAfterPanic(
            panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| {
                    panic
                        .downcast_ref::<&str>()
                        .map(|reason| (*reason).to_owned())
                })
                .unwrap_or_else(|| "non-string panic".to_owned()),
        )),
    }
}

fn fresh_manifest_dir(parent: &Path) -> Result<PathBuf, MetadataRefuse> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    loop {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = parent.join(format!("grant-binding-meta-{}-{n}", std::process::id()));
        match builder.create(&dir) {
            Ok(()) => return Ok(dir),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(MetadataRefuse::CreateDirectory),
        }
    }
}

fn write_metadata_inputs(dir: &Path, cargo_toml: &str) -> Result<(), MetadataRefuse> {
    fs::write(dir.join("Cargo.toml"), cargo_toml).map_err(|_| MetadataRefuse::WriteManifest)?;
    fs::write(dir.join("src/lib.rs"), "").map_err(|_| MetadataRefuse::WriteSource)
}

fn stage_manifest(dir: &Path, cargo_toml: &str) -> Result<(), MetadataRefuse> {
    fs::create_dir(dir.join("src")).map_err(|_| MetadataRefuse::CreateSourceDirectory)?;
    write_metadata_inputs(dir, cargo_toml)
}

#[cfg(test)]
fn metadata_dependency_names(dir: &Path, cargo_toml: &str) -> Result<Vec<String>, MetadataRefuse> {
    stage_manifest(dir, cargo_toml)?;
    Ok(metadata_names(&dir.join("Cargo.toml")))
}

/// One `cargo metadata --offline --no-deps` parse.
///
/// An unsuccessful Cargo exit returns an empty list. Launch and decode failures
/// stop the check with their own reasons. The list is dependency names, plus
/// member names when this directory is the workspace root.
fn metadata_names(manifest: &Path) -> Vec<String> {
    let manifest = fs::canonicalize(manifest).unwrap_or_else(|_| {
        panic!(
            "dependency check failed: {}",
            MetadataRefuse::ResolveManifest
        )
    });
    let manifest_dir = manifest.parent().unwrap_or_else(|| {
        panic!(
            "dependency check failed: {}",
            MetadataRefuse::ManifestParent
        )
    });
    let program = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let output = match Command::new(program)
        .current_dir(manifest_dir)
        .env("CARGO_TARGET_DIR", manifest_dir.join("target"))
        .args([
            "metadata",
            "--offline",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
        ])
        .arg(&manifest)
        .output()
    {
        Ok(output) => output,
        Err(_) => panic!("dependency check failed: {}", MetadataRefuse::LaunchCargo),
    };
    if !output.status.success() {
        return Vec::new();
    }
    let json = match String::from_utf8(output.stdout) {
        Ok(json) => json,
        Err(_) => panic!("dependency check failed: {}", MetadataRefuse::DecodeOutput),
    };
    names_for_manifest(&read_metadata(&json), &manifest)
        .unwrap_or_else(|error| panic!("dependency check failed: {error}"))
}

/// `name` strings from each package object's `dependencies` array.
///
/// A `dependencies` array inside metadata is not a package dependency.
/// The package object's own `name` is not a dependency.
#[cfg(test)]
fn names_in_dependency_arrays(json: &str) -> Vec<String> {
    read_metadata(json)
        .packages
        .into_iter()
        .flat_map(|package| package.dependencies)
        .collect()
}

struct SeenPackage {
    id: String,
    name: String,
    manifest_path: String,
    dependencies: Vec<String>,
}

struct MetadataSeen {
    open_deps: Vec<String>,
    workspace_root: Option<String>,
    member_ids: Vec<String>,
    packages: Vec<SeenPackage>,
}

fn read_metadata(json: &str) -> MetadataSeen {
    let mut seen = MetadataSeen {
        open_deps: Vec::new(),
        workspace_root: None,
        member_ids: Vec::new(),
        packages: Vec::new(),
    };
    let mut scan = JsonScan {
        bytes: json.as_bytes(),
        index: 0,
    };
    scan.walk_document(&mut seen);
    seen
}

/// Dependency names of the checked package or workspace, plus member names
/// when this directory is the workspace root.
///
/// A member manifest collects its own dependencies. A workspace root also
/// collects its members' dependencies and names, leaving its own package name
/// out. Each package path is resolved once before either collection rule.
fn names_for_manifest(seen: &MetadataSeen, manifest: &Path) -> Result<Vec<String>, MetadataRefuse> {
    let own = fs::canonicalize(manifest).map_err(|_| MetadataRefuse::ResolveManifest)?;
    // The canonical manifest already gives us a resolved directory, including
    // for a relative path or a symlink to a manifest in another directory.
    let manifest_dir = own.parent().ok_or(MetadataRefuse::ManifestParent)?;
    let workspace_root = seen
        .workspace_root
        .as_deref()
        .ok_or(MetadataRefuse::WorkspaceRoot)?;
    let workspace_root =
        fs::canonicalize(workspace_root).map_err(|_| MetadataRefuse::ResolveWorkspaceRoot)?;
    let is_workspace_root = manifest_dir == workspace_root;
    let mut names = Vec::new();
    for package in &seen.packages {
        let path = fs::canonicalize(&package.manifest_path)
            .map_err(|_| MetadataRefuse::ResolvePackageManifest)?;
        let is_member = seen.member_ids.iter().any(|id| id == &package.id);
        if path == own || (is_workspace_root && is_member) {
            names.extend(package.dependencies.iter().cloned());
        }
        if is_workspace_root && is_member && path != own {
            names.push(package.name.clone());
        }
    }
    Ok(names)
}

struct JsonScan<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl JsonScan<'_> {
    fn skip_ws(&mut self) {
        while self
            .bytes
            .get(self.index)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.index += 1;
        }
    }

    fn walk_document(&mut self, seen: &mut MetadataSeen) {
        self.skip_ws();
        if self.bytes.get(self.index) == Some(&b'{') {
            self.walk_object(seen, false, false, true);
        } else {
            self.walk_value(seen);
        }
    }

    fn walk_value(&mut self, seen: &mut MetadataSeen) {
        self.skip_ws();
        match self.bytes.get(self.index).copied() {
            Some(b'{') => self.walk_object(seen, false, false, false),
            Some(b'[') => self.walk_array(seen, false, false, false),
            Some(b'"') => {
                let _ = self.parse_string();
            }
            Some(b't' | b'f' | b'n') => self.skip_letters(),
            Some(b'-' | b'0'..=b'9') => self.skip_number(),
            Some(_) => self.index += 1,
            None => {}
        }
    }

    /// `is_package` is an element of the root `packages` array.
    /// Metadata objects stay plain: their keys are not dependency data.
    /// A package object's own `name` is recorded for workspace members only.
    fn walk_object(
        &mut self,
        seen: &mut MetadataSeen,
        in_dependency: bool,
        is_package: bool,
        is_root: bool,
    ) {
        self.index += 1;
        let mut package_id = String::new();
        let mut package_name = String::new();
        let mut package_manifest = String::new();
        let saved_open_deps = if is_package {
            std::mem::take(&mut seen.open_deps)
        } else {
            Vec::new()
        };
        loop {
            self.skip_ws();
            match self.bytes.get(self.index).copied() {
                None | Some(b'}') => {
                    if self.bytes.get(self.index) == Some(&b'}') {
                        self.index += 1;
                    }
                    if is_package {
                        let dependencies = std::mem::take(&mut seen.open_deps);
                        seen.open_deps = saved_open_deps;
                        seen.packages.push(SeenPackage {
                            id: package_id,
                            name: package_name,
                            manifest_path: package_manifest,
                            dependencies,
                        });
                    }
                    return;
                }
                Some(b',') => self.index += 1,
                Some(_) => {
                    let key = self.parse_string();
                    self.skip_ws();
                    if self.bytes.get(self.index) == Some(&b':') {
                        self.index += 1;
                    }
                    self.skip_ws();
                    if in_dependency && key == "name" && self.bytes.get(self.index) == Some(&b'"') {
                        seen.open_deps.push(self.parse_string());
                    } else if is_package
                        && key == "dependencies"
                        && self.bytes.get(self.index) == Some(&b'[')
                    {
                        self.walk_array(seen, true, false, false);
                    } else if is_package && key == "id" && self.bytes.get(self.index) == Some(&b'"')
                    {
                        package_id = self.parse_string();
                    } else if is_package
                        && key == "name"
                        && self.bytes.get(self.index) == Some(&b'"')
                    {
                        package_name = self.parse_string();
                    } else if is_package
                        && key == "manifest_path"
                        && self.bytes.get(self.index) == Some(&b'"')
                    {
                        package_manifest = self.parse_string();
                    } else if is_root
                        && key == "packages"
                        && self.bytes.get(self.index) == Some(&b'[')
                    {
                        self.walk_array(seen, false, true, false);
                    } else if is_root
                        && key == "workspace_root"
                        && self.bytes.get(self.index) == Some(&b'"')
                    {
                        seen.workspace_root = Some(self.parse_string());
                    } else if is_root
                        && key == "workspace_members"
                        && self.bytes.get(self.index) == Some(&b'[')
                    {
                        self.walk_array(seen, false, false, true);
                    } else {
                        self.walk_value(seen);
                    }
                }
            }
        }
    }

    fn walk_array(
        &mut self,
        seen: &mut MetadataSeen,
        dependency_elements: bool,
        package_elements: bool,
        member_id_elements: bool,
    ) {
        self.index += 1;
        loop {
            self.skip_ws();
            match self.bytes.get(self.index).copied() {
                None => return,
                Some(b']') => {
                    self.index += 1;
                    return;
                }
                Some(b',') => self.index += 1,
                Some(b'{') => {
                    self.walk_object(seen, dependency_elements, package_elements, false);
                }
                Some(b'"') if member_id_elements => {
                    seen.member_ids.push(self.parse_string());
                }
                Some(_) => self.walk_value(seen),
            }
        }
    }

    fn parse_string(&mut self) -> String {
        if self.bytes.get(self.index) != Some(&b'"') {
            if self.index < self.bytes.len() {
                self.index += 1;
            }
            return String::new();
        }
        self.index += 1;
        let mut out = Vec::new();
        while let Some(byte) = self.bytes.get(self.index).copied() {
            self.index += 1;
            if byte == b'"' {
                break;
            }
            if byte != b'\\' {
                out.push(byte);
                continue;
            }
            let Some(escaped) = self.bytes.get(self.index).copied() else {
                break;
            };
            self.index += 1;
            match escaped {
                b'"' | b'\\' | b'/' => out.push(escaped),
                b'b' => out.push(0x08),
                b'f' => out.push(0x0c),
                b'n' => out.push(b'\n'),
                b'r' => out.push(b'\r'),
                b't' => out.push(b'\t'),
                b'u' => {
                    if let Some(ch) = self.decode_u_escape() {
                        let mut buf = [0u8; 4];
                        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                    }
                }
                other => out.push(other),
            }
        }
        String::from_utf8(out).unwrap_or_default()
    }

    fn decode_u_escape(&mut self) -> Option<char> {
        let mut value = 0u32;
        for _ in 0..4 {
            let digit = self.bytes.get(self.index).copied()?;
            let hex = match digit {
                b'0'..=b'9' => u32::from(digit - b'0'),
                b'a'..=b'f' => u32::from(digit - b'a') + 10,
                b'A'..=b'F' => u32::from(digit - b'A') + 10,
                _ => return None,
            };
            self.index += 1;
            value = (value << 4) | hex;
        }
        char::from_u32(value)
    }

    fn skip_letters(&mut self) {
        while self
            .bytes
            .get(self.index)
            .is_some_and(u8::is_ascii_alphabetic)
        {
            self.index += 1;
        }
    }

    fn skip_number(&mut self) {
        while self
            .bytes
            .get(self.index)
            .is_some_and(|byte| matches!(byte, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E'))
        {
            self.index += 1;
        }
    }
}

#[cfg(test)]
fn package_manifest(body: &str) -> String {
    format!("[package]\nname = \"fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n{body}")
}

#[cfg(test)]
fn dependency_manifest(deps: &str) -> String {
    package_manifest(&format!("[dependencies]\n{deps}"))
}

#[cfg(test)]
fn root_then_package(root: &str) -> String {
    format!("{root}\n[package]\nname = \"fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\n")
}

#[cfg(test)]
fn metadata_test_child(dir: &Path, cargo: Option<&Path>) -> std::process::Output {
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args(["--exact", std::thread::current().name().expect("test name")])
        .env("GRANT_BINDING_METADATA_TEST_CHILD", "1")
        .env("TMPDIR", dir)
        .env("TMP", dir)
        .env("TEMP", dir);
    if let Some(cargo) = cargo {
        command.env("CARGO", cargo);
    }
    command.output().expect("run metadata test child")
}

#[cfg(test)]
fn assert_metadata_child_failure(output: std::process::Output, reason: &str) {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(101), "{text}");
    assert!(
        text.lines()
            .any(|line| line == format!("dependency check failed: {reason}")),
        "{text}"
    );
}

#[test]
#[cfg(unix)]
fn model_metadata_collisions_preserve_existing_files() {
    use std::os::unix::fs::symlink;

    if std::env::var_os("GRANT_BINDING_METADATA_TEST_CHILD").is_some() {
        // The child runs only this test, so its first candidate uses counter 0.
        let parent = std::env::temp_dir();
        let candidate = |n| parent.join(format!("grant-binding-meta-{}-{n}", std::process::id()));
        let planted = candidate(0);
        fs::create_dir(&planted).expect("collision directory");
        fs::create_dir(planted.join("src")).expect("planted source directory");
        fs::write(planted.join("sentinel"), "keep sentinel").expect("sentinel");
        fs::write(planted.join("Cargo.toml"), "keep manifest").expect("manifest sentinel");
        let target = parent.join("disposable-source");
        fs::write(&target, "keep source").expect("disposable source");
        symlink(&target, planted.join("src/lib.rs")).expect("planted source symlink");
        fs::write(candidate(1), "keep file collision").expect("file collision");
        symlink(&planted, candidate(2)).expect("directory symlink collision");
        symlink(parent.join("absent"), candidate(3)).expect("dangling symlink collision");

        assert!(cargo_toml_path_depends_on_grant_binding(
            &dependency_manifest("grant-binding = '1.2.3'\n\n[workspace]\n")
        ));
        assert_eq!(
            fs::read_to_string(planted.join("sentinel")).unwrap(),
            "keep sentinel"
        );
        assert_eq!(
            fs::read_to_string(planted.join("Cargo.toml")).unwrap(),
            "keep manifest"
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep source");
        assert_eq!(fs::read_link(planted.join("src/lib.rs")).unwrap(), target);
        assert_eq!(
            fs::read_to_string(candidate(1)).unwrap(),
            "keep file collision"
        );
        assert_eq!(fs::read_link(candidate(2)).unwrap(), planted);
        assert_eq!(fs::read_link(candidate(3)).unwrap(), parent.join("absent"));
        assert!(!candidate(4).exists(), "owned directory was cleaned");
        assert_eq!(fs::read_dir(parent).unwrap().count(), 5);
        return;
    }
    with_manifest_dir(&std::env::temp_dir(), |dir| {
        let output = metadata_test_child(dir, None);
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    })
    .unwrap();
}

#[test]
fn model_metadata_file_failures_have_reasons_and_cleanup() {
    with_manifest_dir(&std::env::temp_dir(), |parent| {
        let missing_parent = parent.join("missing");
        let error = with_manifest_dir(&missing_parent, |_| -> Result<(), MetadataRefuse> {
            panic!("operation requires an owned directory")
        })
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "cannot create temporary manifest directory"
        );
        for (stage, reason) in [
            (0, "cannot create temporary source directory"),
            (1, "cannot write temporary Cargo.toml"),
            (2, "cannot write temporary src/lib.rs"),
        ] {
            let error = with_manifest_dir(parent, |dir| {
                if stage == 0 {
                    fs::write(dir.join("src"), "occupied").unwrap();
                    return metadata_dependency_names(dir, &package_manifest(""));
                }
                fs::create_dir(dir.join("src")).unwrap();
                let blocked = if stage == 1 {
                    "Cargo.toml"
                } else {
                    "src/lib.rs"
                };
                fs::create_dir(dir.join(blocked)).unwrap();
                write_metadata_inputs(dir, &package_manifest(""))?;
                Ok(Vec::new())
            })
            .unwrap_err();
            assert_eq!(error.to_string(), reason);
            assert_eq!(fs::read_dir(parent).unwrap().count(), 0);
        }
        Ok(())
    })
    .unwrap();
}

#[test]
fn model_metadata_missing_cargo_stops_the_detector() {
    if std::env::var_os("GRANT_BINDING_METADATA_TEST_CHILD").is_some() {
        assert!(!cargo_toml_path_depends_on_grant_binding(
            &dependency_manifest("grant-binding = { path = 'missing-gb' }\n")
        ));
        return;
    }
    with_manifest_dir(&std::env::temp_dir(), |dir| {
        let output = metadata_test_child(dir, Some(&dir.join("missing-cargo")));
        assert_metadata_child_failure(output, "cannot launch cargo metadata");
        assert_eq!(fs::read_dir(dir).unwrap().count(), 0);
        Ok(())
    })
    .unwrap();
}

#[test]
#[cfg(unix)]
fn model_metadata_output_failure_and_nonzero_exit_stay_distinct() {
    use std::os::unix::fs::PermissionsExt;

    if std::env::var_os("GRANT_BINDING_METADATA_TEST_CHILD").is_some() {
        let root = std::env::temp_dir().join("ws");
        fs::create_dir_all(root.join("gb/src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"gb\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        fs::write(
            root.join("gb/Cargo.toml"),
            "[package]\nname = \"grant-binding\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(root.join("gb/src/lib.rs"), "").unwrap();
        let manifest = root.join("Cargo.toml");
        let cargo = PathBuf::from(std::env::var_os("CARGO").unwrap());
        for status in [0, 1, 101] {
            fs::write(
                &cargo,
                format!("#!/bin/sh\nprintf '\\377'\nexit {status}\n"),
            )
            .unwrap();
            fs::set_permissions(&cargo, fs::Permissions::from_mode(0o700)).unwrap();
            if status == 0 {
                for direct in [true, false] {
                    let panic = std::panic::catch_unwind(|| {
                        if direct {
                            manifest_depends_on_grant_binding(&manifest)
                        } else {
                            cargo_toml_path_depends_on_grant_binding(&package_manifest(""))
                        }
                    })
                    .unwrap_err();
                    assert_eq!(
                        panic.downcast_ref::<String>().unwrap(),
                        "dependency check failed: cargo metadata output is not UTF-8"
                    );
                }
            } else {
                assert_eq!(metadata_names(&manifest), Vec::<String>::new(), "{status}");
                assert!(!manifest_depends_on_grant_binding(&manifest), "{status}");
                assert!(
                    !cargo_toml_path_depends_on_grant_binding(&package_manifest("")),
                    "{status}"
                );
            }
        }
        fs::remove_dir_all(&root).unwrap();
        return;
    }
    with_manifest_dir(&std::env::temp_dir(), |dir| {
        let cargo = dir.join("cargo-fixture");
        let output = metadata_test_child(dir, Some(&cargo));
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_dir(dir).unwrap().count(),
            1,
            "only the fixture remains"
        );
        Ok(())
    })
    .unwrap();
}

#[test]
fn model_metadata_rejection_returns_an_empty_list() {
    let root = std::env::temp_dir().join(format!("gb-reject-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"missing\"]\n",
    )
    .unwrap();
    assert_eq!(
        metadata_names(&root.join("Cargo.toml")),
        Vec::<String>::new()
    );
    assert!(!manifest_depends_on_grant_binding(&root.join("Cargo.toml")));
    assert!(!cargo_toml_path_depends_on_grant_binding(
        "[workspace]\nmembers = [\"missing\"]\n"
    ));
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn model_metadata_cleanup_failure_keeps_both_reasons() {
    with_manifest_dir(&std::env::temp_dir(), |parent| {
        for (result, reason) in [
            (Ok(false), "cannot remove temporary manifest directory"),
            (Ok(true), "cannot remove temporary manifest directory"),
            (
                Err(MetadataRefuse::LaunchCargo),
                "cannot launch cargo metadata; cannot remove temporary manifest directory",
            ),
        ] {
            let error = with_manifest_dir(parent, |dir| {
                fs::remove_dir(dir).unwrap();
                fs::write(dir, "block directory cleanup").unwrap();
                result
            })
            .unwrap_err();
            assert_eq!(error.to_string(), reason);
        }
        Ok(())
    })
    .unwrap();
}

#[test]
fn model_escaped_unicode_path_is_a_link() {
    let escaped =
        dependency_manifest("gb = { package = \"grant-bind\\u0069ng\", version = \"1.2.3\" }\n");
    assert!(!escaped.contains("grant-binding"));
    assert!(escaped.contains("\\u0069"));
    assert!(cargo_toml_path_depends_on_grant_binding(&escaped));
    let wide = dependency_manifest(
        "gb = { package = \"grant-bind\\U00000069ng\", version = \"1.2.3\" }\n",
    );
    assert!(!wide.contains("grant-binding"));
    assert!(cargo_toml_path_depends_on_grant_binding(&wide));
    let literal =
        dependency_manifest("gb = { package = 'grant-bind\\u0069ng', version = '1.2.3' }\n");
    assert!(!literal.contains("grant-binding"));
    assert!(!cargo_toml_path_depends_on_grant_binding(&literal));
    let comment = dependency_manifest(
        "# don't edit\ngb = { package = \"grant-bind\\u0069ng\", version = \"1.2.3\" }\n",
    );
    assert!(!comment.contains("grant-binding"));
    assert!(comment.contains("\\u0069"));
    assert!(cargo_toml_path_depends_on_grant_binding(&comment));
    let quoted_comment = dependency_manifest(
        "# the \"quoted note\ngb = { package = \"grant-bind\\u0069ng\", version = \"1.2.3\" }\n",
    );
    assert!(!quoted_comment.contains("grant-binding"));
    assert!(cargo_toml_path_depends_on_grant_binding(&quoted_comment));
}

#[test]
fn model_multiline_basic_string_escape_is_a_link() {
    let multiline = dependency_manifest(
        "gb = { package = \"\"\"grant-bind\\u0069ng\"\"\", version = \"1.2.3\" }\n",
    );
    assert!(!multiline.contains("grant-binding"));
    assert!(multiline.contains("\\u0069"));
    assert!(multiline.contains("\"\"\""));
    assert!(cargo_toml_path_depends_on_grant_binding(&multiline));
}

#[test]
fn model_unknown_hex_escape_is_not_a_link() {
    let hex =
        dependency_manifest("gb = { package = \"grant-bind\\x69ng\", version = \"1.2.3\" }\n");
    assert!(!hex.contains("grant-binding"));
    assert!(hex.contains("\\x69"));
    assert!(!cargo_toml_path_depends_on_grant_binding(&hex));
}

#[test]
fn model_uppercase_hex_escape_is_a_link() {
    let upper =
        dependency_manifest("gb = { package = \"grant-bindi\\u006Eg\", version = \"1.2.3\" }\n");
    assert!(!upper.contains("grant-binding"));
    assert!(upper.contains("\\u006E"));
    assert!(cargo_toml_path_depends_on_grant_binding(&upper));
}

#[test]
fn model_lowercase_hex_escape_is_a_link() {
    let lower =
        dependency_manifest("gb = { package = \"grant-bindi\\u006eg\", version = \"1.2.3\" }\n");
    assert!(!lower.contains("grant-binding"));
    assert!(lower.contains("\\u006e"));
    assert!(cargo_toml_path_depends_on_grant_binding(&lower));
}

#[test]
fn model_newline_escape_is_not_a_link() {
    let escaped =
        dependency_manifest("gb = { package = \"grant-bindi\\ng\", version = \"1.2.3\" }\n");
    assert!(!escaped.contains("grant-binding"));
    assert!(escaped.contains("\\n"));
    assert!(!cargo_toml_path_depends_on_grant_binding(&escaped));
}

#[test]
fn model_backspace_escape_is_not_a_link() {
    let escaped =
        dependency_manifest("gb = { package = \"grant-\\binding\", version = \"1.2.3\" }\n");
    assert!(!escaped.contains("grant-binding"));
    assert!(escaped.contains("\\b"));
    assert!(!cargo_toml_path_depends_on_grant_binding(&escaped));
}

#[test]
fn model_tab_escape_is_not_a_link() {
    let escaped =
        dependency_manifest("gb = { package = \"gran\\t-binding\", version = \"1.2.3\" }\n");
    assert!(!escaped.contains("grant-binding"));
    assert!(escaped.contains("\\t"));
    assert!(!cargo_toml_path_depends_on_grant_binding(&escaped));
}

#[test]
fn model_carriage_return_escape_is_not_a_link() {
    let escaped =
        dependency_manifest("gb = { package = \"g\\rant-binding\", version = \"1.2.3\" }\n");
    assert!(!escaped.contains("grant-binding"));
    assert!(escaped.contains("\\r"));
    assert!(!cargo_toml_path_depends_on_grant_binding(&escaped));
}

#[test]
fn model_line_ending_escape_is_a_link() {
    let lf = dependency_manifest(
        "gb = { package = \"\"\"grant-bindi\\\nng\"\"\", version = \"1.2.3\" }\n",
    );
    assert!(!lf.contains("grant-binding"));
    assert!(lf.contains("\\\n"));
    assert!(cargo_toml_path_depends_on_grant_binding(&lf));
    let crlf = dependency_manifest(
        "gb = { package = \"\"\"grant-bindi\\\r\nng\"\"\", version = \"1.2.3\" }\n",
    );
    assert!(!crlf.contains("grant-binding"));
    assert!(cargo_toml_path_depends_on_grant_binding(&crlf));
    let spaced = dependency_manifest(
        "gb = { package = \"\"\"grant-bindi\\\n  ng\"\"\", version = \"1.2.3\" }\n",
    );
    assert!(!spaced.contains("grant-binding"));
    assert!(cargo_toml_path_depends_on_grant_binding(&spaced));
    let literal =
        dependency_manifest("gb = { package = '''grant-bindi\\\nng''', version = '1.2.3' }\n");
    assert!(!literal.contains("grant-binding"));
    assert!(!cargo_toml_path_depends_on_grant_binding(&literal));
}

#[test]
fn model_comment_is_not_a_path_link() {
    let whole_line = package_manifest("# path = \"../grant-binding\"\n");
    assert!(whole_line.contains("grant-binding"));
    assert!(whole_line.contains("path"));
    assert!(!cargo_toml_path_depends_on_grant_binding(&whole_line));
    let trailing = "\
[package]\n\
name = \"grant-binding\"\n\
version = \"0.1.0\"\n\
edition = \"2021\"\n\
# path = \"lab/grant-binding\"\n";
    assert!(trailing.contains("grant-binding"));
    assert!(trailing.contains("path"));
    assert!(!cargo_toml_path_depends_on_grant_binding(trailing));
    let followed = package_manifest(
        "# path = \"../grant-binding\"\n[dependencies]\ngrant-binding = { path = \"missing-gb\" }\n",
    );
    assert!(cargo_toml_path_depends_on_grant_binding(&followed));
}

#[test]
fn model_literal_string_path_is_a_link() {
    let single = dependency_manifest("grant-binding = { path = '../missing-gb' }\n");
    assert!(single.contains("grant-binding"));
    assert!(single.contains("path"));
    assert!(cargo_toml_path_depends_on_grant_binding(&single));
    let multi = dependency_manifest("grant-binding = { path = '''../missing-gb''' }\n");
    assert!(multi.contains("grant-binding"));
    assert!(multi.contains("path"));
    assert!(cargo_toml_path_depends_on_grant_binding(&multi));
    let escaped =
        dependency_manifest("gb = { package = 'grant-bind\\u0069ng', version = '1.2.3' }\n");
    assert!(!escaped.contains("grant-binding"));
    assert!(!cargo_toml_path_depends_on_grant_binding(&escaped));
}

#[test]
fn model_case_different_manifest_is_not_a_link() {
    let renamed = dependency_manifest("Grant-Binding = { path = \"missing-gb\" }\n");
    assert!(renamed.contains("path"));
    assert!(!renamed.contains("grant-binding"));
    assert!(!cargo_toml_path_depends_on_grant_binding(&renamed));
    let key = dependency_manifest("grant-binding = { Path = \"lab/grant-binding\" }\n");
    assert!(key.contains("grant-binding"));
    assert!(!key.contains("path"));
    assert!(!cargo_toml_path_depends_on_grant_binding(&key));
}

#[test]
fn model_hash_inside_a_string_is_still_a_link() {
    let basic = "\
[package]\n\
name = \"fixture\"\n\
version = \"0.0.0\"\n\
edition = \"2021\"\n\
description = \"uses # syntax\"\n\
\n\
[dependencies]\n\
grant-binding = { path = \"missing-gb\" }\n";
    assert!(basic.contains("grant-binding"));
    assert!(basic.contains("path"));
    assert!(basic.contains('#'));
    assert!(cargo_toml_path_depends_on_grant_binding(basic));
    let literal = "\
[package]\n\
name = \"fixture\"\n\
version = \"0.0.0\"\n\
edition = \"2021\"\n\
description = 'uses # syntax'\n\
\n\
[dependencies]\n\
grant-binding = { path = 'missing-gb' }\n";
    assert!(literal.contains("grant-binding"));
    assert!(literal.contains("path"));
    assert!(literal.contains('#'));
    assert!(cargo_toml_path_depends_on_grant_binding(literal));
}

#[test]
fn model_git_or_registry_dependency_is_a_link() {
    for manifest in [
        dependency_manifest("grant-binding = { git = \"https://example.com/gb.git\" }\n"),
        dependency_manifest("grant-binding={git=\"https://example.com/gb.git\"}\n"),
        dependency_manifest("grant-binding = { version = \"1.2.3\" }\n"),
        dependency_manifest("grant-binding={version=\"1.2.3\"}\n"),
        dependency_manifest("grant-binding = \"1.2.3\"\n"),
        dependency_manifest("grant-binding=\"1.2.3\"\n"),
        dependency_manifest("gb = { package = \"grant-binding\", version = \"1.2.3\" }\n"),
        dependency_manifest(
            "gb = { package = \"grant-binding\", git = \"https://example.com/gb.git\" }\n",
        ),
        package_manifest(
            "[dependencies]\ngrant-binding = { default-features = false, version = \"1.2.3\" }\n",
        ),
        package_manifest(
            "[dependencies]\ngrant-binding = { default-features = false, git = \"https://example.com/gb.git\" }\n",
        ),
        package_manifest("[dependencies]\ngrant-binding = '1.2.3'\n"),
        package_manifest("[dependencies.grant-binding]\nversion = \"1.2.3\"\n"),
        package_manifest(
            "[dependencies.grant-binding]\ndefault-features = false\ngit = 'https://example.com/gb.git'\n",
        ),
        package_manifest("[dependencies]\n'grant-binding' = '1.2.3'\n"),
        package_manifest("[dependencies]\n\"grant-binding\" = \"1.2.3\"\n"),
        package_manifest("[dependencies]\n\"grant-b\\u0069nding\" = '1.2.3'\n"),
        package_manifest("[dependencies]\ngrant-binding = '''1.2.3'''\n"),
        package_manifest("[dependencies]\ngrant-binding = \"\"\"1.2.3\"\"\"\n"),
        package_manifest(
            "[dependencies]\n'grant-binding' = { 'default-features' = false, 'version' = '1.2.3' }\n",
        ),
        package_manifest(
            "[dependencies]\n\"grant-binding\" = { \"default-features\" = false, \"git\" = 'https://example.com/gb.git' }\n",
        ),
        package_manifest("['dependencies'.'grant-binding']\n'version' = '1.2.3'\n"),
        package_manifest(
            "[\"dependencies\".\"grant-binding\"]\n\"git\" = 'https://example.com/gb.git'\n",
        ),
        package_manifest("[dependencies]\ngrant-binding.version = '1.2.3'\n"),
        package_manifest("[dependencies]\n'grant-binding'.'git' = 'https://example.com/gb.git'\n"),
        root_then_package("dependencies.grant-binding.version = '1.2.3'"),
        root_then_package(
            "dependencies = { grant-binding = { default-features = false, git = 'https://example.com/gb.git' } }",
        ),
        package_manifest(
            "[dependencies]\ngb = { default-features = false, package = 'grant-binding', version = '1.2.3' }\n",
        ),
        package_manifest(
            "[dependencies]\ngb = { git = 'https://example.com/gb.git', 'package' = 'grant-binding' }\n",
        ),
        package_manifest(
            "[dependencies]\ngb = { \"version\" = '1.2.3', \"package\" = \"grant-binding\" }\n",
        ),
        package_manifest(
            "[dependencies]\ngb = { version = '1.2.3', package = '''grant-binding''' }\n",
        ),
        package_manifest(
            "[dependencies]\ngb = { git = 'https://example.com/gb.git', package = \"\"\"grant-binding\"\"\" }\n",
        ),
        package_manifest("[dependencies.gb]\nversion = '1.2.3'\npackage = 'grant-binding'\n"),
        package_manifest(
            "[dependencies.gb]\npackage = 'grant-binding'\ngit = 'https://example.com/gb.git'\n",
        ),
        package_manifest("[dependencies]\ngb.package = 'grant-binding'\ngb.version = '1.2.3'\n"),
        package_manifest("[dev-dependencies.grant-binding]\nversion = '1.2.3'\n"),
        package_manifest("[build-dependencies.grant-binding]\ngit = 'https://example.com/gb.git'\n"),
        package_manifest(
            "[target.'cfg(unix)'.dependencies.grant-binding]\nversion = '1.2.3'\n",
        ),
    ] {
        assert!(
            cargo_toml_path_depends_on_grant_binding(&manifest),
            "{manifest}"
        );
    }
    assert!(!cargo_toml_path_depends_on_grant_binding(
        "[package]\nname = \"grant-binding\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
    ));
    assert!(!cargo_toml_path_depends_on_grant_binding(
        "package = \"grant-binding\"\n"
    ));
    for manifest in [
        "[package]\nname = 'grant-binding'\nversion = '1.2.3'\n".to_string(),
        "[package]\n\"name\" = \"grant-binding\"\n\"version\" = '1.2.3'\n".to_string(),
        package_manifest("[dependencies]\ngb = { package = 'grant-binding' }\n"),
        dependency_manifest("'Grant-Binding' = '1.2.3'\n"),
        package_manifest("[dependencies.Grant-Binding]\nversion = '1.2.3'\n"),
        dependency_manifest("grant-binding = { Version = '1.2.3' }\n"),
        package_manifest("[dependencies.grant-binding]\nGit = 'https://example.com/gb.git'\n"),
        package_manifest("[dependencies]\n# grant-binding = '1.2.3'\n"),
        dependency_manifest("Grant-Binding = { git = \"https://example.com/gb.git\" }\n"),
        dependency_manifest("Grant-Binding = { version = \"1.2.3\" }\n"),
        dependency_manifest("grant-binding-other = \"1.2.3\"\n"),
        package_manifest("[workspace.dependencies.grant-binding]\nversion = '1.2.3'\n"),
    ] {
        assert!(
            !cargo_toml_path_depends_on_grant_binding(&manifest),
            "{manifest}"
        );
    }
}

#[test]
fn model_table_or_dotted_dependency_is_a_link() {
    let branch_first = dependency_manifest(
        "grant-binding = { branch = \"main\", git = \"https://example.com/gb.git\" }\n",
    );
    assert!(cargo_toml_path_depends_on_grant_binding(&branch_first));
    let registry_first =
        dependency_manifest("grant-binding = { registry = \"crates-io\", version = \"1.2.3\" }\n");
    assert!(cargo_toml_path_depends_on_grant_binding(&registry_first));
    let registry_only = dependency_manifest("grant-binding = { registry = \"crates-io\" }\n");
    assert!(!cargo_toml_path_depends_on_grant_binding(&registry_only));
    let registry_table =
        package_manifest("[dependencies.grant-binding]\nregistry = \"crates-io\"\n");
    assert!(!cargo_toml_path_depends_on_grant_binding(&registry_table));
    let dotted_registry = dependency_manifest("grant-binding.registry = \"crates-io\"\n");
    assert!(!cargo_toml_path_depends_on_grant_binding(&dotted_registry));
    let workspace = dependency_manifest("grant-binding = { workspace = true }\n");
    assert!(!cargo_toml_path_depends_on_grant_binding(&workspace));
    let table = package_manifest("[dependencies.grant-binding]\nversion = \"1.2.3\"\n");
    assert!(cargo_toml_path_depends_on_grant_binding(&table));
    let dev_table = package_manifest(
        "[dev-dependencies.grant-binding]\ngit = \"https://example.com/gb.git\"\n",
    );
    assert!(cargo_toml_path_depends_on_grant_binding(&dev_table));
    let patch_table =
        package_manifest("[patch.crates-io.grant-binding]\ngit = \"https://example.com/gb.git\"\n");
    assert!(!cargo_toml_path_depends_on_grant_binding(&patch_table));
    let dotted_version = dependency_manifest("grant-binding.version = \"1.2.3\"\n");
    assert!(cargo_toml_path_depends_on_grant_binding(&dotted_version));
    let dotted_git = dependency_manifest("grant-binding.git = \"https://example.com/gb.git\"\n");
    assert!(cargo_toml_path_depends_on_grant_binding(&dotted_git));
    let dotted_workspace = dependency_manifest("grant-binding.workspace = true\n");
    assert!(!cargo_toml_path_depends_on_grant_binding(&dotted_workspace));
    assert!(!cargo_toml_path_depends_on_grant_binding(
        "[package]\nname = \"grant-binding\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
    ));
    assert!(!cargo_toml_path_depends_on_grant_binding(
        "package = \"grant-binding\"\n"
    ));
    assert!(!cargo_toml_path_depends_on_grant_binding(
        &dependency_manifest("serde = { workspace = true }\n")
    ));
    assert!(!cargo_toml_path_depends_on_grant_binding(
        &dependency_manifest("other = { git = \"https://example.com/grant-binding.git\" }\n")
    ));
    assert!(!cargo_toml_path_depends_on_grant_binding(
        &package_manifest("[dependencies.grant-binding]\n")
    ));
    assert!(!cargo_toml_path_depends_on_grant_binding(
        &root_then_package("Grant-Binding.version = \"1.2.3\"")
    ));
    assert!(!cargo_toml_path_depends_on_grant_binding(
        &package_manifest("[dependencies.Grant-Binding]\nversion = \"1.2.3\"\n")
    ));
}

#[test]
fn model_workspace_member_is_a_link() {
    assert!(!cargo_toml_path_depends_on_grant_binding(
        "[workspace]\nmembers = [\"lab/grant-binding\"]\n"
    ));
}

#[test]
fn model_metadata_dependencies_are_not_a_link() {
    assert!(!cargo_toml_path_depends_on_grant_binding(
        &package_manifest("[package.metadata]\ndependencies = [{ name = \"grant-binding\" }]\n",)
    ));
    assert!(!cargo_toml_path_depends_on_grant_binding(
        &package_manifest(
            "[package.metadata.nested]\ndependencies = [{ name = \"grant-binding\" }]\n",
        )
    ));
    assert!(!cargo_toml_path_depends_on_grant_binding(&format!(
        "[workspace.metadata]\ndependencies = [{{ name = \"grant-binding\" }}]\npackages = [{{ dependencies = [{{ name = \"grant-binding\" }}] }}]\n\n{}",
        package_manifest("")
    )));
    assert!(cargo_toml_path_depends_on_grant_binding(
        &package_manifest(
            "[package.metadata]\ndependencies = [{ name = \"other\" }]\n\n[dependencies]\ngrant-binding = { path = \"missing-gb\" }\n",
        )
    ));
    let ahead = r#"{"metadata":{"dependencies":[{"name":"grant-binding"}],"packages":[{"dependencies":[{"name":"grant-binding"}]}]},"packages":[{"metadata":{"dependencies":[{"name":"grant-binding"}]},"name":"grant-binding","dependencies":[{"name":"kept"}]}]}"#;
    assert_eq!(names_in_dependency_arrays(ahead), vec!["kept".to_string()]);
    let absent = r#"{"packages":[{"name":"grant-binding","metadata":{"dependencies":[{"name":"grant-binding"}],"packages":[{"dependencies":[{"name":"grant-binding"}]}]},"dependencies":[]}],"metadata":{"dependencies":[{"name":"grant-binding"}]}}"#;
    assert!(names_in_dependency_arrays(absent).is_empty());
}

#[test]
fn model_metadata_panics_preserve_cleanup_failures() {
    with_manifest_dir(&std::env::temp_dir(), |parent| {
        let panic = std::panic::catch_unwind(|| {
            with_manifest_dir(parent, |_| -> Result<(), MetadataRefuse> {
                panic!("fixture operation failed")
            })
        })
        .unwrap_err();
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"fixture operation failed")
        );
        assert_eq!(fs::read_dir(parent).unwrap().count(), 0);

        for (kind, reason) in [
            (0, "metadata operation panicked: fixture operation failed; cannot remove temporary manifest directory"),
            (1, "metadata operation panicked: owned panic reason; cannot remove temporary manifest directory"),
            (2, "metadata operation panicked: non-string panic; cannot remove temporary manifest directory"),
        ] {
            let error = with_manifest_dir(parent, |dir| -> Result<(), MetadataRefuse> {
                fs::remove_dir(dir).unwrap();
                fs::write(dir, "block directory cleanup").unwrap();
                match kind {
                    0 => panic!("fixture operation failed"),
                    1 => std::panic::panic_any(String::from("owned panic reason")),
                    _ => std::panic::panic_any(17u8),
                }
            })
            .unwrap_err();
            assert_eq!(error.to_string(), reason);
        }
        Ok(())
    })
    .unwrap();
}

#[test]
fn model_workspace_relative_manifest_is_a_link() {
    // Keep a relative manifest beneath the test working directory without
    // changing the process directory used by other tests.
    fs::create_dir_all("target").unwrap();
    with_manifest_dir(Path::new("target"), |dir| {
        let root = dir.join("ws");
        fs::create_dir(&root).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = ['gb', 'other']\nresolver = '2'\n",
        )
        .unwrap();
        for (member, name) in [("gb", "grant-binding"), ("other", "other")] {
            let package = root.join(member);
            fs::create_dir(&package).unwrap();
            stage_manifest(
                &package,
                &format!("[package]\nname = '{name}'\nversion = '0.0.0'\nedition = '2021'\n"),
            )?;
        }
        let manifest = root.join("Cargo.toml");
        assert!(manifest.is_relative());
        assert!(manifest_depends_on_grant_binding(
            &manifest.canonicalize().unwrap()
        ));
        assert!(manifest_depends_on_grant_binding(&manifest));
        assert!(!manifest_depends_on_grant_binding(
            &root.join("gb/Cargo.toml")
        ));
        assert!(!manifest_depends_on_grant_binding(
            &root.join("other/Cargo.toml")
        ));
        Ok(())
    })
    .unwrap();
}

#[cfg(test)]
fn stage_registry_workspace(dir: &Path) -> PathBuf {
    fs::write(
        dir.join("Cargo.toml"),
        "[workspace]\nmembers = ['app', 'other']\nresolver = '2'\n",
    )
    .unwrap();
    for (name, dependencies) in [
        ("app", "[dependencies]\ngrant-binding = '1.2.3'\n"),
        ("other", ""),
    ] {
        let package = dir.join(name);
        fs::create_dir(&package).unwrap();
        stage_manifest(
            &package,
            &format!(
                "[package]\nname = '{name}'\nversion = '0.0.0'\nedition = '2021'\n\n{dependencies}"
            ),
        )
        .unwrap();
    }
    dir.join("Cargo.toml")
}

#[test]
fn model_virtual_workspace_keeps_member_dependency_names() {
    with_manifest_dir(&std::env::temp_dir(), |dir| {
        let manifest = stage_registry_workspace(dir);
        assert!(manifest_depends_on_grant_binding(&manifest));
        assert!(manifest_depends_on_grant_binding(
            &dir.join("app/Cargo.toml")
        ));
        assert!(!manifest_depends_on_grant_binding(
            &dir.join("other/Cargo.toml")
        ));
        Ok(())
    })
    .unwrap();
}

#[test]
fn model_metadata_path_failures_have_exact_reasons() {
    with_manifest_dir(&std::env::temp_dir(), |dir| {
        let dir = &dir.canonicalize().unwrap();
        let manifest = stage_registry_workspace(dir);
        // Capture real metadata while all referenced files exist. The same
        // parsed snapshot must fail explicitly when one of its paths is lost.
        let output = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .current_dir(dir)
            .args([
                "metadata",
                "--offline",
                "--no-deps",
                "--format-version",
                "1",
                "--manifest-path",
            ])
            .arg(&manifest)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut seen = read_metadata(&String::from_utf8(output.stdout).unwrap());
        let mut names = names_for_manifest(&seen, &manifest).unwrap();
        names.sort();
        assert_eq!(names, ["app", "grant-binding", "other"]);

        let workspace_root = seen.workspace_root.take();
        assert_eq!(
            names_for_manifest(&seen, &manifest)
                .unwrap_err()
                .to_string(),
            "cargo metadata has no workspace root"
        );
        seen.workspace_root = Some(dir.join("missing-root").to_str().unwrap().to_owned());
        assert_eq!(
            names_for_manifest(&seen, &manifest)
                .unwrap_err()
                .to_string(),
            "cannot resolve metadata workspace root"
        );
        seen.workspace_root = workspace_root;

        let text = fs::read_to_string(&manifest).unwrap();
        fs::remove_file(&manifest).unwrap();
        assert_eq!(
            names_for_manifest(&seen, &manifest)
                .unwrap_err()
                .to_string(),
            "cannot resolve input manifest path"
        );
        fs::write(&manifest, text).unwrap();

        let filesystem_root = manifest.ancestors().last().unwrap();
        assert_eq!(
            names_for_manifest(&seen, filesystem_root)
                .unwrap_err()
                .to_string(),
            "input manifest path has no parent directory"
        );
        for package in &seen.packages {
            let text = fs::read_to_string(&package.manifest_path).unwrap();
            fs::remove_file(&package.manifest_path).unwrap();
            for input in [&manifest, &dir.join("app/Cargo.toml")] {
                // A removed input has its own reason; this checks a removed
                // referenced package for both root and member queries.
                if input != Path::new(&package.manifest_path) {
                    assert_eq!(
                        names_for_manifest(&seen, input).unwrap_err().to_string(),
                        "cannot resolve metadata package manifest path"
                    );
                }
            }
            fs::write(&package.manifest_path, text).unwrap();
        }
        assert_eq!(names_for_manifest(&seen, &manifest).unwrap().len(), 3);
        Ok(())
    })
    .unwrap();
}

#[test]
#[cfg(unix)]
fn model_metadata_path_failures_stop_both_entry_points() {
    use std::os::unix::fs::PermissionsExt;

    if std::env::var_os("GRANT_BINDING_METADATA_TEST_CHILD").is_some() {
        let cargo = PathBuf::from(std::env::var_os("CARGO").unwrap());
        fs::write(&cargo, "#!/bin/sh\ncat \"$CARGO.json\"\n").unwrap();
        fs::set_permissions(&cargo, fs::Permissions::from_mode(0o700)).unwrap();
        with_manifest_dir(&std::env::temp_dir(), |dir| {
            stage_manifest(dir, &package_manifest(""))?;
            let manifest = dir.join("Cargo.toml");
            let root = dir.canonicalize().unwrap();
            for (json, reason) in [
                (
                    "{\"packages\":[]}".to_owned(),
                    "dependency check failed: cargo metadata has no workspace root",
                ),
                (
                    format!("{{\"workspace_root\":{:?},\"packages\":[]}}", root.join("missing")),
                    "dependency check failed: cannot resolve metadata workspace root",
                ),
                (
                    format!(
                        "{{\"workspace_root\":{root:?},\"workspace_members\":[\"missing\"],\"packages\":[{{\"id\":\"missing\",\"name\":\"grant-binding\",\"manifest_path\":{:?},\"dependencies\":[]}}]}}",
                        root.join("missing/Cargo.toml")
                    ),
                    "dependency check failed: cannot resolve metadata package manifest path",
                ),
            ] {
                fs::write(cargo.with_extension("json"), json).unwrap();
                for direct in [true, false] {
                    let panic = std::panic::catch_unwind(|| {
                        if direct {
                            manifest_depends_on_grant_binding(&manifest)
                        } else {
                            cargo_toml_path_depends_on_grant_binding(&package_manifest(""))
                        }
                    })
                    .unwrap_err();
                    assert_eq!(panic.downcast_ref::<String>().unwrap(), reason);
                }
            }
            Ok(())
        })
        .unwrap();
        return;
    }
    with_manifest_dir(&std::env::temp_dir(), |dir| {
        let output = metadata_test_child(dir, Some(&dir.join("cargo-fixture")));
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_dir(dir).unwrap().count(),
            2,
            "only fixtures remain"
        );
        Ok(())
    })
    .unwrap();
}

#[test]
fn model_metadata_input_path_failures_stop_the_detector() {
    with_manifest_dir(&std::env::temp_dir(), |dir| {
        for (manifest, reason) in [
            (
                dir.join("missing/Cargo.toml"),
                "dependency check failed: cannot resolve input manifest path",
            ),
            (
                dir.ancestors().last().unwrap().to_owned(),
                "dependency check failed: input manifest path has no parent directory",
            ),
        ] {
            let panic = std::panic::catch_unwind(|| manifest_depends_on_grant_binding(&manifest))
                .unwrap_err();
            assert_eq!(panic.downcast_ref::<String>().unwrap(), reason);
        }
        Ok(())
    })
    .unwrap();
}

#[test]
fn model_workspace_metadata_names_the_member() {
    let root = std::env::temp_dir().join(format!("gb-ws-a-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("gb/src")).unwrap();
    std::fs::create_dir_all(root.join("other/src")).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"gb\", \"other\"]\nresolver = \"2\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("gb/Cargo.toml"),
        "[package]\nname = \"grant-binding\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(root.join("gb/src/lib.rs"), "").unwrap();
    std::fs::write(
        root.join("other/Cargo.toml"),
        "[package]\nname = \"other\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(root.join("other/src/lib.rs"), "").unwrap();
    assert!(
        manifest_depends_on_grant_binding(&root.join("Cargo.toml")),
        "workspace root"
    );
    assert!(
        !manifest_depends_on_grant_binding(&root.join("gb/Cargo.toml")),
        "own manifest"
    );
    assert!(
        !manifest_depends_on_grant_binding(&root.join("other/Cargo.toml")),
        "sibling"
    );
    std::fs::remove_dir_all(&root).unwrap();

    let root_b = std::env::temp_dir().join(format!("gb-ws-b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root_b);
    std::fs::create_dir_all(root_b.join("app/src")).unwrap();
    std::fs::create_dir_all(root_b.join("vendor/grant-binding/src")).unwrap();
    std::fs::write(
        root_b.join("Cargo.toml"),
        "[workspace]\nmembers = [\"app\"]\nresolver = \"2\"\n\n[workspace.dependencies]\ngrant-binding = { path = \"vendor/grant-binding\" }\n",
    )
    .unwrap();
    std::fs::write(
        root_b.join("app/Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[dependencies]\ngrant-binding = { workspace = true }\n",
    )
    .unwrap();
    std::fs::write(root_b.join("app/src/lib.rs"), "").unwrap();
    std::fs::write(
        root_b.join("vendor/grant-binding/Cargo.toml"),
        "[package]\nname = \"grant-binding\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(root_b.join("vendor/grant-binding/src/lib.rs"), "").unwrap();
    assert!(
        manifest_depends_on_grant_binding(&root_b.join("app/Cargo.toml")),
        "workspace dependency"
    );
    assert!(
        !manifest_depends_on_grant_binding(&root_b.join("vendor/grant-binding/Cargo.toml")),
        "vendor own manifest"
    );
    std::fs::remove_dir_all(&root_b).unwrap();

    let root_c = std::env::temp_dir().join(format!("gb-ws-c-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root_c);
    std::fs::create_dir_all(root_c.join("gb/src")).unwrap();
    std::fs::write(
        root_c.join("Cargo.toml"),
        "[workspace]\nmembers = [\"gb\"]\nresolver = \"2\"\n",
    )
    .unwrap();
    std::fs::write(
        root_c.join("gb/Cargo.toml"),
        "[package]\nname = \"grant-binding-other\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(root_c.join("gb/src/lib.rs"), "").unwrap();
    assert!(
        !manifest_depends_on_grant_binding(&root_c.join("Cargo.toml")),
        "longer name"
    );
    std::fs::remove_dir_all(&root_c).unwrap();
}
