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
#[rustfmt::skip]
pub fn cargo_toml_path_depends_on_grant_binding(cargo_toml: &str) -> bool {
    dependency_names(cargo_toml).iter().any(|name| name == "grant-binding")
}

/// Dependency names from one `cargo metadata` parse.
///
/// A manifest cargo cannot parse yields an empty list. The package's own
/// name is not included.
fn dependency_names(cargo_toml: &str) -> Vec<String> {
    with_manifest_dir(&std::env::temp_dir(), |dir| {
        metadata_dependency_names(dir, cargo_toml)
    })
    .unwrap_or_else(|error| panic!("dependency check failed: {error}"))
}

#[derive(Debug)]
enum MetadataRefuse {
    CreateDirectory,
    CreateSourceDirectory,
    WriteManifest,
    WriteSource,
    LaunchCargo,
    DecodeOutput,
    RemoveDirectory,
    CleanupAfter(Box<MetadataRefuse>),
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
            Self::RemoveDirectory => "cannot remove temporary manifest directory",
            Self::CleanupAfter(error) => {
                return write!(f, "{error}; {}", Self::RemoveDirectory);
            }
        })
    }
}

/// This is the shared ownership boundary for all metadata files and cleanup.
fn with_manifest_dir<T>(
    parent: &Path,
    operation: impl FnOnce(&Path) -> Result<T, MetadataRefuse>,
) -> Result<T, MetadataRefuse> {
    let dir = fresh_manifest_dir(parent)?;
    let result = operation(&dir);
    match fs::remove_dir_all(&dir) {
        Ok(()) => result,
        Err(_) => Err(match result {
            Ok(_) => MetadataRefuse::RemoveDirectory,
            Err(error) => MetadataRefuse::CleanupAfter(Box::new(error)),
        }),
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

fn metadata_dependency_names(dir: &Path, cargo_toml: &str) -> Result<Vec<String>, MetadataRefuse> {
    fs::create_dir(dir.join("src")).map_err(|_| MetadataRefuse::CreateSourceDirectory)?;
    write_metadata_inputs(dir, cargo_toml)?;
    let program = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let manifest = dir.join("Cargo.toml");
    let output = Command::new(program)
        .current_dir(dir)
        .env("CARGO_TARGET_DIR", dir.join("target"))
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
        .map_err(|_| MetadataRefuse::LaunchCargo)?;
    if !output.status.success() {
        return Ok(Vec::new());
    }
    let json = String::from_utf8(output.stdout).map_err(|_| MetadataRefuse::DecodeOutput)?;
    Ok(names_in_dependency_arrays(&json))
}

/// `name` strings of objects inside a `dependencies` array.
fn names_in_dependency_arrays(json: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut scan = JsonScan {
        bytes: json.as_bytes(),
        index: 0,
    };
    scan.walk_value(&mut names);
    names
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

    fn walk_value(&mut self, names: &mut Vec<String>) {
        self.skip_ws();
        match self.bytes.get(self.index).copied() {
            Some(b'{') => self.walk_object(names, false),
            Some(b'[') => self.walk_array(names, false),
            Some(b'"') => {
                let _ = self.parse_string();
            }
            Some(b't' | b'f' | b'n') => self.skip_letters(),
            Some(b'-' | b'0'..=b'9') => self.skip_number(),
            Some(_) => self.index += 1,
            None => {}
        }
    }

    fn walk_object(&mut self, names: &mut Vec<String>, in_dependency: bool) {
        self.index += 1;
        loop {
            self.skip_ws();
            match self.bytes.get(self.index).copied() {
                None => return,
                Some(b'}') => {
                    self.index += 1;
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
                        names.push(self.parse_string());
                    } else if key == "dependencies" && self.bytes.get(self.index) == Some(&b'[') {
                        self.walk_array(names, true);
                    } else {
                        self.walk_value(names);
                    }
                }
            }
        }
    }

    fn walk_array(&mut self, names: &mut Vec<String>, dependency_elements: bool) {
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
                Some(b'{') if dependency_elements => self.walk_object(names, true),
                Some(_) => self.walk_value(names),
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
        assert!(!cargo_toml_path_depends_on_grant_binding(
            &dependency_manifest("grant-binding = { path = 'missing-gb' }\n")
        ));
        return;
    }
    with_manifest_dir(&std::env::temp_dir(), |dir| {
        let cargo = dir.join("cargo-fixture");
        for status in [0, 1] {
            fs::write(
                &cargo,
                format!("#!/bin/sh\nprintf '\\377'\nexit {status}\n"),
            )
            .unwrap();
            fs::set_permissions(&cargo, fs::Permissions::from_mode(0o700)).unwrap();
            let output = metadata_test_child(dir, Some(&cargo));
            if status == 0 {
                assert_metadata_child_failure(output, "cargo metadata output is not UTF-8");
            } else {
                assert!(
                    output.status.success(),
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            assert_eq!(
                fs::read_dir(dir).unwrap().count(),
                1,
                "only the fixture remains"
            );
        }
        Ok(())
    })
    .unwrap();
}

#[test]
fn model_metadata_cleanup_failure_keeps_both_reasons() {
    with_manifest_dir(&std::env::temp_dir(), |parent| {
        for failed in [false, true] {
            let error = with_manifest_dir(parent, |dir| {
                fs::remove_dir(dir).unwrap();
                fs::write(dir, "block directory cleanup").unwrap();
                if failed {
                    Err(MetadataRefuse::LaunchCargo)
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
            assert_eq!(
                error.to_string(),
                if failed {
                    "cannot launch cargo metadata; cannot remove temporary manifest directory"
                } else {
                    "cannot remove temporary manifest directory"
                }
            );
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
