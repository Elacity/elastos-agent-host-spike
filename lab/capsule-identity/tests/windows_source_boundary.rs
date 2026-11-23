//! Keep the Windows walk's handle boundary under the same path-access guard as
//! the Unix walk. These scans read the Windows sources even on a Unix runner.

fn source_without_comments(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn windows_walk_opens_only_the_volume_by_path() {
    let walk = source_without_comments(include_str!(
        "../../../elastos/crates/elastos-bundle-identity/src/windows_walk.rs"
    ));
    let handles = source_without_comments(include_str!(
        "../../../elastos/crates/elastos-bundle-identity-windows-handle/src/lib.rs"
    ));
    let scanned = format!("{walk}\n{handles}");

    assert_eq!(walk.matches("OpenOptions::new(").count(), 1);
    let root_start = walk.find("fn local_root(").expect("volume root opener");
    let root_end = walk[root_start..]
        .find("\nfn list_folder(")
        .expect("end of root opener")
        + root_start;
    assert_eq!(
        walk[root_start..root_end]
            .matches("OpenOptions::new(")
            .count(),
        1,
        "the volume root is the only path-based open"
    );
    assert_eq!(handles.matches("NtCreateFile(").count(), 1);
    assert_eq!(handles.matches("GetFileInformationByHandleEx(").count(), 1);
    assert!(!walk.contains("NtCreateFile("));
    assert!(!walk.contains("GetFileInformationByHandleEx("));
    assert_eq!(walk.matches(".metadata(").count(), 3);
    assert_eq!(walk.matches("handle.metadata(").count(), 2);
    assert_eq!(walk.matches("handle\n        .metadata(").count(), 1);

    for forbidden in [
        "fs::read(",
        "fs::read_dir(",
        "read_dir(",
        "fs::metadata(",
        "Path::metadata(",
        "symlink_metadata(",
        "File::open(",
        "canonicalize(",
    ] {
        assert!(
            !scanned.contains(forbidden),
            "Windows walk reaches a file by path: {forbidden}"
        );
    }
}
