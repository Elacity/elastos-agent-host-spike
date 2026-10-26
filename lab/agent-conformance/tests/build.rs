use agent_conformance::build::copy_agent_host;
use agent_conformance::harness::ThrowawayHome;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

fn contents(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, path: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(root, &path, files);
            } else {
                files.insert(
                    path.strip_prefix(root).unwrap().into(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    visit(root, root, &mut files);
    files
}

#[test]
fn agent_host_copy_takes_only_listed_files() {
    let home = ThrowawayHome::new().unwrap();
    let source = home.root().join("source");
    fs::create_dir_all(source.join("src/nested")).unwrap();
    let listed = [
        "Cargo.toml",
        "Cargo.lock",
        "capsule.json",
        "src/lib.rs",
        "src/nested/module.rs",
    ];
    for name in listed
        .into_iter()
        .chain(["README.md", "agent-host.component.wasm", "asks.json"])
    {
        fs::write(source.join(name), name).unwrap();
    }
    let before = contents(&source);
    let destination = home.root().join("copy");
    copy_agent_host(&source, &destination).unwrap();
    let expected = listed
        .into_iter()
        .map(|name| (PathBuf::from(name), name.as_bytes().to_vec()))
        .collect();
    assert_eq!(
        contents(&destination),
        expected,
        "only listed inputs may be copied"
    );
    assert_eq!(
        contents(&source),
        before,
        "copy leaves the source unchanged"
    );
    fs::write(
        destination.join("Cargo.toml"),
        b"preserve existing destination",
    )
    .unwrap();
    let existing = contents(&destination);
    let refusal = copy_agent_host(&source, &destination).unwrap_err();
    assert!(
        refusal.contains(destination.to_str().unwrap()),
        "destination refusal names its path"
    );
    assert_eq!(contents(&destination), existing);
    for name in ["Cargo.toml", "src/nested/module.rs"] {
        let path = source.join(name);
        fs::remove_file(&path).unwrap();
        symlink(source.join("README.md"), &path).unwrap();
        let refused = home.root().join("refused");
        let reason = copy_agent_host(&source, &refused).unwrap_err();
        assert!(reason.contains(path.to_str().unwrap()) && reason.contains("symlink"));
        assert!(
            !refused.exists(),
            "symlink refused before destination creation"
        );
        fs::remove_file(&path).unwrap();
        fs::write(path, name).unwrap();
    }
    let alias = home.root().join("source-alias");
    symlink(&source, &alias).unwrap();
    assert!(copy_agent_host(&alias, &home.root().join("alias-copy"))
        .unwrap_err()
        .contains(alias.to_str().unwrap()));
    let outside = home.root().join("../escape");
    assert!(copy_agent_host(&source, &outside).is_err());
    assert_eq!(contents(&source), before);
    home.finish().unwrap();
}
