use agent_conformance::build::{copy_agent_host, offline_build, repository};
use agent_conformance::harness::ThrowawayHome;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::time::Duration;

const BUILD_TEST: &str = "offline_build_overrides_inherited_output_settings";
const BUILD_SETTINGS: [&str; 5] = [
    "CARGO_NET_OFFLINE",
    "CARGO_TARGET_DIR",
    "CARGO_BUILD_BUILD_DIR",
    "TMPDIR",
    "CARGO_INCREMENTAL",
];

fn offline_build_worker(target: &Path) {
    let home = PathBuf::from(std::env::var_os("HOME").expect("worker fixture Home"));
    assert!(target == home.join("build target"), "owned worker target");
    let decoys = ["parent-target", "parent-build", "parent-tmp"].map(|name| home.join(name));
    let before = decoys.each_ref().map(|path| contents(path));
    assert!(!target.exists(), "selected target starts absent");
    let mut command = offline_build("/bin/sh", target).expect("prepare build witness");
    assert!(target.join("tmp").is_dir(), "helper creates selected tmp");
    // Check every actual write destination before any shell write, including
    // inherited decoys on planted runs. All six locations belong to this Home.
    let output = command
        .args([
            "-c",
            r#"for directory in "$CARGO_TARGET_DIR" "$CARGO_BUILD_BUILD_DIR" "$TMPDIR"; do
    case "$directory" in
        "$1/build target"|"$1/build target/build"|"$1/build target/tmp"|"$1/parent-target"|"$1/parent-build"|"$1/parent-tmp") ;;
        *) exit 92 ;;
    esac
done
printf '%s\n' "$CARGO_NET_OFFLINE" "$CARGO_TARGET_DIR" "$CARGO_BUILD_BUILD_DIR" "$TMPDIR" "$CARGO_INCREMENTAL" "$PWD"
/bin/mkdir -p "$CARGO_BUILD_BUILD_DIR" || exit 93
printf 'owned build output' > "$CARGO_TARGET_DIR/output.marker" || exit 94
printf 'owned build output' > "$CARGO_BUILD_BUILD_DIR/output.marker" || exit 95
printf 'owned build output' > "$TMPDIR/output.marker" || exit 96
"#,
            "build-witness",
            home.to_str().unwrap(),
        ])
        .output()
        .expect("run build witness");
    assert!(output.status.success(), "build witness exits successfully");
    assert!(output.stderr.is_empty(), "build witness has empty stderr");
    let text = std::str::from_utf8(&output.stdout).expect("build witness UTF-8");
    let mut observed = text.lines();
    let build = target.join("build");
    let tmp = target.join("tmp");
    for (name, expected) in BUILD_SETTINGS.into_iter().zip([
        "true",
        target.to_str().unwrap(),
        build.to_str().unwrap(),
        tmp.to_str().unwrap(),
        "0",
    ]) {
        assert!(
            observed.next() == Some(expected),
            "{name} observed-value assertion"
        );
    }
    assert!(
        observed.next() == repository().to_str(),
        "repository working-directory assertion"
    );
    assert!(observed.next().is_none(), "only six witness observations");
    for directory in [target, build.as_path(), tmp.as_path()] {
        assert!(
            fs::read(directory.join("output.marker")).unwrap() == b"owned build output",
            "selected output marker bytes"
        );
    }
    for (decoy, initial) in decoys.iter().zip(before) {
        assert!(
            contents(decoy) == initial,
            "decoy initial contents retained"
        );
    }
}

#[test]
fn offline_build_overrides_inherited_output_settings() {
    if std::env::var_os("AC_BUILD_OUTPUT_WORKER").as_deref() == Some("154".as_ref()) {
        let target = std::env::var_os("AC_BUILD_OUTPUT_TARGET").expect("worker target supplied");
        offline_build_worker(Path::new(&target));
        return;
    }
    let parent_settings = BUILD_SETTINGS.map(std::env::var_os);
    let parent_directory = std::env::current_dir().unwrap();
    let home = ThrowawayHome::new().unwrap();
    let root = home.root().to_path_buf();
    for name in ["parent-target", "parent-build", "parent-tmp"] {
        let decoy = home.home().join(name);
        fs::create_dir(&decoy).unwrap();
        fs::write(decoy.join("initial"), b"parent output stays").unwrap();
    }
    let target = home.home().join("build target");
    let executable = std::env::current_exe().expect("current integration test executable");
    let args = [
        "AC_BUILD_OUTPUT_WORKER=154".to_owned(),
        format!("AC_BUILD_OUTPUT_TARGET={}", target.display()),
        "CARGO_NET_OFFLINE=false".to_owned(),
        "CARGO_INCREMENTAL=1".to_owned(),
        format!(
            "CARGO_TARGET_DIR={}",
            home.home().join("parent-target").display()
        ),
        format!(
            "CARGO_BUILD_BUILD_DIR={}",
            home.home().join("parent-build").display()
        ),
        format!("TMPDIR={}", home.home().join("parent-tmp").display()),
        executable.to_str().unwrap().to_owned(),
        BUILD_TEST.to_owned(),
        "--exact".to_owned(),
        "--test-threads=1".to_owned(),
    ];
    let args: Vec<_> = args.iter().map(String::as_str).collect();
    let output = home
        .launch(Path::new("/usr/bin/env"), &args, Duration::from_secs(5))
        .expect("bounded build worker completes");
    assert!(
        BUILD_SETTINGS.map(std::env::var_os) == parent_settings,
        "parent build settings preserved"
    );
    assert!(
        std::env::current_dir().unwrap() == parent_directory,
        "parent directory preserved"
    );
    let text = std::str::from_utf8(&output.stdout).expect("worker result UTF-8");
    // Forward only a fixed setting label; captured values stay in memory.
    for name in BUILD_SETTINGS {
        let label = format!("{name} observed-value assertion");
        assert!(!text.contains(&label), "{label}");
    }
    assert!(output.status.success(), "build worker test passes");
    assert!(output.stderr.is_empty(), "build worker has empty stderr");
    for expected in [
        "running 1 test".to_owned(),
        format!("test {BUILD_TEST} ... ok"),
    ] {
        assert!(
            text.lines().filter(|line| *line == expected).count() == 1,
            "one named worker test ran"
        );
    }
    assert!(
        text.lines()
            .filter(|line| line
                .starts_with("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;"))
            .count()
            == 1,
        "one worker test passed"
    );
    home.finish().unwrap();
    assert!(!root.exists(), "passed build fixture removed");
}

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
