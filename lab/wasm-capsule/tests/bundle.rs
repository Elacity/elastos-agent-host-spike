//! `tools/bundle` writes a new lab bundle and prints its lab CID, or prints the
//! lab CID of an existing bundle (PRINCIPLES P10, P11, P13). Its rules are
//! library functions in `wasm_capsule_tools::bundle`, tested here in-process.
//! The build mode's seam is the build script's path: these tests pass small
//! stand-in scripts from `tests/bundle_builds/`. Exactly one test,
//! `tools_bundle_builds_a_new_bundle_and_prints_its_lab_cid`, spawns the real
//! `tools/bundle`.
//!
//! The tests share one process, so none changes process-wide state.

mod common;

use common::build::{lane_dir, sha256_file, Receipt, TempDir};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use wasm_capsule_tools::bundle::{
    parse_args, run, write_all_to, write_new_file, ArgRefusal, Mode, USAGE,
};
use wasm_capsule_tools::{bundle_identity, CAPSULE_MANIFEST};

/// The smallest core Wasm module: the magic and version 1, no sections.
const MODULE: &[u8] = b"\0asm\x01\0\0\0";

/// The lab CID of this capsule's manifest beside [`MODULE`]: 010's pinned
/// vector (`this_capsule_bundle_has_the_pinned_lab_cid`).
const MODULE_BUNDLE_LAB_CID: &str =
    "lab-cid:sha256:dd6673dafaf1a3180310d3207cccc59b3e414b584b2d93002bb81c8d293a3c47";

/// wc-001's pinned `capsule.wasm` (README, "Claim scope").
const PINNED_ARTIFACT_SHA256: &str =
    "6dd9af1a8d33d14f48514611663e3f5b262f91ef2729de4ec851441af9b22b13";

/// The lab CID `tools/bundle` prints on this Mac: this capsule's manifest
/// beside the pinned `capsule.wasm` (README, "tools/bundle").
const REFERENCE_LAB_CID: &str =
    "lab-cid:sha256:9ca715378b264e54614d2a231ee4d8e58e6a145873c55291fd02066aaf57f930";

/// The reasons the run refusals give, after `<path>: `.
const OUT_DIR_EXISTS: &str = "OUT_DIR already exists: tools/bundle makes a new OUT_DIR and never writes into or through what is already there";
const BUNDLE_DIR_EXISTS: &str = "bundle/ already exists: it appeared during the build, and tools/bundle never writes into or through it";
const NO_SUCH_FILE: &str = "No such file or directory (os error 2)";

/// A stand-in `tools/build` from `tests/bundle_builds/`.
fn stand_in(name: &str) -> PathBuf {
    lane_dir().join("tests").join("bundle_builds").join(name)
}

fn os(arg: &str) -> OsString {
    OsString::from(arg)
}

/// Every entry under `dir`, sorted by path, with a regular file's bytes, a
/// link's target, or nothing for a folder. Two equal snapshots mean nothing
/// under `dir` changed.
fn snapshot(dir: &Path) -> Vec<(PathBuf, String, Vec<u8>)> {
    let mut entries = Vec::new();
    let mut folders = vec![dir.to_path_buf()];
    while let Some(folder) = folders.pop() {
        for entry in fs::read_dir(&folder).expect("list a folder") {
            let path = entry.expect("read a folder entry").path();
            let kind = fs::symlink_metadata(&path)
                .expect("stat an entry")
                .file_type();
            let (label, bytes) = if kind.is_symlink() {
                let target = fs::read_link(&path).expect("read a link");
                ("link", target.as_os_str().as_bytes().to_vec())
            } else if kind.is_dir() {
                folders.push(path.clone());
                ("folder", Vec::new())
            } else {
                ("file", fs::read(&path).expect("read a file"))
            };
            entries.push((path, label.to_owned(), bytes));
        }
    }
    entries.sort();
    entries
}

/// A folder `sentinel` holding one file, beside where OUT_DIR will be.
fn sentinel_dir(tmp: &TempDir) -> PathBuf {
    let sentinel = tmp.path().join("sentinel");
    fs::create_dir(&sentinel).expect("create the sentinel folder");
    fs::write(sentinel.join("keep.txt"), b"sentinel: never written\n").expect("write the sentinel");
    sentinel
}

/// The refusal text for `path` and `reason`, as `RunRefusal` prints it.
fn refused(path: &Path, reason: &str) -> String {
    format!("{}: {reason}", path.display())
}

/// `run` must refuse; its printed refusal.
fn run_refusal(mode: &Mode, build_script: &Path) -> String {
    match run(mode, build_script) {
        Ok(name) => panic!("run gave the name {name}, not a refusal"),
        Err(refusal) => refusal.to_string(),
    }
}

/// The names of the entries in `dir`, sorted.
fn names_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("list a folder")
        .map(|entry| {
            entry
                .expect("read a folder entry")
                .file_name()
                .into_string()
                .expect("a UTF-8 name")
        })
        .collect();
    names.sort();
    names
}

#[test]
fn bundle_arguments_are_refused_with_their_reason() {
    let unknown = |arg: &str| format!("unknown option {arg:?}: the only option is --name");
    let extra = |arg: &str| {
        format!("extra argument {arg:?}: give one OUT_DIR, or --name and one BUNDLE_DIR")
    };
    let cases: Vec<(Vec<&str>, String)> = vec![
        (
            vec![],
            "no argument: give OUT_DIR, or --name BUNDLE_DIR".into(),
        ),
        (vec!["--unknown"], unknown("--unknown")),
        (vec!["-"], unknown("-")),
        (vec!["out", "-x"], unknown("-x")),
        (vec!["--name", "-x"], unknown("-x")),
        (vec!["--name"], "--name needs a BUNDLE_DIR after it".into()),
        (
            vec!["--name", "--name"],
            "--name needs a BUNDLE_DIR after it".into(),
        ),
        (vec!["out", "more"], extra("more")),
        (vec!["out", "--name"], extra("--name")),
        (vec!["--name", "dir", "more"], extra("more")),
        (vec![""], "an empty path names no directory".into()),
        (
            vec!["--name", ""],
            "an empty path names no directory".into(),
        ),
    ];
    for (args, reason) in &cases {
        let args: Vec<OsString> = args.iter().map(|arg| os(arg)).collect();
        match parse_args(&args) {
            Ok(mode) => panic!("{args:?} was accepted as {mode:?}"),
            Err(refusal) => {
                assert_eq!(refusal.to_string(), *reason, "the reason for {args:?}");
                assert_ne!(
                    refusal.to_string(),
                    USAGE,
                    "{args:?} got only the usage line"
                );
            }
        }
    }

    // The five rules give five different reasons.
    let mut reasons: Vec<String> = [
        ArgRefusal::NoArgument,
        ArgRefusal::UnknownOption(os("-x")),
        ArgRefusal::NameWithoutDir,
        ArgRefusal::ExtraArgument(os("-x")),
        ArgRefusal::EmptyPath,
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    reasons.sort();
    reasons.dedup();
    assert_eq!(reasons.len(), 5, "two argument rules share a reason");

    assert_eq!(
        parse_args(&[os("out")]),
        Ok(Mode::Build {
            out_dir: PathBuf::from("out")
        })
    );
    assert_eq!(
        parse_args(&[os("--name"), os("dir")]),
        Ok(Mode::Name {
            bundle_dir: PathBuf::from("dir")
        })
    );
}

#[test]
fn bundle_arguments_preserve_non_utf8_paths() {
    let out = OsString::from_vec(b"out-\xff\xfe".to_vec());
    match parse_args(&[out.clone()]) {
        Ok(Mode::Build { out_dir }) => assert_eq!(out_dir.as_os_str().as_bytes(), out.as_bytes()),
        other => panic!("a non-UTF-8 OUT_DIR gave {other:?}"),
    }
    let dir = OsString::from_vec(b"dir-\x80".to_vec());
    match parse_args(&[os("--name"), dir.clone()]) {
        Ok(Mode::Name { bundle_dir }) => {
            assert_eq!(bundle_dir.as_os_str().as_bytes(), dir.as_bytes())
        }
        other => panic!("a non-UTF-8 BUNDLE_DIR gave {other:?}"),
    }
}

#[test]
fn tools_bundle_name_mode_prints_the_lab_cid() {
    let tmp = TempDir::new("bundle-name-mode");
    let bundle = tmp.path().join("bundle");
    fs::create_dir(&bundle).expect("create the bundle folder");
    fs::write(bundle.join("capsule.json"), CAPSULE_MANIFEST).expect("write capsule.json");
    fs::write(bundle.join("capsule.wasm"), MODULE).expect("write capsule.wasm");

    let mode = parse_args(&[os("--name"), bundle.clone().into_os_string()]).expect("parse");
    // The name mode never builds: a build script that does not exist is fine.
    let name = run(&mode, &tmp.path().join("no-build")).expect("name the bundle");
    let expected = bundle_identity(&bundle).expect("bundle_identity names the bundle");
    assert_eq!(name, expected.to_string());
    assert_eq!(name, MODULE_BUNDLE_LAB_CID);
}

#[test]
fn an_existing_out_dir_is_refused_and_nothing_is_written() {
    let tmp = TempDir::new("bundle-existing-out");
    let sentinel = sentinel_dir(&tmp);
    let before = snapshot(&sentinel);

    let folder = tmp.path().join("a-folder");
    fs::create_dir(&folder).expect("create a folder");
    let file = tmp.path().join("a-file");
    fs::write(&file, b"not a folder\n").expect("write a file");
    let link = tmp.path().join("a-link");
    symlink(&sentinel, &link).expect("link to the sentinel folder");

    for out_dir in [&folder, &file, &link] {
        let mode = Mode::Build {
            out_dir: out_dir.clone(),
        };
        assert_eq!(
            run_refusal(&mode, &stand_in("module")),
            refused(out_dir, OUT_DIR_EXISTS)
        );
    }
    assert!(
        names_in(&folder).is_empty(),
        "something was written into the folder"
    );
    assert_eq!(fs::read(&file).expect("read the file"), b"not a folder\n");
    assert_eq!(snapshot(&sentinel), before, "the sentinel folder changed");
}

#[test]
fn a_link_planted_during_the_build_is_never_written_through() {
    // A link at OUT_DIR/bundle to a folder: bundle/ is refused, nothing goes
    // into the folder.
    let tmp = TempDir::new("bundle-planted-dir-link");
    let sentinel = sentinel_dir(&tmp);
    let before = snapshot(&sentinel);
    let out_dir = tmp.path().join("out");
    let mode = Mode::Build {
        out_dir: out_dir.clone(),
    };
    assert_eq!(
        run_refusal(&mode, &stand_in("plant-bundle-link")),
        refused(&out_dir.join("bundle"), BUNDLE_DIR_EXISTS)
    );
    assert_eq!(snapshot(&sentinel), before, "the sentinel folder changed");

    // A link at OUT_DIR/capsule.wasm to a file: it moves into the bundle as a
    // link, and bundle_identity refuses it with its own link reason.
    let tmp = TempDir::new("bundle-planted-module-link");
    let sentinel_file = tmp.path().join("sentinel-file");
    fs::write(&sentinel_file, b"sentinel: never in a bundle\n").expect("write the sentinel");
    let out_dir = tmp.path().join("out");
    let mode = Mode::Build {
        out_dir: out_dir.clone(),
    };
    let refusal = run_refusal(&mode, &stand_in("link-module"));
    let bundle = out_dir.join("bundle");
    let shared = bundle_identity(&bundle).expect_err("bundle_identity refuses a linked module");
    assert_eq!(refusal, refused(&bundle, &shared.to_string()));
    assert!(
        refusal.ends_with("capsule.wasm is a symbolic link: the lab CID covers only regular files and never follows a link"),
        "not the shared link reason: {refusal}"
    );
    assert_eq!(
        fs::read(&sentinel_file).expect("read the sentinel"),
        b"sentinel: never in a bundle\n"
    );
}

#[test]
fn a_failed_build_is_refused_with_its_cause() {
    let tmp = TempDir::new("bundle-failed-build");
    let failing = stand_in("exit-3");
    let failed = run_refusal(
        &Mode::Build {
            out_dir: tmp.path().join("out-1"),
        },
        &failing,
    );
    assert_eq!(
        failed,
        refused(&failing, "tools/build failed (exit status: 3)")
    );

    let missing = tmp.path().join("no-such-build");
    let not_started = run_refusal(
        &Mode::Build {
            out_dir: tmp.path().join("out-2"),
        },
        &missing,
    );
    assert_eq!(
        not_started,
        refused(
            &missing,
            &format!("tools/build did not start: {NO_SUCH_FILE}")
        )
    );
    assert_ne!(failed, not_started);
}

/// A writer whose every write fails.
struct FailingWriter;

impl io::Write for FailingWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("the test writer refuses every byte"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn bundle_io_refusals_keep_path_and_cause() {
    let tmp = TempDir::new("bundle-io-refusals");

    // OUT_DIR's parent does not exist.
    let out_dir = tmp.path().join("missing").join("out");
    assert_eq!(
        run_refusal(
            &Mode::Build {
                out_dir: out_dir.clone()
            },
            &stand_in("module")
        ),
        refused(
            &out_dir,
            &format!("OUT_DIR cannot be created: {NO_SUCH_FILE}")
        )
    );

    // The build leaves OUT_DIR read-only, so bundle/ cannot be made in it.
    let out_dir = tmp.path().join("locked");
    let refusal = run_refusal(
        &Mode::Build {
            out_dir: out_dir.clone(),
        },
        &stand_in("lock-out-dir"),
    );
    fs::set_permissions(&out_dir, fs::Permissions::from_mode(0o755)).expect("unlock OUT_DIR");
    assert_eq!(
        refusal,
        refused(
            &out_dir.join("bundle"),
            "bundle/ cannot be created: Permission denied (os error 13)"
        )
    );

    // The build writes no module, so there is nothing to move.
    let out_dir = tmp.path().join("no-module");
    assert_eq!(
        run_refusal(
            &Mode::Build {
                out_dir: out_dir.clone()
            },
            &stand_in("nothing")
        ),
        refused(
            &out_dir.join("capsule.wasm"),
            &format!("capsule.wasm cannot be moved into the bundle: {NO_SUCH_FILE}")
        )
    );

    // capsule.json is made new: a missing folder, an existing file and a link
    // are each refused, and nothing is written through the link.
    let missing = tmp.path().join("missing").join("capsule.json");
    let error = write_new_file(&missing, CAPSULE_MANIFEST).expect_err("no folder");
    assert_eq!(
        error.to_string(),
        refused(
            &missing,
            &format!("capsule.json cannot be created: {NO_SUCH_FILE}")
        )
    );
    let existing = tmp.path().join("existing.json");
    fs::write(&existing, b"already here\n").expect("write a file");
    let target = tmp.path().join("target.json");
    fs::write(&target, b"behind a link\n").expect("write a file");
    let link = tmp.path().join("link.json");
    symlink(&target, &link).expect("link to a file");
    for path in [&existing, &link] {
        let error = write_new_file(path, CAPSULE_MANIFEST).expect_err("an entry is there");
        assert_eq!(
            error.to_string(),
            refused(
                path,
                "capsule.json cannot be created: File exists (os error 17)"
            )
        );
    }
    assert_eq!(fs::read(&existing).expect("read"), b"already here\n");
    assert_eq!(fs::read(&target).expect("read"), b"behind a link\n");

    // A write that fails after the file is made.
    let made = tmp.path().join("made.json");
    let error = write_all_to(&made, &mut FailingWriter, CAPSULE_MANIFEST).expect_err("refused");
    assert_eq!(
        error.to_string(),
        refused(
            &made,
            "capsule.json cannot be written: the test writer refuses every byte"
        )
    );
}

/// Run the real `tools/bundle` with `args`. The child cargo gets its own
/// target and build folder, `child_target`, so it never waits on the outer
/// `cargo test`'s build lock; it is set on the child only. The caller puts
/// it under its own temp dir, so the test writes nothing in the checkout.
fn tools_bundle(child_target: &Path, args: &[&OsString]) -> Output {
    Command::new(lane_dir().join("tools").join("bundle"))
        .args(args)
        .env("CARGO_TARGET_DIR", child_target)
        .env("CARGO_BUILD_BUILD_DIR", child_target)
        .output()
        .expect("spawn tools/bundle")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Panic with everything the child printed.
fn show(what: &str, output: &Output) -> String {
    format!(
        "{what} ({}):\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        text(&output.stdout),
        text(&output.stderr)
    )
}

/// A refused child: `status`, nothing on stdout, and stderr ending with
/// `tail`.
fn assert_refused(output: &Output, status: i32, tail: &str) {
    assert_eq!(
        output.status.code(),
        Some(status),
        "{}",
        show("the exit status", output)
    );
    assert!(
        output.stdout.is_empty(),
        "{}",
        show("a refusal printed to stdout", output)
    );
    assert!(
        text(&output.stderr).ends_with(tail),
        "{}\n--- expected the end ---\n{tail}",
        show("the stderr", output)
    );
}

#[test]
fn tools_bundle_builds_a_new_bundle_and_prints_its_lab_cid() {
    let tmp = TempDir::new("tools-bundle");
    let out_dir = tmp.path().join("out");
    let child_target = tmp.path().join("child-target");
    let output = tools_bundle(&child_target, &[&out_dir.clone().into_os_string()]);
    assert!(
        output.status.success(),
        "{}",
        show("tools/bundle failed", &output)
    );

    let bundle = out_dir.join("bundle");
    let named = bundle_identity(&bundle).expect("bundle_identity names the new bundle");
    assert_eq!(
        text(&output.stdout),
        format!("{named}\n"),
        "stdout is not the one name"
    );
    assert_eq!(names_in(&bundle), ["capsule.json", "capsule.wasm"]);
    for name in ["capsule.json", "capsule.wasm"] {
        let kind = fs::symlink_metadata(bundle.join(name))
            .expect("stat")
            .file_type();
        assert!(kind.is_file(), "{name} is not a regular file");
    }
    // OUT_DIR keeps the receipt; the module moved into the bundle.
    assert_eq!(names_in(&out_dir), ["bundle", "receipt.txt"]);
    let module_sha = sha256_file(&bundle.join("capsule.wasm"));
    assert_eq!(module_sha, Receipt::read(&out_dir).get("artifact_sha256"));
    assert_eq!(
        module_sha, PINNED_ARTIFACT_SHA256,
        "capsule.wasm changed: STOP"
    );
    assert_eq!(
        fs::read(bundle.join("capsule.json")).expect("read"),
        CAPSULE_MANIFEST
    );
    assert_eq!(named.to_string(), REFERENCE_LAB_CID);

    // The name mode prints the same name.
    let output = tools_bundle(
        &child_target,
        &[&os("--name"), &bundle.clone().into_os_string()],
    );
    assert!(
        output.status.success(),
        "{}",
        show("tools/bundle --name failed", &output)
    );
    assert_eq!(text(&output.stdout), format!("{named}\n"));

    // The same OUT_DIR again: refused, and the bundle is unchanged.
    let before = snapshot(&out_dir);
    let output = tools_bundle(&child_target, &[&out_dir.clone().into_os_string()]);
    assert_refused(
        &output,
        1,
        &format!("bundle: refused: {}\n", refused(&out_dir, OUT_DIR_EXISTS)),
    );
    assert_eq!(snapshot(&out_dir), before, "OUT_DIR changed");

    // A folder that is no bundle: bundle_identity's own refusal, unchanged.
    let empty = tmp.path().join("empty");
    fs::create_dir(&empty).expect("create a folder");
    let shared = bundle_identity(&empty).expect_err("an empty folder is no bundle");
    let output = tools_bundle(
        &child_target,
        &[&os("--name"), &empty.clone().into_os_string()],
    );
    assert_refused(
        &output,
        1,
        &format!(
            "bundle: refused: {}\n",
            refused(&empty, &shared.to_string())
        ),
    );

    // An unknown option: its reason, then the usage line.
    let output = tools_bundle(&child_target, &[&os("--unknown")]);
    assert_refused(
        &output,
        2,
        &format!("bundle: unknown option \"--unknown\": the only option is --name\n{USAGE}\n"),
    );
}
