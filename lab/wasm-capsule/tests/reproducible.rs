//! The lane's foundation claim: two clean builds of the same source, in
//! different paths, are byte-identical on this one Mac (PRINCIPLES P13).

mod common;

use common::build::{
    copy_lane_source, lane_dir, run_build, run_build_with_env, sha256_file, spawn_build, TempDir,
    SYSTEM_BASH,
};
use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn two_clean_builds_in_different_paths_are_byte_identical() {
    let lane = lane_dir();
    let a = TempDir::new("repro-a");
    let b = TempDir::new("repro-b");

    // Two copies of the lane source at two different absolute paths, each under
    // a directory whose name has a space, so the build must not split that path
    // on whitespace when it passes --remap-path-prefix to rustc. Each copy is
    // laid out as `<root>/lab/wasm-capsule`, with the out-of-lane path
    // dependencies reachable from it (`copy_lane_source`).
    let root_a = a.path().join("capsule lab");
    let root_b = b.path().join("capsule lab");
    fs::create_dir_all(&root_a).expect("create root_a");
    fs::create_dir_all(&root_b).expect("create root_b");
    let lane_a = copy_lane_source(&lane, &root_a);
    let lane_b = copy_lane_source(&lane, &root_b);
    assert_ne!(lane_a, lane_b, "the two copies must be at different paths");

    // Build each from its own empty out dir; tools/build uses a fresh target.
    let out_a = a.path().join("out");
    let out_b = b.path().join("out");
    run_build(&lane_a, &out_a);
    run_build(&lane_b, &out_b);

    let wasm_a = out_a.join("capsule.wasm");
    let wasm_b = out_b.join("capsule.wasm");
    let sha_a = sha256_file(&wasm_a);
    let sha_b = sha256_file(&wasm_b);
    assert_eq!(
        sha_a, sha_b,
        "two clean builds in different paths must have the same sha256"
    );
    // Byte equality is the real claim; the sha is only for a readable message.
    assert_eq!(
        fs::read(&wasm_a).expect("read a"),
        fs::read(&wasm_b).expect("read b"),
        "the two artifacts differ in bytes"
    );
}

/// What the status test's planted line prints on stderr before the build's
/// target folder, so the test can see that folder is in its own TMPDIR.
const TARGET_PROBE_PREFIX: &str = "wc-probe target dir: ";

/// The line the status test plants right after the cleanup trap: an expansion
/// of a variable the test removes from the build's environment.
const UNSET_PROBE_LINE: &str = ": \"$WC_UNSET_PROBE\"\n";

/// `script` with a line that prints `$TARGET_DIR` after [`TARGET_PROBE_PREFIX`],
/// then [`UNSET_PROBE_LINE`], inserted right after the line that arms the
/// cleanup trap: the one line starting with `trap ` before the `cargo build`
/// line. Panics unless that line is found exactly once.
fn with_unset_probe_after_the_trap(script: &str) -> String {
    let lines: Vec<&str> = script.split_inclusive('\n').collect();
    let build = lines
        .iter()
        .position(|line| line.starts_with("cargo build"))
        .expect("tools/build has a line starting with `cargo build`");
    let traps: Vec<usize> = (0..build)
        .filter(|&index| lines[index].starts_with("trap "))
        .collect();
    assert_eq!(
        traps.len(),
        1,
        "tools/build has {} lines starting with `trap ` before `cargo build`, not one",
        traps.len()
    );
    let mut planted = String::new();
    for (index, line) in lines.iter().enumerate() {
        planted.push_str(line);
        if index == traps[0] {
            planted.push_str(&format!("echo \"{TARGET_PROBE_PREFIX}$TARGET_DIR\" >&2\n"));
            planted.push_str(UNSET_PROBE_LINE);
        }
    }
    planted
}

/// The first line of `/bin/bash --version`, after checking it names 3.2. The
/// status test proves nothing on another version, so it fails there, with the
/// version it found, and never passes or SKIPs (task 036).
fn require_system_bash_3_2() -> String {
    let output = Command::new(SYSTEM_BASH)
        .arg("--version")
        .output()
        .unwrap_or_else(|error| panic!("start {SYSTEM_BASH} --version: {error}"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let first = stdout.lines().next().unwrap_or("").to_string();
    assert!(
        output.status.success() && first.contains(" version 3.2."),
        "this test needs {SYSTEM_BASH} 3.2, where a `set -u` error reaches the EXIT trap \
         with $? 0; found: {first:?} ({})",
        output.status
    );
    first
}

/// The names left in `dir`.
fn entries(dir: &Path) -> Vec<std::ffi::OsString> {
    fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
        .map(|entry| entry.expect("a directory entry").file_name())
        .collect()
}

/// Task 035 (P11): a `set -u` error after the cleanup trap must still fail the
/// build. On `/bin/bash` 3.2.57 such an error reaches the EXIT trap with `$?` 0,
/// so with a plain `rm -rf` trap the script exited 0 with no capsule and no
/// receipt. A copy of `tools/build` with one unbound expansion right after the
/// trap runs there, with its own empty TMPDIR and OUT_DIR. Task 036: the build
/// makes its target folder in that TMPDIR (the planted line prints it), so the
/// empty check at the end watches the folder the trap deletes.
#[test]
fn build_script_fails_closed_after_an_unbound_variable() {
    require_system_bash_3_2();
    let real =
        fs::read_to_string(lane_dir().join("tools").join("build")).expect("read tools/build");
    let tmp = TempDir::new("trap-status");
    let lane = tmp.path().join("lane");
    fs::create_dir_all(lane.join("tools")).expect("create the copy's tools/");
    fs::write(
        lane.join("tools").join("build"),
        with_unset_probe_after_the_trap(&real),
    )
    .expect("write the planted tools/build");
    let tmpdir = tmp.path().join("tmpdir");
    let out = tmp.path().join("out");
    fs::create_dir_all(&tmpdir).expect("create the build's TMPDIR");
    fs::create_dir_all(&out).expect("create OUT_DIR");

    let tmpdir_env = tmpdir.to_str().expect("a UTF-8 temp path");
    let output = spawn_build(
        SYSTEM_BASH,
        &lane,
        &out,
        &[("TMPDIR", tmpdir_env)],
        &["WC_UNSET_PROBE"],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "tools/build exited {} after an unbound variable past its cleanup trap:\n{stderr}",
        output.status
    );
    assert!(
        stderr.contains("WC_UNSET_PROBE: unbound variable"),
        "tools/build failed for another reason:\n{stderr}"
    );
    for name in ["capsule.wasm", "receipt.txt"] {
        assert!(
            !out.join(name).exists(),
            "a failed build left OUT_DIR/{name}"
        );
    }
    let target = stderr
        .lines()
        .find_map(|line| line.strip_prefix(TARGET_PROBE_PREFIX))
        .unwrap_or_else(|| panic!("the planted line printed no target dir:\n{stderr}"));
    assert_eq!(
        Path::new(target).parent(),
        Some(tmpdir.as_path()),
        "tools/build made its target dir {target} outside the TMPDIR it was given"
    );
    let left = entries(&tmpdir);
    assert!(
        left.is_empty(),
        "the cleanup trap left {left:?} in the build's TMPDIR"
    );
}

/// Task 036 (P11): a finished build removes its target folder too. One real
/// build, with TMPDIR set to a new empty folder, must leave that folder empty
/// after it succeeds (the trap the script's last line re-arms).
#[test]
fn finished_build_leaves_its_tmpdir_empty() {
    let tmp = TempDir::new("cleanup-on-success");
    let tmpdir = tmp.path().join("tmpdir");
    let out = tmp.path().join("out");
    fs::create_dir_all(&tmpdir).expect("create the build's TMPDIR");

    let tmpdir_env = tmpdir.to_str().expect("a UTF-8 temp path");
    run_build_with_env(&lane_dir(), &out, &[("TMPDIR", tmpdir_env)]);

    assert!(
        out.join("capsule.wasm").is_file(),
        "the finished build wrote no capsule.wasm"
    );
    let left = entries(&tmpdir);
    assert!(
        left.is_empty(),
        "a finished build left {left:?} in its TMPDIR"
    );
}
