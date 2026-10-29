use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use wasm_capsule_audit::{audit_component, Refusal};

#[path = "support.rs"]
mod support;

use support::*;

const FUNC_IMPORT: &str = r#"(component (import "wasi:cli/exit@0.2.0" (func)))"#;
const INTERFACE: &str = "wasi:cli/exit@0.2.0";
const REFUSAL_DISPLAY: &str = "undeclared interface wasi:cli/exit@0.2.0";

#[test]
fn func_import_is_refused() {
    assert!(
        FUNC_IMPORT.contains("(func)"),
        "fixture is a function import"
    );
    let wasm = wat::parse_str(FUNC_IMPORT).expect("fixture parses");
    let attribution = read_live_attribution(FUNC_FINDING_ID);
    let detail = accept_detail("function", FUNC_IMPORT);
    let finding = finding_path(FUNC_FINDING_FILE);
    match audit_component(&wasm, &[]) {
        Err(ref refusal @ Refusal::UndeclaredInterface { ref name }) => {
            assert_eq!(name, INTERFACE);
            assert_eq!(refusal.to_string(), REFUSAL_DISPLAY);
            record_outcome(false, &finding, &attribution, &detail).expect("record refusal");
            assert_no_finding(&finding);
        }
        Ok(listed) => {
            record_outcome(true, &finding, &attribution, &detail).expect("record accept");
            panic!("accepted undeclared function import: {listed:?}");
        }
        Err(refusal) => panic!("failure, not a skip: {refusal}"),
    }
}

#[test]
fn declared_func_import_is_listed() {
    assert!(
        FUNC_IMPORT.contains("(func)"),
        "fixture is a function import"
    );
    let wasm = wat::parse_str(FUNC_IMPORT).expect("fixture parses");
    let listed = audit_component(&wasm, &[INTERFACE]).expect("declared function import is listed");
    assert_eq!(listed, vec![INTERFACE.to_string()]);
}

#[test]
fn plant_skips_when_the_anchor_is_not_once() {
    // plant_edit does not run cargo. Zero and two anchors are skips.
    let replacement = type_skip_replacement("Func");
    for count in [0, 2] {
        match plant_edit(&ANCHOR.repeat(count), &replacement) {
            Plant::Skip(reason) => assert!(reason.contains(SKIP_MARK), "{reason}"),
            Plant::Source(text) => panic!("count {count} planted: {text}"),
        }
    }
}

#[test]
fn stale_plant_is_reported_as_skip() {
    let replacement = type_skip_replacement("Func");
    for count in [0, 2] {
        let plant = plant_edit(&ANCHOR.repeat(count), &replacement);
        let report = report_plant(&plant);
        assert_skip_report(&report);
        let falsified = falsifier_reports_skip_as_pass(&plant);
        let caught = catch_unwind(AssertUnwindSafe(|| assert_skip_report(&falsified)));
        assert!(
            caught.is_err(),
            "a falsifier that reports the skipped plant as passed was not caught"
        );
    }
    match plant_edit(ANCHOR, &replacement) {
        Plant::Source(planted) => assert_func_skip_shape(ANCHOR, &planted),
        Plant::Skip(reason) => panic!("one anchor skipped: {reason}"),
    }
}

#[test]
fn finding_uses_live_head_and_bytes() {
    let args = git_log_args();
    assert!(args.contains(&"HEAD"));
    assert!(!args.iter().any(|arg| arg.contains("spike/agent-host")));
    // The oracle calls the tools directly so a frozen implementation helper
    // cannot also freeze the expected value.
    let expected_commit = Command::new("git")
        .args(["log", "-1", "--format=%H", "HEAD", "--", LIVE_LIB_REL])
        .current_dir(repo_root())
        .output()
        .expect("independent HEAD lookup");
    assert!(expected_commit.status.success());
    let commit = String::from_utf8(expected_commit.stdout)
        .expect("commit utf-8")
        .trim()
        .to_string();
    assert_eq!(commit.len(), 40);
    let expected_digest = Command::new("shasum")
        .args(["-a", "256"])
        .arg(audit_lib())
        .output()
        .expect("independent file digest");
    assert!(expected_digest.status.success());
    let digest = String::from_utf8(expected_digest.stdout)
        .expect("digest utf-8")
        .split_whitespace()
        .next()
        .expect("digest")
        .to_string();
    assert_eq!(digest.len(), 64);
    for finding_id in [FUNC_FINDING_ID, MODULE_FINDING_ID, TYPE_FINDING_ID] {
        let line = read_live_attribution(finding_id);
        assert_live_attribution(&line, finding_id, &commit, &digest);
        let frozen = attribution(finding_id, "frozen-commit", "frozen-digest");
        let caught = catch_unwind(AssertUnwindSafe(|| {
            assert_live_attribution(&frozen, finding_id, &commit, &digest);
        }));
        assert!(caught.is_err(), "frozen attribution was accepted");
    }
}

#[test]
fn frozen_attribution_helpers_are_caught() {
    let _hold = isolated_temp("frozen-attribution");
    let dir = _hold.dir.clone();
    let lane = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = fs::read_to_string(lane.join("Cargo.toml"))
        .expect("lane manifest")
        .replace(
            "\"../wasm-capsule/audit\"",
            &format!("{:?}", audit_root().canonicalize().expect("audit path")),
        );
    fs::write(dir.join("Cargo.toml"), manifest).expect("mutant manifest");
    copy_file(&lane.join("Cargo.lock"), &dir.join("Cargo.lock")).expect("locked dependencies");
    fs::create_dir_all(dir.join("src")).expect("mutant src");
    copy_file(&lane.join("src/lib.rs"), &dir.join("src/lib.rs")).expect("empty library");
    fs::create_dir_all(dir.join("tests")).expect("mutant tests");
    let probe = fs::read_to_string(lane.join("tests/func_import.rs"))
        .expect("probe source")
        .replace("env!(\"CARGO_MANIFEST_DIR\")", &format!("{lane:?}"));
    let support_source = fs::read_to_string(lane.join("tests/support.rs"))
        .expect("support source")
        .replace("env!(\"CARGO_MANIFEST_DIR\")", &format!("{lane:?}"));
    fs::write(dir.join("tests/redteam_func_import.rs"), probe).expect("probe copy");
    let mut args = test_args(&dir.join("Cargo.toml"));
    *args.last_mut().expect("test name") = "finding_uses_live_head_and_bytes".into();
    for (helper, parameters, width) in [("git_commit", "", 40), ("sha256_file", "path: &Path", 64)]
    {
        let anchor = format!("fn {helper}({parameters}) -> String {{");
        assert_eq!(
            support_source.matches(&anchor).count(),
            1,
            "{helper} anchor"
        );
        let frozen = format!("{anchor}\n    return {:?}.to_string();", "0".repeat(width));
        fs::write(
            dir.join("tests/support.rs"),
            support_source.replacen(&anchor, &frozen, 1),
        )
        .expect("freeze attribution helper");
        let output = run_cargo(&args, &dir.join("target"), PLANT_TIMEOUT);
        assert!(!output.spawn_error, "{}", output.output);
        assert!(!output.timed_out, "{}", tail(&output.output));
        assert_eq!(output.exit_code, Some(101), "{}", tail(&output.output));
        assert!(
            !output.output.contains(COULD_NOT_COMPILE),
            "{}",
            output.output
        );
        assert!(
            output
                .output
                .contains("test finding_uses_live_head_and_bytes ... FAILED"),
            "frozen {helper} escaped the named test: {}",
            output.output
        );
        assert!(output.output.contains("assertion `left == right` failed"));
    }
    finish_plant(&dir, b"unchanged", b"unchanged").expect("mutant cleanup");
    assert!(!dir.exists(), "mutant directory remains");
}

#[test]
fn clean_run_writes_no_finding() {
    let _hold = isolated_temp("finding");
    let dir = _hold.dir.clone();
    // The module fixture stays in module_import.rs. This case only proves a
    // refusal does not create the module finding.
    let cases = [
        (
            FUNC_FINDING_ID,
            FUNC_FINDING_FILE,
            accept_detail("function", FUNC_IMPORT),
        ),
        (
            MODULE_FINDING_ID,
            MODULE_FINDING_FILE,
            accept_detail("core-module", "env"),
        ),
        (
            TYPE_FINDING_ID,
            TYPE_FINDING_FILE,
            accept_detail("type", "env"),
        ),
    ];
    for (finding_id, file_name, detail) in cases {
        let finding = dir.join(file_name);
        let attribution = read_live_attribution(finding_id);
        record_outcome(false, &finding, &attribution, &detail).expect("record refusal");
        assert_no_finding(&finding);
        falsifier_writes_after_refusal(&finding, &attribution, &detail).expect("falsifier writes");
        let caught = catch_unwind(AssertUnwindSafe(|| assert_no_finding(&finding)));
        assert!(
            caught.is_err(),
            "a finding written after a refusal was not caught"
        );
    }
    assert_no_finding(&finding_path(FUNC_FINDING_FILE));
    assert_no_finding(&finding_path(MODULE_FINDING_FILE));
    assert_no_finding(&finding_path(TYPE_FINDING_FILE));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn plant_harness_errors_are_errors() {
    assert_eq!(PLANT_TIMEOUT, Duration::from_secs(360));
    let cases = [
        (LOCKFILE_ERROR, real_lockfile_failure()),
        (COMPILE_ERROR, real_compile_failure()),
        (LAUNCH_ERROR, real_launch_failure()),
        (TIMEOUT_ERROR, real_timeout()),
    ];
    let mut reasons = Vec::new();
    for (reason, step) in cases {
        assert_is_error(&classify(&step), reason);
        reasons.push(reason);
        let falsified = falsifier_classifies_harness_error_as_caught(&step);
        let caught = catch_unwind(AssertUnwindSafe(|| assert_is_error(&falsified, reason)));
        assert!(
            caught.is_err(),
            "{reason} was not caught when misclassified as a caught plant"
        );
    }
    for (index, reason) in reasons.iter().enumerate() {
        for other in reasons.iter().skip(index + 1) {
            assert_ne!(reason, other);
        }
    }
    let mixed = Step::Test(CommandOutput {
        exit_code: Some(101),
        output: format!("{COULD_NOT_COMPILE}\n{MUST_REFUSE}"),
        timed_out: false,
        spawn_error: false,
    });
    assert_is_error(&classify(&mixed), COMPILE_ERROR);
    let caught = Step::Test(CommandOutput {
        exit_code: Some(101),
        output: format!("must refuse: Ok([])"),
        timed_out: false,
        spawn_error: false,
    });
    assert!(
        classify(&caught).is_ok(),
        "nonzero exit with {MUST_REFUSE} is the caught plant"
    );
}

#[test]
fn classify_test_reports_split_utf8_as_a_harness_error() {
    let output = "€".repeat(1334);
    let naive = output.len().saturating_sub(TAIL_BYTES);
    assert!(
        !output.is_char_boundary(naive),
        "the last {TAIL_BYTES} bytes must start inside a character"
    );
    let result = classify_test(&CommandOutput {
        exit_code: Some(1),
        output: output.clone(),
        timed_out: false,
        spawn_error: false,
    });
    assert_eq!(
        result,
        Err(format!("the plant was not caught\nexit: Some(1)\n{output}"))
    );
    let split = catch_unwind(AssertUnwindSafe(|| {
        falsifier_tail_splits_a_character(&output)
    }));
    assert!(
        split.is_err(),
        "a tail that starts inside a character was not caught"
    );
}

#[test]
fn plant_cleanup_and_source_guard_are_enforced() {
    let same = b"live-bytes";
    for body in [Ok(()), Err("launch failed".to_string())] {
        let _hold = isolated_temp("guard");
        let dir = _hold.dir.clone();
        fs::write(dir.join("marker"), b"x").expect("marker");
        let expect_body = body.clone();
        let result = apply_guard(&dir, same, same, body);
        assert!(!dir.exists(), "temp directory remains");
        assert_eq!(result, expect_body);
    }
    for body in [Ok(()), Err("launch failed".to_string())] {
        let _hold = isolated_temp("changed");
        let dir = _hold.dir.clone();
        fs::write(dir.join("marker"), b"x").expect("marker");
        let result = apply_guard(&dir, b"before", b"after", body);
        assert!(!dir.exists(), "temp directory remains");
        assert_byte_change_is_error(&result);
    }
    for body in [Ok(()), Err("launch failed".to_string())] {
        let _hold = isolated_temp("leak");
        let dir = _hold.dir.clone();
        fs::write(dir.join("marker"), b"x").expect("marker");
        let leaked = apply_guard_omit_cleanup(&dir, same, same, body);
        let caught = catch_unwind(AssertUnwindSafe(|| {
            assert!(!dir.exists(), "temp directory remains");
            let _ = leaked;
        }));
        assert!(caught.is_err(), "omitted cleanup was not caught");
        let _ = fs::remove_dir_all(&dir);
    }
    for body in [Ok(()), Err("launch failed".to_string())] {
        let _hold = isolated_temp("bypass");
        let dir = _hold.dir.clone();
        let bypass = apply_guard_bypass_bytes(&dir, b"before", b"after", body);
        let caught = catch_unwind(AssertUnwindSafe(|| assert_byte_change_is_error(&bypass)));
        assert!(caught.is_err(), "bypassed byte comparison was not caught");
    }
    // Checked while the guard is still held, so a refusal that created the
    // directory cannot pass by dropping it afterwards.
    let parent = isolated_temp("init-parent");
    let parent_dir = parent.dir.clone();
    let (created_hold, created) = open_owned(&parent_dir, "plant");
    assert_eq!(created, Ok(()));
    assert!(
        created_hold.dir.exists(),
        "initialization did not create a directory"
    );
    drop(created_hold);
    let manifest = parent_dir.join("Cargo.toml");
    fs::write(&manifest, b"").expect("parent manifest");
    let reason = format!("parent has Cargo.toml: {}", manifest.display());
    let (hold, refused) = open_owned(&parent_dir, "plant");
    assert_eq!(refused, Err(reason.clone()));
    assert!(!hold.dir.exists(), "initialization left a directory");
    drop(hold);
    let leaked_child = parent_dir.join("redteam-func-plant-init-leak");
    let leaked = falsifier_create_isolated_dir(&leaked_child);
    assert_eq!(leaked, Err(reason));
    let caught = catch_unwind(AssertUnwindSafe(|| {
        assert!(!leaked_child.exists(), "temp directory remains");
    }));
    assert!(
        caught.is_err(),
        "initialization that creates before the parent check was not caught"
    );
    let _ = fs::remove_dir_all(&leaked_child);
}

#[test]
fn skipped_func_import_is_caught() {
    run_skipped_plant(&func_probe());
}

#[test]
fn command_timeout_bounds_descendants_and_cleanup() {
    // Cover a waiting parent, an exited parent with inherited output handles,
    // and a recorded descendant whose termination is checked independently.
    for script in [
        "sleep 2 & wait",
        "sleep 2 &",
        "sleep 2 & echo $! > child.pid; wait",
    ] {
        let _hold = isolated_temp("descendant-timeout");
        let dir = _hold.dir.clone();
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script]).current_dir(&dir);
        let started = Instant::now();
        let output = run_command(command, Duration::from_millis(200));
        let child_pid = fs::read_to_string(dir.join("child.pid")).ok();
        let result = apply_guard(&dir, b"same", b"same", classify(&Step::Test(output)));
        assert_is_error(&result, TIMEOUT_ERROR);
        assert!(!dir.exists(), "temp directory remains");
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "timeout and cleanup waited for the descendant: {script}"
        );
        if script.contains("child.pid") {
            let pid = child_pid.expect("descendant started before timeout");
            let reaping = Instant::now();
            let state = loop {
                let state = Command::new("/bin/kill")
                    .args(["-0", pid.trim()])
                    .env("LC_ALL", "C")
                    .output()
                    .expect("inspect descendant");
                if !state.status.success() || reaping.elapsed() >= Duration::from_millis(200) {
                    break state;
                }
                thread::sleep(Duration::from_millis(5));
            };
            assert!(
                !state.status.success(),
                "descendant still runs after cleanup"
            );
            let error = String::from_utf8_lossy(&state.stderr);
            assert!(
                error.contains("No such process"),
                "descendant termination was not proven: {error}"
            );
        }
    }
}

#[test]
fn command_collects_both_output_streams() {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "printf stdout; printf stderr >&2"]);
    let output = run_command(command, Duration::from_secs(2));
    assert!(!output.spawn_error, "{}", output.output);
    assert!(!output.timed_out);
    assert_eq!(output.exit_code, Some(0));
    assert_eq!(output.output, "stdoutstderr");
}

#[test]
fn command_output_limit_is_an_error() {
    let mut command = Command::new("/bin/dd");
    command.args([
        "if=/dev/zero",
        "bs=65536",
        &format!("count={}", OUTPUT_LIMIT / 65536 + 1),
    ]);
    let output = run_command(command, Duration::from_secs(10));
    assert!(
        output.spawn_error,
        "output limit was accepted: exit {:?}, timed out {}, collected {} bytes",
        output.exit_code,
        output.timed_out,
        output.output.len()
    );
    assert!(!output.timed_out);
    assert!(output.output.starts_with("command output limit exceeded\n"));
    assert_is_error(&classify(&Step::Test(output)), LAUNCH_ERROR);
}

fn assert_func_skip_shape(original: &str, planted: &str) {
    assert_type_skip_shape(original, planted, "Func");
}

fn func_probe() -> PlantedProbe {
    PlantedProbe {
        replacement: type_skip_replacement("Func"),
        assert_shape: assert_func_skip_shape,
        test_file: "redteam_func_import.rs",
        test_source: refusal_test_source("func_import_is_refused", FUNC_IMPORT),
        test_binary: "redteam_func_import",
        exact_test: "func_import_is_refused",
    }
}

fn test_args(manifest: &Path) -> Vec<String> {
    cargo_test_args(manifest, "redteam_func_import", "func_import_is_refused")
}

fn compile_fault_args(manifest: &Path) -> Vec<String> {
    vec![
        "test".into(),
        "--offline".into(),
        "--locked".into(),
        "--manifest-path".into(),
        manifest.display().to_string(),
    ]
}

fn real_lockfile_failure() -> Step {
    let _hold = isolated_temp("lockfile");
    let dir = _hold.dir.clone();
    let manifest = dir.join("Cargo.toml");
    let output = run_cargo(
        &lockfile_args(&manifest),
        &dir.join("target"),
        Duration::from_secs(60),
    );
    assert!(!output.spawn_error, "{}", output.output);
    assert!(!output.timed_out, "{}", tail(&output.output));
    assert_ne!(output.exit_code, Some(0), "{}", tail(&output.output));
    Step::Lockfile(output)
}

fn real_compile_failure() -> Step {
    let _hold = isolated_temp("compile");
    let dir = _hold.dir.clone();
    fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"redteam-compile-fault\"\nversion = \"0.0.0\"\nedition = \"2021\"\npublish = false\n",
    )
    .expect("manifest");
    fs::create_dir_all(dir.join("src")).expect("src");
    fs::write(dir.join("src/lib.rs"), "fn broken( {\n").expect("broken lib");
    let manifest = dir.join("Cargo.toml");
    let target = dir.join("target");
    let lockfile = run_cargo(&lockfile_args(&manifest), &target, Duration::from_secs(120));
    assert_eq!(
        lockfile.exit_code,
        Some(0),
        "lockfile for the compile fault: {}",
        tail(&lockfile.output)
    );
    let output = run_cargo(
        &compile_fault_args(&manifest),
        &target,
        Duration::from_secs(180),
    );
    assert!(
        output.output.contains(COULD_NOT_COMPILE),
        "{}",
        tail(&output.output)
    );
    Step::Test(output)
}

fn real_launch_failure() -> Step {
    let output = run_command(
        Command::new("redteam-missing-cargo-039"),
        Duration::from_secs(5),
    );
    assert!(output.spawn_error, "{}", output.output);
    Step::Test(output)
}

fn real_timeout() -> Step {
    let mut command = Command::new("sleep");
    command.arg("30");
    let output = run_command(command, Duration::from_millis(200));
    assert!(output.timed_out, "sleep finished before the timeout");
    Step::Test(output)
}
