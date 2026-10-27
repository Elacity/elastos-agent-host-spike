use std::fs;
use std::io::Read;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use wasm_capsule_audit::{audit_component, Refusal};

const FUNC_IMPORT: &str = r#"(component (import "wasi:cli/exit@0.2.0" (func)))"#;
const INTERFACE: &str = "wasi:cli/exit@0.2.0";
const REFUSAL_DISPLAY: &str = "undeclared interface wasi:cli/exit@0.2.0";
const ANCHOR: &str = "interfaces.push(import.name.name.to_owned());";
const SKIP_MARK: &str = "does not cover that plant";
const LIVE_LIB_REL: &str = "lab/wasm-capsule/audit/src/lib.rs";
const FINDING_ID: &str = "cx-wasm-audit-001";
const FINDING_FILE: &str = "cx-wasm-audit-001.md";
const MUST_REFUSE: &str = "must refuse";
const COULD_NOT_COMPILE: &str = "could not compile";
const LOCKFILE_ERROR: &str = "lockfile failed";
const COMPILE_ERROR: &str = "compile failed";
const LAUNCH_ERROR: &str = "launch failed";
const TIMEOUT_ERROR: &str = "timeout";
const PLANT_TIMEOUT: Duration = Duration::from_secs(360);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Plant {
    Source(String),
    Skip(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Report {
    Passed,
    Skipped(String),
}

#[derive(Debug, Clone)]
struct CommandOutput {
    exit_code: Option<i32>,
    output: String,
    timed_out: bool,
    spawn_error: bool,
}

#[derive(Debug, Clone)]
enum Step {
    Lockfile(CommandOutput),
    Test(CommandOutput),
}

#[test]
fn func_import_is_refused() {
    assert!(
        FUNC_IMPORT.contains("(func)"),
        "fixture is a function import"
    );
    let wasm = wat::parse_str(FUNC_IMPORT).expect("fixture parses");
    match audit_component(&wasm, &[]) {
        Err(ref refusal @ Refusal::UndeclaredInterface { ref name }) => {
            assert_eq!(name, INTERFACE);
            assert_eq!(refusal.to_string(), REFUSAL_DISPLAY);
            record_outcome(false, &finding_path(), &read_live_attribution())
                .expect("record refusal");
            assert_no_finding(&finding_path());
        }
        Ok(listed) => {
            record_outcome(true, &finding_path(), &read_live_attribution()).expect("record accept");
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
    for count in [0, 2] {
        match plant_edit(&ANCHOR.repeat(count)) {
            Plant::Skip(reason) => assert!(reason.contains(SKIP_MARK), "{reason}"),
            Plant::Source(text) => panic!("count {count} planted: {text}"),
        }
    }
}

#[test]
fn stale_plant_is_reported_as_skip() {
    for count in [0, 2] {
        let plant = plant_edit(&ANCHOR.repeat(count));
        let report = report_plant(&plant);
        assert_skip_report(&report);
        let falsified = falsifier_reports_skip_as_pass(&plant);
        let caught = catch_unwind(AssertUnwindSafe(|| assert_skip_report(&falsified)));
        assert!(
            caught.is_err(),
            "a falsifier that reports the skipped plant as passed was not caught"
        );
    }
    match plant_edit(ANCHOR) {
        Plant::Source(planted) => assert_func_skip_shape(ANCHOR, &planted),
        Plant::Skip(reason) => panic!("one anchor skipped: {reason}"),
    }
}

#[test]
fn finding_uses_live_head_and_bytes() {
    let args = git_log_args();
    assert!(args.contains(&"HEAD"));
    assert!(!args.iter().any(|arg| arg.contains("spike/agent-host")));
    let commit = git_commit();
    let digest = sha256_file(&audit_lib());
    let line = read_live_attribution();
    assert_live_attribution(&line, &commit, &digest);
    let frozen = frozen_attribution();
    let caught = catch_unwind(AssertUnwindSafe(|| {
        assert_live_attribution(&frozen, &commit, &digest);
    }));
    assert!(caught.is_err(), "frozen attribution was accepted");
}

#[test]
fn clean_run_writes_no_finding() {
    let dir = isolated_temp("finding");
    let finding = dir.join(FINDING_FILE);
    record_outcome(false, &finding, &read_live_attribution()).expect("record refusal");
    assert_no_finding(&finding);
    assert_no_finding(&finding_path());
    falsifier_writes_after_refusal(&finding, &frozen_attribution()).expect("falsifier writes");
    let caught = catch_unwind(AssertUnwindSafe(|| assert_no_finding(&finding)));
    assert!(
        caught.is_err(),
        "a finding written after a refusal was not caught"
    );
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
fn plant_cleanup_and_source_guard_are_enforced() {
    let same = b"live-bytes";
    for body in [Ok(()), Err("launch failed".to_string())] {
        let dir = isolated_temp("guard");
        fs::write(dir.join("marker"), b"x").expect("marker");
        let expect_body = body.clone();
        let result = apply_guard(&dir, same, same, body);
        assert!(!dir.exists(), "temp directory remains");
        assert_eq!(result, expect_body);
    }
    for body in [Ok(()), Err("launch failed".to_string())] {
        let dir = isolated_temp("changed");
        fs::write(dir.join("marker"), b"x").expect("marker");
        let result = apply_guard(&dir, b"before", b"after", body);
        assert!(!dir.exists(), "temp directory remains");
        assert_byte_change_is_error(&result);
    }
    for body in [Ok(()), Err("launch failed".to_string())] {
        let dir = isolated_temp("leak");
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
        let dir = isolated_temp("bypass");
        let bypass = apply_guard_bypass_bytes(&dir, b"before", b"after", body);
        let caught = catch_unwind(AssertUnwindSafe(|| assert_byte_change_is_error(&bypass)));
        assert!(caught.is_err(), "bypassed byte comparison was not caught");
    }
}

#[test]
fn skipped_func_import_is_caught() {
    let live = audit_lib();
    let before = fs::read(&live).expect("read live audit");
    let run = catch_unwind(AssertUnwindSafe(|| run_skipped_plant(&live, &before)));
    let after = fs::read(&live).expect("reread live audit");
    assert_eq!(before, after, "live src/lib.rs bytes changed");
    let (dir, result) = match run {
        Ok(value) => value,
        Err(payload) => resume_unwind(payload),
    };
    assert!(!dir.exists(), "temp directory remains: {}", dir.display());
    result.expect("caught plant");
}

fn run_skipped_plant(live: &Path, before: &[u8]) -> (PathBuf, Result<(), String>) {
    let dir = plant_dir();
    let _hold = TempCopy { dir: dir.clone() };
    let body = plant_body(&dir, before);
    let after = match fs::read(live) {
        Ok(bytes) => bytes,
        Err(err) => {
            let _ = fs::remove_dir_all(&dir);
            return (dir, Err(format!("reread audit source: {err}")));
        }
    };
    let result = apply_guard(&dir, before, &after, body);
    (dir, result)
}

fn plant_body(dir: &Path, before: &[u8]) -> Result<(), String> {
    let source =
        std::str::from_utf8(before).map_err(|err| format!("audit source is not utf-8: {err}"))?;
    match plant_edit(source) {
        Plant::Skip(reason) => refuse_silent_pass(&Plant::Skip(reason)),
        Plant::Source(planted) => {
            assert_func_skip_shape(source, &planted);
            run_cargo_plant(dir, &planted)
        }
    }
}

fn refuse_silent_pass(plant: &Plant) -> Result<(), String> {
    // A Rust test that returns normally counts as PASS. A stale anchor is
    // reported as SKIPPED and this function does not return Ok for it.
    let report = report_plant(plant);
    assert_skip_report(&report);
    match report {
        Report::Skipped(text) => Err(text),
        Report::Passed => Err("a skipped plant was reported as passed".into()),
    }
}

fn run_cargo_plant(dir: &Path, planted: &str) -> Result<(), String> {
    assert_parents_have_no_manifest(dir);
    copy_audit(dir)?;
    fs::write(dir.join("src/lib.rs"), planted).map_err(|err| err.to_string())?;
    let generated = redteam_test_source();
    assert!(generated.contains("expect_err(\"must refuse\")"));
    assert!(!generated.contains("UndeclaredInterface"));
    fs::write(dir.join("tests/redteam_func_import.rs"), generated)
        .map_err(|err| err.to_string())?;
    if dir.join("target").exists() {
        return Err("copied target/".into());
    }
    let manifest = dir.join("Cargo.toml");
    let target = dir.join("target");
    let lockfile = run_cargo(&lockfile_args(&manifest), &target, PLANT_TIMEOUT);
    classify(&Step::Lockfile(lockfile))?;
    let test = run_cargo(&test_args(&manifest), &target, PLANT_TIMEOUT);
    classify(&Step::Test(test))
}

fn plant_edit(source: &str) -> Plant {
    let count = source.matches(ANCHOR).count();
    if count != 1 {
        return Plant::Skip(format!(
            "{LIVE_LIB_REL} holds {count} copies of the anchor, not one. This run does not cover that plant."
        ));
    }
    Plant::Source(source.replacen(ANCHOR, &func_skip_replacement(), 1))
}

fn func_skip_replacement() -> String {
    format!(
        "if matches!(import.ty, wasmparser::ComponentTypeRef::Func(_)) {{\n                    continue;\n                }}\n                {ANCHOR}"
    )
}

fn assert_func_skip_shape(original: &str, planted: &str) {
    let replacement = func_skip_replacement();
    assert_eq!(original.matches(ANCHOR).count(), 1);
    assert_eq!(planted.matches(ANCHOR).count(), 1);
    let func_at = planted
        .find("wasmparser::ComponentTypeRef::Func(_)")
        .expect("func skip");
    let continue_at = planted.find("continue").expect("continue");
    let push_at = planted.find(ANCHOR).expect("push");
    assert!(func_at < continue_at && continue_at < push_at);
    assert_eq!(planted.replacen(&replacement, ANCHOR, 1), original);
}

fn report_plant(plant: &Plant) -> Report {
    match plant {
        Plant::Skip(reason) => Report::Skipped(format!("SKIPPED: {reason}")),
        Plant::Source(_) => Report::Passed,
    }
}

fn falsifier_reports_skip_as_pass(plant: &Plant) -> Report {
    let _ = plant;
    Report::Passed
}

fn assert_skip_report(report: &Report) {
    match report {
        Report::Skipped(text) => {
            assert!(text.starts_with("SKIPPED: "), "{text}");
            assert!(text.contains(SKIP_MARK), "{text}");
        }
        Report::Passed => panic!("a skipped plant was reported as passed"),
    }
}

fn read_live_attribution() -> String {
    attribution(&git_commit(), &sha256_file(&audit_lib()))
}

fn frozen_attribution() -> String {
    attribution("frozen-commit", "frozen-digest")
}

fn attribution(commit: &str, digest: &str) -> String {
    format!("{FINDING_ID} {commit} sha256 {digest}")
}

fn assert_live_attribution(line: &str, commit: &str, digest: &str) {
    assert_eq!(line, attribution(commit, digest));
    assert!(line.contains(commit), "{line}");
    assert!(line.contains(digest), "{line}");
}

fn record_outcome(accepted: bool, finding: &Path, attribution: &str) -> Result<(), String> {
    if !accepted {
        return Ok(());
    }
    if let Some(parent) = finding.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let body = format!(
        "{attribution}\n\naccepted an undeclared component function import\nfixture: {FUNC_IMPORT}\ndeclarations: empty\n"
    );
    fs::write(finding, body).map_err(|err| err.to_string())
}

fn falsifier_writes_after_refusal(finding: &Path, attribution: &str) -> Result<(), String> {
    record_outcome(true, finding, attribution)
}

fn assert_no_finding(path: &Path) {
    assert!(
        !path.exists(),
        "wrote a finding after a refusal: {}",
        path.display()
    );
}

fn classify(step: &Step) -> Result<(), String> {
    match step {
        Step::Lockfile(output) => classify_lockfile(output),
        Step::Test(output) => classify_test(output),
    }
}

fn classify_lockfile(output: &CommandOutput) -> Result<(), String> {
    if output.timed_out {
        return Err(TIMEOUT_ERROR.into());
    }
    if output.spawn_error {
        return Err(LAUNCH_ERROR.into());
    }
    if output.exit_code != Some(0) {
        return Err(LOCKFILE_ERROR.into());
    }
    Ok(())
}

fn classify_test(output: &CommandOutput) -> Result<(), String> {
    if output.timed_out {
        return Err(TIMEOUT_ERROR.into());
    }
    if output.spawn_error {
        return Err(LAUNCH_ERROR.into());
    }
    // A compile failure can share a nonzero exit with a caught test. The
    // compile phrase is an error, not evidence that the plant was caught.
    if output.output.contains(COULD_NOT_COMPILE) {
        return Err(COMPILE_ERROR.into());
    }
    if output.exit_code.is_some_and(|code| code != 0) && output.output.contains(MUST_REFUSE) {
        return Ok(());
    }
    Err(format!(
        "the plant was not caught\nexit: {:?}\n{}",
        output.exit_code,
        tail(&output.output)
    ))
}

fn falsifier_classifies_harness_error_as_caught(step: &Step) -> Result<(), String> {
    match classify(step) {
        Err(reason)
            if reason == LOCKFILE_ERROR
                || reason == COMPILE_ERROR
                || reason == LAUNCH_ERROR
                || reason == TIMEOUT_ERROR =>
        {
            Ok(())
        }
        other => other,
    }
}

fn assert_is_error(result: &Result<(), String>, reason: &str) {
    match result {
        Err(got) => assert_eq!(got, reason),
        Ok(()) => panic!("{reason} was classified as a caught plant"),
    }
}

fn apply_guard(
    dir: &Path,
    before: &[u8],
    after: &[u8],
    body: Result<(), String>,
) -> Result<(), String> {
    finish_plant(dir, before, after)?;
    body
}

fn apply_guard_omit_cleanup(
    dir: &Path,
    before: &[u8],
    after: &[u8],
    body: Result<(), String>,
) -> Result<(), String> {
    finish_omit_cleanup(dir, before, after)?;
    body
}

fn apply_guard_bypass_bytes(
    dir: &Path,
    before: &[u8],
    after: &[u8],
    body: Result<(), String>,
) -> Result<(), String> {
    finish_bypass_bytes(dir, before, after)?;
    body
}

fn finish_plant(dir: &Path, before: &[u8], after: &[u8]) -> Result<(), String> {
    if dir.exists() {
        fs::remove_dir_all(dir).map_err(|err| format!("temp directory remains: {err}"))?;
    }
    if dir.exists() {
        return Err(format!("temp directory remains: {}", dir.display()));
    }
    if before != after {
        return Err("live bytes changed".into());
    }
    Ok(())
}

fn finish_omit_cleanup(dir: &Path, before: &[u8], after: &[u8]) -> Result<(), String> {
    let _ = dir;
    if before != after {
        return Err("live bytes changed".into());
    }
    Ok(())
}

fn finish_bypass_bytes(dir: &Path, before: &[u8], after: &[u8]) -> Result<(), String> {
    let _ = (before, after);
    if dir.exists() {
        fs::remove_dir_all(dir).map_err(|err| format!("temp directory remains: {err}"))?;
    }
    Ok(())
}

fn assert_byte_change_is_error(result: &Result<(), String>) {
    let err = result
        .as_ref()
        .expect_err("a live byte change must be an error");
    assert!(err.contains("live bytes"), "{err}");
}

fn real_lockfile_failure() -> Step {
    let dir = isolated_temp("lockfile");
    let _hold = TempCopy { dir: dir.clone() };
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
    let dir = isolated_temp("compile");
    let _hold = TempCopy { dir: dir.clone() };
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

fn compile_fault_args(manifest: &Path) -> Vec<String> {
    vec![
        "test".into(),
        "--offline".into(),
        "--locked".into(),
        "--manifest-path".into(),
        manifest.display().to_string(),
    ]
}

fn lockfile_args(manifest: &Path) -> Vec<String> {
    vec![
        "generate-lockfile".into(),
        "--offline".into(),
        "--manifest-path".into(),
        manifest.display().to_string(),
    ]
}

fn test_args(manifest: &Path) -> Vec<String> {
    vec![
        "test".into(),
        "--offline".into(),
        "--locked".into(),
        "--manifest-path".into(),
        manifest.display().to_string(),
        "--test".into(),
        "redteam_func_import".into(),
        "--".into(),
        "--exact".into(),
        "func_import_is_refused".into(),
    ]
}

fn run_cargo(args: &[String], target_dir: &Path, timeout: Duration) -> CommandOutput {
    let mut command = Command::new("cargo");
    command.args(args);
    command.env("CARGO_NET_OFFLINE", "true");
    command.env("CARGO_TARGET_DIR", target_dir);
    command.env("CARGO_TERM_COLOR", "never");
    if let Some(parent) = manifest_parent(args) {
        if parent.exists() {
            command.current_dir(parent);
        }
    }
    run_command(command, timeout)
}

fn manifest_parent(args: &[String]) -> Option<&Path> {
    let index = args.iter().position(|arg| arg == "--manifest-path")?;
    Path::new(args.get(index + 1)?).parent()
}

fn run_command(mut command: Command, timeout: Duration) -> CommandOutput {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            return CommandOutput {
                exit_code: None,
                output: err.to_string(),
                timed_out: false,
                spawn_error: true,
            };
        }
    };
    let mut stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let out_thread = thread::spawn(move || read_all(&mut stdout));
    let err_thread = thread::spawn(move || read_all(&mut stderr));
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if started.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(());
            }
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                let stdout = out_thread.join().unwrap_or_default();
                let stderr = err_thread.join().unwrap_or_default();
                return CommandOutput {
                    exit_code: None,
                    output: format!("{err}\n{}", combine(&stdout, &stderr)),
                    timed_out: false,
                    spawn_error: true,
                };
            }
        }
    };
    let stdout = out_thread.join().unwrap_or_default();
    let stderr = err_thread.join().unwrap_or_default();
    match status {
        Err(()) => CommandOutput {
            exit_code: None,
            output: combine(&stdout, &stderr),
            timed_out: true,
            spawn_error: false,
        },
        Ok(status) => CommandOutput {
            exit_code: status.code(),
            output: combine(&stdout, &stderr),
            timed_out: false,
            spawn_error: false,
        },
    }
}

fn read_all(reader: &mut dyn Read) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = reader.read_to_end(&mut buf);
    buf
}

fn combine(stdout: &[u8], stderr: &[u8]) -> String {
    let mut text = String::from_utf8_lossy(stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(stderr));
    text
}

fn tail(text: &str) -> String {
    let start = text.len().saturating_sub(4000);
    text[start..].to_string()
}

fn redteam_test_source() -> String {
    format!(
        r#"#[test]
fn func_import_is_refused() {{
    let wasm = wat::parse_str({fixture:?}).unwrap();
    wasm_capsule_audit::audit_component(&wasm, &[]).expect_err("must refuse");
}}
"#,
        fixture = FUNC_IMPORT,
    )
}

fn copy_audit(dest: &Path) -> Result<(), String> {
    fs::create_dir_all(dest).map_err(|err| err.to_string())?;
    copy_file(&audit_root().join("Cargo.toml"), &dest.join("Cargo.toml"))?;
    copy_dir(&audit_root().join("src"), &dest.join("src"))?;
    copy_dir(&audit_root().join("tests"), &dest.join("tests"))?;
    if dest.join("target").exists() {
        return Err("copied target/".into());
    }
    Ok(())
}

fn copy_dir(from: &Path, to: &Path) -> Result<(), String> {
    fs::create_dir_all(to).map_err(|err| err.to_string())?;
    for entry in fs::read_dir(from).map_err(|err| err.to_string())? {
        let entry = entry.map_err(|err| err.to_string())?;
        if entry.file_name() == "target" {
            continue;
        }
        let dest = to.join(entry.file_name());
        let kind = entry.file_type().map_err(|err| err.to_string())?;
        if kind.is_symlink() {
            return Err(format!(
                "refusing to copy symlink {}",
                entry.path().display()
            ));
        }
        if kind.is_dir() {
            copy_dir(&entry.path(), &dest)?;
        } else if kind.is_file() {
            copy_file(&entry.path(), &dest)?;
        }
    }
    Ok(())
}

fn copy_file(from: &Path, to: &Path) -> Result<(), String> {
    fs::copy(from, to)
        .map(|_| ())
        .map_err(|err| err.to_string())
}

struct TempCopy {
    dir: PathBuf,
}

impl Drop for TempCopy {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn plant_dir() -> PathBuf {
    let dir = isolated_temp("plant");
    assert_parents_have_no_manifest(&dir);
    dir
}

fn isolated_temp(label: &str) -> PathBuf {
    static COUNT: AtomicU64 = AtomicU64::new(0);
    let n = COUNT.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "redteam-func-{label}-{}-{nanos}-{n}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("temp dir");
    assert_parents_have_no_manifest(&dir);
    dir
}

fn assert_parents_have_no_manifest(dir: &Path) {
    let mut parent = dir.parent();
    while let Some(dir) = parent {
        let manifest = dir.join("Cargo.toml");
        assert!(
            !manifest.exists(),
            "parent has Cargo.toml: {}",
            manifest.display()
        );
        parent = dir.parent();
    }
}

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("lab")
        .parent()
        .expect("repository root")
}

fn audit_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../wasm-capsule/audit")
}

fn audit_lib() -> PathBuf {
    audit_root().join("src/lib.rs")
}

fn finding_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("findings")
        .join(FINDING_FILE)
}

fn git_log_args() -> [&'static str; 6] {
    ["log", "-1", "--format=%H", "HEAD", "--", LIVE_LIB_REL]
}

fn git_commit() -> String {
    let output = Command::new("git")
        .args(git_log_args())
        .current_dir(repo_root())
        .output()
        .expect("git log");
    assert!(
        output.status.success(),
        "git log failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let commit = String::from_utf8(output.stdout)
        .expect("git log utf-8")
        .trim()
        .to_string();
    assert_eq!(commit.len(), 40, "{commit}");
    assert!(commit.chars().all(|c| c.is_ascii_hexdigit()), "{commit}");
    commit
}

fn sha256_file(path: &Path) -> String {
    let output = Command::new("shasum")
        .args(["-a", "256"])
        .arg(path)
        .output()
        .expect("shasum");
    assert!(
        output.status.success(),
        "shasum failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).expect("shasum utf-8");
    let digest = text.split_whitespace().next().expect("shasum digest");
    assert_eq!(digest.len(), 64, "{digest}");
    assert!(digest.chars().all(|c| c.is_ascii_hexdigit()), "{digest}");
    digest.to_string()
}
