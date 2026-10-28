#![allow(dead_code)]
// One plant runner. Import probes load this file with `#[path = "support.rs"]`.
// Cargo also builds this path as its own test target.

use std::fs;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const ANCHOR: &str = "interfaces.push(import.name.name.to_owned());";
pub const CORE_ANCHOR: &str = "                imports.push(DeclaredImport {\n                    module: import.module.to_owned(),\n                    name: import.name.to_owned(),\n                });";
pub const SKIP_MARK: &str = "does not cover that plant";
pub const LIVE_LIB_REL: &str = "lab/wasm-capsule/audit/src/lib.rs";
pub const FUNC_FINDING_ID: &str = "cx-wasm-audit-001";
pub const FUNC_FINDING_FILE: &str = "cx-wasm-audit-001.md";
pub const MODULE_FINDING_ID: &str = "cx-wasm-audit-002";
pub const MODULE_FINDING_FILE: &str = "cx-wasm-audit-002.md";
pub const TYPE_FINDING_ID: &str = "cx-wasm-audit-003";
pub const TYPE_FINDING_FILE: &str = "cx-wasm-audit-003.md";
pub const COMPONENT_FINDING_ID: &str = "cx-wasm-audit-004";
pub const COMPONENT_FINDING_FILE: &str = "cx-wasm-audit-004.md";
pub const GLOBAL_FINDING_ID: &str = "cx-wasm-audit-005";
pub const GLOBAL_FINDING_FILE: &str = "cx-wasm-audit-005.md";
pub const TABLE_FINDING_ID: &str = "cx-wasm-audit-006";
pub const TABLE_FINDING_FILE: &str = "cx-wasm-audit-006.md";
pub const MUST_REFUSE: &str = "must refuse";
pub const COULD_NOT_COMPILE: &str = "could not compile";
pub const LOCKFILE_ERROR: &str = "lockfile failed";
pub const COMPILE_ERROR: &str = "compile failed";
pub const LAUNCH_ERROR: &str = "launch failed";
pub const TIMEOUT_ERROR: &str = "timeout";
pub const PLANT_TIMEOUT: Duration = Duration::from_secs(360);
pub const OUTPUT_LIMIT: usize = 1024 * 1024;
pub const TAIL_BYTES: usize = 4000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plant {
    Source(String),
    Skip(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Report {
    Passed,
    Skipped(String),
}

#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub exit_code: Option<i32>,
    pub output: String,
    pub timed_out: bool,
    pub spawn_error: bool,
}

#[derive(Debug, Clone)]
pub enum Step {
    Lockfile(CommandOutput),
    Test(CommandOutput),
}

pub struct PlantedProbe {
    pub anchor: &'static str,
    pub replacement: String,
    pub assert_shape: fn(&str, &str),
    pub test_file: &'static str,
    pub test_source: String,
    pub test_binary: &'static str,
    pub exact_test: &'static str,
}

pub struct TempCopy {
    pub dir: PathBuf,
}

impl Drop for TempCopy {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

pub fn plant_at(source: &str, anchor: &str, replacement: &str) -> Plant {
    let count = source.matches(anchor).count();
    if count != 1 {
        return Plant::Skip(format!(
            "{LIVE_LIB_REL} holds {count} copies of the anchor, not one. This run {SKIP_MARK}."
        ));
    }
    Plant::Source(source.replacen(anchor, replacement, 1))
}

pub fn plant_edit(source: &str, replacement: &str) -> Plant {
    plant_at(source, ANCHOR, replacement)
}

pub fn type_skip_replacement(type_name: &str) -> String {
    format!(
        "if matches!(import.ty, wasmparser::ComponentTypeRef::{type_name}(_)) {{\n                    continue;\n                }}\n                {ANCHOR}"
    )
}

pub fn assert_type_skip_shape(original: &str, planted: &str, type_name: &str) {
    let replacement = type_skip_replacement(type_name);
    assert_eq!(original.matches(ANCHOR).count(), 1);
    assert_eq!(planted.matches(ANCHOR).count(), 1);
    let needle = format!("wasmparser::ComponentTypeRef::{type_name}(_)");
    let type_at = planted.find(&needle).expect("type skip");
    let continue_at = planted.find("continue").expect("continue");
    let push_at = planted.find(ANCHOR).expect("push");
    assert!(type_at < continue_at && continue_at < push_at);
    assert_eq!(planted.replacen(&replacement, ANCHOR, 1), original);
}

pub fn core_skip_replacement(type_name: &str) -> String {
    format!(
        "                if matches!(import.ty, wasmparser::TypeRef::{type_name}(_)) {{\n                    continue;\n                }}\n{CORE_ANCHOR}"
    )
}

pub fn assert_core_skip_shape(original: &str, planted: &str, type_name: &str) {
    let replacement = core_skip_replacement(type_name);
    assert_eq!(original.matches(CORE_ANCHOR).count(), 1);
    assert_eq!(planted.matches(CORE_ANCHOR).count(), 1);
    let needle = format!("wasmparser::TypeRef::{type_name}(_)");
    let type_at = planted.find(&needle).expect("type skip");
    let continue_at = planted.find("continue").expect("continue");
    let push_at = planted.find(CORE_ANCHOR).expect("push");
    assert!(type_at < continue_at && continue_at < push_at);
    assert_eq!(planted.replacen(&replacement, CORE_ANCHOR, 1), original);
}

pub fn report_plant(plant: &Plant) -> Report {
    match plant {
        Plant::Skip(reason) => Report::Skipped(format!("SKIPPED: {reason}")),
        Plant::Source(_) => Report::Passed,
    }
}

pub fn falsifier_reports_skip_as_pass(plant: &Plant) -> Report {
    let _ = plant;
    Report::Passed
}

pub fn assert_skip_report(report: &Report) {
    match report {
        Report::Skipped(text) => {
            assert!(text.starts_with("SKIPPED: "), "{text}");
            assert!(text.contains(SKIP_MARK), "{text}");
        }
        Report::Passed => panic!("a skipped plant was reported as passed"),
    }
}

pub fn refusal_test_source(test_name: &str, fixture: &str) -> String {
    format!(
        r#"#[test]
fn {test_name}() {{
    let wasm = wat::parse_str({fixture:?}).unwrap();
    wasm_capsule_audit::audit_component(&wasm, &[]).expect_err("must refuse");
}}
"#
    )
}

pub fn core_refusal_test_source(test_name: &str, fixture: &str) -> String {
    format!(
        r#"#[test]
fn {test_name}() {{
    let wasm = wat::parse_str({fixture:?}).unwrap();
    wasm_capsule_audit::audit(&wasm, &[]).expect_err("must refuse");
}}
"#
    )
}

pub fn run_skipped_plant(probe: &PlantedProbe) {
    let live = audit_lib();
    let before = fs::read(&live).expect("read live audit");
    let run = catch_unwind(AssertUnwindSafe(|| execute_plant(&live, &before, probe)));
    let after = fs::read(&live).expect("reread live audit");
    assert_eq!(before, after, "live src/lib.rs bytes changed");
    let (dir, result) = match run {
        Ok(value) => value,
        Err(payload) => resume_unwind(payload),
    };
    assert!(!dir.exists(), "temp directory remains: {}", dir.display());
    result.expect("caught plant");
}

fn execute_plant(
    live: &Path,
    before: &[u8],
    probe: &PlantedProbe,
) -> (PathBuf, Result<(), String>) {
    // The guard is held before creation. A parent-manifest refusal returns
    // here, and Drop removes a directory if one was created.
    let (hold, created) = open_owned(&std::env::temp_dir(), "plant");
    let dir = hold.dir.clone();
    if let Err(reason) = created {
        return (dir, Err(reason));
    }
    let body = plant_body(&dir, before, probe);
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

fn plant_body(dir: &Path, before: &[u8], probe: &PlantedProbe) -> Result<(), String> {
    let source =
        std::str::from_utf8(before).map_err(|err| format!("audit source is not utf-8: {err}"))?;
    match plant_at(source, probe.anchor, &probe.replacement) {
        Plant::Skip(reason) => refuse_silent_pass(&Plant::Skip(reason)),
        Plant::Source(planted) => {
            (probe.assert_shape)(source, &planted);
            run_cargo_plant(dir, &planted, probe)
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

fn run_cargo_plant(dir: &Path, planted: &str, probe: &PlantedProbe) -> Result<(), String> {
    assert_parents_have_no_manifest(dir);
    copy_audit(dir)?;
    fs::write(dir.join("src/lib.rs"), planted).map_err(|err| err.to_string())?;
    let generated = &probe.test_source;
    assert!(generated.contains("expect_err(\"must refuse\")"));
    assert!(!generated.contains("UndeclaredInterface"));
    fs::write(dir.join("tests").join(probe.test_file), generated).map_err(|err| err.to_string())?;
    if dir.join("target").exists() {
        return Err("copied target/".into());
    }
    let manifest = dir.join("Cargo.toml");
    let target = dir.join("target");
    let lockfile = run_cargo(&lockfile_args(&manifest), &target, PLANT_TIMEOUT);
    classify(&Step::Lockfile(lockfile))?;
    let test = run_cargo(
        &cargo_test_args(&manifest, probe.test_binary, probe.exact_test),
        &target,
        PLANT_TIMEOUT,
    );
    classify(&Step::Test(test))
}

pub fn classify(step: &Step) -> Result<(), String> {
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

pub fn classify_test(output: &CommandOutput) -> Result<(), String> {
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

pub fn falsifier_classifies_harness_error_as_caught(step: &Step) -> Result<(), String> {
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

pub fn assert_is_error(result: &Result<(), String>, reason: &str) {
    match result {
        Err(got) => assert_eq!(got, reason),
        Ok(()) => panic!("{reason} was classified as a caught plant"),
    }
}

pub fn apply_guard(
    dir: &Path,
    before: &[u8],
    after: &[u8],
    body: Result<(), String>,
) -> Result<(), String> {
    finish_plant(dir, before, after)?;
    body
}

pub fn apply_guard_omit_cleanup(
    dir: &Path,
    before: &[u8],
    after: &[u8],
    body: Result<(), String>,
) -> Result<(), String> {
    finish_omit_cleanup(dir, before, after)?;
    body
}

pub fn apply_guard_bypass_bytes(
    dir: &Path,
    before: &[u8],
    after: &[u8],
    body: Result<(), String>,
) -> Result<(), String> {
    finish_bypass_bytes(dir, before, after)?;
    body
}

pub fn finish_plant(dir: &Path, before: &[u8], after: &[u8]) -> Result<(), String> {
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

pub fn assert_byte_change_is_error(result: &Result<(), String>) {
    let err = result
        .as_ref()
        .expect_err("a live byte change must be an error");
    assert!(err.contains("live bytes"), "{err}");
}

pub fn lockfile_args(manifest: &Path) -> Vec<String> {
    vec![
        "generate-lockfile".into(),
        "--offline".into(),
        "--manifest-path".into(),
        manifest.display().to_string(),
    ]
}

pub fn cargo_test_args(manifest: &Path, test_binary: &str, exact_test: &str) -> Vec<String> {
    vec![
        "test".into(),
        "--offline".into(),
        "--locked".into(),
        "--manifest-path".into(),
        manifest.display().to_string(),
        "--test".into(),
        test_binary.into(),
        "--".into(),
        "--exact".into(),
        exact_test.into(),
    ]
}

pub fn run_cargo(args: &[String], target_dir: &Path, timeout: Duration) -> CommandOutput {
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

pub fn run_command(mut command: Command, timeout: Duration) -> CommandOutput {
    // Nonblocking sockets avoid reader threads that can outlive the timeout
    // when a descendant keeps stdout or stderr open.
    let (mut stdout_reader, stdout_writer) = UnixStream::pair().expect("stdout socket");
    let (mut stderr_reader, stderr_writer) = UnixStream::pair().expect("stderr socket");
    stdout_reader
        .set_nonblocking(true)
        .expect("stdout nonblocking");
    stderr_reader
        .set_nonblocking(true)
        .expect("stderr nonblocking");
    command
        .process_group(0)
        .stdout(Stdio::from(OwnedFd::from(stdout_writer)))
        .stderr(Stdio::from(OwnedFd::from(stderr_writer)));
    let started = Instant::now();
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
    // Command retains its configured descriptors after spawn.
    drop(command);
    let group = format!("-{}", child.id());
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut status = None;
    let result = (|| -> io::Result<bool> {
        loop {
            if started.elapsed() >= timeout {
                return Ok(true);
            }
            if status.is_none() {
                status = child.try_wait()?;
            }
            let collected = stdout.len() + stderr.len();
            let out_closed = read_available(&mut stdout_reader, &mut stdout)?;
            let err_closed = read_available(&mut stderr_reader, &mut stderr)?;
            if status.is_some() && out_closed && err_closed {
                return Ok(false);
            }
            if collected == stdout.len() + stderr.len() {
                thread::sleep(Duration::from_millis(5));
            }
        }
    })();
    // The group belongs to this invocation. Clean it on success, timeout and
    // read/wait errors, including when the direct child has already exited.
    let _ = Command::new("/bin/kill")
        .args(["-KILL", "--", &group])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = child.kill();
    let reaping = Instant::now();
    while matches!(child.try_wait(), Ok(None)) && reaping.elapsed() < Duration::from_millis(200) {
        thread::sleep(Duration::from_millis(5));
    }
    let output = combine(&stdout, &stderr);
    CommandOutput {
        exit_code: if matches!(result, Ok(false)) {
            status.and_then(|status| status.code())
        } else {
            None
        },
        timed_out: matches!(result, Ok(true)),
        spawn_error: result.is_err(),
        output: match result {
            Err(err) => format!("{err}\n{output}"),
            Ok(_) => output,
        },
    }
}

fn read_available(reader: &mut UnixStream, output: &mut Vec<u8>) -> io::Result<bool> {
    // One bounded read per stream keeps a busy writer from starving the
    // deadline check. A limit failure remains a harness error.
    let mut buf = [0; 16 * 1024];
    match reader.read(&mut buf) {
        Ok(0) => Ok(true),
        Ok(count) => {
            if output.len() + count > OUTPUT_LIMIT {
                return Err(io::Error::other("command output limit exceeded"));
            }
            output.extend_from_slice(&buf[..count]);
            Ok(false)
        }
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        Err(err) => Err(err),
    }
}

fn combine(stdout: &[u8], stderr: &[u8]) -> String {
    let mut text = String::from_utf8_lossy(stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(stderr));
    text
}

pub fn tail(text: &str) -> String {
    // The window is counted in bytes. It has to start on a character, or the
    // harness error panics instead of returning its reason.
    let start = text.floor_char_boundary(text.len().saturating_sub(TAIL_BYTES));
    text[start..].to_string()
}

pub fn falsifier_tail_splits_a_character(text: &str) -> String {
    let start = text.len().saturating_sub(TAIL_BYTES);
    text[start..].to_string()
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

pub fn copy_file(from: &Path, to: &Path) -> Result<(), String> {
    fs::copy(from, to)
        .map(|_| ())
        .map_err(|err| err.to_string())
}

pub fn isolated_temp(label: &str) -> TempCopy {
    match open_owned(&std::env::temp_dir(), label) {
        (hold, Ok(())) => hold,
        (_hold, Err(reason)) => panic!("{reason}"),
    }
}

pub fn open_owned(root: &Path, label: &str) -> (TempCopy, Result<(), String>) {
    let dir = temp_candidate(root, label);
    // Own the path before creation so a refusal cannot leave the directory.
    let hold = TempCopy { dir: dir.clone() };
    (hold, create_isolated_dir(&dir))
}

fn create_isolated_dir(dir: &Path) -> Result<(), String> {
    if let Some(manifest) = parent_manifest(dir) {
        return Err(format!("parent has Cargo.toml: {}", manifest.display()));
    }
    fs::create_dir_all(dir).map_err(|err| format!("temp dir: {err}"))
}

pub fn falsifier_create_isolated_dir(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|err| format!("temp dir: {err}"))?;
    if let Some(manifest) = parent_manifest(dir) {
        return Err(format!("parent has Cargo.toml: {}", manifest.display()));
    }
    Ok(())
}

fn temp_candidate(root: &Path, label: &str) -> PathBuf {
    static COUNT: AtomicU64 = AtomicU64::new(0);
    let n = COUNT.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    root.join(format!(
        "redteam-func-{label}-{}-{nanos}-{n}",
        std::process::id()
    ))
}

fn parent_manifest(dir: &Path) -> Option<PathBuf> {
    let mut parent = dir.parent();
    while let Some(current) = parent {
        let manifest = current.join("Cargo.toml");
        if manifest.exists() {
            return Some(manifest);
        }
        parent = current.parent();
    }
    None
}

fn assert_parents_have_no_manifest(dir: &Path) {
    if let Some(manifest) = parent_manifest(dir) {
        panic!("parent has Cargo.toml: {}", manifest.display());
    }
}

pub fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("lab")
        .parent()
        .expect("repository root")
}

pub fn audit_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../wasm-capsule/audit")
}

pub fn audit_lib() -> PathBuf {
    audit_root().join("src/lib.rs")
}

pub fn finding_path(file_name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("findings")
        .join(file_name)
}

pub fn git_log_args() -> [&'static str; 6] {
    ["log", "-1", "--format=%H", "HEAD", "--", LIVE_LIB_REL]
}

pub fn git_commit() -> String {
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

pub fn sha256_file(path: &Path) -> String {
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

pub fn attribution(finding_id: &str, commit: &str, digest: &str) -> String {
    format!("{finding_id} {commit} sha256 {digest}")
}

pub fn read_live_attribution(finding_id: &str) -> String {
    attribution(finding_id, &git_commit(), &sha256_file(&audit_lib()))
}

pub fn assert_live_attribution(line: &str, finding_id: &str, commit: &str, digest: &str) {
    assert_eq!(line, attribution(finding_id, commit, digest));
    assert!(line.contains(commit), "{line}");
    assert!(line.contains(digest), "{line}");
}

pub fn accept_detail(kind: &str, fixture: &str) -> String {
    // Core module imports are globals and tables. Component kinds keep the
    // component label; a blanket word would misidentify one of the two.
    let world = match kind {
        "global" | "table" => "core",
        _ => "component",
    };
    format!("accepted an undeclared {world} {kind} import\nfixture: {fixture}\ndeclarations: empty")
}

pub fn record_outcome(
    accepted: bool,
    finding: &Path,
    attribution: &str,
    detail: &str,
) -> Result<(), String> {
    if !accepted {
        return Ok(());
    }
    if let Some(parent) = finding.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let body = format!("{attribution}\n\n{detail}\n");
    fs::write(finding, body).map_err(|err| err.to_string())
}

pub fn falsifier_writes_after_refusal(
    finding: &Path,
    attribution: &str,
    detail: &str,
) -> Result<(), String> {
    record_outcome(true, finding, attribution, detail)
}

pub fn assert_no_finding(path: &Path) {
    assert!(
        !path.exists(),
        "wrote a finding after a refusal: {}",
        path.display()
    );
}
