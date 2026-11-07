//! B4, did leg: the real provider under a Landlock ruleset built from its
//! declared rights. A lab launcher, not the Runtime; files only (see CONFINEMENT.md).
#![cfg(target_os = "linux")]

use serde_json::{json, Value};
use std::ffi::{c_int, c_long};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
    fn prctl(option: c_int, ...) -> c_int;
}
const SYS_CREATE: c_long = 444;
const SYS_ADD_RULE: c_long = 445;
const SYS_RESTRICT: c_long = 446;
const PR_SET_NO_NEW_PRIVS: c_int = 38;
const EXECUTE: u64 = 1;
const READ_FILE: u64 = 1 << 2;
/// Every file right of ABI 3, the oldest ABI that can express the storage row.
const ABI3_RIGHTS: u64 = (1 << 15) - 1;
const IOCTL_DEV: u64 = 1 << 15;
/// execve opens the file with both rights, so the binary stays readable here.
const RUN: u64 = READ_FILE | EXECUTE;
/// READ_FILE, WRITE_FILE, READ_DIR, REMOVE_DIR, REMOVE_FILE, MAKE_DIR, MAKE_REG, TRUNCATE.
const STORE: u64 = 0b100_0001_1011_1110;
const BINARY: &str = env!("CARGO_BIN_EXE_did-provider");
const RIGHTS: &str = include_str!("fixtures/confine/declared-rights.json");

type Row = (PathBuf, u64);

fn handled_rights(abi: i64) -> Result<u64, String> {
    match abi {
        3.. => Ok(ABI3_RIGHTS | if abi >= 5 { IOCTL_DEV } else { 0 }),
        _ => Err(format!(
            "refused: Landlock ABI {abi} cannot express the storage row"
        )),
    }
}

/// Maps each declared rule to its row. A rule with no mapping refuses the launch.
fn declared_rows(rights: &Value, root: &Path, exe: &Path) -> Result<Vec<Row>, String> {
    let mut rows = Vec::new();
    for right in rights["rights"].as_array().ok_or("no rights list")? {
        for rule in right["rules"].as_array().ok_or("right with no rules")? {
            match rule.as_str().unwrap_or_default() {
                r#"(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))"# => {
                    rows.push((root.to_path_buf(), STORE))
                }
                r#"(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))"# => {
                    rows.push((exe.to_path_buf(), RUN))
                }
                // Landlock rules cover a whole tree, so one on the parent would
                // grant every sibling; stat needs no Landlock right.
                r#"(allow file-read* (literal (param "STORAGE_PARENT")))"# => {}
                other => return Err(format!("refused: no Linux row for {other}")),
            }
        }
    }
    Ok(rows)
}

/// A named departure, not a right: this dynamic build needs its loader. execve opens the
/// interpreter, so it needs RUN; libraries are read and mapped, which Landlock does not gate.
fn loader_rows(exe: &Path) -> Vec<Row> {
    let out = Command::new("ldd").arg(exe).output().expect("ldd must run");
    assert!(out.status.success(), "ldd refused {}", exe.display());
    let text = String::from_utf8(out.stdout).expect("ldd output");
    let row = |line: &'_ str| -> Option<Row> {
        let (file, rights) = match line.split_once("=> ") {
            Some((_, library)) => (library, READ_FILE),
            None => (line.trim_start(), RUN),
        };
        let file = file
            .split(' ')
            .next()
            .filter(|file| file.starts_with('/'))?;
        Some((PathBuf::from(file), rights))
    };
    text.lines().filter_map(row).collect()
}

fn rows_for(base: &Path) -> Vec<Row> {
    let rights = serde_json::from_str(RIGHTS).expect("declared rights");
    let exe = fs::canonicalize(BINARY).expect("provider binary");
    let mut rows = declared_rows(&rights, &base.join("did"), &exe).expect("declared rows");
    rows.extend(loader_rows(&exe));
    rows
}

fn ruleset(rows: &[Row]) -> OwnedFd {
    let abi = unsafe { syscall(SYS_CREATE, std::ptr::null::<u64>(), 0usize, 1u32) };
    let handled = handled_rights(abi).unwrap_or_else(|refusal| panic!("{refusal}"));
    let fd = unsafe { syscall(SYS_CREATE, &handled as *const u64, 8usize, 0u32) };
    assert!(fd >= 0, "creating the ruleset failed");
    // SAFETY: the kernel just returned this descriptor, close-on-exec, and nothing else owns it.
    let fd = unsafe { OwnedFd::from_raw_fd(fd as c_int) };
    for (path, allowed) in rows {
        let target = File::open(path).expect("a row's path must open");
        #[repr(C, packed)]
        #[allow(dead_code)] // read by the kernel
        struct PathBeneath(u64, c_int);
        let rule = PathBeneath(*allowed, target.as_raw_fd());
        let added = unsafe { syscall(SYS_ADD_RULE, fd.as_raw_fd(), 1u32, &rule as *const _, 0u32) };
        assert_eq!(added, 0, "adding the row for {} failed", path.display());
    }
    fd
}

struct Provider(Child, ChildStdin, BufReader<ChildStdout>);

impl Provider {
    /// A failed install stops the spawn.
    fn spawn(program: &Path, rows: &[Row]) -> std::io::Result<Self> {
        let mut command = Command::new(program);
        command.stdin(Stdio::piped()).stdout(Stdio::piped());
        let fd = ruleset(rows);
        // SAFETY: the closure makes only two async-signal-safe system calls.
        unsafe {
            command.pre_exec(move || {
                if prctl(PR_SET_NO_NEW_PRIVS, 1u64, 0u64, 0u64, 0u64) != 0
                    || syscall(SYS_RESTRICT, fd.as_raw_fd(), 0u32) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn()?;
        let (stdin, stdout) = (child.stdin.take().unwrap(), child.stdout.take().unwrap());
        Ok(Self(child, stdin, BufReader::new(stdout)))
    }

    fn started(base: &Path, rows: &[Row]) -> Self {
        fs::create_dir_all(base.join("did")).expect("storage root");
        let mut provider = Self::spawn(Path::new(BINARY), rows).expect("the launch must succeed");
        let config = json!({ "base_path": base, "encryption_key": hex::encode([0x42u8; 32]) });
        provider.ok(json!({ "op": "init", "config": config }));
        provider
    }

    fn send(&mut self, request: Value) -> Value {
        writeln!(self.1, "{request}").expect("request");
        let mut line = String::new();
        self.2.read_line(&mut line).expect("answer");
        serde_json::from_str(&line).unwrap_or_else(|err| panic!("{request} -> {line:?}: {err}"))
    }

    fn ok(&mut self, request: Value) -> Value {
        let answer = self.send(request);
        assert_eq!(answer["status"], "ok", "{answer}");
        answer["data"].clone()
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn linux_set_nickname_is_served_and_kept_under_landlock() {
    let fixture = tempfile::tempdir().expect("fixture");
    let base = fs::canonicalize(fixture.path()).expect("base");
    let rows = rows_for(&base);
    let mut provider = Provider::started(&base, &rows);
    let did = provider.ok(json!({ "op": "get_did" }));
    assert!(did["did"].as_str().unwrap().starts_with("did:key:"));
    provider.ok(json!({ "op": "set_nickname", "nickname": "Allowed" }));
    assert!(base.join("did/nickname.enc").is_file());
    // A second launch can only answer by reading the file back under the ruleset.
    let mut again = Provider::started(&base, &rows);
    let nickname = again.ok(json!({ "op": "get_nickname" }));
    assert_eq!(nickname["nickname"], "Allowed");
}

#[test]
fn launch_refuses_what_landlock_cannot_express() {
    for abi in [-1, 0, 1, 2] {
        assert!(handled_rights(abi).is_err(), "ABI {abi}");
    }
    assert_eq!(handled_rights(4), Ok(ABI3_RIGHTS));
    assert_eq!(handled_rights(5), Ok(ABI3_RIGHTS | IOCTL_DEV));
    let rights = json!({ "rights": [{ "rules": ["(allow network*)"] }] });
    let refused = declared_rows(&rights, Path::new("/r"), Path::new("/e")).unwrap_err();
    assert_eq!(refused, "refused: no Linux row for (allow network*)");
}

#[test]
fn only_the_interpreter_among_the_loader_files_may_execute() {
    let rows = loader_rows(Path::new(BINARY));
    let executable = rows.iter().filter(|row| row.1 & EXECUTE != 0).count();
    assert_eq!(executable, 1, "{rows:?}");
}
