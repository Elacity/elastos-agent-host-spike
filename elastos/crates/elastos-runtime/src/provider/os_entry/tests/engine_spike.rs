//! Measurements for the checked engine launch. This file is test-only.
//! It does not change how a provider or an engine is started.

use std::io::{Read, Write};
#[cfg(target_os = "macos")]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Child;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::super::super::checked_executable::CheckedExecutable;

#[cfg(target_os = "macos")]
const DIRECT_LIBS: &[&str] = &[
    "libllama-server-impl.dylib",
    "libllama-common.0.dylib",
    "libmtmd.0.dylib",
    "libllama.0.dylib",
    "libggml.0.dylib",
    "libggml-cpu.0.dylib",
    "libggml-blas.0.dylib",
    "libggml-metal.0.dylib",
    "libggml-rpc.0.dylib",
    "libggml-base.0.dylib",
];

fn engine_env() -> Option<(PathBuf, PathBuf, PathBuf)> {
    let server = std::env::var("ELASTOS_TEST_LLAMA_SERVER").ok()?;
    let libs = std::env::var("ELASTOS_TEST_LLAMA_LIBS").ok()?;
    let gguf = std::env::var("ELASTOS_TEST_GGUF").ok()?;
    if server.is_empty() || libs.is_empty() || gguf.is_empty() {
        return None;
    }
    let server = PathBuf::from(server);
    let server = if server.is_dir() {
        server.join("llama-server")
    } else {
        server
    };
    Some((
        std::fs::canonicalize(&server).unwrap_or_else(|_| panic!("server {}", server.display())),
        std::fs::canonicalize(&libs).unwrap_or_else(|_| panic!("libs {libs}")),
        std::fs::canonicalize(&gguf).unwrap_or_else(|_| panic!("gguf {gguf}")),
    ))
}

fn sha256_hex(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path).unwrap();
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    format!("{:x}", hasher.finalize())
}

fn compile_helper(dir: &Path, name: &str, source: &str) -> PathBuf {
    let source_path = dir.join(format!("{name}.c"));
    let binary = dir.join(name);
    std::fs::write(&source_path, source).unwrap();
    let status = Command::new("/usr/bin/cc")
        .args(["-O2", "-Wall", "-Wextra", "-o"])
        .arg(&binary)
        .arg(&source_path)
        .status()
        .unwrap();
    assert!(status.success(), "compile {name}");
    binary
}

fn process_view(pid: i32) -> (String, Option<i32>) {
    let output = Command::new("/bin/ps")
        .args(["-o", "stat=,ppid=", "-p", &pid.to_string()])
        .output();
    let Ok(output) = output else {
        return ("gone".into(), None);
    };
    if !output.status.success() {
        return ("gone".into(), None);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut parts = text.split_whitespace();
    let Some(stat) = parts.next() else {
        return ("gone".into(), None);
    };
    let ppid = parts.next().and_then(|value| value.parse().ok());
    (stat.to_string(), ppid)
}

fn running(stat: &str) -> bool {
    matches!(stat.chars().next(), Some('R' | 'S' | 'U' | 'I'))
}

struct Reap(Vec<i32>);

impl Drop for Reap {
    fn drop(&mut self) {
        for pid in &self.0 {
            unsafe {
                libc::kill(*pid, libc::SIGKILL);
            }
        }
    }
}

fn wait_pidfile(path: &Path) -> i32 {
    let start = Instant::now();
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Ok(pid) = text.trim().parse::<i32>() {
                if pid > 0 {
                    return pid;
                }
            }
        }
        if start.elapsed() > Duration::from_secs(5) {
            panic!("no pid in {}", path.display());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

const PARENT_PLAIN: &str = r#"
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
    (void)argc;
    alarm(30);
    pid_t engine = fork();
    if (engine == 0) {
        execv(argv[2], &argv[2]);
        _exit(127);
    }
    FILE *file = fopen(argv[1], "w");
    if (file == 0) _exit(2);
    fprintf(file, "%d\n", (int)engine);
    fclose(file);
    for (;;) pause();
}
"#;

const WATCHER: &str = r#"
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc, char **argv) {
    (void)argc;
    alarm(30);
    pid_t engine = fork();
    if (engine == 0) {
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) dup2(devnull, 0);
        execv(argv[2], &argv[2]);
        _exit(127);
    }
    FILE *file = fopen(argv[1], "w");
    if (file == 0) _exit(2);
    fprintf(file, "%d\n", (int)engine);
    fclose(file);
    char buffer[64];
    while (read(0, buffer, sizeof buffer) > 0) {}
    kill(engine, SIGTERM);
    int status = 0;
    for (;;) {
        pid_t got = waitpid(engine, &status, WNOHANG);
        if (got == engine || got < 0) _exit(0);
        usleep(5000);
    }
}
"#;

const PROVIDER: &str = r#"
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
    (void)argc;
    alarm(30);
    int pipes[2];
    if (pipe(pipes) != 0) _exit(2);
    pid_t watcher = fork();
    if (watcher == 0) {
        close(pipes[1]);
        if (dup2(pipes[0], 0) < 0) _exit(3);
        if (pipes[0] != 0) close(pipes[0]);
        execv(argv[2], &argv[2]);
        _exit(127);
    }
    close(pipes[0]);
    for (;;) pause();
}
"#;

fn helpers(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    (
        compile_helper(dir, "parent-plain", PARENT_PLAIN),
        compile_helper(dir, "watcher", WATCHER),
        compile_helper(dir, "provider-hold", PROVIDER),
    )
}

fn argv_c(argv: &[std::ffi::OsString]) -> Vec<std::ffi::OsString> {
    argv.to_vec()
}

/// Parent SIGKILL with no death signal and no watcher.
fn plain_orphan(dir: &Path, engine: &[std::ffi::OsString]) -> String {
    let (parent_bin, _, _) = helpers(dir);
    let pidfile = dir.join("plain.pid");
    let mut command = Command::new(&parent_bin);
    command.arg(&pidfile).arg(&engine[0]);
    for arg in &engine[1..] {
        command.arg(arg);
    }
    let mut parent = command.spawn().unwrap();
    let mut reap = Reap(vec![parent.id() as i32]);
    let engine_pid = wait_pidfile(&pidfile);
    reap.0.push(engine_pid);
    let (before, before_ppid) = process_view(engine_pid);
    let start = Instant::now();
    assert_eq!(unsafe { libc::kill(parent.id() as i32, libc::SIGKILL) }, 0);
    let _ = parent.wait();
    reap.0.retain(|pid| *pid != parent.id() as i32);
    let mut lines = vec![format!(
        "before stat={before} ppid={}",
        before_ppid.unwrap_or(-1)
    )];
    for mark in [0.1, 1.0, 5.0] {
        let left = Duration::from_secs_f64(mark).saturating_sub(start.elapsed());
        thread::sleep(left);
        let (stat, ppid) = process_view(engine_pid);
        lines.push(format!(
            "t={mark:.1}s stat={stat} ppid={} running={}",
            ppid.unwrap_or(-1),
            running(&stat)
        ));
    }
    let (stat, ppid) = process_view(engine_pid);
    assert!(
        running(&stat),
        "the engine stopped after the parent was killed: {lines:?}"
    );
    assert_ne!(
        ppid,
        Some(parent.id() as i32),
        "the engine still names the dead parent"
    );
    lines.push(format!(
        "orphan_after_5s stat={stat} ppid={}",
        ppid.unwrap_or(-1)
    ));
    drop(reap);
    lines.join("\n")
}

/// The watcher reads the parent's pipe and SIGTERMs the engine on EOF.
fn watcher_stops(dir: &Path, engine: &[std::ffi::OsString]) -> String {
    let (_, watcher_bin, provider_bin) = helpers(dir);
    let pidfile = dir.join("watch.pid");
    let mut watcher_argv = vec![
        std::ffi::OsString::from(watcher_bin),
        std::ffi::OsString::from(&pidfile),
    ];
    watcher_argv.extend(engine.iter().cloned());
    let mut command = Command::new(&provider_bin);
    command.arg(&pidfile);
    for arg in &watcher_argv {
        command.arg(arg);
    }
    let mut parent = command.spawn().unwrap();
    let mut reap = Reap(vec![parent.id() as i32]);
    let engine_pid = wait_pidfile(&pidfile);
    reap.0.push(engine_pid);
    thread::sleep(Duration::from_millis(100));
    let (before, before_ppid) = process_view(engine_pid);
    let start = Instant::now();
    assert_eq!(unsafe { libc::kill(parent.id() as i32, libc::SIGKILL) }, 0);
    let _ = parent.wait();
    let mut stopped = None;
    let mut last = String::new();
    while start.elapsed() < Duration::from_secs(2) {
        let (stat, ppid) = process_view(engine_pid);
        last = format!("stat={stat} ppid={}", ppid.unwrap_or(-1));
        if !running(&stat) {
            stopped = Some(start.elapsed());
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let stopped = stopped.unwrap_or_else(|| panic!("engine still running after 2s ({last})"));
    drop(reap);
    format!(
        "before stat={before} ppid={}\nstopped_after_ms={} ({last})",
        before_ppid.unwrap_or(-1),
        stopped.as_millis()
    )
}

#[test]
fn spike_parent_sigkill_leaves_the_engine() {
    let dir = tempfile::tempdir().unwrap();
    let engine = argv_c(&["/bin/sleep".into(), "120".into()]);
    let report = plain_orphan(dir.path(), &engine);
    println!("MEASURED plain-orphan\n{report}");
}

#[test]
fn spike_watching_reader_stops_the_engine() {
    let dir = tempfile::tempdir().unwrap();
    let engine = argv_c(&["/bin/sleep".into(), "120".into()]);
    let report = watcher_stops(dir.path(), &engine);
    println!("MEASURED watching-reader\n{report}");
}

#[cfg(target_os = "linux")]
const PDEATH_PARENT: &str = r#"
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>
int main(int argc, char **argv) {
    (void)argc;
    alarm(30);
    int race = argv[2][0] == 'r';
    pid_t engine = fork();
    if (engine == 0) {
        pid_t expected = getppid();
        if (race) sleep(2);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0) _exit(2);
        if (getppid() != expected) {
            raise(SIGKILL);
            _exit(3);
        }
        execv(argv[3], &argv[3]);
        _exit(127);
    }
    FILE *file = fopen(argv[1], "w");
    if (file == 0) _exit(2);
    fprintf(file, "%d\n", (int)engine);
    fclose(file);
    for (;;) pause();
}
"#;

#[cfg(target_os = "linux")]
#[test]
fn spike_linux_pdeathsig_preexec_kills_the_engine() {
    let dir = tempfile::tempdir().unwrap();
    let helper = compile_helper(dir.path(), "pdeath-parent", PDEATH_PARENT);
    let sleep = ["/bin/sleep", "120"];
    let armed = dir.path().join("armed.pid");
    let mut parent = Command::new(&helper)
        .arg(&armed)
        .arg("armed")
        .arg(sleep[0])
        .arg(sleep[1])
        .spawn()
        .unwrap();
    let engine = wait_pidfile(&armed);
    let mut reap = Reap(vec![parent.id() as i32, engine]);
    thread::sleep(Duration::from_millis(200));
    let (before, _) = process_view(engine);
    assert!(
        running(&before),
        "armed engine did not reach exec: {before}"
    );
    let start = Instant::now();
    assert_eq!(unsafe { libc::kill(parent.id() as i32, libc::SIGKILL) }, 0);
    let _ = parent.wait();
    let mut stopped = None;
    while start.elapsed() < Duration::from_secs(2) {
        let (stat, _) = process_view(engine);
        if !running(&stat) {
            stopped = Some((start.elapsed(), stat));
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let (elapsed, stat) = stopped.expect("pdeathsig left the engine running");
    println!(
        "MEASURED pdeathsig-armed stopped_after_ms={} stat={stat}",
        elapsed.as_millis()
    );
    drop(reap);

    let raced = dir.path().join("raced.pid");
    let mut parent = Command::new(&helper)
        .arg(&raced)
        .arg("race")
        .arg(sleep[0])
        .arg(sleep[1])
        .spawn()
        .unwrap();
    let engine = wait_pidfile(&raced);
    let reap = Reap(vec![parent.id() as i32, engine]);
    let start = Instant::now();
    assert_eq!(unsafe { libc::kill(parent.id() as i32, libc::SIGKILL) }, 0);
    let _ = parent.wait();
    let mut stopped = None;
    while start.elapsed() < Duration::from_secs(4) {
        let (stat, _) = process_view(engine);
        if !running(&stat) {
            stopped = Some((start.elapsed(), stat));
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let (elapsed, stat) = stopped.expect("parent-changed check left the engine running");
    println!(
        "MEASURED pdeathsig-race stopped_after_ms={} stat={stat}",
        elapsed.as_millis()
    );
    drop(reap);
}

#[cfg(target_os = "macos")]
fn metadata_lines(path: &Path) -> String {
    let mut lines = String::new();
    for ancestor in path.ancestors().skip(1) {
        let text = ancestor.to_str().expect("path");
        assert!(
            !text.contains(['"', '\\']),
            "profile path has a quote: {text}"
        );
        lines.push_str(&format!(
            "(allow file-read-metadata (literal \"{text}\"))\n"
        ));
    }
    lines
}

#[cfg(target_os = "macos")]
fn literal(path: &Path) -> String {
    let text = path.to_str().expect("path");
    assert!(!text.contains(['"', '\\']));
    text.to_string()
}

#[cfg(all(target_os = "macos", not(elastos_unsupported_os_check)))]
fn sandbox_version(binary: &Path, profile: &str) -> (i32, String) {
    let mut command = super::super::macos_sandbox_command(
        Path::new("/usr/bin/sandbox-exec"),
        profile,
        binary,
        &[],
        None,
        &[],
    )
    .unwrap_or_else(|error| panic!("sandbox command: {error}"));
    command.arg("--version");
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let (code, text) = finish_child(&mut child, Duration::from_secs(20));
    (code, text)
}

#[cfg(target_os = "macos")]
fn finish_child(child: &mut Child, limit: Duration) -> (i32, String) {
    let start = Instant::now();
    loop {
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            return (-1, "timeout".into());
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                if let Some(pipe) = child.stdout.as_mut() {
                    pipe.read_to_end(&mut stdout).ok();
                }
                if let Some(pipe) = child.stderr.as_mut() {
                    pipe.read_to_end(&mut stderr).ok();
                }
                let mut text = String::from_utf8_lossy(&stderr).into_owned();
                text.push_str(&String::from_utf8_lossy(&stdout));
                return (status.code().unwrap_or(-1), text);
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(error) => return (-1, error.to_string()),
        }
    }
}

#[cfg(target_os = "macos")]
fn plain_version(binary: &Path) -> (i32, String) {
    let mut child = Command::new(binary)
        .arg("--version")
        .env_clear()
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    finish_child(&mut child, Duration::from_secs(20))
}

#[cfg(target_os = "macos")]
fn version_profile(copy: &Path, copy_dir: bool, bundle: Option<&Path>) -> String {
    let copy = literal(copy);
    let mut profile = String::from("(version 1)\n(deny default)\n(deny network*)\n");
    profile.push_str(&format!("(allow process-exec (literal \"{copy}\"))\n"));
    profile.push_str("(allow process-fork)\n");
    profile.push_str(&format!("(allow file-read* (literal \"{copy}\"))\n"));
    if copy_dir {
        let dir = literal(Path::new(&copy).parent().unwrap());
        profile.push_str(&format!("(allow file-read* (subpath \"{dir}\"))\n"));
    }
    if let Some(bundle) = bundle {
        let bundle = literal(bundle);
        profile.push_str(&format!("(allow file-read* (subpath \"{bundle}\"))\n"));
    }
    profile.push_str("(allow file-read* (subpath \"/usr/lib\"))\n");
    profile.push_str("(allow file-read* (subpath \"/System/Library\"))\n");
    profile.push_str("(allow file-read-data (literal \"/\"))\n");
    profile.push_str("(allow sysctl-read)\n");
    profile.push_str("(allow file-read* file-write-data (literal \"/dev/null\"))\n");
    profile.push_str("(allow file-read* (literal \"/dev/urandom\"))\n");
    profile.push_str("(allow signal (target self))\n");
    profile.push_str(&metadata_lines(Path::new(&copy)));
    if let Some(bundle) = bundle {
        profile.push_str(&metadata_lines(bundle));
    }
    profile
}

#[cfg(target_os = "macos")]
fn home_copy(
    dir: &Path,
    binary: &Path,
    siblings: bool,
) -> super::super::super::checked_executable::PreparedExecutable {
    let checksum = format!("sha256:{}", sha256_hex(binary));
    let mut executable = CheckedExecutable::pinned(binary, &checksum)
        .unwrap()
        .with_home_data_dir(dir);
    if siblings {
        for name in DIRECT_LIBS {
            executable = executable.with_sibling(name);
        }
    }
    executable.verify_at_spawn().unwrap()
}

#[cfg(target_os = "macos")]
fn receipt_digest(bundle: &Path, name: &str) -> String {
    let receipt = std::fs::read(bundle.join(".elastos-engine.json")).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
    value["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["path"] == name)
        .unwrap_or_else(|| panic!("receipt has no {name}"))["sha256"]
        .as_str()
        .unwrap()
        .to_string()
}

#[cfg(target_os = "macos")]
fn copy_checked_libs(bundle: &Path, dest: &Path) {
    for name in DIRECT_LIBS {
        let source = bundle.join(name);
        let target = dest.join(name);
        std::fs::copy(&source, &target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o500)).unwrap();
        let copied = format!("sha256:{}", sha256_hex(&target));
        assert_eq!(copied, receipt_digest(bundle, name), "{name}");
        let from = std::fs::metadata(&source).unwrap();
        let into = std::fs::metadata(&target).unwrap();
        assert_ne!(
            (from.dev(), from.ino()),
            (into.dev(), into.ino()),
            "{name} is a new inode"
        );
    }
}

#[cfg(target_os = "macos")]
fn show(label: &str, outcome: (i32, String)) -> (i32, String) {
    let mut text = outcome.1.clone();
    text.truncate(500);
    println!("TRIAL {label} exit={} text={text:?}", outcome.0);
    outcome
}

#[cfg(all(target_os = "macos", not(elastos_unsupported_os_check)))]
#[test]
#[ignore = "set ELASTOS_TEST_LLAMA_SERVER, ELASTOS_TEST_LLAMA_LIBS, and ELASTOS_TEST_GGUF"]
fn spike_macos_checked_copy_sandbox() {
    let Some((server, libs, gguf)) = engine_env() else {
        println!("SKIPPED spike_macos_checked_copy_sandbox");
        return;
    };
    assert!(server.is_file(), "{}", server.display());
    assert!(libs.is_dir(), "{}", libs.display());
    assert!(gguf.is_file() && std::fs::metadata(&gguf).unwrap().len() > 0);
    let bundle = if libs.join(DIRECT_LIBS[0]).is_file() {
        libs
    } else {
        server.parent().unwrap().to_path_buf()
    };
    for name in DIRECT_LIBS {
        assert!(bundle.join(name).is_file(), "{name}");
    }
    let loads = Command::new("/usr/bin/otool")
        .args(["-l"])
        .arg(&server)
        .output()
        .unwrap();
    let mut load_text = String::new();
    let mut command = String::new();
    for line in String::from_utf8_lossy(&loads.stdout).lines() {
        let line = line.trim();
        if line.starts_with("cmd ") {
            command = line.split_whitespace().nth(1).unwrap_or("").to_string();
        }
        if command == "LC_RPATH" && line.starts_with("path ") {
            load_text.push_str(line);
            load_text.push('\n');
        }
        if command == "LC_LOAD_DYLIB" && line.starts_with("name ") {
            load_text.push_str(line);
            load_text.push('\n');
        }
    }
    println!("MEASURED load-commands\n{load_text}");

    let (code, text) = show("original-no-sandbox", plain_version(&server));
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("version:"), "{text}");

    let home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let prepared = home_copy(home.path(), &server, false);
    let copy = std::fs::canonicalize(prepared.exec_path()).unwrap();
    let (code, text) = show("copy-only-no-sandbox", plain_version(&copy));
    assert_ne!(code, 0, "{text}");
    assert!(text.contains("Library not loaded"), "{text}");
    assert!(
        text.contains(copy.parent().unwrap().to_str().unwrap()),
        "{text}"
    );

    let profile = version_profile(&copy, false, Some(&bundle));
    let (code, text) = show("copy-only-sandbox", sandbox_version(&copy, &profile));
    assert_ne!(code, 0, "{text}");
    assert!(text.contains("Library not loaded"), "{text}");
    drop(prepared);

    let profile = version_profile(&server, false, Some(&bundle));
    let (code, text) = show("original-sandbox", sandbox_version(&server, &profile));
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("version:"), "{text}");

    let home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let prepared = home_copy(home.path(), &server, true);
    let copy = std::fs::canonicalize(prepared.exec_path()).unwrap();
    let linked = copy.parent().unwrap().join(DIRECT_LIBS[0]);
    assert!(linked.symlink_metadata().unwrap().file_type().is_symlink());
    let profile = version_profile(&copy, true, Some(&bundle));
    let (code, text) = show("symlink-bundle-sandbox", sandbox_version(&copy, &profile));
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("version:"), "{text}");
    let profile = version_profile(&copy, true, None);
    let (code, text) = show(
        "symlink-no-bundle-sandbox",
        sandbox_version(&copy, &profile),
    );
    assert_ne!(code, 0, "{text}");
    assert!(
        text.contains("blocked by sandbox") || text.contains("Library not loaded"),
        "{text}"
    );
    drop(prepared);

    let home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let prepared = home_copy(home.path(), &server, false);
    let copy = std::fs::canonicalize(prepared.exec_path()).unwrap();
    copy_checked_libs(&bundle, copy.parent().unwrap());
    let profile = version_profile(&copy, true, None);
    let (code, text) = show("checked-copies-sandbox", sandbox_version(&copy, &profile));
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("version:"), "{text}");
    let profile = version_profile(&copy, false, None);
    let (code, text) = show(
        "checked-copies-no-directory-read",
        sandbox_version(&copy, &profile),
    );
    assert_ne!(code, 0, "{text}");
    assert!(text.contains("blocked by sandbox"), "{text}");
    println!("MEASURED macos checked copy");
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "set ELASTOS_TEST_LLAMA_SERVER, ELASTOS_TEST_LLAMA_LIBS, and ELASTOS_TEST_GGUF"]
fn spike_macos_real_engine_parent_death() {
    let Some((server, _, gguf)) = engine_env() else {
        println!("SKIPPED spike_macos_real_engine_parent_death");
        return;
    };
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let engine = argv_c(&[
        server.into(),
        "-m".into(),
        gguf.into(),
        "--host".into(),
        "127.0.0.1".into(),
        "--port".into(),
        port.to_string().into(),
        "--gpu-layers".into(),
        "0".into(),
        "--ctx-size".into(),
        "64".into(),
        "--log-disable".into(),
    ]);
    let dir = tempfile::tempdir().unwrap();
    let plain = plain_orphan(dir.path(), &engine);
    println!("MEASURED llama-plain-orphan\n{plain}");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let engine = replace_port(&engine, port);
    let dir = tempfile::tempdir().unwrap();
    let watched = watcher_stops(dir.path(), &engine);
    println!("MEASURED llama-watching-reader\n{watched}");
}

#[cfg(target_os = "macos")]
fn replace_port(engine: &[std::ffi::OsString], port: u16) -> Vec<std::ffi::OsString> {
    let mut args = engine.to_vec();
    let marker = args.iter().position(|arg| arg == "--port").unwrap();
    args[marker + 1] = port.to_string().into();
    args
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
#[ignore = "set ELASTOS_TEST_LLAMA_SERVER, ELASTOS_TEST_LLAMA_LIBS, and ELASTOS_TEST_GGUF"]
fn spike_listening_descriptor() {
    let Some((server, _, gguf)) = engine_env() else {
        println!("SKIPPED spike_listening_descriptor");
        return;
    };
    let help = Command::new(&server).arg("--help").output().unwrap();
    let help_text = format!(
        "{}{}",
        String::from_utf8_lossy(&help.stdout),
        String::from_utf8_lossy(&help.stderr)
    );
    println!("MEASURED help-status {}", help.status.code().unwrap_or(-1));
    for line in help_text.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("hf-repo") || lower.contains("spec-draft") {
            continue;
        }
        if ["listen", "socket", "systemd", "descriptor"]
            .iter()
            .any(|word| lower.contains(word))
        {
            println!("help: {}", line.trim());
        }
    }
    let rejected = Command::new(&server)
        .args(["--listen-fd", "3", "--help"])
        .output()
        .unwrap();
    let rejected_text = format!(
        "{}{}",
        String::from_utf8_lossy(&rejected.stdout),
        String::from_utf8_lossy(&rejected.stderr)
    );
    println!(
        "MEASURED listen-fd exit={} text={}",
        rejected.status.code().unwrap_or(-1),
        rejected_text.lines().next().unwrap_or("")
    );

    let inherited = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let inherited_port = inherited.local_addr().unwrap().port();
    let raw = std::os::fd::AsRawFd::as_raw_fd(&inherited);
    let server_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let server_port = server_listener.local_addr().unwrap().port();
    drop(server_listener);
    let mut command = Command::new(&server);
    command
        .args([
            "-m",
            gguf.to_str().unwrap(),
            "--host",
            "127.0.0.1",
            "--port",
            &server_port.to_string(),
            "--gpu-layers",
            "0",
            "--ctx-size",
            "64",
            "--log-disable",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        use std::os::unix::process::CommandExt;
        command.pre_exec(move || {
            if libc::dup2(raw, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let fds = std::ffi::CString::new("1").unwrap();
            let pid = std::ffi::CString::new(format!("{}", libc::getpid())).unwrap();
            if libc::setenv(c"LISTEN_FDS".as_ptr(), fds.as_ptr(), 1) != 0
                || libc::setenv(c"LISTEN_PID".as_ptr(), pid.as_ptr(), 1) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    let reap = Reap(vec![child.id() as i32]);
    // The parent still holds the listening socket until this drop. A connect
    // before the drop succeeds against the parent, so it says nothing about
    // the engine. Release it, then wait until the engine's own port is healthy.
    drop(inherited);
    let start = Instant::now();
    let mut own = String::from("not-ready");
    while start.elapsed() < Duration::from_secs(30) {
        if child.try_wait().unwrap().is_some() {
            own = format!("server-exited {}", child.wait().unwrap());
            break;
        }
        match http_probe(server_port, Duration::from_millis(500)) {
            probe if probe.contains("\"status\":\"ok\"") => {
                own = probe;
                break;
            }
            probe if probe.starts_with("HTTP/") => {
                own = probe;
                thread::sleep(Duration::from_millis(100));
            }
            _ => thread::sleep(Duration::from_millis(100)),
        }
    }
    let sockets = Command::new("/usr/sbin/lsof")
        .args(["-nP", "-p", &child.id().to_string(), "-a", "-iTCP"])
        .output();
    let socket_text = match sockets {
        Ok(output) => String::from_utf8_lossy(&output.stdout).into_owned(),
        Err(error) => format!("lsof-failed {error}"),
    };
    let inherited_body = http_probe(inherited_port, Duration::from_secs(1));
    println!("MEASURED parent-listener-closed-before-probe");
    println!("MEASURED ports own={server_port} inherited={inherited_port} placed-on-fd=3");
    println!("MEASURED own-port {own}");
    println!("MEASURED inherited-port {inherited_body}");
    println!("MEASURED engine-tcp\n{socket_text}");
    assert!(
        own.contains("\"status\":\"ok\""),
        "own port did not become healthy, so the inherited-port trial is not a serving engine: {own}"
    );
    drop(reap);
    let _ = child.wait();
}

fn http_probe(port: u16, timeout: Duration) -> String {
    let mut stream = match std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(200),
    ) {
        Ok(stream) => stream,
        Err(error) => return format!("connect-failed {error}"),
    };
    if stream.set_read_timeout(Some(timeout)).is_err()
        || stream.set_write_timeout(Some(timeout)).is_err()
    {
        return "timeout-setup-failed".into();
    }
    if stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return "write-failed".into();
    }
    let mut buffer = [0u8; 800];
    let mut got = Vec::new();
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                got.extend_from_slice(&buffer[..count]);
                if got.len() > 800 {
                    break;
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                break
            }
            Err(error) => return format!("read-failed {error}"),
        }
    }
    if got.is_empty() {
        return "connected-no-bytes".into();
    }
    String::from_utf8_lossy(&got).replace(['\r', '\n'], " ")
}

#[cfg(target_os = "linux")]
fn elf_library_notes(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap();
    if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
        return "not a little-endian ELF64 file".into();
    }
    let read_u16 = |at: usize| u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap());
    let read_u32 = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    let read_u64 = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    let phoff = read_u64(32) as usize;
    let phentsize = read_u16(54) as usize;
    let phnum = read_u16(56) as usize;
    let mut loads = Vec::new();
    let mut dynamic = None;
    for index in 0..phnum {
        let at = phoff + index * phentsize;
        let kind = read_u32(at);
        let offset = read_u64(at + 8);
        let vaddr = read_u64(at + 16);
        let filesz = read_u64(at + 32);
        if kind == 1 {
            loads.push((vaddr, offset, filesz));
        }
        if kind == 2 {
            dynamic = Some((offset as usize, filesz as usize));
        }
    }
    let Some((dyn_off, dyn_len)) = dynamic else {
        return "ELF has no dynamic segment".into();
    };
    let vaddr_to_off = |vaddr: u64| -> Option<usize> {
        for (start, offset, filesz) in &loads {
            if vaddr >= *start && vaddr < start + filesz {
                return Some((offset + (vaddr - start)) as usize);
            }
        }
        None
    };
    let mut strtab = None;
    let mut strsz = 0usize;
    let mut needed = Vec::new();
    let mut rpath = None;
    let mut runpath = None;
    let mut at = dyn_off;
    while at + 16 <= dyn_off + dyn_len && at + 16 <= bytes.len() {
        let tag = read_u64(at) as i64;
        let value = read_u64(at + 8);
        if tag == 0 {
            break;
        }
        match tag {
            1 => needed.push(value),
            5 => strtab = vaddr_to_off(value),
            10 => strsz = value as usize,
            15 => rpath = Some(value),
            29 => runpath = Some(value),
            _ => {}
        }
        at += 16;
    }
    let Some(str_at) = strtab else {
        return "ELF dynamic segment has no string table".into();
    };
    let string_at = |offset: u64| -> String {
        let start = str_at + offset as usize;
        let end = (str_at + strsz).min(bytes.len());
        if start >= end {
            return "<bad>".into();
        }
        let tail = &bytes[start..end];
        let len = tail
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(tail.len());
        String::from_utf8_lossy(&tail[..len]).into_owned()
    };
    let mut lines = Vec::new();
    for offset in needed {
        lines.push(format!("NEEDED {}", string_at(offset)));
    }
    if let Some(offset) = rpath {
        lines.push(format!("RPATH {}", string_at(offset)));
    }
    if let Some(offset) = runpath {
        lines.push(format!("RUNPATH {}", string_at(offset)));
    }
    if lines.is_empty() {
        lines.push("no NEEDED, RPATH, or RUNPATH".into());
    }
    lines.join("\n")
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "set ELASTOS_TEST_LLAMA_SERVER, ELASTOS_TEST_LLAMA_LIBS, and ELASTOS_TEST_GGUF"]
fn spike_linux_fexecve_libraries() {
    let Some((server, libs, gguf)) = engine_env() else {
        println!("SKIPPED spike_linux_fexecve_libraries");
        return;
    };
    assert!(libs.is_dir(), "{}", libs.display());
    let gguf_len = std::fs::metadata(&gguf).unwrap().len();
    assert!(gguf_len > 0);
    println!("MEASURED gguf-bytes {gguf_len} (checked, not passed to the engine)");
    println!("MEASURED elf\n{}", elf_library_notes(&server));
    let checksum = format!("sha256:{}", sha256_hex(&server));
    let prepared = CheckedExecutable::pinned(&server, &checksum)
        .unwrap()
        .verify_at_spawn()
        .unwrap();
    let path_exec = Command::new(&server)
        .arg("--version")
        .env_clear()
        .output()
        .unwrap();
    println!(
        "MEASURED path-exec exit={} text={}",
        path_exec.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&path_exec.stderr)
            .chars()
            .take(400)
            .collect::<String>()
    );
    let fd = prepared.fd();
    let mut command = Command::new("/bin/true");
    command.env_clear();
    unsafe {
        use std::os::unix::process::CommandExt;
        command.pre_exec(move || {
            let arg0 = std::ffi::CString::new("llama-server").unwrap();
            let arg1 = std::ffi::CString::new("--version").unwrap();
            let argv = [arg0.as_ptr(), arg1.as_ptr(), std::ptr::null()];
            let envp = [std::ptr::null::<libc::c_char>()];
            libc::fexecve(fd, argv.as_ptr(), envp.as_ptr());
            Err(std::io::Error::last_os_error())
        });
    }
    match command.output() {
        Ok(output) => println!(
            "MEASURED fexecve exit={} text={}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(400)
                .collect::<String>()
        ),
        Err(error) => println!("MEASURED fexecve spawn-error {error}"),
    }
}
