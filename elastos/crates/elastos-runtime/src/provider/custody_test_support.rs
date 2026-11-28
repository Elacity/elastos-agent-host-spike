//! Custody fixtures use the product launcher, including raw protocol tests.
//! Enabled only by the Runtime's test-hooks feature.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::super::{os_entry, CheckedExecutable, CUSTODY_STATE_ROOT_RELATIVE};
use super::ProviderBridge;
use elastos_common::ProviderAuthority;
use sha2::{Digest, Sha256};

/// Prepare exactly the state directory that the product fence admits.
pub fn state_root(data_dir: &Path) -> PathBuf {
    let data_dir = fs::canonicalize(data_dir).unwrap();
    fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let state = data_dir.join(CUSTODY_STATE_ROOT_RELATIVE);
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&state)
        .unwrap();
    state
}

fn checked(binary: &Path, data_dir: &Path) -> CheckedExecutable {
    let checksum = format!("sha256:{:x}", Sha256::digest(fs::read(binary).unwrap()));
    CheckedExecutable::pinned(binary, &checksum)
        .unwrap()
        .with_home_data_dir(data_dir)
}

/// A separate thread also permits use inside an existing async test runtime.
pub fn provision(binary: &Path, state: &Path, issuer: &str) -> Vec<u8> {
    let data_dir = state.ancestors().nth(3).expect("custody data directory");
    assert_eq!(state_root(data_dir), state, "use the product custody root");
    let executable = checked(binary, data_dir);
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(ProviderBridge::spawn_custody_provision(
                        &executable,
                        data_dir,
                        issuer,
                        8 * 1024,
                        Duration::from_secs(5),
                    ))
                    .unwrap_or_else(|error| panic!("fenced custody provisioning: {error}"))
            })
            .join()
            .unwrap()
    })
}

/// Raw pipes preserve Init and shutdown protocol assertions. The same
/// `start_path_allow` used by the product bridge owns admission and launch.
pub struct CustodyTestProcess {
    pid: libc::pid_t,
    stdin: File,
    stdout: File,
    reaped: bool,
    #[cfg(all(not(elastos_unsupported_os_check), target_os = "macos"))]
    _prepared: super::super::checked_executable::PreparedExecutable,
}

impl CustodyTestProcess {
    pub fn start(binary: &Path, data_dir: &Path) -> Self {
        state_root(data_dir);
        let data_dir = fs::canonicalize(data_dir).unwrap();
        let authority = ProviderAuthority {
            reason: "runtime grant".to_string(),
            capabilities: Vec::new(),
            audit_events: Vec::new(),
            rights: Vec::new(),
        };
        let (child_in, child_out, stdio) = ProviderBridge::protocol_pipes().unwrap();
        let launched = os_entry::start_path_allow(
            "custody-provider",
            &authority,
            &checked(binary, &data_dir),
            &data_dir,
            stdio,
        )
        .unwrap_or_else(|error| panic!("fenced custody start: {error}"));
        drop((child_in, child_out));
        Self {
            pid: launched.pid,
            stdin: File::from(launched.to_child),
            stdout: File::from(launched.from_child),
            reaped: false,
            #[cfg(all(not(elastos_unsupported_os_check), target_os = "macos"))]
            _prepared: launched.prepared,
        }
    }

    pub fn request(&mut self, value: serde_json::Value) -> serde_json::Value {
        serde_json::to_writer(&mut self.stdin, &value).unwrap();
        writeln!(self.stdin).unwrap();
        self.stdin.flush().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut line = Vec::new();
        loop {
            assert!(Instant::now() < deadline, "custody response timed out");
            let mut fd = libc::pollfd {
                fd: self.stdout.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut fd, 1, 100) };
            assert!(ready >= 0, "custody pipe poll failed");
            if ready == 0 {
                continue;
            }
            let mut byte = [0];
            self.stdout.read_exact(&mut byte).expect("custody response");
            if byte[0] == b'\n' {
                return serde_json::from_slice(&line).unwrap();
            }
            line.push(byte[0]);
            assert!(line.len() <= 1024 * 1024, "custody response too large");
        }
    }

    /// Keep the input descriptor open until the provider has exited.
    pub fn wait_with_stdin_open(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut status = 0;
            let waited = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            assert!(waited >= 0, "custody wait failed");
            if waited == self.pid {
                self.reaped = true;
                assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
                return;
            }
            assert!(Instant::now() < deadline, "custody shutdown timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for CustodyTestProcess {
    fn drop(&mut self) {
        if !self.reaped {
            unsafe { libc::kill(self.pid, libc::SIGKILL) };
            loop {
                let waited = unsafe { libc::waitpid(self.pid, std::ptr::null_mut(), 0) };
                if waited >= 0
                    || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                {
                    break;
                }
            }
        }
    }
}
