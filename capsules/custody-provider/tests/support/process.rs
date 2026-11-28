//! Raw custody protocol support, compiled only by the process test.

use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::{Duration, Instant};

use elastos_common::ProviderAuthority;
use elastos_runtime::provider::bridge::{start_path_allow, ChildStdio, Launched};

use super::custody_test_support::{checked, state_root};

/// Raw pipes preserve Init and shutdown protocol assertions. The same
/// `start_path_allow` used by the product bridge owns admission and launch.
pub struct CustodyTestProcess {
    launched: Launched,
    stdin: std::io::PipeWriter,
    stdout: std::io::PipeReader,
    reaped: bool,
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
        let (child_in, stdin) = std::io::pipe().unwrap();
        let (stdout, child_out) = std::io::pipe().unwrap();
        assert!(
            [
                child_in.as_raw_fd(),
                stdin.as_raw_fd(),
                stdout.as_raw_fd(),
                child_out.as_raw_fd(),
            ]
            .into_iter()
            .all(|fd| fd >= 3),
            "custody protocol pipes must be above stdio"
        );
        let stdio = ChildStdio {
            stdin: child_in.as_raw_fd(),
            stdout: child_out.as_raw_fd(),
            to_child: stdin.try_clone().unwrap().into(),
            from_child: stdout.try_clone().unwrap().into(),
        };
        let launched = start_path_allow(
            "custody-provider",
            &authority,
            &checked(binary, &data_dir),
            &data_dir,
            stdio,
        )
        .unwrap_or_else(|error| panic!("fenced custody start: {error}"));
        drop((child_in, child_out));
        Self {
            stdin,
            stdout,
            launched,
            reaped: false,
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
            if ready == 0
                || (ready < 0
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted)
            {
                continue;
            }
            assert!(ready >= 0, "custody pipe poll failed");
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
            let waited = unsafe { libc::waitpid(self.launched.pid, &mut status, libc::WNOHANG) };
            assert!(
                waited >= 0
                    || std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted,
                "custody wait failed"
            );
            if waited == self.launched.pid {
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
            unsafe { libc::kill(self.launched.pid, libc::SIGKILL) };
            loop {
                let waited = unsafe { libc::waitpid(self.launched.pid, std::ptr::null_mut(), 0) };
                if waited >= 0
                    || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                {
                    break;
                }
            }
        }
    }
}
