use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

// The observer is loaded before the test binary starts, so it sees std::fs and
// descriptor-relative libc calls even when production code omits record_access.
pub(crate) fn run_observed_child(name: &str) -> bool {
    if std::env::var("WALLET_IO_OBSERVER_CHILD").as_deref() == Ok(name) {
        return false;
    }
    static LIBRARY: OnceLock<(tempfile::TempDir, std::path::PathBuf)> = OnceLock::new();
    let (_, library) = LIBRARY.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let library = dir.path().join("wallet-io-observer.so");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tests/io_observer.c");
        let mut cc = Command::new("cc");
        cc.args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-fPIC"]);
        #[cfg(target_os = "macos")]
        cc.arg("-dynamiclib");
        #[cfg(not(target_os = "macos"))]
        cc.args(["-shared", "-ldl"]);
        let output = cc.arg(source).arg("-o").arg(&library).output().unwrap();
        assert!(
            output.status.success(),
            "observer build: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        (dir, library)
    });
    let mut child = Command::new(std::env::current_exe().unwrap());
    child
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env("WALLET_IO_OBSERVER_CHILD", name);
    #[cfg(target_os = "macos")]
    child.env("DYLD_INSERT_LIBRARIES", library);
    #[cfg(not(target_os = "macos"))]
    child.env("LD_PRELOAD", library);
    let output = child.output().unwrap();
    assert!(
        output.status.success(),
        "observed {name}:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

/// Pause the first fstat of this file after libc has filled its metadata.
/// A second thread changes the links, then releases the provider to stat the
/// path. The observer counts real reads and mode changes through the descriptor.
pub(crate) struct LinkRace {
    _connection: std::os::unix::net::UnixStream,
    worker: std::thread::JoinHandle<()>,
}

impl LinkRace {
    pub(crate) fn begin(path: &Path, change_links: impl FnOnce() + Send + 'static) -> Self {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;

        let (connection, mut worker_connection) = UnixStream::pair().unwrap();
        let timeout = Some(std::time::Duration::from_secs(10));
        for stream in [&connection, &worker_connection] {
            stream.set_read_timeout(timeout).unwrap();
            stream.set_write_timeout(timeout).unwrap();
        }
        let path =
            std::ffi::CString::new(path.canonicalize().unwrap().as_os_str().as_encoded_bytes())
                .unwrap();
        unsafe {
            let symbol = libc::dlsym(libc::RTLD_DEFAULT, c"wallet_link_probe_begin".as_ptr());
            assert!(!symbol.is_null());
            let begin: unsafe extern "C" fn(*const libc::c_char, libc::c_int) =
                std::mem::transmute(symbol);
            begin(path.as_ptr(), connection.as_raw_fd());
        }
        let worker = std::thread::spawn(move || {
            let mut ready = [0];
            worker_connection.read_exact(&mut ready).unwrap();
            assert_eq!(ready, [1]);
            change_links();
            worker_connection.write_all(&[1]).unwrap();
        });
        Self {
            _connection: connection,
            worker,
        }
    }

    pub(crate) fn finish(self, expected_snapshot_links: i32) {
        self.worker.join().unwrap();
        let mut result = [0; 5];
        unsafe {
            let symbol = libc::dlsym(libc::RTLD_DEFAULT, c"wallet_link_probe_end".as_ptr());
            assert!(!symbol.is_null());
            let end: unsafe extern "C" fn(*mut libc::c_int) = std::mem::transmute(symbol);
            end(result.as_mut_ptr());
        }
        assert_eq!(result[0], 1, "the race must pause exactly once after fstat");
        assert_eq!(
            result[1], expected_snapshot_links,
            "unexpected fstat snapshot"
        );
        assert_eq!(result[2], 0, "the provider read the linked file");
        assert_eq!(result[3], 0, "the provider changed the linked file's mode");
        assert_eq!(result[4], 0, "the race synchronization failed");
    }
}

pub(super) struct Observation;
impl Observation {
    pub(super) fn begin(root: &Path, bootstrap: bool) -> Self {
        let root = std::ffi::CString::new(root.as_os_str().as_encoded_bytes()).unwrap();
        unsafe {
            let symbol = libc::dlsym(libc::RTLD_DEFAULT, c"wallet_probe_begin".as_ptr());
            assert!(
                !symbol.is_null(),
                "independent filesystem observer is required"
            );
            let begin: unsafe extern "C" fn(*const libc::c_char, libc::c_int) =
                std::mem::transmute(symbol);
            begin(root.as_ptr(), i32::from(bootstrap));
        }
        Self
    }
    pub(super) fn finish(self) {
        unsafe {
            let symbol = libc::dlsym(libc::RTLD_DEFAULT, c"wallet_probe_end".as_ptr());
            assert!(!symbol.is_null());
            let end: unsafe extern "C" fn() -> libc::c_int = std::mem::transmute(symbol);
            assert_eq!(
                end(),
                0,
                "independent observer detected outside filesystem access"
            );
        }
    }
}
