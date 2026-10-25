use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

// The observer is loaded before the test binary starts, so it sees std::fs and
// descriptor-relative libc calls even when production code omits record_access.
pub(super) fn run_observed_child(name: &str) -> bool {
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
