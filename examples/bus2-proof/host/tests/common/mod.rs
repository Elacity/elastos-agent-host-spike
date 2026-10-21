//! Shared by the proof tests: the built guests, componentized.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// A guest's core module from `target/wasm32-unknown-unknown/release`,
/// componentized. `verify.sh` builds the guests first.
pub fn guest(name: &str) -> Vec<u8> {
    let path = root()
        .join("target/wasm32-unknown-unknown/release")
        .join(format!("{name}.wasm"));
    let core = std::fs::read(&path).unwrap_or_else(|err| {
        panic!(
            "{}: {err}; build the guests first (./verify.sh)",
            path.display()
        )
    });
    bus2_host::componentize(&core).unwrap()
}

pub fn fixture(name: &str) -> Vec<u8> {
    wat::parse_file(root().join("fixtures").join(name)).unwrap()
}

/// Runs `f` on its own thread with a single-threaded tokio runtime, and fails
/// if it gives no result within `limit`. A guest that starves the executor
/// cannot time itself out, so the watchdog is outside it.
pub fn within<R: Send + 'static>(
    limit: std::time::Duration,
    f: impl std::future::Future<Output = R> + Send + 'static,
) -> R {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        let _ = sender.send(local.block_on(&runtime, f));
    });
    match receiver.recv_timeout(limit) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!("watchdog: no result within {limit:?}")
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("the run panicked; see its output above")
        }
    }
}
