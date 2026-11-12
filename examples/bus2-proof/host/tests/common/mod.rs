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

/// Like `within`, for a test that should not leave its worker running. When
/// the limit runs out, the worker is told to stop, the test waits a short,
/// fixed time for it to end, and then fails. `f` should hold the whole test,
/// its preparation too.
///
/// The stop is seen the next time the executor gets the thread back. Guests
/// that yield give it back within a fuel slice. Work that is not a guest
/// (compiling a component) runs to its end first. A guest that never yields
/// gives the thread back only when it ends, so every guest in `f` needs an
/// epoch deadline (`Limits::max_ticks`) and a running `Ticker`.
///
/// The wait for the worker is `STOP_WAIT`, 10 s, and no longer, so a worker
/// that cannot stop never holds the test up for more than that: it is left
/// running, as `within` leaves its worker, and the failure says so. 10 s is
/// enough for a worker that can stop: the longest step it may be in the
/// middle of is compiling a guest, about 1 s on the machine this was written
/// on, so 10 s allows for one several times slower.
pub fn within_then_stop<R: Send + 'static>(
    limit: std::time::Duration,
    f: impl std::future::Future<Output = R> + Send + 'static,
) -> R {
    const STOP_WAIT: std::time::Duration = std::time::Duration::from_secs(10);
    let (sender, receiver) = std::sync::mpsc::channel();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let worker = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        let result = local.block_on(&runtime, async move {
            tokio::select! {
                result = f => Some(result),
                _ = stopped => None,
            }
        });
        let _ = sender.send(result);
    });
    let result = match receiver.recv_timeout(limit) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            let _ = stop.send(());
            if matches!(
                receiver.recv_timeout(STOP_WAIT),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) {
                // Not joined: a worker that cannot stop must not hold the
                // test up any longer.
                panic!(
                    "no result within {limit:?}; the worker did not stop within \
                     {STOP_WAIT:?} more and was left running"
                );
            }
            None
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("the run panicked; see its output above")
        }
    };
    // The worker has ended, or is ending: no thread is left.
    let _ = worker.join();
    result.unwrap_or_else(|| panic!("no result within {limit:?}; the worker was stopped"))
}

/// A clock that a test moves by hand, for a proof that must hold on a fast
/// machine, a slow one and a loaded one alike. No `Ticker` runs next to it.
///
/// It wraps the future that runs the guests and counts its turns: a turn ends
/// each time that future gives the thread back to the executor unfinished.
/// After every `turns_per_tick` turns it advances the engine's epoch by one
/// tick. So a tick is a counted amount of guest work (a busy guest gives the
/// thread back once per fuel slice), not an amount of time, and a guest that
/// never gives the thread back never sees a tick.
pub struct HandClock {
    engine: wasmtime::Engine,
    turns_per_tick: u64,
    turns: std::sync::atomic::AtomicU64,
}

impl HandClock {
    pub fn new(engine: &wasmtime::Engine, turns_per_tick: u64) -> HandClock {
        HandClock {
            engine: engine.clone(),
            turns_per_tick,
            turns: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// The ticks so far.
    pub fn ticks(&self) -> u64 {
        self.turns.load(std::sync::atomic::Ordering::Relaxed) / self.turns_per_tick
    }

    /// Runs `work` to its end, counting its turns and advancing the epoch.
    pub async fn run<R>(&self, work: impl std::future::Future<Output = R>) -> R {
        use std::sync::atomic::Ordering;
        let mut work = std::pin::pin!(work);
        std::future::poll_fn(|context| {
            let poll = work.as_mut().poll(context);
            if poll.is_pending() {
                let turns = self.turns.fetch_add(1, Ordering::Relaxed) + 1;
                if turns.is_multiple_of(self.turns_per_tick) {
                    self.engine.increment_epoch();
                }
            }
            poll
        })
        .await
    }

    /// Waits, one turn at a time, until the clock shows `tick`. Only for use
    /// inside `run`.
    pub async fn at_tick(&self, tick: u64) {
        while self.ticks() < tick {
            tokio::task::yield_now().await;
        }
    }
}

// ---- Test credentials ----
//
// The photo guest pins the test publisher's key in its capsule.json. The
// seeds are the SHA-256 of fixed labels: test keys, not real ones.

pub const PUBLISHER_LABEL: &[u8] = b"elastos bus2-proof test publisher (not a real key)";
pub const OTHER_LABEL: &[u8] = b"elastos bus2-proof other key (not a real key)";
pub const PUBLISHER_DID: &str = "did:key:z6MkoJQGyiFajdmdvoaFYk6g6FotMRiqSJHbssfFhFR2J7n4";
pub const OTHER_DID: &str = "did:key:z6Mkk5hSU3e5gkYprGUeXwEV1oq8DCopYapGbJ51BSmuxfvS";
pub const KIND: &str = "elastos.bus2-proof.licence/v1";
pub const TAG: &str = "elastos:bus2-proof:credential:v1";

pub fn key(label: &[u8]) -> ed25519_dalek::SigningKey {
    use sha2::Digest as _;
    ed25519_dalek::SigningKey::from_bytes(&sha2::Sha256::digest(label).into())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The message the guest checks: tag, kind and subject hash, one per line.
pub fn message(tag: &str, kind: &str, subject_sha256: &str) -> Vec<u8> {
    format!("{tag}\n{kind}\n{subject_sha256}").into_bytes()
}

pub fn credential(
    kind: &str,
    signer: &str,
    subject_sha256: &str,
    key: &ed25519_dalek::SigningKey,
    message: &[u8],
) -> bus2_host::Credential {
    use ed25519_dalek::Signer as _;
    bus2_host::Credential {
        kind: kind.to_string(),
        signer: signer.to_string(),
        subject_sha256: subject_sha256.to_string(),
        body: key.sign(message).to_bytes().to_vec(),
    }
}

/// A good licence for `bytes` from the pinned publisher.
pub fn licence(bytes: &[u8]) -> bus2_host::Credential {
    let subject = sha256_hex(bytes);
    credential(
        KIND,
        PUBLISHER_DID,
        &subject,
        &key(PUBLISHER_LABEL),
        &message(TAG, KIND, &subject),
    )
}
