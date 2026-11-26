//! Chain reads `/etc/resolv.conf` once, inside the fence, at start.
//!
//! Before each chain dispatch the Runtime stats that path again. The identity
//! is the file's device and inode, or absent when the path is missing. A
//! symlink is followed, which is what macOS's `/etc/resolv.conf` is. When the
//! identity changed, the running helper is killed and `spawn_path_allow` starts
//! another with the same component key, authority, binary, and data directory.
//! The config is the last Init the helper accepted. The new helper is kept
//! beside the bridge the caller already holds. The fence is that same start.
//! One observed identity restarts at most once. The dispatch that saw the
//! change before sending uses the replacement. An in-flight call ends with
//! `chain_resolver_changed`. Only `accept_following_init` retries an Init once.
//! Other dispatches return that name. A failed start leaves the
//! helper down, and later dispatches return `chain is off`.

use super::bridge::{BridgeError, ProviderBridge, ProviderConfig};
use super::CheckedExecutable;
use elastos_common::ProviderAuthority;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;

pub(super) const CHAIN_RESOLVER_CHANGED: &str = "chain_resolver_changed";
pub(super) const CHAIN_IS_OFF: &str = "chain is off";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResolverIdentity {
    Absent,
    File { dev: u64, ino: u64 },
}

#[cfg(test)]
static RESOLV_OVERRIDE: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

#[cfg(test)]
pub(super) fn resolv_override() -> Option<PathBuf> {
    RESOLV_OVERRIDE
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .clone()
}

#[cfg(not(test))]
fn resolv_override() -> Option<PathBuf> {
    None
}

pub(super) fn resolv_conf_path() -> PathBuf {
    resolv_override().unwrap_or_else(|| PathBuf::from("/etc/resolv.conf"))
}

#[cfg(test)]
static RESOLV_SWAP_AFTER_OPEN: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
static RACE_RESTART: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
pub(super) fn arm_race_restart() {
    RACE_RESTART.store(true, Ordering::SeqCst);
}

#[cfg(test)]
pub(super) fn take_race_restart() -> bool {
    RACE_RESTART.swap(false, Ordering::SeqCst)
}

#[cfg(test)]
pub(super) fn arm_resolv_swap_after_open() {
    RESOLV_SWAP_AFTER_OPEN.store(true, Ordering::SeqCst);
}

#[cfg(test)]
pub(super) fn swap_resolv_after_open(path: &Path) {
    let next = path.with_extension("next");
    if next.is_file() && RESOLV_SWAP_AFTER_OPEN.swap(false, Ordering::SeqCst) {
        let _ = std::fs::rename(&next, path);
    }
}

fn identity_from(opened: Option<Option<(u64, u64)>>, path: &Path) -> ResolverIdentity {
    match opened {
        Some(Some((dev, ino))) => ResolverIdentity::File { dev, ino },
        Some(None) => ResolverIdentity::Absent,
        None => read_identity(path).unwrap_or(ResolverIdentity::Absent),
    }
}

/// `metadata` follows a symlink. Absence is `NotFound`. Any other error is
/// not an identity: the caller keeps the helper it already started.
fn read_identity(path: &Path) -> Result<ResolverIdentity, ()> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(path) {
        Ok(meta) => Ok(ResolverIdentity::File {
            dev: meta.dev(),
            ino: meta.ino(),
        }),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(ResolverIdentity::Absent),
        Err(_) => Err(()),
    }
}

struct Inputs {
    component_key: String,
    authority: ProviderAuthority,
    binary: CheckedExecutable,
    data_dir: PathBuf,
    /// Last Init the helper accepted. A restart sends this config.
    config: std::sync::Mutex<ProviderConfig>,
    resolv: PathBuf,
}

pub(super) struct ChainResolver {
    inputs: Inputs,
    held: std::sync::Mutex<ResolverIdentity>,
    replacement: std::sync::Mutex<Option<Arc<ProviderBridge>>>,
    restart: AsyncMutex<()>,
    off: AtomicBool,
    generation: AtomicU64,
    restarts: AtomicU64,
}

impl ChainResolver {
    pub(super) fn prepare(
        component_key: &str,
        authority: &ProviderAuthority,
        binary: &CheckedExecutable,
        data_dir: &Path,
        config: &ProviderConfig,
        opened: Option<Option<(u64, u64)>>,
    ) -> Arc<Self> {
        let resolv = resolv_conf_path();
        let held = identity_from(opened, &resolv);
        Arc::new(Self {
            inputs: Inputs {
                component_key: component_key.to_string(),
                authority: authority.clone(),
                binary: binary.duplicate(),
                data_dir: data_dir.to_path_buf(),
                config: std::sync::Mutex::new(config.clone()),
                resolv,
            },
            held: std::sync::Mutex::new(held),
            replacement: std::sync::Mutex::new(None),
            restart: AsyncMutex::new(()),
            off: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            restarts: AtomicU64::new(0),
        })
    }

    fn accepted(&self) -> std::sync::MutexGuard<'_, ProviderConfig> {
        let guard = self.inputs.config.lock();
        guard.unwrap_or_else(|err| err.into_inner())
    }

    /// The bridge calls this when an Init returns Ok. A refused Init is not
    /// recorded, so a restart keeps the previous accepted config.
    pub(super) fn record_accepted(&self, config: ProviderConfig) {
        *self.accepted() = config;
    }

    pub(super) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(super) fn restarts(&self) -> u64 {
        self.restarts.load(Ordering::Acquire)
    }

    #[cfg(test)]
    fn bump_generation_for_test(&self) {
        self.generation.fetch_add(1, Ordering::Release);
    }

    /// `None` means the call uses the bridge it already has. `Some` is the
    /// helper started after a previous change. An error is the whole dispatch.
    pub(super) async fn before(
        &self,
        host: &ProviderBridge,
    ) -> Result<(Option<Arc<ProviderBridge>>, u64), BridgeError> {
        let _lock = self.restart.lock().await;
        if self.off.load(Ordering::Acquire) {
            return Err(BridgeError::Refused(CHAIN_IS_OFF.to_string()));
        }
        let now = match read_identity(&self.inputs.resolv) {
            Ok(identity) => identity,
            Err(()) => return Ok(self.sampled()),
        };
        let held = *self.held.lock().unwrap_or_else(|err| err.into_inner());
        if now != held {
            self.restart_once(host).await?;
        }
        Ok(self.sampled())
    }

    fn sampled(&self) -> (Option<Arc<ProviderBridge>>, u64) {
        (self.live(), self.generation())
    }

    fn live(&self) -> Option<Arc<ProviderBridge>> {
        self.replacement
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone()
    }

    async fn restart_once(&self, host: &ProviderBridge) -> Result<(), BridgeError> {
        // Bump before the await so a call already on the old helper sees the
        // change without a second flag.
        self.generation.fetch_add(1, Ordering::Release);
        if let Some(current) = self.live() {
            current.abandon_child_for_restart().await;
        } else {
            host.abandon_child_for_restart().await;
        }
        let config = self.accepted().clone();
        // A replacement does not attach another resolver. The host bridge is
        // the one the caller holds, and this start is the same fence.
        let attach_resolver = false;
        let spawned = ProviderBridge::spawn_path_allow_with(
            &self.inputs.component_key,
            &self.inputs.authority,
            &self.inputs.binary,
            &self.inputs.data_dir,
            config,
            attach_resolver,
        )
        .await;
        self.restarts.fetch_add(1, Ordering::Release);
        let off = spawned.is_err();
        #[rustfmt::skip]
        let now = identity_from(spawned.as_ref().ok().and_then(|c| c.bridge().resolv_opened.get().copied()), &self.inputs.resolv);
        let replacement = spawned.ok().map(|confined| Arc::clone(confined.bridge()));
        *self
            .replacement
            .lock()
            .unwrap_or_else(|err| err.into_inner()) = replacement;
        *self.held.lock().unwrap_or_else(|err| err.into_inner()) = now;
        // A call that sampled the generation during the spawn has to see a
        // second change, or it treats this helper as the one it already held.
        self.generation.fetch_add(1, Ordering::Release);
        if off {
            self.off.store(true, Ordering::Release);
            return Err(BridgeError::Refused(CHAIN_IS_OFF.to_string()));
        }
        Ok(())
    }

    /// A call that overlapped a change does not keep its answer. Only
    /// `accept_following_init` retries an Init once. After a failed restart
    /// every answer is `chain is off`.
    pub(super) fn map_transport<T>(
        &self,
        observed: u64,
        result: Result<T, BridgeError>,
    ) -> Result<T, BridgeError> {
        if self.off.load(Ordering::Acquire) {
            return Err(BridgeError::Refused(CHAIN_IS_OFF.to_string()));
        }
        if self.generation.load(Ordering::Acquire) != observed {
            return Err(BridgeError::Refused(CHAIN_RESOLVER_CHANGED.to_string()));
        }
        result
    }

    pub(super) async fn shutdown_replacement(&self) {
        let _lock = self.restart.lock().await;
        let live = self
            .replacement
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .take();
        if let Some(live) = live {
            let _ = Box::pin(live.shutdown()).await;
        }
    }
}

#[cfg(test)]
fn set_resolv_override(path: Option<PathBuf>) {
    *RESOLV_OVERRIDE
        .lock()
        .unwrap_or_else(|err| err.into_inner()) = path;
}

#[cfg(test)]
mod tests {
    use super::{read_identity, ResolverIdentity};

    #[test]
    fn chain_restart_uses_spawn_path_allow() {
        let src = include_str!("chain_resolver.rs");
        let production = src.split("mod tests").next().unwrap();
        assert!(
            production.contains("ProviderBridge::spawn_path_allow_with("),
            "deleting the restart's spawn_path_allow turns this red"
        );
        assert!(
            production.contains("let attach_resolver = false;"),
            "the restart must pass attach_resolver false"
        );
        assert!(
            production.contains("fn record_accepted"),
            "deleting the accepted-Init record turns this red"
        );
        assert!(
            production.contains("self.inputs.config"),
            "the restart must clone the accepted config"
        );
        let bridge = include_str!("bridge.rs");
        let follow = bridge
            .split("fn accept_following_init")
            .nth(1)
            .expect("accept_following_init");
        let follow = follow.split("\n    pub async fn request").next().unwrap();
        assert_eq!(
            follow.matches("ProviderRequest::Init").count(),
            2,
            "the second Init tries once more, then returns the name"
        );
        assert!(
            follow.contains("chain_resolver_changed"),
            "a second change is refused by name"
        );
        assert!(
            !production.contains("ProviderBridge::spawn("),
            "a plain spawn is a wider fence"
        );
    }

    #[test]
    fn resolver_identity_is_absent_or_the_file_and_rename_changes_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        assert_eq!(read_identity(&path), Ok(ResolverIdentity::Absent));
        std::fs::write(&path, b"nameserver 127.0.0.1\n").unwrap();
        let ResolverIdentity::File { ino: first, .. } = read_identity(&path).unwrap() else {
            panic!("a present file has a device and inode");
        };
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(read_identity(&link), read_identity(&path));
        let next = dir.path().join("resolv.next");
        std::fs::write(&next, b"nameserver 127.0.0.2\n").unwrap();
        std::fs::rename(&next, &path).unwrap();
        let ResolverIdentity::File { ino: second, .. } = read_identity(&path).unwrap() else {
            panic!("the renamed file is present");
        };
        assert_ne!(first, second, "rename replaces the inode");
        assert_eq!(read_identity(&link), read_identity(&path));
    }

    #[cfg(all(
        not(elastos_unsupported_os_check),
        any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )
    ))]
    mod restart {
        use super::super::{
            set_resolv_override, BridgeError, CheckedExecutable, ProviderAuthority, ProviderBridge,
            ProviderConfig, CHAIN_IS_OFF, CHAIN_RESOLVER_CHANGED,
        };
        use std::os::unix::fs::PermissionsExt;
        use std::path::{Path, PathBuf};
        use std::sync::Arc;

        fn tests_lock() -> &'static tokio::sync::Mutex<()> {
            static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
            &LOCK
        }

        struct ClearOverride;
        impl Drop for ClearOverride {
            fn drop(&mut self) {
                set_resolv_override(None);
            }
        }

        fn chain_binary() -> PathBuf {
            let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../../target/provider-fence-tests/debug/chain-provider");
            assert!(
                binary.is_file(),
                "chain-provider is not at {}. Run `just prepare-providers` before this row.",
                binary.display()
            );
            binary
        }

        fn authority() -> ProviderAuthority {
            let manifest: elastos_common::CapsuleManifest = serde_json::from_str(include_str!(
                "../../../../../capsules/chain-provider/capsule.json"
            ))
            .unwrap();
            manifest.authority.unwrap()
        }

        fn pinned(path: &Path, data: &Path) -> CheckedExecutable {
            use sha2::{Digest, Sha256};
            let digest = hex::encode(Sha256::digest(std::fs::read(path).unwrap()));
            CheckedExecutable::pinned(path, &format!("sha256:{digest}"))
                .unwrap()
                .with_home_data_dir(data)
        }

        struct Started {
            bridge: Arc<ProviderBridge>,
            resolv: PathBuf,
            _home: tempfile::TempDir,
            _guard: ClearOverride,
        }

        async fn start(resolv_body: Option<&[u8]>) -> Started {
            let home = tempfile::tempdir().unwrap();
            let data = home.path().join("data");
            std::fs::create_dir(&data).unwrap();
            std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
            let resolv = home.path().join("resolv.conf");
            if let Some(body) = resolv_body {
                std::fs::write(&resolv, body).unwrap();
            }
            set_resolv_override(Some(resolv.clone()));
            let bridge = ProviderBridge::spawn_path_allow(
                "chain-provider",
                &authority(),
                &pinned(&chain_binary(), &data),
                &data,
                ProviderConfig {
                    base_path: data.display().to_string(),
                    ..ProviderConfig::default()
                },
            )
            .await
            .unwrap_or_else(|err| panic!("chain start failed: {err}"));
            Started {
                bridge: Arc::clone(bridge.bridge()),
                resolv,
                _home: home,
                _guard: ClearOverride,
            }
        }

        async fn networks(bridge: &ProviderBridge) -> Result<serde_json::Value, BridgeError> {
            bridge
                .send_raw(&serde_json::json!({"op": "networks"}))
                .await
        }

        fn replace_by_rename(path: &Path, body: &[u8]) {
            let next = path.with_extension("next");
            std::fs::write(&next, body).unwrap();
            std::fs::rename(&next, path).unwrap();
        }

        /// Absent at start, then the file appears, then a rename. Each observed
        /// identity restarts once. The dispatch that sees the change is
        /// answered by the replacement.
        #[tokio::test]
        async fn chain_resolver_rename_and_absent_start_restart_once() {
            let _lock = tests_lock().lock().await;
            let started = start(None).await;
            let first = networks(&started.bridge).await.unwrap();
            assert_eq!(first["status"], "ok", "{first}");
            assert_eq!(started.bridge.chain_resolver_restarts(), 0);
            std::fs::write(&started.resolv, b"nameserver 127.0.0.1\n").unwrap();
            let changed = networks(&started.bridge).await.unwrap();
            assert_eq!(changed["status"], "ok", "{changed}");
            assert_eq!(started.bridge.chain_resolver_restarts(), 1);
            let again = networks(&started.bridge).await.unwrap();
            assert_eq!(again["status"], "ok", "{again}");
            assert_eq!(started.bridge.chain_resolver_restarts(), 1);
            replace_by_rename(&started.resolv, b"nameserver 127.0.0.2\n");
            let renamed = networks(&started.bridge).await.unwrap();
            assert_eq!(renamed["status"], "ok", "{renamed}");
            assert_eq!(started.bridge.chain_resolver_restarts(), 2);
            let after = networks(&started.bridge).await.unwrap();
            assert_eq!(after["status"], "ok", "{after}");
            assert_eq!(started.bridge.chain_resolver_restarts(), 2);
            started.bridge.shutdown().await.unwrap();
        }

        /// Two dispatches that both see one new identity start one helper.
        /// Neither has sent yet, so both are answered by that helper.
        #[tokio::test]
        async fn chain_resolver_two_dispatches_restart_once() {
            let _lock = tests_lock().lock().await;
            let started = start(Some(b"nameserver 127.0.0.1\n")).await;
            let warm = networks(&started.bridge).await.unwrap();
            assert_eq!(warm["status"], "ok", "{warm}");
            replace_by_rename(&started.resolv, b"nameserver 127.0.0.2\n");
            let bridge = Arc::clone(&started.bridge);
            let left = Arc::clone(&bridge);
            let right = Arc::clone(&bridge);
            let (one, two) = tokio::join!(async move { networks(&left).await }, async move {
                networks(&right).await
            },);
            assert_eq!(one.unwrap()["status"], "ok");
            assert_eq!(two.unwrap()["status"], "ok");
            assert_eq!(bridge.chain_resolver_restarts(), 1);
            let after = networks(&bridge).await.unwrap();
            assert_eq!(after["status"], "ok", "{after}");
            assert_eq!(bridge.chain_resolver_restarts(), 1);
            bridge.shutdown().await.unwrap();
        }

        /// A start that fails after the identity changed does not try again.
        /// Later dispatches name chain as off.
        #[tokio::test]
        async fn chain_resolver_failed_restart_leaves_chain_off() {
            let _lock = tests_lock().lock().await;
            let home = tempfile::tempdir().unwrap();
            let data = home.path().join("data");
            std::fs::create_dir(&data).unwrap();
            std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
            let copy = home.path().join("chain-copy");
            std::fs::copy(chain_binary(), &copy).unwrap();
            std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o755)).unwrap();
            let resolv = home.path().join("resolv.conf");
            std::fs::write(&resolv, b"nameserver 127.0.0.1\n").unwrap();
            let _guard = ClearOverride;
            set_resolv_override(Some(resolv.clone()));
            let started = ProviderBridge::spawn_path_allow(
                "chain-provider",
                &authority(),
                &pinned(&copy, &data),
                &data,
                ProviderConfig {
                    base_path: data.display().to_string(),
                    ..ProviderConfig::default()
                },
            )
            .await
            .unwrap_or_else(|err| panic!("chain start failed: {err}"));
            let bridge = Arc::clone(started.bridge());
            let warm = networks(&bridge).await.unwrap();
            assert_eq!(warm["status"], "ok", "{warm}");
            let aside = home.path().join("chain-aside");
            std::fs::rename(&copy, &aside).unwrap();
            std::fs::write(&copy, b"not-the-helper").unwrap();
            replace_by_rename(&resolv, b"nameserver 127.0.0.9\n");
            let failed = networks(&bridge).await.unwrap_err();
            assert_eq!(failed.to_string(), CHAIN_IS_OFF);
            assert_eq!(bridge.chain_resolver_restarts(), 1);
            replace_by_rename(&resolv, b"nameserver 127.0.0.8\n");
            let still = networks(&bridge).await.unwrap_err();
            assert_eq!(still.to_string(), CHAIN_IS_OFF);
            assert_eq!(bridge.chain_resolver_restarts(), 1);
            bridge.shutdown().await.unwrap();
        }

        fn issuer_hex() -> String {
            let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
            format!("0x{}", hex::encode(key.verifying_key().to_bytes()))
        }

        /// Product settings live in a fixture file: the generic Runtime names
        /// no product.
        fn second_init_settings() -> serde_json::Value {
            let text = std::fs::read_to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/chain-second-init.json"
            ))
            .unwrap();
            serde_json::from_str(&text.replace("__ISSUER__", &issuer_hex())).unwrap()
        }

        fn protected_config() -> ProviderConfig {
            ProviderConfig {
                extra: second_init_settings(),
                ..ProviderConfig::default()
            }
        }

        fn esc_name(value: &serde_json::Value) -> String {
            value["data"]["networks"]
                .as_array()
                .and_then(|nets| nets.iter().find(|net| net["id"] == "esc-mainnet"))
                .and_then(|net| net["display_name"].as_str())
                .unwrap_or("")
                .to_string()
        }

        /// The last Ok Init is what the restarted helper receives.
        #[tokio::test]
        async fn protected_settings_survive_a_resolv_replacement() {
            let _lock = tests_lock().lock().await;
            let started = start(Some(b"nameserver 127.0.0.1\n")).await;
            let before = networks(&started.bridge).await.unwrap();
            assert_eq!(esc_name(&before), "Elastos Smart Chain", "{before}");
            let applied = started
                .bridge
                .accept_following_init(protected_config())
                .await
                .unwrap();
            assert!(
                matches!(
                    applied,
                    super::super::super::bridge::ProviderResponse::Ok { .. }
                ),
                "{applied:?}"
            );
            let armed = networks(&started.bridge).await.unwrap();
            assert_eq!(esc_name(&armed), "Protected ESC", "{armed}");
            replace_by_rename(&started.resolv, b"nameserver 127.0.0.2\n");
            let changed = networks(&started.bridge).await.unwrap();
            assert_eq!(esc_name(&changed), "Protected ESC", "{changed}");
            assert_eq!(started.bridge.chain_resolver_restarts(), 1);
            let after = networks(&started.bridge).await.unwrap();
            assert_eq!(esc_name(&after), "Protected ESC", "{after}");
            assert_eq!(started.bridge.chain_resolver_restarts(), 1);
            started.bridge.shutdown().await.unwrap();
        }

        fn base_restart_settings() -> serde_json::Value {
            let text = std::fs::read_to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/chain-base-restart.json"
            ))
            .unwrap();
            serde_json::from_str(&text.replace("__ISSUER__", &issuer_hex())).unwrap()
        }

        struct OperatorEnv {
            base: Option<String>,
            bitcoin: Option<String>,
        }

        impl OperatorEnv {
            fn set(base: &str, bitcoin: &str) -> Self {
                let previous = Self {
                    base: std::env::var("BASE_RPC_URL").ok(),
                    bitcoin: std::env::var("BITCOIN_REST_URL").ok(),
                };
                std::env::set_var("BASE_RPC_URL", base);
                std::env::set_var("BITCOIN_REST_URL", bitcoin);
                previous
            }
        }

        impl Drop for OperatorEnv {
            fn drop(&mut self) {
                restore_env("BASE_RPC_URL", self.base.as_deref());
                restore_env("BITCOIN_REST_URL", self.bitcoin.as_deref());
            }
        }

        fn restore_env(key: &str, value: Option<&str>) {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }

        struct Hits {
            port: u16,
            hits: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        }

        impl Hits {
            fn serve() -> Self {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let port = listener.local_addr().unwrap().port();
                let hits = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
                let record = std::sync::Arc::clone(&hits);
                std::thread::spawn(move || {
                    for _ in 0..64 {
                        let Ok((mut sock, _)) = listener.accept() else {
                            break;
                        };
                        let mut buf = [0u8; 2048];
                        let n = std::io::Read::read(&mut sock, &mut buf).unwrap_or(0);
                        let text = String::from_utf8_lossy(&buf[..n]);
                        let path = text.split_whitespace().nth(1).unwrap_or("").to_string();
                        record.lock().unwrap().push(path.clone());
                        let body: &[u8] = if text.contains("eth_chainId") {
                            br#"{"jsonrpc":"2.0","id":1,"result":"0x2105"}"#
                        } else if text.contains("eth_blockNumber") {
                            br#"{"jsonrpc":"2.0","id":1,"result":"0x10"}"#
                        } else if path.contains("tip/height") {
                            b"800000"
                        } else if path.contains("tip/hash") {
                            b"0000000000000000000000000000000000000000000000000000000000000001"
                        } else {
                            b"{}"
                        };
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = std::io::Write::write_all(&mut sock, header.as_bytes());
                        let _ = std::io::Write::write_all(&mut sock, body);
                    }
                });
                Self { port, hits }
            }

            fn saw(&self, marker: &str) -> bool {
                self.hits
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|path| path.contains(marker))
            }

            fn clear(&self) {
                self.hits.lock().unwrap().clear();
            }
        }

        fn url_stayed_out(text: &str) {
            assert!(!text.contains("127.0.0.1"), "{text}");
            assert!(!text.contains("/env"), "{text}");
            assert!(!text.contains("/accepted"), "{text}");
            assert!(!text.contains("/btc"), "{text}");
            assert!(!text.contains("/kept"), "{text}");
        }

        async fn status_text(bridge: &ProviderBridge, id: &str) -> String {
            bridge
                .send_raw(&serde_json::json!({"op": "status", "network": id}))
                .await
                .unwrap_or_else(|err| panic!("{id}: {err}"))
                .to_string()
        }

        fn display_name(value: &serde_json::Value, id: &str) -> String {
            value["data"]["networks"]
                .as_array()
                .and_then(|nets| nets.iter().find(|net| net["id"] == id))
                .and_then(|net| net["display_name"].as_str())
                .unwrap_or("")
                .to_string()
        }

        /// First start applies BASE_RPC_URL to the default network. The accepted
        /// network keeps the rpc from its Init, including after a restart that
        /// injects BASE_RPC_URL again. BITCOIN_REST_URL still fills btc-mainnet,
        /// which this Init did not replace.
        #[tokio::test]
        async fn an_accepted_network_keeps_its_rpc_when_base_rpc_url_is_set() {
            let _lock = tests_lock().lock().await;
            let hits = Hits::serve();
            let _env = OperatorEnv::set(
                &format!("http://127.0.0.1:{}/env", hits.port),
                &format!("http://127.0.0.1:{}/btc", hits.port),
            );
            let mut extra = base_restart_settings();
            let id = extra["accepted_id"].as_str().unwrap().to_string();
            let accepted = format!("http://127.0.0.1:{}/accepted", hits.port);
            extra["accepted_rpc_url"] = serde_json::json!(&accepted);
            extra["protected_content_network"]["rpc_url"] = serde_json::json!(&accepted);
            let accepted_name = extra["accepted_display_name"].as_str().unwrap().to_string();
            let object = extra.as_object_mut().unwrap();
            object.remove("accepted_id");
            object.remove("accepted_rpc_url");
            object.remove("accepted_display_name");
            let started = start(Some(b"nameserver 127.0.0.1\n")).await;
            let first = status_text(&started.bridge, &id).await;
            assert!(
                hits.saw("/env"),
                "{first} hits {:?}",
                hits.hits.lock().unwrap()
            );
            url_stayed_out(&first);
            hits.clear();
            let bitcoin = status_text(&started.bridge, "btc-mainnet").await;
            assert!(hits.saw("/btc"), "{bitcoin}");
            url_stayed_out(&bitcoin);
            let applied = started
                .bridge
                .accept_following_init(ProviderConfig {
                    extra,
                    ..ProviderConfig::default()
                })
                .await
                .unwrap();
            assert!(
                matches!(
                    applied,
                    super::super::super::bridge::ProviderResponse::Ok { .. }
                ),
                "{applied:?}"
            );
            let armed = networks(&started.bridge).await.unwrap();
            assert_eq!(display_name(&armed, &id), accepted_name, "{armed}");
            hits.clear();
            let armed_status = status_text(&started.bridge, &id).await;
            assert!(hits.saw("/accepted"), "{armed_status}");
            assert!(!hits.saw("/env"), "{armed_status}");
            url_stayed_out(&armed_status);
            replace_by_rename(&started.resolv, b"nameserver 127.0.0.7\n");
            let changed = networks(&started.bridge).await.unwrap();
            assert_eq!(display_name(&changed, &id), accepted_name, "{changed}");
            assert_eq!(started.bridge.chain_resolver_restarts(), 1);
            let after = networks(&started.bridge).await.unwrap();
            assert_eq!(display_name(&after, &id), accepted_name, "{after}");
            hits.clear();
            let after_status = status_text(&started.bridge, &id).await;
            assert!(hits.saw("/accepted"), "{after_status}");
            assert!(!hits.saw("/env"), "{after_status}");
            url_stayed_out(&after_status);
            hits.clear();
            let bitcoin_after = status_text(&started.bridge, "btc-mainnet").await;
            assert!(hits.saw("/btc"), "{bitcoin_after}");
            url_stayed_out(&bitcoin_after);
            assert_eq!(started.bridge.chain_resolver_restarts(), 1);
            started.bridge.shutdown().await.unwrap();
        }

        /// A bad operator URL does not change the running network list, and
        /// the refused Init is not what a resolv restart starts from.
        #[tokio::test]
        async fn an_invalid_operator_setting_leaves_the_saved_init() {
            let _lock = tests_lock().lock().await;
            let hits = Hits::serve();
            let _env = OperatorEnv::set(
                &format!("http://127.0.0.1:{}/kept", hits.port),
                &format!("http://127.0.0.1:{}/btc", hits.port),
            );
            let started = start(Some(b"nameserver 192.0.2.10\n")).await;
            let first = status_text(&started.bridge, "base-mainnet").await;
            assert!(hits.saw("/kept"), "{first}");
            url_stayed_out(&first);
            let before = networks(&started.bridge).await.unwrap();
            assert_eq!(display_name(&before, "base-mainnet"), "Base", "{before}");
            let secret = "saved-init-secret-key";
            let refused = started
                .bridge
                .request(super::super::super::bridge::ProviderRequest::Init {
                    config: ProviderConfig {
                        extra: serde_json::json!({
                            "networks": [{
                                "id": "base-mainnet",
                                "display_name": "Should Not Stick",
                                "kind": "evm_json_rpc",
                                "chain_id": 8453,
                                "native_symbol": "ETH",
                                "provider": "test",
                                "mainnet": true,
                                "explorer_url": null,
                                "rpc_url": "https://staged.example.invalid"
                            }],
                            "operator_settings": {
                                "BASE_RPC_URL": format!("http://evil.example/v2/{secret}")
                            }
                        }),
                        ..ProviderConfig::default()
                    },
                })
                .await
                .unwrap();
            let refused_text = format!("{refused:?}");
            assert!(
                matches!(
                    refused,
                    super::super::super::bridge::ProviderResponse::Error { .. }
                ),
                "{refused:?}"
            );
            assert!(!refused_text.contains(secret), "{refused_text}");
            assert!(!refused_text.contains("evil.example"), "{refused_text}");
            let running = networks(&started.bridge).await.unwrap();
            assert_eq!(display_name(&running, "base-mainnet"), "Base", "{running}");
            assert_eq!(esc_name(&running), "Elastos Smart Chain", "{running}");
            hits.clear();
            let still = status_text(&started.bridge, "base-mainnet").await;
            assert!(hits.saw("/kept"), "{still}");
            assert!(!hits.saw("evil"), "{still}");
            url_stayed_out(&still);
            replace_by_rename(&started.resolv, b"nameserver 192.0.2.11\n");
            hits.clear();
            let after = networks(&started.bridge).await.unwrap();
            assert_eq!(display_name(&after, "base-mainnet"), "Base", "{after}");
            assert_eq!(esc_name(&after), "Elastos Smart Chain", "{after}");
            assert_eq!(started.bridge.chain_resolver_restarts(), 1);
            let after_status = status_text(&started.bridge, "base-mainnet").await;
            assert!(hits.saw("/kept"), "{after_status}");
            url_stayed_out(&after_status);
            started.bridge.shutdown().await.unwrap();
        }

        /// The dispatch samples the generation under the restart lock. A
        /// restart in that gap is `chain_resolver_changed`, not a dead process.
        #[tokio::test]
        async fn a_restart_during_dispatch_is_chain_resolver_changed() {
            let _lock = tests_lock().lock().await;
            let started = start(Some(b"nameserver 192.0.2.20\n")).await;
            super::super::arm_race_restart();
            let err = networks(&started.bridge)
                .await
                .expect_err("the raced dispatch must be the changed-resolver name");
            let text = err.to_string();
            assert_eq!(text, "chain_resolver_changed");
            started.bridge.shutdown().await.unwrap();
        }

        /// resolv.conf changes after spawn and before Home's second Init.
        /// That Init has not been sent, so it is answered by the replacement
        /// and the protected settings land there.
        #[tokio::test]
        async fn a_change_between_spawn_and_the_second_init_is_tried_once() {
            let _lock = tests_lock().lock().await;
            let started = start(Some(b"nameserver 127.0.0.1\n")).await;
            replace_by_rename(&started.resolv, b"nameserver 127.0.0.4\n");
            let applied = started
                .bridge
                .accept_following_init(protected_config())
                .await
                .unwrap();
            assert!(
                matches!(
                    applied,
                    super::super::super::bridge::ProviderResponse::Ok { .. }
                ),
                "{applied:?}"
            );
            assert_eq!(started.bridge.chain_resolver_restarts(), 1);
            let after = networks(&started.bridge).await.unwrap();
            assert_eq!(esc_name(&after), "Protected ESC", "{after}");
            started.bridge.shutdown().await.unwrap();
        }

        /// An Init the helper refuses does not become the restart config.
        #[tokio::test]
        async fn a_refused_init_is_not_recorded() {
            let _lock = tests_lock().lock().await;
            let started = start(Some(b"nameserver 127.0.0.1\n")).await;
            let refused = started
                .bridge
                .request(super::super::super::bridge::ProviderRequest::Init {
                    config: ProviderConfig {
                        extra: serde_json::json!({"node_supervisor": "operator"}),
                        ..ProviderConfig::default()
                    },
                })
                .await
                .unwrap();
            assert!(
                matches!(
                    refused,
                    super::super::super::bridge::ProviderResponse::Error { .. }
                ),
                "{refused:?}"
            );
            replace_by_rename(&started.resolv, b"nameserver 127.0.0.5\n");
            let after = networks(&started.bridge).await.unwrap();
            assert_eq!(after["status"], "ok", "{after}");
            assert_eq!(esc_name(&after), "Elastos Smart Chain", "{after}");
            assert_eq!(started.bridge.chain_resolver_restarts(), 1);
            started.bridge.shutdown().await.unwrap();
        }

        /// Replace resolv.conf, then read a wallet balance. The helper answers
        /// that read. The address is not hex, so the row does not call upstream.
        #[tokio::test]
        async fn a_resolv_change_then_a_balance_read_is_answered_once() {
            let _lock = tests_lock().lock().await;
            let started = start(Some(b"nameserver 127.0.0.1\n")).await;
            replace_by_rename(&started.resolv, b"nameserver 127.0.0.3\n");
            let answer = started
                .bridge
                .send_raw(&serde_json::json!({
                    "op": "balance",
                    "network": "esc-mainnet",
                    "address": "0xnot",
                }))
                .await
                .unwrap_or_else(|err| panic!("balance was not answered: {err}"));
            assert_eq!(answer["status"], "error", "{answer}");
            assert_eq!(answer["code"], "invalid_address", "{answer}");
            assert_eq!(started.bridge.chain_resolver_restarts(), 1);
            started.bridge.shutdown().await.unwrap();
        }

        /// The file is replaced after the fence opens it and before the record.
        /// The record is the opened descriptor, so the next read restarts once.
        #[tokio::test]
        async fn a_resolv_file_replaced_between_open_and_record_restarts_once() {
            let _lock = tests_lock().lock().await;
            let home = tempfile::tempdir().unwrap();
            let data = home.path().join("data");
            std::fs::create_dir(&data).unwrap();
            std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
            let resolv = home.path().join("resolv.conf");
            std::fs::write(&resolv, b"nameserver 127.0.0.1\n").unwrap();
            std::fs::write(resolv.with_extension("next"), b"nameserver 127.0.0.2\n").unwrap();
            let _guard = ClearOverride;
            set_resolv_override(Some(resolv));
            super::super::arm_resolv_swap_after_open();
            let started = ProviderBridge::spawn_path_allow(
                "chain-provider",
                &authority(),
                &pinned(&chain_binary(), &data),
                &data,
                ProviderConfig {
                    base_path: data.display().to_string(),
                    ..ProviderConfig::default()
                },
            )
            .await
            .unwrap_or_else(|err| panic!("chain start failed: {err}"));
            let bridge = started.bridge();
            let answer = networks(bridge)
                .await
                .unwrap_or_else(|err| panic!("not answered: {err}"));
            assert_eq!(answer["status"], "ok", "{answer}");
            assert_eq!(bridge.chain_resolver_restarts(), 1);
            let again = networks(bridge).await.unwrap();
            assert_eq!(again["status"], "ok", "{again}");
            assert_eq!(bridge.chain_resolver_restarts(), 1);
            bridge.shutdown().await.unwrap();
        }

        /// `chain_resolver_changed` is the generation moving under a call that
        /// already sampled it. A call that has not sent yet does not use it.
        #[tokio::test]
        async fn chain_resolver_changed_is_only_an_in_flight_call() {
            let _lock = tests_lock().lock().await;
            let home = tempfile::tempdir().unwrap();
            let data = home.path().join("data");
            std::fs::create_dir(&data).unwrap();
            let resolver = super::super::ChainResolver::prepare(
                "chain-provider",
                &authority(),
                &pinned(&chain_binary(), &data),
                &data,
                &ProviderConfig::default(),
                None,
            );
            let observed = resolver.generation();
            resolver.bump_generation_for_test();
            let err = resolver.map_transport(observed, Ok(())).unwrap_err();
            assert_eq!(err.to_string(), CHAIN_RESOLVER_CHANGED);
            assert!(resolver
                .map_transport(resolver.generation(), Ok(()))
                .is_ok());
        }
    }
}
