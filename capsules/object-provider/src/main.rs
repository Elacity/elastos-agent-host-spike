//! ElastOS Object Provider Capsule
//!
//! Principal-root object authority. Library remains the app capsule; Runtime
//! injects the authenticated principal and forwards typed operations to this
//! provider process.

use elastos_server::Zeroize;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

const PROVIDER_VERSION: &str = env!("CARGO_PKG_VERSION");

const PROVIDER_ID: &str = "object-provider";

struct ObjectProviderProcess {
    data_dir: Option<PathBuf>,
}

impl ObjectProviderProcess {
    fn new() -> Self {
        Self { data_dir: None }
    }

    fn handle(&mut self, mut request: Value) -> Value {
        let response = match request.get("op").and_then(Value::as_str) {
            Some("init") => self.init(request.get("config").cloned().unwrap_or(Value::Null)),
            Some("shutdown") => response_ok(json!({
                "provider": PROVIDER_ID,
            })),
            Some(_) => match self.data_dir.clone() {
                Some(data_dir) => elastos_server::library::handle_object_provider_raw_request(
                    &data_dir,
                    &mut request,
                ),
                None => response_error("not_initialized", "object-provider is not initialized"),
            },
            None => response_error("invalid_request", "provider request missing op"),
        };
        elastos_server::object_authority::wipe_object_authority(&mut request);
        response
    }

    fn init(&mut self, config: Value) -> Value {
        let base_path = config
            .get("base_path")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let Some(base_path) = base_path else {
            return response_error(
                "invalid_config",
                "object-provider requires config.base_path",
            );
        };
        let data_dir = PathBuf::from(base_path);
        if !data_dir.is_absolute() {
            return response_error("invalid_config", "config.base_path must be absolute");
        }
        #[cfg(unix)]
        if !device_key_is_closed(&data_dir) {
            return response_error(
                "refused",
                if cfg!(target_os = "linux") {
                    "object helper can open identity/device.key"
                } else {
                    "object helper can open or stat identity/device.key"
                },
            );
        }
        #[cfg(unix)]
        {
            let marker = config
                .get("extra")
                .and_then(|extra| extra.get("record_auth_write_refusal"))
                .and_then(Value::as_bool)
                .unwrap_or(false)
                .then(|| data_dir.join("Users/auth-write-refused"));
            if let Err((code, message)) = auth_is_closed(&data_dir, marker.as_deref()) {
                return response_error(code, message);
            }
        }
        #[cfg(unix)]
        if let Err((code, message)) = install_public_runtime_did(&config) {
            return response_error(code, &message);
        }
        self.data_dir = Some(data_dir.clone());
        response_ok(json!({
            "provider": PROVIDER_ID,
            "protocol_version": "1.0",
            "version": PROVIDER_VERSION,
            "base_path": data_dir,
        }))
    }
}

/// A missing key is closed. A successful open refuses init.
///
/// macOS also requires lstat to fail. Linux Landlock does not mediate lstat,
/// so a successful stat is not treated as an open. This is not a grant.
#[cfg(unix)]
fn device_key_is_closed(data_dir: &std::path::Path) -> bool {
    let path = data_dir.join("identity").join("device.key");
    let closed = |err: &std::io::Error| {
        matches!(
            err.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
        )
    };
    let open_closed = match std::fs::File::open(&path) {
        Err(err) => closed(&err),
        Ok(_) => false,
    };
    if cfg!(target_os = "linux") {
        return open_closed;
    }
    let stat_closed = match std::fs::symlink_metadata(&path) {
        Err(err) => closed(&err),
        Ok(_) => false,
    };
    open_closed && stat_closed
}

/// The sign-in folder stays closed. A missing file is closed. An open, or a
/// macOS lstat of the sign-in folder or of `ElastOS`, refuses init. A write
/// under `ElastOS/System/Auth` must fail on macOS and Linux. `marker`
/// receives the refusal kind when the confined row asks for it.
#[cfg(unix)]
fn auth_is_closed(
    data_dir: &std::path::Path,
    marker: Option<&std::path::Path>,
) -> Result<(), (&'static str, &'static str)> {
    let auth = match elastos_server::auth::auth_state_path(data_dir) {
        Ok(path) => path.parent().map(std::path::Path::to_path_buf).ok_or((
            "object_helper_can_open_auth_state",
            "object helper can open auth state",
        ))?,
        Err(_) => {
            return Err((
                "object_helper_can_open_auth_state",
                "object helper can open auth state",
            ))
        }
    };
    let closed = |err: &std::io::Error| {
        matches!(
            err.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
        )
    };
    for name in [
        "auth-state.json",
        "audit-chain-required.json",
        "audit-chain-required.json.lock",
        "recovery-archive.key",
        "agent-records.json",
        "principal-root-lifecycle.lock",
    ] {
        match std::fs::File::open(auth.join(name)) {
            Err(err) if closed(&err) => {}
            _ => {
                return Err((
                    "object_helper_can_open_auth_state",
                    "object helper can open auth state",
                ))
            }
        }
    }
    let probe = auth.join("object-write-probe");
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Err(err) if closed(&err) => {
            if let Some(path) = marker {
                std::fs::write(path, err.kind().to_string()).map_err(|_| {
                    (
                        "object_helper_can_write_auth",
                        "object helper could not record the Auth write refusal",
                    )
                })?;
            }
        }
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            return Err((
                "object_helper_can_write_auth",
                "object helper can write under ElastOS/System/Auth",
            ));
        }
        Err(_) => {
            return Err((
                "object_helper_can_write_auth",
                "object helper can write under ElastOS/System/Auth",
            ));
        }
    }
    if cfg!(target_os = "linux") {
        return Ok(());
    }
    let elastos = data_dir.join("ElastOS");
    for path in [auth.as_path(), elastos.as_path()] {
        match std::fs::symlink_metadata(path) {
            Err(err) if closed(&err) => {}
            _ => {
                return Err((
                    "object_helper_can_stat_elastos",
                    "object helper can stat ElastOS",
                ))
            }
        }
    }
    Ok(())
}

/// The public runtime DID from init config. A missing or non-canonical DID
/// refuses init with `no_public_runtime_did`. A different DID already stored
/// in this process keeps its own code and the install message. The value is
/// kept in memory. There is no runtime-did file.
#[cfg(unix)]
fn install_public_runtime_did(config: &Value) -> Result<(), (&'static str, String)> {
    let did = config
        .get("extra")
        .and_then(|extra| extra.get("runtime_did"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if elastos_identity::decode_did_key(did).is_err() {
        return Err((
            "no_public_runtime_did",
            "object helper spawn refused: no public runtime DID".to_string(),
        ));
    }
    elastos_identity::install_object_helper_runtime_did(did)
        .map_err(|err| ("runtime_did_install_failed", err.to_string()))
}

fn response_ok(data: Value) -> Value {
    json!({
        "status": "ok",
        "data": data,
    })
}

fn response_error(code: &str, message: &str) -> Value {
    json!({
        "status": "error",
        "code": code,
        "message": message,
    })
}

fn main() {
    #[cfg(unix)]
    std::env::set_var("ELASTOS_OBJECT_HELPER", "1");
    eprintln!("object-provider: starting v{PROVIDER_VERSION}");
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut provider = ObjectProviderProcess::new();
    let mut stdin = stdin.lock();
    let mut line = elastos_server::Zeroizing::new(Vec::new());

    loop {
        line.clear();
        let read = match stdin.read_until(b'\n', &mut line) {
            Ok(read) => read,
            Err(err) => {
                eprintln!("object-provider read error: {err}");
                break;
            }
        };
        if read == 0 {
            break;
        }
        if line.iter().all(|byte| byte.is_ascii_whitespace()) {
            continue;
        }
        let request = match serde_json::from_slice::<Value>(&line) {
            Ok(request) => request,
            Err(err) => {
                line.zeroize();
                response_error("invalid_request", &err.to_string())
            }
        };
        line.zeroize();
        let is_shutdown = request.get("op").and_then(Value::as_str) == Some("shutdown");
        let response = provider.handle(request);
        writeln!(stdout, "{}", serde_json::to_string(&response).unwrap()).unwrap();
        stdout.flush().unwrap();
        if is_shutdown {
            break;
        }
    }

    eprintln!("object-provider: exiting");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_requests_before_init() {
        let mut provider = ObjectProviderProcess::new();

        let response = provider.handle(json!({
            "op": "list",
            "principal_id": "alice",
            "uri": "localhost://Users/alice/Documents"
        }));

        assert_eq!(response["status"], "error");
        assert_eq!(response["code"], "not_initialized");
    }

    #[test]
    fn init_requires_absolute_base_path() {
        let mut provider = ObjectProviderProcess::new();

        let missing = provider.handle(json!({
            "op": "init",
            "config": {}
        }));
        assert_eq!(missing["status"], "error");
        assert_eq!(missing["code"], "invalid_config");

        let relative = provider.handle(json!({
            "op": "init",
            "config": {
                "base_path": "relative/path"
            }
        }));
        assert_eq!(relative["status"], "error");
        assert_eq!(relative["code"], "invalid_config");
    }

    fn public_runtime_did() -> String {
        elastos_identity::derive_did(&[0x11; 32]).1
    }

    fn init_config(base: &std::path::Path) -> Value {
        json!({
            "base_path": base.to_string_lossy().to_string(),
            "extra": { "runtime_did": public_runtime_did() }
        })
    }

    #[cfg(unix)]
    #[test]
    fn init_refuses_a_missing_public_runtime_did() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = ObjectProviderProcess::new();
        let response = provider.handle(json!({
            "op": "init",
            "config": { "base_path": dir.path().to_string_lossy().to_string() }
        }));
        assert_eq!(response["status"], "error");
        assert_eq!(response["code"], "no_public_runtime_did");
        assert_eq!(
            response["message"],
            "object helper spawn refused: no public runtime DID"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_different_runtime_did_keeps_its_install_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = ObjectProviderProcess::new();
        let first = provider.handle(json!({
            "op": "init",
            "config": init_config(dir.path())
        }));
        assert_eq!(first["status"], "ok", "{first}");
        let same = provider.handle(json!({
            "op": "init",
            "config": init_config(dir.path())
        }));
        assert_eq!(same["status"], "ok", "{same}");
        let other = elastos_identity::derive_did(&[0x22; 32]).1;
        let again = tempfile::tempdir().unwrap();
        let response = provider.handle(json!({
            "op": "init",
            "config": {
                "base_path": again.path().to_string_lossy().to_string(),
                "extra": { "runtime_did": other }
            }
        }));
        assert_eq!(response["code"], "runtime_did_install_failed");
        let message = response["message"].as_str().unwrap();
        assert!(message.contains("already set"), "{message}");
        assert_ne!(
            message,
            "object helper spawn refused: no public runtime DID"
        );
    }

    #[cfg(unix)]
    #[test]
    fn init_refuses_when_the_device_key_can_be_opened() {
        let dir = tempfile::tempdir().unwrap();
        let identity = dir.path().join("identity");
        std::fs::create_dir(&identity).unwrap();
        std::fs::write(identity.join("device.key"), b"secret").unwrap();
        let mut provider = ObjectProviderProcess::new();
        let response = provider.handle(json!({
            "op": "init",
            "config": init_config(dir.path())
        }));
        assert_eq!(response["code"], "refused");
        let message = response["message"].as_str().unwrap();
        if cfg!(target_os = "linux") {
            assert_eq!(message, "object helper can open identity/device.key");
        } else {
            assert_eq!(
                message,
                "object helper can open or stat identity/device.key"
            );
        }
    }

    #[test]
    fn initialized_raw_provider_refuses_runtime_coordinated_content_ops() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider = ObjectProviderProcess::new();

        let init = provider.handle(json!({
            "op": "init",
            "config": init_config(dir.path())
        }));
        assert_eq!(init["status"], "ok", "{init}");

        let response = provider.handle(json!({
            "op": "publish",
            "principal_id": "alice",
            "uri": "localhost://Users/alice/Documents/file.txt"
        }));
        assert_eq!(response["status"], "error");
        assert_eq!(response["code"], "library_error");
        assert!(response["message"]
            .as_str()
            .unwrap()
            .contains("Runtime content coordinator"));
    }
}
