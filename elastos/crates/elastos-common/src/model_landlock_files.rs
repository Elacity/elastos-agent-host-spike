//! Exact files a local model start may name.
//!
//! Landlock attaches these as one rule per existing inode. A signed manifest
//! that omits `local-model-files` gets none of them. The slot below is set on
//! the thread that builds the plan and cleared before that thread waits.
//!
//! AF_UNIX `connect` is `LANDLOCK_ACCESS_FS_WRITE_FILE` on the socket inode
//! that already exists. `LANDLOCK_ACCESS_NET_CONNECT_TCP` is TCP only and does
//! not mediate this socket. llama-server b10516 binds `--host` itself, so a
//! listen descriptor passed by the Runtime would be unused. The Runtime creates
//! one directory per offer before the child runs and grants `MAKE_SOCK` and
//! `REMOVE_FILE` on that directory only. The engine binds
//! `{index}.listen/engine.sock` there. The broker runs outside the ruleset and
//! connects to that same path. The listen inode is not granted `WRITE_FILE`,
//! so a confined process cannot connect to it. One shared ruleset still lists
//! every admitted offer's directory.
//!
//! A library gets `READ_FILE` only. `EXECUTE` stays on the admitted engine.
//! The engine listen socket is created in its own directory. That directory
//! gets `MAKE_SOCK|REMOVE_FILE` and nothing else, so the broker socket beside
//! it cannot be replaced. `/dev/null`, `/dev/urandom`, and `/proc` are absent.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

pub const MODEL_RULE: &str = r#"(allow file-read* (literal (param "MODEL")))"#;
pub const ENGINE_RULE: &str = r#"(allow process-exec (literal (param "ENGINE")))"#;
pub const LIBRARY_RULE: &str = r#"(allow file-read* (literal (param "ENGINE_LIBRARY")))"#;
pub const SOCKET_RULE: &str =
    r#"(allow file-read* file-write-data (literal (param "ENGINE_SOCKET")))"#;

/// `LANDLOCK_ACCESS_FS_READ_FILE`.
pub const READ_FILE: u64 = 1 << 2;
/// `LANDLOCK_ACCESS_FS_WRITE_FILE`. This is the AF_UNIX connect right.
pub const WRITE_FILE: u64 = 1 << 1;
/// `LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE`.
pub const BINARY: u64 = (1 << 0) | READ_FILE;
/// `MAKE_SOCK` on a directory. The engine binds its listen socket here.
pub const MAKE_SOCK: u64 = 1 << 9;
/// `REMOVE_FILE` on that same directory, so a stale listen socket can be unlinked.
pub const REMOVE_FILE: u64 = 1 << 5;
/// The engine listen directory. No read, no write, no create of other kinds.
pub const LISTEN_DIR: u64 = MAKE_SOCK | REMOVE_FILE;

pub const MAX_LOCAL_OFFERS: usize = 2;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalModelFiles {
    pub models: Vec<PathBuf>,
    pub engines: Vec<PathBuf>,
    pub libraries: Vec<PathBuf>,
    pub sockets: Vec<PathBuf>,
    pub listen_dirs: Vec<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedLocal {
    pub files: LocalModelFiles,
    pub offer_ids: Vec<String>,
    pub engine_2: PathBuf,
    pub model_2: PathBuf,
}

#[derive(Debug)]
pub enum AdmitError {
    Io(std::io::Error),
    Rejected(String),
}

pub struct ClearGuard;

impl Drop for ClearGuard {
    fn drop(&mut self) {
        clear();
    }
}

thread_local! {
    static ADMITTED: RefCell<LocalModelFiles> = RefCell::new(LocalModelFiles::default());
}

pub fn install(files: LocalModelFiles) {
    ADMITTED.with(|slot| *slot.borrow_mut() = files);
}

pub fn clear() {
    ADMITTED.with(|slot| *slot.borrow_mut() = LocalModelFiles::default());
}

pub fn clear_on_drop() -> ClearGuard {
    ClearGuard
}

pub fn broker_socket_paths(base: &Path, count: usize) -> Vec<PathBuf> {
    let dir = base.join("providers/model-provider/sockets");
    (0..count)
        .map(|index| dir.join(format!("{index}.sock")))
        .collect()
}

pub fn socket_directory(base: &Path) -> PathBuf {
    base.join("providers/model-provider/sockets")
}

/// `{dir}/{index}.listen`, the only directory where offer `index` may bind.
pub fn engine_listen_dir(base: &Path, index: usize) -> PathBuf {
    socket_directory(base).join(format!("{index}.listen"))
}

/// The listen socket the pinned engine binds with `--host`. One inode, created
/// by the engine inside the directory the Runtime made beforehand.
pub fn engine_listen_socket(base: &Path, index: usize) -> PathBuf {
    engine_listen_dir(base, index).join("engine.sock")
}

/// Create the per-offer listen directory. Mode 0700, not a symlink. The broker
/// socket stays in the parent directory and is not created here.
pub fn prepare_listen_dir(base: &Path, index: usize) -> std::io::Result<PathBuf> {
    let dir = engine_listen_dir(base, index);
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        let meta = std::fs::symlink_metadata(&dir)?;
        if meta.file_type().is_symlink()
            || !meta.is_dir()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o077 != 0
        {
            return Err(std::io::Error::other("unsafe engine listen directory"));
        }
    }
    Ok(engine_listen_socket(base, index))
}

/// `Some` when `form` is one of the four local-model rules. An empty list
/// means the rule is admitted and no file was installed (a hosted start).
pub fn grants_for(form: &str) -> Option<Vec<(&'static str, PathBuf, u64)>> {
    ADMITTED.with(|slot| {
        let files = slot.borrow();
        let grants = match form {
            MODEL_RULE => files
                .models
                .iter()
                .map(|path| ("MODEL", path.clone(), READ_FILE))
                .collect(),
            ENGINE_RULE => files
                .engines
                .iter()
                .map(|path| ("ENGINE", path.clone(), BINARY))
                .collect(),
            LIBRARY_RULE => files
                .libraries
                .iter()
                .map(|path| ("ENGINE_LIBRARY", path.clone(), READ_FILE))
                .collect(),
            SOCKET_RULE => {
                let mut grants: Vec<_> = files
                    .sockets
                    .iter()
                    .map(|path| ("ENGINE_SOCKET", path.clone(), WRITE_FILE))
                    .collect();
                grants.extend(
                    files
                        .listen_dirs
                        .iter()
                        .map(|path| ("ENGINE_LISTEN", path.clone(), LISTEN_DIR)),
                );
                grants
            }
            _ => return None,
        };
        Some(grants)
    })
}

/// Admit at most two local offers. `selected` is the engine, weights, and
/// bundle the caller already resolved. Linux passes `None` and the first
/// offer's engine parent is the bundle.
#[cfg(unix)]
pub fn admit_offers(
    base: &Path,
    offers: &[serde_json::Value],
    extension: &str,
    selected: Option<(&Path, &Path, &Path)>,
) -> Result<AdmittedLocal, AdmitError> {
    let local: Vec<_> = offers
        .iter()
        .filter(|offer| {
            offer
                .pointer("/adapter/kind")
                .and_then(|value| value.as_str())
                == Some("local_llama_cpp_text")
        })
        .collect();
    if local.len() > MAX_LOCAL_OFFERS {
        return Err(AdmitError::Rejected("too many local model offers".into()));
    }
    let (engine, model, bundle) = match selected {
        Some((engine, model, bundle)) => (
            engine.to_path_buf(),
            model.to_path_buf(),
            bundle.to_path_buf(),
        ),
        None if local.is_empty() => {
            return Ok(AdmittedLocal {
                files: LocalModelFiles::default(),
                offer_ids: Vec::new(),
                engine_2: PathBuf::new(),
                model_2: PathBuf::new(),
            });
        }
        None => {
            let engine = offer_path(
                local[0],
                "/adapter/engine/path",
                "model engine path unavailable",
            )?;
            let model = offer_path(
                local[0],
                "/adapter/model/path",
                "model weights path unavailable",
            )?;
            let bundle = engine
                .parent()
                .ok_or_else(|| AdmitError::Rejected("model engine directory unavailable".into()))?
                .to_path_buf();
            (engine, model, bundle)
        }
    };
    if !file_inside(base, &engine, true)
        || !file_inside(base, &bundle, false)
        || !engine.starts_with(&bundle)
    {
        return Err(AdmitError::Rejected("unsafe model artifact path".into()));
    }
    if local.is_empty() {
        if !file_inside(base, &model, true) {
            return Err(AdmitError::Rejected("unsafe model artifact path".into()));
        }
        return Ok(AdmittedLocal {
            files: LocalModelFiles::default(),
            offer_ids: Vec::new(),
            engine_2: engine,
            model_2: model,
        });
    }
    let mut offer_ids = Vec::with_capacity(local.len());
    let mut seen = BTreeSet::new();
    let mut models = Vec::new();
    let mut engines = Vec::new();
    for offer in &local {
        let id = offer
            .get("id")
            .and_then(|value| value.as_str())
            .filter(|id| !id.is_empty())
            .ok_or_else(|| AdmitError::Rejected("local offer id unavailable".into()))?;
        if !seen.insert(id.to_string()) {
            return Err(AdmitError::Rejected("duplicate local offer id".into()));
        }
        offer_ids.push(id.to_string());
        let offer_engine = offer_path(
            offer,
            "/adapter/engine/path",
            "model engine path unavailable",
        )?;
        let offer_model = offer_path(
            offer,
            "/adapter/model/path",
            "model weights path unavailable",
        )?;
        if !file_inside(base, &offer_engine, true)
            || !offer_engine.starts_with(&bundle)
            || !file_inside(base, &offer_model, true)
        {
            return Err(AdmitError::Rejected("unsafe model artifact path".into()));
        }
        engines.push(offer_engine);
        models.push(offer_model);
    }
    if engines[0] != engine || models[0] != model {
        return Err(AdmitError::Rejected(
            "model offer paths differ from the admitted start".into(),
        ));
    }
    for weights in &models {
        preparation_file(base, weights)?;
        no_sidecar(weights)?;
    }
    bundle_layout(base, &bundle)?;
    let mut libraries = Vec::new();
    let mut scanned = BTreeSet::new();
    for engine_path in &engines {
        let directory = engine_path
            .parent()
            .ok_or_else(|| AdmitError::Rejected("model engine directory unavailable".into()))?;
        if !scanned.insert(directory.to_path_buf()) {
            continue;
        }
        libraries.extend(admitted_libraries(base, engine_path, extension)?);
    }
    libraries.sort();
    libraries.dedup();
    let engine_2 = engines.get(1).unwrap_or(&engines[0]).clone();
    let model_2 = models.get(1).unwrap_or(&models[0]).clone();
    Ok(AdmittedLocal {
        files: LocalModelFiles {
            models,
            engines,
            libraries,
            sockets: Vec::new(),
            listen_dirs: Vec::new(),
        },
        offer_ids,
        engine_2,
        model_2,
    })
}

#[cfg(unix)]
fn offer_path(
    offer: &serde_json::Value,
    pointer: &str,
    missing: &str,
) -> Result<PathBuf, AdmitError> {
    offer
        .pointer(pointer)
        .and_then(|value| value.as_str())
        .map(PathBuf::from)
        .ok_or_else(|| AdmitError::Rejected(missing.into()))
}

#[cfg(unix)]
fn file_inside(base: &Path, path: &Path, file: bool) -> bool {
    path.starts_with(base)
        && std::fs::canonicalize(path).ok().as_deref() == Some(path)
        && std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file() == file)
}

#[cfg(unix)]
fn preparation_file(base: &Path, model: &Path) -> Result<(), AdmitError> {
    let relative = model
        .strip_prefix(base.join("model-preparation"))
        .map_err(|_| AdmitError::Rejected("model preparation path is not admitted".into()))?;
    let mut parts = relative.components();
    let admission = parts.next().and_then(|part| match part {
        Component::Normal(name) => name.to_str()?.strip_prefix("admitted-"),
        _ => None,
    });
    let file = matches!(parts.next(), Some(Component::Normal(_)));
    if parts.next().is_some()
        || !file
        || !admission.is_some_and(|id| {
            id.len() == 64
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        return Err(AdmitError::Rejected(
            "model preparation path is not admitted".into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn no_sidecar(model: &Path) -> Result<(), AdmitError> {
    let name = model
        .file_name()
        .ok_or_else(|| AdmitError::Rejected("model preparation path is not admitted".into()))?;
    let parent = model
        .parent()
        .ok_or_else(|| AdmitError::Rejected("model preparation path is not admitted".into()))?;
    for entry in std::fs::read_dir(parent).map_err(AdmitError::Io)? {
        if entry.map_err(AdmitError::Io)?.file_name() != name {
            return Err(AdmitError::Rejected("unlisted model sidecar".into()));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn bundle_layout(base: &Path, bundle: &Path) -> Result<(), AdmitError> {
    let relative = bundle
        .strip_prefix(base.join("libexec/llama.cpp"))
        .map_err(|_| AdmitError::Rejected("unsafe model engine bundle".into()))?;
    if relative.components().count() != 2
        || !relative
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err(AdmitError::Rejected("unsafe model engine bundle".into()));
    }
    Ok(())
}

#[cfg(unix)]
fn admitted_libraries(
    base: &Path,
    engine: &Path,
    extension: &str,
) -> Result<Vec<PathBuf>, AdmitError> {
    use crate::model_engine_receipt::{
        model_engine_receipt_entries, model_engine_receipt_file_matches,
    };
    let engine_dir = engine
        .parent()
        .ok_or_else(|| AdmitError::Rejected("model engine directory unavailable".into()))?;
    let mut on_disk = Vec::new();
    for entry in std::fs::read_dir(engine_dir).map_err(AdmitError::Io)? {
        let path = entry.map_err(AdmitError::Io)?.path();
        if path.extension().and_then(|value| value.to_str()) == Some(extension) {
            on_disk.push(path);
        }
    }
    let receipt = engine_dir.join(".elastos-engine.json");
    if on_disk.is_empty() && !receipt.is_file() {
        return Ok(Vec::new());
    }
    let (bundle, entries) = model_engine_receipt_entries(base, engine).map_err(receipt_error)?;
    for path in &on_disk {
        let name = path
            .strip_prefix(&bundle)
            .ok()
            .and_then(|path| path.to_str())
            .ok_or_else(|| AdmitError::Rejected("invalid model engine file".into()))?;
        let matching: Vec<_> = entries
            .iter()
            .filter(|entry| entry["path"].as_str() == Some(name))
            .collect();
        if matching.len() != 1 {
            return Err(AdmitError::Rejected("unlisted model engine file".into()));
        }
        let entry = matching[0];
        let metadata = std::fs::symlink_metadata(path).map_err(AdmitError::Io)?;
        if metadata.file_type().is_symlink() {
            let target = std::fs::read_link(path).map_err(AdmitError::Io)?;
            if entry["type"] != "symlink"
                || entry["target"].as_str() != target.to_str()
                || target.components().count() != 1
                || !target
                    .components()
                    .all(|part| matches!(part, Component::Normal(_)))
            {
                return Err(AdmitError::Rejected("changed model engine file".into()));
            }
        } else if !model_engine_receipt_file_matches(path, entry).map_err(receipt_error)? {
            return Err(AdmitError::Rejected("changed model engine file".into()));
        }
        let canonical = std::fs::canonicalize(path).map_err(AdmitError::Io)?;
        if !canonical.starts_with(engine_dir)
            || !std::fs::metadata(&canonical).is_ok_and(|metadata| metadata.is_file())
        {
            return Err(AdmitError::Rejected("unsafe model engine file".into()));
        }
        if metadata.file_type().is_symlink() {
            let target = canonical
                .strip_prefix(&bundle)
                .ok()
                .and_then(|path| path.to_str())
                .ok_or_else(|| AdmitError::Rejected("unsafe model engine file".into()))?;
            let matching: Vec<_> = entries
                .iter()
                .filter(|entry| entry["path"].as_str() == Some(target))
                .collect();
            if matching.len() != 1
                || !model_engine_receipt_file_matches(&canonical, matching[0])
                    .map_err(receipt_error)?
            {
                return Err(AdmitError::Rejected("changed model engine file".into()));
            }
        }
    }
    let mut granted = Vec::new();
    for entry in &entries {
        if entry["type"] != "file" {
            continue;
        }
        let name = entry["path"]
            .as_str()
            .ok_or_else(|| AdmitError::Rejected("invalid model engine file".into()))?;
        let path = bundle.join(name);
        if !path.is_file() {
            return Err(AdmitError::Rejected(format!(
                "missing admitted library {name}"
            )));
        }
        if !model_engine_receipt_file_matches(&path, entry).map_err(receipt_error)? {
            return Err(AdmitError::Rejected("changed model engine file".into()));
        }
        let canonical = std::fs::canonicalize(&path).map_err(AdmitError::Io)?;
        if !canonical.starts_with(&bundle)
            || !std::fs::metadata(&canonical).is_ok_and(|metadata| metadata.is_file())
        {
            return Err(AdmitError::Rejected("unsafe model engine file".into()));
        }
        granted.push(canonical);
    }
    Ok(granted)
}

#[cfg(unix)]
fn receipt_error(error: crate::model_engine_receipt::ModelReceiptError) -> AdmitError {
    use crate::model_engine_receipt::ModelReceiptError;
    match error {
        ModelReceiptError::Io(error) => AdmitError::Io(error),
        ModelReceiptError::Rejected(reason) => AdmitError::Rejected(reason.into()),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn hex_id(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn tree(root: &Path, id: &str, name: &str) -> (PathBuf, PathBuf, PathBuf) {
        let bundle = root.join("libexec/llama.cpp/test/platform");
        std::fs::create_dir_all(&bundle).unwrap();
        let engine = bundle.join("llama-server");
        std::fs::write(&engine, b"engine").unwrap();
        let admitted = root.join(format!("model-preparation/admitted-{id}"));
        std::fs::create_dir_all(&admitted).unwrap();
        let model = admitted.join(name);
        std::fs::write(&model, b"gguf").unwrap();
        (engine, model, bundle)
    }

    #[test]
    fn a_missing_admitted_library_is_refused_by_name() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let (engine, model, bundle) = tree(&base, &hex_id(1), "weights.gguf");
        let receipt = bundle.join(".elastos-engine.json");
        std::fs::write(
            &receipt,
            br#"{"schema":"elastos.local-model-engine/v2","entries":[{"path":"libmissing.so","type":"file","sha256":"sha256:00"}]}"#,
        )
        .unwrap();
        std::fs::set_permissions(&receipt, std::fs::Permissions::from_mode(0o400)).unwrap();
        let offers = serde_json::json!([{
            "id": "one",
            "adapter": {
                "kind": "local_llama_cpp_text",
                "engine": {"path": engine},
                "model": {"path": model}
            }
        }]);
        let error = admit_offers(
            &base,
            offers.as_array().unwrap(),
            "so",
            Some((&engine, &model, &bundle)),
        )
        .expect_err("the named library is absent");
        match error {
            AdmitError::Rejected(reason) => {
                assert_eq!(reason, "missing admitted library libmissing.so")
            }
            AdmitError::Io(error) => panic!("io before the name: {error}"),
        }
    }

    #[test]
    fn a_second_offer_is_admitted_and_a_third_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let (engine, model, bundle) = tree(&base, &hex_id(1), "weights.gguf");
        let model_2_dir = base.join(format!("model-preparation/admitted-{}", hex_id(2)));
        std::fs::create_dir_all(&model_2_dir).unwrap();
        let model_2 = model_2_dir.join("other.gguf");
        std::fs::write(&model_2, b"gguf").unwrap();
        let engine_2 = bundle.join("llama-server-b");
        std::fs::write(&engine_2, b"engine").unwrap();
        let two = serde_json::json!([
            {"id":"one","adapter":{"kind":"local_llama_cpp_text","engine":{"path":engine},"model":{"path":model}}},
            {"id":"two","adapter":{"kind":"local_llama_cpp_text","engine":{"path":engine_2},"model":{"path":model_2}}}
        ]);
        let admitted = admit_offers(
            &base,
            two.as_array().unwrap(),
            "dylib",
            Some((&engine, &model, &bundle)),
        )
        .expect("two offers");
        assert_eq!(admitted.files.models, vec![model.clone(), model_2.clone()]);
        assert_eq!(
            admitted.files.engines,
            vec![engine.clone(), engine_2.clone()]
        );
        assert_eq!(admitted.engine_2, engine_2);
        assert_eq!(admitted.model_2, model_2);
        assert!(admitted.files.libraries.is_empty());
        let three = serde_json::json!([
            {"id":"one","adapter":{"kind":"local_llama_cpp_text","engine":{"path":engine},"model":{"path":model}}},
            {"id":"two","adapter":{"kind":"local_llama_cpp_text","engine":{"path":engine_2},"model":{"path":model_2}}},
            {"id":"three","adapter":{"kind":"local_llama_cpp_text","engine":{"path":engine},"model":{"path":model}}}
        ]);
        let error = admit_offers(
            &base,
            three.as_array().unwrap(),
            "dylib",
            Some((&engine, &model, &bundle)),
        )
        .expect_err("three offers");
        match error {
            AdmitError::Rejected(reason) => assert_eq!(reason, "too many local model offers"),
            AdmitError::Io(error) => panic!("{error}"),
        }
    }
}
