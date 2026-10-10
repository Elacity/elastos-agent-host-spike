//! Startup Content restore walks the data directory for complete local
//! objects. Its heap must stay bounded however large the files under it are:
//! a Qwen-sized admitted model package once grew Home past 7 GB and the kernel
//! OOM-killed an 8 GB host. This binary owns its global allocator to measure it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::Arc;

use elastos_runtime::provider::{
    Provider, ProviderError, ProviderRegistry, ResourceRequest, ResourceResponse,
};
use elastos_server::content::ContentProvider;
use serde_json::{json, Value};
use sha2::Digest;
use tokio::sync::Mutex;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static LIMIT: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Counts live heap bytes and refuses growth past `LIMIT`, so a regression
/// fails this test instead of exhausting the host running it.
struct Counting;

fn reserve(bytes: usize) -> bool {
    let live = LIVE.fetch_add(bytes, Relaxed) + bytes;
    if live > LIMIT.load(Relaxed) {
        LIVE.fetch_sub(bytes, Relaxed);
        return false;
    }
    PEAK.fetch_max(live, Relaxed);
    true
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !reserve(layout.size()) {
            return std::ptr::null_mut();
        }
        let pointer = System.alloc(layout);
        if pointer.is_null() {
            LIVE.fetch_sub(layout.size(), Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        System.dealloc(pointer, layout);
        LIVE.fetch_sub(layout.size(), Relaxed);
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let old = layout.size();
        if size > old && !reserve(size - old) {
            return std::ptr::null_mut();
        }
        let moved = System.realloc(pointer, layout, size);
        if moved.is_null() {
            if size > old {
                LIVE.fetch_sub(size - old, Relaxed);
            }
        } else if size < old {
            LIVE.fetch_sub(old - size, Relaxed);
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Restore may hold small manifests and objects; never a large payload.
const HEAP_BOUND: usize = 16 * 1024 * 1024;
const CID: &str = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
// Sparse fixture files read as zeros; these are SHA-256 digests of N zero bytes.
const QWEN_WEIGHTS_BYTES: u64 = 1_117_320_736;
const QWEN_ZEROS_SHA256: &str = "8de2df505f2c46dd3b893364749702df7863e3183de4f386e868373848a157e9";
// One byte over Content's 64 MiB JSON import bound.
const OVER_IMPORT_BOUND_BYTES: u64 = 64 * 1024 * 1024 + 1;
const OVER_IMPORT_ZEROS_SHA256: &str =
    "91990977345985aaf03af1358f4f989d7eaf985b58529efb72f613c588f6599a";

enum Body<'a> {
    Bytes(&'a [u8]),
    Zeros(u64, &'a str),
}

/// A complete local object: every file matches its manifest entry.
fn write_object(dir: &Path, files: &[(&str, Body<'_>)]) {
    std::fs::create_dir_all(dir).unwrap();
    let mut entries = Vec::new();
    for (path, body) in files {
        let (size, sha256) = match body {
            Body::Bytes(bytes) => {
                std::fs::write(dir.join(path), bytes).unwrap();
                (
                    bytes.len() as u64,
                    format!("{:x}", sha2::Sha256::digest(bytes)),
                )
            }
            Body::Zeros(size, sha256) => {
                let file = std::fs::File::create(dir.join(path)).unwrap();
                file.set_len(*size).unwrap();
                (*size, sha256.to_string())
            }
        };
        entries.push(json!({"path": path, "sha256": sha256, "size": size}));
    }
    let manifest = json!({
        "schema": "elastos.content.object.manifest/v1",
        "kind": "directory",
        "content_digest": format!("sha256:{}", "0".repeat(64)),
        "files": entries,
    });
    std::fs::write(
        dir.join("_elastos_object.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
}

#[derive(Default)]
struct Ipfs {
    imported: Mutex<Vec<Vec<String>>>,
}

#[async_trait::async_trait]
impl Provider for Ipfs {
    async fn handle(&self, _: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider("raw operations only".into()))
    }

    fn schemes(&self) -> Vec<&'static str> {
        Vec::new()
    }

    fn name(&self) -> &'static str {
        "restore-memory-ipfs"
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        if request["op"] == "add_directory" {
            let paths = request["files"].as_array().unwrap().iter();
            self.imported.lock().await.push(
                paths
                    .map(|file| file["path"].as_str().unwrap().to_owned())
                    .collect(),
            );
        }
        Ok(json!({"status": "ok", "data": {"cid": CID}}))
    }
}

#[tokio::test]
async fn startup_restore_skips_model_packages_with_bounded_heap() {
    let data = tempfile::tempdir().unwrap();
    // A small held object proves the restore walk ran and still imports.
    write_object(
        &data.path().join("held-object"),
        &[("index.md", Body::Bytes(b"hello object"))],
    );
    // Runtime-private admitted model packages, laid out as preparation admits
    // them. Neither the Qwen-sized nor a small one is a Content replica.
    let models = data.path().join("model-preparation");
    write_object(
        &models.join(format!("admitted-{}", "a".repeat(64))),
        &[
            ("capsule.json", Body::Bytes(br#"{"name":"qwen"}"#)),
            (
                "weights.gguf",
                Body::Zeros(QWEN_WEIGHTS_BYTES, QWEN_ZEROS_SHA256),
            ),
        ],
    );
    write_object(
        &models.join(format!("admitted-{}", "b".repeat(64))),
        &[
            ("capsule.json", Body::Bytes(br#"{"name":"tiny"}"#)),
            ("weights.gguf", Body::Bytes(b"GGUF\x03\0\0\0")),
        ],
    );
    // An ordinary object too large for the JSON provider import.
    write_object(
        &data.path().join("large-object"),
        &[(
            "media.bin",
            Body::Zeros(OVER_IMPORT_BOUND_BYTES, OVER_IMPORT_ZEROS_SHA256),
        )],
    );
    let registry = Arc::new(ProviderRegistry::new());
    let ipfs = Arc::new(Ipfs::default());
    registry
        .register_sub_provider("ipfs", ipfs.clone())
        .await
        .unwrap();
    let content = Arc::new(ContentProvider::new(
        data.path().to_path_buf(),
        Arc::downgrade(&registry),
    ));

    let baseline = LIVE.load(Relaxed);
    PEAK.store(baseline, Relaxed);
    LIMIT.store(baseline + 16 * HEAP_BOUND, Relaxed);
    content.restore_complete_local_objects().await;
    LIMIT.store(usize::MAX, Relaxed);

    let growth = PEAK.load(Relaxed) - baseline;
    assert!(
        growth <= HEAP_BOUND,
        "restore heap grew {growth} bytes, bound {HEAP_BOUND}"
    );
    assert_eq!(
        *ipfs.imported.lock().await,
        [["index.md", "_elastos_object.json"]]
    );
}
