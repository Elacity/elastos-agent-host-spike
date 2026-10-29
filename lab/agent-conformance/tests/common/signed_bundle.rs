//! One signed fixture bundle for the tests that launch through the stand-in.
//!
//! The stand-in admits a bundle by its lab CID and checks the publisher's
//! name signature, so a caller needs the bundle bytes, a key and the accepted
//! publisher list. This one fixture gives those through the crate's own
//! `capsule_identity` and `elastos_identity` calls; it mints no grant.
//!
//! The bundle also declares its asks in `asks.json`, inside the signed bytes
//! (M1 check B2). The fixture replaces the committed file with one set: a
//! `read` and a `write` of `localhost://Public/resident-instances/shared.txt`,
//! the resource these journeys request, beside the committed file's asks. A
//! test that needs another declared set writes `asks.json` before it signs.

#![allow(dead_code)]

use capsule_identity::{checked_bundle, sign_bundle, NameSignature};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// The resource the shared journeys request through the route.
const SHARED_ASKS_RESOURCE: &str = "localhost://Public/resident-instances/shared.txt";

/// The committed `agent-host` fixture: a real bundle the walk accepts.
const AGENT_HOST_FILES: [(&str, &[u8]); 2] = [
    (
        "capsule.json",
        include_bytes!("../../../capsule-identity/fixtures/agent-host/capsule.json"),
    ),
    (
        "asks.json",
        include_bytes!("../../../capsule-identity/fixtures/agent-host/asks.json"),
    ),
];

/// The committed `content-sample` fixture: a real bundle the walk accepts
/// whose manifest `role` is `content`.
const CONTENT_FILES: [(&str, &[u8]); 2] = [
    (
        "capsule.json",
        include_bytes!("../../../capsule-identity/fixtures/content-sample/capsule.json"),
    ),
    (
        "sample.example",
        include_bytes!("../../../capsule-identity/fixtures/content-sample/sample.example"),
    ),
];

/// The manifest `name` of `AGENT_HOST_FILES`.
pub const SHARED_NAME: &str = "agent-host";

/// The manifest `name` of `CONTENT_FILES`.
pub const CONTENT_NAME: &str = "example-content";

/// One signed fixture bundle in a fresh tempdir, its accepted publisher and
/// the key that signed it.
pub struct SignedBundle {
    bundle: TempDir,
    key: SigningKey,
    accepted: Vec<String>,
}

impl SignedBundle {
    pub fn new() -> Self {
        Self::from_files(&AGENT_HOST_FILES)
    }

    /// The `content` bundle: `CONTENT_FILES`, signed by its own key, its
    /// accepted list holding that key alone.
    pub fn content() -> Self {
        Self::from_files(&CONTENT_FILES)
    }

    fn from_files(files: &[(&str, &[u8])]) -> Self {
        let bundle = TempDir::new().expect("make a bundle tempdir");
        write_files(bundle.path(), files);
        let key = SigningKey::generate(&mut OsRng);
        let accepted = vec![elastos_identity::encode_signing_key_did(&key)];
        SignedBundle {
            bundle,
            key,
            accepted,
        }
    }

    /// A second bundle: the same files plus one byte, so another lab CID, and
    /// the manifest `name` `name`, so a launch that reports one admitted name
    /// for every launch is caught.
    pub fn distinct(name: &str) -> Self {
        let second = Self::new();
        let manifest = second.path().join("capsule.json");
        let text = fs::read_to_string(&manifest).expect("read capsule.json");
        let name_key = format!("\"name\": \"{SHARED_NAME}\"");
        assert!(
            text.contains(&name_key) && text.contains("\"role\": \"app\""),
            "the committed fixture manifest holds {name_key} and the app role"
        );
        let renamed = text.replace(&name_key, &format!("\"name\": \"{name}\""));
        fs::write(&manifest, renamed).expect("rename the second bundle's manifest");
        let asks = second.path().join("asks.json");
        let mut bytes = fs::read(&asks).expect("read asks.json");
        bytes.push(b'\n');
        fs::write(&asks, &bytes).expect("change the second bundle");
        second
    }

    pub fn path(&self) -> &Path {
        self.bundle.path()
    }

    /// The printed lab CID of this bundle's bytes: identity, not a grant.
    pub fn cid(&self) -> String {
        checked_bundle(self.path())
            .expect("the walk names the fixture bundle")
            .cid()
            .to_string()
    }

    pub fn signature(&self) -> NameSignature {
        sign_bundle(&self.key, self.path()).expect("sign the fixture bundle")
    }

    pub fn accepted(&self) -> &[String] {
        &self.accepted
    }

    /// The launch body: one `cid` key, the printed lab CID.
    pub fn launch_body(&self) -> Value {
        json!({ "cid": self.cid() })
    }
}

fn write_files(root: &Path, files: &[(&str, &[u8])]) {
    for &(path, bytes) in files {
        let target: PathBuf = root.join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).expect("make a bundle folder");
        }
        fs::write(&target, bytes).expect("write a bundle file");
    }
    // The content fixture declares no asks: it never runs as code, so the one
    // admission refuses it on its role and the asks file does not apply.
    if !root.join("asks.json").is_file() {
        return;
    }
    let committed = fs::read(root.join("asks.json")).expect("read the committed asks");
    let mut asks: Value = serde_json::from_slice(&committed).expect("parse the committed asks");
    let listed = asks["asks"]
        .as_array_mut()
        .expect("the committed asks list asks");
    for kind in ["read", "write"] {
        listed.push(json!({ "kind": kind, "resource": SHARED_ASKS_RESOURCE }));
    }
    fs::write(
        root.join("asks.json"),
        serde_json::to_vec_pretty(&asks).expect("encode the fixture asks"),
    )
    .expect("write the fixture asks");
}
