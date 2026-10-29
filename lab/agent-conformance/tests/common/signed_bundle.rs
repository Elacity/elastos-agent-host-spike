//! One signed fixture bundle for the tests that launch through the stand-in.
//!
//! The stand-in admits a bundle by its lab CID and checks the publisher's
//! name signature, so a caller needs the bundle bytes, a key and the accepted
//! publisher list. This one fixture gives those through the crate's own
//! `capsule_identity` and `elastos_identity` calls; it mints no grant.

#![allow(dead_code)]

use capsule_identity::{checked_bundle, sign_bundle, NameSignature};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

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

/// The manifest `name` of `AGENT_HOST_FILES`.
pub const SHARED_NAME: &str = "agent-host";

/// One signed fixture bundle in a fresh tempdir, its accepted publisher and
/// the key that signed it.
pub struct SignedBundle {
    bundle: TempDir,
    key: SigningKey,
    accepted: Vec<String>,
}

impl SignedBundle {
    pub fn new() -> Self {
        let bundle = TempDir::new().expect("make a bundle tempdir");
        write_agent_host(bundle.path());
        let key = SigningKey::generate(&mut OsRng);
        let accepted = vec![elastos_identity::encode_signing_key_did(&key)];
        SignedBundle {
            bundle,
            key,
            accepted,
        }
    }

    /// A second bundle: the same files plus one byte, so another lab CID.
    pub fn distinct() -> Self {
        let second = Self::new();
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

fn write_agent_host(root: &Path) {
    for (path, bytes) in AGENT_HOST_FILES {
        let target: PathBuf = root.join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).expect("make a bundle folder");
        }
        fs::write(&target, bytes).expect("write a bundle file");
    }
}
