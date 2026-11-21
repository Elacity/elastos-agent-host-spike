//! Shared fixture and source readers for the stand-in matrix.
//!
//! Needles are built at run time so this file does not hold the stand-in
//! scheme as one literal, and does not hold the server call texts that
//! source-scanning tests count.

use std::fs;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use elastos_common::{
    AffordanceApprovalMode, CapsuleAffordanceDescriptor, CapsuleManifest, SCHEMA_V1,
};
use elastos_runtime::provider::{Provider, ProviderError, ResourceRequest, ResourceResponse};
use elastos_runtime::signature::{hash_content, SignatureVerifier, SigningKey};

pub fn join(parts: &[&str]) -> String {
    parts.concat()
}

/// The stand-in scheme, built from parts so the source has no one literal.
pub fn scheme() -> String {
    join(&["stand", "in-", "swap"])
}

pub fn provider_name() -> String {
    format!("{}-provider", scheme())
}

pub fn app_name() -> String {
    format!("{}-app", scheme())
}

pub fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn repo_root() -> PathBuf {
    manifest_dir()
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

pub fn fixture(kind: &str) -> PathBuf {
    manifest_dir().join("fixtures").join(kind)
}

pub fn read_text(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

pub fn load_manifest(kind: &str) -> CapsuleManifest {
    let path = fixture(kind).join("capsule.json");
    let text = read_text(&path);
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("parse {}: {err}", path.display()))
}

pub fn entry_bytes(kind: &str, file_name: &str) -> Vec<u8> {
    fs::read(fixture(kind).join(file_name))
        .unwrap_or_else(|err| panic!("read entry {kind}/{file_name}: {err}"))
}

/// Public test seed already used in this repo: thirty-two bytes of value 7.
/// Disposable. It is not a publisher key.
pub fn lab_test_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

pub fn content_hash_hex(bytes: &[u8]) -> String {
    hash_content(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn base58_btc(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
    let mut digits = vec![0u8; bytes.len() * 138 / 100 + 1];
    let mut len = 0usize;
    for &byte in bytes {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut().take(len) {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits[len] = (carry % 58) as u8;
            len += 1;
            carry /= 58;
        }
    }
    let mut out = String::new();
    for _ in 0..zeros {
        out.push('1');
    }
    for digit in digits[..len].iter().rev() {
        out.push(ALPHABET[*digit as usize] as char);
    }
    out
}

/// `did:key` of `key`, same shape as the repo encoder: multicodec ed25519
/// public key `0xed 0x01`, then base58btc, with the `did:key:z` prefix.
pub fn signer_did(key: &SigningKey) -> String {
    let mut raw = Vec::with_capacity(34);
    raw.extend_from_slice(&[0xed, 0x01]);
    raw.extend_from_slice(key.verifying_key().as_bytes());
    format!("did:key:z{}", base58_btc(&raw))
}

pub fn assert_base58_vectors() {
    assert_eq!(base58_btc(b""), "");
    assert_eq!(base58_btc(&[0]), "1");
    assert_eq!(base58_btc(b"hello"), "Cn8eVZg");
    assert_eq!(base58_btc(&hex_bytes("0000287fb4cd")), "11233QC4");
}

fn hex_bytes(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

pub fn identity(kind: &str) -> serde_json::Value {
    let path = fixture(kind).join("identity.json");
    serde_json::from_str(&read_text(&path))
        .unwrap_or_else(|err| panic!("parse {}: {err}", path.display()))
}

pub fn verify_signed(kind: &str, entry_name: &str) {
    let manifest = load_manifest(kind);
    assert_eq!(manifest.schema, SCHEMA_V1);
    manifest
        .validate()
        .unwrap_or_else(|err| panic!("{kind} validate: {err}"));
    let bytes = entry_bytes(kind, entry_name);
    let hash = hash_content(&bytes);
    let recorded = identity(kind);
    assert_eq!(
        recorded["content_sha256"].as_str().unwrap(),
        content_hash_hex(&bytes),
        "{kind} content hash"
    );
    let key = lab_test_key();
    let did = signer_did(&key);
    assert_eq!(did.len(), 56);
    assert!(did.starts_with("did:key:z6Mk"));
    assert_eq!(
        recorded["signer_did"].as_str().unwrap(),
        did,
        "{kind} signer"
    );
    let mut verifier = SignatureVerifier::new();
    verifier
        .add_trusted_key(key.verifying_key())
        .expect("test key is not weak");
    let matched = verifier
        .verify_capsule(&manifest, &hash)
        .unwrap_or_else(|err| panic!("{kind} signature: {err}"));
    assert_eq!(matched, Some(key.verifying_key()), "{kind} signature");
}

pub fn server_file(relative: &str) -> String {
    read_text(&repo_root().join(relative))
}

mod scan;
pub use scan::{
    action_variant_counts, call_inventory, call_with_last_arg, calls_in_functions,
    const_expression, field_reads, ident_inventory, manifest_struct_fields, provides_readers,
    register_signature_returns_nothing, registration_sites, repo_call_inventory, sites_json,
    validate_fns_mention,
};

/// Body of the item whose signature line contains `sig`, up to the next
/// top-level item. A following item is not part of the body.
pub fn item_body<'a>(source: &'a str, sig: &str) -> &'a str {
    let start = source
        .find(sig)
        .unwrap_or_else(|| panic!("missing item {sig}"));
    let after = start + sig.len();
    let rest = &source[after..];
    let mut end = rest.len();
    for marker in [
        "\npub(",
        "\npub fn ",
        "\npub async fn ",
        "\nfn ",
        "\nasync fn ",
        "\npub const ",
        "\nconst ",
        "\n#[",
        "\npub struct ",
        "\nstruct ",
        "\npub enum ",
        "\nenum ",
        "\nimpl ",
        "\npub mod ",
        "\nmod ",
        "\npub use ",
        "\nuse ",
        "\npub static ",
        "\nstatic ",
        "\npub trait ",
        "\ntrait ",
        "\npub type ",
        "\ntype ",
    ] {
        if let Some(found) = rest.find(marker) {
            end = end.min(found);
        }
    }
    &source[start..after + end]
}

pub fn walk_text_files(root: &Path) -> Vec<(PathBuf, String)> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let name = path
            .file_name()
            .and_then(|text| text.to_str())
            .unwrap_or("");
        if name == "target" || name == "target-build" || name == ".git" {
            continue;
        }
        let meta = fs::symlink_metadata(&path).unwrap_or_else(|err| {
            panic!("stat {}: {err}", path.display());
        });
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            for entry in fs::read_dir(&path).unwrap_or_else(|err| {
                panic!("read dir {}: {err}", path.display());
            }) {
                stack.push(entry.expect("dir entry").path());
            }
            continue;
        }
        if !meta.is_file() {
            continue;
        }
        let bytes = fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        if let Ok(text) = String::from_utf8(bytes) {
            found.push((path, text));
        }
    }
    found
}

pub struct MarkerProvider {
    pub scheme: &'static str,
    pub marker: &'static str,
}

#[async_trait]
impl Provider for MarkerProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Ok(ResourceResponse::Data(self.marker.as_bytes().to_vec()))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec![self.scheme]
    }

    fn name(&self) -> &'static str {
        self.marker
    }
}

pub fn answer(response: ResourceResponse) -> Vec<u8> {
    match response {
        ResourceResponse::Data(bytes) => bytes,
        other => panic!("unexpected response {other:?}"),
    }
}

pub fn user_approval_method(manifest: &CapsuleManifest) -> &CapsuleAffordanceDescriptor {
    let methods: Vec<_> = manifest
        .interfaces
        .iter()
        .flat_map(|interface| interface.methods.iter())
        .filter(|method| method.approval == AffordanceApprovalMode::User)
        .collect();
    assert_eq!(methods.len(), 1, "one operation marked approval user");
    methods[0]
}
