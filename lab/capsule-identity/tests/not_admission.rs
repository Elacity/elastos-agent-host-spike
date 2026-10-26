//! M1 check B1: verify is not admit. A valid test-key signature over the
//! `agent-host` fixture verifies, and that success leaves nothing a grant or
//! an admission could come from. Admission and grants are the Runtime's
//! (PRINCIPLES 13 and 8); no test here models either.
mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use capsule_identity::{lab_cid, sign_bundle, verify_name_signature, Refusal, MANIFEST_FILE};
use common::*;
use elastos_common::CapsuleManifest;

/// The names in the folder `parent`, sorted.
fn listing(parent: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(parent)
        .unwrap_or_else(|error| panic!("list {}: {error}", parent.display()))
        .map(|entry| {
            entry
                .expect("read a folder entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// After `step`, the bundle's lab CID and its parent folder's listing are
/// what they were before: no byte the lab CID covers changed, and no entry
/// was added next to the bundle.
fn assert_untouched(step: &str, bundle: &Path, cid: &str, before: &[String]) {
    let parent = bundle.parent().expect("the bundle has a parent folder");
    let after = listing(parent);
    if let Some(name) = after.iter().find(|name| !before.contains(name)) {
        panic!("{step} wrote {name} next to the bundle");
    }
    assert_eq!(after, before, "{step} removed an entry next to the bundle");
    let now = lab_cid(bundle)
        .unwrap_or_else(|refusal| panic!("{step} changed the bundle: {refusal}"))
        .to_string();
    assert_eq!(now, cid, "{step} changed the bundle");
}

/// The bundle's `capsule.json`, parsed with the Runtime's `CapsuleManifest`.
fn runtime_manifest(bundle: &Path) -> CapsuleManifest {
    let bytes = fs::read(bundle.join(MANIFEST_FILE)).expect("read capsule.json");
    serde_json::from_slice(&bytes).expect("the Runtime's CapsuleManifest parses capsule.json")
}

/// The answer refuses `did` with 004's accepted-list reason.
fn assert_signer_not_accepted(answer: Result<(), Refusal>, did: &str, list: &str) {
    let Err(refusal) = answer else {
        panic!("the check with {list} was not refused: a success left a standing approval")
    };
    assert_eq!(
        refusal,
        Refusal::SignerNotAccepted {
            did: did.to_owned()
        },
        "the check with {list} was refused for another reason"
    );
    assert_eq!(
        refusal.to_string(),
        format!("signer {did} is not in the accepted list")
    );
}

#[test]
fn valid_signature_grants_nothing_by_itself() {
    let parent = temp_dir();
    let bundle = parent.path().join(AGENT_HOST.name);
    assemble_at(&AGENT_HOST, &bundle);
    let key = fresh_signing_key();

    // a. Before.
    let cid = named(&bundle).to_string();
    assert_eq!(cid, AGENT_HOST_LAB_CID);
    let before = listing(parent.path());
    assert_eq!(
        before,
        [AGENT_HOST.name],
        "the bundle is the parent's one entry"
    );
    assert!(runtime_manifest(&bundle).signature.is_none());

    // b. Signing names the bundle and writes nothing.
    let sig = sign_bundle(&key, &bundle).unwrap_or_else(|refusal| panic!("sign: {refusal}"));
    assert_eq!(sig.name, cid);
    assert_untouched("signing", &bundle, &cid, &before);

    // c. The signature is valid, and verifying writes nothing.
    let signer = elastos_identity::encode_signing_key_did(&key);
    assert_eq!(sig.signer_did, signer);
    verify_name_signature(&bundle, &sig, &[signer.clone()])
        .unwrap_or_else(|refusal| panic!("a valid signature was refused: {refusal}"));
    assert_untouched("verifying", &bundle, &cid, &before);
    assert!(
        runtime_manifest(&bundle).signature.is_none(),
        "a lab signature reached the manifest's signature field"
    );

    // d. Each check stands alone: the success approved nothing for the next.
    assert_signer_not_accepted(
        verify_name_signature(&bundle, &sig, &[]),
        &signer,
        "an empty accepted list",
    );
    let other = elastos_identity::encode_signing_key_did(&fresh_signing_key());
    assert_ne!(other, signer, "two fresh test keys have one DID");
    assert_signer_not_accepted(
        verify_name_signature(&bundle, &sig, &[other]),
        &signer,
        "only another key's DID accepted",
    );
}

/// Every `pub fn` the library declares: identity checks only. `check_name`
/// is listed twice: the free function and `CheckedBundle`'s checked form.
const IDENTITY_FUNCTIONS: [&str; 15] = [
    "lab_cid",
    "lab_cid_observed",
    "checked_bundle",
    "checked_bundle_observed",
    "check_name",
    "cid",
    "entries",
    "check_name",
    "encode_entries",
    "entry_kind",
    "entry_path",
    "name_signature_message",
    "sign_bundle",
    "verify_checked_signature",
    "verify_name_signature",
];

/// How many times each name occurs in `names`.
fn counted<'a>(names: impl IntoIterator<Item = &'a str>) -> BTreeMap<&'a str, usize> {
    let mut counts = BTreeMap::new();
    for name in names {
        *counts.entry(name).or_insert(0) += 1;
    }
    counts
}

#[test]
fn the_harness_exports_only_identity_checks() {
    let code = library_code();
    let declared = code.lines().filter_map(|line| {
        let rest = line.trim_start().strip_prefix("pub fn ")?;
        let end = rest
            .find(|c: char| c == '(' || c == '<')
            .unwrap_or(rest.len());
        Some(rest[..end].trim())
    });
    let declared = counted(declared);
    let expected = counted(IDENTITY_FUNCTIONS);
    let mut problems = Vec::new();
    for (name, &count) in &declared {
        let want = expected.get(name).copied().unwrap_or(0);
        if count > want {
            problems.push(format!(
                "extra pub fn {name} (declared {count}, listed {want})"
            ));
        }
    }
    for (name, &want) in &expected {
        let count = declared.get(name).copied().unwrap_or(0);
        if count < want {
            problems.push(format!(
                "missing pub fn {name} (declared {count}, listed {want})"
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "the library's pub fn set is not the identity checks: {}",
        problems.join("; ")
    );
}
