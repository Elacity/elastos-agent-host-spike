//! Admitting a capsule bundle that is named by the CID of its files.
//!
//! A bundle's name is the CID that `elastos-bundle-identity` computes from
//! its folder. A publisher's signature over that name lives in a file beside
//! the bundle, never inside it. This module holds the checks that signature
//! must pass, the limits under which a bundle is walked, and the fixed codes
//! a refusal is reported by. It admits nothing by itself and starts nothing.

use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

use elastos_bundle_identity::{Budget, LabCid, Refusal};
use elastos_runtime::signature::SignatureVerifier;
use serde::Deserialize;

// The lab's own refusals (its test signatures, records and platform variants)
// are compiled into `elastos-bundle-identity` only under its `lab` feature.
// Cargo can turn a feature on for a whole build without anyone asking for it
// here, so this crate refuses to build if that has happened.
const _: () = assert!(
    !elastos_bundle_identity::LAB_REFUSALS,
    "elastos-server must not be built with elastos-bundle-identity's `lab` feature"
);

/// Domain of a bundle signature: it is made over the CID text under this.
pub const BUNDLE_SIGNATURE_DOMAIN: &str = "elastos.capsule.bundle.v1";

/// `schema` of the signature file beside a bundle.
pub const BUNDLE_SIGNATURE_SCHEMA: &str = "elastos.capsule.bundle-signature/v1";

/// The most a walk of a bundle may take in, at staging and at every start.
///
/// - Depth 16: the deepest bundle in the tree today is two parts
///   (`images/01.png`); 16 leaves room and keeps the encoder's recursion to
///   16 frames.
/// - 1,024 bytes of path: the smaller of the whole-path limits of the two
///   systems the Runtime runs on, so no bundle that either can hold has a
///   longer one. It is a bound, not a promise: the store's own folder comes
///   before a bundle's path, so a path near the limit can still be too long
///   to write there, and that bundle is then not staged.
/// - 4,096 entries and 64 MiB: the walk holds every byte it reads, so the
///   byte limit is its memory bound. The largest example bundle today is
///   under 1 MiB.
pub const BUNDLE_WALK_BUDGET: Budget = Budget {
    max_entries: 4_096,
    max_total_bytes: 64 * 1024 * 1024,
    max_depth: 16,
    max_path_bytes: 1_024,
};

/// Why a bundle was not admitted. Each has one fixed code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleRefusal {
    /// There is no signature file beside the bundle.
    Unsigned,
    /// The Home trusts no key, so no signature can be accepted.
    TrustSetEmpty,
    /// The signature file is not the one shape it may have.
    SignatureUnparsed(String),
    /// The signature file is for another bundle.
    SignatureNamesAnotherCid { file: String, computed: String },
    /// The signer is not a canonical key, or the signature does not verify,
    /// or the key that verified it is not trusted. One refusal for all
    /// three, with no detail, so that the answer does not say which.
    SignatureNotAccepted,
    /// The walk of the bundle's folder refused it.
    Walk { code: &'static str, detail: String },
    /// The store's slot for this CID holds something that is not this bundle.
    SlotDiffers { cid: String, found: String },
    /// The store could not be read or written.
    Store(String),
}

impl BundleRefusal {
    /// The fixed code of this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            BundleRefusal::Unsigned => "bundle_unsigned",
            BundleRefusal::TrustSetEmpty => "bundle_trust_set_empty",
            BundleRefusal::SignatureUnparsed(_) => "bundle_signature_unparsed",
            BundleRefusal::SignatureNamesAnotherCid { .. } => "bundle_signature_names_another_cid",
            BundleRefusal::SignatureNotAccepted => "bundle_signature_not_accepted",
            BundleRefusal::Walk { code, .. } => code,
            BundleRefusal::SlotDiffers { .. } => "bundle_slot_differs",
            BundleRefusal::Store(_) => "bundle_store_io",
        }
    }
}

impl fmt::Display for BundleRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            BundleRefusal::Unsigned => write!(f, "{code}: no signature file beside the bundle"),
            BundleRefusal::TrustSetEmpty => write!(f, "{code}: this Home trusts no signing key"),
            BundleRefusal::SignatureUnparsed(why) => write!(f, "{code}: {why}"),
            BundleRefusal::SignatureNamesAnotherCid { file, computed } => write!(
                f,
                "{code}: the signature file names {file}, the bundle is {computed}"
            ),
            BundleRefusal::SignatureNotAccepted => {
                write!(f, "{code}: the bundle's signature is not accepted")
            }
            BundleRefusal::Walk { detail, .. } => write!(f, "{code}: {detail}"),
            BundleRefusal::SlotDiffers { cid, found } => write!(
                f,
                "{code}: the store's slot for {cid} does not hold that bundle: {found}"
            ),
            BundleRefusal::Store(why) => write!(f, "{code}: {why}"),
        }
    }
}

impl std::error::Error for BundleRefusal {}

/// The most that is read of a signature file. One is about 300 bytes.
pub const MAX_SIGNATURE_FILE_BYTES: u64 = 4_096;

/// Where the Home at `data_dir` keeps the files of the bundle `cid`.
pub fn bundle_slot(data_dir: &Path, cid: &LabCid) -> PathBuf {
    by_cid(data_dir).join(cid.to_string())
}

/// Where the Home at `data_dir` keeps the signature over `cid`: beside the
/// bundle's folder, never inside it.
pub fn bundle_signature_path(data_dir: &Path, cid: &LabCid) -> PathBuf {
    by_cid(data_dir).join(format!("{cid}.sig.json"))
}

fn by_cid(data_dir: &Path) -> PathBuf {
    data_dir.join("capsules").join("by-cid")
}

/// Read a signature file, at most [`MAX_SIGNATURE_FILE_BYTES`] of it. A file
/// that is not there is `None`, which the check refuses as unsigned.
pub fn read_signature_file(path: &Path) -> Result<Option<Vec<u8>>, BundleRefusal> {
    let unread = |error: std::io::Error| {
        BundleRefusal::SignatureUnparsed(format!("could not read the signature file: {error}"))
    };
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(unread(error)),
    };
    let mut bytes = Vec::new();
    file.take(MAX_SIGNATURE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(unread)?;
    if bytes.len() as u64 > MAX_SIGNATURE_FILE_BYTES {
        return Err(BundleRefusal::SignatureUnparsed(format!(
            "the signature file is over {MAX_SIGNATURE_FILE_BYTES} bytes"
        )));
    }
    Ok(Some(bytes))
}

/// The signature file beside a bundle, exactly: no other key is allowed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleSignatureFile {
    schema: String,
    cid: String,
    signer_did: String,
    signature: String,
}

/// Check the signature file `file` for the bundle the Runtime computed `cid`
/// for, against the keys `verifier` trusts. Returns the signer's `did:key`.
///
/// The order is fixed: the file exists; the Home trusts at least one key;
/// the file parses and names this CID; the signer is one canonical Ed25519
/// `did:key`; the signature verifies strictly for that key over the CID text;
/// and only then, that key is one the Home trusts. There is no `dev_mode`
/// here: a bundle named by CID is never admitted unsigned.
///
/// The key in the file is a claim by whoever wrote the file. Trust is asked
/// only of a key that has already verified the signature, and this is the
/// one place in the server that asks it.
///
/// NOT EQUALISED: TIME. The three ways the last three steps fail give one
/// refusal with one detail and one log line, but they do not take the same
/// time: trust adds a list scan, and the signature and key checks keep
/// caches of what passed (`crypto.rs`, `elastos-identity/src/store.rs`). The
/// only caller today is a person running a command, one process per attempt,
/// on a file they supplied. BEFORE ANY ROUTE LETS A REMOTE CALLER REACH THIS
/// FUNCTION, ITS TIME MUST BE MADE THE SAME FOR THOSE THREE.
pub fn check_bundle_signature(
    file: Option<&[u8]>,
    cid: &LabCid,
    verifier: &SignatureVerifier,
) -> Result<String, BundleRefusal> {
    let file = file.ok_or(BundleRefusal::Unsigned)?;
    if verifier.trusted_key_count() == 0 {
        return Err(BundleRefusal::TrustSetEmpty);
    }
    let file: BundleSignatureFile = serde_json::from_slice(file)
        .map_err(|error| BundleRefusal::SignatureUnparsed(error.to_string()))?;
    if file.schema != BUNDLE_SIGNATURE_SCHEMA {
        return Err(BundleRefusal::SignatureUnparsed(format!(
            "schema is not {BUNDLE_SIGNATURE_SCHEMA}"
        )));
    }
    if file.signature.len() != 128 || !file.signature.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(BundleRefusal::SignatureUnparsed(
            "signature is not 128 hex characters".into(),
        ));
    }
    let computed = cid.to_string();
    if file.cid != computed {
        return Err(BundleRefusal::SignatureNamesAnotherCid {
            file: file.cid,
            computed,
        });
    }
    let Ok(key) = crate::crypto::decode_did_key(&file.signer_did) else {
        return Err(not_accepted(&computed));
    };
    if crate::crypto::verify_domain_separated_signature(
        &file.signer_did,
        BUNDLE_SIGNATURE_DOMAIN,
        computed.as_bytes(),
        &file.signature,
    )
    .is_err()
    {
        return Err(not_accepted(&computed));
    }
    if !verifier.trusts(&key) {
        return Err(not_accepted(&computed));
    }
    Ok(file.signer_did)
}

/// The one refusal, and the one log line, for a signer that is not a
/// canonical key, a signature that does not verify, and a key that is not
/// trusted. It says nothing that tells them apart.
fn not_accepted(cid: &str) -> BundleRefusal {
    tracing::warn!("bundle {cid}: signature not accepted");
    BundleRefusal::SignatureNotAccepted
}

/// The code and detail for a refusal of the walk. Every variant is named:
/// a refusal added to the crate later does not compile here until it has a
/// code. The lab's own refusals are not among them, because they do not
/// exist in this build (see the assertion at the top of this file).
pub fn walk_refusal(refusal: Refusal) -> BundleRefusal {
    let code = match &refusal {
        Refusal::NoManifest => "bundle_walk_no_manifest",
        Refusal::ManifestUnparsed(_) => "bundle_walk_manifest_unparsed",
        Refusal::ManifestInvalid(_) => "bundle_walk_manifest_invalid",
        Refusal::NotRegularFile { .. } => "bundle_walk_not_regular_file",
        Refusal::NonUtf8Name { .. } => "bundle_walk_non_utf8_name",
        Refusal::DuplicatePath { .. } => "bundle_walk_duplicate_path",
        Refusal::BadPathPart { .. } => "bundle_walk_bad_path_part",
        Refusal::FileAndDirectory { .. } => "bundle_walk_file_and_directory",
        Refusal::FileOverChunkLimit { .. } => "bundle_walk_file_over_chunk_limit",
        Refusal::FileOverLeafLimit { .. } => "bundle_walk_file_over_leaf_limit",
        Refusal::DirectoryOverBlockLimit { .. } => "bundle_walk_directory_over_block_limit",
        Refusal::Changed { .. } => "bundle_walk_changed",
        Refusal::Unreadable { .. } => "bundle_walk_unreadable",
        Refusal::OverBudget { .. } => "bundle_walk_over_budget",
        Refusal::NotALabCid { .. } => "bundle_walk_not_a_cid",
        Refusal::NameMismatch { .. } => "bundle_walk_name_mismatch",
    };
    BundleRefusal::Walk {
        code,
        detail: refusal.to_string(),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use sha2::{Digest, Sha256};

    /// A CID recorded by the lab for one of its fixtures (`web-app`); the
    /// tests here need a well-formed CID, not that bundle.
    pub(crate) const CID_A: &str = "bafybeibc5wcwbtdmjt7qbwbi2rfqvfcfzumivqsoct2ekdqeec2yodqy7q";
    /// Another of the lab's recorded CIDs (`agent-host`).
    pub(crate) const CID_B: &str = "bafybeicesxlwcolv5hifwotsyafyyaclaq23gyzwl7esuvhwlownrhatym";

    pub(crate) fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    pub(crate) fn did(key: &VerifyingKey) -> String {
        crate::crypto::encode_did_key(key).expect("did:key")
    }

    /// A signature made here by hand, not by the server's signer: the
    /// SHA-256 of the domain, one zero byte and the payload, signed.
    pub(crate) fn sign_by_hand(key: &SigningKey, domain: &str, payload: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(domain.as_bytes());
        hasher.update([0u8]);
        hasher.update(payload.as_bytes());
        hex::encode(key.sign(&hasher.finalize()).to_bytes())
    }

    pub(crate) fn file_for(cid: &str, signer: &str, signature: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": BUNDLE_SIGNATURE_SCHEMA,
            "cid": cid,
            "signer_did": signer,
            "signature": signature,
        }))
        .expect("json")
    }

    pub(crate) fn signed(cid: &str, key: &SigningKey) -> Vec<u8> {
        file_for(
            cid,
            &did(&key.verifying_key()),
            &sign_by_hand(key, BUNDLE_SIGNATURE_DOMAIN, cid),
        )
    }

    fn trusting(keys: &[&SigningKey]) -> SignatureVerifier {
        let mut verifier = SignatureVerifier::new();
        for key in keys {
            verifier.add_trusted_key(key.verifying_key()).expect("key");
        }
        verifier
    }

    fn cid(text: &str) -> LabCid {
        text.parse().expect("a recorded CID")
    }

    fn check(
        file: Option<&[u8]>,
        cid_text: &str,
        verifier: &SignatureVerifier,
    ) -> Result<String, BundleRefusal> {
        check_bundle_signature(file, &cid(cid_text), verifier)
    }

    #[test]
    fn a_trusted_publishers_signature_over_the_cid_is_accepted_and_names_the_signer() {
        let publisher = key(1);
        let verifier = trusting(&[&publisher, &key(2)]);
        assert_eq!(
            check(Some(&signed(CID_A, &publisher)), CID_A, &verifier),
            Ok(did(&publisher.verifying_key()))
        );
    }

    #[test]
    fn a_missing_file_is_unsigned_whatever_the_trust_set_holds() {
        assert_eq!(
            check(None, CID_A, &trusting(&[&key(1)])),
            Err(BundleRefusal::Unsigned)
        );
        assert_eq!(
            check(None, CID_A, &trusting(&[])),
            Err(BundleRefusal::Unsigned)
        );
        assert_eq!(BundleRefusal::Unsigned.code(), "bundle_unsigned");
    }

    #[test]
    fn an_empty_trust_set_refuses_before_the_file_is_parsed() {
        let publisher = key(1);
        let empty = trusting(&[]);
        assert_eq!(
            check(Some(&signed(CID_A, &publisher)), CID_A, &empty),
            Err(BundleRefusal::TrustSetEmpty)
        );
        // A file that does not even parse gets the same answer, so the trust
        // set is asked first.
        assert_eq!(
            check(Some(b"not json"), CID_A, &empty),
            Err(BundleRefusal::TrustSetEmpty)
        );
        assert_eq!(
            BundleRefusal::TrustSetEmpty.code(),
            "bundle_trust_set_empty"
        );
    }

    #[test]
    fn a_file_of_another_shape_is_unparsed() {
        let publisher = key(1);
        let verifier = trusting(&[&publisher]);
        let signer = did(&publisher.verifying_key());
        let signature = sign_by_hand(&publisher, BUNDLE_SIGNATURE_DOMAIN, CID_A);
        let unknown_key = serde_json::to_vec(&serde_json::json!({
            "schema": BUNDLE_SIGNATURE_SCHEMA, "cid": CID_A, "signer_did": signer,
            "signature": signature, "note": "x",
        }))
        .unwrap();
        let other_schema = serde_json::to_vec(&serde_json::json!({
            "schema": "elastos.capsule.bundle-signature/v2", "cid": CID_A,
            "signer_did": signer, "signature": signature,
        }))
        .unwrap();
        let short = file_for(CID_A, &signer, &signature[..127]);
        let not_hex = file_for(CID_A, &signer, &format!("{}g", &signature[..127]));
        for file in [unknown_key, other_schema, short, not_hex, b"{".to_vec()] {
            let refusal = check(Some(&file), CID_A, &verifier).expect_err("another shape");
            assert_eq!(refusal.code(), "bundle_signature_unparsed", "{refusal}");
        }
    }

    #[test]
    fn a_valid_signature_file_for_another_bundle_is_refused_by_that_code() {
        let publisher = key(1);
        let verifier = trusting(&[&publisher]);
        // Valid for A in every way; offered for B.
        let refusal = check(Some(&signed(CID_A, &publisher)), CID_B, &verifier).expect_err("for A");
        assert_eq!(
            refusal,
            BundleRefusal::SignatureNamesAnotherCid {
                file: CID_A.into(),
                computed: CID_B.into()
            }
        );
        assert_eq!(refusal.code(), "bundle_signature_names_another_cid");
    }

    #[test]
    fn a_signature_under_another_domain_is_not_accepted() {
        let publisher = key(1);
        let verifier = trusting(&[&publisher]);
        let other_domain = file_for(
            CID_A,
            &did(&publisher.verifying_key()),
            &sign_by_hand(&publisher, "elastos.capsule.record.v1", CID_A),
        );
        assert_eq!(
            check(Some(&other_domain), CID_A, &verifier),
            Err(BundleRefusal::SignatureNotAccepted)
        );
    }

    #[test]
    fn a_trusted_key_named_beside_a_signature_that_does_not_verify_is_not_accepted() {
        // The file names a key the Home trusts. The signature was made by
        // another key. Trust in the name must not admit it.
        let trusted = key(1);
        let verifier = trusting(&[&trusted]);
        let forged = file_for(
            CID_A,
            &did(&trusted.verifying_key()),
            &sign_by_hand(&key(9), BUNDLE_SIGNATURE_DOMAIN, CID_A),
        );
        assert_eq!(
            check(Some(&forged), CID_A, &verifier),
            Err(BundleRefusal::SignatureNotAccepted)
        );
    }

    #[test]
    fn a_valid_signature_by_a_key_that_is_not_trusted_is_not_accepted() {
        let stranger = key(7);
        let verifier = trusting(&[&key(1)]);
        assert_eq!(
            check(Some(&signed(CID_A, &stranger)), CID_A, &verifier),
            Err(BundleRefusal::SignatureNotAccepted)
        );
        // The control: the same file is accepted once that key is trusted.
        assert!(check(
            Some(&signed(CID_A, &stranger)),
            CID_A,
            &trusting(&[&stranger])
        )
        .is_ok());
    }

    #[test]
    fn a_bad_signer_a_bad_signature_and_an_untrusted_key_get_one_identical_refusal() {
        let trusted = key(1);
        let verifier = trusting(&[&trusted]);
        let signature = sign_by_hand(&trusted, BUNDLE_SIGNATURE_DOMAIN, CID_A);
        let bad_signer = file_for(CID_A, "did:web:example.org", &signature);
        let bad_signature = file_for(
            CID_A,
            &did(&trusted.verifying_key()),
            &sign_by_hand(&key(9), BUNDLE_SIGNATURE_DOMAIN, CID_A),
        );
        let untrusted = signed(CID_A, &key(7));
        let refusals: Vec<BundleRefusal> = [bad_signer, bad_signature, untrusted]
            .iter()
            .map(|file| check(Some(file), CID_A, &verifier).expect_err("not accepted"))
            .collect();
        for refusal in &refusals {
            assert_eq!(refusal, &refusals[0]);
            assert_eq!(refusal.to_string(), refusals[0].to_string());
            assert_eq!(refusal.code(), "bundle_signature_not_accepted");
        }
        assert_eq!(
            refusals[0].to_string(),
            "bundle_signature_not_accepted: the bundle's signature is not accepted"
        );
    }

    /// This file's code without its tests.
    fn production() -> &'static str {
        let source = include_str!("bundle_admission.rs");
        &source[..source.find("#[cfg(test)]").expect("the tests module")]
    }

    #[test]
    fn trust_is_asked_once_in_the_server_and_only_after_the_signature_verified() {
        let code = production();
        assert_eq!(
            code.matches(".trusts(").count(),
            1,
            "one call site in this file"
        );
        let verify = code
            .find("verify_domain_separated_signature(")
            .expect("the verify call");
        let trusts = code.find(".trusts(").expect("the trust question");
        assert!(
            verify < trusts,
            "trust is asked before the signature is verified"
        );
        // The three refusals share one maker, which holds the one log line.
        assert_eq!(code.matches("Err(not_accepted(&computed))").count(), 3);
        assert_eq!(code.matches("tracing::").count(), 1, "one log line");
        // Outside its comments this file never names `dev_mode`: the check
        // takes no such input, so no setting can relax it.
        let named: Vec<&str> = code
            .lines()
            .filter(|line| !line.trim_start().starts_with("//") && line.contains("dev_mode"))
            .collect();
        assert!(named.is_empty(), "dev_mode named in code: {named:?}");

        // No other file of the server asks the question.
        fn rust_files(dir: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
            for item in std::fs::read_dir(dir).expect("list") {
                let path = item.expect("entry").path();
                if path.is_dir() {
                    rust_files(&path, found);
                } else if path.extension().is_some_and(|extension| extension == "rs") {
                    found.push(path);
                }
            }
        }
        let mut files = Vec::new();
        rust_files(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut files,
        );
        assert!(
            files.len() > 50,
            "the walk of the server's sources found {} files",
            files.len()
        );
        let askers: Vec<String> = files
            .iter()
            .filter(|path| {
                std::fs::read_to_string(path)
                    .expect("read")
                    .contains(".trusts(")
            })
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            askers,
            ["bundle_admission.rs"],
            "who asks whether a key is trusted"
        );
    }

    #[test]
    fn the_server_does_not_build_with_the_labs_refusals() {
        // The assertion itself cannot be run as a test: with the feature on
        // this crate does not compile. This holds that it is still here, in
        // the code and not under a test cfg.
        let code = production();
        assert!(
            code.contains("const _: () = assert!(\n    !elastos_bundle_identity::LAB_REFUSALS,")
        );
    }

    #[test]
    fn a_walk_refusal_keeps_its_own_name_and_text() {
        let refusal = walk_refusal(Refusal::OverBudget {
            limit: "depth",
            path: "a/b".into(),
        });
        assert_eq!(refusal.code(), "bundle_walk_over_budget");
        assert_eq!(
            refusal.to_string(),
            "bundle_walk_over_budget: a/b passes the walk's limit on depth"
        );
        assert_eq!(
            walk_refusal(Refusal::NoManifest).code(),
            "bundle_walk_no_manifest"
        );
    }

    #[test]
    fn the_walk_budget_is_the_four_numbers_the_design_gives() {
        assert_eq!(
            BUNDLE_WALK_BUDGET,
            Budget {
                max_entries: 4_096,
                max_total_bytes: 67_108_864,
                max_depth: 16,
                max_path_bytes: 1_024,
            }
        );
    }
}
