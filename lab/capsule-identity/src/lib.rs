//! Lab capsule identity: one deterministic **lab CID**, a lab package CID,
//! over a whole capsule bundle (PRINCIPLES 13 and 15).
//!
//! This crate answers two questions: "do these bytes match this name?" and
//! "did this test key sign this lab CID?". It never answers "may this run?":
//! it makes no trust, admission or launch decision and sits in no admission
//! or launch path. Its value is a lab package CID: the CIDv1 SHA-256 UnixFS
//! directory root of the bundle, printed as 59 characters that start
//! `bafybei`. It is a prototype, not an admission, and it defines no shared
//! capsule identity. It is not the Runtime's published name either: the
//! Runtime names a published capsule by the CID its IPFS provider returns
//! for the capsule archive, and an archive hash is a delivery check, not
//! this CID.
//!
//! # The encoding
//!
//! The profile is Kubo v0.40.1's import flags as
//! `capsules/ipfs-provider/src/directory_hash.rs` sends them: CIDv1, sha2-256,
//! raw leaves, chunker `size-262144`, no inline, no HAMT shard below its
//! threshold. The lab CID follows the
//! Kubo v0.40.1 profile, computed by the lab: no Kubo has computed any pin,
//! so until an offline Kubo cross-check prints the same value as a committed
//! pin, it is not called equal to the Runtime's CID or to Kubo's output.
//! This crate runs no Kubo and pins only the non-sharded subset of that
//! profile, with files of up to one tree level:
//!
//! 1. Each regular file of at most 262144 bytes (`CHUNK_SIZE`) is one raw
//!    leaf: its block is the file's bytes (an empty file is an empty block),
//!    its CID is the bytes `01 55 12 20` and the SHA-256 of the block (CID
//!    version 1, raw codec `0x55`, multihash sha2-256 of 32 bytes), and its
//!    Tsize is its length. A larger file is split into 262144-byte raw
//!    leaves, the last one shorter, under one balanced dag-pb file root
//!    (trickle off): for each leaf in order a link with the leaf's CID, an
//!    empty name and the leaf's length as Tsize; then the UnixFS data `08 02`
//!    (type file), the file's length (field 3) and each leaf's length (field
//!    4, one tag per value). Its CID is `01 70 12 20` and the SHA-256 of that
//!    block, and its Tsize is the block's length plus its leaves' lengths. A
//!    file of more than 174 leaves (`max-file-links`), over 45613056 bytes,
//!    would need a second tree level and is refused.
//! 2. A bundle path such as `browser/app.js` is a directory `browser` that
//!    links `app.js`. Each directory's block is dag-pb: one link per child,
//!    sorted by name bytes, each as protobuf field 2 holding the child's CID
//!    (field 1), its name (field 2) and its Tsize (field 3, a varint); then
//!    the UnixFS data `08 01` (type directory) as field 1. A directory's CID
//!    is `01 70 12 20` and the SHA-256 of its block (dag-pb codec `0x70`).
//!    The Tsize of a link to a directory is that directory's block length
//!    plus the Tsizes of its links. A block over 262144 bytes is refused: no
//!    HAMT shard.
//! 3. The root is the directory of the bundle's entries. Its CID prints as
//!    `b` and the RFC 4648 base32 of its 36 bytes, lowercase, no padding.
//!
//! No empty directory is emitted. Nothing else enters a block: no folder
//! name, absolute path, mtime, mode, owner or symlink target. The CIDv1 bytes
//! and the base32 text are one marked lab copy in this crate, so the lab adds
//! no crate (the Runtime's `cid` crate lives only in server crates the lab
//! does not link, and a new crate would stale two consumer locks).
//!
//! # One naming path
//!
//! [`checked_bundle`] walks a bundle, checks its root manifest, and hands its
//! entries to [`encode_entries`]. That makes each entry's node from its bytes
//! (one raw leaf, or a file root over its leaves) and hands the nodes to the
//! one tree builder. [`encode_listed_files`], which a caller with its own
//! walk calls directly with a closure listing ([`ListedFile`]: path, size,
//! SHA-256), makes one raw leaf per listed file with the same leaf rule and
//! hands them to the same builder. Together the walk and these two calls are
//! the only code that names a bundle; tests and tools call them and
//! re-implement none. [`lab_cid`] is the same walk and returns only
//! its lab CID. [`check_name`] checks a claimed name, such as one a URL or a
//! Store row gives, by recomputing the name with [`lab_cid`]: it computes no
//! name of its own. [`CheckedBundle::check_name`] is its checked form: the
//! same claim check and the same compare, on the lab CID a checked bundle
//! holds. [`lab_cid`] is [`lab_cid_observed`] with an observer that does
//! nothing, and [`lab_cid_observed`] is [`checked_bundle_observed`]'s lab
//! CID, so there is one walk; tests watch it at two [`Moment`]s to change a
//! bundle while it is named. The walk's two checks, [`entry_kind`] and
//! [`entry_path`], are public only so tests can give them what a test folder
//! cannot hold: a device, or a name that is not UTF-8.
//!
//! # The checked bundle
//!
//! A caller that must use the bytes a name covers, to audit, stage or sign
//! them, takes them from the [`CheckedBundle`] the walk returns, never from a
//! second read of the folder: a file changed between two reads would be used
//! under a name that does not cover it. The value's fields are private, so
//! its lab CID always names its entries. It holds a name and bytes, never a
//! decision.
//!
//! # Test-key publisher signature
//!
//! [`sign_bundle`] signs the printed lab CID from [`lab_cid`]. The signed
//! bytes are [`name_signature_message`]: SHA-256 over a lab domain, one
//! `0x00` byte and that printed name. [`verify_checked_signature`] checks a
//! signature against a [`CheckedBundle`], in order: a canonical `did:key`,
//! an explicit accepted list, [`CheckedBundle::check_name`], then the
//! Ed25519 signature. [`verify_name_signature`] is [`checked_bundle`] and
//! then that check, so it holds no check of its own. A refusal is one of
//! those checks and nothing else. `Ok(())` means the test key signed that
//! name; it is not a permission to run.
//!
//! # Lab package record
//!
//! A [`PackageRecord`] is the signed record that sits outside the bundle: it
//! names the signer and binds the printed lab CID. Its bytes are
//! [`PackageRecord::package_record_payload`], compact JSON with the keys
//! `cid`, `schema` ([`PACKAGE_RECORD_SCHEMA`]) and `signer_did`, and no name
//! field. The record binds a lab CID however it was computed: a folder walk,
//! a checked bundle, entries or a closure listing. [`sign_cid_record`] signs
//! [`domain_separated_digest`] of [`PACKAGE_RECORD_DOMAIN`] and the payload
//! for one [`LabCid`]; it writes nothing. [`verify_cid_record`] checks, in
//! order, the signer's `did:key`, the explicit accepted list, the record's
//! CID against that lab CID, then the Ed25519 signature.
//! [`sign_package_record`] is [`lab_cid`] and then [`sign_cid_record`];
//! [`verify_checked_package_record`] is [`verify_cid_record`] over the
//! checked bundle's CID; [`verify_package_record`] is [`checked_bundle`] and
//! then the checked call. So a record is built, signed and checked in one
//! place each. Both signatures share one
//! digest, one DID encoder and decoder, one accepted-list check and one
//! Ed25519 verification. `Ok(())` grants nothing.
//!
//! # Lab variant binding
//!
//! A [`VariantBinding`] sits outside every bundle and groups the printed lab
//! CIDs of a capsule's platform variants, each under a platform label from
//! [`VARIANT_PLATFORMS`], with the lab CID of their recipe. No manifest
//! field, folder name or path holds a platform label, so the binding is the
//! label's only home as metadata. The stand-in payloads of the variant
//! fixtures hold the words only so their CIDs differ; the lab never reads
//! them. A label, the portable `*` too, is the signer's claim: the lab never
//! reads one from a manifest, path or payload, so it does not check that a
//! variant's bytes were built for its label. Its bytes are
//! [`VariantBinding::variant_binding_payload`], compact JSON with the keys
//! `recipe`, `schema` ([`VARIANT_BINDING_SCHEMA`]), `signer_did` and
//! `variants`, and no name or group identity field. [`sign_variant_binding`]
//! signs [`domain_separated_digest`] of [`VARIANT_BINDING_DOMAIN`] and that
//! payload; it writes nothing. [`verify_checked_variant_binding`] checks, in
//! order, the signer's `did:key`, the explicit accepted list, the shape of
//! both variant lists, the platforms, each variant's CID, that a WASM app is
//! bound only under the portable label [`PORTABLE_PLATFORM`] (`*`), the
//! recipe's CID, then the Ed25519 signature. The portable label stands alone
//! in a binding, so a WASM app has one variant and one CID. Whether a bundle
//! is a WASM app comes from the one manifest check, never a second parse.
//! [`verify_variant_binding`] is [`checked_bundle`]
//! for each variant and then that check. It shares the record's digest, DID
//! encoder and decoder, accepted-list check and Ed25519 verification. Each
//! variant is still its own closure with its own [`PackageRecord`]. The
//! binding groups CIDs; it defines no shared capsule identity, and `Ok(())`
//! grants nothing.
//!
//! # The walk reads only checked handles
//!
//! The walk opens the bundle root once, by its path. After that it reaches
//! every entry through its folder's open handle, never by a path:
//!
//! 1. It reads a folder's whole listing from the folder's handle, skipping
//!    `.` and `..`.
//! 2. It refuses a link, FIFO, socket or device from the listing's own type,
//!    without opening it.
//! 3. It opens each other entry relative to its folder's handle, never
//!    following a link and never waiting on a FIFO.
//! 4. It checks the open handle's own type: a regular file or a folder, and
//!    the kind the listing said.
//! 5. It reads a file's bytes from that same handle, and lists a folder from
//!    it.
//!
//! So an entry changed while the bundle is named is refused, or named
//! exactly as the bytes its checked handle held.
#![forbid(unsafe_code)]

use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub use elastos_bundle_identity::{
    check_name, checked_bundle, checked_bundle_observed, encode_entries, encode_listed_files,
    entry_kind, entry_path, lab_cid, lab_cid_observed, BundleEntry, CheckedBundle, EntryKind,
    LabCid, ListedFile, Moment, Refusal, MANIFEST_FILE, PORTABLE_PLATFORM, VARIANT_PLATFORMS,
};

/// Domain of the lab name signature, for [`domain_separated_digest`]. It is a
/// lab proposal.
pub const NAME_SIGNATURE_DOMAIN: &str = "lab.capsule-identity.name-signature/v1";

/// Schema of the lab package record's payload. It is the lab's own name, not
/// the Runtime's capsule record schema.
pub const PACKAGE_RECORD_SCHEMA: &str = "lab.capsule-identity.record/v1";

/// Domain of the lab package record's signature, for
/// [`domain_separated_digest`]. It is a lab proposal.
pub const PACKAGE_RECORD_DOMAIN: &str = "lab.capsule-identity.package-record/v1";

/// Schema of the lab variant binding's payload. It is the lab's own name.
pub const VARIANT_BINDING_SCHEMA: &str = "lab.capsule-identity.variant-binding/v1";

/// Domain of the lab variant binding's signature, for
/// [`domain_separated_digest`]. It is a lab proposal.
pub const VARIANT_BINDING_DOMAIN: &str = "lab.capsule-identity.variant-binding/v1";

/// The path of the one entry a variant recipe is named under: its lab CID is
/// [`encode_entries`] of one entry with this path and the recipe's bytes.
pub const VARIANT_RECIPE_ENTRY: &str = "provider-variant.recipe";

/// A test-key signature over a printed lab CID.
///
/// It lives in memory only. It is not a file, an envelope or a manifest
/// field, and nothing writes it to disk. It has no serialized form. The
/// signature never goes into `capsule.json`: that file is inside the bytes
/// the lab CID covers, so a signature written there would change the name it
/// signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameSignature {
    /// The printed lab CID the signature covers, as `LabCid` prints it.
    pub name: String,
    /// The signer's canonical Ed25519 `did:key`.
    pub signer_did: String,
    /// The 64-byte Ed25519 signature over [`name_signature_message`] of
    /// [`NameSignature::name`].
    pub signature: [u8; 64],
}

/// A test-key signed record, outside the bundle, that names the signer and
/// binds a printed lab CID.
///
/// It lives in memory only, like [`NameSignature`]: no serde derive, no file,
/// and nothing writes it into or next to the bundle. It has no name field, so
/// it binds a CID and never a capsule name. The signature is not part of the
/// payload it covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageRecord {
    /// The printed lab CID the record binds, as `LabCid`'s `Display` prints it.
    pub cid: String,
    /// The signer's canonical Ed25519 `did:key`.
    pub signer_did: String,
    /// The 64-byte Ed25519 signature over [`domain_separated_digest`] of
    /// [`PACKAGE_RECORD_DOMAIN`] and [`PackageRecord::package_record_payload`].
    pub signature: [u8; 64],
}

/// A test-key signed binding, outside every bundle, that groups the lab CIDs
/// of a capsule's platform variants and the lab CID of their recipe.
///
/// It lives in memory only, like [`PackageRecord`]: no serde derive, no file,
/// and nothing writes it. It has no name and no group identity field: it
/// groups CIDs and defines no shared capsule identity. Each variant is still
/// its own closure with its own [`PackageRecord`]. The signature is not part
/// of the payload it covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariantBinding {
    /// The recipe's printed lab CID.
    pub recipe: String,
    /// The `(platform, cid)` pairs: a platform label and the printed lab CID
    /// of that variant's bundle, in the order signing was given them. The
    /// payload sorts them.
    pub variants: Vec<(String, String)>,
    /// The signer's canonical Ed25519 `did:key`.
    pub signer_did: String,
    /// The 64-byte Ed25519 signature over [`domain_separated_digest`] of
    /// [`VARIANT_BINDING_DOMAIN`] and [`VariantBinding::variant_binding_payload`].
    pub signature: [u8; 64],
}

/// The digest every lab signature covers: SHA-256 over the UTF-8 bytes of
/// `domain`, one `0x00` byte and `payload`.
///
/// This is the three-step form of `domain_separated_sign` in
/// `elastos/crates/elastos-server/src/crypto.rs`. That form lives only in the
/// Runtime server, which this lab does not link, so the lab keeps this one
/// marked copy and calls it a lab proposal. It is the one message hash: the
/// name signature and the package record both call it, each with its own
/// domain. [`naming_hash`], which the encoder calls, remains the one naming
/// hash.
pub fn domain_separated_digest(domain: &str, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(b"\0");
    hasher.update(payload);
    hasher.finalize().into()
}

/// The bytes a name signature covers: [`domain_separated_digest`] of
/// [`NAME_SIGNATURE_DOMAIN`] and the UTF-8 bytes of the printed lab CID.
///
/// Signing and verifying both call this, and nothing else builds the message.
/// The whole printed lab CID, its `b` prefix included, is the signed name.
pub fn name_signature_message(name: &str) -> [u8; 32] {
    domain_separated_digest(NAME_SIGNATURE_DOMAIN, name.as_bytes())
}

/// Sign `bundle`'s printed lab CID with `key`.
///
/// The name comes from [`lab_cid`]. A bundle [`lab_cid`] refuses gets no
/// signature, and the refusal is [`lab_cid`]'s own. The signature is Ed25519
/// over [`name_signature_message`] of that printed name. `signer_did` is
/// `elastos_identity::encode_signing_key_did` of `key`. Nothing is written.
pub fn sign_bundle(key: &SigningKey, bundle: &Path) -> Result<NameSignature, Refusal> {
    let name = lab_cid(bundle)?.to_string();
    let digest = name_signature_message(&name);
    let signature = key.sign(&digest).to_bytes();
    Ok(NameSignature {
        name,
        signer_did: signer_did_of(key),
        signature,
    })
}

/// The canonical Ed25519 `did:key` of `key`, from
/// `elastos_identity::encode_signing_key_did`: the one DID encoding both
/// signers use.
fn signer_did_of(key: &SigningKey) -> String {
    elastos_identity::encode_signing_key_did(key)
}

/// Check `sig` against the bytes `checked` holds.
///
/// The checks run in this order, and the first refusal is the answer:
///
/// 1. `elastos_identity::decode_did_key` on `sig.signer_did`. A DID it refuses
///    is not a canonical Ed25519 `did:key`, and the reason carries the
///    decoder's own text.
/// 2. `sig.signer_did` is an exact member of `accepted`. An empty list refuses
///    every signer. The list is an explicit input, not a trust policy.
/// 3. [`CheckedBundle::check_name`] of `sig.name`. Its refusals pass through
///    unchanged. This reads nothing from disk.
/// 4. Ed25519 verification of `sig.signature` over [`name_signature_message`]
///    of `sig.name`, with the key from step 1.
///
/// `Ok(())` means all four passed. It is not a trust, admission or launch
/// value. A wrong key, a changed signature and a name moved onto other bytes
/// all fail step 4 with one reason.
pub fn verify_checked_signature(
    checked: &CheckedBundle,
    sig: &NameSignature,
    accepted: &[String],
) -> Result<(), Refusal> {
    let key = decode_signer(&sig.signer_did)?;
    require_accepted(&sig.signer_did, accepted)?;
    checked.check_name(&sig.name)?;
    verify_signature(&key, sig)?;
    Ok(())
}

/// Check `sig` against the bundle at `bundle`.
///
/// This is [`checked_bundle`] and then [`verify_checked_signature`]. It holds
/// no check of its own, so a bundle the walk refuses is refused first, with
/// the walk's own reason. The signature is judged on the bytes that walk read.
pub fn verify_name_signature(
    bundle: &Path,
    sig: &NameSignature,
    accepted: &[String],
) -> Result<(), Refusal> {
    let checked = checked_bundle(bundle)?;
    verify_checked_signature(&checked, sig, accepted)
}

/// Check (a): `did` is one canonical Ed25519 `did:key`.
fn decode_signer(did: &str) -> Result<VerifyingKey, Refusal> {
    elastos_identity::decode_did_key(did).map_err(|error| Refusal::MalformedSignerDid {
        did: did.to_owned(),
        reason: error.to_string(),
    })
}

/// Check (b): `did` is an exact member of `accepted`.
fn require_accepted(did: &str, accepted: &[String]) -> Result<(), Refusal> {
    if !accepted.iter().any(|one| one == did) {
        return Err(Refusal::SignerNotAccepted {
            did: did.to_owned(),
        });
    }
    Ok(())
}

/// Check (d): Ed25519 verification of `sig` over the message of its name.
fn verify_signature(key: &VerifyingKey, sig: &NameSignature) -> Result<(), Refusal> {
    let digest = name_signature_message(&sig.name);
    verify_ed25519(key, &digest, &sig.signature, &sig.signer_did, &sig.name)
}

/// The one Ed25519 verification: `signature` by `key` over `digest`. A
/// failure is refused with the signer `did` and the signed `name`.
fn verify_ed25519(
    key: &VerifyingKey,
    digest: &[u8; 32],
    signature: &[u8; 64],
    did: &str,
    name: &str,
) -> Result<(), Refusal> {
    let signature = Signature::from_bytes(signature);
    key.verify(digest, &signature)
        .map_err(|_| Refusal::SignatureDoesNotVerify {
            did: did.to_owned(),
            name: name.to_owned(),
        })?;
    Ok(())
}

impl PackageRecord {
    /// The bytes the record's signature covers: compact JSON, keys in this
    /// order, no spaces and no trailing newline:
    /// `{"cid":"<cid>","schema":"lab.capsule-identity.record/v1","signer_did":"<did>"}`.
    ///
    /// This is the only builder of those bytes. The signature is not in them,
    /// and there is no name field. The values are written as they are: when
    /// verification hashes these bytes, check (a) has already decoded the DID
    /// as a canonical `did:key` and check (c) has already found the CID equal
    /// to a printed lab CID, so neither holds a character JSON would escape.
    pub fn package_record_payload(&self) -> Vec<u8> {
        format!(
            "{{\"cid\":\"{}\",\"schema\":\"{}\",\"signer_did\":\"{}\"}}",
            self.cid, PACKAGE_RECORD_SCHEMA, self.signer_did
        )
        .into_bytes()
    }
}

/// The digest a package record's signature covers: [`domain_separated_digest`]
/// of [`PACKAGE_RECORD_DOMAIN`] and [`PackageRecord::package_record_payload`].
/// Signing and verifying both call this.
fn package_record_message(record: &PackageRecord) -> [u8; 32] {
    domain_separated_digest(PACKAGE_RECORD_DOMAIN, &record.package_record_payload())
}

/// Sign a package record for the lab CID `cid` with `key`.
///
/// This is the one place a record is built and signed. The record's CID is
/// `cid`'s printed form, and `signer_did` is
/// `elastos_identity::encode_signing_key_did` of `key`. The signature is
/// Ed25519 over [`domain_separated_digest`] of [`PACKAGE_RECORD_DOMAIN`] and
/// the record's payload. It writes no file and reads none.
///
/// It signs a name, not bytes: `cid` must come from [`encode_listed_files`],
/// [`encode_entries`], [`lab_cid`] or [`checked_bundle`], so it names the
/// bytes that call read or was given. It grants nothing.
pub fn sign_cid_record(key: &SigningKey, cid: LabCid) -> PackageRecord {
    let cid = cid.to_string();
    let signer_did = signer_did_of(key);
    let mut record = PackageRecord {
        cid,
        signer_did,
        signature: [0; 64],
    };
    record.signature = key.sign(&package_record_message(&record)).to_bytes();
    record
}

/// Sign a package record for `bundle` with `key`.
///
/// This is [`lab_cid`] and then [`sign_cid_record`]; it builds and signs
/// nothing itself. A bundle [`lab_cid`] refuses gets no record, and the
/// refusal is [`lab_cid`]'s own. It writes no file and changes no bundle byte.
pub fn sign_package_record(key: &SigningKey, bundle: &Path) -> Result<PackageRecord, Refusal> {
    let cid = lab_cid(bundle)?;
    Ok(sign_cid_record(key, cid))
}

/// Check `record` against the lab CID `cid`.
///
/// This is the one place a record is checked. The checks run in this order,
/// and the first refusal is the answer:
///
/// 1. `elastos_identity::decode_did_key` on `record.signer_did`, with the name
///    signature's reason.
/// 2. `record.signer_did` is an exact member of `accepted`, with the name
///    signature's reason. An empty list refuses every signer.
/// 3. `record.cid` is `cid`'s printed form. Otherwise it is refused naming
///    both. This reads nothing from disk.
/// 4. Ed25519 verification of `record.signature` over the record's digest,
///    with the key from step 1 and the name signature's reason.
///
/// It checks a signature over a name, not bytes: `cid` must come from
/// [`encode_listed_files`], [`encode_entries`], [`lab_cid`] or
/// [`checked_bundle`]. `Ok(())` means all four passed. It is not a trust,
/// admission or launch value, and it grants nothing.
pub fn verify_cid_record(
    cid: LabCid,
    record: &PackageRecord,
    accepted: &[String],
) -> Result<(), Refusal> {
    let key = decode_signer(&record.signer_did)?;
    require_accepted(&record.signer_did, accepted)?;
    require_record_cid(cid, record)?;
    let message = package_record_message(record);
    verify_ed25519(
        &key,
        &message,
        &record.signature,
        &record.signer_did,
        &record.cid,
    )?;
    Ok(())
}

/// Check `record` against the bytes `checked` holds.
///
/// This is [`verify_cid_record`] over `checked.cid()`, so it holds no check
/// of its own and reads nothing from disk. `Ok(())` grants nothing.
pub fn verify_checked_package_record(
    checked: &CheckedBundle,
    record: &PackageRecord,
    accepted: &[String],
) -> Result<(), Refusal> {
    verify_cid_record(checked.cid(), record, accepted)
}

/// Check `record` against the bundle at `bundle`.
///
/// This is [`checked_bundle`] and then [`verify_checked_package_record`]. It
/// holds no check of its own, so a bundle the walk refuses is refused first,
/// with the walk's own reason.
pub fn verify_package_record(
    bundle: &Path,
    record: &PackageRecord,
    accepted: &[String],
) -> Result<(), Refusal> {
    let held = checked_bundle(bundle)?;
    verify_checked_package_record(&held, record, accepted)
}

/// Check (c) of a package record: it binds `cid`'s printed form.
fn require_record_cid(cid: LabCid, record: &PackageRecord) -> Result<(), Refusal> {
    if record.cid != cid.to_string() {
        return Err(Refusal::RecordNamesAnotherCid {
            record: record.cid.clone(),
            bundle: cid,
        });
    }
    Ok(())
}

impl VariantBinding {
    /// The bytes the binding's signature covers: compact JSON, keys in this
    /// order, no spaces and no trailing newline, the variants sorted by
    /// platform label in byte order:
    /// `{"recipe":"<cid>","schema":"lab.capsule-identity.variant-binding/v1","signer_did":"<did>","variants":[{"cid":"<cid>","platform":"<label>"},...]}`.
    ///
    /// This is the only builder of those bytes, and the one place the pairs
    /// are sorted, so the order they were given in does not change them. The
    /// signature is not in them, and there is no name or group identity
    /// field. The values are written as they are: when verification hashes
    /// these bytes, check (a) has decoded the DID as a canonical `did:key`,
    /// check (c) has found every label in [`VARIANT_PLATFORMS`], and checks
    /// (e) and (f) have found every CID equal to a printed lab CID, so none
    /// holds a character JSON would escape.
    pub fn variant_binding_payload(&self) -> Vec<u8> {
        let mut pairs: Vec<&(String, String)> = self.variants.iter().collect();
        pairs.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        let variants: Vec<String> = pairs
            .iter()
            .map(|(platform, cid)| format!("{{\"cid\":\"{cid}\",\"platform\":\"{platform}\"}}"))
            .collect();
        format!(
            "{{\"recipe\":\"{}\",\"schema\":\"{}\",\"signer_did\":\"{}\",\"variants\":[{}]}}",
            self.recipe,
            VARIANT_BINDING_SCHEMA,
            self.signer_did,
            variants.join(",")
        )
        .into_bytes()
    }
}

/// The digest a variant binding's signature covers: [`domain_separated_digest`]
/// of [`VARIANT_BINDING_DOMAIN`] and `payload`, the binding's
/// [`VariantBinding::variant_binding_payload`]. Signing and verifying both
/// call this.
fn variant_binding_message(payload: &[u8]) -> [u8; 32] {
    domain_separated_digest(VARIANT_BINDING_DOMAIN, payload)
}

/// The lab CID of a variant recipe: [`encode_entries`], which calls the one
/// encoder, of one entry at [`VARIANT_RECIPE_ENTRY`] holding `recipe`.
/// Nothing here reads the recipe from disk; the caller gives its bytes.
fn recipe_cid(recipe: &[u8]) -> Result<LabCid, Refusal> {
    encode_entries(&[BundleEntry {
        path: VARIANT_RECIPE_ENTRY.to_owned(),
        content: recipe.to_vec(),
    }])
}

/// Sign a variant binding with `key` for the bundles in `variants`, each
/// given with its platform label, and the recipe bytes `recipe`.
///
/// It first refuses the shapes verification refuses (check (c), for the
/// `given` list): no variant, a label not in [`VARIANT_PLATFORMS`], one label
/// twice, or [`PORTABLE_PLATFORM`] with another label. Then it checks each
/// bundle with [`checked_bundle`], the one walk, which gives both its lab CID
/// and its manifest type; a bundle the walk refuses gets no binding, and the
/// refusal is the walk's own. Then it refuses what check (e2) refuses, with
/// the same function: a `wasm` bundle under a label but
/// [`PORTABLE_PLATFORM`]. The recipe is named with [`encode_entries`] of one
/// entry. `signer_did` is
/// `elastos_identity::encode_signing_key_did` of `key`. The signature is
/// Ed25519 over [`domain_separated_digest`] of [`VARIANT_BINDING_DOMAIN`] and
/// the binding's payload. It writes no file and changes no bundle byte.
pub fn sign_variant_binding(
    key: &SigningKey,
    variants: &[(&str, &Path)],
    recipe: &[u8],
) -> Result<VariantBinding, Refusal> {
    let labels = variants.iter().map(|(platform, _)| *platform);
    require_variant_shape("given", labels)?;
    let mut walked = Vec::new();
    for (platform, bundle) in variants {
        walked.push((*platform, checked_bundle(bundle)?));
    }
    require_portable_wasm(
        walked
            .iter()
            .map(|(platform, checked)| (*platform, checked)),
    )?;
    let mut binding = VariantBinding {
        variants: walked
            .iter()
            .map(|(platform, checked)| ((*platform).to_owned(), checked.cid().to_string()))
            .collect(),
        recipe: recipe_cid(recipe)?.to_string(),
        signer_did: signer_did_of(key),
        signature: [0; 64],
    };
    let payload = binding.variant_binding_payload();
    binding.signature = key.sign(&variant_binding_message(&payload)).to_bytes();
    Ok(binding)
}

/// Check `binding` against the checked bundles in `variants`, each given with
/// its platform label, and the recipe bytes `recipe`.
///
/// The checks run in this order, and the first refusal is the answer:
///
/// 1. (a) `elastos_identity::decode_did_key` on `binding.signer_did`, with
///    the name signature's reason.
/// 2. (b) `binding.signer_did` is an exact member of `accepted`, with the name
///    signature's reason. An empty list refuses every signer.
/// 3. (c) The shape of the binding's pairs, then of the given pairs: at least
///    one variant, every label one of [`VARIANT_PLATFORMS`], no label twice,
///    and [`PORTABLE_PLATFORM`] with no other label.
/// 4. (d) The given platforms are the binding's platforms; otherwise both
///    sorted lists are named.
/// 5. (e) Each given bundle's printed lab CID is the binding's CID for its
///    label; otherwise the label and both CIDs are named.
/// 6. (e2) A given bundle whose manifest `type` is `wasm` is bound only under
///    [`PORTABLE_PLATFORM`]; otherwise its label and CID are named. So a WASM
///    app has one variant and one CID.
/// 7. (f) The lab CID of `recipe` is the binding's recipe CID; otherwise
///    both are named.
/// 8. (g) Ed25519 verification of `binding.signature` over the binding's
///    digest, with the key from step 1 and the name signature's reason. The
///    signed name in that reason is the payload, as text.
///
/// It reads nothing from disk. `Ok(())` means all eight passed. It is not a
/// trust, admission or launch value, and it grants nothing.
///
/// Each label is the signer's claim. No check reads a label from a manifest,
/// path or payload, so it is not checked against the bundle's bytes: a
/// variant built for one platform verifies under another label if the signer
/// bound it there.
pub fn verify_checked_variant_binding(
    binding: &VariantBinding,
    variants: &[(&str, &CheckedBundle)],
    recipe: &[u8],
    accepted: &[String],
) -> Result<(), Refusal> {
    let key = decode_signer(&binding.signer_did)?;
    require_accepted(&binding.signer_did, accepted)?;
    require_variant_shape(
        "binding",
        binding
            .variants
            .iter()
            .map(|(platform, _)| platform.as_str()),
    )?;
    require_variant_shape("given", variants.iter().map(|(platform, _)| *platform))?;
    require_same_platforms(binding, variants)?;
    require_variant_cids(binding, variants)?;
    require_portable_wasm(variants.iter().copied())?;
    require_recipe_cid(binding, recipe)?;
    let payload = binding.variant_binding_payload();
    let message = variant_binding_message(&payload);
    verify_ed25519(
        &key,
        &message,
        &binding.signature,
        &binding.signer_did,
        &String::from_utf8_lossy(&payload),
    )?;
    Ok(())
}

/// Check `binding` against the bundles at the paths in `variants`, each given
/// with its platform label, and the recipe bytes `recipe`.
///
/// This is [`checked_bundle`] for each path, in the order given, and then
/// [`verify_checked_variant_binding`]. It holds no check of its own, so a
/// bundle the walk refuses is refused first, with the walk's own reason.
pub fn verify_variant_binding(
    binding: &VariantBinding,
    variants: &[(&str, &Path)],
    recipe: &[u8],
    accepted: &[String],
) -> Result<(), Refusal> {
    let walked = variants
        .iter()
        .map(|(platform, bundle)| Ok((*platform, checked_bundle(bundle)?)))
        .collect::<Result<Vec<_>, Refusal>>()?;
    let given: Vec<(&str, &CheckedBundle)> = walked
        .iter()
        .map(|(platform, walked)| (*platform, walked))
        .collect();
    verify_checked_variant_binding(binding, &given, recipe, accepted)
}

/// Check (c) on one list of platform labels; `list` says whose, `binding` or
/// `given`. The first label not in [`VARIANT_PLATFORMS`], or the first label
/// seen twice, is refused; then a list that holds [`PORTABLE_PLATFORM`] and
/// another label is refused naming all its labels; a list with no label is
/// refused.
fn require_variant_shape<'a>(
    list: &'static str,
    labels: impl IntoIterator<Item = &'a str>,
) -> Result<(), Refusal> {
    let mut seen: Vec<&str> = Vec::new();
    for label in labels {
        if !VARIANT_PLATFORMS.contains(&label) {
            return Err(Refusal::UnknownPlatform {
                list,
                label: label.to_owned(),
            });
        }
        if seen.contains(&label) {
            return Err(Refusal::DuplicatePlatform {
                list,
                label: label.to_owned(),
            });
        }
        seen.push(label);
    }
    if seen.len() > 1 && seen.contains(&PORTABLE_PLATFORM) {
        let mut labels: Vec<String> = seen.iter().map(|label| (*label).to_owned()).collect();
        labels.sort();
        return Err(Refusal::PortableNotAlone { list, labels });
    }
    if seen.is_empty() {
        return Err(Refusal::NoVariants { list });
    }
    Ok(())
}

/// Check (d): the given platforms, sorted, are the binding's, sorted.
fn require_same_platforms(
    binding: &VariantBinding,
    variants: &[(&str, &CheckedBundle)],
) -> Result<(), Refusal> {
    let mut bound: Vec<String> = binding
        .variants
        .iter()
        .map(|(platform, _)| platform.clone())
        .collect();
    let mut given: Vec<String> = variants
        .iter()
        .map(|(platform, _)| (*platform).to_owned())
        .collect();
    bound.sort();
    given.sort();
    if bound != given {
        return Err(Refusal::PlatformsDiffer {
            binding: bound,
            given,
        });
    }
    Ok(())
}

/// Check (e): each given bundle, taken in label byte order, has the printed
/// lab CID the binding names for its label. Check (d) has matched the
/// platforms, so every label is bound; were one not, its empty CID would
/// match no bundle and be refused here too.
fn require_variant_cids(
    binding: &VariantBinding,
    variants: &[(&str, &CheckedBundle)],
) -> Result<(), Refusal> {
    let mut given: Vec<&(&str, &CheckedBundle)> = variants.iter().collect();
    given.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    for (platform, checked) in given {
        let bound = binding
            .variants
            .iter()
            .find(|(label, _)| label == platform)
            .map_or("", |(_, cid)| cid.as_str());
        if bound != checked.cid().to_string() {
            return Err(Refusal::VariantNamesAnotherCid {
                platform: (*platform).to_owned(),
                binding: bound.to_owned(),
                bundle: checked.cid(),
            });
        }
    }
    Ok(())
}

/// Check (e2), which signing runs too: a bundle whose manifest `type` is
/// `wasm`, as the one manifest check found it, is bound only under
/// [`PORTABLE_PLATFORM`]. Of the bundles under another label, the first in
/// label byte order is refused, naming its label and its lab CID.
fn require_portable_wasm<'a>(
    variants: impl IntoIterator<Item = (&'a str, &'a CheckedBundle)>,
) -> Result<(), Refusal> {
    let refused = variants
        .into_iter()
        .filter(|(platform, checked)| checked.wasm() && *platform != PORTABLE_PLATFORM)
        .min_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    match refused {
        Some((platform, checked)) => Err(Refusal::WasmNotPortable {
            platform: platform.to_owned(),
            bundle: checked.cid(),
        }),
        None => Ok(()),
    }
}

/// Check (f): the recipe bytes' lab CID is the binding's recipe CID.
fn require_recipe_cid(binding: &VariantBinding, recipe: &[u8]) -> Result<(), Refusal> {
    let named = recipe_cid(recipe)?;
    if binding.recipe != named.to_string() {
        return Err(Refusal::RecipeNamesAnotherCid {
            binding: binding.recipe.clone(),
            recipe: named,
        });
    }
    Ok(())
}
