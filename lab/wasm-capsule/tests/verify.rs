//! wc-004: the one verify path, `wasm_capsule_tools::verify` (PRINCIPLES P10,
//! P11, P13, P15). A checked bundle's in-memory name signature is checked by
//! cc-capsule-identity's `verify_checked_signature`, then the manifest's
//! entrypoint module, from the same checked bytes, goes through the
//! cx-wasm-audit crate's `audit` with the caller's granted imports. Ordinary
//! callers grant nothing; only the grant tests pass a non-empty list.
//!
//! wc-009a: `read_grants`, the one lab grants file reader, and the grants the
//! module does not import (`unused_grants()`), also in `verify.rs`.
//!
//! Every test key is made fresh in memory inside its test, with no fixed seed,
//! and is never written, kept in a constant or printed. The signature stays in
//! memory too: there is no signature file. The tests share one process, so
//! none changes process-wide state.

mod common;

use capsule_identity::{
    checked_bundle, sign_bundle, verify_checked_signature, BundleEntry, NameSignature,
    Refusal as IdentityRefusal,
};
use common::build::{lane_dir, run_build, sha256_file, Receipt, TempDir};
use common::grants::{env_f, grant, grants_file, write_grants, IMPORTING_MODULE};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use wasm_capsule_audit::{audit, DeclaredImport, Refusal as AuditRefusal};
use wasm_capsule_tools::verify::{
    read_grants, verify_bundle, verify_checked, GrantsReason, GrantsRefusal, VerifiedBundle,
    VerifyRefusal, GRANTS_LABEL, GRANTS_SCHEMA,
};
use wasm_capsule_tools::{bundle_identity, CAPSULE_MANIFEST};

/// The smallest core Wasm module: the magic and version 1, no sections.
const MODULE: &[u8] = b"\0asm\x01\0\0\0";

/// A valid core module with one custom section, `x`, whose data is a whole
/// Wasm module: the audit's "code in custom section" case.
const CUSTOM_CODE_MODULE: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic, version 1
    0x00, 0x0a, 0x01, b'x', // custom section, 10 bytes, named "x"
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // its data: a module
];

/// Bytes that are not a core module.
const MALFORMED_MODULE: &[u8] = b"not a module";

/// wc-001's pinned `capsule.wasm` (README, "Claim scope").
const PINNED_ARTIFACT_SHA256: &str =
    "6dd9af1a8d33d14f48514611663e3f5b262f91ef2729de4ec851441af9b22b13";

/// The unsigned reason, exactly.
const UNSIGNED: &str = "the bundle has no signature: an unsigned bundle is refused";

fn fresh_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// The canonical `did:key` of `key`, from the Runtime's own encoder.
fn did(key: &SigningKey) -> String {
    elastos_identity::encode_signing_key_did(key)
}

/// This capsule's manifest with its entrypoint changed to `entrypoint`.
fn manifest_with_entrypoint(entrypoint: &str) -> Vec<u8> {
    let text = std::str::from_utf8(CAPSULE_MANIFEST).expect("the manifest is UTF-8");
    let declared = "\"entrypoint\": \"capsule.wasm\"";
    assert_eq!(
        text.matches(declared).count(),
        1,
        "the manifest's entrypoint"
    );
    text.replace(declared, &format!("\"entrypoint\": \"{entrypoint}\""))
        .into_bytes()
}

/// A new bundle folder `name` under `tmp`, holding `manifest` as
/// `capsule.json` and each of `files`.
fn bundle_with(tmp: &TempDir, name: &str, manifest: &[u8], files: &[(&str, &[u8])]) -> PathBuf {
    let bundle = tmp.path().join(name);
    fs::create_dir(&bundle).expect("create the bundle folder");
    fs::write(bundle.join("capsule.json"), manifest).expect("write capsule.json");
    for (path, bytes) in files {
        fs::write(bundle.join(path), bytes).expect("write a bundle file");
    }
    bundle
}

/// The fixture: this capsule's manifest and the 8-byte module.
fn fixture(tmp: &TempDir) -> PathBuf {
    bundle_with(tmp, "bundle", CAPSULE_MANIFEST, &[("capsule.wasm", MODULE)])
}

/// This capsule's manifest beside a module that imports `env.f`.
fn importing_bundle(tmp: &TempDir) -> PathBuf {
    bundle_with(
        tmp,
        "importing",
        CAPSULE_MANIFEST,
        &[("capsule.wasm", IMPORTING_MODULE)],
    )
}

fn sign(key: &SigningKey, bundle: &Path) -> NameSignature {
    sign_bundle(key, bundle).unwrap_or_else(|refusal| panic!("sign_bundle refused: {refusal}"))
}

fn verified(result: Result<VerifiedBundle, VerifyRefusal>) -> VerifiedBundle {
    result.unwrap_or_else(|refusal| panic!("the verifier refused: {refusal}"))
}

fn refused(result: Result<VerifiedBundle, VerifyRefusal>) -> VerifyRefusal {
    match result {
        Ok(value) => panic!("the verifier passed {}, not a refusal", value.cid()),
        Err(refusal) => refusal,
    }
}

/// The identity lane's mismatch refusal for `bundle` as it is now, against
/// the signed name; its text names both values.
fn mismatch(bundle: &Path, sig: &NameSignature) -> VerifyRefusal {
    let actual = bundle_identity(bundle).expect("the changed bundle still gets a lab CID");
    assert_ne!(actual.to_string(), sig.name, "the bundle did not change");
    VerifyRefusal::Identity(IdentityRefusal::NameMismatch {
        actual,
        claimed: sig.name.clone(),
    })
}

/// Sign the fixture-like `bundle`, change it with `change`, and check that
/// the verifier refuses it with the identity lane's mismatch reason.
fn assert_changed_after_signing_is_refused(bundle: &Path, change: impl FnOnce(&Path)) {
    let key = fresh_key();
    let sig = sign(&key, bundle);
    change(bundle);
    let refusal = refused(verify_bundle(bundle, Some(&sig), &[did(&key)], &[]));
    let expected = mismatch(bundle, &sig);
    assert_eq!(refusal, expected);
    let text = refusal.to_string();
    assert_eq!(
        text,
        format!(
            "bundle bytes name {}; the claim is {}",
            bundle_identity(bundle).expect("named"),
            sig.name
        )
    );
}

/// The entries as (path, bytes), sorted by path.
fn sorted(entries: &[BundleEntry]) -> Vec<(String, Vec<u8>)> {
    let mut entries: Vec<(String, Vec<u8>)> = entries
        .iter()
        .map(|entry| (entry.path.clone(), entry.content.clone()))
        .collect();
    entries.sort();
    entries
}

#[test]
fn signed_bundle_verifies_against_its_key() {
    let tmp = TempDir::new("verify-signed");
    let bundle = fixture(&tmp);
    let key = fresh_key();
    let sig = sign(&key, &bundle);

    let value = verified(verify_bundle(&bundle, Some(&sig), &[did(&key)], &[]));
    assert_eq!(
        value.cid(),
        bundle_identity(&bundle).expect("the fixture is named")
    );
    assert!(value.imports().is_empty(), "imports: {:?}", value.imports());
    let on_disk = vec![
        (
            "capsule.json".to_owned(),
            fs::read(bundle.join("capsule.json")).expect("read capsule.json"),
        ),
        (
            "capsule.wasm".to_owned(),
            fs::read(bundle.join("capsule.wasm")).expect("read capsule.wasm"),
        ),
    ];
    assert_eq!(sorted(value.entries()), on_disk);
}

#[test]
fn unsigned_bundle_is_refused() {
    let tmp = TempDir::new("verify-unsigned");
    let bundle = fixture(&tmp);
    let accepted = [did(&fresh_key())];

    let refusal = refused(verify_bundle(&bundle, None, &accepted, &[]));
    assert_eq!(refusal, VerifyRefusal::Unsigned);
    assert_eq!(refusal.to_string(), UNSIGNED);

    let checked = checked_bundle(&bundle).expect("the fixture is checked");
    let refusal = refused(verify_checked(checked, None, &accepted, &[]));
    assert_eq!(refusal, VerifyRefusal::Unsigned);
}

#[test]
fn bundle_signed_by_an_unlisted_key_is_refused() {
    let tmp = TempDir::new("verify-unlisted");
    let bundle = fixture(&tmp);
    let key_a = fresh_key();
    let key_b = fresh_key();
    let sig = sign(&key_b, &bundle);
    let expected = VerifyRefusal::Identity(IdentityRefusal::SignerNotAccepted { did: did(&key_b) });
    let text = format!("signer {} is not in the accepted list", did(&key_b));

    let refusal = refused(verify_bundle(&bundle, Some(&sig), &[did(&key_a)], &[]));
    assert_eq!(refusal, expected);
    assert_eq!(refusal.to_string(), text);

    let refusal = refused(verify_bundle(&bundle, Some(&sig), &[], &[]));
    assert_eq!(refusal, expected, "an empty accepted list");
    assert_eq!(refusal.to_string(), text);
}

#[test]
fn wasm_changed_after_signing_is_refused() {
    let tmp = TempDir::new("verify-wasm-changed");
    let bundle = fixture(&tmp);
    assert_changed_after_signing_is_refused(&bundle, |bundle| {
        let mut module = MODULE.to_vec();
        module[4] = 0x02;
        fs::write(bundle.join("capsule.wasm"), module).expect("change capsule.wasm");
    });
}

#[test]
fn manifest_changed_after_signing_is_refused() {
    let tmp = TempDir::new("verify-manifest-changed");
    let bundle = fixture(&tmp);
    assert_changed_after_signing_is_refused(&bundle, |bundle| {
        let text = std::str::from_utf8(CAPSULE_MANIFEST).expect("the manifest is UTF-8");
        let inside_description = "lab tooling only";
        assert_eq!(text.matches(inside_description).count(), 1);
        let changed = text.replace(inside_description, "Lab tooling only");
        fs::write(bundle.join("capsule.json"), changed).expect("change capsule.json");
    });
}

#[test]
fn extra_file_after_signing_is_refused() {
    let tmp = TempDir::new("verify-extra-file");
    let bundle = fixture(&tmp);
    assert_changed_after_signing_is_refused(&bundle, |bundle| {
        fs::write(bundle.join("extra.txt"), b"added after signing\n").expect("add a file");
    });
}

#[test]
fn bundle_with_undeclared_import_is_refused_even_if_signed() {
    let tmp = TempDir::new("verify-undeclared");
    let bundle = importing_bundle(&tmp);
    let key = fresh_key();
    let sig = sign(&key, &bundle);

    let refusal = refused(verify_bundle(&bundle, Some(&sig), &[did(&key)], &[]));
    assert_eq!(
        refusal,
        VerifyRefusal::Audit(AuditRefusal::Undeclared {
            module: "env".into(),
            name: "f".into(),
        })
    );
    assert_eq!(refusal.to_string(), "undeclared import env.f");
}

#[test]
fn a_grant_reaches_the_audit_unchanged() {
    let tmp = TempDir::new("verify-grant");
    let bundle = importing_bundle(&tmp);
    let key = fresh_key();
    let sig = sign(&key, &bundle);
    let granted = [env_f()];

    let value = verified(verify_bundle(&bundle, Some(&sig), &[did(&key)], &granted));
    let audits_own =
        audit(IMPORTING_MODULE, &granted).expect("the audit passes the granted import");
    assert_eq!(value.imports(), audits_own.as_slice());
    assert_eq!(value.imports(), [env_f()].as_slice());
}

#[test]
fn verifier_audits_the_checked_bytes() {
    let tmp = TempDir::new("verify-checked-bytes");
    let bundle = fixture(&tmp);
    let key = fresh_key();
    let sig = sign(&key, &bundle);
    let accepted = [did(&key)];
    let held = checked_bundle(&bundle).expect("the fixture is checked");
    fs::write(bundle.join("capsule.wasm"), IMPORTING_MODULE).expect("replace capsule.wasm");

    let value = verified(verify_checked(held, Some(&sig), &accepted, &[]));
    assert!(
        value.imports().is_empty(),
        "the held value was audited from disk: {:?}",
        value.imports()
    );
    let module = value
        .entries()
        .iter()
        .find(|entry| entry.path == "capsule.wasm")
        .expect("the held value keeps capsule.wasm");
    assert_eq!(module.content, MODULE);

    let refusal = refused(verify_bundle(&bundle, Some(&sig), &accepted, &[]));
    assert_eq!(refusal, mismatch(&bundle, &sig));
}

#[test]
fn the_real_capsule_passes_the_verifier() {
    let tmp = TempDir::new("verify-real");
    let out = tmp.path().join("out");
    fs::create_dir(&out).expect("create OUT_DIR");
    run_build(&lane_dir(), &out);
    let built = fs::read(out.join("capsule.wasm")).expect("read the built capsule.wasm");
    let bundle = bundle_with(
        &tmp,
        "bundle",
        CAPSULE_MANIFEST,
        &[("capsule.wasm", &built)],
    );
    let key = fresh_key();
    let sig = sign(&key, &bundle);

    let value = verified(verify_bundle(&bundle, Some(&sig), &[did(&key)], &[]));
    assert!(value.imports().is_empty(), "imports: {:?}", value.imports());
    let module_sha256 = sha256_file(&bundle.join("capsule.wasm"));
    assert_eq!(
        module_sha256,
        Receipt::read(&out).get("artifact_sha256"),
        "the verified module is not the receipted artifact"
    );
    assert_eq!(module_sha256, PINNED_ARTIFACT_SHA256);
}

#[test]
fn missing_entrypoint_is_refused() {
    let tmp = TempDir::new("verify-no-entrypoint");
    let bundle = bundle_with(
        &tmp,
        "bundle",
        &manifest_with_entrypoint("main.wasm"),
        &[("capsule.wasm", MODULE)],
    );
    let key = fresh_key();
    let sig = sign(&key, &bundle);

    let refusal = refused(verify_bundle(&bundle, Some(&sig), &[did(&key)], &[]));
    assert_eq!(
        refusal,
        VerifyRefusal::EntrypointMissing {
            entrypoint: "main.wasm".into()
        }
    );
    assert_eq!(
        refusal.to_string(),
        "the manifest's entrypoint \"main.wasm\" is not a file in the bundle"
    );
}

#[test]
fn verifier_uses_manifest_entrypoint() {
    let tmp = TempDir::new("verify-entrypoint");
    let bundle = bundle_with(
        &tmp,
        "bundle",
        &manifest_with_entrypoint("main.wasm"),
        &[("main.wasm", IMPORTING_MODULE), ("capsule.wasm", MODULE)],
    );
    let key = fresh_key();
    let sig = sign(&key, &bundle);
    let accepted = [did(&key)];

    let refusal = refused(verify_bundle(&bundle, Some(&sig), &accepted, &[]));
    assert_eq!(refusal.to_string(), "undeclared import env.f");
    let value = verified(verify_bundle(&bundle, Some(&sig), &accepted, &[env_f()]));
    assert_eq!(value.imports(), [env_f()].as_slice());
}

#[test]
fn verified_entrypoint_is_the_audited_module() {
    let tmp = TempDir::new("verify-entrypoint-accessor");
    let bundle = bundle_with(
        &tmp,
        "bundle",
        &manifest_with_entrypoint("main.wasm"),
        &[("capsule.wasm", MODULE), ("main.wasm", IMPORTING_MODULE)],
    );
    let key = fresh_key();
    let sig = sign(&key, &bundle);

    let value = verified(verify_bundle(&bundle, Some(&sig), &[did(&key)], &[env_f()]));
    let entrypoint = value.entrypoint();
    assert_eq!(
        entrypoint.path, "main.wasm",
        "not the manifest's entrypoint"
    );
    assert_eq!(
        entrypoint.content, IMPORTING_MODULE,
        "not the audited bytes"
    );
    assert_eq!(
        audit(&entrypoint.content, &[env_f()]).expect("the audit passes it"),
        value.imports(),
        "the entrypoint is not the module the audit read"
    );
    let held = value
        .entries()
        .iter()
        .find(|entry| entry.path == "main.wasm")
        .expect("the checked entries hold main.wasm");
    assert!(
        std::ptr::eq(entrypoint, held),
        "the entrypoint is not one of the checked entries"
    );
}

#[test]
fn verifier_preserves_upstream_refusals() {
    let tmp = TempDir::new("verify-upstream");
    let key = fresh_key();
    let accepted = [did(&key)];

    // The walk's refusals, unchanged: no manifest, and a link.
    let no_manifest = tmp.path().join("no-manifest");
    fs::create_dir(&no_manifest).expect("create a folder");
    fs::write(no_manifest.join("capsule.wasm"), MODULE).expect("write capsule.wasm");
    let linked = fixture(&tmp);
    let sig = sign(&key, &linked);
    std::os::unix::fs::symlink("capsule.wasm", linked.join("link.wasm")).expect("plant a link");
    for (folder, kind) in [(&no_manifest, "no manifest"), (&linked, "a link")] {
        let walk = checked_bundle(folder).expect_err("the walk refuses the folder");
        let refusal = refused(verify_bundle(folder, Some(&sig), &accepted, &[]));
        assert_eq!(refusal.to_string(), walk.to_string(), "{kind}");
        assert_eq!(refusal, VerifyRefusal::Identity(walk), "{kind}");
    }

    // The signature check's refusals, unchanged: a malformed DID, a name that
    // is not a lab CID, and a signature that does not verify.
    let bundle = bundle_with(
        &tmp,
        "signed",
        CAPSULE_MANIFEST,
        &[("capsule.wasm", MODULE)],
    );
    let good = sign(&key, &bundle);
    let mut bad_did = good.clone();
    bad_did.signer_did = "did:key:not-a-key".into();
    let mut bad_name = good.clone();
    bad_name.name = "sha256:not-a-lab-cid".into();
    let mut bad_signature = good.clone();
    bad_signature.signature[0] ^= 0x01;
    let cases = [
        (bad_did, "a malformed DID"),
        (bad_name, "a malformed name"),
        (bad_signature, "an invalid signature"),
    ];
    for (sig, kind) in cases {
        let checked = checked_bundle(&bundle).expect("the bundle is checked");
        let own = verify_checked_signature(&checked, &sig, &accepted)
            .expect_err("the identity lane refuses the signature");
        let refusal = refused(verify_checked(checked, Some(&sig), &accepted, &[]));
        assert_eq!(refusal.to_string(), own.to_string(), "{kind}");
        assert_eq!(refusal, VerifyRefusal::Identity(own), "{kind}");
    }

    // The audit's refusals, unchanged: a malformed module and code in a
    // custom section.
    for (module, kind) in [
        (MALFORMED_MODULE, "a malformed module"),
        (CUSTOM_CODE_MODULE, "code in a custom section"),
    ] {
        let tmp = TempDir::new("verify-upstream-audit");
        let bundle = bundle_with(
            &tmp,
            "bundle",
            CAPSULE_MANIFEST,
            &[("capsule.wasm", module)],
        );
        let sig = sign(&key, &bundle);
        let own = audit(module, &[]).expect_err("the audit refuses the module");
        let refusal = refused(verify_bundle(&bundle, Some(&sig), &accepted, &[]));
        assert_eq!(refusal.to_string(), own.to_string(), "{kind}");
        assert_eq!(refusal, VerifyRefusal::Audit(own), "{kind}");
    }
}

#[test]
fn verifier_preserves_check_order() {
    let tmp = TempDir::new("verify-order");
    let key = fresh_key();
    let unlisted = fresh_key();
    let accepted = [did(&key)];
    let not_accepted = VerifyRefusal::Identity(IdentityRefusal::SignerNotAccepted {
        did: did(&unlisted),
    });

    // The walk before the unsigned check: no manifest and no signature.
    let no_manifest = tmp.path().join("no-manifest");
    fs::create_dir(&no_manifest).expect("create a folder");
    fs::write(no_manifest.join("capsule.wasm"), MODULE).expect("write capsule.wasm");
    assert_eq!(
        refused(verify_bundle(&no_manifest, None, &accepted, &[])),
        VerifyRefusal::Identity(IdentityRefusal::NoManifest)
    );

    // The unsigned check before the audit: no signature and an undeclared
    // import.
    let importing = importing_bundle(&tmp);
    assert_eq!(
        refused(verify_bundle(&importing, None, &accepted, &[])),
        VerifyRefusal::Unsigned
    );

    // The signature before the audit: an unlisted signer and an undeclared
    // import.
    let sig = sign(&unlisted, &importing);
    assert_eq!(
        refused(verify_bundle(&importing, Some(&sig), &accepted, &[])),
        not_accepted
    );

    // The signature before the entrypoint: an unlisted signer and a missing
    // entrypoint.
    let missing = bundle_with(
        &tmp,
        "missing",
        &manifest_with_entrypoint("main.wasm"),
        &[("capsule.wasm", MODULE)],
    );
    let sig = sign(&unlisted, &missing);
    assert_eq!(
        refused(verify_bundle(&missing, Some(&sig), &accepted, &[])),
        not_accepted
    );

    // The name before the audit: bytes changed after signing into a module
    // with an undeclared import.
    let bundle = fixture(&tmp);
    let sig = sign(&key, &bundle);
    fs::write(bundle.join("capsule.wasm"), IMPORTING_MODULE).expect("replace capsule.wasm");
    assert_eq!(
        refused(verify_bundle(&bundle, Some(&sig), &accepted, &[])),
        mismatch(&bundle, &sig)
    );
}

#[test]
fn verifier_uses_audit_api_v1() {
    assert_eq!(wasm_capsule_audit::AUDIT_API, 1);
}

/// The reader's refusal for the file at `path`.
fn grants_refused(path: &Path) -> GrantsRefusal {
    match read_grants(path) {
        Ok(grants) => panic!("read_grants passed {}: {grants:?}", path.display()),
        Err(refusal) => refusal,
    }
}

/// A grants document with `imports` as given and the right schema and label.
fn grants_text(imports: &str) -> String {
    format!(r#"{{"schema": "{GRANTS_SCHEMA}", "label": "{GRANTS_LABEL}", "imports": {imports}}}"#)
}

/// wc-009a: every refusal of `read_grants` has its own reason, asserted as an
/// exact string after the path, and a well-formed file reads in file order.
#[test]
fn grants_file_refusals_keep_their_reason() {
    assert_eq!(GRANTS_SCHEMA, "wc-009.lab-grants/v1");
    assert_eq!(GRANTS_LABEL, "lab stand-in, not admission");
    let tmp = TempDir::new("grants-refusals");
    let folder = tmp.path();

    // Well-formed: an empty list, and two grants kept in file order.
    let empty = grants_file(folder, "empty.json", &[]);
    assert_eq!(read_grants(&empty).expect("an empty list is valid"), []);
    let two = grants_file(folder, "two.json", &[("env", "g"), ("env", "f")]);
    assert_eq!(
        read_grants(&two).expect("two grants are valid"),
        [grant("env", "g"), env_f()]
    );

    // The file cannot be read: the OS cause is kept.
    let missing = folder.join("missing.json");
    let refusal = grants_refused(&missing);
    match &refusal.reason {
        GrantsReason::Unreadable(error) => {
            assert_eq!(error.kind(), std::io::ErrorKind::NotFound)
        }
        other => panic!("not an unreadable refusal: {other}"),
    }
    assert_eq!(refusal.path, missing);
    assert_eq!(
        refusal.to_string(),
        format!(
            "{}: the grants file cannot be read: No such file or directory (os error 2)",
            missing.display()
        )
    );

    let entry = "grant 1 is not an object of exactly two strings, module and name";
    let cases: [(&str, String, &str); 19] = [
        (
            "not JSON",
            "{".into(),
            "the grants file is not JSON: EOF while parsing an object at line 1 column 1",
        ),
        (
            "a list document",
            "[]".into(),
            "the grants file is not a JSON object",
        ),
        (
            "a string document",
            "\"grants\"".into(),
            "the grants file is not a JSON object",
        ),
        (
            "an unknown key",
            format!(
                r#"{{"schema": "{GRANTS_SCHEMA}", "label": "{GRANTS_LABEL}", "imports": [], "kind": "x"}}"#
            ),
            "the grants file has an unknown key \"kind\"",
        ),
        (
            "no schema",
            format!(r#"{{"label": "{GRANTS_LABEL}", "imports": []}}"#),
            "the grants file has no \"schema\" key",
        ),
        (
            "no label",
            format!(r#"{{"schema": "{GRANTS_SCHEMA}", "imports": []}}"#),
            "the grants file has no \"label\" key",
        ),
        (
            "no imports",
            format!(r#"{{"schema": "{GRANTS_SCHEMA}", "label": "{GRANTS_LABEL}"}}"#),
            "the grants file has no \"imports\" key",
        ),
        (
            "another schema",
            format!(
                r#"{{"schema": "wc-009.lab-grants/v2", "label": "{GRANTS_LABEL}", "imports": []}}"#
            ),
            "the grants file's schema is \"wc-009.lab-grants/v2\", not \"wc-009.lab-grants/v1\"",
        ),
        (
            "a number schema",
            format!(r#"{{"schema": 1, "label": "{GRANTS_LABEL}", "imports": []}}"#),
            "the grants file's schema is 1, not \"wc-009.lab-grants/v1\"",
        ),
        (
            "another label",
            format!(r#"{{"schema": "{GRANTS_SCHEMA}", "label": "admission", "imports": []}}"#),
            "the grants file's label is \"admission\", not \"lab stand-in, not admission\"",
        ),
        (
            "imports as an object",
            grants_text(r#"{"module": "env", "name": "f"}"#),
            "the grants file's imports is not a list",
        ),
        (
            "an entry that is a string",
            grants_text(r#"[{"module": "env", "name": "g"}, "env.f"]"#),
            entry,
        ),
        (
            "an entry with no name",
            grants_text(r#"[{"module": "env", "name": "g"}, {"module": "env"}]"#),
            entry,
        ),
        (
            "an entry with a third key",
            grants_text(
                r#"[{"module": "env", "name": "g"}, {"module": "env", "name": "f", "kind": "func"}]"#,
            ),
            entry,
        ),
        (
            "an entry with another key",
            grants_text(r#"[{"module": "env", "name": "g"}, {"module": "env", "nam": "f"}]"#),
            entry,
        ),
        (
            "an entry with a number name",
            grants_text(r#"[{"module": "env", "name": "g"}, {"module": "env", "name": 1}]"#),
            entry,
        ),
        (
            "an entry with a null module",
            grants_text(r#"[{"module": "env", "name": "g"}, {"module": null, "name": "f"}]"#),
            entry,
        ),
        (
            "the same pair twice",
            grants_text(
                r#"[{"module": "env", "name": "f"}, {"module": "env", "name": "g"}, {"name": "f", "module": "env"}]"#,
            ),
            "the grant env.f is listed twice",
        ),
        (
            "a label with a trailing space",
            format!(
                r#"{{"schema": "{GRANTS_SCHEMA}", "label": "{GRANTS_LABEL} ", "imports": []}}"#
            ),
            "the grants file's label is \"lab stand-in, not admission \", not \"lab stand-in, not admission\"",
        ),
    ];
    for (index, (kind, text, reason)) in cases.iter().enumerate() {
        let path = write_grants(folder, &format!("case-{index}.json"), text);
        let refusal = grants_refused(&path);
        assert_eq!(refusal.path, path, "{kind}");
        assert_eq!(
            refusal.to_string(),
            format!("{}: {reason}", path.display()),
            "{kind}"
        );
    }
}

/// wc-009a: `unused_grants()` holds exactly the grants the module does not
/// import, in file order, and `imports()` only what the module imports. The
/// grants file is outside the bundle and no part of its lab CID.
#[test]
fn unused_grants_excludes_linked_and_preserves_file_order() {
    let tmp = TempDir::new("verify-unused");
    let bundle = importing_bundle(&tmp);
    let key = fresh_key();
    let sig = sign(&key, &bundle);
    let name = bundle_identity(&bundle).expect("name the bundle");
    let grants = grants_file(
        tmp.path(),
        "grants.json",
        &[("z", "last"), ("env", "f"), ("a", "first")],
    );
    let granted: Vec<DeclaredImport> = read_grants(&grants).expect("read the grants");

    let value = verified(verify_bundle(&bundle, Some(&sig), &[did(&key)], &granted));
    assert_eq!(value.imports(), [env_f()], "the linked imports");
    assert_eq!(
        value.unused_grants(),
        [grant("z", "last"), grant("a", "first")],
        "the unused grants, in file order"
    );
    assert_eq!(value.cid(), name, "the grants changed the lab CID");
    let mut paths: Vec<&str> = value
        .entries()
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    paths.sort();
    assert_eq!(
        paths,
        ["capsule.json", "capsule.wasm"],
        "the bundle entries"
    );
}

/// `text` without its whole-line comments (`//`, or `#` for a manifest).
fn without_comments(text: &str, marker: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with(marker))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The verifier's module, without its whole-line comments.
fn verifier_code() -> String {
    without_comments(include_str!("../tools/src/verify.rs"), "//")
}

/// Every `.rs` file under the tools crate's `src/`, without whole-line
/// comments, as (path, code).
fn tools_code() -> Vec<(PathBuf, String)> {
    let mut files = Vec::new();
    let mut folders = vec![lane_dir().join("tools").join("src")];
    while let Some(folder) = folders.pop() {
        for entry in fs::read_dir(&folder).expect("list a tools folder") {
            let path = entry.expect("read a tools entry").path();
            if path.is_dir() {
                folders.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let text = fs::read_to_string(&path).expect("read a tools source file");
                files.push((path, without_comments(&text, "//")));
            }
        }
    }
    assert!(!files.is_empty(), "no tools source found");
    files
}

/// One item of `code`: the text from `head`, found exactly once, to the
/// closing brace at `head`'s own indent.
fn item<'a>(code: &'a str, head: &str) -> &'a str {
    assert_eq!(code.matches(head).count(), 1, "the verifier holds {head:?}");
    let start = code.find(head).expect("found once");
    let line_start = code[..start].rfind('\n').map_or(0, |at| at + 1);
    let close = format!("\n{}}}", &code[line_start..start]);
    let end = code[start..]
        .find(&close)
        .unwrap_or_else(|| panic!("{head:?} has no closing brace"));
    &code[start..start + end + close.len()]
}

/// How many times `code` calls `name`: `name(` with no identifier character
/// just before it.
fn calls(code: &str, name: &str) -> usize {
    let call = format!("{name}(");
    code.match_indices(&call)
        .filter(|(at, _)| {
            !code[..*at]
                .chars()
                .next_back()
                .is_some_and(|before| before.is_alphanumeric() || before == '_')
        })
        .count()
}

#[test]
fn verifier_has_no_import_parser_of_its_own() {
    // Built at run time, so this file does not match itself.
    let parser = ["wasm", "parser"].concat();
    let manifest = fs::read_to_string(lane_dir().join("tools").join("Cargo.toml"))
        .expect("read tools/Cargo.toml");
    assert!(
        !without_comments(&manifest, "#").contains(&parser),
        "tools/Cargo.toml names {parser}"
    );
    for (path, code) in tools_code() {
        assert!(!code.contains(&parser), "{} uses {parser}", path.display());
    }
}

#[test]
fn verifier_reads_no_bundle_file_by_path() {
    // wc-009a: the grants reader is the one place that reads a file by a path,
    // the caller's grants file, once. The rest of the verifier reaches no file.
    let code = verifier_code();
    let reader = item(&code, "pub fn read_grants(");
    let rest = code.replacen(reader, "", 1);
    for call in [
        "fs::read",
        "File::open",
        "OpenOptions",
        "read_dir",
        "metadata",
        "read_to_end",
    ] {
        assert!(
            !rest.contains(call),
            "the verifier reaches a file by a path outside read_grants: {call}"
        );
    }
    assert_eq!(
        calls(reader, "fs::read"),
        1,
        "read_grants does not read the grants file exactly once"
    );
    for call in [
        "File::open",
        "OpenOptions",
        "read_dir",
        "metadata",
        "read_to_end",
    ] {
        assert!(!reader.contains(call), "read_grants reaches a file: {call}");
    }
}

#[test]
fn verifier_has_one_check_path() {
    let all: String = tools_code()
        .into_iter()
        .map(|(_, code)| code)
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        calls(&all, "verify_checked_signature"),
        1,
        "the tools crate checks a name signature in more than one place"
    );
    assert_eq!(
        calls(&all, "audit"),
        1,
        "the tools crate audits a module in more than one place"
    );
    for other in ["verify_name_signature", "audit_component"] {
        assert!(!all.contains(other), "the tools crate uses {other}");
    }
    // One manifest read and one grants read: two parses in the whole crate,
    // one in each reader, and one call of each reader beside its definition.
    assert_eq!(
        calls(&all, "from_slice"),
        2,
        "the tools crate parses JSON somewhere other than the manifest and grants readers"
    );
    assert_eq!(
        calls(&all, "manifest_entrypoint"),
        2,
        "the tools crate reads the manifest's entrypoint in more than one place"
    );
    // wc-009a: one grants-file read and one grants parse. `read_grants` is
    // defined and called by nobody in the crate (the caller passes its list);
    // `parse_grants` is called once, by `read_grants`.
    assert_eq!(
        calls(&all, "fs::read"),
        1,
        "the tools crate reads a file by fs::read in more than one place"
    );
    assert_eq!(
        calls(&all, "read_grants"),
        1,
        "the tools crate calls the grants reader itself"
    );
    assert_eq!(
        calls(&all, "parse_grants"),
        2,
        "the tools crate parses grants in more than one place"
    );

    let code = verifier_code();
    let reader = item(&code, "pub fn read_grants(");
    assert_eq!(calls(reader, "fs::read"), 1, "read_grants reads once");
    assert_eq!(calls(reader, "parse_grants"), 1, "read_grants parses once");
    let parser = item(&code, "fn parse_grants(");
    assert_eq!(calls(parser, "from_slice"), 1, "parse_grants parses once");
    let manifest = item(&code, "fn manifest_entrypoint(");
    assert_eq!(
        calls(manifest, "from_slice"),
        1,
        "the manifest is parsed once"
    );
    let check = item(&code, "pub fn verify_checked(");
    assert_eq!(calls(check, "verify_checked_signature"), 1);
    assert_eq!(calls(check, "audit"), 1);
    assert_eq!(calls(check, "read_grants"), 0, "the verifier reads grants");
    let wrapper = item(&code, "pub fn verify_bundle(");
    assert_eq!(calls(wrapper, "checked_bundle"), 1, "the walk");
    assert_eq!(calls(wrapper, "verify_checked"), 1, "the delegation");
    for own in ["verify_checked_signature", "audit", "entrypoint_index"] {
        assert_eq!(calls(wrapper, own), 0, "verify_bundle calls {own} itself");
    }
    let accessor = item(&code, "pub fn entrypoint(");
    for read in ["manifest_entrypoint", "from_slice", "entrypoint_index"] {
        assert_eq!(
            calls(accessor, read),
            0,
            "entrypoint() reads the manifest again: {read}"
        );
    }
}

#[test]
fn verified_bundle_is_sealed() {
    let code = verifier_code();
    let definition = item(&code, "pub struct VerifiedBundle {");
    for line in definition.lines().skip(1) {
        assert!(
            !line.trim_start().starts_with("pub"),
            "a VerifiedBundle field is public: {line}"
        );
    }

    let mut public: Vec<&str> = code
        .match_indices("pub fn ")
        .map(|(at, head)| {
            let rest = &code[at + head.len()..];
            &rest[..rest.find('(').expect("a function has a parameter list")]
        })
        .collect();
    public.sort();
    assert_eq!(
        public,
        [
            "cid",
            "entries",
            "entrypoint",
            "imports",
            "read_grants",
            "unused_grants",
            "verify_bundle",
            "verify_checked"
        ],
        "the verifier's public functions"
    );
    assert!(
        !code.contains("pub("),
        "the verifier has a restricted-public item"
    );
    assert!(
        !code.contains("&mut self"),
        "the verifier gives mutable access"
    );
    for maker in ["Deserialize", "Default", "for VerifiedBundle"] {
        assert!(!code.contains(maker), "the verifier has {maker}");
    }
    assert_eq!(
        code.matches("VerifiedBundle {").count(),
        3,
        "a VerifiedBundle is made somewhere other than verify_checked's one literal"
    );
    let accessors = item(&code, "impl VerifiedBundle {");
    for signature in [
        "pub fn cid(&self) -> LabCid {",
        "pub fn entries(&self) -> &[BundleEntry] {",
        "pub fn entrypoint(&self) -> &BundleEntry {",
        "pub fn imports(&self) -> &[DeclaredImport] {",
        "pub fn unused_grants(&self) -> &[DeclaredImport] {",
    ] {
        assert!(accessors.contains(signature), "missing {signature}");
    }
    let literal = item(&code, "pub fn verify_checked(");
    assert!(
        literal.contains(
            "Ok(VerifiedBundle {\n        checked,\n        entrypoint,\n        imports,\n        unused,\n    })"
        ),
        "verify_checked does not make the value"
    );
}

/// What a key-material scan reports for one listed file, `path` relative to
/// `root`. The name is checked before any read, and a file that cannot be read
/// is itself a finding, so a file git lists but the scan cannot see fails.
fn scan_lane_file(root: &Path, path: &str) -> Vec<String> {
    let mut findings = key_name_findings(path);
    match fs::read(root.join(path)) {
        Ok(bytes) => findings.extend(key_content_findings(path, &bytes)),
        Err(error) => findings.push(format!("{path}: cannot read ({error})")),
    }
    findings
}

/// What a key-material scan reports for one file held in memory.
fn key_material_findings(path: &str, bytes: &[u8]) -> Vec<String> {
    let mut findings = key_name_findings(path);
    findings.extend(key_content_findings(path, bytes));
    findings
}

fn key_name_findings(path: &str) -> Vec<String> {
    // Built at run time, so this file does not match itself.
    let key_suffix = [".", "key"].concat();
    let seed_suffix = [".", "seed"].concat();
    let mut findings = Vec::new();
    for suffix in [&key_suffix, &seed_suffix] {
        if path.ends_with(suffix.as_str()) {
            findings.push(format!("{path}: a {suffix} file"));
        }
    }
    findings
}

fn key_content_findings(path: &str, bytes: &[u8]) -> Vec<String> {
    // Built at run time, so this file does not match itself.
    let pem_head = ["-----", "BEGIN "].concat();
    let pem_tail = ["PRIVATE", " KEY-----"].concat();
    let mut findings = Vec::new();
    let text = String::from_utf8_lossy(bytes);
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.starts_with(&pem_head) && line.ends_with(&pem_tail) {
            findings.push(format!("{path}:{}: a PEM private-key line", number + 1));
        }
    }
    if bytes.len() == 32 && std::str::from_utf8(bytes).is_err() {
        findings.push(format!("{path}: 32 bytes that are not UTF-8"));
    }
    findings
}

#[test]
fn no_key_material_is_tracked_in_the_lane() {
    // The scan is not vacuous: each planted item is reported.
    let pem = format!(
        "notes\n  {}EC {}\n",
        ["-----", "BEGIN "].concat(),
        ["PRIVATE", " KEY-----"].concat()
    );
    let mut raw = [0xffu8; 32];
    raw[0] = 0x80;
    let planted: [(&str, &[u8]); 4] = [
        ("tools/test.key", b"text"),
        ("test.seed", b"text"),
        ("README.md", pem.as_bytes()),
        ("blob.bin", &raw),
    ];
    for (path, bytes) in planted {
        assert_eq!(
            key_material_findings(path, bytes).len(),
            1,
            "the scan misses the planted {path}"
        );
    }
    // A listed file that is gone from the worktree (still in git's index) is
    // reported by name and as unreadable, never skipped.
    let empty = TempDir::new("key-scan");
    let seed_name = ["gone", ".", "seed"].concat();
    let cause = fs::read(empty.path().join(&seed_name)).expect_err("the file is absent");
    assert_eq!(cause.kind(), std::io::ErrorKind::NotFound);
    assert_eq!(
        scan_lane_file(empty.path(), &seed_name),
        [
            format!("{seed_name}: a .seed file"),
            format!("{seed_name}: cannot read ({cause})"),
        ],
        "the scan skips a listed key file it cannot read"
    );
    let gone = scan_lane_file(empty.path(), "gone.txt");
    assert_eq!(gone.len(), 1, "the scan skips an unreadable file: {gone:?}");
    assert!(
        gone[0].starts_with("gone.txt: cannot read ("),
        "the unreadable file has no path and cause: {gone:?}"
    );

    let lane = lane_dir();
    let output = Command::new("git")
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ])
        .current_dir(&lane)
        .output()
        .expect("run git ls-files in the lane");
    assert!(
        output.status.success(),
        "git ls-files failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let listing = String::from_utf8(output.stdout).expect("git lists UTF-8 paths");
    let listed: Vec<&str> = listing
        .split('\0')
        .filter(|path| !path.is_empty())
        .collect();
    assert!(!listed.is_empty(), "git listed no lane file");
    let findings: Vec<String> = listed
        .iter()
        .flat_map(|path| scan_lane_file(&lane, path))
        .collect();
    assert!(
        findings.is_empty(),
        "key material in the lane: {findings:?}"
    );
}

#[test]
fn key_and_seed_files_are_ignored_by_git() {
    let paths = ["x.key", "tools/x.key", "x.seed", "tools/x.seed"];
    let output = Command::new("git")
        .arg("check-ignore")
        .arg("--")
        .args(paths)
        .current_dir(lane_dir())
        .output()
        .expect("run git check-ignore in the lane");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let ignored: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        ignored,
        paths,
        "git check-ignore ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}
