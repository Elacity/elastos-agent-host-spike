//! A lab variant binding outside every bundle groups the lab CIDs of a
//! capsule's platform variants and its recipe's lab CID under one test-key
//! signature. Each variant is still its own closure with its own record, and
//! the binding defines no shared capsule identity. Verification checks the
//! binding and nothing else: no trust policy, no admission, no launch. Every
//! expected CID comes from the pins in `common`.
mod common;

use std::fs;
use std::path::{Path, PathBuf};

use capsule_identity::{
    checked_bundle, domain_separated_digest, encode_entries, lab_cid, sign_package_record,
    sign_variant_binding, verify_checked_variant_binding, verify_package_record,
    verify_variant_binding, BundleEntry, CheckedBundle, LabCid, Refusal, VariantBinding,
    MANIFEST_FILE,
};
use common::*;
use ed25519_dalek::{Signer, SigningKey};
use tempfile::TempDir;

/// The domains, written out here rather than read from the library, so a
/// changed domain constant fails these tests.
const BINDING_DOMAIN: &str = "lab.capsule-identity.variant-binding/v1";
const RECORD_DOMAIN: &str = "lab.capsule-identity.package-record/v1";

/// The three platform labels, written out here.
const DARWIN: &str = "aarch64-darwin";
const ARM_LINUX: &str = "aarch64-linux";
const LINUX: &str = "x86_64-linux";

/// A label the Runtime's release script uses for its setup tools, not for a
/// capsule platform.
const UNKNOWN: &str = "darwin-arm64";

/// The text every unknown-label refusal ends with: the portable label, then
/// the three platform labels.
const KNOWN: &str = "*, aarch64-darwin, aarch64-linux, x86_64-linux";

/// The two variant bundles, assembled side by side in one fresh parent.
struct Variants {
    parent: TempDir,
    a: PathBuf,
    b: PathBuf,
}

fn variants() -> Variants {
    let parent = temp_dir();
    let a = parent.path().join(PROVIDER_VARIANT_A.name);
    let b = parent.path().join(PROVIDER_VARIANT_B.name);
    assemble_at(&PROVIDER_VARIANT_A, &a);
    assemble_at(&PROVIDER_VARIANT_B, &b);
    Variants { parent, a, b }
}

impl Variants {
    /// The test's binding: a under `aarch64-darwin`, b under `x86_64-linux`.
    fn pairs(&self) -> [(&'static str, &Path); 2] {
        [(DARWIN, self.a.as_path()), (LINUX, self.b.as_path())]
    }
}

fn did_of(key: &SigningKey) -> String {
    elastos_identity::encode_signing_key_did(key)
}

fn sign(key: &SigningKey, pairs: &[(&str, &Path)], recipe: &[u8]) -> VariantBinding {
    sign_variant_binding(key, pairs, recipe)
        .unwrap_or_else(|refusal| panic!("sign the binding: {refusal}"))
}

/// The payload the rule gives, formatted here from its parts and never by
/// the library. `variants` is given in platform byte order.
fn expected_payload(recipe: &str, did: &str, variants: &[(&str, &str)]) -> String {
    let variants: Vec<String> = variants
        .iter()
        .map(|(platform, cid)| format!("{{\"cid\":\"{cid}\",\"platform\":\"{platform}\"}}"))
        .collect();
    format!(
        "{{\"recipe\":\"{recipe}\",\"schema\":\"lab.capsule-identity.variant-binding/v1\",\"signer_did\":\"{did}\",\"variants\":[{}]}}",
        variants.join(",")
    )
}

/// The payload of the test's binding by `did`, from the pins.
fn test_payload(did: &str) -> String {
    expected_payload(
        PROVIDER_VARIANT_RECIPE_LAB_CID,
        did,
        &[
            (DARWIN, PROVIDER_VARIANT_A_LAB_CID),
            (LINUX, PROVIDER_VARIANT_B_LAB_CID),
        ],
    )
}

/// The lab CID of recipe bytes, by the encoder over the one entry the rule
/// names, written out here.
fn recipe_named(recipe: &[u8]) -> LabCid {
    encode_entries(&[BundleEntry {
        path: "provider-variant.recipe".to_owned(),
        content: recipe.to_vec(),
    }])
    .expect("one entry has one path")
}

/// The committed recipe with its first bit flipped.
fn changed_recipe() -> Vec<u8> {
    let mut recipe = variant_recipe();
    recipe[0] ^= 1;
    recipe
}

/// Both verifiers' answers for `binding` on the bundles at `pairs`: the
/// checked form on fresh `checked_bundle`s, then the path form. Every refusal
/// test judges both, so a check that lives only in one form fails it.
fn both(
    binding: &VariantBinding,
    pairs: &[(&str, &Path)],
    recipe: &[u8],
    accepted: &[String],
) -> [(&'static str, Result<(), Refusal>); 2] {
    let held: Vec<(&str, CheckedBundle)> = pairs
        .iter()
        .map(|(platform, bundle)| (*platform, checked(bundle)))
        .collect();
    let given: Vec<(&str, &CheckedBundle)> = held
        .iter()
        .map(|(platform, bundle)| (*platform, bundle))
        .collect();
    [
        (
            "verify_checked_variant_binding",
            verify_checked_variant_binding(binding, &given, recipe, accepted),
        ),
        (
            "verify_variant_binding",
            verify_variant_binding(binding, pairs, recipe, accepted),
        ),
    ]
}

/// Both verifiers refuse with `expected`, whose text is `text`.
fn both_refuse(
    binding: &VariantBinding,
    pairs: &[(&str, &Path)],
    recipe: &[u8],
    accepted: &[String],
    expected: &Refusal,
    text: &str,
) {
    for (verifier, answer) in both(binding, pairs, recipe, accepted) {
        let Err(refusal) = answer else {
            panic!("{verifier} passed a binding it must refuse ({text})")
        };
        assert_refusal(&refusal, expected, text, verifier);
    }
}

/// Both verifiers refuse, and `judge` checks each refusal.
fn both_refuse_with(
    binding: &VariantBinding,
    pairs: &[(&str, &Path)],
    recipe: &[u8],
    accepted: &[String],
    judge: impl Fn(Refusal),
) {
    for (verifier, answer) in both(binding, pairs, recipe, accepted) {
        let Err(refusal) = answer else {
            panic!("{verifier} passed a binding it must refuse")
        };
        judge(refusal);
    }
}

/// Both verifiers pass the binding.
fn both_pass(
    binding: &VariantBinding,
    pairs: &[(&str, &Path)],
    recipe: &[u8],
    accepted: &[String],
) {
    for (verifier, answer) in both(binding, pairs, recipe, accepted) {
        answer.unwrap_or_else(|refusal| panic!("{verifier} refused the binding: {refusal}"));
    }
}

/// The refusal is `expected`, and its text is `text`.
fn assert_refusal(refusal: &Refusal, expected: &Refusal, text: &str, step: &str) {
    assert_eq!(refusal, expected, "{step}");
    assert_eq!(refusal.to_string(), text, "{step}");
}

/// Signing `pairs` is refused with `expected`, whose text is `text`.
fn signing_refuses(pairs: &[(&str, &Path)], expected: &Refusal, text: &str) {
    let refusal = sign_variant_binding(&fresh_signing_key(), pairs, &variant_recipe())
        .expect_err("signing must refuse this variant list");
    assert_refusal(&refusal, expected, text, "signing");
}

/// The (e) refusal: the binding names `bound` for `platform`, and the bundle
/// given for it names `bundle`.
fn another_cid(platform: &str, bound: &str, bundle: &str) -> (Refusal, String) {
    (
        Refusal::VariantNamesAnotherCid {
            platform: platform.to_owned(),
            binding: bound.to_owned(),
            bundle: bundle.parse().expect("a pin is a printed lab CID"),
        },
        format!(
            "the binding names {bound} for {platform}; the bundle given for {platform} names {bundle}"
        ),
    )
}

/// The (d) refusal for the two sorted label lists.
fn platforms_differ(binding: &[&str], given: &[&str]) -> (Refusal, String) {
    let owned = |labels: &[&str]| labels.iter().map(|label| label.to_string()).collect();
    (
        Refusal::PlatformsDiffer {
            binding: owned(binding),
            given: owned(given),
        },
        format!("the binding holds the platforms {binding:?}; the given variants are {given:?}"),
    )
}

/// The (f) refusal for the changed recipe.
fn recipe_differs() -> (Refusal, String) {
    let changed = recipe_named(&changed_recipe());
    (
        Refusal::RecipeNamesAnotherCid {
            binding: PROVIDER_VARIANT_RECIPE_LAB_CID.to_owned(),
            recipe: changed,
        },
        format!(
            "the binding names the recipe {PROVIDER_VARIANT_RECIPE_LAB_CID}; the recipe bytes name {changed}"
        ),
    )
}

/// The three (c) refusals for `list`: no variant, the unknown label, and
/// `aarch64-darwin` twice.
fn shape_refusals(list: &'static str) -> [(Refusal, String); 3] {
    [
        (
            Refusal::NoVariants { list },
            format!("the {list} variant list is empty: a binding holds at least one variant"),
        ),
        (
            Refusal::UnknownPlatform {
                list,
                label: UNKNOWN.to_owned(),
            },
            format!("the {list} variant list holds the platform \"{UNKNOWN}\", which is not one of {KNOWN}"),
        ),
        (
            Refusal::DuplicatePlatform {
                list,
                label: DARWIN.to_owned(),
            },
            format!("the {list} variant list holds the platform {DARWIN} twice: one CID per platform"),
        ),
    ]
}

/// The signature refusal for a binding: the signer `did`, and the payload as
/// text as the signed name.
fn does_not_verify(did: &str, payload: &str) -> (Refusal, String) {
    (
        Refusal::SignatureDoesNotVerify {
            did: did.to_owned(),
            name: payload.to_owned(),
        },
        format!("signature by {did} does not verify over {payload}"),
    )
}

#[test]
fn variant_binding_binds_each_variant_cid_and_verifies() {
    let v = variants();
    let recipe = variant_recipe();
    assert_eq!(
        recipe_named(&recipe).to_string(),
        PROVIDER_VARIANT_RECIPE_LAB_CID
    );
    assert_ne!(PROVIDER_VARIANT_A_LAB_CID, PROVIDER_VARIANT_B_LAB_CID);
    assert_eq!(named(&v.a).to_string(), PROVIDER_VARIANT_A_LAB_CID);
    assert_eq!(named(&v.b).to_string(), PROVIDER_VARIANT_B_LAB_CID);
    assert_ne!(named(&v.a), named(&v.b), "the two variants have one CID");

    let key = fresh_signing_key();
    let did = did_of(&key);
    let binding = sign(&key, &v.pairs(), &recipe);
    assert_eq!(binding.recipe, PROVIDER_VARIANT_RECIPE_LAB_CID);
    assert_eq!(binding.signer_did, did);
    assert_eq!(
        binding.variants,
        [
            (DARWIN.to_owned(), PROVIDER_VARIANT_A_LAB_CID.to_owned()),
            (LINUX.to_owned(), PROVIDER_VARIANT_B_LAB_CID.to_owned()),
        ]
    );
    let payload = String::from_utf8(binding.variant_binding_payload()).expect("UTF-8 JSON");
    assert_eq!(payload, test_payload(&did));
    let accepted = [did.clone()];
    both_pass(&binding, &v.pairs(), &recipe, &accepted);

    // Each variant is still its own closure, with its own record.
    let record_a = sign_package_record(&key, &v.a).expect("sign a's record");
    let record_b = sign_package_record(&key, &v.b).expect("sign b's record");
    assert_eq!(record_a.cid, PROVIDER_VARIANT_A_LAB_CID);
    assert_eq!(record_b.cid, PROVIDER_VARIANT_B_LAB_CID);
    verify_package_record(&v.a, &record_a, &accepted).expect("a's record verifies");
    verify_package_record(&v.b, &record_b, &accepted).expect("b's record verifies");
    // b's record does not bind a's bundle: one record, one closure.
    let refusal =
        verify_package_record(&v.a, &record_b, &accepted).expect_err("b's record binds a's bundle");
    assert_eq!(
        refusal,
        Refusal::RecordNamesAnotherCid {
            record: PROVIDER_VARIANT_B_LAB_CID.to_owned(),
            bundle: named(&v.a),
        }
    );
}

#[test]
fn variant_binding_payload_ignores_input_order() {
    let v = variants();
    let recipe = variant_recipe();
    let key = fresh_signing_key();
    let did = did_of(&key);
    let forward = sign(&key, &[(DARWIN, &v.a), (LINUX, &v.b)], &recipe);
    let backward = sign(&key, &[(LINUX, &v.b), (DARWIN, &v.a)], &recipe);
    assert_eq!(
        forward.variant_binding_payload(),
        backward.variant_binding_payload(),
        "the order the pairs were given in changed the payload"
    );
    assert_eq!(
        String::from_utf8(backward.variant_binding_payload()).expect("UTF-8 JSON"),
        test_payload(&did)
    );
    assert_eq!(forward.signature, backward.signature);
    let accepted = [did];
    both_pass(&backward, &v.pairs(), &recipe, &accepted);
    both_pass(
        &forward,
        &[(LINUX, &v.b), (DARWIN, &v.a)],
        &recipe,
        &accepted,
    );
}

#[test]
fn variant_swapped_between_platforms_is_refused() {
    let v = variants();
    let recipe = variant_recipe();
    let binding = sign(&fresh_signing_key(), &v.pairs(), &recipe);
    let accepted = [binding.signer_did.clone()];
    let a = PROVIDER_VARIANT_A_LAB_CID;
    let b = PROVIDER_VARIANT_B_LAB_CID;

    // b's bundle given as aarch64-darwin, and a's as x86_64-linux.
    let (expected, text) = another_cid(DARWIN, a, b);
    both_refuse(
        &binding,
        &[(DARWIN, &v.b), (LINUX, &v.a)],
        &recipe,
        &accepted,
        &expected,
        &text,
    );
    // b's bundle given for both labels.
    both_refuse(
        &binding,
        &[(DARWIN, &v.b), (LINUX, &v.b)],
        &recipe,
        &accepted,
        &expected,
        &text,
    );
    // a's bundle given for both labels: x86_64-linux is the one refused.
    let (expected, text) = another_cid(LINUX, b, a);
    both_refuse(
        &binding,
        &[(DARWIN, &v.a), (LINUX, &v.a)],
        &recipe,
        &accepted,
        &expected,
        &text,
    );
}

#[test]
fn variant_missing_or_extra_is_refused() {
    let v = variants();
    let recipe = variant_recipe();
    let key = fresh_signing_key();
    let binding = sign(&key, &v.pairs(), &recipe);
    let accepted = [binding.signer_did.clone()];

    // Only a given.
    let (expected, text) = platforms_differ(&[DARWIN, LINUX], &[DARWIN]);
    both_refuse(
        &binding,
        &[(DARWIN, &v.a)],
        &recipe,
        &accepted,
        &expected,
        &text,
    );
    // A third label added.
    let (expected, text) = platforms_differ(&[DARWIN, LINUX], &[DARWIN, ARM_LINUX, LINUX]);
    let extra: [(&str, &Path); 3] = [(DARWIN, &v.a), (LINUX, &v.b), (ARM_LINUX, &v.a)];
    both_refuse(&binding, &extra, &recipe, &accepted, &expected, &text);
    // A binding of a alone, given both.
    let only_a = sign(&key, &[(DARWIN, &v.a)], &recipe);
    let (expected, text) = platforms_differ(&[DARWIN], &[DARWIN, LINUX]);
    both_refuse(&only_a, &v.pairs(), &recipe, &accepted, &expected, &text);
}

#[test]
fn variant_binding_shape_is_refused() {
    let v = variants();
    let recipe = variant_recipe();
    let binding = sign(&fresh_signing_key(), &v.pairs(), &recipe);
    let accepted = [binding.signer_did.clone()];
    let bad_lists: [Vec<(&str, &Path)>; 3] = [
        Vec::new(),
        vec![(UNKNOWN, &v.a)],
        vec![(DARWIN, &v.a), (DARWIN, &v.b)],
    ];

    // The given list, at signing and at verifying a valid binding.
    for (pairs, (expected, text)) in bad_lists.iter().zip(shape_refusals("given")) {
        signing_refuses(pairs, &expected, &text);
        both_refuse(&binding, pairs, &recipe, &accepted, &expected, &text);
    }

    // The binding's own list, verified against the valid given list.
    let mut empty = binding.clone();
    empty.variants.clear();
    let mut unknown = binding.clone();
    unknown.variants[0].0 = UNKNOWN.to_owned();
    let mut twice = binding.clone();
    twice.variants[1] = (DARWIN.to_owned(), PROVIDER_VARIANT_B_LAB_CID.to_owned());
    for (bad, (expected, text)) in [empty, unknown, twice]
        .iter()
        .zip(shape_refusals("binding"))
    {
        both_refuse(bad, &v.pairs(), &recipe, &accepted, &expected, &text);
    }
}

#[test]
fn variant_binding_recipe_is_pinned() {
    let v = variants();
    let recipe = variant_recipe();
    let binding = sign(&fresh_signing_key(), &v.pairs(), &recipe);
    assert_eq!(binding.recipe, PROVIDER_VARIANT_RECIPE_LAB_CID);
    let accepted = [binding.signer_did.clone()];
    let changed = changed_recipe();
    assert_ne!(
        recipe_named(&changed).to_string(),
        PROVIDER_VARIANT_RECIPE_LAB_CID,
        "one changed recipe byte kept the recipe's lab CID"
    );
    let (expected, text) = recipe_differs();
    assert!(text.contains(PROVIDER_VARIANT_RECIPE_LAB_CID));
    both_refuse(&binding, &v.pairs(), &changed, &accepted, &expected, &text);
}

#[test]
fn variant_binding_signed_under_another_domain_is_refused() {
    let v = variants();
    let recipe = variant_recipe();
    let key = fresh_signing_key();
    let did = did_of(&key);
    let binding = sign(&key, &v.pairs(), &recipe);
    let mut wrong = binding.clone();
    wrong.signature = key
        .sign(&domain_separated_digest(
            RECORD_DOMAIN,
            test_payload(&did).as_bytes(),
        ))
        .to_bytes();
    let (expected, text) = does_not_verify(&did, &test_payload(&did));
    both_refuse(&wrong, &v.pairs(), &recipe, &[did], &expected, &text);
}

#[test]
fn variant_binding_signature_uses_its_domain() {
    let v = variants();
    let recipe = variant_recipe();
    let key = fresh_signing_key();
    let did = did_of(&key);
    let binding = sign(&key, &v.pairs(), &recipe);
    // Ed25519 signatures are deterministic: the test's own digest, over the
    // test's own payload, under the literal domain, is the signer's.
    let mut right = binding.clone();
    right.signature = key
        .sign(&domain_separated_digest(
            BINDING_DOMAIN,
            test_payload(&did).as_bytes(),
        ))
        .to_bytes();
    assert_eq!(
        right.signature, binding.signature,
        "sign_variant_binding does not sign the binding domain's digest of the payload"
    );
    both_pass(&right, &v.pairs(), &recipe, &[did]);
}

#[test]
fn variant_binding_by_another_signer_is_refused() {
    let v = variants();
    let recipe = variant_recipe();
    let key_a = fresh_signing_key();
    let key_b = fresh_signing_key();
    let did_a = did_of(&key_a);
    let did_b = did_of(&key_b);
    assert_ne!(did_a, did_b, "two fresh test keys have one DID");
    let by_b = sign(&key_b, &v.pairs(), &recipe);
    assert_eq!(by_b.signer_did, did_b);

    // Key B's signature with A's DID.
    let mut claims_a = by_b.clone();
    claims_a.signer_did = did_a.clone();
    let (expected, text) = does_not_verify(&did_a, &test_payload(&did_a));
    both_refuse(
        &claims_a,
        &v.pairs(),
        &recipe,
        &[did_a.clone()],
        &expected,
        &text,
    );

    // B's DID, with only A accepted, and with an empty list.
    let expected = Refusal::SignerNotAccepted { did: did_b.clone() };
    let text = format!("signer {did_b} is not in the accepted list");
    both_refuse(
        &by_b,
        &v.pairs(),
        &recipe,
        &[did_a.clone()],
        &expected,
        &text,
    );
    both_refuse(&by_b, &v.pairs(), &recipe, &[], &expected, &text);
}

#[test]
fn variant_binding_malformed_signer_did_is_refused() {
    let v = variants();
    let recipe = variant_recipe();
    let key = fresh_signing_key();
    let binding = sign(&key, &v.pairs(), &recipe);
    let real = did_of(&key);
    for did in [
        "did:web:example.invalid".to_owned(),
        format!("{real}1"),
        String::new(),
    ] {
        let mut bad = binding.clone();
        bad.signer_did = did.clone();
        // Listed, so only the decoder can refuse it.
        both_refuse_with(&bad, &v.pairs(), &recipe, &[did.clone()], |refusal| {
            assert_malformed(refusal, &did)
        });
    }
}

#[test]
fn variant_binding_refusal_order_is_stable() {
    // Each input has two faults, at two adjacent checks. The earlier check is
    // the one that answers, so swapping two adjacent checks changes the
    // refusal, in both verifiers.
    let v = variants();
    let recipe = variant_recipe();
    let changed = changed_recipe();
    let key_a = fresh_signing_key();
    let did_a = did_of(&key_a);
    let did_b = did_of(&fresh_signing_key());
    let binding = sign(&key_a, &v.pairs(), &recipe);
    let accepted = [did_a.clone()];

    // (a) before (b): the DID is not canonical and it is not accepted.
    let mut malformed = binding.clone();
    malformed.signer_did.clear();
    both_refuse_with(&malformed, &v.pairs(), &recipe, &[], |refusal| {
        assert_malformed(refusal, "")
    });

    // (b) before (c): B is not accepted, and the binding holds no variant.
    let mut unlisted_and_empty = binding.clone();
    unlisted_and_empty.signer_did = did_b.clone();
    unlisted_and_empty.variants.clear();
    both_refuse_with(
        &unlisted_and_empty,
        &v.pairs(),
        &recipe,
        &accepted,
        |refusal| assert_not_accepted(refusal, &did_b),
    );

    // (c) before (d): one label given twice, so the platforms differ too.
    let [_, _, (expected, text)] = shape_refusals("given");
    let twice: [(&str, &Path); 2] = [(DARWIN, &v.a), (DARWIN, &v.b)];
    both_refuse(&binding, &twice, &recipe, &accepted, &expected, &text);

    // (d) before (e): only b given, as aarch64-darwin, so its CID is wrong
    // too.
    let (expected, text) = platforms_differ(&[DARWIN, LINUX], &[DARWIN]);
    both_refuse(
        &binding,
        &[(DARWIN, &v.b)],
        &recipe,
        &accepted,
        &expected,
        &text,
    );

    // (e) before (f): the variants are swapped, and the recipe is changed.
    let swapped: [(&str, &Path); 2] = [(DARWIN, &v.b), (LINUX, &v.a)];
    let (expected, text) = another_cid(
        DARWIN,
        PROVIDER_VARIANT_A_LAB_CID,
        PROVIDER_VARIANT_B_LAB_CID,
    );
    both_refuse(&binding, &swapped, &changed, &accepted, &expected, &text);

    // (f) before (g): the recipe is changed, and the signature too.
    let mut flipped = binding.clone();
    flipped.signature[0] ^= 1;
    let (expected, text) = recipe_differs();
    both_refuse(&flipped, &v.pairs(), &changed, &accepted, &expected, &text);
}

#[test]
fn variant_binding_paths_preserve_walk_refusals() {
    let v = variants();
    let recipe = variant_recipe();
    let key = fresh_signing_key();
    let binding = sign(&key, &v.pairs(), &recipe);
    let did = binding.signer_did.clone();
    let mut malformed = binding.clone();
    malformed.signer_did = "did:web:example.invalid".to_owned();
    let mut flipped = binding.clone();
    flipped.signature[0] ^= 1;
    let mut empty = binding.clone();
    empty.variants.clear();
    let mut swapped = binding.clone();
    swapped.variants.reverse();
    for pair in &mut swapped.variants {
        let other = if pair.0 == DARWIN { LINUX } else { DARWIN };
        pair.0 = other.to_owned();
    }
    let inputs = [
        (&binding, vec![did.clone()], recipe.clone()),
        (
            &malformed,
            vec![malformed.signer_did.clone()],
            recipe.clone(),
        ),
        (&binding, Vec::new(), recipe.clone()),
        (&empty, vec![did.clone()], recipe.clone()),
        (&swapped, vec![did.clone()], recipe.clone()),
        (&binding, vec![did.clone()], changed_recipe()),
        (&flipped, vec![did], recipe.clone()),
    ];
    for refused in &walk_refused_bundles() {
        let path = refused.path();
        let from_lab_cid = lab_cid(path).expect_err("lab_cid refuses this bundle");
        let from_walk = checked_bundle(path).expect_err("the walk refuses this bundle");
        assert_eq!(from_walk, from_lab_cid);
        // The refused bundle first, then second.
        for pairs in [
            [(DARWIN, path), (LINUX, v.b.as_path())],
            [(DARWIN, v.a.as_path()), (LINUX, path)],
        ] {
            assert_same_refusal(
                sign_variant_binding(&fresh_signing_key(), &pairs, &recipe).map(|_| ()),
                &from_lab_cid,
            );
            for (binding, accepted, recipe) in &inputs {
                assert_same_refusal(
                    verify_variant_binding(binding, &pairs, recipe, accepted),
                    &from_walk,
                );
            }
        }
    }
}

#[test]
fn variant_binding_stays_outside_the_bundles() {
    let v = variants();
    let recipe = variant_recipe();
    let before = listing(v.parent.path());
    let mut names = vec![PROVIDER_VARIANT_A.name, PROVIDER_VARIANT_B.name];
    names.sort();
    assert_eq!(before, names, "the two bundles are the parent's entries");
    let bundles = [&v.a, &v.b];
    let cids = bundles.map(|bundle| named(bundle));
    let manifests =
        bundles.map(|bundle| fs::read(bundle.join(MANIFEST_FILE)).expect("read capsule.json"));
    let untouched = |step: &str| {
        assert_eq!(
            listing(v.parent.path()),
            before,
            "{step} changed the entries next to the bundles"
        );
        for (index, bundle) in bundles.iter().enumerate() {
            assert_eq!(
                named(bundle),
                cids[index],
                "{step} changed a bundle's lab CID"
            );
            let now = fs::read(bundle.join(MANIFEST_FILE)).expect("read capsule.json");
            assert_eq!(now, manifests[index], "{step} changed capsule.json");
            assert_eq!(
                listing(bundle),
                [MANIFEST_FILE, "ipfs-provider"],
                "{step} wrote into a bundle"
            );
        }
    };

    let binding = sign(&fresh_signing_key(), &v.pairs(), &recipe);
    untouched("signing");
    let accepted = [binding.signer_did.clone()];
    let held = [checked(&v.a), checked(&v.b)];
    verify_checked_variant_binding(
        &binding,
        &[(DARWIN, &held[0]), (LINUX, &held[1])],
        &recipe,
        &accepted,
    )
    .unwrap_or_else(|refusal| panic!("the checked form refused: {refusal}"));
    untouched("the checked verifier");
    verify_variant_binding(&binding, &v.pairs(), &recipe, &accepted)
        .unwrap_or_else(|refusal| panic!("the path form refused: {refusal}"));
    untouched("the path verifier");
}

#[test]
fn variant_binding_has_no_group_name() {
    let v = variants();
    let binding = sign(&fresh_signing_key(), &v.pairs(), &variant_recipe());
    let payload = binding.variant_binding_payload();
    let value: serde_json::Value = serde_json::from_slice(&payload).expect("the payload is JSON");
    let top = value.as_object().expect("the payload is an object");
    let mut keys: Vec<&str> = top.keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, ["recipe", "schema", "signer_did", "variants"]);
    let listed = top["variants"].as_array().expect("variants is a list");
    assert_eq!(listed.len(), 2);
    for variant in listed {
        let mut keys: Vec<&str> = variant
            .as_object()
            .expect("a variant is an object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort();
        assert_eq!(keys, ["cid", "platform"]);
    }
    let text = String::from_utf8(payload).expect("UTF-8 JSON");
    for identity in [
        "\"name\"",
        "\"id\"",
        "\"identity\"",
        "\"group\"",
        "\"capsule\"",
    ] {
        assert!(
            !text.contains(identity),
            "the payload holds {identity}: {text}"
        );
    }
}

#[test]
fn variant_binding_paths_share_one_implementation() {
    let code = library_code();
    // One payload builder, sorted in one place.
    let payload = library_item(&code, "pub fn variant_binding_payload(&self");
    for text in [
        "\\\"recipe\\\":",
        "\\\"schema\\\":",
        "\\\"signer_did\\\":",
        "\\\"variants\\\":",
        "\\\"cid\\\":",
        "\\\"platform\\\":",
        "VARIANT_BINDING_SCHEMA",
        "sort_by(",
    ] {
        assert_eq!(payload.matches(text).count(), 1, "{text}:\n{payload}");
    }
    for (text, count) in [
        ("\\\"recipe\\\":", 1),
        ("\\\"variants\\\":", 1),
        ("\\\"platform\\\":", 1),
        ("VARIANT_BINDING_SCHEMA", 2),
        ("VARIANT_BINDING_DOMAIN", 2),
        ("VARIANT_RECIPE_ENTRY", 2),
        ("variant_binding_payload(", 3),
        ("variant_binding_message(", 3),
        ("fn recipe_cid(", 1),
        ("fn require_variant_shape<'a>(", 1),
        ("require_variant_shape(", 3),
        ("VARIANT_PLATFORMS.contains(", 1),
        ("fn require_same_platforms(", 1),
        ("require_same_platforms(", 2),
        ("fn require_variant_cids(", 1),
        ("require_variant_cids(", 2),
        ("fn require_recipe_cid(", 1),
        ("require_recipe_cid(", 2),
        // Check (e2): one function, called by signing and the checked form.
        ("fn require_portable_wasm<'a>(", 1),
        ("require_portable_wasm(", 2),
        ("Refusal::WasmNotPortable", 2),
        ("Refusal::PortableNotAlone", 2),
    ] {
        assert_eq!(code.matches(text).count(), count, "{text}");
    }
    // The recipe is named in one place: its definition, the signer and check
    // (f) call it (`require_recipe_cid(` also holds the text `recipe_cid(`).
    assert_eq!(
        code.matches("recipe_cid(").count() - code.matches("require_recipe_cid(").count(),
        3,
        "recipe_cid"
    );
    let message = library_item(&code, "fn variant_binding_message(");
    assert_eq!(
        message
            .matches("domain_separated_digest(VARIANT_BINDING_DOMAIN")
            .count(),
        1,
        "{message}"
    );
    let recipe = library_item(&code, "fn recipe_cid(");
    for call in ["encode_entries(", "VARIANT_RECIPE_ENTRY"] {
        assert_eq!(recipe.matches(call).count(), 1, "{call}:\n{recipe}");
    }
    // Check (e2) is the one place that reads the WASM flag and refuses with
    // its reason; check (c) is the one place that keeps `*` alone.
    let portable = library_item(&code, "fn require_portable_wasm<'a>(");
    for text in [".wasm", "PORTABLE_PLATFORM", "Refusal::WasmNotPortable"] {
        assert_eq!(portable.matches(text).count(), 1, "{text}:\n{portable}");
    }
    assert_eq!(code.matches(".wasm").count(), 1, ".wasm");
    let shape = library_item(&code, "fn require_variant_shape<'a>(");
    assert_eq!(
        shape.matches("Refusal::PortableNotAlone").count(),
        1,
        "{shape}"
    );

    // Signing walks each bundle once, with checked_bundle, the one walk that
    // gives both its CID and its manifest type, and runs check (e2) with the
    // shared function.
    let sign = library_item(&code, "pub fn sign_variant_binding(");
    for call in [
        "require_variant_shape(\"given\"",
        "checked_bundle(",
        "require_portable_wasm(",
        "recipe_cid(",
        "signer_did_of(",
        "variant_binding_payload(",
        "variant_binding_message(",
    ] {
        assert_eq!(sign.matches(call).count(), 1, "{call}:\n{sign}");
    }
    for own in [
        "Sha256",
        "domain_separated_digest(",
        "encode_entries(",
        "format!",
        "lab_cid(",
        "check_manifest(",
        "CapsuleManifest",
        "CapsuleType",
        ".wasm",
        "PORTABLE_PLATFORM",
        "WasmNotPortable",
        "encode_signing_key_did(",
        "VARIANT_PLATFORMS",
        "fs::",
        "File",
    ] {
        assert!(
            !sign.contains(own),
            "the signer does its own work ({own}):\n{sign}"
        );
    }

    let checked = library_item(&code, "pub fn verify_checked_variant_binding(");
    let mut at = Vec::new();
    for call in [
        "decode_signer(",
        "require_accepted(",
        "\"binding\"",
        "\"given\"",
        "require_same_platforms(",
        "require_variant_cids(",
        "require_portable_wasm(",
        "require_recipe_cid(",
        "variant_binding_payload(",
        "variant_binding_message(",
        "verify_ed25519(",
    ] {
        assert_eq!(
            checked.matches(call).count(),
            1,
            "{call} is not the one check in the checked form:\n{checked}"
        );
        at.push(checked.find(call).expect("found once"));
    }
    assert_eq!(
        checked.matches("require_variant_shape(").count(),
        2,
        "{checked}"
    );
    assert!(
        at.windows(2).all(|pair| pair[0] < pair[1]),
        "the checked form's checks are out of order:\n{checked}"
    );
    for own in [
        "decode_did_key(",
        ".verify(",
        "Signature::",
        "format!",
        "Sha256",
        "domain_separated_digest(",
        "encode_entries(",
        "VARIANT_PLATFORMS",
        "sort",
        "checked_bundle(",
        "lab_cid(",
        "fs::",
        "check_manifest(",
        "CapsuleManifest",
        "CapsuleType",
        ".wasm",
        "PORTABLE_PLATFORM",
        "WasmNotPortable",
    ] {
        assert!(
            !checked.contains(own),
            "the checked form does its own work ({own}):\n{checked}"
        );
    }

    let path = library_item(&code, "pub fn verify_variant_binding(");
    assert_eq!(path.matches("checked_bundle(").count(), 1, "{path}");
    assert_eq!(
        path.matches("verify_checked_variant_binding(").count(),
        1,
        "{path}"
    );
    for own in [
        "decode_signer(",
        "require_accepted(",
        "require_variant_shape(",
        "require_same_platforms(",
        "require_variant_cids(",
        "require_recipe_cid(",
        "require_portable_wasm(",
        "recipe_cid(",
        "variant_binding_payload(",
        "variant_binding_message(",
        "verify_ed25519(",
        "decode_did_key(",
        "domain_separated_digest(",
        "Sha256",
        ".verify(",
        "lab_cid(",
        "fs::",
        "File::",
    ] {
        assert!(
            !path.contains(own),
            "the path form does its own work ({own}):\n{path}"
        );
    }

    let definition = library_item(&code, "pub struct VariantBinding {");
    assert!(!definition.contains("serde"), "{definition}");
    for field in ["name", "group", "identity", "id"] {
        assert!(
            !definition.contains(&format!("pub {field}:")),
            "VariantBinding has a {field} field:\n{definition}"
        );
    }
    let start = code
        .find("pub struct VariantBinding {")
        .expect("VariantBinding");
    let attributes: Vec<&str> = code[..start]
        .lines()
        .rev()
        .take_while(|line| line.starts_with("#["))
        .collect();
    for maker in ["Serialize", "Deserialize"] {
        assert!(
            !attributes.iter().any(|attribute| attribute.contains(maker)),
            "VariantBinding derives {maker}: {attributes:?}"
        );
    }
}

/// The portable label, written out here.
const PORTABLE: &str = "*";

/// The (c) refusal for a list that holds `*` with other labels: all of the
/// list's labels, sorted.
fn portable_not_alone(list: &'static str, labels: &[&str]) -> (Refusal, String) {
    let labels: Vec<String> = labels.iter().map(|label| label.to_string()).collect();
    (
        Refusal::PortableNotAlone {
            list,
            labels: labels.clone(),
        },
        format!("the {list} variant list holds the labels {labels:?}: the portable label * stands alone"),
    )
}

/// The (e2) refusal: a WASM app's `bundle` CID given under `platform`.
fn wasm_not_portable(platform: &str, bundle: &str) -> (Refusal, String) {
    (
        Refusal::WasmNotPortable {
            platform: platform.to_owned(),
            bundle: bundle.parse().expect("a pin is a printed lab CID"),
        },
        format!(
            "the bundle {bundle} is a WASM app bound under {platform}: a WASM app has one portable variant, bound under *"
        ),
    )
}

/// `binding` with its first label set to `platform` and signed again by
/// `key`, with the test's own digest under the literal domain, so the label
/// is the only change and the signature still verifies.
fn relabeled(key: &SigningKey, binding: &VariantBinding, platform: &str) -> VariantBinding {
    let mut moved = binding.clone();
    moved.variants[0].0 = platform.to_owned();
    moved.signature = key
        .sign(&domain_separated_digest(
            BINDING_DOMAIN,
            &moved.variant_binding_payload(),
        ))
        .to_bytes();
    moved
}

#[test]
fn a_wasm_app_binds_one_portable_variant() {
    let bundle = assemble(&AGENT_HOST);
    assert_eq!(named(bundle.path()).to_string(), AGENT_HOST_LAB_CID);
    let recipe = variant_recipe();
    let key = fresh_signing_key();
    let did = did_of(&key);
    let pairs = [(PORTABLE, bundle.path())];
    let binding = sign(&key, &pairs, &recipe);
    assert_eq!(
        binding.variants,
        [(PORTABLE.to_owned(), AGENT_HOST_LAB_CID.to_owned())]
    );
    assert_eq!(
        String::from_utf8(binding.variant_binding_payload()).expect("UTF-8 JSON"),
        expected_payload(
            PROVIDER_VARIANT_RECIPE_LAB_CID,
            &did,
            &[(PORTABLE, AGENT_HOST_LAB_CID)]
        )
    );
    both_pass(&binding, &pairs, &recipe, &[did]);
}

#[test]
fn a_wasm_app_under_a_platform_label_is_refused() {
    let bundle = assemble(&AGENT_HOST);
    let recipe = variant_recipe();
    let key = fresh_signing_key();
    let did = did_of(&key);
    let (expected, text) = wasm_not_portable(DARWIN, AGENT_HOST_LAB_CID);

    // At signing, alone and under two labels: the first in byte order is
    // named.
    signing_refuses(&[(DARWIN, bundle.path())], &expected, &text);
    signing_refuses(
        &[(LINUX, bundle.path()), (DARWIN, bundle.path())],
        &expected,
        &text,
    );

    // At verifying: a binding signed under `*`, then moved to
    // aarch64-darwin and signed again, so (e2) is its only fault.
    let portable = sign(&key, &[(PORTABLE, bundle.path())], &recipe);
    let moved = relabeled(&key, &portable, DARWIN);
    both_refuse(
        &moved,
        &[(DARWIN, bundle.path())],
        &recipe,
        &[did],
        &expected,
        &text,
    );
}

#[test]
fn the_portable_label_stands_alone() {
    let v = variants();
    let recipe = variant_recipe();
    let key = fresh_signing_key();
    let binding = sign(&key, &v.pairs(), &recipe);
    let accepted = [binding.signer_did.clone()];
    let mixed: [(&str, &Path); 2] = [(PORTABLE, &v.a), (LINUX, &v.b)];

    // At signing, and in the given list at verifying a valid binding.
    let (expected, text) = portable_not_alone("given", &[PORTABLE, LINUX]);
    signing_refuses(&mixed, &expected, &text);
    both_refuse(&binding, &mixed, &recipe, &accepted, &expected, &text);

    // The binding's own list, signed again so its labels are its only fault.
    let moved = relabeled(&key, &binding, PORTABLE);
    let (expected, text) = portable_not_alone("binding", &[PORTABLE, LINUX]);
    both_refuse(&moved, &v.pairs(), &recipe, &accepted, &expected, &text);

    // `*` alone is a known label.
    let alone = sign(&key, &[(PORTABLE, &v.a)], &recipe);
    both_pass(&alone, &[(PORTABLE, &v.a)], &recipe, &accepted);
}

#[test]
fn a_portable_data_capsule_binds_under_the_portable_label() {
    // content-sample is `type: data`. It binds under `*` and under a
    // platform label alike, so the rule keys on the manifest type, not on
    // the label.
    let bundle = assemble(&CONTENT_SAMPLE);
    assert_eq!(named(bundle.path()).to_string(), CONTENT_SAMPLE_LAB_CID);
    let recipe = variant_recipe();
    let key = fresh_signing_key();
    let did = did_of(&key);
    for platform in [PORTABLE, DARWIN] {
        let pairs = [(platform, bundle.path())];
        let binding = sign(&key, &pairs, &recipe);
        assert_eq!(
            binding.variants,
            [(platform.to_owned(), CONTENT_SAMPLE_LAB_CID.to_owned())]
        );
        assert_eq!(
            String::from_utf8(binding.variant_binding_payload()).expect("UTF-8 JSON"),
            expected_payload(
                PROVIDER_VARIANT_RECIPE_LAB_CID,
                &did,
                &[(platform, CONTENT_SAMPLE_LAB_CID)]
            )
        );
        both_pass(&binding, &pairs, &recipe, &[did.clone()]);
    }
}

#[test]
fn wasm_type_comes_from_the_one_manifest_check() {
    // P10: the WASM type is read from the one parse in check_manifest, and
    // the seam keeps what that one call returns. Nothing else parses
    // capsule.json or names the manifest type.
    let code = library_code();
    let parse = ": CapsuleManifest = serde_json::from_slice";
    assert_eq!(code.matches(parse).count(), 1, "{parse}");
    let check = library_item(&code, "fn check_manifest(");
    assert_eq!(check.matches(parse).count(), 1, "{check}");
    assert_eq!(
        check
            .matches("manifest.capsule_type == CapsuleType::Wasm")
            .count(),
        1,
        "{check}"
    );
    // The `use` line, then check_manifest: nowhere else, apart from the two
    // refusal texts that name the Runtime's checks.
    for (text, count) in [
        ("CapsuleManifest", 4),
        ("CapsuleType", 2),
        ("capsule_type", 1),
        ("serde_json::", 1),
    ] {
        assert_eq!(code.matches(text).count(), count, "{text}");
    }
    assert_eq!(
        code.matches("use elastos_common::{CapsuleManifest, CapsuleType};")
            .count(),
        1
    );
    let seam = library_item(&code, "pub fn checked_bundle_observed(");
    for text in [
        "let wasm = check_manifest(",
        "CheckedBundle { cid, entries, wasm }",
    ] {
        assert_eq!(seam.matches(text).count(), 1, "{text}:\n{seam}");
    }
}

#[test]
fn wasm_variant_refusal_order_is_stable() {
    // Each input has two faults, at (e2) and a check next to it. The earlier
    // check answers, in both verifiers.
    let bundle = assemble(&AGENT_HOST);
    let other = assemble(&AGENT_HOST);
    let mut asks = read_fixture(&AGENT_HOST, "asks.json");
    asks[0] ^= 1;
    write_file(other.path(), "asks.json", &asks);
    let other_cid = named(other.path()).to_string();
    assert_ne!(other_cid, AGENT_HOST_LAB_CID);
    let recipe = variant_recipe();
    let key = fresh_signing_key();
    let accepted = [did_of(&key)];
    let portable = sign(&key, &[(PORTABLE, bundle.path())], &recipe);
    let moved = relabeled(&key, &portable, DARWIN);

    // (e) before (e2): another WASM app given under aarch64-darwin, so its
    // CID is wrong too.
    let (expected, text) = another_cid(DARWIN, AGENT_HOST_LAB_CID, &other_cid);
    both_refuse(
        &moved,
        &[(DARWIN, other.path())],
        &recipe,
        &accepted,
        &expected,
        &text,
    );

    // (e2) before (f): the WASM app under aarch64-darwin, and the recipe
    // changed.
    let (expected, text) = wasm_not_portable(DARWIN, AGENT_HOST_LAB_CID);
    both_refuse(
        &moved,
        &[(DARWIN, bundle.path())],
        &changed_recipe(),
        &accepted,
        &expected,
        &text,
    );

    // (e2) before (g): the label moved without signing again.
    let mut unsigned = portable.clone();
    unsigned.variants[0].0 = DARWIN.to_owned();
    both_refuse(
        &unsigned,
        &[(DARWIN, bundle.path())],
        &recipe,
        &accepted,
        &expected,
        &text,
    );
}

/// The stand-in payload of `bundle` as the one walk read it.
fn walked_payload(bundle: &Path) -> Vec<u8> {
    let held = checked(bundle);
    let entry = held
        .entries()
        .iter()
        .find(|entry| entry.path == "ipfs-provider")
        .expect("a variant holds ipfs-provider");
    entry.content.clone()
}

/// This test pins a limit, not a feature. A label is the signer's claim: the
/// lab never reads a label from a manifest, path or payload, so it does not
/// check that a variant's bytes were built for its label. Here a's payload
/// says `aarch64-darwin` and b's says `x86_64-linux`, a fresh test key binds
/// them the other way round, and both verifiers pass. The pinned recipe
/// stands in for the build that would back the claim
/// (https://github.com/Elacity/elastos-runtime/issues/285). If the lab ever
/// checks bytes against labels, this test must change with that rule.
#[test]
fn a_variant_label_is_the_signers_claim() {
    let v = variants();
    // The words are in the bytes the verifiers hold.
    assert_eq!(walked_payload(&v.a), b"lab fixture aarch64-darwin\n");
    assert_eq!(walked_payload(&v.b), b"lab fixture x86_64-linux\n");

    let recipe = variant_recipe();
    let key = fresh_signing_key();
    let did = did_of(&key);
    let swapped: [(&str, &Path); 2] = [(LINUX, &v.a), (DARWIN, &v.b)];
    let binding = sign(&key, &swapped, &recipe);
    assert_eq!(binding.recipe, PROVIDER_VARIANT_RECIPE_LAB_CID);
    assert_eq!(
        binding.variants,
        [
            (LINUX.to_owned(), PROVIDER_VARIANT_A_LAB_CID.to_owned()),
            (DARWIN.to_owned(), PROVIDER_VARIANT_B_LAB_CID.to_owned()),
        ]
    );
    assert_eq!(
        String::from_utf8(binding.variant_binding_payload()).expect("UTF-8 JSON"),
        expected_payload(
            PROVIDER_VARIANT_RECIPE_LAB_CID,
            &did,
            &[
                (DARWIN, PROVIDER_VARIANT_B_LAB_CID),
                (LINUX, PROVIDER_VARIANT_A_LAB_CID),
            ]
        )
    );
    both_pass(&binding, &swapped, &recipe, &[did]);
}
