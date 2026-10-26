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

/// The exported items, after a bare `pub`, that are not functions.
const OTHER_ITEMS: [&str; 7] = ["struct", "enum", "type", "trait", "mod", "use", "static"];

/// Whether `c` can be part of a name.
fn is_name_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The next token of `text`, after any white space, line breaks included: a
/// run of name characters, or one other character ("" at the end). And the
/// text after it.
fn token(text: &str) -> (&str, &str) {
    let text = text.trim_start();
    let end = match text.find(|c: char| !is_name_char(c)) {
        Some(0) => text.chars().next().map_or(0, char::len_utf8),
        Some(end) => end,
        None => text.len(),
    };
    text.split_at(end)
}

/// The name of the function the declaration after one `pub` exports, or
/// `None` when it exports no function. The declaration is read token by
/// token across line breaks: any of `async`, `const`, `unsafe` and `extern`
/// (with or without an ABI string) in any order, then `fn` and its name.
/// `pub(crate)` and `pub(super)` export nothing. A declaration this check
/// cannot read is refused with its own reason, never skipped.
fn declared_after_pub(after_pub: &str) -> Result<Option<&str>, String> {
    if token(after_pub).0 == "(" {
        return Ok(None);
    }
    let mut head = vec![String::from("pub")];
    let mut rest = after_pub;
    loop {
        let (word, after) = token(rest);
        rest = after;
        let qualifiers: Vec<&str> = head[1..].iter().map(String::as_str).collect();
        match word {
            "" => return Err(format!("`{}` ends the code with no item", head.join(" "))),
            "fn" => {
                let name = token(after).0;
                if name.starts_with(|c: char| is_name_char(c) && !c.is_ascii_digit()) {
                    return Ok(Some(name));
                }
                return Err(format!(
                    "`{} fn` is followed by {name:?}, not a name",
                    head.join(" ")
                ));
            }
            "async" | "const" | "unsafe" => head.push(word.to_owned()),
            "extern" => match token(after) {
                ("\"", abi) => {
                    let close = abi
                        .find('"')
                        .ok_or("the ABI string after `extern` has no closing quote")?;
                    head.push(format!("extern \"{}\"", &abi[..close]));
                    rest = &abi[close + 1..];
                }
                _ => head.push(word.to_owned()),
            },
            _ => {
                let not_a_function = match qualifiers.as_slice() {
                    [] => OTHER_ITEMS.contains(&word) || token(after).0 == ":",
                    ["const"] => word.starts_with(is_name_char),
                    ["unsafe"] => word == "trait",
                    ["extern"] => word == "crate",
                    _ => false,
                };
                if not_a_function {
                    return Ok(None);
                }
                return Err(format!(
                    "`{} {word}` is not a declaration this check reads",
                    head.join(" ")
                ));
            }
        }
    }
}

/// Every function `code` exports, by name: the declaration after each `pub`
/// word, wherever it is and however its tokens are split across lines. The
/// first declaration this check cannot read is refused with its reason.
fn exported_functions(code: &str) -> Result<Vec<&str>, String> {
    let mut names = Vec::new();
    for (at, _) in code.match_indices("pub") {
        let before = code[..at].chars().next_back();
        let after = &code[at + "pub".len()..];
        if before.is_some_and(is_name_char) || after.starts_with(is_name_char) {
            continue;
        }
        names.extend(declared_after_pub(after)?);
    }
    Ok(names)
}

#[test]
fn every_exported_function_form_is_read() {
    for (code, name) in [
        ("pub fn plain(", "plain"),
        ("    pub fn method(&self", "method"),
        ("pub async fn admit() {}", "admit"),
        ("pub const fn grant() {}", "grant"),
        ("pub unsafe fn launch()", "launch"),
        ("pub extern \"C\" fn run()", "run"),
        ("pub extern fn run_c()", "run_c"),
        ("pub const async unsafe extern \"C\" fn all<T>()", "all"),
        ("pub unsafe extern \"system\" fn sys()", "sys"),
        ("#[rustfmt::skip]\npub async\nfn admit() {}", "admit"),
        ("pub\n    const\n    fn\n    grant() {}", "grant"),
        ("pub extern\n\"C\"\nfn run()", "run"),
        ("pub fn\nsplit_name\n()", "split_name"),
    ] {
        assert_eq!(exported_functions(code), Ok(vec![name]), "{code:?}");
    }
    for code in [
        "pub(crate) fn inner()",
        "pub(super) async fn inner()",
        "pub (crate)\nfn inner()",
        "pub const MANIFEST_FILE: &str = \"capsule.json\";",
        "pub struct LabCid([u8; 32]);",
        "pub struct Entry {\n    pub path: String,\n}",
        "pub enum Moment {}",
        "pub unsafe trait Marker {}",
        "pub extern crate x;",
        "fn private()",
        "let publish = 1; fn pub_key() {}",
    ] {
        assert_eq!(exported_functions(code), Ok(vec![]), "{code:?}");
    }
}

#[test]
fn an_unreadable_pub_declaration_is_refused_with_its_reason() {
    for (code, reason) in [
        ("pub", "`pub` ends the code with no item"),
        ("pub async\n", "`pub async` ends the code with no item"),
        (
            "pub extern \"C fn run()",
            "the ABI string after `extern` has no closing quote",
        ),
        ("pub fn (", "`pub fn` is followed by \"(\", not a name"),
        ("pub fn", "`pub fn` is followed by \"\", not a name"),
        (
            "pub async struct S;",
            "`pub async struct` is not a declaration this check reads",
        ),
        (
            "pub extern \"C\" crate x;",
            "`pub extern \"C\" crate` is not a declaration this check reads",
        ),
        (
            "pub struct Opaque(pub u8);",
            "`pub u8` is not a declaration this check reads",
        ),
        (
            "pub macro m() {}",
            "`pub macro` is not a declaration this check reads",
        ),
        (
            "pub fn first() {}\npub async move",
            "`pub async move` is not a declaration this check reads",
        ),
    ] {
        assert_eq!(exported_functions(code), Err(reason.to_owned()), "{code:?}");
    }
}

#[test]
fn the_harness_exports_only_identity_checks() {
    let code = library_code();
    let declared = exported_functions(&code)
        .unwrap_or_else(|reason| panic!("the export check cannot read the library: {reason}"));
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
