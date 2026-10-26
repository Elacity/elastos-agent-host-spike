//! README's "For a lab that uses the lab CID" is under test: its list of
//! consumer manifests equals the lab crates that path-depend on this crate,
//! and it states how a consumer recomputes a pin outside the code. So the
//! next change to what `lab_cid` prints cannot miss a consumer (P12).
mod common;

use common::*;

/// The sentence of the note that keeps a pin outside the code, as written.
const NEVER_COPIED: &str = "A pin is never copied from the code's output.";

/// The note's text with every run of white space one space, so a sentence
/// is found however README wraps it.
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn every_lab_cid_consumer_is_in_the_adoption_note() {
    let found = lab_cid_consumers().unwrap_or_else(|reason| panic!("the consumer scan: {reason}"));
    let listed =
        readme_lab_cid_consumers().unwrap_or_else(|reason| panic!("the adoption note: {reason}"));
    assert!(!listed.is_empty(), "the adoption note lists no consumer");
    let missing: Vec<&String> = found.iter().filter(|path| !listed.contains(path)).collect();
    let extra: Vec<&String> = listed.iter().filter(|path| !found.contains(path)).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "README's adoption note and the lab's manifests differ: \
         missing from the note {missing:?}; listed but no path dependency found {extra:?}"
    );
}

#[test]
fn the_adoption_note_states_the_outside_recomputation() {
    let note =
        readme_adoption_note().unwrap_or_else(|reason| panic!("the adoption note: {reason}"));
    let note = one_line(note);
    for needed in ["python3 -I", CONTENT_SAMPLE_LAB_CID, NEVER_COPIED] {
        assert!(
            note.contains(needed),
            "README's adoption note does not say {needed:?}"
        );
    }
}

#[test]
fn the_consumer_scan_refuses_what_it_cannot_read() {
    let title = ADOPTION_HEADING.trim_end();

    // A missing section or list fails with its reason, never as an empty list.
    assert_eq!(
        consumers_listed_in("").expect_err("no section"),
        format!("README.md has no {title:?} section")
    );
    assert_eq!(
        consumers_listed_in(&format!("{ADOPTION_HEADING}No list.\n")).expect_err("no list"),
        format!("README.md's {title:?} holds no ```text block")
    );
    let unread = "lab/wasm-capsule/Cargo.toml";
    assert_eq!(
        consumers_listed_in(&format!("{ADOPTION_HEADING}```text\n{unread}\n```\n"))
            .expect_err("a line with no use"),
        format!(
            "the adoption note's line {unread:?} is not a manifest path and pins, parse or both"
        )
    );

    // An unreadable manifest fails with its path and cause.
    let gone = "lab/no-such-lab/Cargo.toml";
    let refusal = read_manifest(gone).expect_err("no such manifest");
    assert!(
        refusal.starts_with(&format!("read {gone}: ")) && refusal.contains("No such file"),
        "{refusal}"
    );

    // The forms the scan reads, and a mention in a comment, which is none.
    let path = "lab/x/Cargo.toml";
    let reads = |text: &str| depends_on_this_crate(path, text);
    let inline = "capsule-identity = { path = \"../capsule-identity\" }";
    assert_eq!(reads(&format!("[dependencies]\n{inline}\n")), Ok(true));
    assert_eq!(reads(&format!("[dev-dependencies]\n{inline}\n")), Ok(true));
    assert_eq!(
        reads("# names capsule-identity in a comment\n[dependencies]\n"),
        Ok(false)
    );

    // Any other form that names the crate fails with its line.
    for (text, line, shown) in [
        (
            format!("[build-dependencies]\n{inline}\n"),
            2,
            inline.to_owned(),
        ),
        (
            "[dependencies.capsule-identity]\npath = \"../capsule-identity\"\n".to_owned(),
            1,
            "[dependencies.capsule-identity]".to_owned(),
        ),
        (
            "[dependencies]\ncapsule-identity = \"0.1\"\n".to_owned(),
            2,
            "capsule-identity = \"0.1\"".to_owned(),
        ),
    ] {
        assert_eq!(
            reads(&text),
            Err(format!(
                "{path}:{line}: {shown:?} names capsule-identity in a form the scan does not read"
            ))
        );
    }
}
