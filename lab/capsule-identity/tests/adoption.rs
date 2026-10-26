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

    // A quoted key is read with its escapes decoded, so a consumer that
    // spells the key another valid way is still found (Codex, 022 round 1).
    for key in [
        r#""capsule-identity""#,
        r#""capsule\U0000002didentity""#,
        r#""capsule-identity""#,
        "'capsule-identity'",
    ] {
        let text = format!("[dependencies]\n{key} = {{ path = \"../capsule\\u002didentity\" }}\n");
        assert_eq!(reads(&text), Ok(true), "{text}");
    }
    // A `#` inside a string is text, not a comment.
    assert_eq!(
        reads("[dependencies]\ncapsule-identity = { path = \"../a#b\" }\n"),
        Ok(true)
    );

    // The text of a string is never a table or a key (Codex, 022 round 1):
    // a `[package]` description that holds a dependency's lines declares
    // none, in either kind of multi-line string.
    let held = "[dependencies]\ncapsule-identity = { path = \"../capsule-identity\" }\n";
    for quotes in ["\"\"\"", "'''"] {
        let text = format!("[package]\ndescription = {quotes}\n{held}{quotes}\n[dependencies]\n");
        assert_eq!(reads(&text), Ok(false), "{text}");
    }

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
        (
            "[dependencies]\nci = { package = \"capsule\\u002didentity\", path = \"../ci\" }\n"
                .to_owned(),
            2,
            "ci = { package = \"capsule\\u002didentity\", path = \"../ci\" }".to_owned(),
        ),
        (
            "[dependencies]\nx = { path = \"../x\", note = \"\"\"\ncapsule-identity\n\"\"\" }\n"
                .to_owned(),
            2,
            "x = { path = \"../x\", note = \"\"\"".to_owned(),
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

#[test]
fn the_manifest_reader_refuses_what_is_not_toml() {
    let path = "lab/x/Cargo.toml";
    for (text, reason) in [
        ("name = \"x\n", "1: a one-line string is never closed"),
        ("[package]\nd = \"\"\"\nx\n", "2: a string is never closed"),
        ("name = \"\\q\"\n", "1: the escape \\q is not TOML's"),
        (
            "name = \"\\u00zz\"\n",
            "1: the escape \\u00zz is not a character",
        ),
        (
            "d = \"\"\"a\\ b\"\"\"\n",
            "1: a \\ in a multi-line string is not at a line's end",
        ),
        ("]\n", "1: a ']' closes nothing"),
        ("x = [\n1,\n", "1: a bracket opened here is never closed"),
    ] {
        assert_eq!(
            manifest_statements(path, text),
            Err(format!("{path}:{reason}")),
            "{text:?}"
        );
        assert_eq!(
            depends_on_this_crate(path, text),
            Err(format!("{path}:{reason}"))
        );
    }

    // What the reader keeps: one statement per header or key, a multi-line
    // string or array kept whole with its first line, and escapes decoded.
    let text = "[a] # note\nb = \"\"\"\nx\\\n   y\"\"\"\nc = [\n'1',\n]\n";
    let word = |text: &str| Token::Word(text.to_owned());
    let string = |text: &str| Token::Text(text.to_owned());
    assert_eq!(
        manifest_statements(path, text),
        Ok(vec![
            Statement {
                line: 1,
                source: "[a] # note",
                tokens: vec![Token::Mark('['), word("a"), Token::Mark(']')],
            },
            Statement {
                line: 2,
                source: "b = \"\"\"",
                tokens: vec![word("b"), Token::Mark('='), string("xy")],
            },
            Statement {
                line: 5,
                source: "c = [",
                tokens: vec![
                    word("c"),
                    Token::Mark('='),
                    Token::Mark('['),
                    string("1"),
                    Token::Mark(','),
                    Token::Mark(']'),
                ],
            },
        ])
    );
}
