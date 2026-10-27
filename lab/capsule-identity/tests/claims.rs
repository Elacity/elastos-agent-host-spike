//! The lane makes one claim about the lab CID, and it stays narrow (P12):
//! "Kubo v0.40.1 profile, computed by the lab". No Kubo is installed on this
//! Mac and no Kubo has computed a pin, so until an offline Kubo cross-check
//! prints the same value as a committed pin, no lane doc or code calls the
//! lab CID equal to the Runtime's CID or to Kubo's output. The scan reads the
//! files themselves, so it never passes on an empty read and never skips.
mod common;

use common::*;

/// The files the claim test must have read, at the least.
const MUST_READ: [&str; 3] = ["README.md", "GAP-REPORT.md", "src/lib.rs"];

#[test]
fn the_lab_cid_claim_stays_computed_by_the_lab() {
    let files = claim_scan().unwrap_or_else(|reason| panic!("the claim scan: {reason}"));
    let paths: Vec<&str> = files.iter().map(|(path, _)| path.as_str()).collect();
    for needed in MUST_READ {
        assert!(
            paths.contains(&needed),
            "the claim scan did not read {needed}; it read {paths:?}"
        );
    }

    let mut claims = Vec::new();
    for (path, bytes) in &files {
        claims.extend(equality_claims_in(path, bytes).unwrap_or_else(|reason| panic!("{reason}")));
    }
    assert!(
        claims.is_empty(),
        "the lab CID is called equal to the Runtime's CID or Kubo's output: {claims:#?}"
    );

    let text = |name: &str| {
        let (_, bytes) = files
            .iter()
            .find(|(path, _)| path == name)
            .expect("read above");
        std::str::from_utf8(bytes).unwrap_or_else(|error| panic!("{name}: {error}"))
    };
    let missing = claim_wording_findings(text("README.md"), text("src/lib.rs"));
    assert!(
        missing.is_empty(),
        "the claim {COMPUTED_BY_THE_LAB:?} is not stated where it must be: {missing:#?}"
    );
}

/// The wording check names each place that lacks the claim or the gate: the
/// claim only in "Claim scope" leaves "The encoding" without it, the claim in
/// the code but not in its module doc does not count, and a README without
/// "Claim scope" is refused with the section reader's reason.
#[test]
fn the_claim_wording_check_names_each_gap() {
    let readme = format!(
        "## The encoding\n\nKubo v0.40.1's import flags.\n\n## Claim scope\n\nOne Mac.\n{}\n\n## Run\n",
        COMPUTED_BY_THE_LAB
    );
    let library = format!(
        "//! The lab CID.\n#![forbid(unsafe_code)]\n// {COMPUTED_BY_THE_LAB}\nconst X: u8 = 0;\n"
    );
    let lacks = |place: &str, needed: &str| format!("{place} does not say {needed:?}");
    assert_eq!(
        claim_wording_findings(&readme, &library),
        [
            lacks("README.md's \"## The encoding\"", COMPUTED_BY_THE_LAB),
            lacks("README.md's \"## Claim scope\"", KUBO_GATE),
            lacks("src/lib.rs's module doc", COMPUTED_BY_THE_LAB),
        ]
    );

    let no_scope = readme.replacen("## Claim scope\n", "## Scope\n", 1);
    let reason = "README.md has no \"## Claim scope\" section".to_owned();
    assert_eq!(
        claim_wording_findings(&no_scope, &library)[1..3],
        [reason.clone(), reason]
    );

    let complete = format!(
        "## The encoding\n\n{COMPUTED_BY_THE_LAB}.\n\n## Claim scope\n\n{COMPUTED_BY_THE_LAB}.\n{}\n",
        KUBO_GATE.replace(". ", ".\n")
    );
    let doc = format!("//! The\n//! {COMPUTED_BY_THE_LAB}.\nconst X: u8 = 0;\n");
    assert_eq!(
        claim_wording_findings(&complete, &doc),
        Vec::<String>::new()
    );
}

/// The scan reads a claim however it is written: in any case, over a line
/// break, over two comment, blockquote or block-comment lines, with a
/// typographic apostrophe, with emphasis or code marks around a word. It names
/// the file, the line where the claim starts and the phrase, and a negation is
/// not a claim, quoted or not. A file it cannot read or decode is refused with
/// its cause.
#[test]
fn the_claim_scan_finds_a_claim_however_it_is_written() {
    let cases: [(&str, &str, &[&str]); 11] = [
        (
            "case.md",
            "One line.\nThe lab CID EQUALS THE RUNTIME'S CID.\n",
            &["case.md:2: \"equals the runtime's cid\""],
        ),
        (
            "wrapped.md",
            "The lab CID\nmatches\nKubo.\n",
            &["wrapped.md:2: \"matches kubo\""],
        ),
        (
            "src/doc.rs",
            "/// The lab CID is the\n/// Runtime's CID.\nconst X: u8 = 0;\n",
            &["src/doc.rs:1: \"is the runtime's cid\""],
        ),
        (
            "apostrophe.md",
            "It is the same as the Runtime\u{2019}s CID.\n",
            &["apostrophe.md:1: \"same as the runtime's cid\""],
        ),
        (
            "negation.md",
            "It is not the Runtime's CID, and no Kubo has computed it.\n",
            &[],
        ),
        (
            "two.md",
            "Kubo-compatible.\n\n//! the same CID as Kubo\n",
            &[
                "two.md:1: \"kubo-compatible\"",
                "two.md:3: \"same cid as kubo\"",
            ],
        ),
        (
            "quote.md",
            "> The lab CID matches\n> Kubo.\n",
            &["quote.md:1: \"matches kubo\""],
        ),
        (
            "emphasis.md",
            "It equals *the* Runtime's CID.\n",
            &["emphasis.md:1: \"equals the runtime's cid\""],
        ),
        (
            "code.md",
            "It is the same as the `Runtime's` CID.\n",
            &["code.md:1: \"same as the runtime's cid\""],
        ),
        (
            "src/block.rs",
            "/* The lab CID is the\n * Runtime's CID. */\nconst X: u8 = 0;\n",
            &["src/block.rs:1: \"is the runtime's cid\""],
        ),
        (
            "quoted-negation.md",
            "> It is not the Runtime's CID.\n",
            &[],
        ),
    ];
    for (path, text, expected) in cases {
        let found = equality_claims_in(path, text.as_bytes())
            .unwrap_or_else(|reason| panic!("{path}: {reason}"));
        let mut found: Vec<&str> = found.iter().map(String::as_str).collect();
        found.sort();
        assert_eq!(found, expected, "{path}: {text:?}");
    }

    let not_utf8 = equality_claims_in("bytes.md", &[b'a', 0xff]).expect_err("not UTF-8");
    assert!(
        not_utf8.starts_with("bytes.md is not UTF-8: "),
        "{not_utf8}"
    );

    let missing = "no-such-file.md".to_owned();
    let unreadable = read_lane_files(&["README.md".to_owned(), missing])
        .expect_err("a file that cannot be read fails the scan");
    assert!(
        unreadable.starts_with("the claim scan cannot read no-such-file.md: "),
        "{unreadable}"
    );
}
