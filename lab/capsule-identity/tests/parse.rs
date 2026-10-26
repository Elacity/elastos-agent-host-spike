//! A printed lab CID is read back with one parse, `str::parse::<LabCid>()`.
//! It runs the claim check both name checks run and refuses what they
//! refuse, so a consumer never copies the printed form.
mod common;

use capsule_identity::{check_name, encode_entries, BundleEntry, LabCid, Refusal};
use common::*;

/// `printed` parses back to `value`, and the parsed value prints `printed`.
fn assert_parses_back(value: LabCid, printed: &str) {
    let parsed: LabCid = printed
        .parse()
        .unwrap_or_else(|refusal| panic!("{printed} did not parse: {refusal}"));
    assert_eq!(parsed, value, "{printed} parsed to another value");
    assert_eq!(parsed.to_string(), printed);
}

#[test]
fn printed_lab_cid_parses_back_to_the_same_value() {
    let pinned = [
        (&CONTENT_SAMPLE, CONTENT_SAMPLE_LAB_CID),
        (&WEB_APP, WEB_APP_LAB_CID),
        (&AGENT_HOST, AGENT_HOST_LAB_CID),
    ];
    let mut values = Vec::new();
    for (fixture, pin) in pinned {
        let bundle = assemble(fixture);
        let value = named(bundle.path());
        assert_eq!(value.to_string(), pin, "{}", fixture.name);
        assert_parses_back(value, pin);
        values.push(value);
    }

    // A synthetic value from the encoder: no bundle and no manifest, so a
    // consumer can make a well-formed value without knowing the printed form.
    let synthetic = encode_entries(&[
        BundleEntry {
            path: "one.txt".to_owned(),
            content: b"one".to_vec(),
        },
        BundleEntry {
            path: "folder/two.txt".to_owned(),
            content: b"two".to_vec(),
        },
    ])
    .expect("two entries with two paths are named");
    assert_parses_back(synthetic, &synthetic.to_string());
    values.push(synthetic);

    // Two different values never parse to the same value.
    let parsed: Vec<LabCid> = values
        .iter()
        .map(|value| value.to_string().parse().expect("a printed value parses"))
        .collect();
    for (i, a) in parsed.iter().enumerate() {
        for b in &parsed[i + 1..] {
            assert_ne!(a, b, "two different printed values parsed to one value");
        }
    }
}

#[test]
fn parse_refuses_what_the_name_check_refuses() {
    let bundle = assemble(&WEB_APP);
    let digits = WEB_APP_LAB_CID
        .strip_prefix("lab-cid:sha256:")
        .expect("the pin has the label");
    // A copy of the list in `tests/check_name.rs`
    // `claimed_name_is_checked_never_trusted` (lines 23-42).
    let not_lab_cids = [
        // No label, the right digits.
        digits.to_owned(),
        // Another label, or the label in capitals.
        format!("sha256:{digits}"),
        format!("LAB-CID:SHA256:{digits}"),
        // Uppercase hex.
        format!("lab-cid:sha256:{}", digits.to_uppercase()),
        // A character that is not hex, in place of the last digit.
        format!("lab-cid:sha256:{}g", &digits[..63]),
        // A character that is not ASCII: 64 bytes, but not 64 hex digits.
        format!("lab-cid:sha256:{}é", &digits[..62]),
        // 63 and 65 characters, a trailing newline, and none.
        format!("lab-cid:sha256:{}", &digits[..63]),
        format!("lab-cid:sha256:{digits}0"),
        format!("{WEB_APP_LAB_CID}\n"),
        "lab-cid:sha256:".to_owned(),
        String::new(),
    ];
    for claim in not_lab_cids {
        let refusal = claim
            .parse::<LabCid>()
            .expect_err("text that is not a lab CID must not parse");
        assert_eq!(
            refusal,
            Refusal::NotALabCid {
                claimed: claim.clone()
            },
            "{claim:?}"
        );
        let name_check = check_name(bundle.path(), &claim)
            .expect_err("the name check refuses a claim that is not a lab CID");
        assert_eq!(refusal, name_check, "{claim:?}");
        assert_eq!(refusal.to_string(), name_check.to_string(), "{claim:?}");
    }
}

#[test]
fn parse_shares_the_one_claim_check() {
    let code = library_code();
    let parse = library_item(&code, "fn from_str(");
    assert_eq!(
        parse.matches("lab_cid_digits(").count(),
        1,
        "the parse must call the one claim check once:\n{parse}"
    );
    for copy in ["strip_prefix", "LAB_CID_PREFIX", "lab-cid:sha256:"] {
        assert!(
            !parse.contains(copy),
            "the parse holds {copy:?}, a copy of the claim check:\n{parse}"
        );
    }
    // The map form is used: the parse names `Refusal::NotALabCid` exactly
    // once, to map the decode error, which the claim check has already ruled
    // out. It is no second claim check.
    assert_eq!(
        parse.matches("Refusal::NotALabCid").count(),
        1,
        "the parse names NotALabCid more than in its one decode-error map:\n{parse}"
    );
}
