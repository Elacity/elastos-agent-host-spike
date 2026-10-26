//! README's "For a lab that uses the lab CID" is under test: its list of
//! consumer manifests equals the lab crates that depend on this crate by
//! path, as Cargo's own reader reads their manifests, and it states how a
//! consumer recomputes a pin outside the code. So the next change to what
//! `lab_cid` prints cannot miss a consumer (P12). No TOML is read by hand.
mod common;

use std::path::{Path, PathBuf};

use common::*;
use tempfile::TempDir;

/// The sentence of the note that keeps a pin outside the code, as written.
const NEVER_COPIED: &str = "A pin is never copied from the code's output.";

/// A one-package crate in a fresh temp folder outside the tree: a manifest
/// with `tables` after its `[package]` table, and an empty `src/lib.rs`.
fn consumer_fixture(tables: &str) -> TempDir {
    let fixture = temp_dir();
    let manifest = format!(
        "[package]\nname = \"fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n{tables}"
    );
    write_file(fixture.path(), "Cargo.toml", manifest.as_bytes());
    write_file(fixture.path(), "src/lib.rs", b"");
    fixture
}

fn manifest_of(fixture: &TempDir) -> PathBuf {
    fixture.path().join("Cargo.toml")
}

/// This lane's folder as a TOML literal string.
fn lane_literal() -> String {
    let lane = lane_dir().display().to_string();
    assert!(!lane.contains('\''), "{lane} fits a TOML literal string");
    format!("'{lane}'")
}

/// The scan's answer for a fixture with `tables`.
fn scanned(tables: &str) -> Result<bool, String> {
    let fixture = consumer_fixture(tables);
    depends_on_this_crate(&manifest_of(&fixture))
}

#[test]
fn every_lab_cid_consumer_is_in_the_adoption_note() {
    let manifests = lab_manifests().unwrap_or_else(|reason| panic!("the git listing: {reason}"));
    let folders: Vec<PathBuf> = manifests
        .iter()
        .map(|path| {
            repo_dir()
                .join(path)
                .parent()
                .expect("a manifest's folder")
                .to_path_buf()
        })
        .collect();
    let before: Vec<_> = folders.iter().map(|folder| folder_state(folder)).collect();

    let found = lab_cid_consumers().unwrap_or_else(|reason| panic!("the consumer scan: {reason}"));

    // Cargo's reader wrote nothing in any scanned crate, ignored files too.
    for (folder, state) in folders.iter().zip(&before) {
        assert!(
            &folder_state(folder) == state,
            "the consumer scan changed {}",
            folder.display()
        );
    }

    let listed =
        readme_lab_cid_consumers().unwrap_or_else(|reason| panic!("the adoption note: {reason}"));
    assert!(!listed.is_empty(), "the adoption note lists no consumer");
    let missing: Vec<&String> = found.iter().filter(|path| !listed.contains(path)).collect();
    let extra: Vec<&String> = listed.iter().filter(|path| !found.contains(path)).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "README's adoption note and the lab's manifests differ: \
         missing from the note {missing:?}; listed but no dependency on this crate found {extra:?}"
    );
}

#[test]
fn the_consumer_scan_uses_cargos_reader() {
    let lane = lane_literal();

    // (a) A manifest Cargo cannot read fails with that manifest and Cargo's
    // own message, never as "no dependency".
    let broken = consumer_fixture("[dependencies}\n");
    let manifest = manifest_of(&broken);
    let refusal = depends_on_this_crate(&manifest).expect_err("Cargo cannot read [dependencies}");
    assert!(
        refusal.starts_with(&format!("cargo metadata refused {}", manifest.display()))
            && refusal.contains("[dependencies}"),
        "{refusal}"
    );

    // (b) A quoted key, and (c) a rename, are the same package to Cargo.
    let quoted = format!("[dependencies]\n\"capsule-identity\" = {{ path = {lane} }}\n");
    assert_eq!(scanned(&quoted), Ok(true), "{quoted}");
    let renamed =
        format!("[dependencies]\nci = {{ package = \"capsule-identity\", path = {lane} }}\n");
    assert_eq!(scanned(&renamed), Ok(true), "{renamed}");

    // Any kind: a dev-dependency and a build-dependency count too.
    for table in ["dev-dependencies", "build-dependencies"] {
        let text = format!("[{table}]\ncapsule-identity = {{ path = {lane} }}\n");
        assert_eq!(scanned(&text), Ok(true), "{text}");
    }

    // (d) No path is not this crate.
    let registry = "[dependencies]\ncapsule-identity = \"0.1\"\n";
    assert_eq!(scanned(registry), Ok(false), "{registry}");

    // The same name at another path is not this crate either.
    let other = temp_dir();
    let elsewhere = format!(
        "[dependencies]\ncapsule-identity = {{ path = '{}' }}\n",
        other.path().display()
    );
    assert_eq!(scanned(&elsewhere), Ok(false), "{elsewhere}");
}

#[test]
fn the_consumer_scan_refuses_bad_metadata() {
    let fixture = consumer_fixture("");
    let manifest = manifest_of(&fixture);
    let shown = manifest.display();
    let read = |json: &str| consumer_in_metadata(&manifest, json.as_bytes());

    let not_json = read("{ not json").expect_err("not JSON");
    assert!(
        not_json.starts_with(&format!("cargo metadata for {shown} is not JSON: ")),
        "{not_json}"
    );

    let other_manifest = lane_dir().join("Cargo.toml");
    let no_package = read(&format!(
        r#"{{"packages":[{{"manifest_path":{:?},"dependencies":[]}}]}}"#,
        other_manifest.display().to_string()
    ))
    .expect_err("no package for that manifest");
    assert_eq!(
        no_package,
        format!("cargo metadata for {shown} holds no package whose manifest is that file")
    );

    let nowhere = fixture.path().join("nowhere").display().to_string();
    let unresolved = read(&format!(
        r#"{{"packages":[{{"manifest_path":{:?},"dependencies":[{{"name":"capsule-identity","path":{nowhere:?}}}]}}]}}"#,
        shown.to_string()
    ))
    .expect_err("a path that does not resolve");
    assert!(
        unresolved.starts_with(&format!(
            "cargo metadata for {shown} names {nowhere}, which does not resolve: "
        )),
        "{unresolved}"
    );

    for (json, reason) in [
        ("{}", "holds no packages list"),
        (
            r#"{"packages":[{}]}"#,
            "has a package with no manifest_path",
        ),
    ] {
        assert_eq!(
            read(json),
            Err(format!("cargo metadata for {shown} {reason}")),
            "{json}"
        );
    }
    let no_dependencies = format!(
        r#"{{"packages":[{{"manifest_path":{:?}}}]}}"#,
        shown.to_string()
    );
    assert_eq!(
        read(&no_dependencies),
        Err(format!(
            "cargo metadata for {shown} holds no dependencies list"
        ))
    );

    // Each refusal has its own cause.
    assert!(not_json != no_package && no_package != unresolved && not_json != unresolved);
}

#[test]
fn the_consumer_scan_writes_nothing() {
    let fixture = consumer_fixture(&format!(
        "[dependencies]\ncapsule-identity = {{ path = {} }}\n",
        lane_literal()
    ));
    let before = folder_state(fixture.path());
    assert_eq!(
        before
            .iter()
            .map(|(path, _)| path.as_path())
            .collect::<Vec<_>>(),
        [
            Path::new("Cargo.toml"),
            Path::new("src"),
            Path::new("src/lib.rs")
        ]
    );
    // The folder is compared first, so a scan that writes and then fails is
    // caught for its write.
    let answer = depends_on_this_crate(&manifest_of(&fixture));
    let after = folder_state(fixture.path());
    assert!(
        after == before,
        "the scan wrote in the fixture: {:?}",
        after.iter().map(|(path, _)| path).collect::<Vec<_>>()
    );
    assert!(!fixture.path().join("target").exists());
    assert!(!fixture.path().join("Cargo.lock").exists());
    assert_eq!(answer, Ok(true));
}

#[test]
fn the_adoption_list_is_read_strictly() {
    let title = ADOPTION_HEADING.trim_end();
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
