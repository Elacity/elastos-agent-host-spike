//! The dependency closure walks the caller's map of printed lab CIDs, so a
//! missing dependency, a cycle or a chain past the cap is refused before the
//! closure is treated as one package. A node is a printed lab CID minted here
//! with the one encoder: no fixture folder is read and no common helper is
//! used. This is identity data only; nothing here admits or launches.

use capsule_identity::{
    dependency_closure, encode_entries, BundleEntry, DependencyRefusal, LabCid,
};
use std::collections::BTreeMap;

/// One printed lab CID, from `encode_entries` over one distinct entry.
fn node(tag: &str) -> String {
    let entry = BundleEntry {
        path: format!("{tag}.wasm"),
        content: tag.as_bytes().to_vec(),
    };
    encode_entries(&[entry])
        .unwrap_or_else(|refusal| panic!("one entry is named: {refusal}"))
        .to_string()
}

/// The map a test declares: each `(tag, children)` pair keyed by its node.
fn links(pairs: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
    pairs
        .iter()
        .map(|(tag, children)| {
            (
                node(tag),
                children.iter().map(|child| node(child)).collect(),
            )
        })
        .collect()
}

/// What a result says, as text, without panicking on the other variant.
fn display(got: &Result<Vec<String>, DependencyRefusal>) -> Option<String> {
    got.as_ref().err().map(|refusal| refusal.to_string())
}

#[test]
fn dependency_diamond_visits_the_shared_node_once() {
    let deps = links(&[
        ("root", &["a", "b"]),
        ("a", &["c"]),
        ("b", &["c"]),
        ("c", &[]),
    ]);
    let got = dependency_closure(&node("root"), &deps, 10);
    assert_eq!(
        got,
        Ok(vec![node("c"), node("a"), node("b"), node("root")]),
        "c comes once, before a and b; the root is last"
    );
}

#[test]
fn dependency_cycle_names_its_path() {
    let deps = links(&[("a", &["b"]), ("b", &["a"])]);
    let got = dependency_closure(&node("a"), &deps, 10);
    let a = node("a");
    let b = node("b");
    assert_eq!(
        got,
        Err(DependencyRefusal::Cycle(vec![
            a.clone(),
            b.clone(),
            a.clone()
        ]))
    );
    assert_eq!(display(&got), Some(format!("cycle: {a} -> {b} -> {a}")));

    // A cycle below the root starts at the repeated node, not at the root.
    let deps = links(&[("r", &["a"]), ("a", &["b"]), ("b", &["a"])]);
    let got = dependency_closure(&node("r"), &deps, 10);
    assert_eq!(
        got,
        Err(DependencyRefusal::Cycle(vec![
            a.clone(),
            b.clone(),
            a.clone()
        ]))
    );
    assert_eq!(display(&got), Some(format!("cycle: {a} -> {b} -> {a}")));
}

#[test]
fn missing_dependency_is_refused() {
    let a = node("a");
    let absent = node("absent");
    let deps = BTreeMap::from([(a.clone(), vec![absent.clone()])]);
    let got = dependency_closure(&a, &deps, 10);
    assert_eq!(got, Err(DependencyRefusal::Missing(absent.clone())));
    assert_eq!(display(&got), Some(format!("missing dependency: {absent}")));

    // The root is a node too: absent from the map, it is refused as missing.
    let root = node("root-absent");
    let got = dependency_closure(&root, &deps, 0);
    assert_eq!(got, Err(DependencyRefusal::Missing(root.clone())));
    assert_eq!(display(&got), Some(format!("missing dependency: {root}")));
}

#[test]
fn dependency_depth_cap_is_enforced() {
    let deps = links(&[("a", &["b"]), ("b", &["c"]), ("c", &["d"]), ("d", &[])]);
    assert_eq!(
        dependency_closure(&node("a"), &deps, 3),
        Ok(vec![node("d"), node("c"), node("b"), node("a")])
    );
    let got = dependency_closure(&node("a"), &deps, 2);
    assert_eq!(got, Err(DependencyRefusal::TooDeep(2)));
    assert_eq!(
        display(&got),
        Some("dependency chain deeper than 2".to_owned())
    );

    // A root with no dependencies is named at cap 0.
    let solo = node("solo");
    let deps = BTreeMap::from([(solo.clone(), Vec::new())]);
    assert_eq!(dependency_closure(&solo, &deps, 0), Ok(vec![solo]));

    // A finished node still answers for its subtree: r -> b -> c -> a -> d
    // is a depth-4 path even though a first finished at depth 1.
    let deps = links(&[
        ("r", &["a", "b"]),
        ("a", &["d"]),
        ("b", &["c"]),
        ("c", &["a"]),
        ("d", &[]),
    ]);
    let got = dependency_closure(&node("r"), &deps, 3);
    assert_eq!(got, Err(DependencyRefusal::TooDeep(3)));
    assert_eq!(
        display(&got),
        Some("dependency chain deeper than 3".to_owned())
    );
}

#[test]
fn dependency_name_that_is_not_a_lab_cid_is_refused() {
    let root = "not-a-cid";
    let parse_refusal = match root.parse::<LabCid>() {
        Err(refusal) => refusal,
        Ok(cid) => panic!("{root} parsed as {cid}"),
    };
    let got = dependency_closure(root, &BTreeMap::new(), 10);
    assert_eq!(
        got,
        Err(DependencyRefusal::NotALabCid(parse_refusal.clone()))
    );
    assert_eq!(display(&got), Some(parse_refusal.to_string()));
    assert!(display(&got)
        .unwrap_or_default()
        .contains("is not a lab CID"));

    // A child takes the same one parse, before its map entry is considered.
    let a = node("a");
    let deps = BTreeMap::from([(a.clone(), vec![root.to_owned()])]);
    let got = dependency_closure(&a, &deps, 10);
    assert_eq!(
        got,
        Err(DependencyRefusal::NotALabCid(parse_refusal.clone()))
    );

    // A 59-character name that the one parse refuses proves the walk calls
    // the shared parser, not a length or shape check of its own.
    let invalid = format!("b{}", "0".repeat(58));
    let shared = match invalid.parse::<LabCid>() {
        Err(refusal) => refusal,
        Ok(cid) => panic!("{invalid} parsed as {cid}"),
    };
    let got = dependency_closure(&invalid, &BTreeMap::new(), 0);
    assert_eq!(got, Err(DependencyRefusal::NotALabCid(shared.clone())));
    assert_eq!(display(&got), Some(shared.to_string()));

    // The closure holds no second identity: no private check and no digest
    // prefix name of its own.
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
    )
    .unwrap_or_else(|error| panic!("src/lib.rs: {error}"));
    let start = source
        .find("pub enum DependencyRefusal")
        .unwrap_or_else(|| panic!("the closure's refusal is declared once"));
    let closure = &source[start..];
    assert!(closure.contains("parse::<LabCid>()"), "{closure}");
    assert!(!closure.contains("fn is_lab_cid"), "{closure}");
    let digest_prefix = ["sha", "256:"].concat();
    assert!(!closure.contains(&digest_prefix), "{closure}");
}
