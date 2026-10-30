//! One lab-CID walk (task 081): `dependency_closure` checks a caller's map
//! from a printed lab CID to the printed lab CIDs it depends on. A missing
//! link, a cycle and a chain past the depth cap are each refused with their
//! own reason, and every reachable node is listed once in post-order.
//!
//! Every node here is minted with `encode_entries` of one distinct
//! `BundleEntry`, so each name is a real printed lab CID. The map is the
//! caller's; the walk reads no folder and no manifest, and it does not admit
//! or launch. This test file uses no shared test support.
use std::collections::BTreeMap;

use capsule_identity::{
    dependency_closure, encode_entries, BundleEntry, DependencyRefusal, Refusal,
};

/// One distinct node: a bundle of one entry whose path and bytes are `text`'s,
/// printed as its lab CID.
fn node(text: &str) -> String {
    encode_entries(&[BundleEntry {
        path: format!("{text}.txt"),
        content: text.as_bytes().to_vec(),
    }])
    .expect("one entry names a bundle")
    .to_string()
}

/// `root` with each dependency list given as pairs.
fn map(pairs: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
    let mut deps = BTreeMap::new();
    for (name, children) in pairs {
        deps.insert(
            (*name).to_owned(),
            children.iter().map(|child| (*child).to_owned()).collect(),
        );
    }
    deps
}

#[test]
fn dependency_diamond_visits_the_shared_node_once() {
    let root = node("root");
    let a = node("a");
    let b = node("b");
    let c = node("c");
    let deps = map(&[(&root, &[&a, &b]), (&a, &[&c]), (&b, &[&c]), (&c, &[])]);

    let closure =
        dependency_closure(&root, &deps, 4).expect("every link of the diamond is present");
    assert_eq!(
        closure,
        [c.clone(), a.clone(), b.clone(), root.clone()],
        "c is listed once, each dependency comes before its dependent, and the root is last"
    );
}

#[test]
fn dependency_cycle_names_its_path() {
    let a = node("a");
    let b = node("b");
    let deps = map(&[(&a, &[&b]), (&b, &[&a])]);

    let refusal = dependency_closure(&a, &deps, 8).expect_err("a cycle is refused");
    assert_eq!(
        refusal,
        DependencyRefusal::Cycle(vec![a.clone(), b.clone(), a.clone()]),
        "the path runs from the repeated node through the current node and back"
    );
    assert_eq!(refusal.to_string(), format!("cycle: {a} -> {b} -> {a}"));
}

#[test]
fn missing_dependency_is_refused() {
    let a = node("a");
    let b = node("b");
    let deps = map(&[(&a, &[&b])]);

    let refusal = dependency_closure(&a, &deps, 8).expect_err("a missing child is refused");
    assert_eq!(refusal, DependencyRefusal::Missing(b.clone()));
    assert_eq!(refusal.to_string(), format!("missing dependency: {b}"));

    let root = node("root");
    let none = BTreeMap::new();
    let refusal = dependency_closure(&root, &none, 0).expect_err("a missing root is refused");
    assert_eq!(refusal, DependencyRefusal::Missing(root.clone()));
    assert_eq!(refusal.to_string(), format!("missing dependency: {root}"));
}

#[test]
fn dependency_depth_cap_is_enforced() {
    let a = node("a");
    let b = node("b");
    let c = node("c");
    let d = node("d");
    let deps = map(&[(&a, &[&b]), (&b, &[&c]), (&c, &[&d]), (&d, &[])]);

    assert_eq!(
        dependency_closure(&a, &deps, 3).expect("d's depth 3 is inside the cap of 3"),
        [d.clone(), c.clone(), b.clone(), a.clone()]
    );
    let refusal = dependency_closure(&a, &deps, 2).expect_err("d's depth 3 is over the cap of 2");
    assert_eq!(refusal, DependencyRefusal::TooDeep(2));
    assert_eq!(refusal.to_string(), "dependency chain deeper than 2");

    let alone = node("alone");
    let one = map(&[(&alone, &[])]);
    assert_eq!(
        dependency_closure(&alone, &one, 0).expect("a root with no dependency is depth 0"),
        [alone.clone()]
    );
}

#[test]
fn dependency_depth_rechecks_a_finished_node() {
    let r = node("r");
    let a = node("a");
    let b = node("b");
    let c = node("c");
    let d = node("d");
    let deps = map(&[
        (&r, &[&a, &b]),
        (&a, &[&d]),
        (&b, &[&c]),
        (&c, &[&a]),
        (&d, &[]),
    ]);

    assert_eq!(
        dependency_closure(&r, &deps, 4).expect("d at depth 4 is inside the cap of 4"),
        [d.clone(), a.clone(), c.clone(), b.clone(), r.clone()],
        "each node is listed once though c reaches a again"
    );

    let refusal =
        dependency_closure(&r, &deps, 3).expect_err("the deeper reach to d is over the cap of 3");
    assert_eq!(refusal, DependencyRefusal::TooDeep(3));
    assert_eq!(refusal.to_string(), "dependency chain deeper than 3");
}

#[test]
fn dependency_name_that_is_not_a_lab_cid_is_refused() {
    let bad = "not-a-cid".to_owned();
    let none = BTreeMap::new();
    let refusal = dependency_closure(&bad, &none, 8).expect_err("the root is not a lab CID");
    assert_eq!(
        refusal,
        DependencyRefusal::NotALabCid(Refusal::NotALabCid {
            claimed: bad.clone()
        }),
        "a bad root is refused before the map is read"
    );
    assert_eq!(
        refusal.to_string(),
        Refusal::NotALabCid {
            claimed: bad.clone()
        }
        .to_string()
    );

    let root = node("root");
    let deps = map(&[(&root, &[&bad])]);
    let refusal = dependency_closure(&root, &deps, 8).expect_err("the child is not a lab CID");
    assert_eq!(
        refusal,
        DependencyRefusal::NotALabCid(Refusal::NotALabCid {
            claimed: bad.clone()
        })
    );
    assert_eq!(
        refusal.to_string(),
        Refusal::NotALabCid {
            claimed: bad.clone()
        }
        .to_string()
    );

    // 59 characters that start `bafybei`, with the 8th character putting bits
    // outside the directory-root bytes, so the one parse refuses it.
    let lookalike = format!("{}z{}", &root[..7], &root[8..]);
    assert_eq!((lookalike.len(), &lookalike[..7]), (59, "bafybei"));
    let refusal =
        dependency_closure(&lookalike, &none, 8).expect_err("a 59-character lookalike is refused");
    assert_eq!(
        refusal,
        DependencyRefusal::NotALabCid(Refusal::NotALabCid {
            claimed: lookalike.clone()
        })
    );
    assert_eq!(
        refusal.to_string(),
        Refusal::NotALabCid {
            claimed: lookalike.clone()
        }
        .to_string()
    );
}
