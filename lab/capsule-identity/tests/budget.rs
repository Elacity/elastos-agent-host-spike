//! The walk under a budget: four limits, each refused as soon as it is
//! passed, and a bundle exactly at its limits named as without them.
//!
//! What a fixture holds is counted here with `std::fs`, not by the walk under
//! test, so each expected number is made independently of the code it checks.
mod common;

use std::fs;
use std::path::Path;

use capsule_identity::{checked_bundle, checked_bundle_within, Budget, LabCid, Refusal};
use common::*;

/// What a folder holds, as [`Budget`] counts it: every file and folder under
/// the root is one entry; a path's parts are its `/`-separated names; a
/// folder counts one part deeper than itself, because that is where its
/// entries would be.
#[derive(Debug, Clone, Copy)]
struct Shape {
    entries: usize,
    bytes: u64,
    depth: usize,
    path_bytes: usize,
}

fn shape(root: &Path) -> Shape {
    fn visit(dir: &Path, prefix: &str, parts: usize, shape: &mut Shape) {
        for item in fs::read_dir(dir).expect("list") {
            let item = item.expect("entry");
            let name = item.file_name().into_string().expect("utf-8 name");
            let path = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            shape.entries += 1;
            shape.path_bytes = shape.path_bytes.max(path.len());
            shape.depth = shape.depth.max(parts);
            let kind = item.file_type().expect("type");
            if kind.is_dir() {
                shape.depth = shape.depth.max(parts + 1);
                visit(&item.path(), &path, parts + 1, shape);
            } else {
                shape.bytes += item.metadata().expect("size").len();
            }
        }
    }
    let mut shape = Shape {
        entries: 0,
        bytes: 0,
        depth: 0,
        path_bytes: 0,
    };
    visit(root, "", 1, &mut shape);
    shape
}

fn exact(shape: Shape) -> Budget {
    Budget {
        max_entries: shape.entries,
        max_total_bytes: shape.bytes,
        max_depth: shape.depth,
        max_path_bytes: shape.path_bytes,
    }
}

fn over(result: Result<capsule_identity::CheckedBundle, Refusal>) -> &'static str {
    match result {
        Err(Refusal::OverBudget { limit, .. }) => limit,
        other => panic!("not an OverBudget refusal: {:?}", other.map(|b| b.cid())),
    }
}

#[test]
fn a_bundle_exactly_at_its_budget_is_named_as_without_one() {
    let bundle = assemble(&WEB_APP);
    let expected: LabCid = WEB_APP_LAB_CID.parse().expect("the recorded CID");
    let within = checked_bundle_within(bundle.path(), exact(shape(bundle.path())))
        .expect("exactly at its budget");
    assert_eq!(within.cid(), expected);
    assert_eq!(
        checked_bundle(bundle.path()).expect("unbudgeted").cid(),
        expected
    );
    // The fixture is not trivial: each limit below has something to cut.
    let shape = shape(bundle.path());
    assert!(shape.entries >= 2 && shape.bytes > 1 && shape.depth >= 2 && shape.path_bytes > 1);
}

#[test]
fn one_entry_over_the_budget_is_refused() {
    let bundle = assemble(&WEB_APP);
    let mut budget = exact(shape(bundle.path()));
    budget.max_entries -= 1;
    assert_eq!(
        over(checked_bundle_within(bundle.path(), budget)),
        "entries"
    );
}

#[test]
fn one_byte_over_the_budget_is_refused() {
    let bundle = assemble(&WEB_APP);
    let mut budget = exact(shape(bundle.path()));
    budget.max_total_bytes -= 1;
    assert_eq!(
        over(checked_bundle_within(bundle.path(), budget)),
        "total bytes"
    );
}

#[test]
fn a_file_far_over_the_budget_is_refused_by_its_size_not_by_reading_it() {
    // 64 MiB that exist only as a length. The budget is what the bundle held
    // before the file was added, so the file is refused from its size alone.
    let bundle = assemble(&WEB_APP);
    let before = exact(shape(bundle.path()));
    let big = fs::File::create(bundle.path().join("zz-big.bin")).expect("create");
    big.set_len(64 * 1024 * 1024).expect("length");
    drop(big);
    let budget = Budget {
        max_entries: before.max_entries + 1,
        ..before
    };
    match checked_bundle_within(bundle.path(), budget) {
        Err(Refusal::OverBudget { limit, path }) => {
            assert_eq!((limit, path.as_str()), ("total bytes", "zz-big.bin"));
        }
        other => panic!("not refused by size: {:?}", other.map(|b| b.cid())),
    }
}

#[test]
fn one_level_deeper_than_the_budget_is_refused() {
    let bundle = assemble(&WEB_APP);
    let mut budget = exact(shape(bundle.path()));
    budget.max_depth -= 1;
    assert_eq!(over(checked_bundle_within(bundle.path(), budget)), "depth");
}

#[test]
fn a_nest_of_folders_is_refused_at_the_depth_limit_before_it_is_entered() {
    // Forty folders, one inside the other, and a budget of sixteen parts.
    let bundle = assemble(&WEB_APP);
    let mut nest = bundle.path().to_path_buf();
    for _ in 0..40 {
        nest.push("d");
    }
    fs::create_dir_all(&nest).expect("nest");
    fs::write(nest.join("leaf.txt"), b"x").expect("leaf");
    let budget = Budget {
        max_depth: 16,
        ..Budget::UNLIMITED
    };
    match checked_bundle_within(bundle.path(), budget) {
        Err(Refusal::OverBudget { limit, path }) => {
            assert_eq!(limit, "depth");
            // The folder that was not entered is the sixteenth `d`.
            assert_eq!(path.split('/').count(), 16, "{path}");
        }
        other => panic!("the nest was walked: {:?}", other.map(|b| b.cid())),
    }
}

#[test]
fn one_path_byte_over_the_budget_is_refused() {
    let bundle = assemble(&WEB_APP);
    let mut budget = exact(shape(bundle.path()));
    budget.max_path_bytes -= 1;
    assert_eq!(
        over(checked_bundle_within(bundle.path(), budget)),
        "path bytes"
    );
}

#[test]
fn the_lab_build_holds_the_lab_refusals_and_says_so() {
    // The lab turns the crate's `lab` feature on; a production crate asserts
    // the opposite at compile time.
    assert!(capsule_identity::LAB_REFUSALS);
}
