//! The walk under a budget: four limits, each refused as soon as it is
//! passed, and a bundle exactly at its limits named as without them.
//!
//! What a fixture holds is counted here with `std::fs`, not by the walk under
//! test, so each expected number is made independently of the code it checks.
mod common;

use std::fs;
use std::path::Path;

use capsule_identity::{
    checked_bundle, checked_bundle_within, checked_bundle_within_observed, Budget, LabCid, Moment,
    Refusal,
};
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
fn a_folder_past_the_depth_limit_is_never_opened() {
    // The same nest, with the walk's observer listening. The walk tells it
    // of every entry right before the open and right after. The sixteenth
    // folder is refused, and the observer never hears of it; it heard of the
    // fifteenth at both moments, so it was listening.
    let bundle = assemble(&WEB_APP);
    let mut nest = bundle.path().to_path_buf();
    for _ in 0..40 {
        nest.push("d");
    }
    fs::create_dir_all(&nest).expect("nest");
    let budget = Budget {
        max_depth: 16,
        ..Budget::UNLIMITED
    };
    let mut seen: Vec<(Moment, String)> = Vec::new();
    let refused = checked_bundle_within_observed(bundle.path(), budget, |moment, path| {
        seen.push((moment, path.to_owned()))
    })
    .expect_err("the nest is refused");
    let sixteenth = ["d"; 16].join("/");
    let fifteenth = ["d"; 15].join("/");
    assert_eq!(
        refused,
        Refusal::OverBudget {
            limit: "depth",
            path: sixteenth.clone()
        }
    );
    let moments = |path: &str| -> Vec<Moment> {
        seen.iter()
            .filter(|(_, seen)| seen == path)
            .map(|(moment, _)| *moment)
            .collect()
    };
    assert_eq!(
        moments(&fifteenth),
        [Moment::BeforeOpen, Moment::AfterCheck]
    );
    assert!(
        moments(&sixteenth).is_empty(),
        "the walk came to open a folder past the depth limit: {:?}",
        moments(&sixteenth)
    );
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
fn an_entry_past_a_listing_limit_is_refused_before_its_path_is_built() {
    // The two limits that are checked while a folder is listed name the
    // folder in their refusal, with `/…` for the entry: the entry's own path
    // was never made. The longest path of the fixture is in `browser`.
    let bundle = assemble(&WEB_APP);
    let exact = exact(shape(bundle.path()));
    let mut budget = exact;
    budget.max_path_bytes -= 1;
    assert_eq!(
        checked_bundle_within(bundle.path(), budget).expect_err("one byte"),
        Refusal::OverBudget {
            limit: "path bytes",
            path: "browser/…".into()
        }
    );
    // One entry only: whichever the listing gives second is refused, in the
    // root, before anything is opened.
    let mut seen = 0;
    let budget = Budget {
        max_entries: 1,
        ..exact
    };
    assert_eq!(
        checked_bundle_within_observed(bundle.path(), budget, |_, _| seen += 1)
            .expect_err("one entry"),
        Refusal::OverBudget {
            limit: "entries",
            path: "./…".into()
        }
    );
    assert_eq!(
        seen, 0,
        "an entry was opened before the listing was refused"
    );

    // And in the source: the count and the length are checked before the
    // path is built, and the depth before the folder is opened.
    let code = library_code();
    let listing = library_item(&code, "fn list_folder(");
    let check = listing.find("tally.entry(prefix, name.to_bytes().len())?;");
    let build = listing.find("entry_path(prefix,");
    assert!(
        matches!((check, build), (Some(check), Some(build)) if check < build),
        "{listing}"
    );
    let walk = library_item(&code, "fn collect_entries(");
    let depth = walk.find("tally.folder(&path)?;");
    let open = walk.find("open_checked(folder.handle.as_fd()");
    assert!(
        matches!((depth, open), (Some(depth), Some(open)) if depth < open),
        "{walk}"
    );
    assert_eq!(code.matches("tally.folder(").count(), 1);
    assert_eq!(code.matches("tally.entry(").count(), 1);
}

/// The count and the length are judged from the name's bytes before the
/// entry's path is built, and building the path is where a name that is not
/// UTF-8 is found out. So a name with both faults is refused for its length.
/// Linux only: the file system of a Mac does not let such a name be made.
#[cfg(target_os = "linux")]
#[test]
fn a_name_too_long_and_not_utf8_is_refused_for_its_length_first() {
    use std::os::unix::ffi::OsStrExt;
    let bundle = assemble(&WEB_APP);
    let fits = exact(shape(bundle.path()));
    let name = std::ffi::OsStr::from_bytes(&[0xff; 64]);
    assert!(
        fits.max_path_bytes < 64,
        "the fixture's longest path is shorter"
    );
    fs::write(bundle.path().join(name), b"x").expect("a name that is not UTF-8");
    let one_more = Budget {
        max_entries: fits.max_entries + 1,
        max_total_bytes: fits.max_total_bytes + 1,
        ..fits
    };
    assert_eq!(
        checked_bundle_within(bundle.path(), one_more).expect_err("too long"),
        Refusal::OverBudget {
            limit: "path bytes",
            path: "./…".into()
        }
    );
    // With room for the path, the same bundle is refused for the name.
    let roomy = Budget {
        max_path_bytes: 1_024,
        ..one_more
    };
    assert!(matches!(
        checked_bundle_within(bundle.path(), roomy),
        Err(Refusal::NonUtf8Name { .. })
    ));
}

#[test]
fn the_lab_build_holds_the_lab_refusals_and_says_so() {
    // The lab turns the crate's `lab` feature on; a production crate asserts
    // the opposite at compile time.
    assert!(std::hint::black_box(capsule_identity::LAB_REFUSALS));
}
