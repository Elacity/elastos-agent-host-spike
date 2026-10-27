//! The falsifier list is the lane's evidence, and two places say what it
//! holds: its own `about` text names the tasks that added entries, and
//! README's "Falsifiers" says how many planted bugs it holds (P12). Both are
//! checked against the list itself, so neither drifts when a task adds
//! entries. One form of each is read; anything else is refused.
mod common;

use common::*;

/// A README "Falsifiers" section that says the list holds `count`.
fn section_holding(count: usize) -> String {
    format!("\n`falsifiers.json` holds {count}\nplanted bugs in the provider format.\n")
}

/// The synthetic list most cases change one part of: tasks 001, 005 and 027,
/// each named in `about`, and a README count of 4.
const ABOUT: &str = "lab falsifiers (tasks 001, 005 and 027). Each one plants a bug.";
const IDS: [&str; 4] = ["F-CI1a", "F-CI5a", "F-CI5b", "F-CI27d"];

#[test]
fn the_falsifier_inventory_matches_the_list() {
    let (about, ids) = falsifier_list();
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    let section = readme_falsifiers_section().unwrap_or_else(|reason| panic!("{reason}"));
    assert_eq!(
        falsifier_inventory_findings(&about, &ids, section),
        Ok(Vec::new()),
        "falsifiers.json's about text or README's count does not match the list"
    );
}

/// Each mismatch is found on its own, with its own message: a task with
/// entries that `about` leaves out, a task `about` names with no entry, a
/// README count that is not the list's length, and `about`'s tasks out of the
/// list's order. The synthetic list with nothing changed gives no mismatch.
#[test]
fn the_falsifier_inventory_finds_each_mismatch() {
    let findings = |about: &str, ids: &[&str], count: usize| {
        falsifier_inventory_findings(about, ids, &section_holding(count))
    };
    assert_eq!(
        findings(ABOUT, &IDS, 4),
        Ok(Vec::new()),
        "the unchanged list"
    );

    let without_027 = ABOUT.replace("001, 005 and 027", "001 and 005");
    assert_eq!(
        findings(&without_027, &IDS, 4),
        Ok(vec![
            "task 027 has falsifiers but `about` does not name it".to_owned()
        ]),
        "(a) a task with entries that about does not name"
    );

    let with_024 = ABOUT.replace("005 and 027", "005, 024 and 027");
    assert_eq!(
        findings(&with_024, &IDS, 4),
        Ok(vec![
            "`about` names task 024, which has no falsifier".to_owned()
        ]),
        "(b) a task about names with no entry"
    );

    assert_eq!(
        findings(ABOUT, &IDS, 3),
        Ok(vec![
            "README says 3 planted bugs; the list holds 4".to_owned()
        ]),
        "(c) README's count differs from the number of ids"
    );

    let out_of_order = ABOUT.replace("001, 005 and 027", "001, 027 and 005");
    assert_eq!(
        findings(&out_of_order, &IDS, 4),
        Ok(vec![
            "`about` names the tasks in the order 001, 027, 005; the list holds them in the order 001, 005, 027"
                .to_owned()
        ]),
        "(d) about names the tasks out of the list's order"
    );
}

/// What the check cannot read is refused, each with its own reason, and is
/// never read as no mismatch: `about` with no "(tasks ...)" list, with two,
/// or with one never closed; an item that is not three digits; a task named
/// twice; an id not of
/// the form `F-CI<n><letters>`; and a README section with no "holds N planted
/// bugs" sentence, or with two.
#[test]
fn the_falsifier_inventory_refuses_what_it_cannot_read() {
    let refused = |about: &str, ids: &[&str], section: &str| {
        falsifier_inventory_findings(about, ids, section)
            .expect_err("an inventory the check cannot read must be refused")
    };
    let section = section_holding(4);

    assert_eq!(
        refused("lab falsifiers. Each one plants a bug.", &IDS, &section),
        "`about` holds no \"(tasks ...)\" list",
        "no (tasks ...) list"
    );
    assert_eq!(
        refused(&format!("{ABOUT} (tasks 001)"), &IDS, &section),
        "`about` holds 2 \"(tasks ...)\" lists, not one",
        "two (tasks ...) lists"
    );
    assert_eq!(
        refused("lab falsifiers (tasks 001, 005 and 027.", &IDS, &section),
        "`about`'s \"(tasks ...)\" list is never closed",
        "a list never closed"
    );
    for (item, about) in [
        ("27", ABOUT.replace("027", "27")),
        ("0027", ABOUT.replace("027", "0027")),
        ("task 005", ABOUT.replace("005", "task 005")),
        ("005,027", ABOUT.replace("005 and 027", "005,027")),
    ] {
        assert_eq!(
            refused(&about, &IDS, &section),
            format!("`about`'s task {item:?} is not three digits"),
            "an item that is not three digits: {about}"
        );
    }
    for id in [
        "F-CI",
        "F-CIa",
        "F-CI27",
        "F-CI027d",
        "F-CI1000a",
        "F-CI27D",
        "F-CI27d1",
        "F-X27d",
        "f-ci27d",
    ] {
        let ids = [IDS[0], IDS[1], IDS[2], id];
        assert_eq!(
            refused(ABOUT, &ids, &section),
            format!("the id {id:?} is not F-CI<n><letters>"),
            "an id not of the form F-CI<n><letters>"
        );
    }
    for section in [
        "\nThe list holds many planted bugs.\n".to_owned(),
        "\nIt holds 4 bugs.\n".to_owned(),
        "\nIt holds +4 planted bugs.\n".to_owned(),
        String::new(),
    ] {
        assert_eq!(
            refused(ABOUT, &IDS, &section),
            "README's \"Falsifiers\" has no \"holds N planted bugs\" sentence",
            "no holds N planted bugs sentence: {section:?}"
        );
    }
    assert_eq!(
        refused(ABOUT, &IDS, &format!("{section}{section}")),
        "README's \"Falsifiers\" says \"holds N planted bugs\" 2 times, not once",
        "two holds N planted bugs sentences"
    );
    assert_eq!(
        refused(
            &ABOUT.replace("001, 005 and 027", "001, 005, 005 and 027"),
            &IDS,
            &section
        ),
        "`about` names task 005 more than once",
        "a task named twice"
    );
}
