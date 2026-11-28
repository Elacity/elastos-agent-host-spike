//! The BLOCKED table: one row per A5 binding check, graded only by
//! `acceptance`, then the evidence for every missing ask.
//!
//! This binary prints a SPEC table. It is not the A5 acceptance gate.
//! Exit 0: no row failed or was skipped; BLOCKED rows stay open in SPEC.md.
//! Exit 1: a row failed. Exit 4: a row was skipped and none failed.

use a5_binding_harness::capability::{describe, ids, Capability, Check};
use a5_binding_harness::{acceptance, counts_as_accepted, repo_root, Grade};

fn main() {
    let mut counts = [0usize; 4];
    let mut evidence = Vec::new();
    println!("check | test | grade");
    for check in Check::ALL {
        let grade = acceptance(check);
        if counts_as_accepted(&grade) && !matches!(grade, Grade::Pass(_)) {
            panic!("{} counted as accepted without PASS", check.id());
        }
        let shown = match &grade {
            Grade::Pass(_) => "PASS".to_owned(),
            Grade::Fail(_) => "FAIL".to_owned(),
            Grade::Blocked(_) => format!("BLOCKED ({})", ids(&check.blocked())),
            Grade::Skipped(reason) => format!("SKIPPED ({reason})"),
        };
        println!("{} | {} | {shown}", check.id(), check.test_name());
        let slot = match grade {
            Grade::Pass(_) => 0,
            Grade::Fail(_) => 1,
            Grade::Blocked(_) => 2,
            Grade::Skipped(_) => 3,
        };
        counts[slot] += 1;
        if matches!(grade, Grade::Pass(_) | Grade::Fail(_)) {
            evidence.push(format!(
                "{} {}: {}",
                check.id(),
                grade.label(),
                grade.detail()
            ));
        }
    }
    let missing: Vec<Capability> = Capability::ALL
        .into_iter()
        .filter(|c| Check::ALL.iter().any(|check| check.blocked().contains(c)))
        .collect();
    if !missing.is_empty() {
        println!("\n{}", describe(&missing, &repo_root()));
    }
    for line in evidence {
        println!("\n{line}");
    }
    let [pass, fail, blocked, skipped] = counts;
    println!(
        "\nA5 binding: accepted {pass} of {}; failed {fail}; blocked {blocked}; skipped {skipped}",
        Check::ALL.len()
    );
    let code = if fail > 0 {
        1
    } else if skipped > 0 {
        4
    } else {
        0
    };
    std::process::exit(code);
}
