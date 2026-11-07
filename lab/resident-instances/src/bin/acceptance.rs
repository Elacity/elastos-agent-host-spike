//! The acceptance table: one row per M1 check, graded only by `acceptance`,
//! then the evidence for every missing capability.
//!
//! Exit 0: no row failed or was skipped; BLOCKED rows stay open in SPEC.md.
//! Exit 1: a row failed. Exit 4: a row was skipped and none failed.

use resident_instances::capability::{describe, ids, Capability, Check};
use resident_instances::{acceptance, repo_root, Grade};

fn main() {
    let mut counts = [0usize; 4];
    let mut evidence = Vec::new();
    println!("check | test | grade");
    for check in Check::ALL {
        let grade = acceptance(check);
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
        "\nresident instances: accepted {pass} of {}; failed {fail}; blocked {blocked}; skipped {skipped}",
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
