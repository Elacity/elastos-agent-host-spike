//! The BLOCKED grades are current. Every gap's evidence still holds in this
//! checkout, every acceptance row names exactly the capabilities its check
//! still needs, and SPEC.md states the same tables as the code.

use resident_instances::capability::{ids, read_pin, Capability, Check, Reading};
use resident_instances::{acceptance, repo_root, Grade};

#[test]
fn blocker_evidence_still_holds() {
    let repo = repo_root();
    let mut moved = Vec::new();
    for capability in Capability::ALL {
        for pin in capability.gap().unwrap_or_default() {
            match read_pin(pin, &repo) {
                Ok(Reading { holds: true, line }) => println!(
                    "{} gap holds: {}{}: {}",
                    capability.id(),
                    pin.path,
                    line.map(|l| format!(":{l}")).unwrap_or_default(),
                    pin.meaning
                ),
                Ok(Reading { holds: false, .. }) => moved.push(format!(
                    "{} evidence moved: {} no longer shows that {}; re-measure {} against a live operator, then update capability.rs and SPEC.md",
                    capability.id(),
                    pin.path,
                    pin.meaning,
                    capability.id()
                )),
                Err(reason) => moved.push(format!("{}: {reason}", capability.id())),
            }
        }
    }
    assert!(moved.is_empty(), "{}", moved.join("\n"));
}

#[test]
fn every_check_reports_blocked_with_its_missing_capabilities() {
    for check in Check::ALL {
        let grade = acceptance(check);
        let Grade::Blocked(text) = &grade else {
            panic!(
                "{} graded {} today: {}",
                check.id(),
                grade.label(),
                grade.detail()
            );
        };
        let head = format!("missing Runtime capabilities {}", ids(&check.blocked()));
        assert!(text.starts_with(&head), "{text}");
        for capability in check.blocked() {
            let title = format!("{} {}", capability.id(), capability.title());
            assert!(text.contains(&title), "{text}");
        }
        assert!(
            !text.contains("[MOVED") && !text.contains("[UNREADABLE"),
            "{text}"
        );
        assert_eq!(
            check.blocked(),
            check.needs(),
            "no capability is measured yet"
        );
    }
}

#[test]
fn acceptance_rows_name_exact_blockers() {
    let source = include_str!("acceptance.rs");
    assert_eq!(
        source.matches("fn acceptance_").count(),
        Check::ALL.len(),
        "one row per check"
    );
    for check in Check::ALL {
        let signature = format!("fn {}()", check.test_name());
        assert_eq!(source.matches(&signature).count(), 1, "{signature}");
        let at = source.find(&signature).unwrap();
        let above = source[..at].trim_end().lines().last().unwrap().trim();
        let blocked = check.blocked();
        let expected = if blocked.is_empty() {
            "#[test]".to_owned()
        } else {
            format!("#[ignore = \"blocked: {}\"]", ids(&blocked))
        };
        assert_eq!(above, expected, "{}", check.test_name());
    }
}

#[test]
fn spec_states_the_same_capabilities_and_checks() {
    let spec = include_str!("../SPEC.md");
    for capability in Capability::ALL {
        let needed_by: Vec<&str> = Check::ALL
            .iter()
            .filter(|check| check.needs().contains(&capability))
            .map(|check| check.id())
            .collect();
        let row = format!(
            "| {} | {} | {} |",
            capability.id(),
            capability.title(),
            needed_by.join(", ")
        );
        assert_eq!(spec.matches(&row).count(), 1, "SPEC.md needs the row {row}");
    }
    for check in Check::ALL {
        let needs: Vec<&str> = check.needs().iter().map(|c| c.id()).collect();
        let row = format!(
            "| {} | `{}` | {} |",
            check.id(),
            check.test_name(),
            needs.join(", ")
        );
        assert_eq!(spec.matches(&row).count(), 1, "SPEC.md needs the row {row}");
    }
}
