//! Seatbelt text for Runtime-owned provider grants. The launcher binds paths with -D.

use super::rights_table::{for_provider, RuntimeProviderId};

const HEAD: &[&str] = &["(version 1)", "(deny default)", "(deny network*)"];

/// Render the approved rights and the macOS process-start baseline in profile order.
#[allow(dead_code)] // The spawn caller is added in a later slice.
pub(super) fn render_macos_profile(provider: RuntimeProviderId) -> String {
    let grants = for_provider(provider);
    let mut forms = HEAD.to_vec();
    // The executable rule precedes the baseline; storage follows it in all three oracles.
    for row in grants.iter().filter(|row| row.id == "bound-executable") {
        forms.extend_from_slice(row.rules);
    }
    forms.push(match provider {
        RuntimeProviderId::Model => "(allow file-read-data (literal \"/\"))",
        RuntimeProviderId::Did | RuntimeProviderId::Wallet => "(allow file-read* (literal \"/\"))",
    });
    forms.push("(allow sysctl-read)");
    for row in grants.iter().filter(|row| row.id != "bound-executable") {
        forms.extend_from_slice(row.rules);
    }
    forms.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forms(profile: &str) -> Vec<&str> {
        profile
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with(';'))
            .collect()
    }

    fn same_rules(actual: &[&str], expected: &[&str]) -> bool {
        actual == expected
    }

    #[test]
    fn rendered_profiles_match_committed_oracles() {
        for (name, provider, oracle) in [
            (
                "did-provider",
                RuntimeProviderId::Did,
                include_str!("../../../../../capsules/did-provider/confine.sb"),
            ),
            (
                "wallet-provider",
                RuntimeProviderId::Wallet,
                include_str!("../../../../../capsules/wallet-provider/confine.sb"),
            ),
            (
                "model-provider",
                RuntimeProviderId::Model,
                include_str!("../../../../../capsules/model-provider/confine.sb"),
            ),
        ] {
            let rendered = render_macos_profile(provider);
            let actual = forms(&rendered);
            let expected = forms(oracle);
            assert_eq!(
                &actual[..3],
                ["(version 1)", "(deny default)", "(deny network*)"],
                "{name} profile head"
            );
            // The lab compares sorted forms after the head; comments are presentation.
            let mut actual_sorted = actual[HEAD.len()..].to_vec();
            let mut expected_sorted = expected[HEAD.len()..].to_vec();
            actual_sorted.sort();
            expected_sorted.sort();
            assert_eq!(actual_sorted, expected_sorted, "{name} complete rule text");
            assert_eq!(same_rules(&actual, &expected), true, "{name} rule order");
            let changed = rendered.replace("STORAGE_PARENT", "STORAGE_ROOT");
            assert_eq!(
                same_rules(&forms(&changed), &expected),
                false,
                "{name} changed rule text must differ"
            );
            let mut reordered = actual.clone();
            reordered.swap(3, 4);
            assert_eq!(
                same_rules(&reordered, &expected),
                false,
                "{name} changed rule order must differ"
            );
            assert!(!rendered.contains("/private/"), "{name} path binding");
        }
    }
}
