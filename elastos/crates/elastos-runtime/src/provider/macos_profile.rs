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
    use std::collections::BTreeSet;

    fn forms(profile: &str) -> Vec<&str> {
        profile
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with(';'))
            .collect()
    }

    fn path_arguments(profile: &str) -> Vec<&str> {
        let mut arguments = Vec::new();
        for line in profile.lines() {
            for (index, _) in line
                .match_indices("(literal ")
                .chain(line.match_indices("(subpath "))
            {
                let argument = line[index..].split_once(' ').unwrap().1;
                let end = if argument.starts_with("(param ") {
                    argument.find("))").unwrap() + 1
                } else {
                    argument.find(')').unwrap()
                };
                arguments.push(&argument[..end]);
            }
        }
        arguments
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
            let mut parameters = BTreeSet::new();
            for argument in path_arguments(&rendered) {
                if argument == "\"/\"" {
                    continue;
                }
                let parameter = argument
                    .strip_prefix("(param \"")
                    .and_then(|value| value.strip_suffix("\")"));
                assert!(
                    parameter.is_some(),
                    "{name} path argument: actual {argument}, expected a param or root literal"
                );
                parameters.insert(parameter.unwrap());
            }
            assert_eq!(
                parameters,
                BTreeSet::from(["PROVIDER_EXECUTABLE", "STORAGE_PARENT", "STORAGE_ROOT"]),
                "{name} path parameters"
            );
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
            assert_eq!(actual, expected, "{name} rule order");
        }
    }
}
