//! Seatbelt text for Runtime-owned provider grants. The launcher binds paths with -D.

use super::rights::AdmittedRights;
use super::rights_table::RuntimeProviderId;

#[cfg_attr(not(target_os = "macos"), allow(dead_code))] // Rendered only by the macOS start arm.
const HEAD: &[&str] = &["(version 1)", "(deny default)", "(deny network*)"];

/// Render `rows` and the macOS process-start baseline in profile order.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))] // Only the macOS start arm calls this outside tests.
pub(super) fn render_macos_profile(
    provider: RuntimeProviderId,
    admitted: &AdmittedRights,
) -> String {
    let mut forms = HEAD.to_vec();
    // The executable rule precedes the baseline; storage follows it in all three oracles.
    for row in admitted
        .rows()
        .iter()
        .filter(|row| row.id == "bound-executable")
    {
        forms.extend_from_slice(row.rules);
    }
    forms.push(match provider {
        RuntimeProviderId::Model => "(allow file-read-data (literal \"/\"))",
        RuntimeProviderId::Did | RuntimeProviderId::Wallet => "(allow file-read* (literal \"/\"))",
    });
    forms.push("(allow sysctl-read)");
    for row in admitted
        .rows()
        .iter()
        .filter(|row| row.id != "bound-executable")
    {
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

    #[rustfmt::skip]
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
            let rendered = render_macos_profile(
                provider,
                &super::super::rights::admit_committed(provider),
            );
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

    #[rustfmt::skip]
    #[test]
    fn macos_reference_files_match_pin_d0dd5693() {
        // Head stays exact in rendered_profiles_match_committed_oracles. Only the tail is a sorted multiset.
        for path in ["capsules/did-provider/confine.sb", "capsules/wallet-provider/confine.sb", "capsules/model-provider/confine.sb", "capsules/did-provider/tests/fixtures/confine/declared-rights.json", "capsules/wallet-provider/tests/fixtures/confine/declared-rights.json", "capsules/model-provider/tests/fixtures/confine/declared-rights.json", "capsules/wallet-provider/tests/common/profile_generator.rs"] {
            let disk = std::fs::read(format!("{}/../../../{path}", env!("CARGO_MANIFEST_DIR"))).unwrap_or_else(|err| panic!("{path}: {err}"));
            let spec = format!("d0dd5693:{path}");
            let out = super::super::rights::git_show(&spec);
            assert!(out.status.success(), "pin {spec} missing: {}", String::from_utf8_lossy(&out.stderr));
            assert_eq!(disk, out.stdout, "moved reference at pin {spec}");
        }
    }
}
