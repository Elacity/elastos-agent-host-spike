//! Seatbelt text for Runtime-owned provider grants. The launcher binds paths with -D.

use super::rights::AdmittedRights;
use super::rights_table::RuntimeProviderId;

const HEAD: &[&str] = &["(version 1)", "(deny default)", "(deny network*)"];

/// Runtime-owned model launch inputs. Each numbered socket is a bound literal;
/// the later caller supplies the canonical paths before starting the child.
fn model_inputs() -> Vec<String> {
    let mut forms = vec![
        // macOS probe X2: the provider forks its guard and the guard forks the engine.
        "(allow process-fork)".into(),
        // macOS probe X4: the model and engine remain bound to verified artifacts.
        r#"(allow file-read* (literal (param "MODEL")))"#.into(),
        r#"(allow file-read* (literal "/dev/urandom"))"#.into(),
        r#"(allow file-read* file-write-data (literal "/dev/null"))"#.into(),
        r#"(allow process-exec (literal (param "ENGINE")))"#.into(),
        r#"(allow file-read* (subpath (param "ENGINE_BUNDLE")))"#.into(),
        // macOS probe X3: only the 64 reserved broker and engine paths.
    ];
    // macOS probe X1: 19 measured canonical ancestors, each a bound literal.
    for index in 0..19 {
        forms.push(format!(
            "(allow file-read-metadata (literal (param \"MODEL_ANCESTOR_{index}\")))"
        ));
    }
    for slot in 0..64 {
        forms.push(format!(
            "(allow network-outbound (literal (param \"BROKER_SOCKET_{slot}\")))"
        ));
        forms.push(format!(
            "(allow file-read-metadata (literal (param \"ENGINE_SOCKET_{slot}\")))"
        ));
        forms.push(format!(
            "(allow file-write* (literal (param \"ENGINE_SOCKET_{slot}\")))"
        ));
        forms.push(format!(
            "(allow network-bind (literal (param \"ENGINE_SOCKET_{slot}\")))"
        ));
    }
    // macOS probe X2: the guard signals only its engine child.
    forms.push("(allow signal (target children))".into());
    forms
}

/// Render `rows` and the macOS process-start baseline in profile order.
#[allow(dead_code)] // The macOS arm renders this profile and then refuses.
pub(super) fn render_macos_profile(
    provider: RuntimeProviderId,
    admitted: &AdmittedRights,
) -> String {
    let mut forms: Vec<String> = HEAD.iter().map(|form| (*form).into()).collect();
    // The executable rule precedes the baseline; storage follows it in all three oracles.
    for row in admitted
        .rows()
        .iter()
        .filter(|row| row.id == "bound-executable")
    {
        forms.extend(row.rules.iter().map(|form| (*form).into()));
    }
    forms.push(
        match provider {
            RuntimeProviderId::Model => "(allow file-read-data (literal \"/\"))",
            RuntimeProviderId::Did | RuntimeProviderId::Wallet => {
                "(allow file-read* (literal \"/\"))"
            }
        }
        .into(),
    );
    forms.push("(allow sysctl-read)".into());
    for row in admitted
        .rows()
        .iter()
        .filter(|row| row.id != "bound-executable")
    {
        forms.extend(row.rules.iter().map(|form| (*form).into()));
    }
    if matches!(provider, RuntimeProviderId::Model) {
        forms.extend(model_inputs());
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
                if name == "model-provider" && argument.starts_with('"') {
                    continue;
                }
                let parameter = argument
                    .strip_prefix("(param \"")
                    .and_then(|value| value.strip_suffix("\")"));
                assert!(parameter.is_some(), "{name} path argument: {argument}");
                parameters.insert(parameter.unwrap());
            }
            let expected = BTreeSet::from(["PROVIDER_EXECUTABLE", "STORAGE_PARENT", "STORAGE_ROOT"]);
            if name == "model-provider" {
                assert!(expected.is_subset(&parameters), "{name} path parameters");
            } else {
                assert_eq!(parameters, expected, "{name} path parameters");
            }
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

    #[test]
    fn model_gpu_right_is_separate_and_narrow() {
        let row = super::super::rights_table::RIGHTS
            .iter()
            .find(|row| row.id == "model-gpu")
            .unwrap();
        assert_eq!(
            row.rules,
            [
                r#"(allow file-read* (subpath "/usr/lib") (subpath "/System"))"#,
                r#"(allow iokit-open-user-client (iokit-user-client-class "AGXDeviceUserClient") (iokit-user-client-class "IOSurfaceRootUserClient"))"#,
                r#"(allow mach-lookup (global-name "com.apple.MTLCompilerService"))"#,
            ]
        );
        for provider in [RuntimeProviderId::Did, RuntimeProviderId::Wallet] {
            assert!(!provider.rights().contains(&"model-gpu"));
            let rendered =
                render_macos_profile(provider, &super::super::rights::admit_committed(provider));
            assert!(!rendered.contains("iokit-open-user-client"));
            assert!(!rendered.contains("MTLCompilerService"));
        }
        assert_eq!(
            RuntimeProviderId::Model
                .rights()
                .iter()
                .filter(|id| **id == "model-gpu")
                .count(),
            1
        );
    }

    #[rustfmt::skip]
    #[test]
    fn macos_reference_files_match_pin_d0dd5693() {
        // Head stays exact in rendered_profiles_match_committed_oracles. Only the tail is a sorted multiset.
        for path in ["capsules/did-provider/confine.sb", "capsules/wallet-provider/confine.sb", "capsules/did-provider/tests/fixtures/confine/declared-rights.json", "capsules/wallet-provider/tests/fixtures/confine/declared-rights.json"] {
            let disk = std::fs::read(format!("{}/../../../{path}", env!("CARGO_MANIFEST_DIR"))).unwrap_or_else(|err| panic!("{path}: {err}"));
            let spec = format!("d0dd5693:{path}");
            let out = super::super::rights::git_show(&spec);
            assert!(out.status.success(), "pin {spec} missing: {}", String::from_utf8_lossy(&out.stderr));
            assert_eq!(disk, out.stdout, "moved reference at pin {spec}");
        }
    }
}
