//! Seatbelt text for Runtime-owned provider grants. The launcher binds paths with -D.

use super::rights::AdmittedRights;
use super::rights_table::RuntimeProviderId;

const HEAD: &[&str] = &["(version 1)", "(deny default)", "(deny network*)"];

/// Runtime-owned model launch inputs. Each numbered socket is a bound literal;
/// the later caller supplies the canonical paths before starting the child.
fn model_inputs() -> Vec<String> {
    // Lab-only X1 layout: 19 ancestors and 64 reserved socket slots. The
    // installer must derive these bounds from its verified launch inputs.
    // X2 is process-fork; proposal rows 2, 4 and 5 cover the fixed inputs.
    let fixed = [
        "(allow process-fork)",
        r#"(allow file-read* (literal (param "MODEL")))"#,
        r#"(allow file-read* (literal "/dev/urandom"))"#,
        r#"(allow file-read* file-write-data (literal "/dev/null"))"#,
        r#"(allow process-exec (literal (param "ENGINE")))"#,
        r#"(allow file-read* (subpath (param "ENGINE_BUNDLE")))"#,
        r#"(allow file-read* (subpath "/usr/lib"))"#,
    ];
    let mut forms: Vec<String> = fixed.into_iter().map(str::to_string).collect();
    // macOS probe X1: 19 measured canonical ancestors, each a bound literal.
    for index in 0..19 {
        forms.push(format!(
            "(allow file-read-metadata (literal (param \"MODEL_ANCESTOR_{index}\")))"
        ));
    }
    // Probe X3 is network-bind; proposal rows 6 and 7 cover the other paths.
    for slot in 0..64 {
        for (op, param) in [
            ("network-outbound", "BROKER_SOCKET"),
            ("file-read-metadata", "ENGINE_SOCKET"),
            ("file-write*", "ENGINE_SOCKET"),
            ("network-bind", "ENGINE_SOCKET"),
        ] {
            forms.push(format!("(allow {op} (literal (param \"{param}_{slot}\")))"));
        }
    }
    // Proposal row 5: the guard signals only its engine child.
    forms.push("(allow signal (target children))".to_string());
    forms
}

/// Render `rows` and the macOS process-start baseline in profile order.
#[allow(dead_code)] // The macOS arm renders this profile and then refuses.
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
    let mut rendered = forms.join("\n");
    if matches!(provider, RuntimeProviderId::Model) {
        rendered.push('\n');
        rendered.push_str(&model_inputs().join("\n"));
    }
    rendered.push('\n');
    rendered
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
                .chain(line.match_indices("(regex "))
            {
                let argument = line[index..].split_once(' ').unwrap().1;
                let end = if argument.starts_with("(param ") {
                    argument.find("))").unwrap() + 1
                } else {
                    argument[1..].find('"').unwrap() + 2
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
            let mut literals = BTreeSet::new();
            for argument in path_arguments(&rendered) {
                if argument == "\"/\"" {
                    continue;
                }
                if let Some(parameter) = argument
                    .strip_prefix("(param \"")
                    .and_then(|value| value.strip_suffix("\")"))
                {
                    parameters.insert(parameter);
                    continue;
                }
                let literal = argument
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'));
                assert!(
                    literal.is_some(),
                    "{name} path argument: actual {argument}, expected a param or root literal"
                );
                literals.insert(literal.unwrap());
            }
            let shared = BTreeSet::from(["PROVIDER_EXECUTABLE", "STORAGE_PARENT", "STORAGE_ROOT"]);
            if name == "model-provider" {
                let mut expected = shared.iter().copied().map(str::to_string).collect::<BTreeSet<_>>();
                expected.extend(["MODEL", "ENGINE", "ENGINE_BUNDLE"].map(str::to_string));
                for index in 0..19 {
                    expected.insert(format!("MODEL_ANCESTOR_{index}"));
                }
                for slot in 0..64 {
                    expected.insert(format!("BROKER_SOCKET_{slot}"));
                    expected.insert(format!("ENGINE_SOCKET_{slot}"));
                }
                assert_eq!(
                    parameters.iter().copied().map(str::to_string).collect::<BTreeSet<_>>(),
                    expected,
                    "{name} path parameters"
                );
                // The fixed paths and one GPU family regex. Another path fails this equality.
                assert_eq!(
                    literals,
                    BTreeSet::from(["/dev/null", "/dev/urandom", "/usr/lib", r"^/System/Library/Extensions/AGXMetal[A-Za-z0-9]+\.bundle(/.*)?$"]),
                    "{name} fixed paths"
                );
            } else {
                assert_eq!(parameters, shared, "{name} path parameters");
                assert!(literals.is_empty(), "{name} fixed paths: {literals:?}");
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
                r#"(allow file-read* (regex "^/System/Library/Extensions/AGXMetal[A-Za-z0-9]+\.bundle(/.*)?$"))"#,
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

    #[test]
    fn model_gpu_path_refuses_non_agx_system_bundles() {
        use regex_automata::meta::Regex;

        let rule = super::super::rights_table::RIGHTS
            .iter()
            .find(|row| row.id == "model-gpu")
            .unwrap()
            .rules[0];
        let pattern = rule
            .strip_prefix("(allow file-read* (regex \"")
            .and_then(|rule| rule.strip_suffix("\"))"))
            .expect("model-gpu must use one regex read rule");
        let regex = Regex::new(pattern).expect("model-gpu regex must compile");
        for path in [
            "/System/Library/Extensions/AGXMetalG17X.bundle",
            "/System/Library/Extensions/AGXMetalG13X.bundle/Contents/Info.plist",
        ] {
            assert!(regex.is_match(path), "AGXMetal bundle refused: {path}");
        }
        for path in [
            "/System/Library/Extensions/Other.bundle",
            "/System/Library/Extensions/IOGraphicsFamily.kext",
            "/System/Library/Extensions/AGXMetalG17X.bundle-extra",
            "/System/Library/Extensions/AGXMetalG17X.bundle-other/Contents",
        ] {
            assert!(!regex.is_match(path), "non-AGX path admitted: {path}");
        }
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
        // The model files grew after the pin. The pin's rules stay the prefix.
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../..");
        let sb = std::fs::read_to_string(format!("{root}/capsules/model-provider/confine.sb")).unwrap();
        let sb_out = super::super::rights::git_show("d0dd5693:capsules/model-provider/confine.sb");
        assert!(sb_out.status.success(), "pin d0dd5693 model confine.sb");
        let sb_pin = String::from_utf8(sb_out.stdout).unwrap();
        fn paren_lines(text: &str) -> Vec<&str> { text.lines().map(str::trim).filter(|line| line.starts_with('(')).collect() }
        let sb_lines = paren_lines(&sb);
        let sb_pin_lines = paren_lines(&sb_pin);
        assert_eq!(&sb_lines[..sb_pin_lines.len()], sb_pin_lines.as_slice(), "pin d0dd5693 model confine.sb rules");
        let disk: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(format!("{root}/capsules/model-provider/tests/fixtures/confine/declared-rights.json")).unwrap()).unwrap();
        let json_out = super::super::rights::git_show("d0dd5693:capsules/model-provider/tests/fixtures/confine/declared-rights.json");
        assert!(json_out.status.success(), "pin d0dd5693 model declared-rights");
        let pinned: serde_json::Value = serde_json::from_slice(&json_out.stdout).unwrap();
        assert_eq!(disk["rights"][0], pinned["rights"][0], "pin d0dd5693 model storage");
        assert_eq!(disk["rights"][1], pinned["rights"][1], "pin d0dd5693 model executable");
        assert_eq!(disk["platform_baseline"]["rules"][0], pinned["platform_baseline"]["rules"][0], "pin d0dd5693 model startup root");
        assert_eq!(disk["platform_baseline"]["rules"][1], pinned["platform_baseline"]["rules"][1], "pin d0dd5693 model sysctl");
    }
}
