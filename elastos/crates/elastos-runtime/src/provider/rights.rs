//! Runtime-owned rule text for each approved provider right.
//!
//! A provider manifest names a right by id, and `CapsuleManifest::validate`
//! caps that id to the approved list. The list caps names, not authority: a
//! manifest that names `storage` could still declare
//! `(allow file-read* file-write* (subpath "/"))` and pass validation. This
//! module holds the Runtime's own template for each approved id, so the rule
//! text has exactly one owner. `check_rights_against_runtime_templates` is the
//! spawn gate: every right's rules must equal the template for its id.
//!
//! The templates are byte-for-byte the rules in the committed provider
//! manifests. Comparison normalises whitespace only; rule order and rule count
//! stay meaningful, and template text carries no `;` comments, so a declared
//! rule with a comment is refused.

// The spawn gate (`check_rights_against_runtime_templates`) gets its caller in
// Y50b; until then its only users are this module's tests. Remove this allow
// with the wiring.
#![allow(dead_code)]

use elastos_common::ProviderAuthority;

/// The Runtime's rules for `storage`, in order: the parent read rule, then the
/// read/write subpath rule.
const STORAGE_RULES: &[&str] = &[
    r#"(allow file-read* (literal (param "STORAGE_PARENT")))"#,
    r#"(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))"#,
];

/// The Runtime's rules for `bound-executable`: the provider binary only.
const BOUND_EXECUTABLE_RULES: &[&str] =
    &[r#"(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))"#];

/// The Runtime's approved rule text for one right id.
pub(crate) fn approved_right_template(id: &str) -> Option<&'static [&'static str]> {
    match id {
        "storage" => Some(STORAGE_RULES),
        "bound-executable" => Some(BOUND_EXECUTABLE_RULES),
        _ => None,
    }
}

/// Normalise a rule to its comparison form: whitespace runs collapse to one
/// space, trimmed at both ends. `;` is ordinary text here, and no template
/// carries a comment, so a commented rule never matches its template.
fn normalised(rule: &str) -> Vec<String> {
    rule.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .split(' ')
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect()
}

fn rules_match(declared: &[String], template: &[&str]) -> bool {
    declared.len() == template.len()
        && declared
            .iter()
            .zip(template)
            .all(|(rule, approved)| normalised(rule) == normalised(approved))
}

/// Refuse any provider right whose rules differ from the Runtime template.
///
/// This is the spawn gate for provider confinement rights. It checks every
/// right before anything starts, so a refusal leaves no provider state behind.
pub(crate) fn check_rights_against_runtime_templates(
    authority: &ProviderAuthority,
) -> Result<(), String> {
    for right in &authority.rights {
        let Some(template) = approved_right_template(&right.id) else {
            return Err(format!(
                "provider authority right \"{}\" is not an approved right id",
                right.id
            ));
        };
        if !rules_match(&right.rules, template) {
            return Err(format!(
                "provider right \"{}\" rule text differs from the Runtime template",
                right.id
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use elastos_common::CapsuleManifest;

    fn committed_authority(name: &str) -> ProviderAuthority {
        let path = format!(
            "{}/../../../capsules/{name}-provider/capsule.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let json = std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{path}: {err}"));
        let manifest: CapsuleManifest =
            serde_json::from_str(&json).unwrap_or_else(|err| panic!("{path}: {err}"));
        manifest
            .authority
            .unwrap_or_else(|| panic!("{path}: provider authority is missing"))
    }

    fn did_authority() -> ProviderAuthority {
        committed_authority("did")
    }

    fn storage_rules(authority: &ProviderAuthority) -> Vec<String> {
        authority
            .rights
            .iter()
            .find(|right| right.id == "storage")
            .unwrap()
            .rules
            .clone()
    }

    fn rules_mut<'a>(authority: &'a mut ProviderAuthority, id: &str) -> &'a mut Vec<String> {
        authority
            .rights
            .iter_mut()
            .find(|right| right.id == id)
            .map(|right| &mut right.rules)
            .unwrap_or_else(|| panic!("provider right \"{id}\" is missing"))
    }

    #[test]
    fn committed_provider_manifests_match_runtime_templates() {
        for name in ["did", "wallet", "model"] {
            let authority = committed_authority(name);
            check_rights_against_runtime_templates(&authority)
                .unwrap_or_else(|err| panic!("{name}-provider: {err}"));
        }
    }

    #[test]
    fn widened_storage_rule_is_refused() {
        let mut authority = did_authority();
        let template = approved_right_template("storage").unwrap();
        let mut rules = vec![r#"(allow file-read* file-write* (subpath "/"))"#.to_string()];
        rules.push(template[1].to_string());
        *rules_mut(&mut authority, "storage") = rules;
        assert_eq!(
            check_rights_against_runtime_templates(&authority),
            Err(
                "provider right \"storage\" rule text differs from the Runtime template"
                    .to_string()
            )
        );
    }

    #[test]
    fn swapped_storage_rules_are_refused() {
        let mut authority = did_authority();
        let mut rules = storage_rules(&authority);
        rules.swap(0, 1);
        *rules_mut(&mut authority, "storage") = rules;
        assert_eq!(
            check_rights_against_runtime_templates(&authority),
            Err(
                "provider right \"storage\" rule text differs from the Runtime template"
                    .to_string()
            )
        );
    }

    #[test]
    fn whitespace_still_matches() {
        let mut authority = did_authority();
        let template = approved_right_template("storage").unwrap();
        *rules_mut(&mut authority, "storage") = vec![
            "  (allow\n file-read*    (literal   (param \"STORAGE_PARENT\")))".to_string(),
            "(allow file-read* file-write*\n (subpath (param \"STORAGE_ROOT\")))\t".to_string(),
        ];
        assert_eq!(template.len(), 2);
        check_rights_against_runtime_templates(&authority).unwrap();
    }

    #[test]
    fn semicolon_smuggled_rule_is_refused() {
        let mut authority = did_authority();
        let smuggled = "  (allow process-exec (literal (param \"PROVIDER_EXECUTABLE\"))) ;x\n\
                        (allow process-exec (subpath \"/\"))";
        *rules_mut(&mut authority, "bound-executable") = vec![smuggled.to_string()];
        assert_eq!(
            check_rights_against_runtime_templates(&authority),
            Err(
                "provider right \"bound-executable\" rule text differs from the Runtime template"
                    .to_string()
            )
        );
    }

    #[test]
    fn widened_bound_executable_rule_is_refused() {
        let mut authority = did_authority();
        *rules_mut(&mut authority, "bound-executable") =
            vec![r#"(allow process-exec (subpath "/"))"#.to_string()];
        assert_eq!(
            check_rights_against_runtime_templates(&authority),
            Err(
                "provider right \"bound-executable\" rule text differs from the Runtime template"
                    .to_string()
            )
        );
    }

    #[test]
    fn unknown_right_id_is_refused() {
        let mut value = serde_json::json!({"reason": "unknown right", "capabilities": [], "audit_events": [], "rights": []});
        value["rights"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"id": "network", "rules": ["(allow network*)"]}));
        let authority: ProviderAuthority = serde_json::from_value(value).unwrap();
        assert_eq!(
            check_rights_against_runtime_templates(&authority),
            Err("provider authority right \"network\" is not an approved right id".to_string())
        );
    }
}
