//! Runtime-owned rule text for each approved provider right.
//!
//! A provider manifest names a right by id, and `CapsuleManifest::validate`
//! caps that id to the approved list. The list caps names, not authority: a
//! manifest that names `storage` could still declare
//! `(allow file-read* file-write* (subpath "/"))` and pass validation. This
//! module holds the Runtime's own template for each approved id, so the rule
//! text has exactly one owner.
//!
//! `check_rights_against_runtime_templates` is the spawn gate. Empty declared
//! rights resolve to the Runtime grant for that Runtime provider id. A
//! non-empty list must be that grant or a subset of it, and each declared
//! right's rules must equal the template. An id that the dictionary knows but
//! this provider's grant does not is refused. `os_entry::start_provider` is
//! the caller. The server does not call it yet.
//!
//! The templates are byte-for-byte the rules in the committed provider
//! manifests. Comparison normalises whitespace only; rule order and rule count
//! stay meaningful, and template text carries no `;` comments, so a declared
//! rule with a comment is refused.

use super::rights_table::{self, RuntimeProviderId};
use elastos_common::ProviderAuthority;

/// The Runtime's approved rule text for one right id.
pub(crate) fn approved_right_template(id: &str) -> Option<&'static [&'static str]> {
    rights_table::RIGHTS
        .iter()
        .find(|row| row.id == id)
        .map(|row| row.rules)
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

fn provider_label(provider: RuntimeProviderId) -> &'static str {
    match provider {
        RuntimeProviderId::Did => "did-provider",
        RuntimeProviderId::Wallet => "wallet-provider",
        RuntimeProviderId::Model => "model-provider",
    }
}

/// Resolve declared rights to the rows the OS entry installs.
///
/// Empty rights select `provider`'s Runtime grant from `dictionary`. Any other
/// list must be that grant or a subset, with each right's rules equal to its
/// template. The Linux plan and the macOS profile are built from the returned
/// rows. The check finishes before a process is created.
pub(super) fn check_rights_against_runtime_templates<'a>(
    provider: RuntimeProviderId,
    authority: &ProviderAuthority,
    dictionary: &'a [rights_table::RightRow],
) -> Result<Vec<&'a rights_table::RightRow>, String> {
    if authority.rights.is_empty() {
        let mut rows = Vec::with_capacity(provider.rights().len());
        for id in provider.rights() {
            let row = dictionary
                .iter()
                .find(|row| row.id == *id)
                .unwrap_or_else(|| panic!("Runtime right {id} is missing from the dictionary"));
            rows.push(row);
        }
        return Ok(rows);
    }
    let mut admitted = Vec::with_capacity(authority.rights.len());
    for (index, right) in authority.rights.iter().enumerate() {
        if authority.rights[..index]
            .iter()
            .any(|earlier| earlier.id == right.id)
        {
            return Err(format!(
                "provider authority right \"{}\" is declared more than once",
                right.id
            ));
        }
        let Some(row) = dictionary.iter().find(|row| row.id == right.id) else {
            return Err(format!(
                "provider authority right \"{}\" is not an approved right id",
                right.id
            ));
        };
        if !provider.rights().contains(&right.id.as_str()) {
            return Err(format!(
                "provider right \"{}\" is not in the {} Runtime grant",
                right.id,
                provider_label(provider)
            ));
        }
        let template = approved_right_template(&right.id).unwrap_or(row.rules);
        if !rules_match(&right.rules, template) {
            return Err(format!(
                "provider right \"{}\" rule text differs from the Runtime template",
                right.id
            ));
        }
        admitted.push(row);
    }
    Ok(admitted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use elastos_common::CapsuleManifest;

    fn gate(authority: &ProviderAuthority) -> Result<(), String> {
        check_rights_against_runtime_templates(
            RuntimeProviderId::Did,
            authority,
            rights_table::RIGHTS,
        )
        .map(|_| ())
    }

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
        for (name, provider) in [
            ("did", RuntimeProviderId::Did),
            ("wallet", RuntimeProviderId::Wallet),
            ("model", RuntimeProviderId::Model),
        ] {
            let authority = committed_authority(name);
            check_rights_against_runtime_templates(provider, &authority, rights_table::RIGHTS)
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
            gate(&authority),
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
            gate(&authority),
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
        gate(&authority).unwrap();
    }

    #[test]
    fn semicolon_smuggled_rule_is_refused() {
        let mut authority = did_authority();
        let smuggled = "  (allow process-exec (literal (param \"PROVIDER_EXECUTABLE\"))) ;x\n\
                        (allow process-exec (subpath \"/\"))";
        *rules_mut(&mut authority, "bound-executable") = vec![smuggled.to_string()];
        assert_eq!(
            gate(&authority),
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
            gate(&authority),
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
            gate(&authority),
            Err("provider authority right \"network\" is not an approved right id".to_string())
        );
    }

    fn row_ids<'a>(
        provider: RuntimeProviderId,
        authority: &ProviderAuthority,
        dictionary: &'a [rights_table::RightRow],
    ) -> Result<Vec<&'a str>, String> {
        check_rights_against_runtime_templates(provider, authority, dictionary)
            .map(|rows| rows.iter().map(|row| row.id).collect())
    }

    fn with_extra_dictionary_id() -> Vec<rights_table::RightRow> {
        let mut dictionary = rights_table::RIGHTS.to_vec();
        dictionary.push(rights_table::RightRow {
            id: "future-only",
            rules: &["(allow file-read*)"],
            linux_syscalls: "",
        });
        dictionary
    }

    #[test]
    fn empty_rights_take_the_runtime_table_for_that_provider() {
        let dictionary = with_extra_dictionary_id();
        for (name, provider) in [
            ("did", RuntimeProviderId::Did),
            ("wallet", RuntimeProviderId::Wallet),
            ("model", RuntimeProviderId::Model),
        ] {
            let mut authority = committed_authority(name);
            authority.rights.clear();
            assert_eq!(
                row_ids(provider, &authority, &dictionary).unwrap(),
                provider.rights().to_vec(),
                "{name} empty rights"
            );
        }
    }

    #[test]
    fn narrower_equal_and_wider_than_the_grant() {
        let mut narrower = did_authority();
        narrower.rights.retain(|right| right.id == "storage");
        assert_eq!(
            row_ids(RuntimeProviderId::Did, &narrower, rights_table::RIGHTS).unwrap(),
            vec!["storage"]
        );
        assert_eq!(
            row_ids(
                RuntimeProviderId::Did,
                &did_authority(),
                rights_table::RIGHTS
            )
            .unwrap(),
            RuntimeProviderId::Did.rights().to_vec()
        );
        let dictionary = with_extra_dictionary_id();
        let mut wider = serde_json::to_value(did_authority()).unwrap();
        wider["rights"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "id": "future-only",
                "rules": ["(allow file-read*)"]
            }));
        let wider: ProviderAuthority = serde_json::from_value(wider).unwrap();
        assert_eq!(
            row_ids(RuntimeProviderId::Did, &wider, &dictionary),
            Err(
                "provider right \"future-only\" is not in the did-provider Runtime grant"
                    .to_string()
            )
        );
    }

    #[test]
    fn dictionary_only_id_is_refused() {
        let dictionary = with_extra_dictionary_id();
        let mut value = serde_json::to_value(did_authority()).unwrap();
        value["rights"] = serde_json::json!([{
            "id": "future-only",
            "rules": ["(allow file-read*)"]
        }]);
        let authority: ProviderAuthority = serde_json::from_value(value).unwrap();
        assert_eq!(
            row_ids(RuntimeProviderId::Did, &authority, &dictionary),
            Err(
                "provider right \"future-only\" is not in the did-provider Runtime grant"
                    .to_string()
            )
        );
        assert_eq!(
            row_ids(RuntimeProviderId::Wallet, &authority, &dictionary),
            Err(
                "provider right \"future-only\" is not in the wallet-provider Runtime grant"
                    .to_string()
            )
        );
    }

    #[test]
    fn duplicate_declared_right_is_refused() {
        let mut authority = did_authority();
        let storage = authority
            .rights
            .iter()
            .find(|right| right.id == "storage")
            .unwrap()
            .clone();
        authority.rights.push(storage);
        assert_eq!(
            gate(&authority),
            Err("provider authority right \"storage\" is declared more than once".to_string())
        );
    }
}
