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
//! rights resolve to the Runtime grant for that Runtime provider id, read from
//! `rights_table::RIGHTS`. A non-empty list must be that grant or a subset of
//! it. Each declared right's rules must equal the template, and the dictionary
//! row must equal that same template in rule text and `linux_syscalls`. The
//! value returned is `AdmittedRights`: its rows are the Runtime table's rows,
//! and only this module can construct it. `os_entry::start_provider` is the
//! caller. The server does not call it yet.
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

fn rules_match(declared: &[impl AsRef<str>], template: &[&str]) -> bool {
    declared.len() == template.len()
        && declared
            .iter()
            .zip(template)
            .all(|(rule, approved)| normalised(rule.as_ref()) == normalised(approved))
}

fn provider_label(provider: RuntimeProviderId) -> &'static str {
    match provider {
        RuntimeProviderId::Did => "did-provider",
        RuntimeProviderId::Wallet => "wallet-provider",
        RuntimeProviderId::Model => "model-provider",
    }
}

/// Rows the gate admitted from `rights_table::RIGHTS`.
///
/// The list is private. `from_table` is the only constructor, and it is private
/// to this module, so a sibling can receive the value and cannot build one.
pub(super) struct AdmittedRights {
    rows: Vec<&'static rights_table::RightRow>,
}

impl AdmittedRights {
    fn from_table(rows: Vec<&'static rights_table::RightRow>) -> Self {
        AdmittedRights { rows }
    }

    pub(super) fn rows(&self) -> &[&'static rights_table::RightRow] {
        &self.rows
    }
}

/// The provider's Runtime grant. Tests that build a plan use this path.
#[cfg(test)]
pub(super) fn admit_runtime_grant(provider: RuntimeProviderId) -> AdmittedRights {
    let authority: ProviderAuthority = serde_json::from_value(serde_json::json!({
        "reason": "runtime grant",
        "capabilities": [],
        "audit_events": [],
        "rights": []
    }))
    .expect("empty authority");
    check_rights_against_runtime_templates(provider, &authority, rights_table::RIGHTS)
        .expect("the Runtime grant admits")
}

/// Resolve declared rights to the rows the OS entry installs.
///
/// Empty rights select `provider`'s grant through `rights_table::resolve` on
/// `rights_table::RIGHTS`. Any other list must be that grant or a subset. The
/// declared rules and the dictionary row's rules must equal the template, and
/// the dictionary row's `linux_syscalls` must equal the template's. The
/// returned rows are those template rows. The check finishes before a process
/// is created.
pub(super) fn check_rights_against_runtime_templates(
    provider: RuntimeProviderId,
    authority: &ProviderAuthority,
    dictionary: &[rights_table::RightRow],
) -> Result<AdmittedRights, String> {
    if authority.rights.is_empty() {
        return Ok(AdmittedRights::from_table(rights_table::resolve(
            provider,
            rights_table::RIGHTS,
        )));
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
        let Some(template_rules) = approved_right_template(&right.id) else {
            return Err(format!(
                "provider authority right \"{}\" is not an approved right id",
                right.id
            ));
        };
        let template = rights_table::RIGHTS
            .iter()
            .find(|item| item.id == right.id)
            .expect("approved template text is a Runtime table row");
        if !rules_match(&right.rules, template_rules) {
            return Err(format!(
                "provider right \"{}\" rule text differs from the Runtime template",
                right.id
            ));
        }
        if !rules_match(row.rules, template.rules) {
            return Err(format!(
                "provider right \"{}\" is not the Runtime table row",
                right.id
            ));
        }
        if row.linux_syscalls != template.linux_syscalls {
            return Err(format!(
                "provider right \"{}\" linux syscalls differ from the Runtime template",
                right.id
            ));
        }
        admitted.push(template);
    }
    Ok(AdmittedRights::from_table(admitted))
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

    fn row_ids(
        provider: RuntimeProviderId,
        authority: &ProviderAuthority,
        dictionary: &[rights_table::RightRow],
    ) -> Result<Vec<&'static str>, String> {
        check_rights_against_runtime_templates(provider, authority, dictionary)
            .map(|admitted| admitted.rows().iter().map(|row| row.id).collect())
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
    fn admitted_rows_are_the_runtime_table_rows() {
        let dictionary = rights_table::RIGHTS.to_vec();
        let admitted = check_rights_against_runtime_templates(
            RuntimeProviderId::Did,
            &did_authority(),
            &dictionary,
        )
        .unwrap();
        for row in admitted.rows() {
            assert!(
                rights_table::RIGHTS
                    .iter()
                    .any(|template| std::ptr::eq(*row, template)),
                "admitted {} must be the Runtime table row, not the caller's copy",
                row.id
            );
        }
        let mut empty = did_authority();
        empty.rights.clear();
        let granted =
            check_rights_against_runtime_templates(RuntimeProviderId::Did, &empty, &dictionary)
                .unwrap();
        for row in granted.rows() {
            assert!(
                rights_table::RIGHTS
                    .iter()
                    .any(|template| std::ptr::eq(*row, template)),
                "empty rights must resolve the Runtime table"
            );
        }
    }

    #[test]
    fn widened_linux_syscalls_are_refused() {
        let mut dictionary = rights_table::RIGHTS.to_vec();
        let storage = dictionary
            .iter_mut()
            .find(|row| row.id == "storage")
            .unwrap();
        storage.linux_syscalls = "socket";
        assert_eq!(
            check_rights_against_runtime_templates(
                RuntimeProviderId::Did,
                &did_authority(),
                &dictionary
            )
            .map(|_| ()),
            Err(
                "provider right \"storage\" linux syscalls differ from the Runtime template"
                    .to_string()
            )
        );
    }

    #[test]
    fn only_rights_constructs_admitted_rights() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut struct_literals = Vec::new();
        let mut constructors = Vec::new();
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                if text.contains("AdmittedRights { rows") {
                    struct_literals.push(path.clone());
                }
                if text.contains("fn from_table") {
                    constructors.push(path);
                }
            }
        }
        let rights =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/provider/rights.rs");
        struct_literals.sort();
        constructors.sort();
        assert_eq!(struct_literals, vec![rights.clone()]);
        assert_eq!(constructors, vec![rights.clone()]);
        let source = std::fs::read_to_string(&rights).unwrap();
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert_eq!(production.matches("AdmittedRights { rows").count(), 1);
        assert_eq!(production.matches("fn from_table").count(), 1);
        assert!(!production.contains("pub fn from_table"));
        assert!(!production.contains("pub(super) fn from_table"));
        assert!(!production.contains("pub(crate) fn from_table"));
        let start = production.find("struct AdmittedRights").unwrap();
        let open = production[start..].find('{').unwrap() + start;
        let close = production[open..].find('}').unwrap() + open;
        let body = &production[open + 1..close];
        assert!(!body.contains("pub"), "AdmittedRights fields stay private");
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
