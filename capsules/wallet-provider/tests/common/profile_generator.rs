use serde_json::Value;
use std::fs;
use std::path::Path;

/// The three head forms every file profile starts with, in profile order.
pub(crate) const PROFILE_HEAD: [&str; 3] = ["(version 1)", "(deny default)", "(deny network*)"];
/// The right ids the shared contract names. A declared-rights file may claim
/// only these.
pub(crate) const CONTRACT_RIGHTS: [&str; 2] = ["storage", "bound-executable"];
/// The platform-baseline ids the shared contract names. A declared-rights file
/// may claim only these under its platform baseline; they are the Runtime
/// platform baseline for the provider executable on macOS, not approved rights.
pub(crate) const PLATFORM_BASELINE_IDS: [&str; 2] = ["startup-root-directory", "startup-sysctl"];
/// The sentence a declared-rights file gives for its own role.
pub(crate) const DECLARED_RIGHTS_ROLE: &str =
    "lab stand-in for the Runtime generator's input, not a manifest field";
/// The one key a declared-rights file holds its platform baseline under.
pub(crate) const PLATFORM_BASELINE: &str = "platform_baseline";
/// The status sentence a declared-rights file gives its platform baseline for
/// `name`, the provider executable the Runtime binds on macOS.
pub(crate) fn platform_baseline_status(name: &str) -> String {
    format!("Runtime platform baseline for the {name} executable on macOS, not approved rights")
}
/// The prefix every platform-baseline justification starts with, naming the
/// provider executable the Runtime binds as PROVIDER_EXECUTABLE.
pub(crate) fn platform_baseline_justification(name: &str) -> String {
    format!("macOS {name} executable bound as PROVIDER_EXECUTABLE: ")
}

/// One declared entry of a declared-rights file: its id and the allow rules it
/// claims.
#[derive(Debug)]
pub(crate) struct DeclaredClaim {
    pub(crate) id: String,
    pub(crate) rules: Vec<String>,
}

/// The rights claims and the platform-baseline claims of `declared`, each
/// proven to hold an id the shared contract names and a rules list of strings,
/// and each platform-baseline entry proven to give a justification that starts
/// with the provider's executable prefix and a reason after it.
///
/// The one declared-rights check and the one lab generator both read the
/// declared entries through this function (P10). It refuses, in this order: a
/// document without the role, provider, rights list or platform baseline; a
/// platform baseline without its own status sentence; a platform baseline
/// without its rules list; an entry of the declared rights list or the
/// platform-baseline rules list without a string id, whose reason names that
/// list and the entry; an entry without a rules list; a rule that is not a
/// string; an id the shared contract does not name; and a platform-baseline
/// entry without a justification that starts with the provider's prefix and
/// gives a reason. Each refusal starts with the provider name and quotes the
/// rule or names the id (P11).
pub(crate) fn declared_entries(
    name: &str,
    declared: &Value,
) -> Result<(Vec<DeclaredClaim>, Vec<DeclaredClaim>), String> {
    if declared["role"].as_str() != Some(DECLARED_RIGHTS_ROLE) {
        return Err(format!(
            "{name} declared-rights file must give the role {DECLARED_RIGHTS_ROLE:?}"
        ));
    }
    if declared["provider"].as_str() != Some(name) {
        return Err(format!(
            "{name} declared-rights file must name the provider {name}"
        ));
    }
    let Some(rights) = declared["rights"].as_array() else {
        return Err(format!(
            "{name} declared-rights file must hold a rights list"
        ));
    };
    let Some(baseline) = declared[PLATFORM_BASELINE].as_object() else {
        return Err(format!(
            "{name} declared-rights file must hold a platform baseline"
        ));
    };
    let status = platform_baseline_status(name);
    if baseline.get("status").and_then(Value::as_str) != Some(status.as_str()) {
        return Err(format!(
            "{name} platform baseline must give the status {status:?}"
        ));
    }
    let Some(baseline_rules) = baseline.get("rules").and_then(Value::as_array) else {
        return Err(format!("{name} platform baseline must hold a rules list"));
    };
    let rights = declared_claims(name, "declared rights list", rights)?;
    let baseline = declared_claims(name, "platform baseline rules", baseline_rules)?;
    for claim in &rights {
        if !CONTRACT_RIGHTS.contains(&claim.id.as_str()) {
            return Err(format!(
                "{name} declares {}, which the shared contract does not name",
                claim.id
            ));
        }
    }
    for claim in &baseline {
        if !PLATFORM_BASELINE_IDS.contains(&claim.id.as_str()) {
            return Err(format!(
                "{name} declares {}, which the shared contract does not name",
                claim.id
            ));
        }
    }
    let prefix = platform_baseline_justification(name);
    for (entry, claim) in baseline_rules.iter().zip(&baseline) {
        let Some(justification) = entry["justification"].as_str() else {
            return Err(format!(
                "{name} platform baseline {} must give a string justification",
                claim.id
            ));
        };
        if !justification.starts_with(&prefix) {
            return Err(format!(
                "{name} platform baseline {} justification must start with {prefix:?}",
                claim.id
            ));
        }
        if justification[prefix.len()..].trim().is_empty() {
            return Err(format!(
                "{name} platform baseline {} justification gives no reason after {prefix:?}",
                claim.id
            ));
        }
    }
    Ok((rights, baseline))
}

/// The one lab generator for a file profile: the contract head, then every
/// rule of every rights claim in file order, then every rule of every
/// platform-baseline claim in file order, one form per line. It emits no
/// comment and nothing else, it reads and writes no file, and it refuses an id
/// the shared contract does not name through `declared_entries`.
pub(crate) fn generate_profile(name: &str, declared: &Value) -> Result<String, String> {
    let (rights, baseline) = declared_entries(name, declared)?;
    let mut profile = String::new();
    for form in PROFILE_HEAD {
        profile.push_str(form);
        profile.push('\n');
    }
    for claim in rights.iter().chain(&baseline) {
        for rule in &claim.rules {
            profile.push_str(rule);
            profile.push('\n');
        }
    }
    Ok(profile)
}

/// The one lab writer of a generated profile: it calls `generate_profile`
/// first and returns that refusal unchanged, before it creates, opens or
/// truncates `path`; only a generated profile is written, and a write failure
/// is a refusal that names the provider and the path. It adds no validation of
/// its own: every refusal reason comes from `declared_entries`.
pub(crate) fn write_generated_profile(
    name: &str,
    declared: &Value,
    path: &Path,
) -> Result<(), String> {
    let profile = generate_profile(name, declared)?;
    fs::write(path, profile).map_err(|err| {
        format!(
            "{name} generated profile {} must be writable: {err}",
            path.display()
        )
    })
}

/// The declared entries of `entries`, each proven to hold a string id and a
/// rules list of strings. `label` names the list in the missing-id refusal, so
/// the reader knows which of the two lists holds the entry; the index names
/// the entry. The two other refusals name the id.
fn declared_claims(
    name: &str,
    label: &str,
    entries: &[Value],
) -> Result<Vec<DeclaredClaim>, String> {
    let mut claims = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let Some(id) = entry["id"].as_str() else {
            return Err(format!(
                "{name} {label} entry {index} must give a string id"
            ));
        };
        let Some(rules) = entry["rules"].as_array() else {
            return Err(format!("{name} declares {id} without a rules list"));
        };
        let mut claimed = Vec::with_capacity(rules.len());
        for rule in rules {
            let Some(rule) = rule.as_str() else {
                return Err(format!(
                    "{name} declares {id} with a rule that is not a string"
                ));
            };
            claimed.push(rule.to_owned());
        }
        claims.push(DeclaredClaim {
            id: id.to_owned(),
            rules: claimed,
        });
    }
    Ok(claims)
}
