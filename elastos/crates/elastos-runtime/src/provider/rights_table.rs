//! Runtime-owned confinement rights for the three B3 providers.

pub(super) struct RightRow {
    pub id: &'static str,
    pub rules: &'static [&'static str],
}

pub(super) const RIGHTS: &[RightRow] = &[
    RightRow {
        id: "storage",
        rules: &[
            r#"(allow file-read* (literal (param "STORAGE_PARENT")))"#,
            r#"(allow file-read* file-write* (subpath (param "STORAGE_ROOT")))"#,
        ],
    },
    RightRow {
        id: "bound-executable",
        rules: &[r#"(allow process-exec (literal (param "PROVIDER_EXECUTABLE")))"#],
    },
];

/// A v2 package without `rights` uses these Runtime-owned rows by name.
/// Other providers remain outside B3 until they declare rights.
#[allow(dead_code)] // The spawn caller is added in a later slice.
pub(super) fn for_provider(name: &str) -> Option<&'static [RightRow]> {
    match name {
        "did-provider" | "wallet-provider" | "model-provider" => Some(RIGHTS),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elastos_common::{CapsuleManifest, APPROVED_RIGHT_IDS};

    #[test]
    fn manifest_ids_and_rules_equal_runtime_table() {
        let table_ids: Vec<_> = RIGHTS.iter().map(|row| row.id).collect();
        for name in ["did-provider", "wallet-provider", "model-provider"] {
            let path = format!(
                "{}/../../../capsules/{name}/capsule.json",
                env!("CARGO_MANIFEST_DIR")
            );
            let json = std::fs::read_to_string(&path).unwrap();
            let manifest: CapsuleManifest = serde_json::from_str(&json).unwrap();
            let rights = &manifest.authority.unwrap().rights;
            assert_eq!(
                rights
                    .iter()
                    .map(|right| right.id.as_str())
                    .collect::<Vec<_>>(),
                table_ids,
                "{name} ids"
            );
            for (right, row) in rights.iter().zip(RIGHTS) {
                assert_eq!(right.rules, row.rules, "{name}: {} rules", row.id);
            }
            let mut v2: serde_json::Value = serde_json::from_str(&json).unwrap();
            v2["authority"].as_object_mut().unwrap().remove("rights");
            let v2: CapsuleManifest = serde_json::from_value(v2).unwrap();
            assert!(v2.authority.unwrap().rights.is_empty());
            assert_eq!(for_provider(name).unwrap().len(), RIGHTS.len());
        }
        assert_eq!(APPROVED_RIGHT_IDS.as_slice(), table_ids);
        assert!(for_provider("other-provider").is_none());
    }

    #[test]
    fn lab_contract_ids_equal_runtime_table() {
        let lab = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../capsules/wallet-provider/tests/common/profile_generator.rs"
        ));
        let line = lab
            .lines()
            .find(|line| line.contains("const CONTRACT_RIGHTS:"))
            .unwrap();
        let ids: Vec<String> =
            serde_json::from_str(line.split_once('=').unwrap().1.trim().trim_end_matches(';'))
                .unwrap();
        assert_eq!(
            ids,
            RIGHTS
                .iter()
                .map(|row| row.id.to_string())
                .collect::<Vec<_>>()
        );
    }
}
