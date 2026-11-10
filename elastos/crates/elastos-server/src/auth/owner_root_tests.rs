use super::*;

const OWNER: &str = "person:local:owner";
const DID: &str = "did:key:z6MkAgentOne";

fn fixture() -> (
    tempfile::TempDir,
    PrincipalRecord,
    PrincipalRootProtectionV1,
) {
    let data = tempfile::tempdir().unwrap();
    store_test_human_principal(data.path(), OWNER);
    let owner = store_test_principal_root_protection(data.path(), OWNER);
    let owner_key = principal_root_data_key_from_protection(data.path(), &owner).unwrap();
    let agent = mint_agent_principal(data.path(), OWNER, DID, "notes", &owner_key, 5).unwrap();
    let protection =
        load_principal_root_protection(data.path(), &agent.principal_id, &agent.localhost_root)
            .unwrap()
            .unwrap();
    (data, agent, protection)
}

#[test]
fn owner_root_cipher_round_trip_uses_principal_object_io() {
    let (data, agent, protection) = fixture();
    let uri = format!("{}/Documents/note.txt", agent.localhost_root);
    let path = rooted_localhost_fs_path(data.path(), &uri).unwrap();
    write_principal_root_object(
        data.path(),
        &agent.principal_id,
        &agent.localhost_root,
        &uri,
        &path,
        b"agent secret 5f71c990",
    )
    .unwrap();
    let on_disk = std::fs::read(&path).unwrap();
    assert!(!on_disk
        .windows(b"agent secret 5f71c990".len())
        .any(|bytes| bytes == b"agent secret 5f71c990"));
    assert_eq!(
        read_principal_root_object(
            data.path(),
            &agent.principal_id,
            &agent.localhost_root,
            &uri,
            &path
        )
        .unwrap(),
        b"agent secret 5f71c990"
    );
    assert_eq!(
        principal_root_data_key_from_protection(data.path(), &protection)
            .unwrap()
            .len(),
        32
    );
}

#[test]
fn owner_root_absent_owner_refuses_before_object_open() {
    let (data, agent, protection) = fixture();
    let uri = format!("{}/Documents/note.txt", agent.localhost_root);
    let path = rooted_localhost_fs_path(data.path(), &uri).unwrap();
    write_principal_root_object(
        data.path(),
        &agent.principal_id,
        &agent.localhost_root,
        &uri,
        &path,
        b"secret",
    )
    .unwrap();
    let before = std::fs::read(&path).unwrap();
    mutate_auth_state(data.path(), |state| {
        state
            .principals
            .retain(|record| record.principal_id != OWNER);
        Ok(())
    })
    .unwrap();
    let owner_root = principal_kind_localhost_root(OWNER, PrincipalKind::Human);
    let decoy_uri = format!("{owner_root}/Documents/decoy.txt");
    let decoy_path = rooted_localhost_fs_path(data.path(), &decoy_uri).unwrap();
    std::fs::create_dir_all(decoy_path.parent().unwrap()).unwrap();
    std::fs::write(&decoy_path, b"owner-id decoy 4cc6dbaa").unwrap();
    let decoy_before = std::fs::read(&decoy_path).unwrap();
    let error = read_principal_root_object(
        data.path(),
        &agent.principal_id,
        &agent.localhost_root,
        &uri,
        &path,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("OwnerRoot owner principal is missing"),
        "{error}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(std::fs::read(&decoy_path).unwrap(), decoy_before);
    assert!(!error.contains("4cc6dbaa"));
    assert_eq!(
        principal_root_data_key_from_protection(data.path(), &protection)
            .unwrap_err()
            .to_string(),
        "OwnerRoot owner principal is missing"
    );
    assert!(!PRINCIPAL_ROOT_OBJECT_OPENS
        .lock()
        .unwrap()
        .get(data.path())
        .is_some_and(|opens| opens.contains(&uri)));
}

#[test]
fn owner_root_absent_current_protection_refuses() {
    let (data, _, protection) = fixture();
    mutate_auth_state(data.path(), |state| {
        state
            .principal_root_protections
            .retain(|stored| stored.principal_id != OWNER);
        Ok(())
    })
    .unwrap();
    let error = principal_root_data_key_from_protection(data.path(), &protection)
        .unwrap_err()
        .to_string();
    assert_eq!(error, "OwnerRoot owner protection is missing");
}

#[test]
fn owner_root_wrong_owner_key_agent_id_and_root_refuse() {
    for case in ["owner key", "agent id", "agent root"] {
        let (data, _, mut protection) = fixture();
        assert_eq!(
            principal_root_data_key_from_protection(data.path(), &protection)
                .unwrap()
                .len(),
            32
        );
        match case {
            "owner key" => {
                store_test_principal_root_protection(data.path(), OWNER);
            }
            "agent id" => protection.principal_id = "agent:v1:other".into(),
            "agent root" => {
                protection.localhost_root = "localhost://UsersAI/aaaaaaaaaaaaaaaaaaaaaaaa".into()
            }
            _ => unreachable!(),
        }
        let error = principal_root_data_key_from_protection(data.path(), &protection)
            .unwrap_err()
            .to_string();
        assert_eq!(error, "OwnerRoot data key unwrap failed", "{case}: {error}");
    }
}

#[test]
fn owner_root_salt_binding_refuses() {
    let (data, _, mut protection) = fixture();
    principal_root_data_key_from_protection(data.path(), &protection).unwrap();
    protection.protectors[0].envelope.as_mut().unwrap().salt = b64_url(&[0; 32]);
    let error = principal_root_data_key_from_protection(data.path(), &protection)
        .unwrap_err()
        .to_string();
    assert_eq!(error, "OwnerRoot data key unwrap failed");
}

#[test]
fn owner_root_distinct_mints_have_distinct_random_keys() {
    let (first, _, first_protection) = fixture();
    let (second, _, second_protection) = fixture();
    assert_ne!(first_protection.data_key_id, second_protection.data_key_id);
    assert_ne!(
        principal_root_data_key_from_protection(first.path(), &first_protection).unwrap(),
        principal_root_data_key_from_protection(second.path(), &second_protection).unwrap()
    );
}

#[test]
fn owner_root_envelope_lengths_and_data_key_id_are_checked() {
    let (data, _, protection) = fixture();
    for (salt, nonce) in [
        (b"short".as_slice(), &[0u8; 12][..]),
        (&[0u8; 32][..], b"short".as_slice()),
    ] {
        let mut invalid = protection.clone();
        invalid.protectors[0].envelope.as_mut().unwrap().salt = b64_url(salt);
        invalid.protectors[0].envelope.as_mut().unwrap().nonce = b64_url(nonce);
        assert_eq!(
            principal_root_data_key_from_protection(data.path(), &invalid)
                .unwrap_err()
                .to_string(),
            "OwnerRoot envelope salt or nonce has invalid length"
        );
    }
    let mut wrong_id = protection;
    wrong_id.data_key_id = "pdek:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
    assert_eq!(
        principal_root_data_key_from_protection(data.path(), &wrong_id)
            .unwrap_err()
            .to_string(),
        "OwnerRoot data key binding mismatch"
    );
}

#[test]
fn owner_root_cas_stale_create_race_and_alias() {
    let (data, agent, protection) = fixture();
    let uri = format!("{}/Documents/note.txt", agent.localhost_root);
    let path = rooted_localhost_fs_path(data.path(), &uri).unwrap();
    let write = |bytes: &[u8], condition| {
        write_principal_root_object_if_revision(
            data.path(),
            &agent.principal_id,
            &agent.localhost_root,
            &uri,
            &path,
            bytes,
            condition,
        )
    };
    write(b"first", PrincipalRootObjectPrecondition::Absent).unwrap();
    let revision = principal_root_object_revision(&agent.principal_id, &uri, b"first");
    write(
        b"winner",
        PrincipalRootObjectPrecondition::Revision(&revision),
    )
    .unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(write(
        b"loser",
        PrincipalRootObjectPrecondition::Revision(&revision)
    )
    .unwrap_err()
    .is::<PrincipalRootObjectWriteConflict>());
    assert!(write(b"duplicate", PrincipalRootObjectPrecondition::Absent)
        .unwrap_err()
        .is::<PrincipalRootObjectWriteConflict>());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let barrier = std::sync::Barrier::new(2);
    let current = principal_root_object_revision(&agent.principal_id, &uri, b"winner");
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = [b"one".as_slice(), b"two".as_slice()]
            .into_iter()
            .map(|bytes| {
                let barrier = &barrier;
                let current = &current;
                let write = &write;
                scope.spawn(move || {
                    barrier.wait();
                    write(bytes, PrincipalRootObjectPrecondition::Revision(current))
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(results
        .iter()
        .find(|result| result.is_err())
        .unwrap()
        .as_ref()
        .unwrap_err()
        .is::<PrincipalRootObjectWriteConflict>());
    let raced_bytes = std::fs::read(&path).unwrap();
    let alias = format!("{}/Documents/../Documents/note.txt", agent.localhost_root);
    let error = write_principal_root_object(
        data.path(),
        &agent.principal_id,
        &agent.localhost_root,
        &alias,
        &path,
        b"alias",
    )
    .unwrap_err()
    .to_string();
    assert!(!error.is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), raced_bytes);
    assert_eq!(
        load_principal_root_protection(data.path(), &agent.principal_id, &agent.localhost_root)
            .unwrap(),
        Some(protection)
    );
    assert_eq!(
        load_auth_state(data.path())
            .unwrap()
            .principal_root_protections
            .len(),
        2
    );
}

#[test]
fn owner_root_kind_binding_refuses_replacement() {
    let (data, agent, protection) = fixture();
    let path = auth_state_path(data.path()).unwrap();
    let before = std::fs::read(&path).unwrap();
    let mut replacement = protection.clone();
    replacement.data_key_id = "pdek:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
    let error = store_principal_root_protection(data.path(), replacement)
        .unwrap_err()
        .to_string();
    assert_eq!(error, "agent root protection cannot be replaced");
    assert_eq!(std::fs::read(&path).unwrap(), before);
    store_test_human_principal(data.path(), "person:local:other");
    let mut recovery = store_test_principal_root_protection(data.path(), "person:local:other");
    recovery.principal_id = agent.principal_id.clone();
    let before = std::fs::read(&path).unwrap();
    let error = store_principal_root_protection(data.path(), recovery)
        .unwrap_err()
        .to_string();
    assert_eq!(error, "agent root protection cannot be replaced");
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
