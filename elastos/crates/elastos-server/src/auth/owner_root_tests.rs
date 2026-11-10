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
fn agent_object_io_refuses_missing_protection_and_human_plaintext_still_works() {
    let (data, agent, _) = fixture();
    let uri = format!("{}/Documents/note.txt", agent.localhost_root);
    let path = rooted_localhost_fs_path(data.path(), &uri).unwrap();
    write_principal_root_object(
        data.path(),
        &agent.principal_id,
        &agent.localhost_root,
        &uri,
        &path,
        b"before",
    )
    .unwrap();
    let before = std::fs::read(&path).unwrap();
    mutate_auth_state(data.path(), |state| {
        state
            .principal_root_protections
            .retain(|p| p.principal_id != agent.principal_id);
        Ok(())
    })
    .unwrap();
    let read_error = read_principal_root_object(
        data.path(),
        &agent.principal_id,
        &agent.localhost_root,
        &uri,
        &path,
    )
    .unwrap_err()
    .to_string();
    assert_eq!(read_error, "Agent root has no stored protection");
    let write_error = write_principal_root_object(
        data.path(),
        &agent.principal_id,
        &agent.localhost_root,
        &uri,
        &path,
        b"after",
    )
    .unwrap_err()
    .to_string();
    assert_eq!(write_error, "Agent root has no stored protection");
    assert_eq!(std::fs::read(&path).unwrap(), before);

    let human = store_test_human_principal(data.path(), "person:local:control");
    let human_uri = format!("{}/Documents/control.txt", human.localhost_root);
    let human_path = rooted_localhost_fs_path(data.path(), &human_uri).unwrap();
    write_principal_root_object(
        data.path(),
        &human.principal_id,
        &human.localhost_root,
        &human_uri,
        &human_path,
        b"human",
    )
    .unwrap();
    assert_eq!(
        read_principal_root_object(
            data.path(),
            &human.principal_id,
            &human.localhost_root,
            &human_uri,
            &human_path
        )
        .unwrap(),
        b"human"
    );
    assert_eq!(std::fs::read(&human_path).unwrap(), b"human");
}

#[test]
fn usersai_missing_agent_record_refuses_upgrade_preflight_without_migration() {
    let (data, agent, _) = fixture();
    let uri = format!("{}/Documents/plain.txt", agent.localhost_root);
    let path = rooted_localhost_fs_path(data.path(), &uri).unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"legacy plaintext").unwrap();
    mutate_auth_state(data.path(), |state| {
        state
            .principals
            .retain(|p| p.principal_id != agent.principal_id);
        Ok(())
    })
    .unwrap();
    let auth_path = auth_state_path(data.path()).unwrap();
    let before = std::fs::read(&auth_path).unwrap();
    let declarations = load_auth_state(data.path())
        .unwrap()
        .principal_root_protections
        .into_iter()
        .map(|p| PrincipalRootUpgradeDeclarationV1 {
            inventory: if p.principal_id == agent.principal_id {
                vec![PrincipalRootProtectedObjectDeclarationV1::exact(
                    uri.clone(),
                )]
            } else {
                vec![]
            },
            principal_id: p.principal_id,
            localhost_root: p.localhost_root,
        })
        .collect::<Vec<_>>();
    let error = preflight_declared_principal_root_upgrade(
        data.path(),
        &declarations,
        PrincipalRootScanMode::Plan,
    )
    .unwrap_err()
    .to_string();
    assert_eq!(error, "UsersAI protection requires its stored Agent root");
    assert_eq!(std::fs::read(&auth_path).unwrap(), before);
    assert_eq!(std::fs::read(&path).unwrap(), b"legacy plaintext");
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
    store_test_human_principal(data.path(), "person:local:decoy");
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
fn owner_root_hkdf_domain_is_pinned() {
    let key = owner_root_wrapping_key(
        &[7; 32],
        &[3; 32],
        "agent:v1:pinned",
        "localhost://UsersAI/pinned",
    )
    .unwrap();
    assert_eq!(
        hex::encode(key),
        "26884641438572eaa661b8b70268d51c4a6de26b6a7e30f2bb9db7d6226da7b3"
    );
}

#[test]
fn owner_root_missing_envelope_refuses_by_name() {
    let (data, _, mut protection) = fixture();
    protection.protectors[0].envelope = None;
    assert_eq!(
        principal_root_data_key_from_protection(data.path(), &protection)
            .unwrap_err()
            .to_string(),
        "OwnerRoot envelope is missing"
    );
}

#[test]
fn owner_root_owner_record_requires_human_kind() {
    let (data, _, protection) = fixture();
    mutate_auth_state(data.path(), |state| {
        state
            .principals
            .iter_mut()
            .find(|p| p.principal_id == OWNER)
            .unwrap()
            .kind = PrincipalKind::Agent;
        Ok(())
    })
    .unwrap();
    assert_eq!(
        principal_root_data_key_from_protection(data.path(), &protection)
            .unwrap_err()
            .to_string(),
        "OwnerRoot owner principal is missing"
    );
}

/// Two agents minted under ONE owner key get data keys that differ from each
/// other and from the owner's key, so an agent's key is not derived from, or a
/// copy of, its owner's.
#[test]
fn owner_root_distinct_mints_have_distinct_random_keys() {
    let (data, _, first_protection) = fixture();
    let owner = load_principal_root_protection(
        data.path(),
        OWNER,
        &principal_kind_localhost_root(OWNER, PrincipalKind::Human),
    )
    .unwrap()
    .unwrap();
    let owner_key = principal_root_data_key_from_protection(data.path(), &owner).unwrap();
    let second = mint_agent_principal(data.path(), OWNER, DID, "mail", &owner_key, 5).unwrap();
    let second_protection =
        load_principal_root_protection(data.path(), &second.principal_id, &second.localhost_root)
            .unwrap()
            .unwrap();

    let first_key =
        principal_root_data_key_from_protection(data.path(), &first_protection).unwrap();
    let second_key =
        principal_root_data_key_from_protection(data.path(), &second_protection).unwrap();

    assert_ne!(first_protection.data_key_id, second_protection.data_key_id);
    assert_ne!(first_key, second_key);
    assert_ne!(first_key, owner_key);
    assert_ne!(second_key, owner_key);
}

/// The envelope is opened only as the algorithms it names. A stored envelope
/// that names another allowed cipher refuses, and the agent object is not
/// returned; so does an envelope handed in with another KDF.
#[test]
fn owner_root_envelope_cipher_and_kdf_are_checked() {
    let (data, agent, protection) = fixture();
    let uri = format!("{}/Documents/note.txt", agent.localhost_root);
    let path = rooted_localhost_fs_path(data.path(), &uri).unwrap();
    let write_then_read = || {
        write_principal_root_object(
            data.path(),
            &agent.principal_id,
            &agent.localhost_root,
            &uri,
            &path,
            b"agent note",
        )?;
        read_principal_root_object(
            data.path(),
            &agent.principal_id,
            &agent.localhost_root,
            &uri,
            &path,
        )
    };
    // Control: the minted envelope opens.
    assert_eq!(write_then_read().unwrap(), b"agent note");

    for (field, value) in [("cipher", "chacha20-poly1305"), ("kdf", "argon2id")] {
        let mut relabelled = protection.clone();
        let envelope = relabelled.protectors[0].envelope.as_mut().unwrap();
        match field {
            "cipher" => envelope.cipher = value.into(),
            _ => envelope.kdf = value.into(),
        }
        assert_eq!(
            principal_root_data_key_from_protection(data.path(), &relabelled)
                .expect_err(field)
                .to_string(),
            "OwnerRoot envelope cipher or KDF is unsupported",
            "{field}"
        );
    }

    // Stored with the other allowed cipher's name, the object no longer opens.
    mutate_auth_state(data.path(), |state| {
        let stored = state
            .principal_root_protections
            .iter_mut()
            .find(|stored| stored.principal_id == agent.principal_id)
            .unwrap();
        stored.protectors[0].envelope.as_mut().unwrap().cipher = "chacha20-poly1305".into();
        Ok(())
    })
    .unwrap();
    let error = read_principal_root_object(
        data.path(),
        &agent.principal_id,
        &agent.localhost_root,
        &uri,
        &path,
    )
    .expect_err("a relabelled stored envelope")
    .to_string();
    assert!(
        error.contains("OwnerRoot protector envelope must use aes-256-gcm"),
        "{error}"
    );
}

#[test]
fn owner_root_store_refuses_other_cipher_name_without_write() {
    let (data, _, mut protection) = fixture();
    let path = auth_state_path(data.path()).unwrap();
    let before = std::fs::read(&path).unwrap();
    protection.protectors[0].envelope.as_mut().unwrap().cipher = "chacha20-poly1305".into();
    let error = store_principal_root_protection(data.path(), protection)
        .unwrap_err()
        .to_string();
    assert_eq!(error, "OwnerRoot protector envelope must use aes-256-gcm");
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn owner_root_envelope_lengths_and_data_key_id_are_checked() {
    let (data, _, protection) = fixture();
    for (salt, nonce) in [
        (b"short".as_slice(), &[0u8; 12][..]),
        (&[0u8; 31][..], &[0u8; 12][..]),
        (&[0u8; 33][..], &[0u8; 12][..]),
        (&[0u8; 32][..], b"short".as_slice()),
        (&[0u8; 32][..], &[0u8; 11][..]),
        (&[0u8; 32][..], &[0u8; 13][..]),
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
    let owner = load_principal_root_protection(
        data.path(),
        OWNER,
        &principal_kind_localhost_root(OWNER, PrincipalKind::Human),
    )
    .unwrap()
    .unwrap();
    let owner_key = principal_root_data_key_from_protection(data.path(), &owner).unwrap();
    for len in [31, 33] {
        let mut invalid = protection.clone();
        let envelope = invalid.protectors[0].envelope.as_mut().unwrap();
        let salt = b64_url_decode(&envelope.salt).unwrap();
        let nonce = b64_url_decode(&envelope.nonce).unwrap();
        let wrapping_key = owner_root_wrapping_key(
            &owner_key,
            &salt,
            &invalid.principal_id,
            &invalid.localhost_root,
        )
        .unwrap();
        let short_key = vec![0; len];
        envelope.wrapped_data_key =
            encrypt_aes256_gcm_bytes(&wrapping_key, &nonce, &short_key).unwrap();
        invalid.data_key_id = principal_data_key_id(&short_key);
        assert_eq!(
            principal_root_data_key_from_protection(data.path(), &invalid)
                .unwrap_err()
                .to_string(),
            "OwnerRoot data key binding mismatch",
            "{len}"
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
    // The one writer that returned Ok is the one whose bytes are stored.
    let winner: &[u8] = if results[0].is_ok() { b"one" } else { b"two" };
    assert_eq!(
        read_principal_root_object(
            data.path(),
            &agent.principal_id,
            &agent.localhost_root,
            &uri,
            &path,
        )
        .unwrap(),
        winner
    );
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
    assert_eq!(
        error,
        "principal-root object URI has no canonical filesystem path"
    );
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
