//! Tests for the agent file. Rules that need the feature on are in
//! `feature_on`; the rest run in every build.

use super::*;
use serde_json::{json, Value};

#[path = "frozen_audit_v2_0_1.rs"]
mod frozen_audit;

pub(crate) const OWNER_ID: &str = "person:local:agents-owner";
const SESSION_ID: &str = "session:agents-test";
const AGENT_A: &str = "agent:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const AGENT_B: &str = "agent:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

type EditAgent = fn(&mut StoredAgent);
type EditFile = fn(&mut AgentRecordsFile);

/// A Home with one admin person who has storage protection.
pub(crate) struct Home {
    pub(crate) dir: tempfile::TempDir,
    pub(crate) owner: PrincipalRecord,
}

impl Home {
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        crate::auth::store_test_principal_root_protection(dir.path(), OWNER_ID);
        make_admin(dir.path(), OWNER_ID);
        let owner = crate::auth::stored_principal_record(dir.path(), OWNER_ID)
            .unwrap()
            .unwrap();
        Self { dir, owner }
    }

    pub(crate) fn path(&self) -> &Path {
        self.dir.path()
    }

    pub(crate) fn caller(&self) -> Caller<'_> {
        Caller {
            principal_id: &self.owner.principal_id,
            proof_binding_id: &self.owner.proof_binding_id,
            session_id: SESSION_ID,
        }
    }

    fn agent_file(&self) -> PathBuf {
        agent_file_path(self.path()).unwrap()
    }

    fn agent_bytes(&self) -> Vec<u8> {
        std::fs::read(self.agent_file()).unwrap()
    }

    /// The sign-in file's own records: the loader also hands agents through,
    /// and that file holds none.
    fn owner_file(&self) -> Vec<PrincipalRecord> {
        crate::auth::load_auth_state(self.path())
            .unwrap()
            .principals
            .into_iter()
            .filter(|record| record.kind != PrincipalKind::Agent)
            .collect()
    }

    fn load(&self) -> AgentFile {
        load(self.path(), &self.owner_file()).unwrap()
    }

    /// The reason a load refuses the file on disk, and proof the load left
    /// its bytes alone.
    fn refusal(&self) -> &'static str {
        let before = std::fs::symlink_metadata(self.agent_file())
            .ok()
            .filter(|metadata| metadata.is_file())
            .map(|_| self.agent_bytes());
        let found = self.load();
        if let Some(before) = before {
            assert_eq!(self.agent_bytes(), before, "a load never rewrites the file");
        }
        match found {
            AgentFile::Unavailable(reason) => reason,
            other => panic!("the file was not refused: {other:?}"),
        }
    }

    /// Puts `value` on disk as the agent file, at mode 0600, with no writer.
    fn plant(&self, value: &Value) {
        let path = self.agent_file();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
        set_mode(&path, 0o600);
    }

    /// The owner's sign-in file as JSON, without its audit chain.
    fn owner_json_without_audit(&self) -> Value {
        let mut value = self.owner_json();
        for key in [
            "audit",
            "audit_chain",
            "audit_chain_state",
            "audit_chain_anchor",
        ] {
            value.as_object_mut().unwrap().remove(key);
        }
        value
    }

    fn owner_json(&self) -> Value {
        let path = crate::auth::auth_state_path(self.path()).unwrap();
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    pub(crate) fn audit(&self) -> Vec<RuntimeAuditEventV1> {
        crate::auth::load_auth_state(self.path()).unwrap().audit
    }

    fn agent_events(&self) -> Vec<RuntimeAuditEventV1> {
        self.audit()
            .into_iter()
            .filter(|event| event.event_type.starts_with("agent."))
            .collect()
    }
}

pub(crate) fn make_admin(data_dir: &Path, principal_id: &str) {
    let mut state = crate::auth::load_auth_state(data_dir).unwrap();
    for principal in &mut state.principals {
        if principal.principal_id == principal_id {
            principal.role = RuntimePrincipalRole::Admin;
        }
    }
    crate::auth::save_auth_state(data_dir, &state, None).unwrap();
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A hand-built agent of `owner`, shaped as create writes one.
fn stored_agent(owner: &str, id: &str) -> StoredAgent {
    let binding = ProofBinding::agent_admission(id, 5);
    let root = crate::auth::principal_kind_localhost_root(id, PrincipalKind::Agent);
    StoredAgent {
        record: PrincipalRecord {
            principal_id: id.to_string(),
            proof_binding_id: binding.id(),
            proof_binding: binding,
            display_name: "Helper".to_string(),
            initial_profile_display_name: None,
            role: RuntimePrincipalRole::Guest,
            localhost_root: root.clone(),
            kind: PrincipalKind::Agent,
            created_at: 5,
            updated_at: 5,
            owner: Some(owner.to_string()),
            request_id: Some(format!("request-{}", &id[9..13])),
            agent_host_package: Some(AgentHostPackage {
                name: "agent-host".to_string(),
                registry_cid: "bafyagenthost".to_string(),
                bundle_cid: "bafyagenthostbytes".to_string(),
            }),
            retired_at: None,
            version: PRINCIPAL_RECORD_VERSION,
        },
        protection: PrincipalRootProtectionV1 {
            schema: PRINCIPAL_ROOT_PROTECTION_SCHEMA.to_string(),
            principal_id: id.to_string(),
            localhost_root: root,
            data_key_id: format!("pdek:{}", "0".repeat(32)),
            crypto: PrincipalRootCryptoProfileV1 {
                recovery_kdf: OWNER_ROOT_KDF.to_string(),
                ..PrincipalRootCryptoProfileV1::default()
            },
            protectors: vec![PrincipalRootProtectorV1 {
                protector_id: format!("protector:owner-root:{}", &id[9..]),
                kind: PrincipalRootProtectorKind::OwnerRoot,
                label: "Owner root".to_string(),
                subject: Some(owner.to_string()),
                created_at: 5,
                verified_at: None,
                envelope: Some(PrincipalRootProtectorEnvelopeV1 {
                    cipher: DEFAULT_PRINCIPAL_ROOT_CIPHER.to_string(),
                    kdf: OWNER_ROOT_KDF.to_string(),
                    salt: OWNER_ROOT_ENVELOPE_SALT.to_string(),
                    nonce: crate::auth::b64_url(&[0u8; 12]),
                    wrapped_data_key: crate::auth::b64_url(&[0u8; 48]),
                }),
                archive: None,
                profile_coverage: None,
            }],
            created_at: 5,
            updated_at: 5,
        },
    }
}

/// An enabled file at sequence 1 holding `agents`.
fn enabled_file(agents: Vec<StoredAgent>) -> AgentRecordsFile {
    AgentRecordsFile {
        schema: AGENT_RECORDS_SCHEMA.to_string(),
        sequence: 1,
        enabled: Some(Enabled {
            by: OWNER_ID.to_string(),
            at: 5,
        }),
        agents,
    }
}

fn as_json(file: &AgentRecordsFile) -> Value {
    serde_json::to_value(file).unwrap()
}

/// Opens for a write and applies `change` to a copy of the file, with the
/// sequence already raised by one.
fn write_change(
    home: &Home,
    operation: Operation,
    change: impl FnOnce(&mut AgentRecordsFile),
) -> anyhow::Result<()> {
    let opened = open(home.path(), true)?;
    let mut after = opened.file.clone();
    after.sequence += 1;
    change(&mut after);
    write(
        home.path(),
        &opened,
        operation,
        &after,
        &home.caller(),
        OWNER_ID,
        9,
    )
}

fn enable(home: &Home) {
    write_change(home, Operation::Enable, |file| {
        file.enabled = Some(Enabled {
            by: OWNER_ID.to_string(),
            at: 9,
        })
    })
    .unwrap();
}

#[test]
fn a_missing_file_means_no_agents() {
    let home = Home::new();
    assert!(matches!(home.load(), AgentFile::Missing));
    assert!(!home.agent_file().exists(), "a load creates nothing");
}

#[test]
fn a_write_appends_one_audit_event_and_leaves_the_owner_file_otherwise_unchanged() {
    let home = Home::new();
    let owner_before = home.owner_json_without_audit();
    let events_before = home.audit().len();

    enable(&home);

    let bytes = home.agent_bytes();
    assert!(matches!(home.load(), AgentFile::Loaded(file) if file.sequence == 1));
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(home.agent_file())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o7777, 0o600, "the agent file is owner-only");

    let events = home.audit();
    assert_eq!(events.len(), events_before + 1, "one event per write");
    let event = events.last().unwrap();
    assert_eq!(event.event_type, "agent.records.enable");
    assert_eq!(event.principal_id.as_deref(), Some(OWNER_ID));
    assert_eq!(event.session_id.as_deref(), Some(SESSION_ID));
    assert_eq!(
        event.reason,
        format!("seq=1 sha256={}", hex::encode(Sha256::digest(&bytes)))
    );
    assert_eq!(
        home.owner_json_without_audit(),
        owner_before,
        "only the audit chain of the owner's file changed"
    );
    assert!(
        !home.owner_json().to_string().contains("owner_root"),
        "the owner's file holds no agent protection"
    );
}

#[test]
fn an_unknown_field_refuses_the_file() {
    let home = Home::new();
    let valid = as_json(&enabled_file(vec![stored_agent(OWNER_ID, AGENT_A)]));
    home.plant(&valid);
    assert!(matches!(home.load(), AgentFile::Loaded(_)), "the control");

    let mut top = valid.clone();
    top["pending"] = json!(null);
    home.plant(&top);
    assert_eq!(home.refusal(), NOT_OUR_FORM);

    let mut nested = valid.clone();
    nested["agents"][0]["record"]["nickname"] = json!("x");
    home.plant(&nested);
    assert_eq!(home.refusal(), NOT_OUR_FORM);

    let mut missing = valid;
    missing.as_object_mut().unwrap().remove("enabled");
    home.plant(&missing);
    assert_eq!(home.refusal(), NOT_OUR_FORM);
}

#[test]
fn an_unknown_schema_or_record_version_refuses_the_file() {
    let home = Home::new();
    let valid = as_json(&enabled_file(vec![stored_agent(OWNER_ID, AGENT_A)]));

    let mut schema = valid.clone();
    schema["schema"] = json!("elastos.agent.records/v2");
    home.plant(&schema);
    assert_eq!(home.refusal(), UNKNOWN_SCHEMA);

    let mut version = valid.clone();
    version["agents"][0]["record"]["version"] = json!(2);
    home.plant(&version);
    assert_eq!(home.refusal(), UNKNOWN_VERSION);

    let mut sequence = valid;
    sequence["sequence"] = json!(0);
    home.plant(&sequence);
    assert_eq!(home.refusal(), BAD_SEQUENCE);
}

#[test]
fn a_repeated_id_refuses_the_file() {
    let home = Home::new();
    let agent = stored_agent(OWNER_ID, AGENT_A);
    home.plant(&as_json(&enabled_file(vec![agent.clone(), agent])));
    assert_eq!(home.refusal(), REPEATED_ID);
}

#[test]
fn a_repeated_root_refuses_the_file() {
    let home = Home::new();
    let first = stored_agent(OWNER_ID, AGENT_A);
    let mut second = stored_agent(OWNER_ID, AGENT_B);
    second.record.localhost_root = first.record.localhost_root.clone();
    second.protection.localhost_root = first.record.localhost_root.clone();
    // A root is derived from its id, so the agent record rule would refuse
    // this file too. The uniqueness check alone, then the whole file:
    let agents = [first, second];
    assert_eq!(repeated_id_or_root(&agents), Some(REPEATED_ROOT));
    home.plant(&as_json(&enabled_file(agents.to_vec())));
    assert_eq!(home.refusal(), REPEATED_ROOT);
}

#[test]
fn a_mode_wider_than_0600_refuses_the_file() {
    let home = Home::new();
    home.plant(&as_json(&enabled_file(Vec::new())));
    assert!(matches!(home.load(), AgentFile::Loaded(_)), "the control");
    for mode in [0o640, 0o604, 0o700] {
        set_mode(&home.agent_file(), mode);
        assert_eq!(home.refusal(), MODE_TOO_WIDE, "mode {mode:o}");
    }
}

#[test]
fn a_path_that_is_not_a_regular_file_refuses() {
    let home = Home::new();
    let valid = as_json(&enabled_file(Vec::new()));
    home.plant(&valid);
    let elsewhere = home.path().join("elsewhere.json");
    std::fs::rename(home.agent_file(), &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, home.agent_file()).unwrap();
    assert_eq!(home.refusal(), NOT_REGULAR, "a symlink to a valid file");

    std::fs::remove_file(home.agent_file()).unwrap();
    std::fs::create_dir(home.agent_file()).unwrap();
    assert_eq!(home.refusal(), NOT_REGULAR, "a directory");
}

#[test]
fn a_linked_parent_folder_of_the_agent_file_refuses_the_file() {
    let home = Home::new();
    home.plant(&as_json(&enabled_file(Vec::new())));
    let owner_file = home.owner_file();
    assert!(matches!(home.load(), AgentFile::Loaded(_)), "the control");
    // The file stays a regular file at mode 0600; only its folder is a link.
    let folder = home.agent_file().parent().unwrap().to_path_buf();
    let moved = folder.with_file_name("Auth-moved");
    std::fs::rename(&folder, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &folder).unwrap();
    match load(home.path(), &owner_file).unwrap() {
        AgentFile::Unavailable(reason) => assert_eq!(reason, NOT_REGULAR),
        other => panic!("the file was not refused: {other:?}"),
    }
}

#[test]
fn a_record_that_fails_the_agent_record_rule_refuses_the_file() {
    let home = Home::new();
    home.plant(&as_json(&enabled_file(vec![stored_agent(
        "person:local:nobody",
        AGENT_A,
    )])));
    assert_eq!(home.refusal(), "agent admission owner missing");

    let mut admin = stored_agent(OWNER_ID, AGENT_A);
    admin.record.role = RuntimePrincipalRole::Admin;
    home.plant(&as_json(&enabled_file(vec![admin])));
    assert_eq!(home.refusal(), AGENT_IS_ADMIN);

    let mut person = stored_agent(OWNER_ID, AGENT_A);
    person.record.kind = PrincipalKind::Human;
    home.plant(&as_json(&enabled_file(vec![person])));
    assert_eq!(home.refusal(), NOT_AN_AGENT);
}

#[test]
fn a_protection_that_is_not_the_owner_root_wrap_refuses_the_file() {
    let home = Home::new();
    let cases: [(&str, EditAgent); 4] = [
        ("another kind", |agent| {
            agent.protection.protectors[0].kind = PrincipalRootProtectorKind::RecoveryPhrase
        }),
        ("another subject", |agent| {
            agent.protection.protectors[0].subject = Some("person:local:other".to_string())
        }),
        ("another root", |agent| {
            agent.protection.localhost_root =
                crate::auth::principal_kind_localhost_root(AGENT_B, PrincipalKind::Agent)
        }),
        ("two protectors", |agent| {
            let mut second = agent.protection.protectors[0].clone();
            second.protector_id.push_str("-b");
            agent.protection.protectors.push(second)
        }),
    ];
    for (name, edit) in cases {
        let mut agent = stored_agent(OWNER_ID, AGENT_A);
        edit(&mut agent);
        home.plant(&as_json(&enabled_file(vec![agent])));
        assert_eq!(home.refusal(), BAD_PROTECTION, "{name}");
    }
}

#[test]
fn an_id_or_root_the_sign_in_file_holds_refuses_the_file() {
    let home = Home::new();
    let mut agent = stored_agent(OWNER_ID, AGENT_A);
    agent.record.localhost_root = home.owner.localhost_root.clone();
    agent.protection.localhost_root = home.owner.localhost_root.clone();
    home.plant(&as_json(&enabled_file(vec![agent])));
    assert_eq!(home.refusal(), HELD_BY_OWNER_FILE);
}

#[test]
fn the_sequence_rises_by_exactly_one() {
    let home = Home::new();
    enable(&home);
    let written = home.agent_bytes();
    for jump in [0u64, 2] {
        let error = write_change(&home, Operation::Disable, |file| {
            file.sequence = 1 + jump;
            file.enabled = None;
        })
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "agent file change is not one Disable permits",
            "a sequence that moves by {jump}"
        );
        assert_eq!(home.agent_bytes(), written, "nothing was written");
    }
    write_change(&home, Operation::Disable, |file| file.enabled = None).unwrap();
    assert!(matches!(home.load(), AgentFile::Loaded(file) if file.sequence == 2));
    let reasons: Vec<String> = home
        .agent_events()
        .iter()
        .map(|event| event.reason[..6].to_string())
        .collect();
    assert_eq!(reasons, ["seq=1 ", "seq=2 "]);
}

#[test]
fn only_the_listed_operations_change_the_file() {
    let before = enabled_file(vec![
        stored_agent(OWNER_ID, AGENT_A),
        stored_agent(OWNER_ID, AGENT_B),
    ]);
    let next = |change: EditFile| {
        let mut after = before.clone();
        after.sequence += 1;
        change(&mut after);
        after
    };
    let retire_first = |file: &mut AgentRecordsFile| {
        file.agents[0].record.retired_at = Some(9);
        file.agents[0].record.updated_at = 9;
    };
    let add_third = |file: &mut AgentRecordsFile| {
        file.agents.push(stored_agent(
            OWNER_ID,
            "agent:v2:cccccccccccccccccccccccccccccccc",
        ))
    };
    let disabled = {
        let mut file = before.clone();
        file.enabled = None;
        file
    };

    // What each operation is for.
    assert!(permits(
        Operation::Disable,
        &before,
        &next(|file| file.enabled = None)
    ));
    assert!(permits(Operation::Create, &before, &next(add_third)));
    assert!(permits(Operation::Retire, &before, &next(retire_first)));
    let mut enabled_again = disabled.clone();
    enabled_again.sequence += 1;
    enabled_again.enabled = before.enabled.clone();
    assert!(permits(Operation::Enable, &disabled, &enabled_again));

    // Anything else, under each operation.
    let refused: [(Operation, EditFile, &str); 9] = [
        (Operation::Enable, |_| {}, "enable when already on"),
        (
            Operation::Disable,
            |file| {
                file.enabled = None;
                file.agents.pop();
            },
            "disable that drops an agent",
        ),
        (
            Operation::Create,
            |file| file.agents[0].record.display_name = "Renamed".to_string(),
            "create that edits an agent",
        ),
        (
            Operation::Create,
            |file| {
                file.agents.push(stored_agent(
                    OWNER_ID,
                    "agent:v2:cccccccccccccccccccccccccccccccc",
                ));
                file.enabled = None;
            },
            "create that turns agents off",
        ),
        (
            Operation::Create,
            |file| {
                let mut agent = stored_agent(OWNER_ID, "agent:v2:cccccccccccccccccccccccccccccccc");
                agent.record.retired_at = Some(9);
                file.agents.push(agent);
            },
            "create of a retired agent",
        ),
        (
            Operation::Retire,
            |file| {
                file.agents[0].record.retired_at = Some(9);
                file.agents[0].record.display_name = "Renamed".to_string();
            },
            "retire that renames",
        ),
        (
            Operation::Retire,
            |file| {
                file.agents[0].record.retired_at = Some(9);
                file.agents[1].record.retired_at = Some(9);
            },
            "retire of two agents",
        ),
        (
            Operation::Retire,
            |file| {
                file.agents[0].record.retired_at = Some(9);
                file.agents[0].protection.data_key_id = format!("pdek:{}", "1".repeat(32));
            },
            "retire that changes the protection",
        ),
        (
            Operation::Retire,
            |file| file.agents.swap(0, 1),
            "retire that reorders",
        ),
    ];
    for (operation, change, name) in refused {
        assert!(!permits(operation, &before, &next(change)), "{name}");
    }
    let mut retired = next(retire_first);
    let mut again = retired.clone();
    again.sequence += 1;
    again.agents[0].record.retired_at = Some(11);
    assert!(
        !permits(Operation::Retire, &retired, &again),
        "retire happens once"
    );
    retired.schema = "elastos.agent.records/v2".to_string();
    assert!(
        !permits(Operation::Retire, &before, &retired),
        "no operation changes the schema"
    );
}

#[test]
fn the_writer_refuses_a_change_its_operation_does_not_permit() {
    let home = Home::new();
    enable(&home);
    let written = home.agent_bytes();
    let events = home.audit().len();
    let error = write_change(&home, Operation::Disable, |file| {
        file.enabled = None;
        file.agents.push(stored_agent(OWNER_ID, AGENT_A));
    })
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "agent file change is not one Disable permits"
    );
    assert_eq!(home.agent_bytes(), written, "nothing was written");
    assert_eq!(home.audit().len(), events, "no event was appended");
}

#[test]
fn the_writer_never_writes_a_file_a_load_would_refuse() {
    let home = Home::new();
    enable(&home);
    let written = home.agent_bytes();
    let error = write_change(&home, Operation::Create, |file| {
        file.agents
            .push(stored_agent("person:local:nobody", AGENT_A))
    })
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "agent file change refused: agent admission owner missing"
    );
    assert_eq!(home.agent_bytes(), written, "nothing was written");
}

fn owner_protection(home: &Home) -> PrincipalRootProtectionV1 {
    crate::auth::load_principal_root_protection(
        home.path(),
        &home.owner.principal_id,
        &home.owner.localhost_root,
    )
    .unwrap()
    .unwrap()
}

/// The wrap key `auth` derives for `agent` under the stored person `owner`.
fn wrap_key(home: &Home, owner: &PrincipalRecord, agent: &PrincipalRootProtectionV1) -> [u8; 32] {
    *crate::auth::owner_root_wrap_key(
        home.path(),
        &owner.principal_id,
        &owner.localhost_root,
        agent,
    )
    .unwrap()
    .expect("the owner has storage protection")
}

/// A second person whose storage protection holds the same data key as the
/// Home's owner: their own Recovery Kit, wrapping the owner's key.
fn person_with_the_owners_data_key(home: &Home, principal_id: &str) -> PrincipalRecord {
    let owner = owner_protection(home);
    let archive = owner.protectors[0].archive.as_ref().unwrap();
    let mut kit = crate::auth::recovery_kit_from_archive(home.path(), archive).unwrap();
    let data_key = crate::auth::recovery_kit_data_key(&kit).unwrap();
    let person = crate::auth::store_test_human_principal(home.path(), principal_id);
    kit.principal_id = person.principal_id.clone();
    kit.localhost_root = person.localhost_root.clone();
    let salt = crate::auth::b64_url_decode(&kit.salt).unwrap();
    let nonce = crate::auth::b64_url_decode(&kit.nonce).unwrap();
    let wrapping = crate::auth::derive_recovery_wrapping_key(
        &kit.recovery_phrase,
        &salt,
        &kit.principal_id,
        &kit.localhost_root,
    )
    .unwrap();
    kit.wrapped_data_key =
        crate::auth::encrypt_aes256_gcm_bytes(&wrapping, &nonce, &data_key).unwrap();
    let descriptor = json!({
        "schema": "elastos.principal.root-descriptor/v1",
        "principal_id": kit.principal_id,
        "localhost_root": kit.localhost_root,
        "data_key_id": kit.data_key_id,
        "created_at": kit.created_at,
    });
    let descriptor_nonce = [3u8; 12];
    let sealed = crate::auth::encrypt_aes256_gcm_bytes(
        &data_key,
        &descriptor_nonce,
        &serde_json::to_vec(&descriptor).unwrap(),
    )
    .unwrap();
    kit.encrypted_root_descriptor = format!(
        "aes-256-gcm:v1:{}:{sealed}",
        crate::auth::b64_url(&descriptor_nonce)
    );
    crate::auth::verify_recovery_kit_material(&kit).unwrap();
    let mut protection = owner.clone();
    protection.principal_id = kit.principal_id.clone();
    protection.localhost_root = kit.localhost_root.clone();
    let protector = &mut protection.protectors[0];
    protector.archive = Some(crate::auth::recovery_archive_from_kit(home.path(), &kit).unwrap());
    protector.envelope.as_mut().unwrap().wrapped_data_key = kit.wrapped_data_key.clone();
    crate::auth::store_principal_root_protection(home.path(), protection).unwrap();
    person
}

/// Opens a wrap with `wrap_key`, as the key reader of a later step will.
fn unwrap_data_key(
    wrap_key: &[u8; 32],
    envelope: &PrincipalRootProtectorEnvelopeV1,
) -> anyhow::Result<Vec<u8>> {
    crate::auth::decrypt_aes256_gcm_bytes(
        wrap_key,
        &crate::auth::b64_url_decode(&envelope.nonce)?,
        &crate::auth::b64_url_decode(&envelope.wrapped_data_key)?,
    )
}

#[test]
fn the_wrap_key_binds_each_input() {
    let home = Home::new();
    let agent = stored_agent(OWNER_ID, AGENT_A).protection;
    let key = |agent: &PrincipalRootProtectionV1| wrap_key(&home, &home.owner, agent);
    let base = key(&agent);
    assert_eq!(key(&agent), base, "the same inputs give the same key");

    // Three pairs. Each differs from the base in one input only.
    let mut other_id = agent.clone();
    other_id.principal_id = AGENT_B.to_string();
    assert_ne!(key(&other_id), base, "the agent id is bound");

    let mut other_root = agent.clone();
    other_root.localhost_root =
        crate::auth::principal_kind_localhost_root(AGENT_B, PrincipalKind::Agent);
    assert_ne!(key(&other_root), base, "the agent root is bound");

    let mut other_key_id = agent.clone();
    other_key_id.data_key_id = format!("pdek:{}", "1".repeat(32));
    assert_ne!(key(&other_key_id), base, "the agent key id is bound");
}

#[test]
fn the_wrap_key_is_the_owners_alone() {
    let home = Home::new();
    let agent = stored_agent(OWNER_ID, AGENT_A).protection;
    let base = wrap_key(&home, &home.owner, &agent);

    let other = crate::auth::store_test_principal_root_protection(home.path(), "person:local:b");
    let other = crate::auth::stored_principal_record(home.path(), &other.principal_id)
        .unwrap()
        .unwrap();
    assert_ne!(
        wrap_key(&home, &other, &agent),
        base,
        "another person derives another key"
    );

    // A person with no storage protection derives nothing.
    let bare = crate::auth::store_test_human_principal(home.path(), "person:local:bare");
    let none = crate::auth::owner_root_wrap_key(
        home.path(),
        &bare.principal_id,
        &bare.localhost_root,
        &agent,
    );
    assert!(none.unwrap().is_none());
}

#[test]
fn the_wrap_key_binds_the_owner_id() {
    // Two people whose protections hold one and the same data key: only the
    // owner id differs between the two derivations.
    let home = Home::new();
    let twin = person_with_the_owners_data_key(&home, "person:local:twin");
    let twin_protection = crate::auth::load_principal_root_protection(
        home.path(),
        &twin.principal_id,
        &twin.localhost_root,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        twin_protection.data_key_id,
        owner_protection(&home).data_key_id,
        "the twin holds the owner's data key"
    );

    let root = crate::auth::principal_kind_localhost_root(AGENT_A, PrincipalKind::Agent);
    let wrapped = protect_agent_root(home.path(), &home.owner, AGENT_A, &root, 9)
        .unwrap()
        .unwrap();
    let envelope = wrapped.protectors[0].envelope.as_ref().unwrap();
    assert!(unwrap_data_key(&wrap_key(&home, &home.owner, &wrapped), envelope).is_ok());
    assert!(
        unwrap_data_key(&wrap_key(&home, &twin, &wrapped), envelope).is_err(),
        "the owner id is bound: the twin cannot open the owner's wrap"
    );
}

/// The owner's own protection with an owner-root wrap added to it.
fn owner_protection_carrying_a_wrap(home: &Home) -> PrincipalRootProtectionV1 {
    let mut protection = owner_protection(home);
    let wrap = stored_agent(OWNER_ID, AGENT_A).protection.protectors[0].clone();
    protection.protectors.push(wrap);
    assert!(validate_principal_root_protection(&protection).is_ok());
    protection
}

#[test]
fn the_sign_in_file_never_stores_an_owner_root_wrap() {
    let home = Home::new();
    let before = home.owner_json();
    let carrying = owner_protection_carrying_a_wrap(&home);
    let error = crate::auth::store_principal_root_protection(home.path(), carrying).unwrap_err();
    assert_eq!(error.to_string(), crate::auth::OWNER_ROOT_IN_SIGN_IN_FILE);
    assert_eq!(home.owner_json(), before, "nothing was stored");
    // The owner's own protection still stores and loads.
    let own = owner_protection(&home);
    crate::auth::store_principal_root_protection(home.path(), own.clone()).unwrap();
    assert_eq!(owner_protection(&home), own);
}

#[test]
fn a_sign_in_file_holding_an_owner_root_wrap_refuses_that_protection_only() {
    let home = Home::new();
    let other = crate::auth::store_test_principal_root_protection(home.path(), "person:local:b");
    // Written past the store, as another writer of the file might.
    crate::auth::plant_principal_root_protection(
        home.path(),
        &owner_protection_carrying_a_wrap(&home),
    );
    let (owner_id, owner_root) = (&home.owner.principal_id, &home.owner.localhost_root);
    let refused = crate::auth::load_principal_root_protection(home.path(), owner_id, owner_root);
    assert_eq!(
        refused.unwrap_err().to_string(),
        crate::auth::OWNER_ROOT_IN_SIGN_IN_FILE
    );
    // No wrap key is derived from it.
    let agent = stored_agent(OWNER_ID, AGENT_B).protection;
    assert!(crate::auth::owner_root_wrap_key(home.path(), owner_id, owner_root, &agent).is_err());
    // The file still loads, the owner still signs in, and another person's
    // protection is read as before.
    crate::auth::load_auth_state(home.path()).unwrap();
    let signed_in =
        crate::auth::load_principal_for_proof_binding(home.path(), &home.owner.proof_binding_id)
            .unwrap();
    assert_eq!(signed_in.principal_id, OWNER_ID);
    let theirs = crate::auth::load_principal_root_protection(
        home.path(),
        &other.principal_id,
        &other.localhost_root,
    );
    assert_eq!(theirs.unwrap(), Some(other));
}

#[test]
fn two_wraps_of_one_key_differ() {
    let (wrap_key, data_key) = ([7u8; 32], [9u8; 32]);
    let first = wrap_data_key(&wrap_key, &data_key).unwrap();
    let second = wrap_data_key(&wrap_key, &data_key).unwrap();
    assert_ne!(first.nonce, second.nonce, "each wrap draws its own nonce");
    assert_ne!(first.wrapped_data_key, second.wrapped_data_key);
    for envelope in [first, second] {
        assert_eq!(unwrap_data_key(&wrap_key, &envelope).unwrap(), data_key);
    }
}

#[test]
fn a_new_agent_protection_opens_under_its_own_derived_key_only() {
    let home = Home::new();
    let root = crate::auth::principal_kind_localhost_root(AGENT_A, PrincipalKind::Agent);
    let protection = protect_agent_root(home.path(), &home.owner, AGENT_A, &root, 9)
        .unwrap()
        .unwrap();
    let mut agent = stored_agent(OWNER_ID, AGENT_A);
    agent.protection = protection.clone();
    assert!(protection_is_sound(&agent), "create's protection loads");

    let envelope = protection.protectors[0].envelope.as_ref().unwrap();
    let data_key = unwrap_data_key(&wrap_key(&home, &home.owner, &protection), envelope).unwrap();
    assert_eq!(
        crate::auth::principal_data_key_id(&data_key),
        protection.data_key_id,
        "the wrap holds the key the protection names"
    );

    let mut other = protection.clone();
    other.principal_id = AGENT_B.to_string();
    assert!(
        unwrap_data_key(&wrap_key(&home, &home.owner, &other), envelope).is_err(),
        "a key derived for another agent opens nothing"
    );
}

/// The reason of a named refusal.
fn refusal_of<T: std::fmt::Debug>(result: anyhow::Result<T>) -> String {
    let error = result.expect_err("the operation was not refused");
    match error.downcast_ref::<Refused>() {
        Some(refused) => refused.0.clone(),
        None => panic!("not a named refusal: {error:#}"),
    }
}

fn turn_on(home: &Home) {
    assert!(set_enabled_in_any_build(home.path(), &home.caller(), true, 9).unwrap());
}

fn loaded(home: &Home) -> AgentRecordsFile {
    match home.load() {
        AgentFile::Loaded(file) => file,
        other => panic!("the agent file did not load: {other:?}"),
    }
}

#[test]
fn turning_agents_on_or_off_writes_once_and_names_the_owner() {
    let home = Home::new();
    assert!(!set_enabled_in_any_build(home.path(), &home.caller(), false, 9).unwrap());
    assert!(
        !home.agent_file().exists(),
        "off when already off writes nothing"
    );

    turn_on(&home);
    turn_on(&home);
    let file = loaded(&home);
    assert_eq!(file.sequence, 1, "on when already on writes nothing");
    assert_eq!(
        file.enabled,
        Some(Enabled {
            by: OWNER_ID.to_string(),
            at: 9
        })
    );

    assert!(!set_enabled_in_any_build(home.path(), &home.caller(), false, 11).unwrap());
    let file = loaded(&home);
    assert_eq!((file.sequence, file.enabled), (2, None));
    let events = home.agent_events();
    let seen: Vec<(&str, Option<&str>)> = events
        .iter()
        .map(|event| (event.event_type.as_str(), event.principal_id.as_deref()))
        .collect();
    assert_eq!(
        seen,
        [
            ("agent.records.enable", Some(OWNER_ID)),
            ("agent.records.disable", Some(OWNER_ID)),
        ]
    );
}

#[test]
fn only_an_admin_person_turns_agents_on() {
    let home = Home::new();
    let guest = crate::auth::store_test_human_principal(home.path(), "person:local:guest");
    let as_guest = Caller {
        principal_id: &guest.principal_id,
        proof_binding_id: &guest.proof_binding_id,
        session_id: SESSION_ID,
    };
    assert_eq!(
        refusal_of(set_enabled_in_any_build(home.path(), &as_guest, true, 9)),
        NOT_AN_ADMIN
    );
    // The admin's id on a binding that is not theirs is no stored person.
    let wrong_binding = Caller {
        proof_binding_id: &guest.proof_binding_id,
        ..home.caller()
    };
    assert_eq!(
        refusal_of(set_enabled_in_any_build(
            home.path(),
            &wrong_binding,
            true,
            9
        )),
        NOT_A_PERSON
    );
    assert!(!home.agent_file().exists(), "a refusal writes nothing");
}

fn request(request_id: &str) -> CreateRequest {
    CreateRequest {
        display_name: "Helper".to_string(),
        agent_host: "agent-host".to_string(),
        request_id: request_id.to_string(),
    }
}

/// Stands in for the Agent Host check, which has its own tests.
fn admit(agent_host: &str) -> anyhow::Result<VerifiedAgentHost> {
    Ok(VerifiedAgentHost::unchecked_for_test(
        agent_host,
        "bafyagenthost",
        "bafyagenthostbytes",
    ))
}

fn create_as(home: &Home, caller: &Caller<'_>, request_id: &str) -> anyhow::Result<AgentView> {
    create_in_any_build(home.path(), caller, &request(request_id), admit, 9)
}

fn create_one(home: &Home, request_id: &str) -> AgentView {
    create_as(home, &home.caller(), request_id).unwrap()
}

/// A second admin person with storage protection, in the same Home.
fn second_person(home: &Home, principal_id: &str) -> PrincipalRecord {
    crate::auth::store_test_principal_root_protection(home.path(), principal_id);
    make_admin(home.path(), principal_id);
    crate::auth::stored_principal_record(home.path(), principal_id)
        .unwrap()
        .unwrap()
}

fn caller_of(person: &PrincipalRecord) -> Caller<'_> {
    Caller {
        principal_id: &person.principal_id,
        proof_binding_id: &person.proof_binding_id,
        session_id: SESSION_ID,
    }
}

/// A valid Home with agents on and one agent, written with no feature check,
/// so a build without the feature can be shown a file it would otherwise
/// serve. Returns the agent's id.
#[cfg(not(feature = "prototype-agents"))]
pub(crate) fn plant_enabled_home_with_one_agent(
    data_dir: &Path,
    principal_id: &str,
    proof_binding_id: &str,
) -> String {
    let caller = Caller {
        principal_id,
        proof_binding_id,
        session_id: SESSION_ID,
    };
    set_enabled_in_any_build(data_dir, &caller, true, 9).unwrap();
    create_in_any_build(data_dir, &caller, &request("request-fixture"), admit, 9)
        .unwrap()
        .agent_id
}

#[test]
fn a_create_leaves_one_record_and_one_protection_in_the_agent_file_only() {
    let home = Home::new();
    turn_on(&home);
    let owner_before = home.owner_json_without_audit();
    let created = create_one(&home, "request-1");

    let file = loaded(&home);
    let [agent] = file.agents.as_slice() else {
        panic!("one agent is stored");
    };
    let record = &agent.record;
    assert_eq!(view(agent), created);
    assert!(crate::auth::validate_agent_id(&record.principal_id).is_ok());
    assert_eq!(record.owner.as_deref(), Some(OWNER_ID));
    assert_eq!(record.kind, PrincipalKind::Agent);
    assert_eq!(record.role, RuntimePrincipalRole::Guest);
    assert_eq!(record.proof_binding.kind, ProofBindingKind::AgentAdmission);
    assert_eq!(record.proof_binding.subject, record.principal_id);
    assert_eq!(
        record.localhost_root,
        crate::auth::principal_kind_localhost_root(&record.principal_id, PrincipalKind::Agent)
    );
    assert_eq!(record.request_id.as_deref(), Some("request-1"));
    assert_eq!(record.display_name, "Helper");
    assert_eq!(
        record.agent_host_package,
        Some(AgentHostPackage {
            name: "agent-host".to_string(),
            registry_cid: "bafyagenthost".to_string(),
            bundle_cid: "bafyagenthostbytes".to_string(),
        })
    );
    assert_eq!((record.retired_at, record.version), (None, 1));

    // The one protection opens under the owner's derived key.
    let protection = &agent.protection;
    let envelope = protection.protectors[0].envelope.as_ref().unwrap();
    let data_key = unwrap_data_key(&wrap_key(&home, &home.owner, protection), envelope).unwrap();
    assert_eq!(
        crate::auth::principal_data_key_id(&data_key),
        protection.data_key_id
    );

    // The owner's file gained an audit event and nothing else.
    assert_eq!(home.owner_json_without_audit(), owner_before);
    let owner_json = home.owner_json();
    assert!(!owner_json.to_string().contains("\"owner_root\""));
    for stored in ["principals", "principal_root_protections", "sessions"] {
        assert!(
            !owner_json[stored]
                .to_string()
                .contains(&record.principal_id),
            "the owner's {stored} do not name the agent"
        );
    }
    let events = home.agent_events();
    let event = events.last().unwrap();
    assert_eq!(event.event_type, "agent.record.create");
    assert_eq!(
        event.principal_id.as_deref(),
        Some(record.principal_id.as_str())
    );
    assert_eq!(
        event.proof_binding_id.as_deref(),
        Some(home.owner.proof_binding_id.as_str())
    );
    assert_eq!(event.session_id.as_deref(), Some(SESSION_ID));
    let digest = hex::encode(Sha256::digest(home.agent_bytes()));
    assert_eq!(event.reason, format!("seq=2 sha256={digest}"));
    assert_eq!(events.len(), 2, "one event for enable and one for create");
}

#[test]
fn a_failed_save_leaves_neither_the_record_nor_the_protection() {
    let home = Home::new();
    turn_on(&home);
    let written = home.agent_bytes();
    let auth_dir = home.agent_file().parent().unwrap().to_path_buf();
    set_mode(&auth_dir, 0o500);
    let result = create_as(&home, &home.caller(), "request-1");
    set_mode(&auth_dir, 0o700);
    assert!(result.is_err(), "the save failed");
    assert_eq!(home.agent_bytes(), written);
    assert!(loaded(&home).agents.is_empty());
    assert_eq!(home.agent_events().len(), 1, "no create event");
}

#[test]
fn the_same_request_returns_the_same_agent_and_a_changed_body_is_refused() {
    let home = Home::new();
    turn_on(&home);
    let first = create_one(&home, "request-1");
    let written = home.agent_bytes();
    let events = home.audit().len();

    assert_eq!(create_one(&home, "request-1"), first);
    assert_eq!(home.agent_bytes(), written, "a repeat writes nothing");
    assert_eq!(home.audit().len(), events, "a repeat appends no event");

    for change in [
        (|body: &mut CreateRequest| body.display_name = "Other".to_string())
            as fn(&mut CreateRequest),
        |body| body.agent_host = "other-host".to_string(),
    ] {
        let mut body = request("request-1");
        change(&mut body);
        let result = create_in_any_build(home.path(), &home.caller(), &body, admit, 9);
        assert_eq!(refusal_of(result), REQUEST_ID_REUSED);
    }
    assert_eq!(home.agent_bytes(), written);

    // The same owner, name and package under another request id: a new agent.
    let second = create_one(&home, "request-2");
    assert_ne!(second.agent_id, first.agent_id);
    let file = loaded(&home);
    assert_ne!(
        file.agents[0].record.localhost_root,
        file.agents[1].record.localhost_root
    );

    // A request id belongs to its owner: another person may use the same one.
    let other = second_person(&home, "person:local:other-owner");
    let theirs = create_as(&home, &caller_of(&other), "request-1").unwrap();
    assert_ne!(theirs.agent_id, first.agent_id);
}

#[test]
fn two_racing_creates_with_one_request_id_leave_one_agent() {
    let home = Home::new();
    turn_on(&home);
    let ids: Vec<String> = std::thread::scope(|scope| {
        let racers: Vec<_> = (0..2)
            .map(|_| scope.spawn(|| create_one(&home, "request-1").agent_id))
            .collect();
        racers
            .into_iter()
            .map(|racer| racer.join().unwrap())
            .collect()
    });
    assert_eq!(ids[0], ids[1]);
    let file = loaded(&home);
    assert_eq!((file.agents.len(), file.sequence), (1, 2));
}

#[test]
fn create_refuses_each_caller_and_request_it_should() {
    let home = Home::new();
    let asked = std::cell::Cell::new(0);
    let counted_admit = |agent_host: &str| {
        asked.set(asked.get() + 1);
        admit(agent_host)
    };

    // Agents are off.
    let result = create_in_any_build(home.path(), &home.caller(), &request("r"), counted_admit, 9);
    assert_eq!(refusal_of(result), NOT_ENABLED);
    assert!(!home.agent_file().exists());
    turn_on(&home);
    let agent = create_one(&home, "request-1");
    let written = home.agent_bytes();

    // An agent is never the caller.
    let stored = loaded(&home).agents[0].record.clone();
    let as_agent = Caller {
        principal_id: &stored.principal_id,
        proof_binding_id: &stored.proof_binding_id,
        session_id: SESSION_ID,
    };
    let result = create_in_any_build(home.path(), &as_agent, &request("r"), counted_admit, 9);
    assert_eq!(refusal_of(result), NOT_A_PERSON);
    assert_eq!(
        refusal_of(set_enabled_in_any_build(home.path(), &as_agent, false, 9)),
        NOT_A_PERSON
    );
    assert_eq!(
        refusal_of(list_in_any_build(home.path(), &as_agent)),
        NOT_A_PERSON
    );

    // A person with no storage protection.
    let bare = crate::auth::store_test_human_principal(home.path(), "person:local:bare");
    let result = create_in_any_build(
        home.path(),
        &caller_of(&bare),
        &request("r"),
        counted_admit,
        9,
    );
    assert_eq!(refusal_of(result), OWNER_UNPROTECTED);

    // A field that is empty, too long or malformed.
    let bad: [fn(&mut CreateRequest); 6] = [
        |body| body.display_name = String::new(),
        |body| body.display_name = " padded ".to_string(),
        |body| body.display_name = "two\nlines".to_string(),
        |body| body.display_name = "n".repeat(65),
        |body| body.agent_host = "../agent-host".to_string(),
        |body| body.request_id = String::new(),
    ];
    for (index, change) in bad.into_iter().enumerate() {
        let mut body = request("r");
        change(&mut body);
        let result = create_in_any_build(home.path(), &home.caller(), &body, counted_admit, 9);
        assert_eq!(refusal_of(result), BAD_REQUEST, "case {index}");
    }
    assert_eq!(asked.get(), 0, "the Agent Host is checked last");

    // The Agent Host check refuses.
    let result = create_in_any_build(
        home.path(),
        &home.caller(),
        &request("r"),
        |_| refused("agent host refused"),
        9,
    );
    assert_eq!(refusal_of(result), "agent host refused");

    assert_eq!(home.agent_bytes(), written, "no refusal wrote anything");
    assert_eq!(
        list_in_any_build(home.path(), &home.caller()).unwrap(),
        [agent]
    );
}

#[test]
fn an_owner_at_the_limit_creates_no_more() {
    let home = Home::new();
    turn_on(&home);
    let agents: Vec<AgentView> = (0..MAX_LIVE_AGENTS_PER_OWNER)
        .map(|index| create_one(&home, &format!("request-{index}")))
        .collect();
    assert_eq!(
        refusal_of(create_as(&home, &home.caller(), "request-more")),
        AT_THE_LIMIT
    );
    assert_eq!(
        create_one(&home, "request-0"),
        agents[0],
        "a repeat still returns its agent at the limit"
    );
    // The limit is each owner's own.
    let other = second_person(&home, "person:local:other-owner");
    create_as(&home, &caller_of(&other), "request-0").unwrap();
    assert_eq!(
        list_in_any_build(home.path(), &caller_of(&other))
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        list_in_any_build(home.path(), &home.caller()).unwrap(),
        agents
    );
}

#[test]
fn create_never_reuses_an_id_or_a_root_any_record_holds() {
    // A unit row on the one function create asks: create draws its own
    // random id, so no route can produce a collision.
    let home = Home::new();
    let mut tombstone = stored_agent(OWNER_ID, AGENT_A);
    tombstone.record.retired_at = Some(7);
    let opened = Opened {
        lock: None,
        owner_file: home.owner_file(),
        file: enabled_file(vec![tombstone.clone()]),
    };
    assert!(id_or_root_held(&opened, &tombstone.record), "a retired id");
    let mut same_root = stored_agent(OWNER_ID, AGENT_B).record;
    same_root.localhost_root = tombstone.record.localhost_root.clone();
    assert!(id_or_root_held(&opened, &same_root), "a retired root");
    let mut persons_root = stored_agent(OWNER_ID, AGENT_B).record;
    persons_root.localhost_root = home.owner.localhost_root.clone();
    assert!(id_or_root_held(&opened, &persons_root), "a person's root");
    assert!(!id_or_root_held(
        &opened,
        &stored_agent(OWNER_ID, AGENT_B).record
    ));
}

#[test]
fn a_create_request_has_three_fields_and_no_other() {
    let parse = |body: Value| serde_json::from_value::<CreateRequest>(body);
    let full = json!({"display_name": "Helper", "agent_host": "agent-host", "request_id": "r"});
    assert_eq!(parse(full.clone()).unwrap(), request("r"));
    for extra in ["owner", "agent_id", "kind"] {
        let mut body = full.clone();
        body[extra] = json!("person:local:someone");
        assert!(parse(body).is_err(), "an unknown field: {extra}");
    }
    for missing in ["display_name", "agent_host", "request_id"] {
        let mut body = full.clone();
        body.as_object_mut().unwrap().remove(missing);
        assert!(parse(body).is_err(), "a missing field: {missing}");
    }
}

#[test]
fn retire_happens_once_and_only_for_the_owner() {
    let home = Home::new();
    turn_on(&home);
    let agent = create_one(&home, "request-1");
    let other = second_person(&home, "person:local:other-owner");

    // Another person's agent answers as an unknown id does.
    for (caller, id) in [
        (caller_of(&other), agent.agent_id.as_str()),
        (home.caller(), AGENT_A),
    ] {
        let result = retire_in_any_build(home.path(), &caller, id, 11);
        assert_eq!(refusal_of(result), NO_SUCH_AGENT);
    }
    assert!(list_in_any_build(home.path(), &caller_of(&other))
        .unwrap()
        .is_empty());

    let retired = retire_in_any_build(home.path(), &home.caller(), &agent.agent_id, 11).unwrap();
    assert_eq!(retired.retired_at, Some(11));
    let file = loaded(&home);
    let record = &file.agents[0].record;
    assert_eq!((record.retired_at, record.updated_at), (Some(11), 11));
    assert_eq!(record.created_at, 9);
    let event = home.agent_events().pop().unwrap();
    assert_eq!(event.event_type, "agent.record.retire");
    assert_eq!(event.principal_id.as_deref(), Some(agent.agent_id.as_str()));
    assert_eq!(event.reason[..6], *"seq=3 ");

    let written = home.agent_bytes();
    let again = retire_in_any_build(home.path(), &home.caller(), &agent.agent_id, 12);
    assert_eq!(refusal_of(again), ALREADY_RETIRED);
    assert_eq!(
        home.agent_bytes(),
        written,
        "a second retire writes nothing"
    );

    // The tombstone stays listed, and still holds its id and root.
    assert_eq!(
        list_in_any_build(home.path(), &home.caller()).unwrap(),
        [retired]
    );
}

#[test]
fn a_retired_agent_no_longer_counts_toward_the_limit() {
    let home = Home::new();
    turn_on(&home);
    let first = create_one(&home, "request-0");
    for index in 1..MAX_LIVE_AGENTS_PER_OWNER {
        create_one(&home, &format!("request-{index}"));
    }
    assert_eq!(
        refusal_of(create_as(&home, &home.caller(), "request-more")),
        AT_THE_LIMIT
    );
    retire_in_any_build(home.path(), &home.caller(), &first.agent_id, 11).unwrap();
    create_one(&home, "request-more");
}

#[test]
fn with_agents_off_every_use_refuses_and_the_records_are_kept() {
    let home = Home::new();
    let no_file = list_in_any_build(home.path(), &home.caller());
    assert_eq!(refusal_of(no_file), NOT_ENABLED, "no file at all");

    turn_on(&home);
    let agent = create_one(&home, "request-1");
    set_enabled_in_any_build(home.path(), &home.caller(), false, 11).unwrap();
    let written = home.agent_bytes();
    assert_eq!(
        loaded(&home).agents.len(),
        1,
        "turning off keeps the record"
    );

    assert_eq!(
        refusal_of(create_as(&home, &home.caller(), "request-2")),
        NOT_ENABLED
    );
    assert_eq!(
        refusal_of(list_in_any_build(home.path(), &home.caller())),
        NOT_ENABLED
    );
    let retire = retire_in_any_build(home.path(), &home.caller(), &agent.agent_id, 12);
    assert_eq!(refusal_of(retire), NOT_ENABLED);
    assert_eq!(home.agent_bytes(), written);

    turn_on(&home);
    assert_eq!(
        list_in_any_build(home.path(), &home.caller()).unwrap(),
        [agent]
    );
}

#[test]
fn a_refused_file_keeps_its_bytes_and_refuses_every_operation() {
    let home = Home::new();
    turn_on(&home);
    let agent = create_one(&home, "request-1");
    let mut value: Value = serde_json::from_slice(&home.agent_bytes()).unwrap();
    value["pending"] = json!(null);
    home.plant(&value);
    let planted = home.agent_bytes();
    let events = home.audit().len();
    let unavailable = format!("agents are unavailable: {NOT_OUR_FORM}");
    let caller = home.caller();

    let on = set_enabled_in_any_build(home.path(), &caller, true, 12);
    assert_eq!(refusal_of(on), unavailable);
    let off = set_enabled_in_any_build(home.path(), &caller, false, 12);
    assert_eq!(refusal_of(off), unavailable);
    assert_eq!(
        refusal_of(create_as(&home, &caller, "request-2")),
        unavailable
    );
    assert_eq!(
        refusal_of(create_as(&home, &caller, "request-1")),
        unavailable
    );
    let retire = retire_in_any_build(home.path(), &caller, &agent.agent_id, 12);
    assert_eq!(refusal_of(retire), unavailable);
    assert_eq!(
        refusal_of(list_in_any_build(home.path(), &caller)),
        unavailable
    );

    assert_eq!(home.agent_bytes(), planted, "the file is never rewritten");
    assert_eq!(home.audit().len(), events, "no event was appended");
    // The owner's own load is as before.
    let state = crate::auth::load_auth_state(home.path()).unwrap();
    assert!(state
        .principals
        .iter()
        .any(|principal| principal.principal_id == OWNER_ID));
    assert_eq!(owner_protection(&home).principal_id, OWNER_ID);
}

#[cfg(not(feature = "prototype-agents"))]
#[test]
fn with_the_feature_off_every_operation_refuses_by_name() {
    assert!(!build_allows());
    let home = Home::new();
    let caller = home.caller();
    let agent_id = plant_enabled_home_with_one_agent(
        home.path(),
        caller.principal_id,
        caller.proof_binding_id,
    );
    assert_eq!(
        loaded(&home).agents.len(),
        1,
        "a valid enabled file is on disk"
    );
    let written = home.agent_bytes();
    let events = home.audit().len();

    assert_eq!(
        refusal_of(set_enabled(home.path(), &caller, true, 12)),
        FEATURE_OFF
    );
    assert_eq!(
        refusal_of(set_enabled(home.path(), &caller, false, 12)),
        FEATURE_OFF
    );
    let created = create(home.path(), &caller, &request("request-2"), admit, 12);
    assert_eq!(refusal_of(created), FEATURE_OFF);
    assert_eq!(refusal_of(list(home.path(), &caller)), FEATURE_OFF);
    assert_eq!(
        refusal_of(retire(home.path(), &caller, &agent_id, 12)),
        FEATURE_OFF
    );

    assert_eq!(home.agent_bytes(), written);
    assert_eq!(home.audit().len(), events);
}

#[cfg(feature = "prototype-agents")]
#[test]
fn with_the_feature_on_the_operations_are_served() {
    assert!(build_allows());
    let home = Home::new();
    let caller = home.caller();
    assert_eq!(refusal_of(list(home.path(), &caller)), NOT_ENABLED);
    assert!(set_enabled(home.path(), &caller, true, 9).unwrap());
    let agent = create(home.path(), &caller, &request("request-1"), admit, 9).unwrap();
    assert_eq!(
        list(home.path(), &caller).unwrap(),
        std::slice::from_ref(&agent)
    );
    let retired = retire(home.path(), &caller, &agent.agent_id, 11).unwrap();
    assert_eq!(retired.retired_at, Some(11));
    assert!(!set_enabled(home.path(), &caller, false, 12).unwrap());
}

/// Every `.rs` file under `dir` that is not test code, with its text.
fn production_sources(dir: &Path, found: &mut Vec<(PathBuf, String)>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if name.contains("tests") || name.starts_with("test_") {
            continue;
        }
        if path.is_dir() {
            production_sources(&path, found);
        } else if name.ends_with(".rs") {
            let text = std::fs::read_to_string(&path).unwrap();
            found.push((path, text));
        }
    }
}

#[test]
fn the_cargo_feature_is_read_in_one_place() {
    let mut sources = Vec::new();
    production_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut sources,
    );
    assert!(sources.len() > 100, "the walk found the crate's sources");
    let name = ["prototype", "-agents"].concat();
    let readers: Vec<(String, usize)> = sources
        .iter()
        .map(|(path, text)| {
            let file = path.file_name().unwrap().to_string_lossy().to_string();
            (file, text.matches(&name).count())
        })
        .filter(|(_, count)| *count > 0)
        .collect();
    assert_eq!(readers, [("agents.rs".to_string(), 1)]);
}

#[test]
fn the_agent_files_name_no_owner_key_function_and_read_no_environment() {
    let sources = [
        ("agents.rs", include_str!("../agents.rs")),
        ("agent_admission.rs", include_str!("../agent_admission.rs")),
        (
            "gateway_agents.rs",
            include_str!("../api/gateway_agents.rs"),
        ),
    ];
    // Every function of `auth` that returns the owner's key, a key that
    // opens it, a fresh secret, or the material a person recovers with.
    let key_functions = [
        "principal_root_data_key_from_protection",
        "load_or_create_recovery_archive_key",
        "recovery_kit_from_archive",
        "recovery_kit_data_key",
        "derive_recovery_wrapping_key",
        "random_secret_hex",
        "recovery_archive_from_kit",
        "decrypt_aes256_gcm_bytes",
        "decrypt_root_descriptor",
        "arm_owner_recovery",
        "check_owner_recovery_code",
        "complete_owner_recovery",
        "attach_recovery_archive",
        "verify_recovery_kit_material",
        // The owner's protection record: it carries the encrypted Recovery Kit.
        "load_principal_root_protection",
        "principal_root_protections",
        "encrypted_recovery_kit",
        // The whole sign-in file holds the protection list; the agents
        // module reads only `load_owner_principals`.
        "load_auth_state",
    ];
    // Broader than the names: no word for opening a ciphertext, and nothing
    // of the person's kit or code.
    let words = [
        "decrypt",
        "recovery_kit",
        "recovery_archive",
        "recovery_code",
        "owner_recovery",
        "RecoveryKit",
        "data_key_from",
    ];
    let environment = ["env::", "var_os", "env!(", "option_env!"];
    // An inline test module is test code, not the module's own.
    let sources = sources.map(|(name, source)| {
        let production = source.split("#[cfg(test)]\npub(crate) mod tests {");
        (name, production.into_iter().next().unwrap())
    });
    for (name, source) in sources {
        for forbidden in key_functions.iter().chain(&words).chain(&environment) {
            assert!(!source.contains(forbidden), "{name} names `{forbidden}`");
        }
    }
    // The one key function they may call returns a derived key only.
    let calls: Vec<usize> = sources
        .iter()
        .map(|(_, source)| source.matches("owner_root_wrap_key(").count())
        .collect();
    assert_eq!(calls, [1, 0, 0]);
}

#[test]
fn an_audit_chain_holding_agent_events_checks_with_the_frozen_code() {
    let home = Home::new();
    turn_on(&home);
    let agent = create_one(&home, "request-1");
    retire_in_any_build(home.path(), &home.caller(), &agent.agent_id, 11).unwrap();
    set_enabled_in_any_build(home.path(), &home.caller(), false, 12).unwrap();

    let path = crate::auth::auth_state_path(home.path()).unwrap();
    let stored: frozen_audit::FrozenAuditState =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let (_, runtime_did) = elastos_identity::load_or_create_did(home.path()).unwrap();
    frozen_audit::verify_audit_chain_from(&runtime_did, &stored)
        .expect("the frozen check accepts a chain that holds agent events");

    let agent_events: Vec<&str> = stored
        .audit
        .iter()
        .map(|event| event.event_type.as_str())
        .filter(|event_type| event_type.starts_with("agent."))
        .collect();
    assert_eq!(
        agent_events,
        [
            "agent.records.enable",
            "agent.record.create",
            "agent.record.retire",
            "agent.records.disable",
        ]
    );
    // Each stored event has exactly the frozen event's fields.
    let ours = serde_json::to_value(home.audit()).unwrap();
    assert_eq!(serde_json::to_value(&stored.audit).unwrap(), ours);
}

/// The launch lookup: one stored agent of the launcher's own, enabled and not
/// retired, and nothing else. The root reader the bridge calls gives the same
/// record, and the protection the sign-in loader keeps apart.
#[cfg(feature = "prototype-agents")]
#[test]
fn a_launch_finds_only_its_owners_enabled_unretired_agent() {
    let home = Home::new();
    turn_on(&home);
    let agent = create_one(&home, "request-1");
    let stored = crate::agents::stored_agent(home.path(), OWNER_ID, &agent.agent_id).unwrap();
    assert_eq!(stored.record.principal_id, agent.agent_id);
    assert_eq!(stored.record.owner.as_deref(), Some(OWNER_ID));
    let root =
        crate::auth::principal_stored_localhost_root(Some(home.path()), &agent.agent_id).unwrap();
    let by_root = stored_agent_for_root(home.path(), &agent.agent_id, &root)
        .unwrap()
        .expect("the root reader finds the same agent");
    assert_eq!(by_root.record.principal_id, agent.agent_id);
    let protection = stored_protection(home.path(), &agent.agent_id, &root)
        .unwrap()
        .expect("the agent's protection is in the file");
    assert_eq!(protection.principal_id, agent.agent_id);

    // A stored person who does not own it sees nothing, and so does a
    // person the Home does not hold.
    crate::auth::store_test_principal_root_protection(home.path(), "person:local:a5-other");
    assert_eq!(
        crate::agents::stored_agent(home.path(), "person:local:a5-other", &agent.agent_id)
            .unwrap_err()
            .to_string(),
        NO_SUCH_AGENT
    );
    assert_eq!(
        crate::agents::stored_agent(home.path(), "person:local:a5-stranger", &agent.agent_id)
            .unwrap_err()
            .to_string(),
        NOT_A_PERSON
    );
    assert_eq!(
        crate::agents::stored_agent(home.path(), OWNER_ID, AGENT_B)
            .unwrap_err()
            .to_string(),
        NO_SUCH_AGENT
    );

    // Retired and turned off are both no agent.
    retire_in_any_build(home.path(), &home.caller(), &agent.agent_id, 11).unwrap();
    assert_eq!(
        crate::agents::stored_agent(home.path(), OWNER_ID, &agent.agent_id)
            .unwrap_err()
            .to_string(),
        NO_SUCH_AGENT
    );
    set_enabled_in_any_build(home.path(), &home.caller(), false, 12).unwrap();
    assert_eq!(
        crate::agents::stored_agent(home.path(), OWNER_ID, &agent.agent_id)
            .unwrap_err()
            .to_string(),
        NOT_ENABLED
    );
}

#[cfg(not(feature = "prototype-agents"))]
#[test]
fn with_the_feature_off_the_launch_lookup_refuses_by_name() {
    let home = Home::new();
    let caller = home.caller();
    let agent_id = plant_enabled_home_with_one_agent(
        home.path(),
        caller.principal_id,
        caller.proof_binding_id,
    );
    assert_eq!(loaded(&home).agents.len(), 1);
    assert_eq!(
        crate::agents::stored_agent(home.path(), OWNER_ID, &agent_id)
            .unwrap_err()
            .to_string(),
        FEATURE_OFF
    );
    // The root reader answers nothing rather than an error: a save that
    // carries a stored agent must not fail on the Home's own setting.
    assert!(stored_agent_for_root(
        home.path(),
        &agent_id,
        &crate::auth::principal_kind_localhost_root(&agent_id, PrincipalKind::Agent),
    )
    .unwrap()
    .is_none());
}

/// A Home with agents on and `count` real agents, each with its own wrap.
/// `bundle_cid` is the CID creation stores for the Agent Host's bytes, from the
/// one walk the Runtime uses.
#[cfg(feature = "prototype-agents")]
fn home_with_agents(count: usize, bundle_cid: &str) -> (crate::agents::tests::Home, Vec<String>) {
    let home = crate::agents::tests::Home::new();
    let caller = home.caller();
    crate::agents::set_enabled(home.path(), &caller, true, 1).unwrap();
    let agents = (0..count)
        .map(|index| {
            crate::agents::create(
                home.path(),
                &caller,
                &crate::agents::CreateRequest {
                    display_name: format!("Agent {index}"),
                    agent_host: crate::agent_admission::tests::AGENT_HOST.to_string(),
                    request_id: format!("request-{index}"),
                },
                |host| {
                    Ok(
                        crate::agent_admission::VerifiedAgentHost::unchecked_for_test(
                            host,
                            crate::agent_admission::tests::AGENT_HOST_CID,
                            bundle_cid,
                        ),
                    )
                },
                1,
            )
            .unwrap()
            .agent_id
        })
        .collect();
    (home, agents)
}

/// One Agent Host capsule folder: a manifest that declares the agent kind and a
/// component, the entrypoint bytes, and an `.elastos-cid` receipt. Returns the
/// folder and the CID the Runtime's own walk gives its bytes.
#[cfg(feature = "prototype-agents")]
fn host_capsule(name: &str, entrypoint: &[u8]) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("capsule.json"),
        serde_json::json!({
            "schema": "elastos.capsule/v1",
            "version": "0.1.0",
            "name": name,
            "role": "app",
            "type": "wasm",
            "runtime_abi": "elastos.component/v1",
            "bus_contract": "elastos:bus@v1",
            "wit_world_sha256": "7a026e0a641c8c04214576dc85a677e0b52c9f02866d231119f9a3ba609d49e2",
            "execution": "component",
            "entrypoint": "main.wasm",
            "agent": {"kind": "agent"}
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(dir.path().join("main.wasm"), entrypoint).unwrap();
    let cid = crate::stage_cmd::bundle_cid(dir.path()).unwrap();
    std::fs::write(dir.path().join(".elastos-cid"), format!("{cid}\n")).unwrap();
    let cid = crate::stage_cmd::bundle_cid(dir.path()).unwrap();
    (dir, cid)
}

/// Two stored agents of one owner admit two actors, and each actor owns
/// the `UsersAI` root its own id derives. The owner's launch with no agent
/// stays unbound.
#[cfg(feature = "prototype-agents")]
#[test]
fn an_agent_launch_admits_each_agents_own_actor_and_root() {
    let (host, host_cid) = host_capsule(
        crate::agent_admission::tests::AGENT_HOST,
        b"agent host entrypoint",
    );
    let (home, agents) = home_with_agents(2, &host_cid);
    let caller = home.caller();
    let first = crate::agent_admission::admit_launch(
        home.path(),
        home.path(),
        host.path(),
        Some(caller.principal_id),
        Some(agents[0].as_str()),
    )
    .unwrap()
    .unwrap();
    let second = crate::agent_admission::admit_launch(
        home.path(),
        home.path(),
        host.path(),
        Some(caller.principal_id),
        Some(agents[1].as_str()),
    )
    .unwrap()
    .unwrap();
    assert_eq!(first.actor, agents[0]);
    assert_eq!(second.actor, agents[1]);
    assert_ne!(first.actor, second.actor);
    let root =
        |id: &str| crate::auth::principal_stored_localhost_root(Some(home.path()), id).unwrap();
    assert_ne!(root(&agents[0]), root(&agents[1]));
    for id in &agents {
        let own = root(id);
        assert!(own.starts_with("localhost://UsersAI/"), "{own}");
        assert_eq!(root(&first.actor), root(&agents[0]));
    }
    assert!(crate::agent_admission::admit_launch(
        home.path(),
        home.path(),
        host.path(),
        Some(caller.principal_id),
        None
    )
    .unwrap()
    .is_none());
}

/// A launcher who does not own the agent is refused, whether that person
/// is stored with no agents or is no stored person at all.
#[cfg(feature = "prototype-agents")]
#[test]
fn an_agent_launch_refuses_a_launcher_who_does_not_own_the_agent() {
    let (host, host_cid) = host_capsule(
        crate::agent_admission::tests::AGENT_HOST,
        b"agent host entrypoint",
    );
    let (home, agents) = home_with_agents(1, &host_cid);
    crate::auth::store_test_principal_root_protection(home.path(), "person:local:a5-other");
    let error = crate::agent_admission::admit_launch(
        home.path(),
        home.path(),
        host.path(),
        Some("person:local:a5-other"),
        Some(agents[0].as_str()),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "the caller owns no agent with that id");
    let error = crate::agent_admission::admit_launch(
        home.path(),
        home.path(),
        host.path(),
        Some("person:local:a5-stranger"),
        Some(agents[0].as_str()),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), crate::agents::NOT_A_PERSON);
}

/// No launcher, no launch, and a child Runtime is not the Home that owns
/// the agent, whatever the launcher says.
#[cfg(feature = "prototype-agents")]
#[test]
fn an_agent_launch_needs_its_launcher_and_its_own_home() {
    let (host, host_cid) = host_capsule(
        crate::agent_admission::tests::AGENT_HOST,
        b"agent host entrypoint",
    );
    let (home, agents) = home_with_agents(1, &host_cid);
    let caller = home.caller();
    let error = crate::agent_admission::admit_launch(
        home.path(),
        home.path(),
        host.path(),
        None,
        Some(agents[0].as_str()),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), crate::agent_admission::NO_LAUNCHER);
    let child = tempfile::tempdir().unwrap();
    let error = crate::agent_admission::admit_launch(
        home.path(),
        child.path(),
        host.path(),
        Some(caller.principal_id),
        Some(agents[0].as_str()),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), crate::agent_admission::NOT_THE_HOME);
}

/// The capsule a launch would load must walk to the Agent Host bytes the agent
/// was created for. A different name, different bytes, a missing receipt, and a
/// forged receipt that claims the stored CID are all refused by name, and
/// admit no actor. The forged receipt is the round-2 case: the folder writes
/// the stored CID itself, and only the Runtime's own walk decides.
#[cfg(feature = "prototype-agents")]
#[test]
fn an_agent_launch_refuses_a_capsule_that_is_not_the_stored_host() {
    let (stored_host, stored_cid) = host_capsule(
        crate::agent_admission::tests::AGENT_HOST,
        b"agent host entrypoint",
    );
    let (home, agents) = home_with_agents(1, &stored_cid);
    let caller = home.caller();
    let launch = |capsule: &Path| {
        crate::agent_admission::admit_launch(
            home.path(),
            home.path(),
            capsule,
            Some(caller.principal_id),
            Some(agents[0].as_str()),
        )
    };
    let (other_name, _) = host_capsule("another-host", b"agent host entrypoint");
    assert_eq!(
        launch(other_name.path()).unwrap_err().to_string(),
        crate::agent_admission::NOT_THE_STORED_HOST
    );
    let (other_bytes, _) = host_capsule(
        crate::agent_admission::tests::AGENT_HOST,
        b"different entrypoint bytes",
    );
    assert_eq!(
        launch(other_bytes.path()).unwrap_err().to_string(),
        crate::agent_admission::NOT_THE_STORED_HOST
    );
    let (no_receipt, _) = host_capsule(
        crate::agent_admission::tests::AGENT_HOST,
        b"agent host entrypoint",
    );
    std::fs::remove_file(no_receipt.path().join(".elastos-cid")).unwrap();
    assert_eq!(
        launch(no_receipt.path()).unwrap_err().to_string(),
        crate::agent_admission::NOT_THE_STORED_HOST
    );
    // The forged receipt: the stored manifest name, the stored CID written into
    // the folder's own receipt, and different bytes. Only the walk decides.
    let (forged, _) = host_capsule(
        crate::agent_admission::tests::AGENT_HOST,
        b"forged agent host bytes",
    );
    std::fs::write(
        forged.path().join(".elastos-cid"),
        format!("{stored_cid}\n"),
    )
    .unwrap();
    assert_eq!(
        launch(forged.path()).unwrap_err().to_string(),
        crate::agent_admission::NOT_THE_STORED_HOST
    );
    // The stored host itself still admits the agent's actor.
    assert_eq!(
        launch(stored_host.path()).unwrap().unwrap().actor,
        agents[0]
    );
}

/// With the feature off, an agent launch is refused before any lookup.
#[cfg(not(feature = "prototype-agents"))]
#[test]
fn with_the_feature_off_an_agent_launch_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let error = crate::agent_admission::admit_launch(
        dir.path(),
        dir.path(),
        dir.path(),
        Some("person:local:a5-owner"),
        Some("agent:v2:cccccccccccccccccccccccccccccccc"),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), crate::agents::FEATURE_OFF);
}

/// The merged loader returns the stored agent once, from either return path,
/// and a save of what it returned writes the owner's records only.
#[cfg(feature = "prototype-agents")]
#[test]
fn the_loader_returns_the_stored_agent_and_the_save_holds_it_back() {
    let home = Home::new();
    turn_on(&home);
    let agent = create_one(&home, "request-1");
    // The cold read and the cached read both carry the agent, once.
    for _ in 0..2 {
        let state = crate::auth::load_auth_state(home.path()).unwrap();
        let found: Vec<&PrincipalRecord> = state
            .principals
            .iter()
            .filter(|record| record.principal_id == agent.agent_id)
            .collect();
        assert_eq!(found.len(), 1, "the agent is returned once");
        assert_eq!(found[0].kind, PrincipalKind::Agent);
        assert_eq!(found[0].owner.as_deref(), Some(OWNER_ID));
        assert_eq!(found[0].role, RuntimePrincipalRole::Guest);
        assert_eq!(
            found[0].proof_binding.kind,
            ProofBindingKind::AgentAdmission
        );
        assert_eq!(found[0].proof_binding.subject, found[0].principal_id);
    }

    // A save of the loader's answer writes the sign-in file's own records.
    let state = crate::auth::load_auth_state(home.path()).unwrap();
    crate::auth::save_auth_state(home.path(), &state, None).unwrap();
    let path = crate::auth::auth_state_path(home.path()).unwrap();
    let saved: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let ids: Vec<&str> = saved["principals"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|record| record["principal_id"].as_str())
        .collect();
    assert!(ids.contains(&OWNER_ID));
    assert!(
        !ids.contains(&agent.agent_id.as_str()),
        "the sign-in file holds no agent: {ids:?}"
    );
    // The agent file keeps its one record, and its protection still opens.
    assert_eq!(loaded(&home).agents.len(), 1);
    let root =
        crate::auth::principal_stored_localhost_root(Some(home.path()), &agent.agent_id).unwrap();
    assert!(
        crate::auth::load_principal_root_protection(home.path(), &agent.agent_id, &root)
            .unwrap()
            .is_some()
    );
}

/// Row 4: an agent writes and reads only its own root, in its own key. The
/// bytes at rest are not the plaintext, and another person cannot read them.
#[cfg(feature = "prototype-agents")]
#[test]
fn an_agent_writes_and_reads_its_own_root_only() {
    let home = Home::new();
    turn_on(&home);
    let agent = create_one(&home, "request-1");
    let root =
        crate::auth::principal_stored_localhost_root(Some(home.path()), &agent.agent_id).unwrap();
    let owner_root =
        crate::auth::principal_stored_localhost_root(Some(home.path()), OWNER_ID).unwrap();
    assert_ne!(root, owner_root);
    let object_uri = format!("{root}/journal/notes.md");
    let path = elastos_common::localhost::rooted_localhost_fs_path(home.path(), &object_uri)
        .expect("the URI has a canonical path");
    let body = b"agent a journal";
    crate::auth::write_principal_root_object(
        home.path(),
        &agent.agent_id,
        &root,
        &object_uri,
        &path,
        body,
    )
    .unwrap();
    assert_eq!(
        crate::auth::read_principal_root_object(
            home.path(),
            &agent.agent_id,
            &root,
            &object_uri,
            &path,
        )
        .unwrap(),
        body
    );
    // The plaintext is nowhere at rest under the data folder.
    let mut files = Vec::new();
    collect_files(home.path(), &mut files);
    assert!(
        !files
            .iter()
            .any(|bytes| bytes.windows(body.len()).any(|w| w == body)),
        "the journal is not stored in the clear"
    );
    // The owner cannot read it through the agent's root.
    assert!(crate::auth::read_principal_root_object(
        home.path(),
        OWNER_ID,
        &root,
        &object_uri,
        &path,
    )
    .is_err());
}

/// Every file under `dir`, for a test that looks for plaintext at rest.
#[cfg(feature = "prototype-agents")]
fn collect_files(dir: &Path, found: &mut Vec<Vec<u8>>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_files(&path, found);
        } else {
            found.push(std::fs::read(&path).unwrap());
        }
    }
}

/// The owner-root arm opens only the protection the agent file stores.
#[cfg(feature = "prototype-agents")]
#[test]
fn an_owner_root_protection_the_agent_file_does_not_store_opens_nothing() {
    let home = Home::new();
    turn_on(&home);
    let agent = create_one(&home, "request-1");
    let root =
        crate::auth::principal_stored_localhost_root(Some(home.path()), &agent.agent_id).unwrap();
    let stored = crate::auth::load_principal_root_protection(home.path(), &agent.agent_id, &root)
        .unwrap()
        .expect("the loader finds the agent's protection");
    // The same shape for a person's root: the file holds no agent for it.
    let owner_root =
        crate::auth::principal_stored_localhost_root(Some(home.path()), OWNER_ID).unwrap();
    let mut person = stored.clone();
    person.principal_id = OWNER_ID.to_string();
    person.localhost_root = owner_root;
    assert_eq!(
        crate::auth::open_agent_root_data_key(home.path(), &person)
            .unwrap_err()
            .to_string(),
        "agent file holds no record for this principal root"
    );
    // The agent's own protection with one field changed is not the stored one.
    let mut changed = stored.clone();
    changed.data_key_id = "00".repeat(32);
    assert_eq!(
        crate::auth::open_agent_root_data_key(home.path(), &changed)
            .unwrap_err()
            .to_string(),
        "principal-root protection is not the agent file's stored one"
    );
    // The stored protection opens the key the record names.
    let key = crate::auth::open_agent_root_data_key(home.path(), &stored).unwrap();
    assert_eq!(
        crate::auth::principal_data_key_id(&key),
        stored.data_key_id.as_str()
    );
}

/// With the feature off the owner's load carries no agent and no agent's
/// protection, though a valid enabled agent file sits beside it.
#[cfg(not(feature = "prototype-agents"))]
#[test]
fn with_the_feature_off_the_owner_load_carries_no_agent_record() {
    let home = Home::new();
    // The agent file is written directly, with no writer and no audit append:
    // this row is about the owner's load, and its setup must not itself save
    // what the load would merge.
    turn_on(&home);
    home.plant(&as_json(&enabled_file(vec![stored_agent(
        OWNER_ID, AGENT_A,
    )])));
    let agent_id = AGENT_A.to_string();
    let state = crate::auth::load_auth_state(home.path()).unwrap();
    assert_eq!(state.principals.len(), 1, "{:?}", state.principals);
    assert!(state
        .principals
        .iter()
        .all(|record| record.principal_id != agent_id));
    assert_eq!(state.principals[0].principal_id, OWNER_ID);
    let root = crate::auth::principal_kind_localhost_root(&agent_id, PrincipalKind::Agent);
    assert!(
        crate::auth::load_principal_root_protection(home.path(), &agent_id, &root)
            .unwrap()
            .is_none()
    );
}
