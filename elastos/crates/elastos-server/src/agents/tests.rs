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

    fn owner_file(&self) -> Vec<PrincipalRecord> {
        crate::auth::load_auth_state(self.path())
            .unwrap()
            .principals
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
    home.plant(&as_json(&enabled_file(vec![first, second])));
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
    let owner = owner_protection(&home);
    let agent = stored_agent(OWNER_ID, AGENT_A).protection;
    let key = |agent: &PrincipalRootProtectionV1| {
        *crate::auth::owner_root_wrap_key(home.path(), &owner, agent).unwrap()
    };
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
    let owner = owner_protection(&home);
    let agent = stored_agent(OWNER_ID, AGENT_A).protection;
    let base = *crate::auth::owner_root_wrap_key(home.path(), &owner, &agent).unwrap();

    let other = crate::auth::store_test_principal_root_protection(home.path(), "person:local:b");
    let theirs = *crate::auth::owner_root_wrap_key(home.path(), &other, &agent).unwrap();
    assert_ne!(theirs, base, "another person derives another key");

    // An owner protection that is itself an owner-root wrap is refused.
    let mut chained = owner.clone();
    chained
        .protectors
        .push(stored_agent(OWNER_ID, AGENT_B).protection.protectors[0].clone());
    let error = crate::auth::owner_root_wrap_key(home.path(), &chained, &agent).unwrap_err();
    assert_eq!(
        error.to_string(),
        "an owner-root wrap needs an owner that is not itself wrapped"
    );
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
    let owner = owner_protection(&home);
    let root = crate::auth::principal_kind_localhost_root(AGENT_A, PrincipalKind::Agent);
    let protection = protect_agent_root(home.path(), &owner, AGENT_A, &root, 9).unwrap();
    let mut agent = stored_agent(OWNER_ID, AGENT_A);
    agent.protection = protection.clone();
    assert!(protection_is_sound(&agent), "create's protection loads");

    let envelope = protection.protectors[0].envelope.as_ref().unwrap();
    let wrap_key = crate::auth::owner_root_wrap_key(home.path(), &owner, &protection).unwrap();
    let data_key = unwrap_data_key(&wrap_key, envelope).unwrap();
    assert_eq!(
        crate::auth::principal_data_key_id(&data_key),
        protection.data_key_id,
        "the wrap holds the key the protection names"
    );

    let mut other = protection.clone();
    other.principal_id = AGENT_B.to_string();
    let other_key = crate::auth::owner_root_wrap_key(home.path(), &owner, &other).unwrap();
    assert!(
        unwrap_data_key(&other_key, envelope).is_err(),
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
        })
    );
    assert_eq!((record.retired_at, record.version), (None, 1));

    // The one protection opens under the owner's derived key.
    let protection = &agent.protection;
    let wrap_key =
        crate::auth::owner_root_wrap_key(home.path(), &owner_protection(&home), protection)
            .unwrap();
    let envelope = protection.protectors[0].envelope.as_ref().unwrap();
    let data_key = unwrap_data_key(&wrap_key, envelope).unwrap();
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
    assert!(owner_protection(&home).principal_id == OWNER_ID);
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
fn agents_rs_names_no_owner_key_function_and_reads_no_environment() {
    let source = include_str!("../agents.rs");
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
    for forbidden in key_functions.iter().chain(&words).chain(&environment) {
        assert!(!source.contains(forbidden), "agents.rs names `{forbidden}`");
    }
    // The one key function it may call returns a derived key only.
    assert_eq!(source.matches("owner_root_wrap_key(").count(), 1);
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
