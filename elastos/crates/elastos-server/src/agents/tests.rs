//! Tests for the agent file. Rules that need the feature on are in
//! `feature_on`; the rest run in every build.

use super::*;
use elastos_runtime::auth::ProofBinding;
use serde_json::{json, Value};

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
            agent_host_package: Some(crate::auth::AgentHostPackage {
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
