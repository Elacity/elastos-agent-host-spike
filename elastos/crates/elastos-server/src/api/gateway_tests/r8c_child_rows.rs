//! R8c evidence rows. A person on a parent device opens a child Runtime's
//! Home with a launch token the parent device signed. The child holds no
//! stored record for that person: it knows them only through the verified
//! token. Each family has a child row and a control row (an ordinary stored
//! person on a child data directory built the same way).
//!
//! The real HTTP handlers cannot be driven with the parent's token from this
//! test binary: they verify against the signer in a process-wide environment
//! variable. Each row therefore calls the functions the handler calls after
//! it has verified the token, with the context the production verifier built.
//!
//! The sign-in store. A real child reads the parent's: the parent sets
//! `ELASTOS_HOME_LAUNCH_TRUSTED_AUTH_DATA_DIR` when it starts the child
//! (runtime_control.rs:1336-1339) and `home_launch_auth_data_dir` reads it
//! (gateway_home_token.rs:1253). The child fixture sets no process variable;
//! it points the test-only thread-local that function checks first (lines
//! 1249-1252) at the parent's data directory, which only the test thread
//! sees. The control reads its own store, as before.

use super::*;
use crate::api::gateway::gateway_home_token::{self as home_token, TestHomeLaunchAuthDataDir};
use elastos_runtime::signature::{generate_keypair, SigningKey};

mod cli_context;
mod direct_messages;
mod documents_rows;
mod library_rows;
mod people;
mod presence;
mod profile;
mod recovery_ready;
mod room_card;

/// A child Runtime's data directory and the parent-signed device person.
struct Child {
    dir: tempfile::TempDir,
    ctx: HomeLaunchTokenContext,
    parent_root: String,
    child_root: String,
    /// The parent's data directory, kept for as long as the child reads it.
    _parent: tempfile::TempDir,
    _auth: TestHomeLaunchAuthDataDir,
}

/// The parent signs a Home launch token for its own device person and the
/// child verifies it against the parent's DID and sign-in store: the calls
/// `verified_parent_device_context` makes, with the parent's directory kept.
fn child(app: &str) -> Child {
    let dir = tempfile::tempdir().unwrap();
    let parent = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let (_, child_did) = elastos_identity::load_or_create_did(dir.path()).unwrap();
    let (_, parent_did) = elastos_identity::load_or_create_did(parent.path()).unwrap();
    let on_parent = home_token::local_home_launch_token_context(parent.path()).unwrap();
    let token =
        home_token::issue_home_launch_token_with_context(parent.path(), app, &on_parent).unwrap();
    let ctx = home_token::require_home_launch_token_value_from_expected_did_for_test(
        dir.path(),
        &token,
        &[app],
        parent_did.clone(),
        parent.path(),
    )
    .unwrap()
    .context;
    let root_of = |did: &str| crate::auth::principal_localhost_root(&format!("device:{did}"));
    let (parent_root, child_root) = (root_of(&parent_did), root_of(&child_did));
    assert_eq!(ctx.root().localhost_root(), parent_root);
    for (store, whose) in [(dir.path(), "child"), (parent.path(), "parent")] {
        let stored = crate::auth::stored_principal_record(store, ctx.principal_id()).unwrap();
        assert!(stored.is_none(), "the {whose} stores no record for them");
    }
    // From here on the child reads the parent's sign-in store.
    let auth = set_test_home_launch_auth_data_dir(parent.path());
    assert_eq!(home_launch_auth_data_dir(dir.path()), parent.path());
    Child {
        dir,
        ctx,
        parent_root,
        child_root,
        _parent: parent,
        _auth: auth,
    }
}

/// The control: a stored passkey person on a child data directory, with the
/// context this Runtime's own verifier builds from that person's token.
struct Control {
    dir: tempfile::TempDir,
    ctx: HomeLaunchTokenContext,
    root: String,
    authority: TestPasskeyAuthority,
}

fn control(app: &str) -> Control {
    let dir = child(app).dir;
    let authority = passkey_authority_with_name(dir.path(), Some("Stored Person"));
    let root =
        crate::auth::store_test_principal_root_protection(dir.path(), &authority.principal_id)
            .localhost_root;
    let token = projection_launch_token_for_authority_context(dir.path(), app, &authority);
    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_static("localhost:61180"));
    headers.insert("origin", HeaderValue::from_static("null"));
    headers.insert("x-elastos-home-token", token.parse().unwrap());
    let ctx = require_home_launch_token_context(dir.path(), &headers, app).unwrap();
    assert_eq!(ctx.root().localhost_root(), root);
    Control {
        dir,
        ctx,
        root,
        authority,
    }
}

/// Test-only arrangement: protection for the parent root and a signed Profile
/// under it, written through the newer storage family. It lets a row reach
/// the storage calls that sit behind the Profile gate. A child cannot
/// produce this state today: this person's Profile update stops at the
/// passkey gate, as the Profile update row shows. The test writes it.
///
/// The Profile lists this child Runtime's own device as its endpoint. The
/// contact store's constructor refuses a Profile that does not list the
/// local device (collaboration_contact_store.rs:914-916), so the two "handed
/// to the route's constructor" steps (contacts, direct messages) answer
/// because of this choice.
fn seed_parent_profile(
    child: &Child,
) -> crate::collaboration_profile_authority::VerifiedCollaborationProfileDocument {
    use crate::collaboration_profile_authority as authority;
    let dir = child.dir.path();
    let id = child.ctx.principal_id();
    crate::auth::store_test_principal_root_protection_for(dir, id, &child.parent_root);
    let device = authority::load_existing_device_did(dir).unwrap().unwrap();
    let key = SigningKey::from_bytes(&generate_keypair().0.to_bytes());
    let now = crate::auth::now_ts();
    let profile = authority::signed_profile_document_for_test(
        &key,
        "Parent Person",
        None,
        1,
        None,
        now,
        vec![device],
    )
    .unwrap();
    let uri = authority::profile_authority_object_uri(&child.parent_root);
    let path = authority::profile_authority_path(dir, &child.parent_root).unwrap();
    crate::auth::create_owner_only_dir_all(dir, path.parent().unwrap()).unwrap();
    let bundle = json!({
        "schema": authority::COLLABORATION_PROFILE_AUTHORITY_BUNDLE_SCHEMA_V1,
        "profile_signing_seed_hex": hex::encode(key.to_bytes()),
        "previous_profiles": [],
        "signed_profile": profile.signed_envelope(),
    });
    let bytes = serde_json::to_vec(&bundle).unwrap();
    crate::auth::write_protected_principal_root_object_resolved(
        dir,
        child.ctx.root(),
        &uri,
        &path,
        &bytes,
    )
    .unwrap();
    profile
}

/// A gateway state whose Discovery service runs on the child's own device
/// key, as production does. No relay is reachable.
async fn state_with_discovery(dir: &std::path::Path) -> GatewayState {
    let (trusted_key, _) = generate_keypair();
    let network =
        super::home_system::configured_discovery_network_profile_for_test(&trusted_key, "r8c");
    let (device_key, _) = elastos_identity::load_or_create_did(dir).unwrap();
    let service = crate::collaboration_discovery_runtime::CollaborationDiscoveryService::new(
        SigningKey::from_bytes(&device_key.to_bytes()),
        network,
        Arc::new(elastos_runtime::provider::ProviderRegistry::new()),
    )
    .await
    .unwrap();
    let mut state = test_state(dir);
    state.collaboration_discovery_service = Some(service);
    state
}

/// Every regular file under the data directory's person roots, as paths
/// relative to the data directory.
fn files_under_roots(data_dir: &std::path::Path) -> Vec<String> {
    fn walk(base: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(base, &path, out);
            } else {
                out.push(path.strip_prefix(base).unwrap().display().to_string());
            }
        }
    }
    let mut out = Vec::new();
    for top in ["Users", "UsersAI"] {
        walk(data_dir, &data_dir.join(top), &mut out);
    }
    out.sort();
    out
}

/// One row's steps, in order. The row fails only after every step ran, so
/// its failure text carries each step's outcome. A row passes only when
/// every step ran and passed: a skipped step fails the row.
struct Steps {
    row: &'static str,
    lines: Vec<String>,
    refused: usize,
    skipped: usize,
}

impl Steps {
    fn new(row: &'static str) -> Self {
        Self {
            row,
            lines: Vec::new(),
            refused: 0,
            skipped: 0,
        }
    }

    /// The call answered. It does not look at the answer: use `step_where`
    /// when the answer carries a value the row depends on.
    fn step<T, E: std::fmt::Display>(&mut self, name: &str, result: Result<T, E>) -> Option<T> {
        match result {
            Ok(value) => {
                self.lines.push(format!("PASS    {name}"));
                Some(value)
            }
            Err(error) => {
                self.refused += 1;
                self.lines.push(format!("REFUSED {name}: {error:#}"));
                None
            }
        }
    }

    /// The call answered and `expected` holds for its answer. An answer that
    /// misses `expected` is recorded as failed and is not handed on.
    fn step_where<T: std::fmt::Debug, E: std::fmt::Display>(
        &mut self,
        name: &str,
        result: Result<T, E>,
        expected: impl FnOnce(&T) -> bool,
    ) -> Option<T> {
        match result {
            Ok(value) if expected(&value) => self.step(name, Ok::<T, E>(value)),
            Ok(value) => {
                self.refused += 1;
                self.lines.push(format!("FAILED  {name}: saw {value:?}"));
                None
            }
            Err(error) => self.step(name, Err(error)),
        }
    }

    fn check(&mut self, name: &str, holds: bool, seen: &dyn std::fmt::Debug) {
        if holds {
            self.lines.push(format!("PASS    {name}"));
        } else {
            self.refused += 1;
            self.lines.push(format!("FAILED  {name}: saw {seen:?}"));
        }
    }

    /// A step that could not run. It fails the row in `finish`.
    fn not_reached(&mut self, name: &str, why: &str) {
        self.skipped += 1;
        self.lines.push(format!("SKIPPED {name}: {why}"));
    }

    /// The bytes landed under `root` and nowhere else.
    fn only_under(&mut self, data_dir: &std::path::Path, root: &str, relative: &str) {
        let prefix = format!("{}/", root.trim_start_matches("localhost://"));
        let files = files_under_roots(data_dir);
        let landed = files.contains(&format!("{prefix}{relative}"));
        self.check(&format!("{relative} is under {root}"), landed, &files);
        let strays: Vec<_> = files.iter().filter(|f| !f.starts_with(&prefix)).collect();
        self.check(
            "nothing is under any other root",
            strays.is_empty(),
            &strays,
        );
    }

    fn finish(self) {
        let report = format!("R8C {}\n{}", self.row, self.lines.join("\n"));
        println!("{report}");
        assert!(self.refused == 0 && self.skipped == 0, "{report}");
    }
}

/// The collector itself: an answer that misses its predicate fails the row.
#[test]
#[should_panic(expected = "R8C collector: a wrong value\nFAILED  an answer of false: saw false")]
fn steps_fail_when_an_answer_misses_its_predicate() {
    let mut steps = Steps::new("collector: a wrong value");
    let handed_on = steps.step_where("an answer of false", Ok::<_, String>(false), |value| *value);
    assert_eq!(handed_on, None);
    steps.finish();
}

/// The collector itself: a step that was skipped fails the row.
#[test]
#[should_panic(
    expected = "R8C collector: a skipped step\nSKIPPED a later step: nothing to run it on"
)]
fn steps_fail_when_a_step_was_skipped() {
    let mut steps = Steps::new("collector: a skipped step");
    steps.not_reached("a later step", "nothing to run it on");
    steps.finish();
}
