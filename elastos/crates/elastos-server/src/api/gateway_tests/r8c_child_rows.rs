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

use super::super::r3_stored_root_tests::verified_parent_device_context;
use super::*;
use elastos_runtime::signature::{generate_keypair, SigningKey};

mod direct_messages;
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
}

fn child(app: &str) -> Child {
    let dir = tempfile::tempdir().unwrap();
    let (ctx, parent_root, child_root, _token) = verified_parent_device_context(dir.path(), app);
    let stored = crate::auth::stored_principal_record(dir.path(), ctx.principal_id()).unwrap();
    assert!(
        stored.is_none(),
        "the child stores no record for the parent"
    );
    Child {
        dir,
        ctx,
        parent_root,
        child_root,
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
/// the storage calls that sit behind the Profile gate.
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
/// its failure text carries each step's outcome.
struct Steps {
    row: &'static str,
    lines: Vec<String>,
    refused: usize,
}

impl Steps {
    fn new(row: &'static str) -> Self {
        Self {
            row,
            lines: Vec::new(),
            refused: 0,
        }
    }

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

    fn check(&mut self, name: &str, holds: bool, seen: &dyn std::fmt::Debug) {
        if holds {
            self.lines.push(format!("PASS    {name}"));
        } else {
            self.refused += 1;
            self.lines.push(format!("FAILED  {name}: saw {seen:?}"));
        }
    }

    fn not_reached(&mut self, name: &str, why: &str) {
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
        assert!(self.refused == 0, "{report}");
    }
}
