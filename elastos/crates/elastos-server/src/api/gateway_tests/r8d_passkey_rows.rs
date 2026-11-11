//! R8d evidence rows. A person signs in on a parent Runtime with a passkey
//! and opens a child Runtime's Home. The parent stores this person: record,
//! passkey binding, protected root and Profile. The child stores none of it:
//! it reads the parent's auth state through the trusted auth data directory
//! and knows the person only through the verified launch token.
//!
//! Each row asserts what the code does today. The controls are the eleven
//! `r8c_control_*` rows: the same calls for a person the child itself stores.
//!
//! As in R8c, the real HTTP handlers cannot be driven with the parent's token
//! from this test binary: they verify against the signer in a process-wide
//! environment variable. Each row calls the functions the handler calls after
//! it has verified the token, with the context the production verifier built.

use super::*;
use crate::api::gateway::gateway_home_token::{
    require_home_launch_token_value_from_expected_did_for_test as verify_on_child,
    RequiredHomeLaunchToken, TestHomeLaunchAuthDataDir,
};
use crate::auth::{PasskeySessionPurpose, PasskeySessionRequest, ResolvedPrincipalRoot};
use crate::collaboration_discovery_runtime::CollaborationDiscoveryService;
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

const RP_ID: &str = "elastos.elacitylabs.com";
const ORIGIN: &str = "https://elastos.elacitylabs.com";
const CREDENTIAL: &str = "r8d-parent-passkey";
const PUBLIC_KEY: &str = "r8d-parent-public-key";

/// `person:local:` + the first 16 bytes of
/// sha256("passkey-credential:elastos.elacitylabs.com:r8d-parent-passkey").
pub(in crate::api) const PERSON: &str = "person:local:8f321f2535862743af435b8e4f9b9a6d";
/// `localhost://Users/` + the first 12 bytes of sha256(PERSON).
pub(in crate::api) const ROOT: &str = "localhost://Users/ecee74316e460e2874b8b6d0";
/// The stored-record refusal for this person, as `auth.rs` words it.
pub(in crate::api) const NO_STORED_RECORD: &str =
    "principal 'person:local:8f321f2535862743af435b8e4f9b9a6d' has no stored record; \
     its root cannot be chosen";
pub(in crate::api) const PROFILE_FILE: &str =
    "Users/ecee74316e460e2874b8b6d0/.AppData/ElastOS/Profile/profile-authority.json";

/// The parent's passkey person, as a child Runtime sees them after it has
/// verified their launch token.
pub(in crate::api) struct PasskeyPerson {
    pub(in crate::api) child: tempfile::TempDir,
    pub(in crate::api) parent: tempfile::TempDir,
    pub(in crate::api) ctx: HomeLaunchTokenContext,
    pub(in crate::api) required: RequiredHomeLaunchToken,
    /// Keeps the child reading the parent's auth state for the row's body, as
    /// `ELASTOS_HOME_LAUNCH_TRUSTED_AUTH_DATA_DIR` does on a real child.
    _auth: TestHomeLaunchAuthDataDir,
}

fn owner_only_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}

/// What the parent stores for the person, then a production sign-in.
fn sign_in_on_parent(parent: &std::path::Path) -> AuthSessionGrantV1 {
    let now = crate::auth::now_ts();
    let binding = ProofBinding::passkey_webauthn(PasskeyWebAuthnBinding {
        credential_id: CREDENTIAL.to_string(),
        public_key: PUBLIC_KEY.to_string(),
        sign_count: 1,
        user_verified: true,
        origin: ORIGIN.to_string(),
        rp_id: RP_ID.to_string(),
        created_at: now,
        last_used_at: now,
        revoked_at: None,
    });
    let id = crate::auth::passkey_credential_principal_id(RP_ID, CREDENTIAL).unwrap();
    let role = crate::auth::RuntimePrincipalRole::Admin;
    let record = crate::auth::upsert_principal_for_binding_as_role_named(
        parent,
        binding,
        id,
        role,
        Some("Parent Person"),
        now,
    )
    .unwrap();
    assert_eq!(record.principal_id, PERSON);
    assert_eq!(record.localhost_root, ROOT);
    crate::auth::store_test_principal_root_protection(parent, PERSON);
    crate::collaboration_profile_authority::update_profile_authority(
        parent,
        PERSON,
        ROOT,
        &record.proof_binding_id,
        "Parent Person",
        None,
        now,
    )
    .unwrap();
    let credential = elastos_identity::StoredCredential {
        credential_id: CREDENTIAL.to_string(),
        public_key: PUBLIC_KEY.to_string(),
        sign_count: 2,
        rp_id: RP_ID.to_string(),
    };
    let grant = crate::auth::grant_passkey_session(
        parent,
        PasskeySessionRequest {
            credential: &credential,
            origin: ORIGIN,
            user_verified: true,
            display_name: None,
            profile_display_name: None,
            reason: "r8d parent passkey sign-in",
            purpose: PasskeySessionPurpose::SignIn,
        },
    )
    .unwrap();
    assert_eq!(grant.apps, ["home", "system"]);
    assert_eq!(grant.principal_id, PERSON);
    grant
}

/// The person opens `app` from the parent's Home: the parent signs a Home
/// projection token for them and the child verifies it against the parent's
/// DID and auth state, as `gateway_home_runtime.rs` and the verifier's proof
/// arm in `gateway_home_token.rs` do.
pub(in crate::api) fn passkey_person(app: &str) -> PasskeyPerson {
    let parent = owner_only_dir();
    let child = owner_only_dir();
    let (_, parent_did) = elastos_identity::load_or_create_did(parent.path()).unwrap();
    elastos_identity::load_or_create_did(child.path()).unwrap();
    let grant = sign_in_on_parent(parent.path());
    let root = ResolvedPrincipalRoot::resolve(parent.path(), parent.path(), PERSON).unwrap();
    let on_parent = HomeLaunchTokenContext::resolved(
        root,
        grant.principal_id.clone(),
        grant.session_id.clone(),
        Some(grant.proof_binding_id.clone()),
        grant.grant_id.clone(),
    );
    let token =
        issue_home_projection_launch_token_with_context(parent.path(), app, app, &on_parent)
            .unwrap();
    let auth = set_test_home_launch_auth_data_dir(parent.path());
    let required =
        verify_on_child(child.path(), &token, &[app], parent_did, parent.path()).unwrap();
    let ctx = required.context.clone();
    assert_eq!(required.launch_context.authority_actor, "home");
    assert_eq!(required.launch_context.executable_actor, app);
    assert_eq!(ctx.principal_id(), PERSON);
    assert_eq!(ctx.root().localhost_root(), ROOT);
    assert_eq!(ctx.session_id(), grant.session_id);
    assert_eq!(ctx.grant_id(), grant.grant_id);
    let proof = ctx.proof_binding_id().unwrap();
    assert!(proof.starts_with("proof:passkey:"), "{proof}");
    let person = PasskeyPerson {
        child,
        parent,
        ctx,
        required,
        _auth: auth,
    };
    let on_parent = tree(person.parent.path());
    assert!(
        on_parent.contains(&PROFILE_FILE.to_string()),
        "{on_parent:?}"
    );
    person.assert_child_holds_only(&[]);
    person
}

/// Every file under `dir`, and every folder with nothing in it (shown with a
/// trailing `/`), as paths relative to `dir`. A link is listed, not followed.
/// An entry that cannot be read fails the row.
fn tree(dir: &std::path::Path) -> Vec<String> {
    fn walk(base: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) {
        let mut entries = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            entries += 1;
            if std::fs::symlink_metadata(&path).unwrap().is_dir() {
                walk(base, &path, out);
            } else {
                out.push(path.strip_prefix(base).unwrap().display().to_string());
            }
        }
        if entries == 0 && dir != base {
            out.push(format!("{}/", dir.strip_prefix(base).unwrap().display()));
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// What a child holds before any row touches it, each with its reason.
const CHILD_OWN: &[&str] = &[
    // The lock file a read of the child's auth state leaves. It holds no
    // state: there is no `auth-state.json` beside it.
    "ElastOS/System/Auth/audit-chain-required.json.lock",
    // The child's own device key, made by `load_or_create_did`.
    "identity/device.key",
    // The identity store's lock file, made with the key.
    "identity/identity.lock",
];

impl PasskeyPerson {
    /// The whole child data directory holds exactly `CHILD_OWN` plus `also`,
    /// and the child's auth state holds no record, no protection and no
    /// session at all, so none for the person. Every problem is reported.
    pub(in crate::api) fn assert_child_holds_only(&self, also: &[&str]) {
        let child = self.child.path();
        let mut problems = Vec::new();
        let mut expected: Vec<String> = CHILD_OWN
            .iter()
            .chain(also)
            .map(|s| s.to_string())
            .collect();
        expected.sort();
        let state = crate::auth::load_auth_state(child).unwrap();
        let found = tree(child);
        if found != expected {
            problems.push(format!(
                "the child data directory holds {found:#?}, expected exactly {expected:#?}"
            ));
        }
        if !state.principals.is_empty() {
            problems.push("the child's auth state stores a record".to_string());
        }
        if !state.principal_root_protections.is_empty() {
            problems.push("the child's auth state stores a protection record".to_string());
        }
        if !state.sessions.is_empty() {
            problems.push("the child's auth state stores a session".to_string());
        }
        if home_launch_auth_data_dir(child) != self.parent.path() {
            problems.push("the child no longer reads the parent's auth state".to_string());
        }
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }

    /// A gateway state on the child's data directory. Built by hand so that
    /// nothing is written into the directory.
    pub(in crate::api) fn child_state(&self) -> GatewayState {
        let dir = self.child.path().to_path_buf();
        GatewayState {
            provider_registry: None,
            collaboration_chat_product_port: None,
            collaboration_presence_product_port: None,
            carrier_endpoint: None,
            collaboration_discovery_service: None,
            browser_internet: Default::default(),
            identity_manager: Arc::new(std::sync::OnceLock::new()),
            cache_dir: dir.clone(),
            data_dir: dir,
        }
    }
}

/// A Discovery service on the directory's own device key, as production
/// builds it. No relay is reachable. Nothing is written into the directory.
pub(in crate::api) async fn discovery_service(
    dir: &std::path::Path,
) -> CollaborationDiscoveryService {
    let (trusted_key, _) = generate_keypair();
    let network =
        super::home_system::configured_discovery_network_profile_for_test(&trusted_key, "r8d");
    let (device_key, _) = elastos_identity::load_or_create_did(dir).unwrap();
    CollaborationDiscoveryService::new(
        SigningKey::from_bytes(&device_key.to_bytes()),
        network,
        Arc::new(elastos_runtime::provider::ProviderRegistry::new()),
    )
    .await
    .unwrap()
}

/// The refusal text, with its whole cause chain, or None when the call passed.
pub(in crate::api) fn refusal<T>(result: anyhow::Result<T>) -> Option<String> {
    result.err().map(|error| format!("{error:#}"))
}
