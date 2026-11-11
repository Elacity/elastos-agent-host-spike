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
