//! Row 4, Home CLI context. The Home terminal hands a Home CLI child process
//! the context as strings in its environment; the process reads them in
//! `gateway_owned_home_cli_launch_context_from_env` (gateway.rs:344) and
//! rebuilds the context with `home_launch_token_context_from_parts`
//! (line 406). The row calls the second function with the same four values.
//! It does not go through the first, which reads process environment
//! variables.

use super::*;

#[test]
fn r8d_child_home_cli_context_rebuilds_with_the_passkey_persons_root() {
    let person = passkey_person(HOME_CLI_SHELL_ID);
    let ctx = &person.ctx;
    // The grant and the record are both read from the parent's auth state
    // (gateway.rs:423-433), so the rebuilt context equals the verified one.
    let rebuilt = home_launch_token_context_from_parts(
        person.child.path(),
        ctx.principal_id(),
        ctx.session_id(),
        ctx.proof_binding_id(),
        ctx.grant_id(),
    )
    .unwrap();
    assert_eq!(rebuilt.root().localhost_root(), ROOT);
    assert_eq!(&rebuilt, ctx);
    // A child started without a trusted auth data directory reads its own
    // auth state, which holds no session for the person. The row points the
    // thread-local at the child's directory for this one call to show it.
    let own = set_test_home_launch_auth_data_dir(person.child.path());
    let alone = home_launch_token_context_from_parts(
        person.child.path(),
        ctx.principal_id(),
        ctx.session_id(),
        ctx.proof_binding_id(),
        ctx.grant_id(),
    );
    drop(own);
    assert_eq!(refusal(alone).as_deref(), Some("auth session not found"));
    person.assert_child_holds_only(&[]);
}
