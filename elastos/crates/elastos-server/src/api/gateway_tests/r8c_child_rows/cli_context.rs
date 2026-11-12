//! Family 9. The Home terminal hands a Home CLI child process the context as
//! strings (gateway_home_terminal.rs:843); the child process rebuilds the
//! context with `home_launch_token_context_from_parts` (gateway.rs:403),
//! reached from `gateway_owned_home_cli_launch_context_from_env` (line 341).

use super::*;

fn rebuilt(dir: &std::path::Path, ctx: &HomeLaunchTokenContext) -> anyhow::Result<String> {
    let rebuilt = home_launch_token_context_from_parts(
        dir,
        ctx.principal_id(),
        ctx.session_id(),
        ctx.proof_binding_id(),
        ctx.grant_id(),
    )?;
    Ok(rebuilt.root().localhost_root().to_string())
}

#[test]
#[ignore = "R8c: refused for a parent-signed device on a child Runtime"]
fn r8c_child_home_cli_context_rebuilds_with_the_parent_root() {
    let child = child(HOME_CLI_SHELL_ID);
    let mut steps = Steps::new("Home CLI context: parent-signed device, child Runtime");
    let root = steps.step(
        "rebuild the context from its parts",
        rebuilt(child.dir.path(), &child.ctx),
    );
    let same = root.as_deref() == Some(child.parent_root.as_str());
    steps.check("the rebuilt root is the parent root", same, &root);
    steps.finish();
}

#[test]
fn r8c_control_home_cli_context_rebuilds_with_the_stored_persons_root() {
    let control = control(HOME_CLI_SHELL_ID);
    let mut steps = Steps::new("Home CLI context: stored person (control)");
    let root = steps.step(
        "rebuild the context from its parts",
        rebuilt(control.dir.path(), &control.ctx),
    );
    let same = root.as_deref() == Some(control.root.as_str());
    steps.check("the rebuilt root is the stored root", same, &root);
    steps.finish();
}
