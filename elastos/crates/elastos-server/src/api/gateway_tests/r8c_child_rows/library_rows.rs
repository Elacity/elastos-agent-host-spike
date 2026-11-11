//! Family 7. Entry: `crate::library::handle_object_provider_raw_request`
//! (library.rs:587), the object provider's handler. `gateway_provider_proxy`
//! (gateway_provider_proxy.rs:1606) stamps the request with the context's
//! principal id (line 1843) and sends it through the registry (line 2027).

use super::*;

fn library(
    dir: &std::path::Path,
    ctx: &HomeLaunchTokenContext,
    op: &str,
    mut request: Value,
) -> Result<Value, String> {
    request["op"] = json!(op);
    request["principal_id"] = json!(ctx.principal_id());
    let response = crate::library::handle_object_provider_raw_request(dir, &request);
    if response["status"] == "ok" {
        return Ok(response["data"].clone());
    }
    Err(format!(
        "{} {} {}",
        response["code"], response["message"], response["detail"]
    ))
}

fn library_steps(steps: &mut Steps, dir: &std::path::Path, ctx: &HomeLaunchTokenContext) {
    let root = ctx.root().localhost_root().to_string();
    let uri = format!("{root}/Documents/r8c-note.txt");
    let data = base64::engine::general_purpose::STANDARD.encode(b"r8c library bytes");
    steps.step(
        "list the Library (op list)",
        library(dir, ctx, "list", json!({})),
    );
    let write = json!({"uri": uri, "data": data, "mime": "text/plain"});
    steps.step("write a file (op write)", library(dir, ctx, "write", write));
    let read = steps.step(
        "read a file (op read)",
        library(dir, ctx, "read", json!({"uri": uri})),
    );
    let same = read.is_some_and(|read| read["data"] == json!(data));
    steps.check("the read returns the written bytes", same, &uri);
    let listed = library(
        dir,
        ctx,
        "list",
        json!({"uri": format!("{root}/Documents")}),
    )
    .map(|list| list["objects"].to_string());
    let listed = steps.step("list the folder (op list)", listed);
    let shown = listed.is_some_and(|objects| objects.contains("r8c-note.txt"));
    steps.check("the folder list shows the file", shown, &uri);
    steps.only_under(dir, &root, "Documents/r8c-note.txt");
}

#[test]
#[ignore = "R8c: refused for a parent-signed device on a child Runtime"]
fn r8c_child_library_lists_writes_and_reads_under_the_parent_root() {
    let child = child(LIBRARY_CAPSULE_ID);
    assert_eq!(child.ctx.root().localhost_root(), child.parent_root);
    let mut steps = Steps::new("Library: parent-signed device, child Runtime");
    library_steps(&mut steps, child.dir.path(), &child.ctx);
    steps.finish();
}

#[test]
fn r8c_control_library_lists_writes_and_reads_under_the_stored_persons_root() {
    let control = control(LIBRARY_CAPSULE_ID);
    let mut steps = Steps::new("Library: stored person (control)");
    library_steps(&mut steps, control.dir.path(), &control.ctx);
    steps.finish();
}
