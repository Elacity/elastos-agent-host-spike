//! Family 9. Entry: `DocumentsProvider::send_raw` (documents.rs:245), which
//! `gateway_provider_proxy` reaches for `/api/provider/documents/:op` after
//! stamping the context's principal id (gateway_provider_proxy.rs:1843).

use super::*;

async fn documents(
    dir: &std::path::Path,
    ctx: &HomeLaunchTokenContext,
    op: &str,
    mut request: Value,
) -> Result<Value, String> {
    request["op"] = json!(op);
    request["principal_id"] = json!(ctx.principal_id());
    let provider =
        crate::documents::DocumentsProvider::new(dir.to_path_buf(), std::sync::Weak::new());
    let response = provider
        .send_raw(&request)
        .await
        .map_err(|error| error.to_string())?;
    if response["status"] == "ok" {
        return Ok(response["data"].clone());
    }
    Err(format!("{} {}", response["code"], response["message"]))
}

async fn documents_steps(steps: &mut Steps, dir: &std::path::Path, ctx: &HomeLaunchTokenContext) {
    let summary = documents(dir, ctx, "summary", json!({})).await;
    steps.step("Documents summary (op summary)", summary);
    let created = documents(dir, ctx, "create", json!({"title": "R8c note"})).await;
    let created = steps.step("create a document (op create)", created);
    let root = ctx
        .root()
        .localhost_root()
        .trim_start_matches("localhost://");
    let files = files_under_roots(dir);
    let landed = files
        .iter()
        .any(|file| file.starts_with(&format!("{root}/Documents/")));
    let landed = created.is_some() && landed;
    steps.check(
        "the document is under this root's Documents",
        landed,
        &files,
    );
    let strays: Vec<_> = files.iter().filter(|f| !f.starts_with(root)).collect();
    steps.check(
        "nothing is under any other root",
        strays.is_empty(),
        &strays,
    );
}

#[tokio::test]
#[ignore = "R8c: refused for a parent-signed device on a child Runtime"]
async fn r8c_child_documents_summary_and_create_under_the_parent_root() {
    let child = child(DOCUMENTS_CAPSULE_ID);
    let mut steps = Steps::new("Documents: parent-signed device, child Runtime");
    documents_steps(&mut steps, child.dir.path(), &child.ctx).await;
    steps.finish();
}

#[tokio::test]
async fn r8c_control_documents_summary_and_create_under_the_stored_persons_root() {
    let control = control(DOCUMENTS_CAPSULE_ID);
    let mut steps = Steps::new("Documents: stored person (control)");
    documents_steps(&mut steps, control.dir.path(), &control.ctx).await;
    steps.finish();
}
