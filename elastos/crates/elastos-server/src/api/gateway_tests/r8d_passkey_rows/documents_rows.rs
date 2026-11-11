//! Row 11, Documents. Entry: `DocumentsProvider::send_raw` (documents.rs:245),
//! which `gateway_provider_proxy` reaches for `/api/provider/documents/:op`
//! after stamping the context's principal id.

use super::*;

async fn documents(dir: &std::path::Path, op: &str, mut request: Value) -> Result<Value, String> {
    request["op"] = json!(op);
    request["principal_id"] = json!(PERSON);
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

#[tokio::test(flavor = "current_thread")]
async fn r8d_child_documents_summary_and_create_under_the_passkey_persons_root() {
    let person = passkey_person(DOCUMENTS_CAPSULE_ID);
    assert_eq!(person.ctx.principal_id(), PERSON);
    let child = person.child.path();
    // Documents resolves the root again from the id, with the child's own
    // data directory as the auth store (documents.rs:742).
    let refused = Err(format!("\"documents_error\" \"{NO_STORED_RECORD}\""));
    let summary = documents(child, "summary", json!({})).await;
    assert_eq!(summary, refused);
    let created = documents(child, "create", json!({"title": "R8d note"})).await;
    assert_eq!(created, refused);
    person.assert_child_holds_only(&[]);
}
