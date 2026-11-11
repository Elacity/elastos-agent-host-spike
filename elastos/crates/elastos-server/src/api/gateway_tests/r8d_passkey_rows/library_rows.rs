//! Row 10, Library. Entry: `crate::library::handle_object_provider_raw_request`
//! (library.rs:587), the object provider's handler. `gateway_provider_proxy`
//! stamps the request with the context's principal id and sends it through
//! the registry.

use super::*;

fn library(dir: &std::path::Path, op: &str, mut request: Value) -> Result<Value, String> {
    request["op"] = json!(op);
    request["principal_id"] = json!(PERSON);
    let response = crate::library::handle_object_provider_raw_request(dir, &request);
    if response["status"] == "ok" {
        return Ok(response["data"].clone());
    }
    Err(format!(
        "{} {} {}",
        response["code"], response["message"], response["detail"]
    ))
}

#[test]
fn r8d_child_library_lists_writes_and_reads_under_the_passkey_persons_root() {
    let person = passkey_person(LIBRARY_CAPSULE_ID);
    assert_eq!(person.ctx.principal_id(), PERSON);
    let child = person.child.path();
    let uri = format!("{ROOT}/Documents/r8d-note.txt");
    let data = base64::engine::general_purpose::STANDARD.encode(b"r8d library bytes");
    // The Library resolves the root again from the id, with the child's own
    // data directory as the auth store (library.rs:1334 and 3977).
    let refused = Err(format!("\"library_error\" \"{NO_STORED_RECORD}\" null"));
    let steps = [
        ("list", json!({})),
        (
            "write",
            json!({"uri": uri, "data": data, "mime": "text/plain"}),
        ),
        ("read", json!({"uri": uri})),
        ("list", json!({"uri": format!("{ROOT}/Documents")})),
    ];
    for (op, request) in steps {
        assert_eq!(library(child, op, request), refused, "op {op}");
    }
    person.assert_child_holds_only(&[]);
}
