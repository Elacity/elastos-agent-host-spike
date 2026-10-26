//! The lab copies three shipped sites. Each pin fails if that site moves or
//! changes, so a report's file:line stays honest.

use std::fs;
use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn first_line(path: &Path, snippet: &str) -> usize {
    let text = fs::read_to_string(path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    let idx = text
        .find(snippet)
        .unwrap_or_else(|| panic!("{}: missing pin:\n{snippet}", path.display()));
    text[..idx].bytes().filter(|b| *b == b'\n').count() + 1
}

#[test]
fn pins_hold_on_this_tree() {
    let repo = repo();
    let guest = repo.join("examples/agent-host/src/lib.rs");
    let compute = repo.join("elastos/crates/elastos-compute/src/providers/component.rs");
    let bridge = repo.join("elastos/crates/elastos-server/src/resource_bridge.rs");

    let ask = first_line(
        &guest,
        "        bus.request_grant(&cursor.resource, action, \"Agent Host task journal\")\n            .ok()\n            .and_then(|id| JournalGrant::new(&id))",
    );
    let wasm = first_line(
        &guest,
        "        match elastos::bus::capabilities::request(&request) {\n            Ok(grant) if grant.resource == resource && grant.actions == [action] => Ok(grant.id),\n            Ok(_) => Err(BusFailure::Invalid),\n            Err(BusError::Denied(_)) => Err(BusFailure::Denied),\n            Err(BusError::Invalid(_)) => Err(BusFailure::Invalid),\n            Err(_) => Err(BusFailure::Other),\n        }",
    );
    let run = first_line(
        &guest,
        "        let grants = request_journal_grants(&mut WasmBus, &cursor);\n        let appended = append_journal(\n            &mut WasmBus,\n            &mut journal,\n            &mut cursor,\n            grants.write.as_ref(),\n        );\n        let followed = match (&grants.write, appended) {\n            (None, AppendOutcome::Denied) => {",
    );
    let denied = first_line(
        &compute,
        "        \"denied\" | \"capability_denied\" | \"missing_token\" | \"invalid_token\" => {\n            elastos::bus::types::BusError::Denied(message)\n        }",
    );
    let internal = first_line(
        &compute,
        "        _ => elastos::bus::types::BusError::Internal(message),",
    );
    let manifest = first_line(
        &bridge,
        "        \"manifest_capability_denied\",\n        &format!(\"capsule manifest does not declare authority for {resource}\"),",
    );

    println!("pin guest ask .ok()                examples/agent-host/src/lib.rs:{ask}");
    println!("pin guest WasmBus Internal→Other   examples/agent-host/src/lib.rs:{wasm}");
    println!("pin guest run empty grants → Ok    examples/agent-host/src/lib.rs:{run}");
    println!("pin Runtime bus_error Denied       elastos/crates/elastos-compute/src/providers/component.rs:{denied}");
    println!("pin Runtime bus_error Internal     elastos/crates/elastos-compute/src/providers/component.rs:{internal}");
    println!("pin Runtime manifest_capability_denied elastos/crates/elastos-server/src/resource_bridge.rs:{manifest}");

    assert_eq!(ask, 3845, "request_journal_grants .ok() moved");
    assert_eq!(wasm, 4213, "WasmBus Internal→Other moved");
    assert_eq!(run, 8086, "run() empty-grant Ok path moved");
    assert_eq!(denied, 271, "bus_error Denied list moved");
    assert_eq!(internal, 289, "bus_error Internal default moved");
    assert_eq!(manifest, 274, "manifest_capability_denied moved");
}
