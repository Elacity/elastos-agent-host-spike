//! This test code stands in for the Runtime's launch by CID, which does not exist yet.

use super::{
    dispatch, dispatch_principal, error, stand_in::record_loaded_instance, Bridge, StandInBinding,
    STAND_IN_TEST_PRINCIPAL,
};
use serde_json::{json, Value};

const CONTENT: &str = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";
const MEMBER: &str = "localhost://Users/self/AppData/stand-in/input.png";
const INSTANCE: &str = "stand-in-instance";
const PRINCIPAL: &str = STAND_IN_TEST_PRINCIPAL;
const BYTES: &[u8] = b"stand-in object bytes";

fn binding(id: &str) -> StandInBinding {
    StandInBinding {
        binding_id: id.into(),
        content_cid: CONTENT.into(),
        instance_id: String::new(),
        principal: PRINCIPAL.into(),
        members: [MEMBER.into()].into(),
        active: false,
        readmit: Box::new(|| Ok(())),
    }
}

fn arm(bridge: &mut Bridge, id: &str) {
    bridge.arm_stand_in(binding(id)).unwrap();
    record_loaded_instance(bridge, INSTANCE);
}

fn arm_with(bridge: &mut Bridge, binding: StandInBinding) {
    bridge.arm_stand_in(binding).unwrap();
    record_loaded_instance(bridge, INSTANCE);
}

fn bridge() -> Bridge {
    let mut bridge = Bridge::default();
    bridge.put(MEMBER, BYTES.into());
    bridge.allow(MEMBER, "read");
    bridge
}

fn grant(resource: &str) -> String {
    grant_action(resource, "read")
}

fn grant_action(resource: &str, action: &str) -> String {
    json!({ "id": 17, "request": {
        "type": "request_capability", "resource": resource, "action": action
    } })
    .to_string()
}

fn invoke(resource: &str, token: &str) -> String {
    json!({ "id": 23, "request": {
        "type": "resource_invoke", "uri": resource, "operation": "read", "token": token,
        "body": { "path": resource, "offset": 0, "length": BYTES.len() }
    } })
    .to_string()
}

fn write(resource: &str, token: &str) -> String {
    json!({ "id": 23, "request": {
        "type": "resource_invoke", "uri": resource, "operation": "write", "token": token,
        "body": { "path": resource, "content": b"{}".to_vec(), "append": false },
    } })
    .to_string()
}

fn issue(bridge: &mut Bridge, resource: &str) -> String {
    let response = dispatch(bridge, &grant(resource), INSTANCE, PRINCIPAL);
    assert_eq!(response["id"], 17);
    assert_eq!(response["response"]["type"], "capability_token");
    response["response"]["token"].as_str().unwrap().into()
}

fn assert_read(response: Value) {
    assert_eq!(response["id"], 23);
    assert_eq!(response["response"]["type"], "resource_result");
    assert_eq!(response["response"]["result"]["status"], "ok");
    assert_eq!(
        response["response"]["result"]["data"]["content"],
        json!(BYTES)
    );
}

fn assert_refused(response: Value, id: u64, code: &str, message: &str) {
    assert_eq!(
        response,
        json!({ "id": id, "response": error(code, message) })
    );
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn ungarded_bridge_still_issues_local_tokens() {
    let mut bridge = bridge();
    assert!(bridge.stand_in.is_none());
    let token = issue(&mut bridge, MEMBER);
    assert_eq!(token, "token-1");
    assert_read(dispatch(
        &mut bridge,
        &invoke(MEMBER, &token),
        INSTANCE,
        PRINCIPAL,
    ));
    assert_eq!(bridge.bytes_served[MEMBER], BYTES.len());
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn guard_allows_a_member_read() {
    let mut bridge = bridge();
    arm(&mut bridge, "stand-in-1");
    assert!(bridge.stand_in.as_ref().unwrap().active);
    let token = issue(&mut bridge, MEMBER);
    assert_eq!(token, "stand-in-1/token-1");
    assert_eq!(
        bridge.issued.get("token-1"),
        Some(&(MEMBER.into(), "read".into()))
    );
    assert_eq!(bridge.issued.len(), 1);
    assert_read(dispatch(
        &mut bridge,
        &invoke(MEMBER, &token),
        INSTANCE,
        PRINCIPAL,
    ));
    assert!(bridge.bytes_served[MEMBER] > 0);
    assert_eq!(bridge.lines.last().unwrap()["request"]["token"], "token-1");

    assert_refused(
        dispatch(&mut bridge, &invoke(MEMBER, ""), INSTANCE, PRINCIPAL),
        23,
        "missing_token",
        "resource_invoke requires a capability token",
    );
    assert_refused(
        dispatch(
            &mut bridge,
            &invoke(MEMBER, "stand-in-1/unknown"),
            INSTANCE,
            PRINCIPAL,
        ),
        23,
        "capability_denied",
        "Capability validation failed",
    );
    bridge.deny(MEMBER, "read");
    assert_refused(
        dispatch(&mut bridge, &grant(MEMBER), INSTANCE, PRINCIPAL),
        17,
        "denied",
        &format!("no read grant for {MEMBER}"),
    );
    bridge.close_stand_in();
    let other = json!({ "id": 29, "request": { "type": "other" } }).to_string();
    let expected = Bridge::default().answer(&other);
    assert_eq!(
        dispatch(&mut bridge, &other, "foreign", "foreign"),
        expected
    );
    assert_eq!(bridge.lines.last().unwrap()["id"], 29);
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn guard_denies_a_read_outside_the_binding() {
    for outside in [
        "localhost://Users/self/Pictures/outside.png",
        "localhost://Users/self/AppData/stand-in/%69nput.png",
        "localhost://Users/self/AppData/stand-in/../stand-in/input.png",
    ] {
        let mut bridge = bridge();
        bridge.put(outside, BYTES.into());
        bridge.allow(outside, "read");
        let token = issue(&mut bridge, outside);
        arm(&mut bridge, "stand-in-1");
        let message =
            format!("Read {outside} is outside content {CONTENT} bound to this stand-in launch.");
        assert_refused(
            dispatch(&mut bridge, &grant(outside), INSTANCE, PRINCIPAL),
            17,
            "denied",
            &message,
        );
        assert_refused(
            dispatch(
                &mut bridge,
                &invoke(outside, &format!("stand-in-1/{token}")),
                INSTANCE,
                PRINCIPAL,
            ),
            23,
            "denied",
            &message,
        );
        bridge.close_stand_in();
        assert_refused(
            dispatch(&mut bridge, &grant(outside), "foreign", "foreign"),
            17,
            "denied",
            &message,
        );
        assert_eq!(bridge.bytes_served.get(outside).copied().unwrap_or(0), 0);
        assert_eq!(bridge.issued.len(), 1);
        assert_eq!(bridge.lines.len(), 1, "the guard must stop before answer");
    }
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn guard_denies_a_write_on_a_content_member() {
    let member = format!("localhost://Users/self/Pictures/Capsules/{CONTENT}/images/input.png");
    let output = "localhost://Users/self/AppData/stand-in/output.txt";
    let mut bridge = Bridge::default();
    bridge.put(&member, BYTES.into());
    bridge.allow(&member, "read");
    // Plant the write grant and an issued token so a missing guard would serve
    // the write rather than fail downstream.
    bridge.allow(&member, "write");
    bridge.allow(output, "write");
    let member_write = dispatch(
        &mut bridge,
        &grant_action(&member, "write"),
        INSTANCE,
        PRINCIPAL,
    );
    let member_write = member_write["response"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    let mut binding = binding("stand-in-1");
    binding.members = [member.clone(), output.into()].into();
    arm_with(&mut bridge, binding);
    let message =
        format!("Content {CONTENT} is read-only; this stand-in launch cannot write {member}.");
    assert_refused(
        dispatch(
            &mut bridge,
            &grant_action(&member, "write"),
            INSTANCE,
            PRINCIPAL,
        ),
        17,
        "denied",
        &message,
    );
    assert_refused(
        dispatch(
            &mut bridge,
            &write(&member, &format!("stand-in-1/{member_write}")),
            INSTANCE,
            PRINCIPAL,
        ),
        23,
        "denied",
        &message,
    );
    assert_eq!(bridge.written.len(), 0);

    // The playlist-equivalent AppData write still works through its own path.
    let response = dispatch(
        &mut bridge,
        &grant_action(output, "write"),
        INSTANCE,
        PRINCIPAL,
    );
    assert_eq!(response["response"]["type"], "capability_token");
    let output_token = response["response"]["token"].as_str().unwrap();
    assert_eq!(
        dispatch(
            &mut bridge,
            &write(output, output_token),
            INSTANCE,
            PRINCIPAL
        )["response"]["result"]["status"],
        "ok"
    );
    assert_eq!(bridge.written[output], "{}");

    // A content member read is still allowed.
    let token = issue(&mut bridge, &member);
    assert_read(dispatch(
        &mut bridge,
        &invoke(&member, &token),
        INSTANCE,
        PRINCIPAL,
    ));
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn guard_denies_a_closed_or_foreign_call() {
    for (close, instance, principal) in [
        (true, INSTANCE, PRINCIPAL),
        (false, INSTANCE, "person:local:other"),
        (false, INSTANCE, ""),
        (false, "other-instance", PRINCIPAL),
    ] {
        let mut bridge = bridge();
        arm(&mut bridge, "stand-in-1");
        let token = issue(&mut bridge, MEMBER);
        if close {
            bridge.close_stand_in();
            assert!(!bridge.stand_in.as_ref().unwrap().active);
        }
        let message = "This stand-in launch is closed or belongs to another instance/principal.";
        assert_refused(
            dispatch(&mut bridge, &invoke(MEMBER, &token), instance, principal),
            23,
            "denied",
            message,
        );
        assert_refused(
            dispatch(&mut bridge, &grant(MEMBER), instance, principal),
            17,
            "denied",
            message,
        );
        assert_eq!(bridge.bytes_served.get(MEMBER).copied().unwrap_or(0), 0);
        assert_eq!(bridge.issued.len(), 1);
        assert_eq!(bridge.lines.len(), 1);
    }
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn guard_rejects_a_grant_from_another_binding() {
    let mut first = bridge();
    let mut second = bridge();
    first.arm_stand_in(binding("stand-in-1")).unwrap();
    second.arm_stand_in(binding("stand-in-2")).unwrap();
    record_loaded_instance(&mut first, INSTANCE);
    record_loaded_instance(&mut second, INSTANCE);
    let token = issue(&mut first, MEMBER);
    let second_token = issue(&mut second, MEMBER);
    assert_ne!(token, second_token);
    assert_eq!(
        first.issued, second.issued,
        "both bridges have the same valid local grant"
    );
    assert_refused(
        dispatch(&mut second, &invoke(MEMBER, &token), INSTANCE, PRINCIPAL),
        23,
        "capability_denied",
        "The grant belongs to another stand-in launch.",
    );
    assert_eq!(second.bytes_served.get(MEMBER).copied().unwrap_or(0), 0);
    assert_eq!(second.lines.len(), 1);
}

fn admits_once() -> StandInBinding {
    let mut binding = binding("stand-in-1");
    let mut calls = 0;
    binding.readmit = Box::new(move || {
        calls += 1;
        if calls == 1 {
            Ok(())
        } else {
            Err("revoked".into())
        }
    });
    binding
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn guard_calls_readmit_before_each_effect() {
    let mut reading = bridge();
    let local_token = issue(&mut reading, MEMBER);
    arm_with(&mut reading, admits_once());
    let line = invoke(MEMBER, &format!("stand-in-1/{local_token}"));
    assert_read(dispatch(&mut reading, &line, INSTANCE, PRINCIPAL));
    let served = reading.bytes_served[MEMBER];
    assert!(served > 0);
    assert_refused(
        dispatch(&mut reading, &line, INSTANCE, PRINCIPAL),
        23,
        "denied",
        "revoked",
    );
    assert_eq!(reading.bytes_served[MEMBER], served);
    assert_eq!(reading.lines.len(), 2);

    let mut granting = bridge();
    arm_with(&mut granting, admits_once());
    assert_eq!(issue(&mut granting, MEMBER), "stand-in-1/token-1");
    assert_refused(
        dispatch(&mut granting, &grant(MEMBER), INSTANCE, PRINCIPAL),
        17,
        "denied",
        "revoked",
    );
    assert_eq!(granting.issued.len(), 1);
    assert_eq!(granting.lines.len(), 1);
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn arming_refuses_an_empty_principal() {
    let mut bridge = bridge();
    let mut binding = binding("stand-in-1");
    binding.principal = String::new();
    assert_eq!(
        bridge.arm_stand_in(binding),
        Err("A stand-in launch needs a caller principal.".into())
    );
    assert!(bridge.stand_in.is_none());
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn guard_denies_a_call_without_a_principal() {
    let mut bridge = bridge();
    // Build the empty-principal binding that arming refuses: a call with no
    // principal must be refused even against it.
    let mut binding = binding("stand-in-1");
    binding.principal = String::new();
    binding.active = true;
    bridge.stand_in = Some(binding);
    record_loaded_instance(&mut bridge, INSTANCE);
    let response = dispatch_principal(&mut bridge, &grant(MEMBER), INSTANCE, Some(""));
    assert_eq!(response["response"]["type"], "capability_token");
    let token = format!(
        "stand-in-1/{}",
        response["response"]["token"].as_str().unwrap()
    );
    let served = bridge.bytes_served.get(MEMBER).copied().unwrap_or(0);
    assert_refused(
        dispatch_principal(&mut bridge, &invoke(MEMBER, &token), INSTANCE, None),
        23,
        "denied",
        super::stand_in::NO_PRINCIPAL,
    );
    assert_eq!(
        bridge.bytes_served.get(MEMBER).copied().unwrap_or(0),
        served
    );
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn run_calls_dispatch_with_the_bus_caller() {
    let source = include_str!("lib.rs");
    let dispatch =
        "        let response = dispatch_principal(&mut host.lock().unwrap(), line, capsule, principal);";
    let callback = "move |line, capsule, principal| {";
    assert_eq!(source.matches(dispatch).count(), 1);
    assert_eq!(source.matches(callback).count(), 1);
    let first_statement = source
        .split_once(callback)
        .expect("the bus hostcall callback is present")
        .1
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with("//"));
    assert_eq!(first_statement, Some(dispatch.trim()));
    assert!(!source.contains("let principal = principal.unwrap_or_default();"));
    assert!(!source.contains("_capsule, _principal"));
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn record_loaded_instance_sets_only_the_instance_id() {
    for active in [false, true] {
        let mut bridge = bridge();
        let mut binding = binding("stand-in-1");
        binding.instance_id = "placeholder".into();
        binding.principal = "person:local:other".into();
        let mut calls = 0;
        binding.readmit = Box::new(move || {
            calls += 1;
            Err(format!("readmit-{calls}"))
        });
        bridge.arm_stand_in(binding).unwrap();
        if !active {
            bridge.close_stand_in();
        }
        assert_eq!(
            (bridge.stand_in.as_mut().unwrap().readmit)(),
            Err("readmit-1".into())
        );

        record_loaded_instance(&mut bridge, "component-1");

        let binding = bridge.stand_in.as_mut().unwrap();
        assert_eq!(binding.instance_id, "component-1");
        assert_eq!(binding.active, active);
        assert_eq!(binding.principal, "person:local:other");
        assert_eq!(binding.members, [MEMBER.into()].into());
        assert_eq!(binding.binding_id, "stand-in-1");
        assert_eq!(binding.content_cid, CONTENT);
        assert_eq!((binding.readmit)(), Err("readmit-2".into()));
    }

    let mut bridge = bridge();
    record_loaded_instance(&mut bridge, "component-1");
    assert!(bridge.stand_in.is_none());
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn run_records_the_loaded_instance_before_start() {
    let source = include_str!("lib.rs");
    let record = "    record_loaded_instance(&mut bridge.lock().unwrap(), &handle.id.0);";
    assert_eq!(source.lines().filter(|line| *line == record).count(), 1);
    let principal = source
        .find(".set_bridge_principal(&handle.id, Some(STAND_IN_TEST_PRINCIPAL.into()))\n        .await;")
        .unwrap();
    let record = source.find(record).unwrap();
    let start = source.find("provider.start").unwrap();
    assert!(principal < record && record < start);
}
