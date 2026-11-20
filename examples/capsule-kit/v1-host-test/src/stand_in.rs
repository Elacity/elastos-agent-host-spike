//! This test code stands in for the Runtime's launch by CID, which does not exist yet.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use super::{error, Bridge};

pub const STAND_IN_TEST_PRINCIPAL: &str = "person:local:test";

pub struct StandInBinding {
    pub binding_id: String,
    pub content_cid: String,
    pub instance_id: String,
    pub principal: String,
    pub members: BTreeSet<String>,
    pub active: bool,
    pub readmit: Box<dyn FnMut() -> Result<(), String> + Send>,
}

pub const NO_PRINCIPAL: &str = "This stand-in launch has no caller principal.";

impl Bridge {
    pub fn arm_stand_in(&mut self, mut binding: StandInBinding) -> Result<(), String> {
        if binding.principal.is_empty() {
            return Err("A stand-in launch needs a caller principal.".into());
        }
        binding.active = true;
        self.stand_in = Some(binding);
        Ok(())
    }

    pub fn close_stand_in(&mut self) {
        if let Some(binding) = self.stand_in.as_mut() {
            binding.active = false;
        }
    }
}

pub fn record_loaded_instance(bridge: &mut Bridge, instance_id: &str) {
    let Some(binding) = bridge.stand_in.as_mut() else {
        return;
    };
    binding.instance_id = instance_id.into();
}

/// A member under the bound content CID is the content itself: read-only.
fn is_content_member(binding: &StandInBinding, resource: &str) -> bool {
    resource.starts_with(&format!(
        "localhost://Users/self/Pictures/Capsules/{}/",
        binding.content_cid
    ))
}

pub fn dispatch(bridge: &mut Bridge, line: &str, capsule: &str, principal: &str) -> Value {
    dispatch_principal(bridge, line, capsule, Some(principal))
}

pub fn dispatch_principal(
    bridge: &mut Bridge,
    line: &str,
    capsule: &str,
    principal: Option<&str>,
) -> Value {
    let Some(binding) = bridge.stand_in.as_mut() else {
        return bridge.answer(line);
    };
    let mut envelope: Value = serde_json::from_str(line).expect("bridge line is JSON");
    let request = &envelope["request"];
    let resource = match request["type"].as_str() {
        Some("request_capability") => request["resource"].as_str().unwrap_or_default(),
        Some("resource_invoke") => request["uri"].as_str().unwrap_or_default(),
        _ => return bridge.answer(line),
    };
    let action = match request["type"].as_str() {
        Some("request_capability") => request["action"].as_str().unwrap_or_default(),
        Some("resource_invoke") => request["operation"].as_str().unwrap_or_default(),
        _ => return bridge.answer(line),
    };
    let refuse = |code: &str, message: &str| json!({ "id": envelope["id"], "response": error(code, message) });
    // The stand-in plays a launch through the person's storage names. The
    // Runtime's own launch names are answered as the bridge answers them when
    // there is no content launch.
    if resource.starts_with("elastos://launch/") {
        return bridge.answer(line);
    }
    let Some(principal) = principal else {
        return refuse("denied", NO_PRINCIPAL);
    };
    if !binding.members.contains(resource) {
        return refuse(
            "denied",
            &format!(
                "Read {resource} is outside content {} bound to this stand-in launch.",
                binding.content_cid
            ),
        );
    }
    if is_content_member(binding, resource) && action != "read" {
        return refuse(
            "denied",
            &format!(
                "Content {} is read-only; this stand-in launch cannot {action} {resource}.",
                binding.content_cid
            ),
        );
    }
    if !binding.active || capsule != binding.instance_id || principal != binding.principal {
        return refuse(
            "denied",
            "This stand-in launch is closed or belongs to another instance/principal.",
        );
    }
    if let Err(reason) = (binding.readmit)() {
        let reason: String = reason;
        return refuse("denied", &reason);
    }
    let prefix = format!("{}/", binding.binding_id);
    if request["type"] == "resource_invoke" {
        let token = request["token"].as_str().unwrap_or_default();
        if !token.is_empty() && !token.starts_with(&prefix) {
            return refuse(
                "capability_denied",
                "The grant belongs to another stand-in launch.",
            );
        }
        if !token.is_empty() {
            envelope["request"]["token"] = json!(&token[prefix.len()..]);
            return bridge.answer(&envelope.to_string());
        }
        return bridge.answer(line);
    }
    let mut response = bridge.answer(line);
    if let Some(token) = response["response"]["token"].as_str() {
        response["response"]["token"] = json!(format!("{prefix}{token}"));
    }
    response
}
