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

impl Bridge {
    pub fn arm_stand_in(&mut self, mut binding: StandInBinding) {
        binding.active = true;
        self.stand_in = Some(binding);
    }

    pub fn close_stand_in(&mut self) {
        if let Some(binding) = self.stand_in.as_mut() {
            binding.active = false;
        }
    }
}

pub(crate) fn record_loaded_instance(bridge: &mut Bridge, instance_id: &str) {
    let Some(binding) = bridge.stand_in.as_mut() else {
        return;
    };
    binding.instance_id = instance_id.into();
}

pub fn dispatch(bridge: &mut Bridge, line: &str, capsule: &str, principal: &str) -> Value {
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
    let refuse = |code: &str, message: &str| json!({ "id": envelope["id"], "response": error(code, message) });
    if !binding.members.contains(resource) {
        return refuse(
            "denied",
            &format!(
                "Read {resource} is outside content {} bound to this stand-in launch.",
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
