#![cfg(all(feature = "prototype-agents", target_os = "macos"))]
//! The hosted rows reach the egress broker through the production model spawn.
//! `spawn_confined_model` starts the existing hosted-effect probe as a real
//! child and stores that child's pid and birth. `from_io` is not used here,
//! and this file does not name the test process.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use elastos_runtime::provider::bridge::{
    BridgeError, ProviderConfig, ProviderRequest, ProviderResponse,
};
use elastos_runtime::provider::ProviderBridge;

use super::{create_grant_after_decision, egress_scope, resolve_effect, EffectRequest};

fn hosted_text_effect(
    data_dir: &Path,
    offer_id: &str,
    run_id: &str,
    request_id: &str,
) -> anyhow::Result<EffectRequest> {
    let offers = super::load_model_provider_operator_offers(data_dir)?;
    let offer = offers
        .iter()
        .find(|offer| offer["id"] == offer_id)
        .ok_or_else(|| anyhow::anyhow!("hosted offer unavailable"))?;
    let model = offer["adapter"]["model"].as_str().unwrap_or_default();
    let limit = offer["policy"]["inline_output_bytes_limit"]
        .as_u64()
        .unwrap_or(0);
    let body = serde_json::json!({
        "model": model,
        "max_tokens": (limit / 4).max(1),
        "messages": [{"role": "user", "content": "hi"}],
    });
    Ok(EffectRequest {
        offer_id: offer_id.to_string(),
        effect: "text".to_string(),
        run_id: run_id.to_string(),
        request_id: request_id.to_string(),
        job_id: None,
        method: reqwest::Method::POST,
        body: serde_json::to_vec(&body)?,
    })
}

pub(crate) fn approve_hosted_text_for_test(
    data_dir: &Path,
    offer_id: &str,
    run_id: &str,
    request_id: &str,
    owner_proof: &str,
) -> anyhow::Result<String> {
    let request = hosted_text_effect(data_dir, offer_id, run_id, request_id)?;
    let destination = resolve_effect(data_dir, &request)?;
    let scope = egress_scope(offer_id, "text", "POST", &destination)?;
    let id = super::model_provider_egress_decision::request(data_dir, &scope, None)?;
    super::model_provider_egress_decision::approve(data_dir, &id, owner_proof)?;
    create_grant_after_decision(
        data_dir,
        offer_id,
        "text",
        "POST",
        &destination,
        None,
        Some((run_id, request_id)),
    )?;
    Ok(id)
}

pub(crate) fn end_hosted_decision_for_test(
    data_dir: &Path,
    id: &str,
    owner_proof: &str,
) -> anyhow::Result<()> {
    super::model_provider_egress_decision::end_decision(data_dir, id, owner_proof)
}

fn compile_hosted_probe(base: &Path) -> anyhow::Result<std::path::PathBuf> {
    let source = base.join("hosted-effect-probe.c");
    std::fs::write(
        &source,
        include_str!("../../../tests/fixtures/hosted_effect_probe.c"),
    )?;
    let binary = base.join("hosted-effect-probe");
    let status = std::process::Command::new("/usr/bin/clang")
        .args(["-O2", "-Wall", "-Wextra", "-o"])
        .arg(&binary)
        .arg(&source)
        .status()?;
    if !status.success() {
        anyhow::bail!("hosted-effect probe did not compile");
    }
    Ok(binary)
}

/// Sends one hosted effect through the production confined model spawn.
/// The returned text is the broker reply the child read.
pub(crate) async fn forward_hosted_text_for_test(
    data_dir: &Path,
    runs_create: &serde_json::Value,
    run_id: &str,
    request_id: &str,
) -> anyhow::Result<String> {
    let base = data_dir.canonicalize()?;
    let binary = compile_hosted_probe(&base)?;
    let journal = base.join("providers/model-provider/journal");
    let config = ProviderConfig {
        base_path: base.to_string_lossy().into_owned(),
        extra: serde_json::json!({
            "offers": [],
            "journal_dir": journal,
        }),
        ..Default::default()
    };
    let checked = crate::test_support::fixture_executable(&binary);
    let mut attempts = 0u32;
    let spawned = loop {
        match ProviderBridge::spawn_confined_model(&checked, config.clone()).await {
            Err(BridgeError::Spawn(error))
                if error.kind() == std::io::ErrorKind::ExecutableFileBusy && attempts < 40 =>
            {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(25));
            }
            other => break other,
        }
    };
    let (bridge, _, _, confined_config, listener) =
        spawned.map_err(|err| anyhow::anyhow!("confined model spawn failed: {err}"))?;
    let bridge = Arc::new(bridge);
    if let Err(err) = super::start(listener, bridge.clone(), data_dir.to_path_buf()) {
        let _ = bridge.shutdown().await;
        anyhow::bail!("hosted broker did not start: {err}");
    }
    let sent = bridge.send_raw(runs_create).await;
    let offer_id = runs_create["offer_id"].as_str().unwrap_or("");
    let effect =
        hosted_text_effect(data_dir, offer_id, run_id, request_id).and_then(|mut effect| {
            let mut body: serde_json::Value = serde_json::from_slice(&effect.body)?;
            body["stream"] = serde_json::json!(true);
            effect.body = serde_json::to_vec(&body)?;
            Ok(effect)
        });
    let hosted_socket = confined_config.extra["runtime_hosted_socket"]
        .as_str()
        .map(str::to_owned);
    let asked = match (sent, effect, hosted_socket) {
        (Ok(_), Ok(effect), Some(hosted_socket)) => {
            let path = format!(
                "{hosted_socket}|{offer_id}|{run_id}|{request_id}|{}",
                hex::encode(&effect.body)
            );
            bridge
                .request(ProviderRequest::Exists {
                    path,
                    token: String::new(),
                })
                .await
        }
        (Err(err), _, _) => Err(err),
        (_, Err(err), _) => {
            let _ = bridge.shutdown().await;
            return Err(err);
        }
        (_, _, None) => {
            let _ = bridge.shutdown().await;
            anyhow::bail!("hosted socket was not recorded");
        }
    };
    let _ = bridge.shutdown().await;
    let response = asked.map_err(|err| anyhow::anyhow!("hosted probe request failed: {err}"))?;
    let ProviderResponse::Ok { data: Some(data) } = response else {
        anyhow::bail!("hosted probe returned no reply");
    };
    let reply_hex = data["http_reply"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("hosted probe reply missing"))?;
    let bytes = hex::decode(reply_hex).map_err(|err| anyhow::anyhow!("{err}"))?;
    let reply = String::from_utf8_lossy(&bytes).into_owned();
    if !reply.starts_with(
        data["http_status"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("hosted probe status missing"))?,
    ) {
        anyhow::bail!("hosted probe status does not match the broker reply");
    }
    Ok(reply)
}
