use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Route an admitted Component's bus calls through the operator Runtime.
/// The ceiling comes from the active instance, after bundle admission.
fn configure_component_bridge(runtime: &Arc<elastos_server::runtime::Runtime>, data_dir: &Path) {
    let bridge_runtime = Arc::downgrade(runtime);
    let audit_data_dir = data_dir.to_path_buf();
    let hostcall_handle = tokio::runtime::Handle::current();
    let session = tokio::sync::OnceCell::<(String, String)>::new();
    runtime.set_bridge_hostcall(Arc::new(move |line, capsule_id, principal_id| {
        let runtime = bridge_runtime
            .upgrade()
            .ok_or_else(|| "Component Runtime has ended".to_string())?;
        let manifest_capabilities = runtime
            .bridge_bounds_for_capsule(capsule_id)
            .ok_or_else(|| "Component has no admitted bridge ceiling".to_string())?;
        let response = hostcall_handle.block_on(async {
            let (api_url, client_token) = session
                .get_or_try_init(|| async {
                    let coords = operator_runtime_coords()
                        .await
                        .map_err(|error| error.to_string())?;
                    let tokens = crate::runtime_control::attach_to_runtime(&coords)
                        .await
                        .map_err(|error| error.to_string())?;
                    Ok::<_, String>((coords.api_url, tokens.client_token))
                })
                .await?;
            elastos_server::resource_bridge::handle_remote_request_with_audit_dir(
                line,
                api_url,
                client_token,
                capsule_id,
                &manifest_capabilities,
                principal_id,
                Some(audit_data_dir.as_path()),
            )
            .await
            .map_err(|error| error.to_string())
        })?;
        serde_json::to_string(&response).map_err(|error| error.to_string())
    }));
}

pub async fn run_capsule(
    path: Option<PathBuf>,
    cid: Option<String>,
    with: Vec<String>,
    carrier_addr: Option<String>,
    dev_unsigned_component: bool,
    capsule_args: Vec<String>,
) -> anyhow::Result<()> {
    if dev_unsigned_component && (!with.is_empty() || carrier_addr.is_some() || cid.is_some()) {
        anyhow::bail!("--dev-unsigned-component takes only a local Component folder");
    }
    if let Some(plan) = resolve_provider_host_plan(
        path.as_deref(),
        cid.as_deref(),
        &with,
        carrier_addr.as_deref(),
    )? {
        if !capsule_args.is_empty() {
            anyhow::bail!(
                "a native provider host takes no capsule arguments; got: {}",
                capsule_args.join(" ")
            );
        }
        return crate::provider_host::run(plan).await;
    }
    if !with.is_empty() || carrier_addr.is_some() {
        anyhow::bail!(
            "--with and --carrier-addr apply only when hosting a native provider; supported providers are: {}",
            crate::provider_host::ProviderPlane::supported_set()
        );
    }

    let capsule_dir = resolve_capsule_dir(path, cid).await?;
    // A pinned Component manifest has keys the legacy manifest reader does
    // not know. Select this path by its type and ABI; staged admission reads
    // and verifies the complete manifest before anything runs.
    if is_component_bundle(&capsule_dir).await? {
        return if dev_unsigned_component {
            run_unsigned_development_component(&capsule_dir, capsule_args).await
        } else {
            run_staged_component(&capsule_dir, capsule_args).await
        };
    }
    if dev_unsigned_component {
        anyhow::bail!("--dev-unsigned-component requires a Component manifest");
    }
    let manifest = load_valid_manifest_if_present(&capsule_dir).await?;

    if let Some(ref manifest) = manifest {
        match manifest.execution_type() {
            elastos_common::CapsuleType::WebProjection => {
                anyhow::bail!("Web projection '{}' opens through Home", manifest.name);
            }
            elastos_common::CapsuleType::NativeHost => {
                anyhow::bail!(
                    "Native host helper '{}' is launched only by Runtime",
                    manifest.name
                );
            }
            elastos_common::CapsuleType::NativeProvider => {
                anyhow::bail!("Native provider '{}' is launched only through trusted Runtime components; capsule manifests grant no native execution", manifest.name);
            }
            elastos_common::CapsuleType::MicroVM => {
                return run_microvm_via_operator_runtime(manifest, &capsule_args).await;
            }
            elastos_common::CapsuleType::Wasm => {
                if !manifest.is_component_capsule() {
                    anyhow::bail!(
                        "WASI Preview 1 capsules are not supported; '{}' must use runtime_abi=\"elastos.component/v1\"",
                        manifest.name
                    );
                }
                return run_staged_component(&capsule_dir, capsule_args).await;
            }
            elastos_common::CapsuleType::Data => {
                let runtime =
                    crate::create_runtime(crate::default_data_dir().join("storage")).await?;
                let addr = crate::find_free_local_addr()?;
                return crate::serve_web_capsule(runtime, capsule_dir, &addr, true, Some(20)).await;
            }
            _ => {}
        }
    }

    let runtime = crate::create_runtime(crate::default_data_dir().join("storage")).await?;
    let handle = runtime.run_local(&capsule_dir, capsule_args).await?;

    match handle.manifest.capsule_type {
        elastos_common::CapsuleType::Wasm => {}
        _ => {
            println!(
                "Capsule '{}' running (ID: {})",
                handle.manifest.name, handle.id
            );
            println!("Press Ctrl+C to stop...");
            tokio::signal::ctrl_c().await?;
            println!("\nStopping capsule...");
            runtime.stop(&handle).await?;
            println!("Capsule stopped.");
        }
    }

    Ok(())
}

/// `elastos run --bundle <cid>`: start a bundle from this Home's store of
/// bundles named by CID: a program, or content, for which the program of
/// its viewer starts (the name printed is then that program's, the signer
/// the content's). The Runtime is made as `stage-bundle` makes it, so
/// the keys asked are the keys that staging asked. This path fetches nothing
/// and attaches to no running Runtime, and no bridge handler is installed
/// here. So a capsule whose manifest has asks has nothing to ask through:
/// its call to the bridge is answered "unavailable" before any ceiling is
/// looked at. One without asks is sealed.
pub async fn run_bundle(cid: &str) -> anyhow::Result<()> {
    let data_dir = crate::default_data_dir();
    let runtime = crate::create_runtime(data_dir.join("storage")).await?;
    let (handle, accepted) = runtime
        .run_by_bundle(&data_dir, cid, Vec::new(), None)
        .await?;
    println!(
        "{}",
        serde_json::json!({
            "cid": cid,
            "name": handle.manifest.name,
            "signer_did": accepted.signer_did,
            "ended": "ok",
        })
    );
    Ok(())
}

/// Decide whether this `elastos run` invocation hosts a native provider.
///
/// App-capsule behavior is untouched: a `--cid` run and any target that is an
/// existing capsule directory take the capsule path exactly as before. Only a
/// target that cannot be a capsule directory is read as a provider, so an
/// unknown one fails closed naming the supported set instead of dying on a
/// missing `capsule.json`.
fn resolve_provider_host_plan(
    path: Option<&Path>,
    cid: Option<&str>,
    with: &[String],
    carrier_addr: Option<&str>,
) -> anyhow::Result<Option<crate::provider_host::ProviderHostPlan>> {
    if cid.is_some() {
        return Ok(None);
    }
    let Some(target) = path else {
        return Ok(None);
    };
    if target.is_dir() {
        return Ok(None);
    }
    let target = target
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("run target must be valid UTF-8"))?;

    crate::provider_host::ProviderHostPlan::resolve(
        crate::default_data_dir(),
        target,
        with,
        carrier_addr,
    )
    .map(Some)
    .map_err(|err| err.context(format!("'{target}' is not an existing capsule directory")))
}

async fn resolve_capsule_dir(
    path: Option<PathBuf>,
    cid: Option<String>,
) -> anyhow::Result<PathBuf> {
    if let Some(cid) = cid {
        tracing::info!("Running capsule from CID: {}", cid);
        let content_registry = crate::get_content_registry().await?;
        return elastos_server::content::prepare_capsule_from_content_provider(
            &content_registry,
            &cid,
        )
        .await;
    }

    if let Some(path) = path {
        tracing::info!("Running capsule from: {}", path.display());
        return Ok(path);
    }

    anyhow::bail!("Either path or --cid must be specified");
}

async fn load_valid_manifest_if_present(
    capsule_dir: &Path,
) -> anyhow::Result<Option<elastos_common::CapsuleManifest>> {
    let manifest_path = capsule_dir.join("capsule.json");
    if !manifest_path.exists() {
        return Ok(None);
    }

    let data = elastos_common::capsule_manifest_file::read(&manifest_path)?;
    let manifest: elastos_common::CapsuleManifest = serde_json::from_slice(&data)?;
    manifest
        .validate()
        .map_err(|e| anyhow::anyhow!("Invalid manifest: {}", e))?;
    Ok(Some(manifest))
}

async fn is_component_bundle(capsule_dir: &Path) -> anyhow::Result<bool> {
    let manifest = capsule_dir.join("capsule.json");
    if !manifest.exists() {
        return Ok(false);
    }
    let value: serde_json::Value = serde_json::from_slice(&tokio::fs::read(manifest).await?)?;
    Ok(
        value.get("type").and_then(|value| value.as_str()) == Some("wasm")
            && value.get("runtime_abi").and_then(|value| value.as_str())
                == Some("elastos.component/v1"),
    )
}

async fn run_staged_component(capsule_dir: &Path, capsule_args: Vec<String>) -> anyhow::Result<()> {
    let data_dir = crate::default_data_dir();
    let runtime = Arc::new(crate::create_runtime(data_dir.join("storage")).await?);
    configure_component_bridge(&runtime, &data_dir);
    let _term_env = crate::capsule_cmd::ScopedTerminalEnv::capture();
    let _saved_termios = crate::runtime_control::enable_host_raw_mode_pub();
    let (handle, _) = elastos_server::stage_cmd::run_staged_folder(
        &runtime,
        &data_dir,
        capsule_dir,
        capsule_args,
    )
    .await
    .map_err(|error| match error {
        elastos_server::bundle_admission::BundleRefusal::Missing(_) => anyhow::anyhow!(
            "{error}; stage the signed folder with `elastos stage-bundle <folder> --signature <file>`"
        ),
        other => other.into(),
    })?;
    eprintln!("[run] Component capsule '{}' exited", handle.manifest.name);
    Ok(())
}

async fn run_unsigned_development_component(
    capsule_dir: &Path,
    capsule_args: Vec<String>,
) -> anyhow::Result<()> {
    let data_dir = crate::default_data_dir();
    let runtime = Arc::new(crate::create_runtime(data_dir.join("storage")).await?);
    configure_component_bridge(&runtime, &data_dir);
    let _term_env = crate::capsule_cmd::ScopedTerminalEnv::capture();
    let _saved_termios = crate::runtime_control::enable_host_raw_mode_pub();
    let handle = runtime
        .run_unsigned_development_component(capsule_dir, capsule_args)
        .await?;
    eprintln!(
        "[run] Development Component capsule '{}' exited",
        handle.manifest.name
    );
    Ok(())
}

async fn operator_runtime_coords() -> anyhow::Result<crate::runtime_control::RuntimeCoords> {
    let data_dir = crate::default_data_dir();
    let coords_path = crate::runtime_control::runtime_coord_path(&data_dir);
    crate::runtime_control::read_operator_runtime_coords(&coords_path)
        .await
        .ok_or_else(|| anyhow::anyhow!(crate::runtime_control::OPERATOR_RUNTIME_REQUIRED_MESSAGE))
}

async fn run_microvm_via_operator_runtime(
    manifest: &elastos_common::CapsuleManifest,
    capsule_args: &[String],
) -> anyhow::Result<()> {
    let coords = operator_runtime_coords().await?;
    eprintln!("[run] Attaching to runtime at {}", coords.api_url);

    let tokens = crate::runtime_control::attach_to_runtime(&coords).await?;
    let client = reqwest::Client::new();
    let _ = client
        .post(format!("{}/api/supervisor/ensure-capsule", coords.api_url))
        .header("Authorization", format!("Bearer {}", tokens.shell_token))
        .json(&serde_json::json!({"name": &manifest.name}))
        .send()
        .await;

    let resp = client
        .post(format!("{}/api/supervisor/launch-capsule", coords.api_url))
        .header("Authorization", format!("Bearer {}", tokens.shell_token))
        .json(&serde_json::json!({
            "name": &manifest.name,
            "config": {},
            "interactive": true,
            "capsule_args": capsule_args,
        }))
        .send()
        .await?;
    let body: serde_json::Value = resp.json().await?;
    if body.get("status").and_then(|s| s.as_str()) != Some("ok") {
        anyhow::bail!(
            "Launch failed: {}",
            body.get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("unknown")
        );
    }

    let handle = body["handle"].as_str().unwrap_or("?").to_string();
    eprintln!("[run] MicroVM '{}' launched: {}", manifest.name, handle);
    let saved = crate::runtime_control::enable_host_raw_mode_pub();
    tokio::signal::ctrl_c().await?;
    drop(saved);
    let _ = client
        .post(format!("{}/api/supervisor/stop-capsule", coords.api_url))
        .header("Authorization", format!("Bearer {}", tokens.shell_token))
        .json(&serde_json::json!({"handle": handle}))
        .send()
        .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_refuses_projection_and_arbitrary_native_manifests() {
        for (source, expected) in [
            (
                include_str!("../../../../templates/capsules/web-app/capsule.json"),
                "opens through Home",
            ),
            (
                include_str!("../../../../templates/capsules/provider-contract/capsule.json"),
                "trusted Runtime components",
            ),
            (
                include_str!("../../../../capsules/model-provider/capsule.json"),
                "trusted Runtime components",
            ),
            (
                include_str!("../../../../capsules/home/capsule.json"),
                "opens through Home",
            ),
            (
                include_str!("../../../capsules/shell/capsule.json"),
                "launched only by Runtime",
            ),
        ] {
            let directory = tempfile::tempdir().unwrap();
            std::fs::write(directory.path().join("capsule.json"), source).unwrap();
            let error = run_capsule(
                Some(directory.path().to_path_buf()),
                None,
                Vec::new(),
                None,
                false,
                Vec::new(),
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    // A Component requirement with a CID pin needs the staged manifest reader.
    const PINNED: &str = r#"{"schema":"elastos.capsule/v1","name":"pinned-fixture","version":"0.1.0","role":"app","type":"wasm","runtime_abi":"elastos.component/v1","bus_contract":"elastos:bus@v1","wit_world_sha256":"7a026e0a641c8c04214576dc85a677e0b52c9f02866d231119f9a3ba609d49e2","execution":"component","projections":["cli"],"entrypoint":"app.wasm","requires":[{"name":"viewer","kind":"capsule","cid":"bafybeicesjf2ejdmnav65ijpbr3qq2blx4ldp6c5tdtczmv5bwim3ndbsy"}]}"#;

    #[tokio::test]
    async fn pinned_component_selects_staged_admission_before_legacy_parse() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("capsule.json"), PINNED).unwrap();
        assert!(is_component_bundle(directory.path()).await.unwrap());
    }

    /// a4 (R6-2a): the three CLI senders put the host keys in the typed
    /// `interactive` / `capsule_args` fields and carry no `_elastos_` key in
    /// `config`. These are source pins with exact literals: each body is one
    /// inline `json!` sent straight to the runtime, with no seam a test can
    /// hold, and `elastos run` then blocks on Ctrl-C, so no in-process drive
    /// reaches a literal outcome. A sender that moves a key back turns this
    /// row red at the pinned line.
    #[test]
    fn r6_2a_cli_senders_use_the_typed_fields_and_send_no_host_key() {
        fn production_text(source: &str) -> &str {
            let end = source.find("\nmod tests {").unwrap_or(source.len());
            &source[..end]
        }

        let run = production_text(include_str!("run_cmd.rs"));
        assert_eq!(run.matches("\"config\": {},").count(), 1, "run config");
        assert_eq!(
            run.matches("\"interactive\": true,").count(),
            1,
            "run interactive"
        );
        assert_eq!(
            run.matches("\"capsule_args\": capsule_args,").count(),
            1,
            "run capsule_args"
        );
        assert_eq!(run.matches("_elastos_").count(), 0, "run host key");

        let capsule = production_text(include_str!("capsule_cmd.rs"));
        assert_eq!(
            capsule
                .matches("\"config\": serde_json::Value::Object(config),")
                .count(),
            1,
            "capsule config"
        );
        assert_eq!(
            capsule.matches("\"interactive\": interactive,").count(),
            1,
            "capsule interactive"
        );
        assert_eq!(capsule.matches("_elastos_").count(), 0, "capsule host key");

        let shell = production_text(include_str!("../../../capsules/shell/src/main.rs"));
        assert_eq!(
            shell.matches("\"config\": config,").count(),
            1,
            "shell config"
        );
        assert_eq!(
            shell
                .matches("\"interactive\": i == last_idx && spec.interactive_target,")
                .count(),
            1,
            "shell interactive"
        );
        assert_eq!(shell.matches("_elastos_").count(), 0, "shell host key");
    }
}
