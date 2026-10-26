//! Two-process A2 journal driver. Each invocation is one Runtime process
//! on a shared store. The guest writes and resumes through the real
//! component bridge. Stale and follow-up writes use that same bridge.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use elastos_common::localhost::rooted_localhost_fs_path;
use elastos_compute::providers::ComponentProvider;
use elastos_runtime::capability::{
    Action, CapabilityManager, GrantDuration, ResourceId, TokenConstraints,
};
use elastos_runtime::primitives::audit::AuditLog;
use elastos_runtime::primitives::metrics::MetricsManager;
use elastos_runtime::provider::ProviderRegistry;
use elastos_server::auth::{
    load_principal_root_protection, principal_localhost_root, read_principal_root_object,
    store_test_principal_root_protection,
};
use elastos_server::resource_bridge::{handle_component_resource_request, BridgeContext};
use elastos_server::runtime::Runtime;
use elastos_storage::providers::LocalFSProvider;
use sha2::{Digest, Sha256};
use tokio::time::timeout;

const PERSON: &str = "person:local:agent-host-e2e";
const SELF_URI: &str = "localhost://Users/self/.AppData/Agents/agent-host/tasks/demo/journal";
const STATE_FILE: &str = "a2-resume-state.json";

#[derive(Clone)]
struct Host {
    runtime: Arc<Runtime>,
    capability_manager: Arc<CapabilityManager>,
    pending_store: Arc<elastos_runtime::capability::pending::PendingRequestStore>,
    data_dir: PathBuf,
    ctx: BridgeContext,
    object_uri: String,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("DRIVER_ERROR {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let phase = args.next().unwrap_or_default();
    let store = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("usage: a2-resume-driver first|second <store-dir>"))?;
    match phase.as_str() {
        "first" => first(&store).await,
        "second" => second(&store).await,
        _ => bail!("usage: a2-resume-driver first|second <store-dir>"),
    }
}

async fn first(store: &Path) -> Result<()> {
    println!("PROCESS first pid={}", std::process::id());
    let host = setup(store, true).await?;
    let before_exists = journal_path(&host).exists();
    match launch_guest(&host).await {
        Ok(()) => {
            let (plain, revision) = read_journal(&host).await?;
            if before_exists {
                row(
                    "WRITE",
                    "FAIL",
                    "store already had a journal before the first launch",
                );
                return Ok(());
            }
            if plain.len() < 6 || &plain[..4] != b"EAHJ" || plain[4..6] != 2u16.to_le_bytes() {
                row(
                    "WRITE",
                    "FAIL",
                    &format!("stored bytes are not format 2 (len={})", plain.len()),
                );
                return Ok(());
            }
            row(
                "WRITE",
                "PASS",
                &format!(
                    "guest wrote format-2 journal through the real bridge; revision={} sha256={} bytes={}",
                    revision,
                    sha256_hex(&plain),
                    plain.len()
                ),
            );
            write_state(
                store,
                &serde_json::json!({
                    "revision": revision,
                    "sha256": sha256_hex(&plain),
                    "bytes": plain.len(),
                    "first_pid": std::process::id(),
                }),
            )?;
            stale_write(&host, &plain, &revision).await?;
        }
        Err(error) => {
            row("WRITE", "FAIL", &format!("guest launch: {error:#}"));
        }
    }
    Ok(())
}

async fn second(store: &Path) -> Result<()> {
    println!("PROCESS second pid={}", std::process::id());
    let state = read_state(store)?;
    let expected_rev = state["revision"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("state missing revision"))?
        .to_string();
    let expected_sha = state["sha256"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("state missing sha256"))?
        .to_string();
    let host = setup(store, false).await?;
    let (before, before_rev) = read_journal(&host).await?;
    if sha256_hex(&before) != expected_sha || before_rev != expected_rev {
        row(
            "RESUME",
            "FAIL",
            "store on the fresh process does not match the first process",
        );
        return Ok(());
    }
    match launch_guest(&host).await {
        Ok(()) => {
            let (after, after_rev) = read_journal(&host).await?;
            if sha256_hex(&after) != expected_sha || after_rev != expected_rev {
                row(
                    "RESUME",
                    "FAIL",
                    &format!(
                        "new launch overwrote the stored journal; before={} after={}",
                        expected_sha,
                        sha256_hex(&after)
                    ),
                );
                return Ok(());
            }
            row(
                "RESUME",
                "PASS",
                &format!(
                    "fresh process loaded the latest revision without writing; revision={} sha256={}",
                    after_rev,
                    sha256_hex(&after)
                ),
            );
            write_again(&host, &after, &after_rev).await?;
        }
        Err(error) => {
            let (after, after_rev) = read_journal(&host)
                .await
                .unwrap_or((before.clone(), expected_rev.clone()));
            let kept = sha256_hex(&after) == expected_sha && after_rev == expected_rev;
            row(
                "RESUME",
                "FAIL",
                &format!("guest launch on the fresh process: {error:#}; stored kept={kept}"),
            );
        }
    }
    Ok(())
}

async fn stale_write(host: &Host, latest: &[u8], revision: &str) -> Result<()> {
    let forged = b"stale if_revision replay";
    let reply = bridge_write(
        host,
        forged,
        serde_json::json!({ "if_revision": "stale-not-current" }),
    )
    .await?;
    let code = reply
        .pointer("/response/result/code")
        .or_else(|| reply.pointer("/response/code"))
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    let (kept, kept_rev) = read_journal(host).await?;
    let unchanged = kept == latest && kept_rev == revision;
    if code == "revision_conflict" && unchanged {
        row(
            "STALE",
            "PASS",
            &format!(
                "stale if_revision refused with revision_conflict; stored sha256={}",
                sha256_hex(&kept)
            ),
        );
    } else {
        row(
            "STALE",
            "FAIL",
            &format!("code={code:?} unchanged={unchanged} reply={reply}"),
        );
    }
    Ok(())
}

async fn write_again(host: &Host, latest: &[u8], revision: &str) -> Result<()> {
    let mut next = latest.to_vec();
    next.extend_from_slice(b"\n#a2-resume-write");
    let reply = bridge_write(host, &next, serde_json::json!({ "if_revision": revision })).await?;
    let status = reply
        .pointer("/response/result/status")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let new_rev = reply
        .pointer("/response/result/data/revision")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    let (stored, stored_rev) = read_journal(host).await?;
    if status == "ok" && new_rev != revision && stored == next && stored_rev == new_rev {
        row(
            "WRITE2",
            "PASS",
            &format!(
                "write with the loaded revision stored a new revision; old={} new={}",
                revision, new_rev
            ),
        );
    } else {
        row(
            "WRITE2",
            "FAIL",
            &format!("status={status:?} new_rev={new_rev:?} reply={reply}"),
        );
    }
    Ok(())
}

async fn setup(store: &Path, create_protection: bool) -> Result<Host> {
    std::fs::create_dir_all(store).context("create store")?;
    let data_dir = store.join("runtime-data");
    std::fs::create_dir_all(&data_dir)?;
    let storage = Arc::new(
        LocalFSProvider::new(store.join("storage"))
            .await
            .map_err(|error| anyhow::anyhow!("storage: {error}"))?,
    );
    let component_provider = Arc::new(ComponentProvider::new());
    let runtime = Arc::new(Runtime::with_providers_and_component(
        storage,
        Vec::new(),
        Some(component_provider),
    ));
    runtime
        .configure_capsule_admission(&data_dir, &[], true)
        .await
        .map_err(|error| anyhow::anyhow!("admission: {error}"))?;
    let root = principal_localhost_root(PERSON);
    if create_protection {
        if load_principal_root_protection(&data_dir, PERSON, &root)
            .ok()
            .flatten()
            .is_none()
        {
            store_test_principal_root_protection(&data_dir, PERSON);
        }
    } else if load_principal_root_protection(&data_dir, PERSON, &root)
        .ok()
        .flatten()
        .is_none()
    {
        bail!("second process found no principal-root protection on the store");
    }
    let audit_log = Arc::new(AuditLog::new());
    let capability_manager = Arc::new(CapabilityManager::new(
        Arc::new(elastos_runtime::capability::CapabilityStore::new()),
        audit_log.clone(),
        Arc::new(MetricsManager::new()),
    ));
    let pending_store =
        Arc::new(elastos_runtime::capability::pending::PendingRequestStore::new(audit_log));
    runtime
        .set_provider_registry(
            Arc::new(ProviderRegistry::new()),
            capability_manager.clone(),
            pending_store.clone(),
            data_dir.clone(),
        )
        .await;
    let object_uri = format!("{root}/.AppData/Agents/agent-host/tasks/demo/journal");
    let ctx = BridgeContext {
        provider_registry: Arc::new(ProviderRegistry::new()),
        capability_manager: capability_manager.clone(),
        pending_store: pending_store.clone(),
        capsule_id: "agent-host".to_string(),
        principal_id: Some(PERSON.to_string()),
        manifest_capabilities: vec![format!("{root}/.AppData/Agents/agent-host/*")],
        data_dir: Some(data_dir.clone()),
    };
    Ok(Host {
        runtime,
        capability_manager,
        pending_store,
        data_dir,
        ctx,
        object_uri,
    })
}

async fn launch_guest(host: &Host) -> Result<()> {
    let dir = agent_host_dir()?;
    if !dir.join("agent-host.component.wasm").is_file() {
        bail!("guest wasm missing at {}", dir.display());
    }
    let runtime = host.runtime.clone();
    let launch = tokio::spawn(async move {
        runtime
            .run_local_with_principal(&dir, Vec::new(), Some(PERSON.to_string()))
            .await
    });
    for _ in 0..2 {
        let pending = next_pending(&host.pending_store).await?;
        let token = host.capability_manager.grant(
            pending.session_id.as_str(),
            pending.resource.clone(),
            pending.action,
            TokenConstraints::default(),
            None,
        );
        host.pending_store
            .grant_request(pending.id.as_str(), token, GrantDuration::Session)
            .await
            .map_err(|error| anyhow::anyhow!("grant: {error}"))?;
    }
    timeout(Duration::from_secs(30), launch)
        .await
        .context("guest launch timed out")?
        .context("guest launch task panicked")?
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    Ok(())
}

async fn next_pending(
    store: &elastos_runtime::capability::pending::PendingRequestStore,
) -> Result<elastos_runtime::capability::pending::PendingCapabilityRequest> {
    timeout(Duration::from_secs(15), async {
        loop {
            if let Some(request) = store.list_pending().await.into_iter().next() {
                break request;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("the guest did not ask for a journal grant")
}

async fn read_journal(host: &Host) -> Result<(Vec<u8>, String)> {
    let token = bridge_token(host, Action::Read)?;
    let line = serde_json::json!({
        "id": 1,
        "request": {
            "type": "resource_invoke",
            "uri": SELF_URI,
            "operation": "read",
            "token": token,
            "body": {},
        }
    })
    .to_string();
    let reply = handle_component_resource_request(&line, host.ctx.clone())
        .await
        .context("bridge read")?;
    let status = reply
        .pointer("/response/result/status")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    if status != "ok" {
        bail!("bridge read failed: {reply}");
    }
    let content: Vec<u8> = serde_json::from_value(
        reply
            .pointer("/response/result/data/content")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    )
    .context("read content")?;
    let revision = reply
        .pointer("/response/result/data/revision")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    if revision.is_empty() {
        bail!("bridge read returned no revision");
    }
    let path = journal_path(host);
    let disk = read_principal_root_object(
        &host.data_dir,
        PERSON,
        &principal_localhost_root(PERSON),
        &host.object_uri,
        &path,
    )
    .context("disk read")?;
    if disk != content {
        bail!("bridge read and disk bytes differ");
    }
    Ok((content, revision))
}

async fn bridge_write(
    host: &Host,
    content: &[u8],
    precondition: serde_json::Value,
) -> Result<serde_json::Value> {
    let token = bridge_token(host, Action::Write)?;
    let mut body = serde_json::json!({ "content": content, "append": false });
    if let Some(extra) = precondition.as_object() {
        for (key, value) in extra {
            body[key] = value.clone();
        }
    }
    let line = serde_json::json!({
        "id": 2,
        "request": {
            "type": "resource_invoke",
            "uri": SELF_URI,
            "operation": "write",
            "token": token,
            "body": body,
        }
    })
    .to_string();
    handle_component_resource_request(&line, host.ctx.clone())
        .await
        .context("bridge write")
}

fn bridge_token(host: &Host, action: Action) -> Result<String> {
    let token = host.capability_manager.grant(
        &host.ctx.capsule_id,
        ResourceId::new(&host.object_uri),
        action,
        TokenConstraints::default(),
        None,
    );
    token
        .to_base64()
        .map_err(|error| anyhow::anyhow!("token: {error}"))
}

fn journal_path(host: &Host) -> PathBuf {
    rooted_localhost_fs_path(&host.data_dir, &host.object_uri).expect("journal path")
}

fn agent_host_dir() -> Result<PathBuf> {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Ok(here.join("../../examples/agent-host").canonicalize()?)
}

fn write_state(store: &Path, value: &serde_json::Value) -> Result<()> {
    std::fs::write(store.join(STATE_FILE), serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn read_state(store: &Path) -> Result<serde_json::Value> {
    let raw = std::fs::read(store.join(STATE_FILE)).context("read state")?;
    Ok(serde_json::from_slice(&raw)?)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn row(name: &str, result: &str, detail: &str) {
    println!("ROW {name} {result} {detail}");
}
