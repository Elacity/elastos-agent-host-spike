//! Two-process A2 journal driver. Each invocation is one Runtime process
//! on a shared store. WRITE, STALE, RESUME, and WRITE2 all go through the
//! guest's real `providers.invoke` hostcall. The driver does not mint a
//! token and does not call `handle_component_resource_request`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use elastos_common::localhost::rooted_localhost_fs_path;
use elastos_compute::providers::ComponentProvider;
use elastos_runtime::capability::{CapabilityManager, GrantDuration, TokenConstraints};
use elastos_runtime::primitives::audit::{AuditEvent, AuditLog};
use elastos_runtime::primitives::metrics::MetricsManager;
use elastos_runtime::provider::ProviderRegistry;
use elastos_server::auth::{
    load_principal_root_protection, principal_localhost_root, read_principal_root_object,
    store_test_principal_root_protection,
};
use elastos_server::runtime::Runtime;
use elastos_storage::providers::LocalFSProvider;
use sha2::{Digest, Sha256};
use tokio::time::timeout;

const PERSON: &str = "person:local:agent-host-e2e";
const STATE_FILE: &str = "a2-resume-state.json";
const GUEST_PIN: &str = "guest.sha256";

#[derive(Clone)]
struct Host {
    runtime: Arc<Runtime>,
    capability_manager: Arc<CapabilityManager>,
    pending_store: Arc<elastos_runtime::capability::pending::PendingRequestStore>,
    audit_log: Arc<AuditLog>,
    data_dir: PathBuf,
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
    let host = setup(store, true).await?;
    println!("PROCESS first pid={}", std::process::id());
    let guest_sha = guest_sha256()?;
    let pinned = pinned_guest_sha256()?;
    println!("EVIDENCE guest_sha256={guest_sha} pinned={pinned}");
    if guest_sha != pinned {
        row(
            "WRITE",
            "FAIL",
            &format!("guest bytes do not match {GUEST_PIN}; got {guest_sha}"),
        );
        return Ok(());
    }
    let before_exists = journal_path(&host).exists();
    match launch_guest(&host).await {
        Ok(()) => {
            let (plain, revision) = read_journal(&host)?;
            let sha = sha256_hex(&plain);
            let invokes = invoke_outcomes(&host.audit_log);
            println!(
                "EVIDENCE journal_sha256={sha} revision={revision} bytes={} format2={} invokes={}",
                plain.len(),
                is_format2(&plain),
                format_invokes(&invokes)
            );
            if before_exists {
                row(
                    "WRITE",
                    "FAIL",
                    "store already had a journal before the first launch",
                );
                return Ok(());
            }
            let wrote =
                is_format2(&plain) && invokes.iter().any(|(op, out)| op == "write" && out == "ok");
            if wrote {
                row(
                    "WRITE",
                    "PASS",
                    &format!(
                        "guest wrote format-2 journal through the real hostcall; revision={revision} sha256={sha} bytes={}",
                        plain.len()
                    ),
                );
                write_state(
                    store,
                    &serde_json::json!({
                        "revision": revision,
                        "sha256": sha,
                        "bytes": plain.len(),
                        "first_pid": std::process::id(),
                        "guest_sha256": guest_sha,
                    }),
                )?;
            } else {
                row(
                    "WRITE",
                    "FAIL",
                    &format!(
                        "stored bytes are not a guest hostcall write (format2={} invokes={})",
                        is_format2(&plain),
                        format_invokes(&invokes)
                    ),
                );
                return Ok(());
            }
            let stale = invokes
                .iter()
                .any(|(op, out)| op == "write" && out == "conflict")
                && read_journal(&host)?.0 == plain;
            if stale {
                row(
                    "STALE",
                    "PASS",
                    &format!(
                        "guest stale if_revision refused with revision_conflict; stored sha256={sha}"
                    ),
                );
            }
            // No STALE row when the guest never sent the stale write.
            // The harness marks that as NOT RUN.
        }
        Err(error) => {
            let invokes = invoke_outcomes(&host.audit_log);
            println!("EVIDENCE invokes={}", format_invokes(&invokes));
            if journal_path(&host).exists() {
                if let Ok((plain, revision)) = read_journal(&host) {
                    println!(
                        "EVIDENCE journal_sha256={} revision={revision} bytes={} format2={}",
                        sha256_hex(&plain),
                        plain.len(),
                        is_format2(&plain)
                    );
                }
            }
            row("WRITE", "FAIL", &format!("guest launch: {error:#}"));
            let unchanged_conflict = invokes
                .iter()
                .any(|(op, out)| op == "write" && out == "conflict");
            if !unchanged_conflict {
                row(
                    "STALE",
                    "FAIL",
                    &format!(
                        "guest launch failed and no write/conflict was audited; invokes={}",
                        format_invokes(&invokes)
                    ),
                );
            }
        }
    }
    Ok(())
}

async fn second(store: &Path) -> Result<()> {
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
    println!("PROCESS second pid={}", std::process::id());
    let guest_sha = guest_sha256()?;
    let pinned = pinned_guest_sha256()?;
    println!("EVIDENCE guest_sha256={guest_sha} pinned={pinned}");
    if guest_sha != pinned {
        row(
            "RESUME",
            "FAIL",
            &format!("guest bytes do not match {GUEST_PIN}; got {guest_sha}"),
        );
        return Ok(());
    }
    let (before, before_rev) = read_journal(&host)?;
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
            let (after, after_rev) = read_journal(&host)?;
            let invokes = invoke_outcomes(&host.audit_log);
            println!(
                "EVIDENCE journal_sha256={} revision={after_rev} bytes={} format2={} invokes={}",
                sha256_hex(&after),
                after.len(),
                is_format2(&after),
                format_invokes(&invokes)
            );
            let loaded = guest_loaded_journal(&invokes) && is_format2(&after);
            if loaded {
                row(
                    "RESUME",
                    "PASS",
                    &format!(
                        "fresh process loaded the latest revision; before={} after={}",
                        expected_sha,
                        sha256_hex(&after)
                    ),
                );
            } else {
                row(
                    "RESUME",
                    "FAIL",
                    &format!(
                        "fresh process did not audit a guest read of the stored journal; invokes={}",
                        format_invokes(&invokes)
                    ),
                );
                return Ok(());
            }
            let wrote = invokes.iter().any(|(op, out)| op == "write" && out == "ok")
                && sha256_hex(&after) != expected_sha
                && after_rev != expected_rev
                && is_format2(&after);
            if wrote {
                row(
                    "WRITE2",
                    "PASS",
                    &format!(
                        "guest wrote with the loaded revision; old={expected_rev} new={after_rev}"
                    ),
                );
            } else {
                row(
                    "WRITE2",
                    "FAIL",
                    &format!(
                        "guest did not store a new format-2 revision after load; after={} invokes={}",
                        sha256_hex(&after),
                        format_invokes(&invokes)
                    ),
                );
            }
        }
        Err(error) => {
            let (after, after_rev) =
                read_journal(&host).unwrap_or((before.clone(), expected_rev.clone()));
            let invokes = invoke_outcomes(&host.audit_log);
            println!(
                "EVIDENCE journal_sha256={} revision={after_rev} bytes={} format2={} invokes={}",
                sha256_hex(&after),
                after.len(),
                is_format2(&after),
                format_invokes(&invokes)
            );
            let kept = sha256_hex(&after) == expected_sha && after_rev == expected_rev;
            let loaded = guest_loaded_journal(&invokes) && (kept || is_format2(&after));
            if loaded {
                row(
                    "RESUME",
                    "PASS",
                    &format!(
                        "fresh process loaded the latest revision; guest write after load failed: {error:#}"
                    ),
                );
                row(
                    "WRITE2",
                    "FAIL",
                    &format!(
                        "guest did not store a new format-2 revision after load; after={} invokes={}",
                        sha256_hex(&after),
                        format_invokes(&invokes)
                    ),
                );
            } else {
                row(
                    "RESUME",
                    "FAIL",
                    &format!("guest launch on the fresh process: {error:#}; stored kept={kept}"),
                );
            }
        }
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
        Arc::new(elastos_runtime::capability::pending::PendingRequestStore::new(audit_log.clone()));
    runtime
        .set_provider_registry(
            Arc::new(ProviderRegistry::new()),
            capability_manager.clone(),
            pending_store.clone(),
            data_dir.clone(),
        )
        .await;
    let object_uri = format!("{root}/.AppData/Agents/agent-host/tasks/demo/journal");
    Ok(Host {
        runtime,
        capability_manager,
        pending_store,
        audit_log,
        data_dir,
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

fn read_journal(host: &Host) -> Result<(Vec<u8>, String)> {
    let path = journal_path(host);
    let content = read_principal_root_object(
        &host.data_dir,
        PERSON,
        &principal_localhost_root(PERSON),
        &host.object_uri,
        &path,
    )
    .context("disk read")?;
    if content.is_empty() {
        bail!("disk journal is empty");
    }
    let revision = journal_revision(&host.object_uri, &content);
    Ok((content, revision))
}

fn journal_revision(object_uri: &str, plaintext: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(PERSON.as_bytes());
    digest.update([0]);
    digest.update(object_uri.as_bytes());
    digest.update([0]);
    digest.update(plaintext);
    format!("\"{}\"", hex::encode(digest.finalize()))
}

fn invoke_outcomes(audit: &AuditLog) -> Vec<(String, String)> {
    audit
        .recent_events(100)
        .iter()
        .filter_map(|event| match event {
            AuditEvent::Custom {
                event_type,
                details,
            } if event_type == "component.invoke.completed" => Some((
                details["operation"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                details["outcome"].as_str().unwrap_or_default().to_string(),
            )),
            _ => None,
        })
        .collect()
}

/// Audit events are newest first. A load is a guest read that happens
/// before a later write. A create_only conflict that then rereads the
/// store is write-then-read, so it is not a resume.
fn guest_loaded_journal(invokes: &[(String, String)]) -> bool {
    let chrono: Vec<&(String, String)> = invokes.iter().rev().collect();
    let Some(read_at) = chrono
        .iter()
        .position(|(op, out)| op == "read" && out == "ok")
    else {
        return false;
    };
    chrono[read_at + 1..].iter().any(|(op, _)| op == "write")
}

fn format_invokes(invokes: &[(String, String)]) -> String {
    if invokes.is_empty() {
        return "none".to_string();
    }
    invokes
        .iter()
        .map(|(op, out)| format!("{op}:{out}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn is_format2(plain: &[u8]) -> bool {
    plain.len() >= 6 && &plain[..4] == b"EAHJ" && plain[4..6] == 2u16.to_le_bytes()
}

fn journal_path(host: &Host) -> PathBuf {
    rooted_localhost_fs_path(&host.data_dir, &host.object_uri).expect("journal path")
}

fn agent_host_dir() -> Result<PathBuf> {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Ok(here.join("../../examples/agent-host").canonicalize()?)
}

fn pinned_guest_sha256() -> Result<String> {
    let pin = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(GUEST_PIN);
    let text = std::fs::read_to_string(&pin).with_context(|| format!("read {}", pin.display()))?;
    let hash = text.trim().to_string();
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{GUEST_PIN} is not a 64-char hex sha256");
    }
    Ok(hash)
}

fn guest_sha256() -> Result<String> {
    let wasm = agent_host_dir()?.join("agent-host.component.wasm");
    let bytes = std::fs::read(&wasm).with_context(|| format!("read {}", wasm.display()))?;
    Ok(sha256_hex(&bytes))
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
