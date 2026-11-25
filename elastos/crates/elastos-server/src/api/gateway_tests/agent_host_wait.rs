//! The real Agent Host guest, through ComponentProvider, waits out the
//! owner's approval time. One test millisecond stands for one second: each
//! park is 30ms and the product park is 30s.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use elastos_runtime::capability::{CapabilityManager, CapabilityStore, TokenConstraints};
use elastos_runtime::primitives::audit::AuditLog;
use elastos_runtime::primitives::metrics::MetricsManager;
use elastos_runtime::provider::ProviderRegistry;
use elastos_storage::providers::LocalFSProvider;

struct Host {
    _temp: tempfile::TempDir,
    _home: crate::agents::tests::Home,
    runtime: Arc<crate::runtime::Runtime>,
    manager: Arc<CapabilityManager>,
    store: Arc<elastos_runtime::capability::pending::PendingRequestStore>,
    data_dir: PathBuf,
    folder: PathBuf,
    agent_id: String,
}

struct ClockGuard {
    home: PathBuf,
}

impl Drop for ClockGuard {
    fn drop(&mut self) {
        crate::api::gateway::seams::set_plan_park_ms(&self.home, 0);
    }
}

async fn host() -> Host {
    use crate::bundle_admission::tests::key;
    use crate::stage_cmd::bundle_cid;
    let temp = tempfile::tempdir().unwrap();
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../examples/agent-host");
    let folder = temp.path().join("agent-host");
    std::fs::create_dir_all(&folder).unwrap();
    let component = std::fs::read(source.join("agent-host.component.wasm")).expect(
        "examples/agent-host/agent-host.component.wasm is missing; build the component first",
    );
    let mut manifest: elastos_common::CapsuleManifest =
        serde_json::from_slice(&std::fs::read(source.join("capsule.json")).unwrap()).unwrap();
    let publisher = key(108);
    elastos_runtime::signature::sign_capsule(
        &publisher,
        &mut manifest,
        &elastos_runtime::signature::hash_content(&component),
    )
    .unwrap();
    std::fs::write(
        folder.join("capsule.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(folder.join("agent-host.component.wasm"), &component).unwrap();
    let cid = bundle_cid(&folder).unwrap();
    let (home, agents) = crate::agents::tests::home_with_agents_if_built(1, &cid)
        .expect("the Agent Host wait needs agents built");
    let agent_id = agents.into_iter().next().unwrap();
    let data_dir = home.path().to_path_buf();
    let runtime = Arc::new(crate::runtime::Runtime::with_providers_and_component(
        Arc::new(
            LocalFSProvider::new(temp.path().join("storage"))
                .await
                .unwrap(),
        ),
        Vec::new(),
        Some(Arc::new(
            elastos_compute::providers::ComponentProvider::new(),
        )),
    ));
    runtime
        .configure_capsule_admission(
            &data_dir,
            &[hex::encode(publisher.verifying_key().to_bytes())],
            false,
        )
        .await
        .unwrap();
    let audit_log = Arc::new(AuditLog::new());
    let manager = Arc::new(CapabilityManager::new(
        Arc::new(CapabilityStore::new()),
        audit_log.clone(),
        Arc::new(MetricsManager::new()),
    ));
    let store = Arc::new(elastos_runtime::capability::pending::PendingRequestStore::new(audit_log));
    runtime
        .set_provider_registry(
            Arc::new(ProviderRegistry::new()),
            manager.clone(),
            store.clone(),
            data_dir.clone(),
        )
        .await;
    Host {
        _temp: temp,
        _home: home,
        runtime,
        manager,
        store,
        data_dir,
        folder,
        agent_id,
    }
}

fn launch(
    host: &Host,
) -> tokio::task::JoinHandle<elastos_common::Result<elastos_compute::CapsuleHandle>> {
    let runtime = host.runtime.clone();
    let data_dir = host.data_dir.clone();
    let agent_id = host.agent_id.clone();
    let folder = host.folder.clone();
    tokio::spawn(async move {
        let admission = crate::agent_admission::admit_launch(
            &data_dir,
            &data_dir,
            Some(crate::agents::tests::OWNER_ID),
            Some(&agent_id),
            crate::agent_admission::walk_launch(&folder).unwrap(),
        )
        .unwrap()
        .unwrap();
        runtime
            .run_local_admitted(&folder, Vec::new(), admission)
            .await
            .map(|(handle, _)| handle)
    })
}

async fn grant_opening_asks(
    host: &Host,
    task: &mut tokio::task::JoinHandle<elastos_common::Result<elastos_compute::CapsuleHandle>>,
) {
    for _ in 0..3 {
        let started = std::time::Instant::now();
        let pending = loop {
            if let Some(request) = host.store.list_pending().await.into_iter().next() {
                break request;
            }
            if task.is_finished() {
                panic!("guest ended before its asks");
            }
            if started.elapsed() > Duration::from_secs(20) {
                panic!("the guest did not ask");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        let token = host.manager.grant(
            pending.session_id.as_str(),
            pending.resource.clone(),
            pending.action,
            TokenConstraints::default(),
            None,
        );
        host.store
            .grant_request(
                pending.id.as_str(),
                token,
                elastos_runtime::capability::pending::GrantDuration::Session,
            )
            .await
            .unwrap();
    }
}

async fn plan_file(data_dir: &Path) -> PathBuf {
    let dir = data_dir.join("inspect-actions");
    for _ in 0..400 {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            if let Some(path) = entries
                .flatten()
                .map(|entry| entry.path())
                .find(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
            {
                return path;
            }
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    panic!("the guest did not store a plan");
}

fn settle(path: &Path, status: &str) {
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(record["status"], "pending", "{record}");
    record["status"] = serde_json::json!(status);
    record["result"] = serde_json::json!({"status": "ok", "data": {"done": true}});
    std::fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
    crate::resource_bridge::notify_plan_waiters();
}

async fn finish(
    task: tokio::task::JoinHandle<elastos_common::Result<elastos_compute::CapsuleHandle>>,
) -> Result<elastos_compute::CapsuleHandle, elastos_common::ElastosError> {
    tokio::time::timeout(Duration::from_secs(20), task)
        .await
        .expect("the guest did not finish")
        .expect("the guest task panicked")
}

/// Approval at 31s and at 100s, denial at 45s, and the named limit.
/// Short clocks: 1ms is 1s of the 300s the owner has.
#[tokio::test]
async fn the_real_guest_waits_out_the_owner_approval_time() {
    for (owner_ms, status) in [(31, "completed"), (100, "completed"), (45, "denied")] {
        let host = host().await;
        let _clock = ClockGuard {
            home: host.data_dir.clone(),
        };
        crate::api::gateway::seams::set_plan_park_ms(&host.data_dir, 30);
        let mut task = launch(&host);
        grant_opening_asks(&host, &mut task).await;
        let path = plan_file(&host.data_dir).await;
        tokio::time::sleep(Duration::from_millis(owner_ms)).await;
        assert!(
            !task.is_finished(),
            "the guest ended before the {owner_ms}s decision"
        );
        settle(&path, status);
        finish(task)
            .await
            .unwrap_or_else(|error| panic!("{owner_ms}s {status} did not land: {error:#}"));
    }
    let host = host().await;
    let _clock = ClockGuard {
        home: host.data_dir.clone(),
    };
    crate::api::gateway::seams::set_plan_park_ms(&host.data_dir, 30);
    let mut task = launch(&host);
    grant_opening_asks(&host, &mut task).await;
    let _plan = plan_file(&host.data_dir).await;
    let error = finish(task).await.expect_err("the limit returned success");
    let text = format!("{error:#}");
    assert!(
        text.contains("the plan decision expired"),
        "the guest did not name its limit: {text}"
    );
}
