//! P2-9 measuring stick. PeerDid is the route above the backend. Removing the
//! listed ticket constructions is a later P2-9 slice.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use elastos_runtime::provider::{
    Provider, ProviderCarrierRoute, ProviderError, ProviderInvocation, ProviderInvocationTransport,
    ProviderRegistry, ProviderTransfer, ResourceRequest, ResourceResponse,
};
use iroh::Watcher as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::carrier::{
    start_carrier_node_with_registry, CarrierGossipProvider, CarrierNode, CarrierProviderInvoker,
};
use crate::content::{FetchReceipt, FetchResult};

const VOICE_ROW: &str = "open: waits for Rong (verb or WebSpace files)";
const FILE_BYTES: &[u8] = b"carrier contract file bytes";

#[derive(Debug)]
struct Observation {
    bytes: Vec<u8>,
    sender_did: String,
    answer: Value,
}

#[derive(Debug)]
struct FileObservation {
    bytes: Vec<u8>,
    sender_did: String,
    answer: Value,
    receipt: FetchReceipt,
}

// The four verbs are addressed by DID or topic. Backend coordinates stay inside
// the implementation. A second real backend later adds one impl and one call.
#[async_trait]
trait CarrierUnderTest: Send + Sync {
    async fn request_reply(
        &self,
        peer_did: &str,
        bytes: &[u8],
    ) -> Result<Observation, ProviderError>;
    async fn send_message(&self, topic: &str, bytes: &[u8]) -> Result<Value, ProviderError>;
    async fn receive(&self, topic: &str) -> Result<Option<Observation>, ProviderError>;
    async fn notify(&self, topic: &str, bytes: &[u8]) -> Result<Value, ProviderError>;
    async fn request_file(
        &self,
        cid: &str,
        from_peer_did: &str,
    ) -> Result<FileObservation, ProviderError>;
    fn peer_did(&self) -> &str;
    fn sender_did(&self) -> &str;
    fn assert_private_answer(&self, answer: &Value);
    fn remote_calls(&self) -> usize;
}

struct ContractPlane {
    requests: Arc<Mutex<Vec<Value>>>,
}

#[async_trait]
impl Provider for ContractPlane {
    async fn handle(&self, _: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(
            "contract plane uses typed invocation".into(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        Vec::new()
    }

    fn name(&self) -> &'static str {
        "carrier-contract-plane"
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        self.requests.lock().unwrap().push(request.clone());
        let sender = request["_runtime_invocation"]["carrier"]["source_endpoint_did"]
            .as_str()
            .unwrap_or_default();
        let body = if request["op"] == "fetch" {
            FILE_BYTES.to_vec()
        } else {
            base64::engine::general_purpose::STANDARD
                .decode(request["body"].as_str().unwrap_or_default())
                .map_err(|_| ProviderError::Provider("invalid contract body".into()))?
        };
        Ok(json!({"status":"ok","data":{
            "body":base64::engine::general_purpose::STANDARD.encode(body),
            "sender_did":sender,
            "cid":request["cid"]
        }}))
    }
}

struct CurrentCarrier {
    sender_node: CarrierNode,
    receiver_node: CarrierNode,
    sender_registry: Arc<ProviderRegistry>,
    receiver_registry: Arc<ProviderRegistry>,
    sender_did: String,
    receiver_did: String,
    remote_requests: Arc<Mutex<Vec<Value>>>,
    receiver_address: String,
    receiver_port: String,
    _sender_dir: tempfile::TempDir,
    _receiver_dir: tempfile::TempDir,
}

impl CurrentCarrier {
    async fn gossip(registry: &ProviderRegistry, request: Value) -> Result<Value, ProviderError> {
        let op = request["op"].as_str().unwrap_or_default().to_string();
        registry
            .invoke_provider(ProviderInvocation {
                source: "carrier-contract".into(),
                target: "peer".into(),
                op,
                request,
                transfer: ProviderTransfer::Json,
                range: None,
                progress: None,
                transport: ProviderInvocationTransport::Local,
            })
            .await
    }

    async fn new() -> Self {
        let sender_dir = tempfile::tempdir().unwrap();
        let receiver_dir = tempfile::tempdir().unwrap();
        let sender_registry = Arc::new(ProviderRegistry::new());
        let receiver_registry = Arc::new(ProviderRegistry::new());
        crate::library::publish_cid_for_test(receiver_dir.path(), &content_cid(FILE_BYTES));
        let (sender_key, sender_did) = elastos_identity::derive_did(&[211; 32]);
        let (receiver_key, receiver_did) = elastos_identity::derive_did(&[212; 32]);
        let sender_node = start_carrier_node_with_registry(
            &sender_key,
            &sender_did,
            sender_dir.path().to_path_buf(),
            Some(Arc::downgrade(&sender_registry)),
        )
        .await
        .unwrap();
        let receiver_node = start_carrier_node_with_registry(
            &receiver_key,
            &receiver_did,
            receiver_dir.path().to_path_buf(),
            Some(Arc::downgrade(&receiver_registry)),
        )
        .await
        .unwrap();
        let mut watcher = receiver_node.endpoint.watch_addr();
        let mut address = watcher.get();
        for _ in 0..100 {
            if address
                .addrs
                .iter()
                .any(|item| matches!(item, iroh::TransportAddr::Ip(_)))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            address = watcher.get();
        }
        assert!(address
            .addrs
            .iter()
            .any(|item| matches!(item, iroh::TransportAddr::Ip(_))));
        sender_node.memory_lookup.add_endpoint_info(address.clone());
        let receiver_address = address
            .addrs
            .iter()
            .find_map(|item| match item {
                iroh::TransportAddr::Ip(socket) => Some(*socket),
                _ => None,
            })
            .unwrap();
        sender_registry
            .set_carrier_invoker(Arc::new(
                CarrierProviderInvoker::with_carrier_endpoint_and_registry(
                    sender_node.endpoint.clone(),
                    Arc::downgrade(&sender_registry),
                ),
            ))
            .await;
        let remote_requests = Arc::new(Mutex::new(Vec::new()));
        let plane = Arc::new(ContractPlane {
            requests: remote_requests.clone(),
        });
        receiver_registry
            .register_sub_provider("collaboration-direct", plane.clone())
            .await
            .unwrap();
        receiver_registry
            .register_sub_provider("content", plane)
            .await
            .unwrap();
        receiver_registry
            .register_sub_provider(
                "peer",
                Arc::new(CarrierGossipProvider::new(
                    receiver_node.gossip_state.clone(),
                )),
            )
            .await
            .unwrap();
        sender_registry
            .register_sub_provider(
                "peer",
                Arc::new(CarrierGossipProvider::new(sender_node.gossip_state.clone())),
            )
            .await
            .unwrap();
        Self {
            sender_node,
            receiver_node,
            sender_registry,
            receiver_registry,
            sender_did,
            receiver_did,
            remote_requests,
            receiver_address: receiver_address.to_string(),
            receiver_port: receiver_address.port().to_string(),
            _sender_dir: sender_dir,
            _receiver_dir: receiver_dir,
        }
    }

    async fn join_topic(&self, topic: &str) {
        let sender = &self.sender_registry;
        let receiver = &self.receiver_registry;
        assert_eq!(
            Self::gossip(
                sender,
                json!({"op":"gossip_join","topic":topic,"mode":"direct"}),
            )
            .await
            .unwrap()["status"],
            "ok"
        );
        let ticket = Self::gossip(sender, json!({"op":"get_ticket"}))
            .await
            .unwrap()["data"]["ticket"]
            .as_str()
            .unwrap()
            .to_string();
        let remembered = Self::gossip(receiver, json!({"op":"remember_peer","ticket":ticket}))
            .await
            .unwrap();
        assert_eq!(remembered["status"], "ok");
        assert_eq!(
            Self::gossip(
                receiver,
                json!({"op":"gossip_join","topic":topic,"mode":"direct"}),
            )
            .await
            .unwrap()["status"],
            "ok"
        );
        assert_eq!(
            Self::gossip(
                receiver,
                json!({"op":"gossip_join_peers","topic":topic,"peers":remembered["data"]["added"]})
            )
            .await
            .unwrap()["status"],
            "ok"
        );
    }

    async fn stop(self) {
        self.sender_node.shutdown().await;
        self.receiver_node.shutdown().await;
    }

    async fn invoke(
        &self,
        peer_did: &str,
        target: &str,
        op: &str,
        request: Value,
    ) -> Result<Value, ProviderError> {
        self.sender_registry
            .invoke_provider(ProviderInvocation {
                source: "carrier-contract".into(),
                target: target.into(),
                op: op.into(),
                request,
                transfer: ProviderTransfer::Json,
                range: None,
                progress: None,
                transport: ProviderInvocationTransport::Carrier(ProviderCarrierRoute::PeerDid {
                    peer_did: peer_did.into(),
                    timeout_ms: Some(2_000),
                    reply_wait_ms: Some(5_000),
                }),
            })
            .await
    }
}

#[async_trait]
impl CarrierUnderTest for CurrentCarrier {
    async fn request_reply(
        &self,
        peer_did: &str,
        bytes: &[u8],
    ) -> Result<Observation, ProviderError> {
        let answer = self
            .invoke(
                peer_did,
                "collaboration-direct",
                "deliver",
                json!({
                    "op":"deliver", "body":base64::engine::general_purpose::STANDARD.encode(bytes)
                }),
            )
            .await?;
        let body = base64::engine::general_purpose::STANDARD
            .decode(answer["data"]["body"].as_str().unwrap_or_default())
            .map_err(|_| ProviderError::Provider("invalid reply body".into()))?;
        Ok(Observation {
            bytes: body,
            sender_did: answer["data"]["sender_did"]
                .as_str()
                .unwrap_or_default()
                .into(),
            answer,
        })
    }

    async fn send_message(&self, topic: &str, bytes: &[u8]) -> Result<Value, ProviderError> {
        Self::gossip(
            &self.sender_registry,
            json!({"op":"gossip_send", "topic":topic,
                "message":base64::engine::general_purpose::STANDARD.encode(bytes)}),
        )
        .await
    }

    async fn receive(&self, topic: &str) -> Result<Option<Observation>, ProviderError> {
        let answer = Self::gossip(
            &self.receiver_registry,
            json!({"op":"gossip_recv","topic":topic,"consumer_id":"carrier-contract","limit":20}),
        )
        .await?;
        let Some(message) = answer["data"]["messages"]
            .as_array()
            .and_then(|messages| messages.first())
        else {
            return Ok(None);
        };
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(message["content"].as_str().unwrap_or_default())
            .map_err(|_| ProviderError::Provider("invalid message body".into()))?;
        Ok(Some(Observation {
            bytes,
            sender_did: message["sender_id"].as_str().unwrap_or_default().into(),
            answer,
        }))
    }

    async fn notify(&self, topic: &str, bytes: &[u8]) -> Result<Value, ProviderError> {
        self.send_message(topic, bytes).await
    }

    async fn request_file(
        &self,
        cid: &str,
        from_peer_did: &str,
    ) -> Result<FileObservation, ProviderError> {
        let answer = self
            .invoke(
                from_peer_did,
                "content",
                "fetch",
                json!({"op":"fetch","cid":cid}),
            )
            .await?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(answer["data"]["body"].as_str().unwrap_or_default())
            .map_err(|_| ProviderError::Provider("invalid file body".into()))?;
        let received_cid = content_cid(&bytes);
        assert_eq!(received_cid, cid);
        let receipt = FetchReceipt::new(
            cid,
            from_peer_did,
            bytes.len() as u64,
            true,
            FetchResult::Ok,
            1,
            1,
        )
        .map_err(ProviderError::Provider)?;
        Ok(FileObservation {
            bytes,
            sender_did: answer["data"]["sender_did"]
                .as_str()
                .unwrap_or_default()
                .into(),
            answer,
            receipt,
        })
    }

    fn peer_did(&self) -> &str {
        &self.receiver_did
    }
    fn sender_did(&self) -> &str {
        &self.sender_did
    }
    fn assert_private_answer(&self, answer: &Value) {
        let serialized = answer.to_string();
        let needles = [
            self.receiver_address.clone(),
            self.receiver_port.clone(),
            self.receiver_node.endpoint.id().to_string(),
            ["connect", "_ticket"].concat(),
            ["re", "lay"].concat(),
            "127.0.0.1".into(),
            "iroh".into(),
        ];
        for needle in needles {
            assert!(
                !serialized.contains(&needle),
                "capsule answer exposed backend detail: {needle}"
            );
        }
    }
    fn remote_calls(&self) -> usize {
        self.remote_requests.lock().unwrap().len()
    }
}

fn content_cid(bytes: &[u8]) -> String {
    let hash = cid::multihash::Multihash::<64>::wrap(0x12, &Sha256::digest(bytes)).unwrap();
    cid::Cid::new_v1(0x55, hash).to_string()
}

fn assert_no_topology(answer: &Value, carrier: &dyn CarrierUnderTest) {
    carrier.assert_private_answer(answer);
}

// dKMS is planned over Carrier (PRINCIPLES 15). This verb carries opaque bytes.
// OPEN in a later P2-9 slice: gossip sender_id is application supplied, gossip
// topics are not peer-DID addressed, and a capability string is not a grant.
async fn run_contract(carrier: &dyn CarrierUnderTest) {
    let claim = format!("claimed_did={}", elastos_identity::derive_did(&[213; 32]).1);
    let calls_without_grant = carrier.remote_calls();
    let request = carrier
        .request_reply(carrier.peer_did(), claim.as_bytes())
        .await
        .unwrap();
    // OPEN: this interface has no grant input, and today's provider plane
    // runs the invoker. A later P2-9 authority slice must refuse before it.
    assert_eq!(carrier.remote_calls(), calls_without_grant + 1);
    assert_eq!(request.bytes, claim.as_bytes());
    assert_eq!(request.sender_did, carrier.sender_did());
    assert_no_topology(&request.answer, carrier);

    let opaque = vec![0xa5; 64 * 1024];
    let large = carrier
        .request_reply(carrier.peer_did(), &opaque)
        .await
        .unwrap();
    assert_eq!(large.bytes, opaque);
    assert_no_topology(&large.answer, carrier);

    let unknown = elastos_identity::derive_did(&[214; 32]).1;
    let calls = carrier.remote_calls();
    let refused = carrier
        .request_reply(&unknown, b"wrong peer")
        .await
        .unwrap_err();
    assert!(matches!(refused, ProviderError::Unavailable(_)));
    assert_eq!(carrier.remote_calls(), calls);

    let file_cid = content_cid(FILE_BYTES);
    let file = carrier
        .request_file(&file_cid, carrier.peer_did())
        .await
        .unwrap();
    assert_eq!(file.bytes, FILE_BYTES);
    assert_eq!(file.sender_did, carrier.sender_did());
    assert_eq!(
        serde_json::to_value(&file.receipt).unwrap()["requested_cid"],
        file_cid
    );
    assert_eq!(
        serde_json::to_value(&file.receipt).unwrap()["bytes_received"],
        FILE_BYTES.len()
    );
    assert_no_topology(&file.answer, carrier);
    let calls = carrier.remote_calls();
    let refused = carrier.request_file(&file_cid, &unknown).await.unwrap_err();
    assert!(matches!(refused, ProviderError::Unavailable(_)));
    assert_eq!(carrier.remote_calls(), calls);

    for (verb, topic) in [
        ("message", "__test/p29-message"),
        ("notification", "__test/p29-notice"),
    ] {
        let sent = format!("{verb}:{claim}");
        let answer = if verb == "message" {
            carrier.send_message(topic, sent.as_bytes()).await.unwrap()
        } else {
            carrier.notify(topic, sent.as_bytes()).await.unwrap()
        };
        assert_eq!(answer["status"], "ok");
        if verb == "notification" {
            assert!(
                answer["data"].get("body").is_none(),
                "notice has no reply body"
            );
        }
        assert_no_topology(&answer, carrier);
        let mut received = None;
        for _ in 0..30 {
            if verb == "message" {
                carrier.send_message(topic, sent.as_bytes()).await.unwrap();
            } else {
                carrier.notify(topic, sent.as_bytes()).await.unwrap();
            }
            if let Some(value) = carrier.receive(topic).await.unwrap() {
                received = Some(value);
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let received = received.expect("gossip receiver got no bytes");
        assert_eq!(received.bytes, sent.as_bytes());
        // Today this field is populated by gossip_send's default. It is not
        // transport-authenticated; the identity row remains OPEN.
        assert_eq!(received.sender_did, carrier.sender_did());
        assert_no_topology(&received.answer, carrier);
    }
    assert_eq!(VOICE_ROW, "open: waits for Rong (verb or WebSpace files)");
}

#[tokio::test]
async fn carrier_contract_current_backend() {
    let carrier = CurrentCarrier::new().await;
    carrier.join_topic("__test/p29-message").await;
    carrier.join_topic("__test/p29-notice").await;
    run_contract(&carrier).await;
    carrier.stop().await;
}

fn walk_rust(path: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if ["target", "target-build", ".git", "tests", "gateway_tests"].contains(&name.as_ref())
            || name.ends_with("_tests.rs")
            || name.starts_with("test_")
            || name == "tests.rs"
        {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            walk_rust(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

// Count only constructors: enum definitions and match arms are patterns.
// The needle is assembled at run time so source-scanning tests do not match it.
#[test]
fn carrier_contract_connect_ticket_construction_inventory() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut files = Vec::new();
    walk_rust(crates, &mut files);
    let needle = ["ProviderCarrierRoute::", "Connect", "Ticket", " {"].concat();
    let mut found = Vec::new();
    for file in files {
        let source = std::fs::read_to_string(&file).unwrap();
        let source = source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .unwrap()
            .split("#[cfg(test)]\npub(crate) mod tests")
            .next()
            .unwrap();
        let relative = file.strip_prefix(crates).unwrap().to_string_lossy();
        for (offset, _) in source.match_indices(&needle) {
            let rest = &source[offset + needle.len()..];
            let Some(close) = rest.find('}') else {
                panic!("unclosed route in {relative}");
            };
            let suffix = rest[close + 1..].trim_start();
            if suffix.starts_with("=>") || suffix.starts_with('|') {
                continue;
            }
            let before = &source[..offset];
            let function = before
                .lines()
                .rev()
                .find_map(|line| {
                    let line = line.trim();
                    let position = line.find("fn ")?;
                    (line.starts_with("fn ")
                        || line.starts_with("async fn ")
                        || line.starts_with("pub ")
                        || line.starts_with("pub(crate) "))
                    .then(|| {
                        line[position + 3..]
                            .split('(')
                            .next()
                            .unwrap_or_default()
                            .to_string()
                    })
                })
                .unwrap_or_default();
            found.push(format!("{relative}:{function}"));
        }
    }
    found.sort();
    let mut expected = vec![
        "elastos-server/src/api/gateway_model_remote.rs:call_grant",
        "elastos-server/src/carrier.rs:ensure_content_via_carrier_provider_invocation",
        "elastos-server/src/carrier.rs:fetch_content_via_carrier_provider_invocation",
        "elastos-server/src/carrier_engine.rs:call",
        "elastos-server/src/collaboration_discovery_runtime.rs:invoke_bootstrap",
    ];
    expected.sort();
    assert_eq!(
        found, expected,
        "production route construction inventory changed"
    );
}
