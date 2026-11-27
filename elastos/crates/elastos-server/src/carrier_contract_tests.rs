//! P2-9 measuring stick. PeerDid is the route above the backend. Removing the
//! listed ticket constructions is a later P2-9 slice.

use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::{Arc, Mutex};
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use async_trait::async_trait;
#[cfg(unix)]
use base64::Engine as _;
#[cfg(unix)]
use elastos_runtime::provider::{
    Provider, ProviderCarrierRoute, ProviderError, ProviderInvocation, ProviderInvocationTransport,
    ProviderRegistry, ProviderTransfer, ResourceRequest, ResourceResponse,
};
#[cfg(unix)]
use iroh::Watcher as _;
#[cfg(unix)]
use serde_json::{json, Value};
#[cfg(unix)]
use sha2::{Digest, Sha256};

#[cfg(unix)]
use crate::carrier::{
    start_isolated_carrier_node_with_registry, CarrierGossipProvider, CarrierNode,
    CarrierProviderInvoker,
};

#[cfg(unix)]
const FILE_BYTES: &[u8] = b"carrier contract file bytes";

#[derive(Debug)]
#[cfg(unix)]
struct Observation {
    bytes: Vec<u8>,
    sender_did: String,
    answer: Value,
}

#[derive(Debug)]
#[cfg(unix)]
struct FileObservation {
    bytes: Vec<u8>,
    sender_did: String,
    answer: Value,
}

// The four verbs are addressed by DID or topic. Backend coordinates stay inside
// the implementation. A second real backend later adds one impl and one call.
#[cfg(unix)]
#[async_trait]
trait CarrierUnderTest: Send + Sync {
    async fn request_reply(
        &self,
        peer_did: &str,
        bytes: &[u8],
    ) -> Result<Observation, ProviderError>;
    async fn send_message(
        &self,
        topic: &str,
        bytes: &[u8],
        sender_id: Option<&str>,
    ) -> Result<Value, ProviderError>;
    async fn receive(&self, topic: &str) -> Result<Option<Observation>, ProviderError>;
    async fn notify(
        &self,
        topic: &str,
        bytes: &[u8],
        sender_id: Option<&str>,
    ) -> Result<Value, ProviderError>;
    /// One DID send: peer DID and opaque bytes. The record's sender is the
    /// transport DID.
    async fn deliver_did(&self, bytes: &[u8]) -> Result<Observation, ProviderError>;
    async fn request_file(
        &self,
        cid: &str,
        from_peer_did: &str,
    ) -> Result<FileObservation, ProviderError>;
    async fn voice_probe(&self) -> Result<Value, ProviderError>;
    fn peer_did(&self) -> &str;
    fn sender_did(&self) -> &str;
    fn assert_private_answer(&self, answer: &Value);
    fn remote_calls(&self) -> usize;
}

#[cfg(unix)]
struct ContractPlane {
    requests: Arc<Mutex<Vec<Value>>>,
}

#[async_trait]
#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
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
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("contract carrier seed");
        let (sender_key, sender_did) = elastos_identity::derive_did(&seed);
        seed[31] ^= 0xff;
        let (receiver_key, receiver_did) = elastos_identity::derive_did(&seed);
        let sender_node = start_isolated_carrier_node_with_registry(
            &sender_key,
            &sender_did,
            sender_dir.path().to_path_buf(),
            Some(Arc::downgrade(&sender_registry)),
        )
        .await
        .unwrap();
        let receiver_node = start_isolated_carrier_node_with_registry(
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
#[cfg(unix)]
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
                    "op":"deliver", "body":base64::engine::general_purpose::STANDARD.encode(bytes),
                    "claimed_did": std::str::from_utf8(bytes).ok()
                        .and_then(|body| body.strip_prefix("claimed_did="))
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

    async fn send_message(
        &self,
        topic: &str,
        bytes: &[u8],
        sender_id: Option<&str>,
    ) -> Result<Value, ProviderError> {
        Self::gossip(
            &self.sender_registry,
            json!({"op":"gossip_send", "topic":topic,
                "message":base64::engine::general_purpose::STANDARD.encode(bytes),
                "sender_id":sender_id}),
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
        // The shown sender is the transport Home, or empty. A payload
        // sender_id is not that Home.
        Ok(Some(Observation {
            bytes,
            sender_did: message["sender_id"].as_str().unwrap_or_default().into(),
            answer,
        }))
    }

    async fn notify(
        &self,
        topic: &str,
        bytes: &[u8],
        sender_id: Option<&str>,
    ) -> Result<Value, ProviderError> {
        self.send_message(topic, bytes, sender_id).await
    }

    async fn deliver_did(&self, bytes: &[u8]) -> Result<Observation, ProviderError> {
        let inbox = self
            .receiver_node
            .gossip_state
            .lock()
            .await
            .did_messages
            .clone();
        let before = inbox.lock().expect("DID message inbox").len();
        let answer =
            crate::carrier::send_did_message(&self.sender_registry, &self.receiver_did, bytes)
                .await?;
        let recorded = inbox.lock().expect("DID message inbox");
        assert_eq!(recorded.len(), before + 1, "DID message was not recorded");
        let message = recorded.last().expect("DID message");
        assert_eq!(message.bytes, bytes);
        assert_eq!(
            answer["data"]["sender_did"].as_str().unwrap_or(""),
            message.source_endpoint_did
        );
        Ok(Observation {
            bytes: message.bytes.clone(),
            sender_did: message.source_endpoint_did.clone(),
            answer,
        })
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
        Ok(FileObservation {
            bytes,
            sender_did: answer["data"]["sender_did"]
                .as_str()
                .unwrap_or_default()
                .into(),
            answer,
        })
    }

    async fn voice_probe(&self) -> Result<Value, ProviderError> {
        Self::gossip(&self.sender_registry, json!({"op":"voice"})).await
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

#[cfg(unix)]
fn content_cid(bytes: &[u8]) -> String {
    let hash = cid::multihash::Multihash::<64>::wrap(0x12, &Sha256::digest(bytes)).unwrap();
    cid::Cid::new_v1(0x55, hash).to_string()
}

#[cfg(unix)]
fn assert_no_topology(answer: &Value, carrier: &dyn CarrierUnderTest) {
    carrier.assert_private_answer(answer);
}

// Remote key-service traffic is planned over Carrier (PRINCIPLES 15). This verb carries opaque bytes.
#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum ContractRow {
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    M1,
    M2,
    M3,
    M4,
    N1,
    N2,
    N3,
    N4,
    F1,
    F2,
    F3,
    F4,
    F5,
    V1,
}

#[cfg(unix)]
const MESSAGE_TOPIC: &str = "__test/p29-message";
#[cfg(unix)]
const NOTICE_TOPIC: &str = "__test/p29-notice";

#[cfg(unix)]
fn claimed_did_body() -> String {
    format!("claimed_did={}", elastos_identity::derive_did(&[213; 32]).1)
}

#[cfg(unix)]
fn unknown_did() -> String {
    // Seed 214 is a live Home in other carrier tests, and mDNS dials it.
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("unknown DID seed");
    elastos_identity::derive_did(&seed).1
}

#[cfg(unix)]
async fn gossip_roundtrip(
    carrier: &dyn CarrierUnderTest,
    topic: &str,
    bytes: &[u8],
    notice: bool,
    sender_id: Option<&str>,
) -> (Value, Observation) {
    let answer = send_gossip(carrier, topic, bytes, notice, sender_id)
        .await
        .unwrap();
    assert_eq!(answer["status"], "ok");
    let mut received = None;
    for _ in 0..30 {
        send_gossip(carrier, topic, bytes, notice, sender_id)
            .await
            .unwrap();
        if let Some(value) = carrier.receive(topic).await.unwrap() {
            received = Some(value);
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    (answer, received.expect("gossip receiver got no bytes"))
}

#[cfg(unix)]
async fn send_gossip(
    carrier: &dyn CarrierUnderTest,
    topic: &str,
    bytes: &[u8],
    notice: bool,
    sender_id: Option<&str>,
) -> Result<Value, ProviderError> {
    if notice {
        carrier.notify(topic, bytes, sender_id).await
    } else {
        carrier.send_message(topic, bytes, sender_id).await
    }
}

#[cfg(unix)]
async fn r1_request_reply_responder_bytes(carrier: &dyn CarrierUnderTest) {
    let body = claimed_did_body();
    let reply = carrier
        .request_reply(carrier.peer_did(), body.as_bytes())
        .await
        .unwrap();
    assert_eq!(reply.bytes, body.as_bytes());
}

#[cfg(unix)]
async fn r2_request_reply_responder_authenticated_did(carrier: &dyn CarrierUnderTest) {
    let body = claimed_did_body();
    let reply = carrier
        .request_reply(carrier.peer_did(), body.as_bytes())
        .await
        .unwrap();
    assert_eq!(reply.sender_did, carrier.sender_did());
    assert_ne!(reply.sender_did, body.trim_start_matches("claimed_did="));
}

#[cfg(unix)]
async fn r3_request_reply_responder_unknown_did(carrier: &dyn CarrierUnderTest) {
    let calls = carrier.remote_calls();
    let refused = carrier
        .request_reply(&unknown_did(), b"wrong peer")
        .await
        .unwrap_err();
    assert!(
        matches!(refused, ProviderError::Unavailable(_)),
        "{refused:?}"
    );
    assert_eq!(carrier.remote_calls(), calls);
}

#[cfg(unix)]
async fn r4_request_reply_responder_private_answer(carrier: &dyn CarrierUnderTest) {
    let reply = carrier
        .request_reply(carrier.peer_did(), b"privacy")
        .await
        .unwrap();
    assert_no_topology(&reply.answer, carrier);
}

#[cfg(unix)]
async fn r5_request_reply_responder_without_grant(carrier: &dyn CarrierUnderTest) {
    let calls = carrier.remote_calls();
    let reply = carrier
        .request_reply(carrier.peer_did(), b"without caller grant")
        .await
        .unwrap();
    assert_eq!(reply.bytes, b"without caller grant");
    assert_eq!(carrier.remote_calls(), calls + 1);
}

#[cfg(unix)]
async fn r6_request_reply_responder_opaque_body(carrier: &dyn CarrierUnderTest) {
    let opaque = vec![0xa5; 64 * 1024];
    let reply = carrier
        .request_reply(carrier.peer_did(), &opaque)
        .await
        .unwrap();
    assert_eq!(reply.bytes, opaque);
}

#[cfg(unix)]
fn assert_visible_gossip_home(
    received: &Observation,
    carrier: &dyn CarrierUnderTest,
    forged: &str,
) {
    assert_ne!(
        received.sender_did, forged,
        "a caller sender_id is not the sending Home"
    );
    assert!(
        received.sender_did.is_empty() || received.sender_did == carrier.sender_did(),
        "gossip shows the transport Home or no sender, got {}",
        received.sender_did
    );
}

// A topic delivers the bytes. The visible sender is the transport Home, or
// none. A caller sender_id is not that Home.
#[cfg(unix)]
async fn m1_message_bytes(carrier: &dyn CarrierUnderTest) {
    let sent = b"message:contract bytes";
    let forged = elastos_identity::derive_did(&[215; 32]).1;
    assert_ne!(forged, carrier.sender_did());
    let (_, received) = gossip_roundtrip(carrier, MESSAGE_TOPIC, sent, false, Some(&forged)).await;
    assert_eq!(received.bytes, sent);
    assert_visible_gossip_home(&received, carrier, &forged);
}

// The recorded sender is the transport DID. A sender_id in the body is not the sender.
#[cfg(unix)]
async fn m2_message_sender_identity(carrier: &dyn CarrierUnderTest) {
    let claimed = elastos_identity::derive_did(&[213; 32]).1;
    assert_ne!(claimed, carrier.sender_did());
    let received = carrier
        .deliver_did(format!("sender_id={claimed}").as_bytes())
        .await
        .unwrap();
    assert_eq!(received.sender_did, carrier.sender_did());
    assert_ne!(received.sender_did, claimed);
}

// A message that names a peer DID and bytes is delivered. It does not need a topic.
#[cfg(unix)]
async fn m3_message_did_send(carrier: &dyn CarrierUnderTest) {
    let sent = b"message:did address";
    let received = carrier.deliver_did(sent).await.unwrap();
    assert_eq!(received.bytes, sent);
    assert_eq!(received.sender_did, carrier.sender_did());
}

#[cfg(unix)]
async fn m4_message_private_answer(carrier: &dyn CarrierUnderTest) {
    let answer = carrier
        .send_message(MESSAGE_TOPIC, b"message:privacy", None)
        .await
        .unwrap();
    assert_eq!(answer["status"], "ok");
    assert_no_topology(&answer, carrier);
}

// A notice delivers the bytes and does not take a caller sender. The visible
// sender is the transport Home, or none.
#[cfg(unix)]
async fn n1_notification_bytes_no_reply(carrier: &dyn CarrierUnderTest) {
    let sent = b"notice:contract bytes";
    let forged = elastos_identity::derive_did(&[215; 32]).1;
    assert_ne!(forged, carrier.sender_did());
    let (_, received) = gossip_roundtrip(carrier, NOTICE_TOPIC, sent, true, Some(&forged)).await;
    assert_eq!(received.bytes, sent);
    assert_visible_gossip_home(&received, carrier, &forged);
    // After the round trip the neighbour link is up, so this acknowledgement
    // is the complete send answer: status, data.remote_peer_count and the
    // runtime's transfer metadata, no reply body and no further keys.
    let answer = carrier.notify(NOTICE_TOPIC, sent, None).await.unwrap();
    let remote_peer_count = answer["data"]["remote_peer_count"].clone();
    let runtime_transfer = answer["_runtime_transfer"].clone();
    assert_eq!(
        answer,
        json!({"status":"ok","data":{"remote_peer_count":remote_peer_count},
            "_runtime_transfer":runtime_transfer})
    );
}

// A notice uses the same DID send. The recorded sender is the transport DID.
#[cfg(unix)]
async fn n2_notification_sender_identity(carrier: &dyn CarrierUnderTest) {
    let claimed = elastos_identity::derive_did(&[213; 32]).1;
    assert_ne!(claimed, carrier.sender_did());
    let received = carrier
        .deliver_did(format!("sender_id={claimed}").as_bytes())
        .await
        .unwrap();
    assert_eq!(received.sender_did, carrier.sender_did());
    assert_ne!(received.sender_did, claimed);
}

// A notice that names a peer DID and bytes is delivered. It does not need a topic.
#[cfg(unix)]
async fn n3_notification_did_send(carrier: &dyn CarrierUnderTest) {
    let sent = b"notice:did address";
    let received = carrier.deliver_did(sent).await.unwrap();
    assert_eq!(received.bytes, sent);
    assert_eq!(received.sender_did, carrier.sender_did());
}

#[cfg(unix)]
async fn n4_notification_private_answer(carrier: &dyn CarrierUnderTest) {
    let answer = carrier
        .notify(NOTICE_TOPIC, b"notice:privacy", None)
        .await
        .unwrap();
    assert_eq!(answer["status"], "ok");
    assert_no_topology(&answer, carrier);
}

#[cfg(unix)]
async fn f1_file_request_responder_bytes(carrier: &dyn CarrierUnderTest) {
    let cid = content_cid(FILE_BYTES);
    let file = carrier
        .request_file(&cid, carrier.peer_did())
        .await
        .unwrap();
    assert_eq!(file.bytes, FILE_BYTES);
}

#[cfg(unix)]
async fn f2_file_request_responder_authenticated_did(carrier: &dyn CarrierUnderTest) {
    let cid = content_cid(FILE_BYTES);
    let file = carrier
        .request_file(&cid, carrier.peer_did())
        .await
        .unwrap();
    assert_eq!(file.sender_did, carrier.sender_did());
}

#[cfg(unix)]
async fn f3_file_request_responder_unknown_did(carrier: &dyn CarrierUnderTest) {
    let cid = content_cid(FILE_BYTES);
    let calls = carrier.remote_calls();
    let refused = carrier
        .request_file(&cid, &unknown_did())
        .await
        .unwrap_err();
    assert!(
        matches!(refused, ProviderError::Unavailable(_)),
        "{refused:?}"
    );
    assert_eq!(carrier.remote_calls(), calls);
}

#[cfg(unix)]
async fn f4_file_request_responder_private_answer(carrier: &dyn CarrierUnderTest) {
    let cid = content_cid(FILE_BYTES);
    let file = carrier
        .request_file(&cid, carrier.peer_did())
        .await
        .unwrap();
    assert_no_topology(&file.answer, carrier);
}

// open: the file-request receipt comes from the product fetch path (distinct-holder fetch), which this suite does not drive yet
#[cfg(unix)]
async fn f5_file_request_responder_receipt_open_today(carrier: &dyn CarrierUnderTest) {
    let cid = content_cid(FILE_BYTES);
    let file = carrier
        .request_file(&cid, carrier.peer_did())
        .await
        .unwrap();
    assert!(file.answer["data"].get("receipt").is_none());
}

// open: waits for Rong (verb or WebSpace files)
#[cfg(unix)]
async fn v1_voice_open(carrier: &dyn CarrierUnderTest) {
    let answer = carrier.voice_probe().await.unwrap();
    assert_eq!(answer["status"], "error");
    assert_eq!(answer["code"], "unknown_op");
}

// This list is the complete contract that a second backend runs.
#[cfg(unix)]
async fn run_contract(carrier: &dyn CarrierUnderTest, only: Option<ContractRow>) {
    use ContractRow::*;
    for row in [
        R1, R2, R3, R4, R5, R6, M1, M2, M3, M4, N1, N2, N3, N4, F1, F2, F3, F4, F5, V1,
    ] {
        if only.is_some_and(|selected| selected != row) {
            continue;
        }
        match row {
            R1 => r1_request_reply_responder_bytes(carrier).await,
            R2 => r2_request_reply_responder_authenticated_did(carrier).await,
            R3 => r3_request_reply_responder_unknown_did(carrier).await,
            R4 => r4_request_reply_responder_private_answer(carrier).await,
            R5 => r5_request_reply_responder_without_grant(carrier).await,
            R6 => r6_request_reply_responder_opaque_body(carrier).await,
            M1 => m1_message_bytes(carrier).await,
            M2 => m2_message_sender_identity(carrier).await,
            M3 => m3_message_did_send(carrier).await,
            M4 => m4_message_private_answer(carrier).await,
            N1 => n1_notification_bytes_no_reply(carrier).await,
            N2 => n2_notification_sender_identity(carrier).await,
            N3 => n3_notification_did_send(carrier).await,
            N4 => n4_notification_private_answer(carrier).await,
            F1 => f1_file_request_responder_bytes(carrier).await,
            F2 => f2_file_request_responder_authenticated_did(carrier).await,
            F3 => f3_file_request_responder_unknown_did(carrier).await,
            F4 => f4_file_request_responder_private_answer(carrier).await,
            F5 => f5_file_request_responder_receipt_open_today(carrier).await,
            V1 => v1_voice_open(carrier).await,
        }
    }
}

#[cfg(unix)]
async fn run_current_row(row: ContractRow) {
    let carrier = CurrentCarrier::new().await;
    use ContractRow::*;
    if matches!(row, M1 | M4) {
        carrier.join_topic(MESSAGE_TOPIC).await;
    }
    if matches!(row, N1 | N4) {
        carrier.join_topic(NOTICE_TOPIC).await;
    }
    run_contract(&carrier, Some(row)).await;
    carrier.stop().await;
}

macro_rules! current_row_test {
    ($name:ident, $row:ident) => {
        #[cfg(unix)]
        #[tokio::test]
        async fn $name() {
            run_current_row(ContractRow::$row).await;
        }
    };
}

current_row_test!(carrier_contract_r1_request_reply_responder_bytes_holds, R1);
current_row_test!(
    carrier_contract_r2_request_reply_responder_authenticated_did_holds,
    R2
);
current_row_test!(
    carrier_contract_r3_request_reply_responder_unknown_did_holds,
    R3
);
current_row_test!(
    carrier_contract_r4_request_reply_responder_private_answer_holds,
    R4
);
current_row_test!(
    carrier_contract_r5_request_reply_responder_without_grant_open_today,
    R5
);
current_row_test!(
    carrier_contract_r6_request_reply_responder_opaque_body_holds,
    R6
);
current_row_test!(carrier_contract_m1_message_bytes_holds, M1);
current_row_test!(carrier_contract_m2_message_sender_identity_holds, M2);
current_row_test!(carrier_contract_m3_message_did_send_holds, M3);
current_row_test!(carrier_contract_m4_message_private_answer_holds, M4);
current_row_test!(carrier_contract_n1_notification_bytes_no_reply_holds, N1);
current_row_test!(carrier_contract_n2_notification_sender_identity_holds, N2);
current_row_test!(carrier_contract_n3_notification_did_send_holds, N3);
current_row_test!(carrier_contract_n4_notification_private_answer_holds, N4);
current_row_test!(carrier_contract_f1_file_request_responder_bytes_holds, F1);
current_row_test!(
    carrier_contract_f2_file_request_responder_authenticated_did_holds,
    F2
);
current_row_test!(
    carrier_contract_f3_file_request_responder_unknown_did_holds,
    F3
);
current_row_test!(
    carrier_contract_f4_file_request_responder_private_answer_holds,
    F4
);
current_row_test!(
    carrier_contract_f5_file_request_responder_receipt_open_today,
    F5
);
current_row_test!(carrier_contract_v1_voice_open_today, V1);

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
        let source = std::fs::read_to_string(&file)
            .unwrap()
            .replace("\r\n", "\n");
        let source = source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .unwrap()
            .split("#[cfg(test)]\npub(crate) mod tests")
            .next()
            .unwrap();
        let relative = file
            .strip_prefix(crates)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
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
    let mut expected: Vec<&str> = vec![];
    expected.sort();
    assert_eq!(
        found, expected,
        "production route construction inventory changed"
    );
}
