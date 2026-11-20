//! Shared provider capability-resource mapping.
//!
//! HTTP host adapters and the resource bridge must derive the same capability
//! resource from the same provider request. Keeping that logic here prevents
//! local and capsule-kernel calls from drifting.
//!
//! Localhost operations live in one table in this file. The resource builder
//! and the action map both read that table. Webspace reads the same actions.

use crate::resource_bridge::{LAUNCH_CONTENT, LAUNCH_CONTENT_PATTERN, LAUNCH_OUTPUT};
use elastos_common::localhost::rooted_localhost_uri;
use elastos_runtime::capability::Action;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const WALLET_STATUS_RESOURCE: &str = "elastos://wallet/meta/status";

/// Build the capability resource string for a provider request.
///
/// First-party `elastos://` sub-providers use `elastos://<scheme>/...`.
/// Unknown schemes and operations fail closed instead of creating wildcard
/// authority such as `<scheme>://*`.
pub fn build_capability_resource(
    scheme: &str,
    op: &str,
    request: &Value,
) -> Result<String, String> {
    #[cfg(test)]
    if scheme == "test" {
        ensure_supported_operation("test", op, &["read"])?;
        return Ok("elastos://test/bus/probe".to_string());
    }

    match scheme {
        "localhost" => localhost_resource(op, request),
        "availability" => simple_elastos_resource("availability", op, &["ensure", "status"]),
        "block-graph" => simple_elastos_resource(
            "block-graph",
            op,
            &["export_graph", "import_graph", "status"],
        ),
        "chain" => {
            if op == "networks" {
                return Ok("elastos://chain/meta/networks".to_string());
            }
            let network = request
                .get("network")
                .and_then(|value| value.as_str())
                .ok_or_else(|| "chain provider request missing network".to_string())?;
            validate_chain_network(network)?;
            if op == "erc1271_is_valid_signature" {
                return Ok(format!("elastos://chain/{network}/proof/erc1271"));
            }
            match op {
                "status"
                | "block_number"
                | "sync_health"
                | "balance"
                | "contract_call"
                | "estimate_gas"
                | "transaction_count"
                | "gas_price"
                | "fee_history"
                | "code"
                | "logs"
                | "transaction"
                | "receipt"
                | "proof"
                | "prepare_transaction"
                | "broadcast_transaction"
                | "node_lifecycle" => Ok(format!("elastos://chain/{network}/{op}")),
                _ => Err(format!("Unsupported chain provider operation: {op}")),
            }
        }
        "drm" => drm_resource(op),
        "net" => net_resource(op),
        "exit" => exit_resource(op),
        "browser-engine" => browser_engine_resource(op),
        "rights" => rights_resource(op),
        "key" => key_resource(op),
        "decrypt" => decrypt_resource(op),
        "wallet" => wallet_resource(op),
        "did" => did_resource(op),
        "ipfs" => ipfs_resource(op),
        "model" => model_resource(op, request),
        "object" => object_resource(op),
        "operator-drive-adapter" => simple_elastos_resource(
            "operator-drive-adapter",
            op,
            &["status", "metadata_index", "read_bytes", "write_bytes"],
        ),
        "peer" => simple_elastos_resource(
            "peer",
            op,
            &[
                "init",
                "connect",
                "remember_peer",
                "get_ticket",
                "get_node_id",
                "list_peers",
                "list_topics",
                "list_topic_peers",
                "gossip_join",
                "gossip_join_peers",
                "gossip_leave",
                "gossip_send",
                "gossip_recv",
            ],
        ),
        "tunnel" => simple_elastos_resource("tunnel", op, &["start", "stop", "status", "ping"]),
        "content" => content_resource(op),
        "inspect" => inspect_resource(op),
        "launch" => launch_resource(op, request),
        _ => Err(format!("Unsupported provider scheme: {scheme}")),
    }
}

/// Canonical capability action for provider operations where the Runtime owns
/// the operation-to-action contract directly.
pub fn provider_operation_action(scheme: &str, op: &str) -> Option<Action> {
    #[cfg(test)]
    if scheme == "test" {
        return (op == "read").then_some(Action::Read);
    }

    match scheme {
        "localhost" | "webspace" => localhost_op_required_action(op),
        "launch" => match op {
            "read" => Some(Action::Read),
            "digest" => Some(Action::Read),
            "write" => Some(Action::Write),
            _ => None,
        },
        "did" => execute_op_required_action(op),
        "availability" => match op {
            "status" => Some(Action::Read),
            "ensure" => Some(Action::Write),
            _ => None,
        },
        "block-graph" => match op {
            "status" | "export_graph" => Some(Action::Read),
            "import_graph" => Some(Action::Write),
            _ => None,
        },
        "chain" => chain_op_required_action(op),
        "content" => match op {
            "status" | "fetch" => Some(Action::Read),
            "publish" | "ensure" | "repair" | "unpublish" => Some(Action::Write),
            _ => None,
        },
        "drm" | "rights" | "key" | "decrypt" => read_only_provider_action(op),
        "net" => match op {
            "status" | "resolve" => Some(Action::Read),
            "connect" | "stream" | "http" => Some(Action::Write),
            _ => None,
        },
        "exit" => match op {
            "status" | "discover_remote_carrier_exits" | "quote" => Some(Action::Read),
            "open_stream" | "close_stream" | "http_fetch" => Some(Action::Write),
            _ => None,
        },
        "browser-engine" => match op {
            "status" | "readiness" | "page_status" | "diagnostics" | "inspect" => {
                Some(Action::Read)
            }
            "launch" | "attach_stream" | "input" | "webrtc_signal" => Some(Action::Write),
            "close_page" => Some(Action::Delete),
            _ => None,
        },
        "wallet" => wallet_op_required_action(op),
        "ipfs" => ipfs_op_required_action(op),
        "model" => match op {
            "offers_list" | "runs_get" | "runs_events" => Some(Action::Read),
            "runs_create" | "runs_cancel" => Some(Action::Execute),
            _ => None,
        },
        "object" => object_op_required_action(op),
        "operator-drive-adapter" => match op {
            "status" | "metadata_index" | "read_bytes" => Some(Action::Read),
            "write_bytes" => Some(Action::Write),
            _ => None,
        },
        "peer" => match op {
            "init" | "connect" | "remember_peer" | "gossip_join" | "gossip_leave"
            | "gossip_send" | "get_ticket" | "get_node_id" | "list_peers" | "list_topics"
            | "list_topic_peers" | "gossip_join_peers" | "gossip_recv" => Some(Action::Message),
            _ => None,
        },
        "tunnel" => {
            Some(Action::Admin).filter(|_| matches!(op, "start" | "stop" | "status" | "ping"))
        }
        "inspect" => inspect_op_required_action(op),
        _ => None,
    }
}

/// What a localhost operation may change. This is the consequence class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocalhostConsequence {
    /// The call reports state and leaves that state as it was.
    Observe,
    /// The call writes bytes at the path, replacing them or appending.
    WriteBytes,
    /// The call creates a directory at the path.
    CreateDirectory,
    /// The call removes the path.
    Remove,
}

/// Whether repeating the operation is the same effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocalhostIdempotency {
    /// Repeating the call leaves the same state.
    Idempotent,
    /// A repeat can act again, so retry needs a durable effect id.
    NeedsEffectId,
}

/// Consequence class plus idempotency. This field decides whether the row
/// stands. The action map reads the right. Dispatch, retry, and audit do
/// not read this field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LocalhostEffect {
    consequence: LocalhostConsequence,
    idempotency: LocalhostIdempotency,
}

/// One localhost operation. The resource builder and the action map both
/// read this table. The table stays in this process.
struct LocalhostOperation {
    name: &'static str,
    inputs: &'static [&'static str],
    outputs: &'static [&'static str],
    right: Action,
    effect: LocalhostEffect,
}

const fn localhost_op(
    name: &'static str,
    inputs: &'static [&'static str],
    outputs: &'static [&'static str],
    right: Action,
    consequence: LocalhostConsequence,
    idempotency: LocalhostIdempotency,
) -> LocalhostOperation {
    LocalhostOperation {
        name,
        inputs,
        outputs,
        right,
        effect: LocalhostEffect {
            consequence,
            idempotency,
        },
    }
}

// A success response serializes as `status` and `data`. Payload fields
// such as `content` and `bytes_written` sit inside `data`.
const LOCALHOST_OPERATIONS: &[LocalhostOperation] = &[
    localhost_op(
        "read",
        &["path", "encoding", "offset", "length"],
        &["status", "data"],
        Action::Read,
        LocalhostConsequence::Observe,
        LocalhostIdempotency::Idempotent,
    ),
    localhost_op(
        "write",
        &["path", "content", "append"],
        &["status", "data"],
        Action::Write,
        LocalhostConsequence::WriteBytes,
        LocalhostIdempotency::NeedsEffectId,
    ),
    localhost_op(
        "list",
        &["path"],
        &["status", "data"],
        Action::Read,
        LocalhostConsequence::Observe,
        LocalhostIdempotency::Idempotent,
    ),
    localhost_op(
        "delete",
        &["path", "recursive"],
        &["status", "data"],
        Action::Delete,
        LocalhostConsequence::Remove,
        LocalhostIdempotency::NeedsEffectId,
    ),
    localhost_op(
        "stat",
        &["path"],
        &["status", "data"],
        Action::Read,
        LocalhostConsequence::Observe,
        LocalhostIdempotency::Idempotent,
    ),
    localhost_op(
        "mkdir",
        &["path", "parents"],
        &["status", "data"],
        Action::Write,
        LocalhostConsequence::CreateDirectory,
        LocalhostIdempotency::NeedsEffectId,
    ),
    localhost_op(
        "exists",
        &["path"],
        &["status", "data"],
        Action::Read,
        LocalhostConsequence::Observe,
        LocalhostIdempotency::Idempotent,
    ),
    localhost_op(
        "resolve",
        &["path", "moniker"],
        &["status", "data"],
        Action::Read,
        LocalhostConsequence::Observe,
        LocalhostIdempotency::Idempotent,
    ),
    // The provider request has no fields. The capability resource is still
    // the rooted path: the builder names that path for every operation.
    localhost_op(
        "ping",
        &[],
        &["status", "data"],
        Action::Read,
        LocalhostConsequence::Observe,
        LocalhostIdempotency::Idempotent,
    ),
];

/// A Read right is an observation, and an observation can be repeated.
/// Write and mkdir take Write. Delete takes Delete. Admin does not stand
/// in their place. A file operation names a path input. Ping's provider
/// request has no fields, so that row names no path. Every row names at
/// least one output.
fn localhost_row_effect_agrees(row: &LocalhostOperation) -> bool {
    let consequence = row.effect.consequence;
    let observes = matches!(consequence, LocalhostConsequence::Observe);
    let idempotent = matches!(row.effect.idempotency, LocalhostIdempotency::Idempotent);
    let names_a_file = row.name != "ping";
    let right_ok = match consequence {
        LocalhostConsequence::Observe => matches!(row.right, Action::Read),
        LocalhostConsequence::WriteBytes | LocalhostConsequence::CreateDirectory => {
            matches!(row.right, Action::Write)
        }
        LocalhostConsequence::Remove => matches!(row.right, Action::Delete),
    };
    right_ok
        && (!observes || idempotent)
        && row.inputs.contains(&"path") == names_a_file
        && !row.outputs.is_empty()
}

fn localhost_operation(name: &str) -> Option<&'static LocalhostOperation> {
    LOCALHOST_OPERATIONS
        .iter()
        .find(|row| row.name == name && localhost_row_effect_agrees(row))
}

fn localhost_op_required_action(op: &str) -> Option<Action> {
    localhost_operation(op).map(|row| row.right)
}

fn execute_op_required_action(op: &str) -> Option<Action> {
    match op {
        "chat_completions"
        | "list_backends"
        | "ping"
        | "status"
        | "health"
        | "list_models"
        | "get_did"
        | "resolve"
        | "sign_chat_message"
        | "verify"
        | "verify_did_recovery"
        | "get_nickname"
        | "set_nickname"
        | "get_persona_did" => Some(Action::Execute),
        _ => None,
    }
}

fn chain_op_required_action(op: &str) -> Option<Action> {
    match op {
        "networks"
        | "status"
        | "block_number"
        | "sync_health"
        | "balance"
        | "transaction"
        | "receipt"
        | "proof"
        | "erc1271_is_valid_signature"
        | "contract_call"
        | "estimate_gas"
        | "transaction_count"
        | "gas_price"
        | "fee_history"
        | "code"
        | "logs" => Some(Action::Read),
        "prepare_transaction" => Some(Action::Write),
        "broadcast_transaction" | "node_lifecycle" => Some(Action::Admin),
        _ => None,
    }
}

fn read_only_provider_action(op: &str) -> Option<Action> {
    match op {
        "status"
        | "open"
        | "has_access_by_content_id"
        | "is_subscription_active"
        | "can_stream"
        | "can_download"
        | "release"
        | "open_session"
        | "render" => Some(Action::Read),
        _ => None,
    }
}

fn wallet_op_required_action(op: &str) -> Option<Action> {
    match op {
        "status" => Some(Action::Read),
        _ => None,
    }
}

fn ipfs_op_required_action(op: &str) -> Option<Action> {
    match op {
        "cat" | "get_bytes" | "ls" | "health" | "status" => Some(Action::Read),
        // The fetched content lands at the caller's destination.
        "cat_to_path" | "download_directory" | "add_bytes" | "add_path" | "add_directory"
        | "pin" => Some(Action::Write),
        "unpin" => Some(Action::Delete),
        _ => None,
    }
}

fn object_op_required_action(op: &str) -> Option<Action> {
    match op {
        "roots"
        | "list"
        | "stat"
        | "read"
        | "download"
        | "status"
        | "events"
        | "list_runtime_custody"
        | "open_viewer"
        | "read_viewer"
        | "close_viewer" => Some(Action::Read),
        "import_runtime_custody" => Some(Action::Write),
        "write" | "mkdir" | "rename" | "move" | "copy" | "trash" | "restore" | "publish"
        | "unpublish" | "repair" | "share" | "buy" => Some(Action::Write),
        "delete_permanently" | "empty_trash" => Some(Action::Delete),
        _ => None,
    }
}

/// Canonical capability action each Capsule Inspector operation requires.
pub fn inspect_op_required_action(op: &str) -> Option<Action> {
    match op {
        "capsules" | "capsule" | "self" | "plan" => Some(Action::Read),
        "revoke" => Some(Action::Write),
        _ => None,
    }
}

fn validate_segment(value: &str, label: &str) -> Result<(), String> {
    if !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Ok(());
    }
    Err(format!("Invalid {label}: {value}"))
}

fn validate_chain_network(network: &str) -> Result<(), String> {
    if !network.is_empty()
        && network
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
    {
        return Ok(());
    }
    Err(format!("Invalid chain network: {network}"))
}

/// A launch name is its own resource, as a storage name is: a read of a
/// file of the launch's content, and a read or a write of a name in the
/// launch's output, are judged, by the ceiling and by the token, as exactly
/// that name. The content's bare name, which asks for the listing, is judged
/// as the pattern: the bridge's matching folds a trailing slash away, so the
/// bare text would be covered by nothing, and it is the one request for all
/// of it. The content is read only, and a digest names one of its files, whole.
/// No other text is a launch name.
fn launch_resource(op: &str, request: &Value) -> Result<String, String> {
    ensure_supported_operation("launch", op, &["read", "write", "digest"])?;
    let name = request
        .get("path")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    if let Some(path) = name.strip_prefix(LAUNCH_OUTPUT) {
        return match path {
            "" => Err(format!(
                "a launch's output is named by a name under {LAUNCH_OUTPUT}"
            )),
            _ if op == "digest" => Err("a digest names content, not the output".to_string()),
            _ => Ok(name.to_string()),
        };
    }
    match name.strip_prefix(LAUNCH_CONTENT) {
        None => Err(format!(
            "a launch name is {LAUNCH_CONTENT} or {LAUNCH_OUTPUT}, or a name under one of them"
        )),
        Some(_) if !matches!(op, "read" | "digest") => {
            Err("a launch's content is read only".to_string())
        }
        Some("") if op == "digest" => Err(format!(
            "a digest names one file of a launch's content, under {LAUNCH_CONTENT}, not its listing"
        )),
        Some("") => Ok(LAUNCH_CONTENT_PATTERN.to_string()),
        Some(_) => Ok(name.to_string()),
    }
}

fn ensure_supported_operation(provider: &str, op: &str, supported: &[&str]) -> Result<(), String> {
    if supported.contains(&op) {
        return Ok(());
    }
    Err(format!("Unsupported {provider} provider operation: {op}"))
}

fn simple_elastos_resource(provider: &str, op: &str, supported: &[&str]) -> Result<String, String> {
    ensure_supported_operation(provider, op, supported)?;
    Ok(format!("elastos://{provider}/{op}"))
}

/// Agent Host journals live under `.AppData/Agents/` in a person's root. The
/// data directory may sit on a filesystem that folds case and Unicode (APFS)
/// and drops empty and `.` segments, so the area is found that way: under
/// `localhost://Users/<root>/`, the first two segments, ignoring empty and `.`
/// ones, fold to `.appdata/agents` under `to_uppercase().to_lowercase()`. The
/// rule does not depend on whose root it is.
///
/// The input is canonicalised here first, the same way the filesystem path is
/// resolved (`rooted_localhost_uri`: surrounding whitespace and slashes go), so
/// no caller can check one string and resolve another.
pub(crate) fn in_agents_area(path: &str) -> bool {
    let Some(rooted) = rooted_localhost_uri(path) else {
        return false;
    };
    let Some(rest) = rooted.strip_prefix("localhost://Users/") else {
        return false;
    };
    let named: Vec<&str> = rest
        .split('/')
        .filter(|segment| !matches!(*segment, "" | "."))
        .collect();
    let folds_to = |segment: &str, target: &str| segment.to_uppercase().to_lowercase() == target;
    named.len() >= 3 && folds_to(named[1], ".appdata") && folds_to(named[2], "agents")
}

/// The one Agents rule, for every route a capsule can use to reach localhost
/// there: local dispatch, the attached (HTTP) bridge, the provider proxy, the
/// protected storage path, and both capability request handlers. In the area
/// only read and write are allowed, only on one spelling: `.AppData/Agents`,
/// then segments matching `^[a-z0-9][a-z0-9._-]*$`, with no empty or `.`
/// segment anywhere. A write needs a name below `Agents`. The area is found on
/// the canonical string (see `in_agents_area`); the exact spelling then
/// refuses any path that is not already canonical, because surrounding
/// whitespace or a trailing slash makes a bad or empty segment. Returns the
/// refusal code and message.
pub(crate) fn agents_area_refusal(
    rooted: &str,
    operation: &str,
) -> Option<(&'static str, &'static str)> {
    if !in_agents_area(rooted) {
        return None;
    }
    if !matches!(operation, "read" | "write") {
        return Some((
            "operation_not_allowed",
            "only read and write are allowed under .AppData/Agents/",
        ));
    }
    let segments: Vec<&str> = rooted
        .strip_prefix("localhost://Users/")
        .unwrap_or_default()
        .split('/')
        .collect();
    let segment_ok = |segment: &&str| {
        segment
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && segment.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
            // Windows drops a trailing '.', so "journal." would name "journal".
            && !segment.ends_with('.')
    };
    let exact = segments.len() >= 3
        && !segments.iter().any(|segment| matches!(*segment, "" | "."))
        && segments[1] == ".AppData"
        && segments[2] == "Agents"
        && segments[3..].iter().all(segment_ok);
    if !exact || (operation == "write" && segments.len() < 4) {
        return Some((
            "invalid_localhost_path",
            "paths under .AppData/Agents/ must be spelled exactly, with lower-case segments of letters, digits, '.', '_' or '-' that do not end in '.'",
        ));
    }
    None
}

fn localhost_resource(op: &str, request: &Value) -> Result<String, String> {
    if localhost_operation(op).is_none() {
        return Err(format!("Unsupported localhost provider operation: {op}"));
    }
    match request
        .get("path")
        .and_then(|value| value.as_str())
        .filter(|path| !path.is_empty())
    {
        Some(path) => rooted_localhost_uri(path)
            .ok_or_else(|| format!("Invalid rooted localhost path: {}", path)),
        None => Err("localhost provider request missing path".to_string()),
    }
}

fn did_resource(op: &str) -> Result<String, String> {
    simple_elastos_resource(
        "did",
        op,
        &[
            "get_did",
            "resolve",
            "sign_chat_message",
            "verify",
            "verify_did_recovery",
            "get_nickname",
            "set_nickname",
            "get_persona_did",
        ],
    )
}

fn ipfs_resource(op: &str) -> Result<String, String> {
    simple_elastos_resource(
        "ipfs",
        op,
        &[
            "add_bytes",
            "add_path",
            "add_directory",
            "cat",
            "cat_to_path",
            "get_bytes",
            "ls",
            "download_directory",
            "pin",
            "unpin",
            "health",
            "status",
        ],
    )
}

fn object_resource(op: &str) -> Result<String, String> {
    simple_elastos_resource(
        "object",
        op,
        &[
            "roots",
            "list",
            "stat",
            "read",
            "download",
            "write",
            "mkdir",
            "rename",
            "move",
            "copy",
            "trash",
            "restore",
            "delete_permanently",
            "empty_trash",
            "status",
            "events",
            "publish",
            "unpublish",
            "repair",
            "share",
            "list_runtime_custody",
            "import_runtime_custody",
            "buy",
            "open_viewer",
            "read_viewer",
            "close_viewer",
        ],
    )
}

fn content_resource(op: &str) -> Result<String, String> {
    match op {
        "publish" => Ok("elastos://content/publish".to_string()),
        "fetch" => Ok("elastos://content/fetch".to_string()),
        "status" => Ok("elastos://content/status".to_string()),
        "ensure" => Ok("elastos://content/ensure".to_string()),
        "repair" => Ok("elastos://content/repair".to_string()),
        "unpublish" => Ok("elastos://content/unpublish".to_string()),
        _ => Err(format!("Unsupported content provider operation: {op}")),
    }
}

fn inspect_resource(op: &str) -> Result<String, String> {
    match inspect_op_required_action(op) {
        Some(_) => Ok(format!("elastos://inspect/{op}")),
        None => Err(format!("Unsupported inspect provider operation: {op}")),
    }
}

fn exit_resource(op: &str) -> Result<String, String> {
    match op {
        "status" => Ok("elastos://exit/meta/status".to_string()),
        "discover_remote_carrier_exits" => {
            Ok("elastos://exit/discover_remote_carrier_exits".to_string())
        }
        "quote" => Ok("elastos://exit/quote".to_string()),
        "open_stream" => Ok("elastos://exit/open_stream".to_string()),
        "close_stream" => Ok("elastos://exit/close_stream".to_string()),
        "http_fetch" => Ok("elastos://exit/http_fetch".to_string()),
        _ => Err(format!("Unsupported exit provider operation: {op}")),
    }
}

fn browser_engine_resource(op: &str) -> Result<String, String> {
    match op {
        "status" => Ok("elastos://browser-engine/meta/status".to_string()),
        "launch" => Ok("elastos://browser-engine/launch".to_string()),
        "attach_stream" => Ok("elastos://browser-engine/attach_stream".to_string()),
        "close_page" => Ok("elastos://browser-engine/close_page".to_string()),
        "page_status" => Ok("elastos://browser-engine/page/status".to_string()),
        "diagnostics" => Ok("elastos://browser-engine/page/diagnostics".to_string()),
        "inspect" => Ok("elastos://browser-engine/page/inspect".to_string()),
        "input" => Ok("elastos://browser-engine/page/input".to_string()),
        "webrtc_signal" => Ok("elastos://browser-engine/page/webrtc_signal".to_string()),
        _ => Err(format!(
            "Unsupported browser-engine provider operation: {op}"
        )),
    }
}

fn net_resource(op: &str) -> Result<String, String> {
    match op {
        "status" => Ok("elastos://net/meta/status".to_string()),
        "resolve" => Ok("elastos://net/resolve".to_string()),
        "connect" => Ok("elastos://net/connect".to_string()),
        "stream" => Ok("elastos://net/stream".to_string()),
        "http" => Ok("elastos://net/http".to_string()),
        _ => Err(format!("Unsupported net provider operation: {op}")),
    }
}

fn wallet_resource(op: &str) -> Result<String, String> {
    match op {
        "status" => Ok(WALLET_STATUS_RESOURCE.to_string()),
        _ => Err(format!("Unsupported wallet provider operation: {op}")),
    }
}

pub fn is_wallet_resource(resource: &str) -> bool {
    resource
        .strip_prefix("elastos://")
        .and_then(|rest| rest.split(['/', '?', '#']).next())
        == Some("wallet")
}

pub fn ensure_generic_wallet_capability(resource: &str, action: Action) -> Result<(), String> {
    if !is_wallet_resource(resource)
        || (resource == WALLET_STATUS_RESOURCE && action == Action::Read)
    {
        return Ok(());
    }
    Err(
        "generic Wallet access is limited to read-only elastos://wallet/meta/status; use the private Runtime Wallet Bus for authority-bound operations"
            .to_string(),
    )
}

fn drm_resource(op: &str) -> Result<String, String> {
    match op {
        "status" => Ok("elastos://drm/meta/status".to_string()),
        "open" => Ok("elastos://drm/open".to_string()),
        _ => Err(format!("Unsupported drm provider operation: {op}")),
    }
}

fn rights_resource(op: &str) -> Result<String, String> {
    match op {
        "status" => Ok("elastos://rights/meta/status".to_string()),
        "has_access_by_content_id" => {
            Ok("elastos://rights/access/has_access_by_content_id".to_string())
        }
        "is_subscription_active" => {
            Ok("elastos://rights/subscription/is_subscription_active".to_string())
        }
        "can_stream" => Ok("elastos://rights/content/can_stream".to_string()),
        "can_download" => Ok("elastos://rights/content/can_download".to_string()),
        _ => Err(format!("Unsupported rights provider operation: {op}")),
    }
}

fn key_resource(op: &str) -> Result<String, String> {
    match op {
        "status" => Ok("elastos://key/meta/status".to_string()),
        "release" => Ok("elastos://key/release".to_string()),
        _ => Err(format!("Unsupported key provider operation: {op}")),
    }
}

fn decrypt_resource(op: &str) -> Result<String, String> {
    match op {
        "status" => Ok("elastos://decrypt/meta/status".to_string()),
        "open_session" => Ok("elastos://decrypt/session/open".to_string()),
        "render" => Ok("elastos://decrypt/render".to_string()),
        _ => Err(format!("Unsupported decrypt provider operation: {op}")),
    }
}

fn model_resource(op: &str, request: &Value) -> Result<String, String> {
    ensure_supported_operation(
        "model",
        op,
        &[
            "offers_list",
            "runs_create",
            "runs_get",
            "runs_events",
            "runs_cancel",
        ],
    )?;
    match op {
        "offers_list" => Ok("elastos://model/offers".to_string()),
        "runs_create" => {
            let offer_hash = model_offer_id_hash(
                request
                    .get("offer_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "model provider request missing offer_id".to_string())?,
            )?;
            Ok(format!("elastos://model/offers/sha256/{offer_hash}/runs"))
        }
        "runs_get" => {
            let run_digest = validated_model_run_digest(
                request
                    .get("run_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "model provider request missing run_id".to_string())?,
            )?;
            Ok(format!("elastos://model/runs/sha256/{run_digest}"))
        }
        "runs_events" => {
            let run_digest = validated_model_run_digest(
                request
                    .get("run_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "model provider request missing run_id".to_string())?,
            )?;
            Ok(format!("elastos://model/runs/sha256/{run_digest}/events"))
        }
        "runs_cancel" => {
            let run_digest = validated_model_run_digest(
                request
                    .get("run_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "model provider request missing run_id".to_string())?,
            )?;
            Ok(format!("elastos://model/runs/sha256/{run_digest}/cancel"))
        }
        _ => Err(format!("Unsupported model provider operation: {op}")),
    }
}

fn validated_model_run_digest(run_id: &str) -> Result<&str, String> {
    let digest = run_id
        .strip_prefix("run:sha256:")
        .ok_or_else(|| "model run_id must be a canonical run:sha256 identifier".to_string())?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("model run_id must be a canonical run:sha256 identifier".to_string());
    }
    if digest.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err("model run_id must be a canonical run:sha256 identifier".to_string());
    }
    validate_segment(digest, "model run_id hash")?;
    Ok(digest)
}

fn model_offer_id_hash(offer_id: &str) -> Result<String, String> {
    if offer_id.is_empty() || offer_id.trim() != offer_id {
        return Err("model offer_id must be a trimmed non-empty string".to_string());
    }
    if offer_id.len() > 256 {
        return Err("model offer_id exceeds 256 bytes".to_string());
    }
    let mut hasher = Sha256::new();
    hasher.update(offer_id.as_bytes());
    Ok(hex_lower(&hasher.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ipfs_preparation_operations_have_no_capsule_mapping() {
        for op in [
            "runtime_prepare_backend",
            "runtime_hash_staged_directory",
            "runtime_add_local_object",
        ] {
            assert!(build_capability_resource("ipfs", op, &serde_json::json!({})).is_err());
            assert!(provider_operation_action("ipfs", op).is_none());
        }
    }

    /// A digest on a launch name is the read action, on one file of the
    /// content: `launch`/`digest` maps to `Read`, and a digest names a content
    /// file name only. The launch operation set is exactly read, write, digest.
    #[test]
    fn a_launch_digest_is_a_read_of_one_content_file() {
        let name = |path: &str| serde_json::json!({"path": path});
        let file = format!("{LAUNCH_CONTENT}images/01.png");
        assert_eq!(
            provider_operation_action("launch", "digest"),
            Some(Action::Read)
        );
        assert_eq!(
            provider_operation_action("launch", "read"),
            Some(Action::Read)
        );
        assert_eq!(
            provider_operation_action("launch", "write"),
            Some(Action::Write)
        );
        assert_eq!(
            build_capability_resource("launch", "digest", &name(&file)).unwrap(),
            file
        );
        assert_eq!(
            build_capability_resource("launch", "read", &name(&file)).unwrap(),
            file
        );
        // The bare content name is the listing, not a digestible file; an
        // output name is not the content; any other text is no launch name.
        assert!(build_capability_resource("launch", "digest", &name(LAUNCH_CONTENT)).is_err());
        assert!(build_capability_resource(
            "launch",
            "digest",
            &name(&format!("{LAUNCH_OUTPUT}playlist.json"))
        )
        .is_err());
        assert!(
            build_capability_resource("launch", "digest", &name("elastos://launch/store")).is_err()
        );
        for op in ["delete", "execute", "admin", "digestall"] {
            assert!(provider_operation_action("launch", op).is_none(), "{op}");
            assert!(
                build_capability_resource("launch", op, &name(&file)).is_err(),
                "{op}"
            );
        }
    }

    #[test]
    fn ipfs_destination_operations_require_write() {
        for op in ["cat_to_path", "download_directory"] {
            assert_eq!(
                provider_operation_action("ipfs", op),
                Some(Action::Write),
                "{op} writes fetched content to the caller's destination"
            );
        }
        for op in ["cat", "get_bytes", "ls", "health", "status"] {
            assert_eq!(
                provider_operation_action("ipfs", op),
                Some(Action::Read),
                "{op}"
            );
        }
    }

    #[test]
    fn browser_inspection_uses_the_existing_read_authority_resource() {
        assert_eq!(
            provider_operation_action("browser-engine", "inspect"),
            Some(Action::Read)
        );
        assert_eq!(
            build_capability_resource("browser-engine", "inspect", &serde_json::json!({})).unwrap(),
            "elastos://browser-engine/page/inspect"
        );
    }

    #[test]
    fn localhost_resource_accepts_full_uri_and_bare_rooted_path() {
        let full = serde_json::json!({"path": "localhost://MyWebSite/Documents/demo.md"});
        assert_eq!(
            build_capability_resource("localhost", "read", &full).unwrap(),
            "localhost://MyWebSite/Documents/demo.md"
        );

        let bare = serde_json::json!({"path": "MyWebSite/Documents/demo.md"});
        assert_eq!(
            build_capability_resource("localhost", "read", &bare).unwrap(),
            "localhost://MyWebSite/Documents/demo.md"
        );
        assert_eq!(
            build_capability_resource("localhost", "delete", &full).unwrap(),
            "localhost://MyWebSite/Documents/demo.md"
        );
    }

    /// The nine localhost rows are the only list. The resource builder and
    /// the action map, for localhost and for webspace, read those rows.
    #[test]
    fn localhost_rows_are_the_one_source_for_both_deciders() {
        let body =
            serde_json::json!({"path": "localhost://Local/SharedByLocalUsersAndBots/Home/a.md"});
        let rooted = "localhost://Local/SharedByLocalUsersAndBots/Home/a.md";
        assert_eq!(
            LOCALHOST_OPERATIONS
                .iter()
                .map(|row| row.name)
                .collect::<Vec<_>>(),
            ["read", "write", "list", "delete", "stat", "mkdir", "exists", "resolve", "ping",]
        );
        let shapes = localhost_protocol_shapes();
        assert_provider_shapes_match_the_capsule(&shapes);
        for row in LOCALHOST_OPERATIONS {
            let (right, consequence, idempotency) = expected_localhost_row(row.name);
            let (inputs, outputs) = &shapes[row.name];
            assert_eq!(row.right, right, "{}", row.name);
            assert_eq!(row.effect.consequence, consequence, "{}", row.name);
            assert_eq!(row.effect.idempotency, idempotency, "{}", row.name);
            let inputs: Vec<&str> = inputs.iter().map(String::as_str).collect();
            let outputs: Vec<&str> = outputs.iter().map(String::as_str).collect();
            assert_eq!(row.inputs, inputs.as_slice(), "{}", row.name);
            assert_eq!(row.outputs, outputs.as_slice(), "{}", row.name);
            assert!(
                localhost_row_effect_agrees(row),
                "{}: a read right is an observation, and a state change does not take Read",
                row.name
            );
            assert_eq!(
                provider_operation_action("localhost", row.name),
                Some(row.right),
                "{}",
                row.name
            );
            assert_eq!(
                provider_operation_action("webspace", row.name),
                Some(row.right),
                "{}",
                row.name
            );
            assert_eq!(
                build_capability_resource("localhost", row.name, &body).unwrap(),
                rooted,
                "{}",
                row.name
            );
        }
        assert!(
            build_capability_resource("localhost", "ping", &serde_json::json!({})).is_err(),
            "ping still names its capability resource with a rooted path"
        );
        assert!(localhost_operation("ping").unwrap().inputs.is_empty());
        assert!(localhost_operation("raw_storage").is_none());
        assert!(provider_operation_action("localhost", "raw_storage").is_none());
        assert!(provider_operation_action("webspace", "raw_storage").is_none());
        assert!(build_capability_resource("localhost", "raw_storage", &body).is_err());
        assert_eq!(
            build_capability_resource("webspace", "read", &body).unwrap_err(),
            "Unsupported provider scheme: webspace"
        );
    }

    fn expected_localhost_row(name: &str) -> (Action, LocalhostConsequence, LocalhostIdempotency) {
        use LocalhostConsequence::{CreateDirectory, Observe, Remove, WriteBytes};
        use LocalhostIdempotency::{Idempotent, NeedsEffectId};
        match name {
            "read" | "list" | "exists" | "resolve" | "ping" | "stat" => {
                (Action::Read, Observe, Idempotent)
            }
            "write" => (Action::Write, WriteBytes, NeedsEffectId),
            "mkdir" => (Action::Write, CreateDirectory, NeedsEffectId),
            "delete" => (Action::Delete, Remove, NeedsEffectId),
            other => panic!("unknown localhost operation {other}"),
        }
    }

    /// Inputs come from the provider text, not from a second copy of the
    /// row. `token` is left out: the runtime attaches it. Outputs are the
    /// keys of a serialized success response.
    fn localhost_protocol_shapes() -> std::collections::BTreeMap<String, (Vec<String>, Vec<String>)>
    {
        let provider = include_str!("../../../capsules/localhost-provider/src/main.rs");
        let webspace = include_str!("../../../../capsules/webspace-provider/src/main.rs");
        let requests = enum_fields(provider, "pub enum ProviderRequest {");
        let outputs = serialized_success_keys(Some(serde_json::json!({})));
        let mut shapes = std::collections::BTreeMap::new();
        for name in ["read", "write", "list", "delete", "stat", "mkdir", "exists"] {
            let fields = requests
                .get(name)
                .unwrap_or_else(|| panic!("missing {name}"));
            shapes.insert(name.to_string(), (without_token(fields), outputs.clone()));
        }
        let web_requests = enum_fields(webspace, "enum Request {");
        let ping_inputs = without_token(web_requests.get("ping").expect("webspace ping"));
        let resolve_inputs = without_token(web_requests.get("resolve").expect("webspace resolve"));
        let resolve_arm = arm_until(webspace, "Request::Resolve", "Request::");
        assert!(
            resolve_arm.contains("to_value(handle)"),
            "resolve returns the handle object in data"
        );
        shapes.insert("ping".to_string(), (ping_inputs, outputs.clone()));
        shapes.insert("resolve".to_string(), (resolve_inputs, outputs));
        shapes
    }

    fn assert_provider_shapes_match_the_capsule(
        shapes: &std::collections::BTreeMap<String, (Vec<String>, Vec<String>)>,
    ) {
        let (read_inputs, _) = &shapes["read"];
        assert!(
            read_inputs.iter().any(|key| key == "encoding"),
            "read request has encoding"
        );
        assert_eq!(shapes["read"].1, ["status", "data"]);
        assert_eq!(shapes["list"].1, ["status", "data"]);
        assert!(shapes["ping"].0.is_empty(), "ping request has no fields");
        assert_eq!(shapes["ping"].1, ["status", "data"]);
        assert_eq!(shapes["resolve"].0, ["path", "moniker"]);
        assert_eq!(shapes["resolve"].1, ["status", "data"]);
    }

    /// The capsule's success response. The tag and the `data` field match
    /// `ProviderResponse::Ok` in the localhost provider.
    #[derive(serde::Serialize)]
    #[serde(tag = "status", rename_all = "snake_case")]
    enum LocalhostSuccess {
        Ok { data: Option<serde_json::Value> },
    }

    fn serialized_success_text(data: Option<serde_json::Value>) -> String {
        serde_json::to_string(&LocalhostSuccess::Ok { data }).expect("success serializes")
    }

    fn serialized_success_keys(data: Option<serde_json::Value>) -> Vec<String> {
        top_level_keys(&serialized_success_text(data))
    }

    /// Keys of one JSON object, in the order `to_string` writes them.
    /// A `Value` map sorts keys, so it is not the provider's line.
    fn top_level_keys(text: &str) -> Vec<String> {
        let mut keys = Vec::new();
        let mut depth = 0;
        let mut rest = text;
        while let Some(index) = rest.find(['{', '}', '[', ']', '"']) {
            let ch = rest[index..].chars().next().expect("matched char");
            if ch == '"' {
                let after = &rest[index + 1..];
                let end = after.find('"').expect("closing quote");
                let tail = after[end + 1..].trim_start();
                if depth == 1 && tail.starts_with(':') {
                    keys.push(after[..end].to_string());
                }
                rest = &after[end + 1..];
                continue;
            }
            if matches!(ch, '{' | '[') {
                depth += 1;
            } else {
                depth -= 1;
            }
            rest = &rest[index + ch.len_utf8()..];
        }
        keys
    }

    fn without_token(fields: &[String]) -> Vec<String> {
        fields
            .iter()
            .filter(|field| field.as_str() != "token" && field.as_str() != "_token")
            .cloned()
            .collect()
    }

    fn enum_fields(source: &str, header: &str) -> std::collections::BTreeMap<String, Vec<String>> {
        let start = source
            .find(header)
            .unwrap_or_else(|| panic!("missing {header}"));
        let rest = &source[start + header.len()..];
        let end = rest
            .find("\n}")
            .unwrap_or_else(|| panic!("enum {header} does not close"));
        let mut map = std::collections::BTreeMap::new();
        let mut name: Option<String> = None;
        let mut fields = Vec::new();
        for line in rest[..end].lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with('#') {
                continue;
            }
            if name.is_none() {
                let ident = leading_ident(trimmed);
                if ident.is_empty() {
                    continue;
                }
                if trimmed.contains('{') && trimmed.contains('}') {
                    map.insert(snake(ident), fields_in_braces(trimmed));
                } else if trimmed.contains('{') {
                    name = Some(snake(ident));
                    fields = Vec::new();
                } else {
                    map.insert(snake(ident), Vec::new());
                }
            } else if trimmed.starts_with('}') {
                map.insert(
                    name.take().expect("open variant"),
                    std::mem::take(&mut fields),
                );
            } else if let Some(field) = field_ident(trimmed) {
                fields.push(field.to_string());
            }
        }
        map
    }

    fn fields_in_braces(trimmed: &str) -> Vec<String> {
        let inner = trimmed
            .split_once('{')
            .and_then(|(_, after)| after.rsplit_once('}'))
            .map(|(body, _)| body)
            .unwrap_or("");
        inner
            .split(',')
            .filter_map(|part| field_ident(part.trim()).map(str::to_string))
            .collect()
    }

    fn field_ident(trimmed: &str) -> Option<&str> {
        let ident = leading_ident(trimmed);
        let rest = trimmed[ident.len()..].trim_start();
        if ident.is_empty() || !rest.starts_with(':') {
            None
        } else {
            Some(ident)
        }
    }

    fn leading_ident(text: &str) -> &str {
        let end = text
            .find(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
            .unwrap_or(text.len());
        &text[..end]
    }

    fn snake(name: &str) -> String {
        let mut out = String::new();
        for (index, ch) in name.chars().enumerate() {
            if ch.is_ascii_uppercase() {
                if index > 0 {
                    out.push('_');
                }
                out.push(ch.to_ascii_lowercase());
            } else {
                out.push(ch);
            }
        }
        out
    }

    fn arm_until(source: &str, marker: &str, next: &str) -> String {
        let start = source
            .find(marker)
            .unwrap_or_else(|| panic!("missing {marker}"));
        let rest = &source[start + marker.len()..];
        let end = rest.find(next).unwrap_or(rest.len());
        rest[..end].to_string()
    }

    /// A literal in the action map that copies the row's right still agrees
    /// with the walk. The map's own text is that check. The agreement tests
    /// execute the rule.
    #[test]
    fn localhost_action_map_has_no_second_action_literal() {
        let source = include_str!("provider_resource.rs");
        let start = source.find("fn localhost_op_required_action").unwrap();
        let rest = &source[start..];
        let end = rest.find("\nfn execute_op_required_action").unwrap();
        assert!(
            !rest[..end].contains("Action::"),
            "the action map reads the row"
        );
    }

    /// The effect is read only while deciding whether the row stands.
    /// `localhost_read_right_on_a_write_effect_does_not_stand` executes that rule.
    #[test]
    fn localhost_effect_gates_the_row_only() {
        let source = include_str!("provider_resource.rs");
        let prod = source.split("\n#[cfg(test)]\nmod tests").next().unwrap();
        let agree = prod.find("fn localhost_row_effect_agrees").unwrap();
        let next = prod.find("fn localhost_operation").unwrap();
        let body = &prod[agree..next];
        assert_eq!(body.matches(".effect").count(), 2);
        assert_eq!(prod.matches(".effect").count(), 2);
    }

    /// A text guard, not behaviour evidence (review checklist 11). It reads
    /// the decision function's source text for a `target_os` branch. The
    /// behaviour evidence is the named `b4r_` rows that Linux CI and macOS CI
    /// each run.
    #[test]
    fn b4r_decision_function_has_no_target_os_text_guard() {
        let source = include_str!("../../elastos-runtime/src/capability/manager.rs");
        let start = source.find("pub async fn validate(").unwrap();
        let end = source.find("pub async fn delegate(").unwrap();
        assert!(start < end, "the decision function precedes delegate");
        let window = &source[start..end];
        assert!(
            window.len() > 1000,
            "the scan window names the decision function"
        );
        assert!(
            window.contains("WrongAction"),
            "the scan window is the action check"
        );
        assert!(
            !window.contains("target_os"),
            "the decision function text has no target_os branch"
        );
    }

    /// Each row's outputs are the keys of one serialized success response.
    /// Payload fields stay inside `data`.
    #[test]
    fn a_serialized_localhost_response_matches_its_row() {
        let samples = [
            (
                "read",
                Some(serde_json::json!({"content": [104], "size": 1})),
            ),
            ("write", Some(serde_json::json!({"bytes_written": 2}))),
            ("list", Some(serde_json::json!([]))),
            ("delete", None),
            (
                "stat",
                Some(serde_json::json!({"path": "a", "is_file": true})),
            ),
            ("mkdir", None),
            ("exists", Some(serde_json::json!({"exists": true}))),
            (
                "resolve",
                Some(serde_json::json!({"handle_uri": "localhost://Local/a"})),
            ),
            ("ping", Some(serde_json::json!({"pong": true}))),
        ];
        for (name, data) in samples {
            let capsule = serialized_success_text(data.clone());
            let runtime =
                serde_json::to_string(&elastos_runtime::provider::bridge::ProviderResponse::Ok {
                    data,
                })
                .expect("runtime success");
            assert_eq!(capsule, runtime, "{name}");
            let keys = top_level_keys(&capsule);
            let key_refs: Vec<&str> = keys.iter().map(String::as_str).collect();
            assert_eq!(
                localhost_operation(name).unwrap().outputs,
                key_refs.as_slice(),
                "{name}"
            );
            for inner in ["content", "bytes_written", "pong", "exists", "encoding"] {
                assert!(!key_refs.contains(&inner), "{name} {inner}");
            }
        }
        let utf8 = serialized_success_text(Some(serde_json::json!({
            "content": "hi",
            "encoding": "utf8",
            "size": 2,
        })));
        assert!(!top_level_keys(&utf8).iter().any(|key| key == "encoding"));
        let parsed: serde_json::Value = serde_json::from_str(&utf8).expect("utf8 read");
        assert_eq!(parsed["data"]["encoding"], "utf8");
    }

    #[test]
    fn localhost_read_right_on_a_write_effect_does_not_stand() {
        let row = localhost_op(
            "read",
            &["path", "encoding", "offset", "length"],
            &["status", "data"],
            Action::Read,
            LocalhostConsequence::WriteBytes,
            LocalhostIdempotency::Idempotent,
        );
        assert!(!localhost_row_effect_agrees(&row));
        assert_eq!(localhost_op_required_action("read"), Some(Action::Read));
        assert_eq!(localhost_op_required_action("write"), Some(Action::Write));
    }

    #[test]
    fn localhost_state_change_refuses_an_admin_right() {
        let cases = [
            (
                "write",
                &["path", "content", "append"][..],
                LocalhostConsequence::WriteBytes,
            ),
            (
                "mkdir",
                &["path", "parents"][..],
                LocalhostConsequence::CreateDirectory,
            ),
            (
                "delete",
                &["path", "recursive"][..],
                LocalhostConsequence::Remove,
            ),
        ];
        for (name, inputs, consequence) in cases {
            let row = localhost_op(
                name,
                inputs,
                &["status", "data"],
                Action::Admin,
                consequence,
                LocalhostIdempotency::NeedsEffectId,
            );
            assert!(!localhost_row_effect_agrees(&row), "{name}");
            assert!(
                localhost_row_effect_agrees(localhost_operation(name).unwrap()),
                "{name}"
            );
        }
    }

    #[test]
    fn localhost_resource_requires_rooted_path() {
        assert!(build_capability_resource("localhost", "read", &serde_json::json!({})).is_err());
        assert!(build_capability_resource(
            "localhost",
            "read",
            &serde_json::json!({"path": "../host"})
        )
        .is_err());
        assert!(build_capability_resource(
            "localhost",
            "raw_storage",
            &serde_json::json!({"path": "localhost://TestRoot/Documents/demo.md"})
        )
        .is_err());
    }

    #[test]
    fn first_party_sub_provider_resource() {
        let request = serde_json::json!({});
        assert_eq!(
            build_capability_resource("did", "get_did", &request).unwrap(),
            "elastos://did/get_did"
        );
        assert_eq!(
            build_capability_resource("peer", "connect", &request).unwrap(),
            "elastos://peer/connect"
        );
        assert_eq!(
            build_capability_resource("peer", "gossip_join", &request).unwrap(),
            "elastos://peer/gossip_join"
        );
        assert_eq!(
            build_capability_resource("peer", "gossip_recv", &request).unwrap(),
            "elastos://peer/gossip_recv"
        );
        assert!(build_capability_resource("did", "raw_secret", &request).is_err());
        assert!(build_capability_resource("peer", "raw_socket", &request).is_err());
    }

    #[test]
    fn first_party_manifest_provider_operations_are_explicit() {
        let request = serde_json::json!({});
        for (scheme, op, resource) in [
            ("availability", "ensure", "elastos://availability/ensure"),
            (
                "block-graph",
                "export_graph",
                "elastos://block-graph/export_graph",
            ),
            ("ipfs", "cat", "elastos://ipfs/cat"),
            ("object", "read", "elastos://object/read"),
            (
                "operator-drive-adapter",
                "metadata_index",
                "elastos://operator-drive-adapter/metadata_index",
            ),
            ("tunnel", "start", "elastos://tunnel/start"),
            (
                "exit",
                "discover_remote_carrier_exits",
                "elastos://exit/discover_remote_carrier_exits",
            ),
            ("wallet", "status", "elastos://wallet/meta/status"),
        ] {
            assert_eq!(
                build_capability_resource(scheme, op, &request).unwrap(),
                resource
            );
        }

        for (scheme, op) in [
            ("availability", "raw_replication_socket"),
            ("block-graph", "raw_car"),
            ("ipfs", "raw_kubo_rpc"),
            ("object", "raw_storage_path"),
            ("operator-drive-adapter", "resolver_credentials"),
            ("tunnel", "raw_cloudflared_admin"),
            ("protected-content-decrypt", "status"),
        ] {
            assert!(
                build_capability_resource(scheme, op, &request).is_err(),
                "{scheme}/{op} must fail closed"
            );
        }
    }

    #[test]
    fn first_party_provider_authority_operations_have_action_mapping() {
        let manifests = [
            (
                "availability",
                "../../../capsules/availability-provider/capsule.json",
            ),
            (
                "block-graph",
                "../../../capsules/content-block-graph-provider/capsule.json",
            ),
            ("chain", "../../../capsules/chain-provider/capsule.json"),
            ("decrypt", "../../../capsules/decrypt-provider/capsule.json"),
            ("did", "../../../capsules/did-provider/capsule.json"),
            ("drm", "../../../capsules/drm-provider/capsule.json"),
            ("exit", "../../../capsules/exit-provider/capsule.json"),
            ("ipfs", "../../../capsules/ipfs-provider/capsule.json"),
            ("key", "../../../capsules/key-provider/capsule.json"),
            ("net", "../../../capsules/net-provider/capsule.json"),
            ("object", "../../../capsules/object-provider/capsule.json"),
            (
                "operator-drive-adapter",
                "../../../capsules/operator-drive-adapter/capsule.json",
            ),
            ("rights", "../../../capsules/rights-provider/capsule.json"),
            ("tunnel", "../../../capsules/tunnel-provider/capsule.json"),
            ("wallet", "../../../capsules/wallet-provider/capsule.json"),
            (
                "browser-engine",
                "../../../capsules/browser-engine-adapter/capsule.json",
            ),
        ];

        for (scheme, manifest_path) in manifests {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(manifest_path);
            let manifest: elastos_common::CapsuleManifest =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            let authority = manifest
                .authority
                .unwrap_or_else(|| panic!("{scheme} provider manifest must declare authority"));
            for capability in authority.capabilities {
                for operation in capability.operations {
                    assert!(
                        provider_operation_action(scheme, &operation).is_some(),
                        "{scheme}/{operation} in {} must have a canonical Runtime action",
                        path.display()
                    );
                }
            }
        }
    }

    #[test]
    fn unknown_provider_scheme_fails_closed() {
        let err =
            build_capability_resource("socket", "connect", &serde_json::json!({})).unwrap_err();
        assert_eq!(err, "Unsupported provider scheme: socket");
    }

    #[test]
    fn content_resource_uses_documented_scopes() {
        let request = serde_json::json!({});
        assert_eq!(
            build_capability_resource("content", "publish", &request).unwrap(),
            "elastos://content/publish"
        );
        assert_eq!(
            build_capability_resource("content", "fetch", &request).unwrap(),
            "elastos://content/fetch"
        );
        assert_eq!(
            build_capability_resource("content", "status", &request).unwrap(),
            "elastos://content/status"
        );
        assert_eq!(
            build_capability_resource("content", "ensure", &request).unwrap(),
            "elastos://content/ensure"
        );
        assert_eq!(
            build_capability_resource("content", "repair", &request).unwrap(),
            "elastos://content/repair"
        );
        assert_eq!(
            build_capability_resource("content", "unpublish", &request).unwrap(),
            "elastos://content/unpublish"
        );
        assert_eq!(
            build_capability_resource("content", "unpin", &request).unwrap_err(),
            "Unsupported content provider operation: unpin"
        );
    }

    #[test]
    fn inspect_resource_and_actions_are_canonical() {
        let request = serde_json::json!({});
        assert_eq!(
            build_capability_resource("inspect", "capsules", &request).unwrap(),
            "elastos://inspect/capsules"
        );
        assert_eq!(
            build_capability_resource("inspect", "plan", &request).unwrap(),
            "elastos://inspect/plan"
        );
        assert_eq!(
            provider_operation_action("inspect", "capsules"),
            Some(elastos_runtime::capability::Action::Read)
        );
        assert_eq!(
            provider_operation_action("inspect", "plan"),
            Some(elastos_runtime::capability::Action::Read)
        );
        assert_eq!(
            provider_operation_action("inspect", "revoke"),
            Some(elastos_runtime::capability::Action::Write)
        );
        assert!(build_capability_resource("inspect", "raw", &request).is_err());
        assert_eq!(
            provider_operation_action("chain", "status"),
            Some(elastos_runtime::capability::Action::Read)
        );
        assert_eq!(
            provider_operation_action("chain", "broadcast_transaction"),
            Some(elastos_runtime::capability::Action::Admin)
        );
        assert_eq!(
            provider_operation_action("localhost", "read"),
            Some(elastos_runtime::capability::Action::Read)
        );
        assert_eq!(
            provider_operation_action("localhost", "write"),
            Some(elastos_runtime::capability::Action::Write)
        );
        assert_eq!(
            provider_operation_action("browser-engine", "close_page"),
            Some(elastos_runtime::capability::Action::Delete)
        );
    }

    #[test]
    fn model_resources_and_actions_are_canonical() {
        let list = serde_json::json!({});
        let offer_a = "offer:flash-chat:pair-a";
        let offer_b = "offer:h3-video:2x";
        let run_id = "run:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            build_capability_resource("model", "offers_list", &list).unwrap(),
            "elastos://model/offers"
        );
        assert_eq!(
            build_capability_resource(
                "model",
                "runs_create",
                &serde_json::json!({"offer_id": offer_a})
            )
            .unwrap(),
            "elastos://model/offers/sha256/6a01612dd8b7e218fcc8d3f037c8672498658b6738262c1fae375cd1514ad77d/runs"
        );
        assert_eq!(
            build_capability_resource(
                "model",
                "runs_create",
                &serde_json::json!({"offer_id": offer_b})
            )
            .unwrap(),
            "elastos://model/offers/sha256/7e635da8f42e2df0918f065be21057fecd516b45639357674d414b4cb8cd2fe7/runs"
        );
        assert_eq!(
            build_capability_resource(
                "model",
                "runs_get",
                &serde_json::json!({"run_id": run_id})
            )
            .unwrap(),
            "elastos://model/runs/sha256/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            build_capability_resource(
                "model",
                "runs_events",
                &serde_json::json!({"run_id": run_id})
            )
            .unwrap(),
            "elastos://model/runs/sha256/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/events"
        );
        assert_eq!(
            build_capability_resource(
                "model",
                "runs_cancel",
                &serde_json::json!({"run_id": run_id})
            )
            .unwrap(),
            "elastos://model/runs/sha256/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/cancel"
        );
        assert_eq!(
            provider_operation_action("model", "offers_list"),
            Some(elastos_runtime::capability::Action::Read)
        );
        assert_eq!(
            provider_operation_action("model", "runs_create"),
            Some(elastos_runtime::capability::Action::Execute)
        );
        assert_eq!(
            provider_operation_action("model", "runs_get"),
            Some(elastos_runtime::capability::Action::Read)
        );
        assert_eq!(
            provider_operation_action("model", "runs_events"),
            Some(elastos_runtime::capability::Action::Read)
        );
        assert_eq!(
            provider_operation_action("model", "runs_cancel"),
            Some(elastos_runtime::capability::Action::Execute)
        );
        assert!(build_capability_resource("model", "runs_create", &serde_json::json!({})).is_err());
        assert!(build_capability_resource(
            "model",
            "runs_create",
            &serde_json::json!({"offer_id": ""})
        )
        .is_err());
        assert!(build_capability_resource(
            "model",
            "runs_create",
            &serde_json::json!({"offer_id": " offer:flash-chat:pair-a "})
        )
        .is_err());
        assert!(build_capability_resource(
            "model",
            "runs_create",
            &serde_json::json!({"offer_id": "x".repeat(257)})
        )
        .is_err());
        assert!(build_capability_resource("model", "runs_get", &serde_json::json!({})).is_err());
        assert!(
            build_capability_resource(
                "model",
                "runs_get",
                &serde_json::json!({"run_id": "run:sha512:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"})
            )
            .is_err()
        );
        assert!(build_capability_resource(
            "model",
            "runs_get",
            &serde_json::json!({"run_id": "run:sha256:01234567"})
        )
        .is_err());
        assert!(
            build_capability_resource(
                "model",
                "runs_get",
                &serde_json::json!({"run_id": "run:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeF"})
            )
            .is_err()
        );
        assert!(
            build_capability_resource(
                "model",
                "runs_get",
                &serde_json::json!({"run_id": "run:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"})
            )
            .is_err()
        );
        assert!(
            build_capability_resource(
                "model",
                "runs_get",
                &serde_json::json!({"run_id": "run:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd/0"})
            )
            .is_err()
        );
    }

    #[test]
    fn chain_resource_is_network_scoped() {
        let request = serde_json::json!({"op": "block_number", "network": "esc-mainnet"});
        assert_eq!(
            build_capability_resource("chain", "block_number", &request).unwrap(),
            "elastos://chain/esc-mainnet/block_number"
        );
        assert_eq!(
            build_capability_resource("chain", "sync_health", &request).unwrap(),
            "elastos://chain/esc-mainnet/sync_health"
        );
        assert_eq!(
            build_capability_resource("chain", "networks", &serde_json::json!({})).unwrap(),
            "elastos://chain/meta/networks"
        );
        assert_eq!(
            build_capability_resource("rights", "has_access_by_content_id", &serde_json::json!({}))
                .unwrap(),
            "elastos://rights/access/has_access_by_content_id",
            "the active provisional rights-provider mapping is preserved until product cutover"
        );
        assert!(
            build_capability_resource("custody", "release_contribution", &serde_json::json!({}))
                .is_err(),
            "inactive custody registration is Runtime-internal until product cutover"
        );
        assert!(
            build_capability_resource("custody", "status", &serde_json::json!({})).is_err(),
            "inactive custody registration is Runtime-internal until product cutover"
        );
        assert!(
            build_capability_resource("protect", "open_protection_session", &serde_json::json!({}))
                .is_err(),
            "protect registration is Runtime-internal until product cutover"
        );
        assert!(
            build_capability_resource("protect", "status", &serde_json::json!({})).is_err(),
            "protect registration is Runtime-internal until product cutover"
        );
        assert!(
            build_capability_resource(
                "chain",
                "describe_protected_content_creator_mint_source",
                &serde_json::json!({})
            )
            .is_err(),
            "protected-content creator mint source description must stay Runtime-internal"
        );
        assert!(
            build_capability_resource(
                "chain",
                "resolve_protected_content_creator_mint",
                &serde_json::json!({})
            )
            .is_err(),
            "protected-content creator mint resolution must stay Runtime-internal"
        );
        assert!(
            build_capability_resource(
                "chain",
                "resolve_protected_content_mint_receipt",
                &serde_json::json!({})
            )
            .is_err(),
            "protected-content mint receipt bind must stay Runtime-internal"
        );
        assert!(
            build_capability_resource(
                "chain",
                "resolve_protected_content_verified_listing",
                &serde_json::json!({})
            )
            .is_err(),
            "protected-content verified listing resolution must stay Runtime-internal"
        );
        assert!(
            build_capability_resource(
                "chain",
                "resolve_protected_content_purchase",
                &serde_json::json!({})
            )
            .is_err(),
            "protected-content purchase assembly must stay Runtime-internal"
        );
        assert!(
            build_capability_resource(
                "chain",
                "resolve_protected_content_purchase_access",
                &serde_json::json!({})
            )
            .is_err(),
            "protected-content purchase access corroboration must stay Runtime-internal"
        );
        assert!(
            build_capability_resource(
                "chain",
                "protected_content_rights_evidence",
                &serde_json::json!({})
            )
            .is_err(),
            "protected-content rights evidence must stay Runtime-internal"
        );
        assert!(
            build_capability_resource(
                "chain",
                "resolve_protected_content_policy",
                &serde_json::json!({})
            )
            .is_err(),
            "protected-content policy resolution must stay Runtime-internal"
        );
        assert!(
            build_capability_resource(
                "chain",
                "has_access_by_content_id",
                &serde_json::json!({"network": "esc-mainnet"})
            )
            .is_err(),
            "legacy Chain rights rail must not remain capsule-invokable"
        );
        assert_eq!(
            build_capability_resource(
                "chain",
                "prepare_transaction",
                &serde_json::json!({"network": "esc-mainnet"})
            )
            .unwrap(),
            "elastos://chain/esc-mainnet/prepare_transaction"
        );
        assert_eq!(
            build_capability_resource(
                "chain",
                "contract_call",
                &serde_json::json!({"network": "esc-mainnet"})
            )
            .unwrap(),
            "elastos://chain/esc-mainnet/contract_call"
        );
        assert_eq!(
            build_capability_resource(
                "chain",
                "estimate_gas",
                &serde_json::json!({"network": "esc-mainnet"})
            )
            .unwrap(),
            "elastos://chain/esc-mainnet/estimate_gas"
        );
        assert_eq!(
            build_capability_resource(
                "chain",
                "transaction_count",
                &serde_json::json!({"network": "esc-mainnet"})
            )
            .unwrap(),
            "elastos://chain/esc-mainnet/transaction_count"
        );
        assert_eq!(
            build_capability_resource(
                "chain",
                "fee_history",
                &serde_json::json!({"network": "esc-mainnet"})
            )
            .unwrap(),
            "elastos://chain/esc-mainnet/fee_history"
        );
        assert_eq!(
            build_capability_resource(
                "chain",
                "logs",
                &serde_json::json!({"network": "esc-mainnet"})
            )
            .unwrap(),
            "elastos://chain/esc-mainnet/logs"
        );
        assert_eq!(
            build_capability_resource(
                "chain",
                "erc1271_is_valid_signature",
                &serde_json::json!({"network": "esc-mainnet"})
            )
            .unwrap(),
            "elastos://chain/esc-mainnet/proof/erc1271"
        );
        assert_eq!(
            build_capability_resource(
                "chain",
                "node_lifecycle",
                &serde_json::json!({"network": "btc-mainnet"})
            )
            .unwrap(),
            "elastos://chain/btc-mainnet/node_lifecycle"
        );
        assert!(build_capability_resource(
            "chain",
            "block_number",
            &serde_json::json!({"network": "../esc-mainnet"})
        )
        .is_err());
        assert!(build_capability_resource(
            "chain",
            "call",
            &serde_json::json!({"network": "esc-mainnet"})
        )
        .is_err());
    }

    #[test]
    fn node_lifecycle_resource_rejects_invalid_networks() {
        assert_eq!(
            build_capability_resource(
                "chain",
                "node_lifecycle",
                &serde_json::json!({"network": "btc-mainnet"})
            )
            .unwrap(),
            "elastos://chain/btc-mainnet/node_lifecycle"
        );
        for network in ["", "BTC-mainnet", "btc_mainnet", "../btc-mainnet"] {
            assert!(build_capability_resource(
                "chain",
                "node_lifecycle",
                &serde_json::json!({"network": network})
            )
            .is_err());
        }
    }

    #[test]
    fn drm_resource_uses_documented_scopes() {
        assert_eq!(
            build_capability_resource("drm", "status", &serde_json::json!({})).unwrap(),
            "elastos://drm/meta/status"
        );
        assert_eq!(
            build_capability_resource("drm", "open", &serde_json::json!({})).unwrap(),
            "elastos://drm/open"
        );
        assert!(build_capability_resource("drm", "raw_key", &serde_json::json!({})).is_err());
    }

    #[test]
    fn net_resource_uses_browser_net_scopes() {
        assert_eq!(
            build_capability_resource("net", "status", &serde_json::json!({})).unwrap(),
            "elastos://net/meta/status"
        );
        assert_eq!(
            build_capability_resource("net", "resolve", &serde_json::json!({})).unwrap(),
            "elastos://net/resolve"
        );
        assert_eq!(
            build_capability_resource("net", "connect", &serde_json::json!({})).unwrap(),
            "elastos://net/connect"
        );
        assert_eq!(
            build_capability_resource("net", "stream", &serde_json::json!({})).unwrap(),
            "elastos://net/stream"
        );
        assert_eq!(
            build_capability_resource("net", "http", &serde_json::json!({})).unwrap(),
            "elastos://net/http"
        );
        assert!(build_capability_resource("net", "raw_socket", &serde_json::json!({})).is_err());
    }

    #[test]
    fn exit_resource_uses_internal_exit_scopes() {
        assert_eq!(
            build_capability_resource("exit", "status", &serde_json::json!({})).unwrap(),
            "elastos://exit/meta/status"
        );
        assert_eq!(
            build_capability_resource("exit", "quote", &serde_json::json!({})).unwrap(),
            "elastos://exit/quote"
        );
        assert_eq!(
            build_capability_resource("exit", "open_stream", &serde_json::json!({})).unwrap(),
            "elastos://exit/open_stream"
        );
        assert_eq!(
            build_capability_resource("exit", "close_stream", &serde_json::json!({})).unwrap(),
            "elastos://exit/close_stream"
        );
        assert_eq!(
            build_capability_resource("exit", "http_fetch", &serde_json::json!({})).unwrap(),
            "elastos://exit/http_fetch"
        );
        assert!(build_capability_resource("exit", "raw_socket", &serde_json::json!({})).is_err());
    }

    #[test]
    fn browser_engine_resource_uses_internal_engine_scopes() {
        assert_eq!(
            build_capability_resource("browser-engine", "status", &serde_json::json!({})).unwrap(),
            "elastos://browser-engine/meta/status"
        );
        assert_eq!(
            build_capability_resource("browser-engine", "launch", &serde_json::json!({})).unwrap(),
            "elastos://browser-engine/launch"
        );
        assert_eq!(
            build_capability_resource("browser-engine", "attach_stream", &serde_json::json!({}))
                .unwrap(),
            "elastos://browser-engine/attach_stream"
        );
        assert_eq!(
            build_capability_resource("browser-engine", "close_page", &serde_json::json!({}))
                .unwrap(),
            "elastos://browser-engine/close_page"
        );
        assert_eq!(
            build_capability_resource("browser-engine", "page_status", &serde_json::json!({}))
                .unwrap(),
            "elastos://browser-engine/page/status"
        );
        assert_eq!(
            build_capability_resource("browser-engine", "diagnostics", &serde_json::json!({}))
                .unwrap(),
            "elastos://browser-engine/page/diagnostics"
        );
        assert_eq!(
            build_capability_resource("browser-engine", "input", &serde_json::json!({})).unwrap(),
            "elastos://browser-engine/page/input"
        );
        assert_eq!(
            build_capability_resource("browser-engine", "webrtc_signal", &serde_json::json!({}))
                .unwrap(),
            "elastos://browser-engine/page/webrtc_signal"
        );
        assert!(
            build_capability_resource("browser-engine", "raw_socket", &serde_json::json!({}))
                .is_err()
        );
        assert!(
            build_capability_resource("browser-engine", "wallet", &serde_json::json!({})).is_err()
        );
    }

    #[test]
    fn rights_resource_uses_documented_scopes() {
        assert_eq!(
            build_capability_resource("rights", "status", &serde_json::json!({})).unwrap(),
            "elastos://rights/meta/status"
        );
        assert_eq!(
            build_capability_resource("rights", "has_access_by_content_id", &serde_json::json!({}))
                .unwrap(),
            "elastos://rights/access/has_access_by_content_id"
        );
        assert_eq!(
            build_capability_resource("rights", "can_stream", &serde_json::json!({})).unwrap(),
            "elastos://rights/content/can_stream"
        );
        assert!(build_capability_resource("rights", "raw_key", &serde_json::json!({})).is_err());
    }

    #[test]
    fn key_resource_uses_documented_scopes() {
        assert_eq!(
            build_capability_resource("key", "status", &serde_json::json!({})).unwrap(),
            "elastos://key/meta/status"
        );
        assert_eq!(
            build_capability_resource("key", "release", &serde_json::json!({})).unwrap(),
            "elastos://key/release"
        );
        assert!(build_capability_resource("key", "raw_cek", &serde_json::json!({})).is_err());
    }

    #[test]
    fn decrypt_resource_uses_documented_scopes() {
        assert_eq!(
            build_capability_resource("decrypt", "status", &serde_json::json!({})).unwrap(),
            "elastos://decrypt/meta/status"
        );
        assert_eq!(
            build_capability_resource("decrypt", "open_session", &serde_json::json!({})).unwrap(),
            "elastos://decrypt/session/open"
        );
        assert_eq!(
            build_capability_resource("decrypt", "render", &serde_json::json!({})).unwrap(),
            "elastos://decrypt/render"
        );
        assert!(build_capability_resource("decrypt", "raw_cek", &serde_json::json!({})).is_err());
    }

    #[test]
    fn wallet_resource_exposes_only_read_only_status() {
        assert_eq!(
            build_capability_resource("wallet", "status", &serde_json::json!({})).unwrap(),
            "elastos://wallet/meta/status"
        );
        assert_eq!(
            provider_operation_action("wallet", "status"),
            Some(Action::Read)
        );
        assert!(ensure_generic_wallet_capability(WALLET_STATUS_RESOURCE, Action::Read).is_ok());
        assert!(ensure_generic_wallet_capability(WALLET_STATUS_RESOURCE, Action::Write).is_err());
    }

    #[test]
    fn wallet_resource_rejects_all_principal_sensitive_operations() {
        for operation in [
            "wallet_contract",
            "challenge",
            "bitcoin_challenge",
            "verify_proof",
            "verify_bip322_proof",
            "verify_contract_proof",
            "link_account",
            "create_managed_account",
            "accounts",
            "revoke_account",
            "rename_account",
            "export_managed_secret",
            "import_managed_secret",
            "export_managed_recovery_set",
            "import_managed_recovery_set",
            "set_default_account",
            "default_account",
            "request_signature",
            "approval_requests",
            "reject_approval",
            "approve_approval",
            "complete_approval",
            "sign_approved",
            "prepare_transaction",
            "broadcast_transaction",
            "raw_proof",
            "raw_secret",
            "sign",
        ] {
            assert!(
                build_capability_resource("wallet", operation, &serde_json::json!({})).is_err(),
                "generic Wallet operation {operation} must fail closed"
            );
            assert_eq!(
                provider_operation_action("wallet", operation),
                None,
                "generic Wallet operation {operation} must not have an action mapping"
            );
        }

        for resource in [
            "elastos://wallet",
            "elastos://wallet/*",
            "elastos://wallet/account/list",
            "elastos://wallet/approval",
            "elastos://wallet/meta/status?principal=other",
        ] {
            assert!(
                ensure_generic_wallet_capability(resource, Action::Read).is_err(),
                "generic Wallet resource {resource} must fail closed"
            );
        }
    }

    #[test]
    fn pc2_wallet_bridge_raw_methods_do_not_become_provider_operations() {
        let pc2_raw_methods = [
            "eth_accounts",
            "eth_requestAccounts",
            "eth_chainId",
            "eth_blockNumber",
            "eth_getBalance",
            "eth_call",
            "eth_estimateGas",
            "eth_sendTransaction",
            "eth_signTransaction",
            "eth_sign",
            "personal_sign",
            "eth_signTypedData",
            "eth_signTypedData_v3",
            "eth_signTypedData_v4",
            "wallet_switchEthereumChain",
            "wallet_addEthereumChain",
        ];
        let request = serde_json::json!({
            "network": "esc-mainnet",
            "intent": "publish_envelope"
        });

        for method in pc2_raw_methods {
            assert!(
                build_capability_resource("wallet", method, &request).is_err(),
                "{method} must not be a raw wallet-provider operation"
            );
            assert!(
                build_capability_resource("chain", method, &request).is_err(),
                "{method} must not be a raw chain-provider operation"
            );
        }
    }

    #[test]
    fn pc2_wallet_bridge_network_effects_stay_on_typed_chain_resources() {
        assert_eq!(
            build_capability_resource(
                "chain",
                "balance",
                &serde_json::json!({"network": "esc-mainnet"})
            )
            .unwrap(),
            "elastos://chain/esc-mainnet/balance"
        );
        assert_eq!(
            build_capability_resource(
                "chain",
                "prepare_transaction",
                &serde_json::json!({"network": "esc-mainnet"})
            )
            .unwrap(),
            "elastos://chain/esc-mainnet/prepare_transaction"
        );
        assert_eq!(
            build_capability_resource(
                "chain",
                "broadcast_transaction",
                &serde_json::json!({"network": "esc-mainnet"})
            )
            .unwrap(),
            "elastos://chain/esc-mainnet/broadcast_transaction"
        );
    }
}
