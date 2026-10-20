//! Agent-host journal guest.
//!
//! The journal fold is ordinary Rust. A series starts when the system head is
//! admitted. Later appends keep that series. A head rewrite or a shrinking
//! compaction starts the next series, and compaction never replaces node 0.
//! The summary is one user checkpoint. A crash between the start and the
//! end of compaction restores the saved bytes and the series.
//! A crash records `not started` or `settlement_unknown` and does not dispatch
//! that step again. A read proposal with no grant stays `denied` and is not
//! dispatched. Cancel before dispatch stays `cancelled` and does not run.
//! Cancel after dispatch leaves the step where it is. A snapshot of the
//! workspace, the time, and the open files appends after the head and does
//! not start a series. A checkpoint copies the model bytes before a step.
//! Cancel after that copy does not dispatch, and a crash keeps its
//! settlement word. A skill under 4000 bytes appends after the head.
//! Over budget leaves the journal unchanged. Compaction keeps the skill.
//! Opening a turn records a turn id. That id is not the series epoch, and
//! the model bytes stay unchanged. Two steps in that turn share the epoch.
//! `derive` omits turn and step markers. The log bytes still keep them.
//! An assistant line is role tag 3. A tool result is role tag 4. The log
//! bytes and replay learn both tags together. An empty assistant line stays
//! in the log and in replay. `derive` omits that empty line. A tool result
//! enters the model view. A step with no result stays in the marker log and
//! stays out of that view. A read observation stores the resource, the
//! version, and the text hash in the log. Replay keeps it. The model view
//! omits it. An unread edit and a stale edit create no step. The old text
//! must occur once in the observed text. A later write stays prepared until
//! the earlier write has a result. Each write keeps its own effect id.
//! A provider write may be asked only with a grant and the current version.
//! The guest does not apply that write. A run proposal records a project
//! resource and keeps its arguments as data. A cancelled run does not start.
//! A restore proposes an observed version and does not apply it. An unknown
//! version is refused. A version that is no longer current is refused until
//! that version is read again. A hosted proposal names a model resource and
//! has no secret field. A missing grant denies it. A child proposal records
//! a narrower resource and does not inherit the parent grant. A project
//! proposal stores `localhost://Users/<root>/Projects/<name>` and no host path.
//! A project tree hash changes when a non-entrypoint file changes. A scaffold
//! write follows the read and version rules and does not apply. A run seat
//! is `microvm`. A run result is an exit code and a capped log, recorded
//! only after a granted dispatch. The guest does not run the test.
//! A journal append writes the whole encoding with a revision precondition,
//! only with the launch grant, which is held in memory and never stored. A
//! lost reply is `settlement_unknown`; resume reads the head back and nothing
//! is appended until it settles. The WASM guest runs that fold inside
//! Wasmtime and exits. It calls a provider only to write its own journal, and
//! with no launch grant it sends nothing. It has no Home window.

#[cfg(target_arch = "wasm32")]
wit_bindgen::generate!({
    path: "../../elastos/wit",
    world: "product-capsule-v1",
});

#[cfg(target_arch = "wasm32")]
const EXPECTED_RUNTIME_ABI: &str = "elastos.component/v1";

#[cfg(any(test, target_arch = "wasm32"))]
const SYSTEM_HEAD: &str = "You are the ElastOS agent host.";

#[cfg(any(test, target_arch = "wasm32"))]
/// Written by Qwen 3.8 27B on 14 Oct 2026. The guest stores it. It does not call the model.
const COMPACTION_SUMMARY: &str =
    "The person greeted, the page was read as a demo, and the test result was okay.";

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    System,
    User,
    Assistant,
    ToolResult,
}

/// Where a log node came from. The bytes keep this so replay can restore it.
#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NodeSource {
    Head,
    InHistory,
    Person,
    Snapshot,
    Skill,
    TurnMarker,
    StepMarker,
    CompactionCheckpoint,
    Observation,
}

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct SurfaceNode {
    role: Role,
    text: String,
    source: NodeSource,
}

/// A step the host has recorded and has not been granted to run.
#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StepState {
    Prepared,
    NotStarted,
    Denied,
    Cancelled,
    Dispatched,
    SettlementUnknown,
}

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProposalKind {
    Unspecified,
    Read,
    Edit,
    Run,
    Restore,
    Hosted,
    Child,
    Init,
    JournalAppend,
}

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct Step {
    id: u64,
    state: StepState,
    kind: ProposalKind,
    resource: String,
    grant: Option<String>,
    effect_id: u64,
    has_result: bool,
    old: String,
    new: String,
    argv: Vec<String>,
    parent_id: Option<u64>,
    seat: String,
    seen_version: Option<u64>,
    inbox: String,
}

/// One turn. The id is the turn's own number. It is not the series epoch.
#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct Turn {
    id: u64,
    steps: Vec<u64>,
}

/// Append-only model history plus the cache epoch. Epoch 0 means no series yet.
#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct Journal {
    events: Vec<SurfaceNode>,
    epoch: u64,
    steps: Vec<Step>,
    turns: Vec<Turn>,
    markers: Vec<SurfaceNode>,
    compaction_open: bool,
    compact_backup: Option<(Vec<SurfaceNode>, u64)>,
    compact_pending: Option<Vec<SurfaceNode>>,
}

/// Model view. Markers, a step with no result, and an empty assistant line
/// stay in the log and drop out of this view. A tool result stays, including
/// an empty one.
#[cfg(any(test, target_arch = "wasm32"))]
fn derive(events: &[SurfaceNode]) -> Vec<SurfaceNode> {
    events
        .iter()
        .filter(|node| match node.source {
            NodeSource::TurnMarker | NodeSource::StepMarker | NodeSource::Observation => false,
            _ => !matches!(node.role, Role::Assistant if node.text.is_empty()),
        })
        .cloned()
        .collect()
}

#[cfg(any(test, target_arch = "wasm32"))]
fn source_tag(source: NodeSource) -> u8 {
    match source {
        NodeSource::Head => 1,
        NodeSource::InHistory => 2,
        NodeSource::Person => 3,
        NodeSource::Snapshot => 4,
        NodeSource::Skill => 5,
        NodeSource::TurnMarker => 6,
        NodeSource::StepMarker => 7,
        NodeSource::CompactionCheckpoint => 8,
        NodeSource::Observation => 9,
    }
}

/// Role tags in the log. Assistant is 3 and a tool result is 4.
#[cfg(any(test, target_arch = "wasm32"))]
fn role_tag(role: Role) -> u8 {
    match role {
        Role::System => 1,
        Role::User => 2,
        Role::Assistant => 3,
        Role::ToolResult => 4,
    }
}

/// Canonical log bytes. Each record is role, source, length, and text.
/// This records every node it is given, including a marker, an empty
/// assistant line, and a tool result. The series epoch and the step list
/// are not part of this. `derive` omits markers and an empty assistant line.
/// This function does not.
#[cfg(any(test, target_arch = "wasm32"))]
fn model_bytes(events: &[SurfaceNode]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for event in events {
        out.push(role_tag(event.role));
        out.push(source_tag(event.source));
        let len = u32::try_from(event.text.len()).ok()?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(event.text.as_bytes());
    }
    Some(out)
}

/// Copy the model bytes before an effect. The copy is not a grant.
#[cfg(any(test, target_arch = "wasm32"))]
fn checkpoint(journal: &Journal) -> Option<Vec<u8>> {
    model_bytes(&journal.events)
}

/// Rebuild recorded nodes from bytes. A short or unknown record returns nothing.
/// A marker comes back as a marker. `derive` is the view that omits it.
#[cfg(any(test, target_arch = "wasm32"))]
fn replay(bytes: &[u8]) -> Option<Vec<SurfaceNode>> {
    let mut events = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let role = match *bytes.get(index)? {
            1 => Role::System,
            2 => Role::User,
            3 => Role::Assistant,
            4 => Role::ToolResult,
            _ => return None,
        };
        index += 1;
        let source = match *bytes.get(index)? {
            1 => NodeSource::Head,
            2 => NodeSource::InHistory,
            3 => NodeSource::Person,
            4 => NodeSource::Snapshot,
            5 => NodeSource::Skill,
            6 => NodeSource::TurnMarker,
            7 => NodeSource::StepMarker,
            8 => NodeSource::CompactionCheckpoint,
            9 => NodeSource::Observation,
            _ => return None,
        };
        index += 1;
        let len_bytes: [u8; 4] = bytes.get(index..index + 4)?.try_into().ok()?;
        let len = usize::try_from(u32::from_le_bytes(len_bytes)).ok()?;
        index += 4;
        let text_bytes = bytes.get(index..index + len)?;
        let text = std::str::from_utf8(text_bytes).ok()?.to_string();
        index += len;
        events.push(SurfaceNode { role, text, source });
    }
    Some(events)
}

/// Format 1 of the UsersAI journal object (`handoff/USERSAI-JOURNAL.md`).
/// The bytes are a header, hash-linked records, and the head hash. A grant
/// string is never encoded, so a decoded step has no grant until Runtime
/// grants it again.
#[cfg(any(test, target_arch = "wasm32"))]
const JOURNAL_MAGIC: &[u8; 4] = b"EAHJ";
#[cfg(any(test, target_arch = "wasm32"))]
const JOURNAL_FORMAT: u16 = 1;
/// Bytes cross the Runtime bridge as a JSON number array, up to four characters
/// per byte ("255,"), inside a 1 MiB frame. 192 KiB of 0xFF fits; 256 KiB does not.
#[cfg(any(test, target_arch = "wasm32"))]
const JOURNAL_CAP: usize = 192 * 1024;
#[cfg(any(test, target_arch = "wasm32"))]
const JOURNAL_HEADER: usize = 4 + 2 + 8 + 1 + 1 + 8 + 1 + 32 + 4;

#[cfg(any(test, target_arch = "wasm32"))]
fn put_str(out: &mut Vec<u8>, text: &str) -> Option<()> {
    out.extend_from_slice(&u32::try_from(text.len()).ok()?.to_le_bytes());
    out.extend_from_slice(text.as_bytes());
    Some(())
}

#[cfg(any(test, target_arch = "wasm32"))]
fn put_opt(out: &mut Vec<u8>, value: Option<u64>) {
    out.push(u8::from(value.is_some()));
    out.extend_from_slice(&value.unwrap_or(0).to_le_bytes());
}

#[cfg(any(test, target_arch = "wasm32"))]
fn node_payload(node: &SurfaceNode) -> Option<Vec<u8>> {
    let mut out = vec![role_tag(node.role), source_tag(node.source)];
    put_str(&mut out, &node.text)?;
    Some(out)
}

#[cfg(any(test, target_arch = "wasm32"))]
fn state_tag(state: StepState) -> u8 {
    match state {
        StepState::Prepared => 1,
        StepState::NotStarted => 2,
        StepState::Denied => 3,
        StepState::Cancelled => 4,
        StepState::Dispatched => 5,
        StepState::SettlementUnknown => 6,
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
fn kind_tag(kind: ProposalKind) -> u8 {
    match kind {
        ProposalKind::Unspecified => 1,
        ProposalKind::Read => 2,
        ProposalKind::Edit => 3,
        ProposalKind::Run => 4,
        ProposalKind::Restore => 5,
        ProposalKind::Hosted => 6,
        ProposalKind::Child => 7,
        ProposalKind::Init => 8,
        ProposalKind::JournalAppend => 9,
    }
}

/// The step without its grant. `grant` has no field in the bytes.
#[cfg(any(test, target_arch = "wasm32"))]
fn step_payload(step: &Step) -> Option<Vec<u8>> {
    let mut out = step.id.to_le_bytes().to_vec();
    out.push(state_tag(step.state));
    out.push(kind_tag(step.kind));
    put_str(&mut out, &step.resource)?;
    out.extend_from_slice(&step.effect_id.to_le_bytes());
    out.push(u8::from(step.has_result));
    put_str(&mut out, &step.old)?;
    put_str(&mut out, &step.new)?;
    out.extend_from_slice(&u32::try_from(step.argv.len()).ok()?.to_le_bytes());
    for arg in &step.argv {
        put_str(&mut out, arg)?;
    }
    put_opt(&mut out, step.parent_id);
    put_str(&mut out, &step.seat)?;
    put_opt(&mut out, step.seen_version);
    put_str(&mut out, &step.inbox)?;
    Some(out)
}

#[cfg(any(test, target_arch = "wasm32"))]
fn turn_payload(turn: &Turn) -> Option<Vec<u8>> {
    let mut out = turn.id.to_le_bytes().to_vec();
    out.extend_from_slice(&u32::try_from(turn.steps.len()).ok()?.to_le_bytes());
    for step in &turn.steps {
        out.extend_from_slice(&step.to_le_bytes());
    }
    Some(out)
}

#[cfg(any(test, target_arch = "wasm32"))]
fn journal_link(previous: &[u8; 32], tag: u8, payload: &[u8]) -> Option<[u8; 32]> {
    let mut message = previous.to_vec();
    message.push(tag);
    message.extend_from_slice(&u32::try_from(payload.len()).ok()?.to_le_bytes());
    message.extend_from_slice(payload);
    Some(sha256(&message))
}

/// Encode a journal as format 1. `prev_head` is the head of the version this
/// one replaces, or zeros for the first. More than the cap returns nothing.
#[cfg(any(test, target_arch = "wasm32"))]
fn encode_journal(journal: &Journal, prev_head: &[u8; 32]) -> Option<Vec<u8>> {
    let mut records: Vec<(u8, Vec<u8>)> = Vec::new();
    for node in &journal.events {
        records.push((1, node_payload(node)?));
    }
    for node in &journal.markers {
        records.push((2, node_payload(node)?));
    }
    for step in &journal.steps {
        records.push((3, step_payload(step)?));
    }
    for turn in &journal.turns {
        records.push((4, turn_payload(turn)?));
    }
    for node in journal.compact_backup.iter().flat_map(|(nodes, _)| nodes) {
        records.push((5, node_payload(node)?));
    }
    for node in journal.compact_pending.iter().flatten() {
        records.push((6, node_payload(node)?));
    }
    let mut out = JOURNAL_MAGIC.to_vec();
    out.extend_from_slice(&JOURNAL_FORMAT.to_le_bytes());
    out.extend_from_slice(&journal.epoch.to_le_bytes());
    out.push(u8::from(journal.compaction_open));
    put_opt(
        &mut out,
        journal.compact_backup.as_ref().map(|(_, epoch)| *epoch),
    );
    out.push(u8::from(journal.compact_pending.is_some()));
    out.extend_from_slice(prev_head);
    out.extend_from_slice(&u32::try_from(records.len()).ok()?.to_le_bytes());
    let mut link = sha256(&out);
    for (tag, payload) in &records {
        link = journal_link(&link, *tag, payload)?;
        out.push(*tag);
        out.extend_from_slice(&u32::try_from(payload.len()).ok()?.to_le_bytes());
        out.extend_from_slice(payload);
        out.extend_from_slice(&link);
        if out.len() > JOURNAL_CAP {
            return None;
        }
    }
    out.extend_from_slice(&link);
    (out.len() <= JOURNAL_CAP).then_some(out)
}

/// A cursor over bytes. Every read past the end is `truncated`.
#[cfg(any(test, target_arch = "wasm32"))]
struct JournalReader<'a> {
    bytes: &'a [u8],
    at: usize,
}

#[cfg(any(test, target_arch = "wasm32"))]
impl<'a> JournalReader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], &'static str> {
        let end = self.at.checked_add(len).ok_or("truncated")?;
        let slice = self.bytes.get(self.at..end).ok_or("truncated")?;
        self.at = end;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8, &'static str> {
        Ok(self.take(1)?[0])
    }

    fn flag(&mut self) -> Result<bool, &'static str> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err("record"),
        }
    }

    fn u32(&mut self) -> Result<u32, &'static str> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| "truncated")?,
        ))
    }

    fn u64(&mut self) -> Result<u64, &'static str> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| "truncated")?,
        ))
    }

    fn hash(&mut self) -> Result<[u8; 32], &'static str> {
        self.take(32)?.try_into().map_err(|_| "truncated")
    }

    fn text(&mut self) -> Result<String, &'static str> {
        let len = usize::try_from(self.u32()?).map_err(|_| "record")?;
        let bytes = self.take(len).map_err(|_| "record")?;
        Ok(std::str::from_utf8(bytes)
            .map_err(|_| "record")?
            .to_string())
    }

    /// A flag and a value. With the flag off, the value must be zero.
    fn opt(&mut self) -> Result<Option<u64>, &'static str> {
        let present = self.flag()?;
        let value = self.u64()?;
        match (present, value) {
            (true, value) => Ok(Some(value)),
            (false, 0) => Ok(None),
            (false, _) => Err("record"),
        }
    }

    fn done(&self) -> Result<(), &'static str> {
        (self.at == self.bytes.len()).then_some(()).ok_or("record")
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
fn decode_node(payload: &[u8]) -> Result<SurfaceNode, &'static str> {
    let mut reader = JournalReader {
        bytes: payload,
        at: 0,
    };
    let role = match reader.byte().map_err(|_| "record")? {
        1 => Role::System,
        2 => Role::User,
        3 => Role::Assistant,
        4 => Role::ToolResult,
        _ => return Err("record"),
    };
    let source = match reader.byte().map_err(|_| "record")? {
        1 => NodeSource::Head,
        2 => NodeSource::InHistory,
        3 => NodeSource::Person,
        4 => NodeSource::Snapshot,
        5 => NodeSource::Skill,
        6 => NodeSource::TurnMarker,
        7 => NodeSource::StepMarker,
        8 => NodeSource::CompactionCheckpoint,
        9 => NodeSource::Observation,
        _ => return Err("record"),
    };
    let text = reader.text()?;
    reader.done()?;
    Ok(SurfaceNode { role, text, source })
}

#[cfg(any(test, target_arch = "wasm32"))]
fn decode_step(payload: &[u8]) -> Result<Step, &'static str> {
    let mut reader = JournalReader {
        bytes: payload,
        at: 0,
    };
    let fail = |_| "record";
    let id = reader.u64().map_err(fail)?;
    let state = match reader.byte().map_err(fail)? {
        1 => StepState::Prepared,
        2 => StepState::NotStarted,
        3 => StepState::Denied,
        4 => StepState::Cancelled,
        5 => StepState::Dispatched,
        6 => StepState::SettlementUnknown,
        _ => return Err("record"),
    };
    let kind = match reader.byte().map_err(fail)? {
        1 => ProposalKind::Unspecified,
        2 => ProposalKind::Read,
        3 => ProposalKind::Edit,
        4 => ProposalKind::Run,
        5 => ProposalKind::Restore,
        6 => ProposalKind::Hosted,
        7 => ProposalKind::Child,
        8 => ProposalKind::Init,
        9 => ProposalKind::JournalAppend,
        _ => return Err("record"),
    };
    let resource = reader.text()?;
    let effect_id = reader.u64().map_err(fail)?;
    let has_result = reader.flag().map_err(fail)?;
    let old = reader.text()?;
    let new = reader.text()?;
    let count = reader.u32().map_err(fail)?;
    let mut argv = Vec::new();
    for _ in 0..count {
        argv.push(reader.text()?);
    }
    let parent_id = reader.opt().map_err(fail)?;
    let seat = reader.text()?;
    let seen_version = reader.opt().map_err(fail)?;
    let inbox = reader.text()?;
    reader.done()?;
    Ok(Step {
        id,
        state,
        kind,
        resource,
        grant: None,
        effect_id,
        has_result,
        old,
        new,
        argv,
        parent_id,
        seat,
        seen_version,
        inbox,
    })
}

#[cfg(any(test, target_arch = "wasm32"))]
fn decode_turn(payload: &[u8]) -> Result<Turn, &'static str> {
    let mut reader = JournalReader {
        bytes: payload,
        at: 0,
    };
    let id = reader.u64().map_err(|_| "record")?;
    let count = reader.u32().map_err(|_| "record")?;
    let mut steps = Vec::new();
    for _ in 0..count {
        steps.push(reader.u64().map_err(|_| "record")?);
    }
    reader.done()?;
    Ok(Turn { id, steps })
}

/// Decode format 1. The size, the format, and the whole hash chain are
/// checked before any record is read. Returns the journal, `prev_head`, and
/// this version's head.
#[cfg(any(test, target_arch = "wasm32"))]
fn decode_journal(bytes: &[u8]) -> Result<(Journal, [u8; 32], [u8; 32]), &'static str> {
    if bytes.len() > JOURNAL_CAP {
        return Err("too large");
    }
    let mut reader = JournalReader { bytes, at: 0 };
    let header = reader.take(JOURNAL_HEADER)?;
    if &header[..4] != JOURNAL_MAGIC {
        return Err("not a journal");
    }
    if header[4..6] != JOURNAL_FORMAT.to_le_bytes() {
        return Err("format version");
    }
    let mut fields = JournalReader {
        bytes: &header[6..],
        at: 0,
    };
    let epoch = fields.u64()?;
    let compaction_open = fields.byte()?;
    let backup_flag = fields.byte()?;
    let backup_epoch = fields.u64()?;
    let pending_flag = fields.byte()?;
    let prev_head = fields.hash()?;
    let count = fields.u32()?;
    let mut link = sha256(header);
    let mut records = Vec::new();
    for _ in 0..count {
        let tag = reader.byte()?;
        let len = usize::try_from(reader.u32()?).map_err(|_| "truncated")?;
        let payload = reader.take(len)?;
        let stored = reader.hash()?;
        link = journal_link(&link, tag, payload).ok_or("record")?;
        if stored != link {
            return Err("hash");
        }
        records.push((tag, payload));
    }
    if reader.hash()? != link {
        return Err("hash");
    }
    if reader.at != bytes.len() {
        return Err("trailing bytes");
    }
    let flag = |value: u8| match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err("record"),
    };
    let backup = flag(backup_flag)?;
    let pending = flag(pending_flag)?;
    if !backup && backup_epoch != 0 {
        return Err("record");
    }
    let mut journal = empty_journal();
    journal.epoch = epoch;
    journal.compaction_open = flag(compaction_open)?;
    let mut backup_nodes = Vec::new();
    let mut pending_nodes = Vec::new();
    let mut last_tag = 0;
    for (tag, payload) in records {
        if tag < last_tag {
            return Err("record");
        }
        last_tag = tag;
        match tag {
            1 => journal.events.push(decode_node(payload)?),
            2 => journal.markers.push(decode_node(payload)?),
            3 => journal.steps.push(decode_step(payload)?),
            4 => journal.turns.push(decode_turn(payload)?),
            5 if backup => backup_nodes.push(decode_node(payload)?),
            6 if pending => pending_nodes.push(decode_node(payload)?),
            _ => return Err("record"),
        }
    }
    journal.compact_backup = backup.then_some((backup_nodes, backup_epoch));
    journal.compact_pending = pending.then_some(pending_nodes);
    Ok((journal, prev_head, link))
}

/// The journal as it reads back from storage: every grant is cleared.
#[cfg(any(test, target_arch = "wasm32"))]
fn without_grants(journal: &Journal) -> Journal {
    let mut copy = journal.clone();
    for step in &mut copy.steps {
        step.grant = None;
    }
    copy
}

#[cfg(any(test, target_arch = "wasm32"))]
fn system_head(events: &[SurfaceNode]) -> Option<&str> {
    events
        .iter()
        .find(|event| event.role == Role::System)
        .map(|event| event.text.as_str())
}

#[cfg(any(test, target_arch = "wasm32"))]
fn visible_bytes(events: &[SurfaceNode]) -> usize {
    events.iter().map(|event| event.text.len()).sum()
}

#[cfg(any(test, target_arch = "wasm32"))]
fn bump_epoch(journal: &mut Journal) {
    journal.epoch = journal.epoch.saturating_add(1);
}

/// `in_history` appends a later system node. The incapable path rewrites node 0.
#[cfg(any(test, target_arch = "wasm32"))]
fn admit_system(journal: &mut Journal, text: &str, in_history: bool) {
    if text.is_empty() {
        return;
    }
    let has_system = journal
        .events
        .iter()
        .any(|event| event.role == Role::System);
    if !has_system {
        journal.events.insert(
            0,
            SurfaceNode {
                role: Role::System,
                text: text.to_string(),
                source: NodeSource::Head,
            },
        );
        bump_epoch(journal);
        return;
    }
    if in_history {
        journal.events.push(SurfaceNode {
            role: Role::System,
            text: text.to_string(),
            source: NodeSource::InHistory,
        });
        return;
    }
    if let Some(head) = journal
        .events
        .iter_mut()
        .find(|event| event.role == Role::System)
    {
        if head.text == text {
            return;
        }
        head.text = text.to_string();
        bump_epoch(journal);
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
fn admit_user(journal: &mut Journal, text: &str) {
    if text.is_empty() {
        return;
    }
    journal.events.push(SurfaceNode {
        role: Role::User,
        text: text.to_string(),
        source: NodeSource::Person,
    });
}

/// A list, a plan, or a goal the person can see. It is journal data. It does
/// not grant, and a host path is refused.
#[cfg(any(test, target_arch = "wasm32"))]
enum VisibleRecord {
    Todo,
    PlanEntered,
    PlanExitAsked,
    Goal,
    SpillPointer,
}

#[cfg(any(test, target_arch = "wasm32"))]
fn record_visible(journal: &mut Journal, kind: VisibleRecord, text: &str) -> bool {
    if text.is_empty() || host_path(text) {
        return false;
    }
    let Some(head) = journal.events.first() else {
        return false;
    };
    if head.role != Role::System || head.source != NodeSource::Head {
        return false;
    }
    let label = match kind {
        VisibleRecord::Todo => "todo",
        VisibleRecord::PlanEntered => "plan-entered",
        VisibleRecord::PlanExitAsked => "plan-exit-asked",
        VisibleRecord::Goal => "goal",
        VisibleRecord::SpillPointer => "spill",
    };
    let epoch = journal.epoch;
    let steps = journal.steps.len();
    journal.events.push(SurfaceNode {
        role: Role::User,
        text: format!("{label}\n{text}"),
        source: NodeSource::Person,
    });
    journal.epoch == epoch && journal.steps.len() == steps
}

/// Record a short pointer for a granted, dispatched step. The file must
/// already have been read. The pointer names that version, so a later edit
/// does not move it. The file text stays where it was read. A host path adds
/// nothing. The grant string is not the pointer.
#[cfg(any(test, target_arch = "wasm32"))]
fn spill_pointer(journal: &mut Journal, step_id: u64, object_resource: &str) -> bool {
    if object_resource.is_empty() || host_path(object_resource) {
        return false;
    }
    let Some(version) =
        current_observation(&journal.events, object_resource).map(|row| row.version)
    else {
        return false;
    };
    let Some(step) = journal.steps.iter().find(|step| step.id == step_id) else {
        return false;
    };
    if step.state != StepState::Dispatched
        || step.grant.as_deref().is_none_or(|grant| grant.is_empty())
        || step.has_result
        || !resource_covers(&step.resource, object_resource)
    {
        return false;
    }
    let pointer = format!("{object_resource}\n{version}");
    if !record_visible(journal, VisibleRecord::SpillPointer, &pointer) {
        return false;
    }
    record_tool_result(journal, step_id, &format!("spill\n{pointer}"))
}

/// The text named by the newest spill pointer for this file that still has
/// a read. A missing version is skipped. A later edit does not move an
/// older pointer.
#[cfg(any(test, target_arch = "wasm32"))]
fn text_at_spill(events: &[SurfaceNode], object_resource: &str) -> Option<String> {
    events.iter().rev().find_map(|node| {
        if node.source != NodeSource::Person {
            return None;
        }
        let mut parts = node.text.splitn(3, '\n');
        let label = parts.next()?;
        let resource = parts.next()?;
        let version = parts.next()?.parse::<u64>().ok()?;
        if label != "spill" || resource != object_resource {
            return None;
        }
        observed_text_at(events, object_resource, version)
    })
}

#[cfg(any(test, target_arch = "wasm32"))]
fn is_durable_visible(node: &SurfaceNode) -> bool {
    node.source == NodeSource::Person
        && matches!(
            node.text.split_once('\n').map(|(label, _)| label),
            Some("todo" | "plan-entered" | "plan-exit-asked" | "goal" | "spill" | "inbox")
        )
}

/// Append an assistant line. Empty text stays in the log. This does not
/// start a series.
#[cfg(any(test, target_arch = "wasm32"))]
fn admit_assistant(journal: &mut Journal, text: &str) {
    journal.events.push(SurfaceNode {
        role: Role::Assistant,
        text: text.to_string(),
        source: NodeSource::InHistory,
    });
}

/// Append one tool result. This does not start a series and does not run a tool.
#[cfg(any(test, target_arch = "wasm32"))]
fn admit_tool_result(journal: &mut Journal, text: &str) {
    journal.events.push(SurfaceNode {
        role: Role::ToolResult,
        text: text.to_string(),
        source: NodeSource::InHistory,
    });
}

/// Append volatile facts after the head. An empty workspace or time is refused.
/// A host path is refused. An empty open-file list adds no third node.
#[cfg(any(test, target_arch = "wasm32"))]
fn admit_snapshot(journal: &mut Journal, cwd: &str, time: &str, open_files: &str) -> bool {
    if cwd.is_empty()
        || time.is_empty()
        || host_path(cwd)
        || host_path(time)
        || host_path(open_files)
    {
        return false;
    }
    let Some(head) = journal.events.first() else {
        return false;
    };
    if head.role != Role::System || head.source != NodeSource::Head {
        return false;
    }
    let head_text = head.text.clone();
    let epoch = journal.epoch;
    for text in [cwd, time, open_files] {
        if text.is_empty() {
            continue;
        }
        journal.events.push(SurfaceNode {
            role: Role::User,
            text: text.to_string(),
            source: NodeSource::Snapshot,
        });
    }
    journal.epoch == epoch
        && journal.events.first().map(|node| node.text.clone()) == Some(head_text)
}

#[cfg(any(test, target_arch = "wasm32"))]
const SKILL_BUDGET: usize = 4_000;

/// Append one skill after the head. Empty, over-budget, or host-path text
/// leaves the journal unchanged.
#[cfg(any(test, target_arch = "wasm32"))]
fn admit_skill(journal: &mut Journal, text: &str) -> bool {
    if text.is_empty() || text.len() > SKILL_BUDGET || host_path(text) {
        return false;
    }
    let Some(head) = journal.events.first() else {
        return false;
    };
    if head.role != Role::System || head.source != NodeSource::Head {
        return false;
    }
    let head_text = head.text.clone();
    let epoch = journal.epoch;
    journal.events.push(SurfaceNode {
        role: Role::User,
        text: text.to_string(),
        source: NodeSource::Skill,
    });
    journal.epoch == epoch
        && journal.events.first().map(|node| node.text.clone()) == Some(head_text)
}

/// Open a compaction. The bytes and the series stay put until commit.
/// A refused summary leaves the journal unchanged. Skill nodes are kept
/// for the commit and are not part of the shrink check.
#[cfg(any(test, target_arch = "wasm32"))]
fn begin_compact(journal: &mut Journal, summary: &str) -> bool {
    if summary.is_empty()
        || host_path(summary)
        || journal.events.len() < 3
        || journal.compaction_open
    {
        return false;
    }
    let Some(head) = journal.events.first().cloned() else {
        return false;
    };
    if head.role != Role::System || head.source != NodeSource::Head {
        return false;
    }
    let replacement_head = [
        head,
        SurfaceNode {
            role: Role::User,
            text: summary.to_string(),
            source: NodeSource::CompactionCheckpoint,
        },
    ];
    let skills: Vec<SurfaceNode> = journal
        .events
        .iter()
        .filter(|node| node.source == NodeSource::Skill)
        .cloned()
        .collect();
    let observations: Vec<SurfaceNode> = journal
        .events
        .iter()
        .filter(|node| node.source == NodeSource::Observation)
        .cloned()
        .collect();
    let snapshots: Vec<SurfaceNode> = journal
        .events
        .iter()
        .filter(|node| node.source == NodeSource::Snapshot)
        .cloned()
        .collect();
    let visible: Vec<SurfaceNode> = journal
        .events
        .iter()
        .filter(|node| is_durable_visible(node))
        .cloned()
        .collect();
    let kept: Vec<SurfaceNode> = journal
        .events
        .iter()
        .filter(|node| {
            !matches!(
                node.source,
                NodeSource::Skill | NodeSource::Observation | NodeSource::Snapshot
            ) && !is_durable_visible(node)
        })
        .cloned()
        .collect();
    if visible_bytes(&replacement_head) >= visible_bytes(&kept) {
        return false;
    }
    let mut replacement = replacement_head.to_vec();
    replacement.extend(skills);
    replacement.extend(observations);
    replacement.extend(snapshots);
    replacement.extend(visible);
    journal.compact_backup = Some((journal.events.clone(), journal.epoch));
    journal.compact_pending = Some(replacement);
    journal.compaction_open = true;
    true
}

/// Apply an open compaction and start the next series.
#[cfg(any(test, target_arch = "wasm32"))]
fn commit_compact(journal: &mut Journal) -> bool {
    if !journal.compaction_open {
        return false;
    }
    let Some(replacement) = journal.compact_pending.take() else {
        return false;
    };
    journal.events = replacement;
    journal.compaction_open = false;
    journal.compact_backup = None;
    bump_epoch(journal);
    true
}

/// A crash while compaction is open restores the saved bytes and series.
#[cfg(any(test, target_arch = "wasm32"))]
fn note_crash_during_compact(journal: &mut Journal) -> bool {
    if !journal.compaction_open {
        return false;
    }
    journal.compact_pending = None;
    let Some((saved, saved_epoch)) = journal.compact_backup.take() else {
        journal.compaction_open = false;
        return false;
    };
    journal.events = saved;
    journal.epoch = saved_epoch;
    journal.compaction_open = false;
    true
}

/// Keep node 0. Replace the conversation tail with one summary only when that
/// tail shrinks. Skills, file reads, workspace snapshots, and visible goals
/// stay after the summary. A refused compaction leaves the journal unchanged.
#[cfg(any(test, target_arch = "wasm32"))]
fn compact(journal: &mut Journal, summary: &str) -> bool {
    begin_compact(journal, summary) && commit_compact(journal)
}

/// Shorten a tool result longer than 80 bytes to its first 40 characters
/// plus an ellipsis. The series and the system head stay put. This does not
/// call a model and does not write the summary.
#[cfg(any(test, target_arch = "wasm32"))]
fn prune_tool_results(journal: &mut Journal) -> usize {
    let mut pruned = 0;
    for node in &mut journal.events {
        if node.role != Role::ToolResult || node.text.len() <= 80 {
            continue;
        }
        let mut kept: String = node.text.chars().take(40).collect();
        kept.push('…');
        node.text = kept;
        pruned += 1;
    }
    pruned
}

/// Text a summary model would read after pruning: the system head, then the
/// lines compaction would replace. Skills, file reads, snapshots, and visible
/// goals are left out. The guest does not call a model.
#[cfg(any(test, target_arch = "wasm32"))]
fn shadowed_summary_input(journal: &Journal) -> Option<String> {
    let visible = derive(&journal.events);
    let head = visible.first()?;
    if head.role != Role::System || head.source != NodeSource::Head {
        return None;
    }
    let mut lines = vec![head.text.clone()];
    for node in visible.iter().skip(1) {
        if matches!(node.source, NodeSource::Skill | NodeSource::Snapshot)
            || is_durable_visible(node)
        {
            continue;
        }
        lines.push(node.text.clone());
    }
    Some(lines.join("\n"))
}

/// SHA-256 of the observed text. The empty digest is the known answer
/// `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
#[cfg(any(test, target_arch = "wasm32"))]
fn sha256(message: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state = [
        0x6a09e667_u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (message.len() as u64).saturating_mul(8);
    let mut data = message.to_vec();
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in data.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, bytes) in chunk.chunks_exact(4).enumerate() {
            let mut block = [0_u8; 4];
            block.copy_from_slice(bytes);
            words[index] = u32::from_be_bytes(block);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(s0.wrapping_add(majority));
        }
        for (slot, value) in [a, b, c, d, e, f, g, h].into_iter().enumerate() {
            state[slot] = state[slot].wrapping_add(value);
        }
    }
    let mut digest = [0_u8; 32];
    for (index, value) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&value.to_be_bytes());
    }
    digest
}

/// One recorded read. Older versions stay in the log. The last row for a
/// resource is the current one.
#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct Observation {
    resource: String,
    version: u64,
    text_hash: [u8; 32],
}

#[cfg(any(test, target_arch = "wasm32"))]
fn observation_record(resource: &str, version: u64, text: &str) -> String {
    let hash = sha256(text.as_bytes());
    let hex: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{version} {hex} {resource}\n{text}")
}

#[cfg(any(test, target_arch = "wasm32"))]
fn read_observation(node: &SurfaceNode) -> Option<Observation> {
    if node.source != NodeSource::Observation {
        return None;
    }
    let (head, text) = node.text.split_once('\n')?;
    let mut parts = head.splitn(3, ' ');
    let version = parts.next()?.parse().ok()?;
    let hex = parts.next()?;
    let resource = parts.next()?;
    if resource.is_empty() || hex.len() != 64 {
        return None;
    }
    let mut text_hash = [0_u8; 32];
    for index in 0..32 {
        text_hash[index] = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok()?;
    }
    if text_hash != sha256(text.as_bytes()) {
        return None;
    }
    Some(Observation {
        resource: resource.to_string(),
        version,
        text_hash,
    })
}

#[cfg(any(test, target_arch = "wasm32"))]
fn current_observation(events: &[SurfaceNode], resource: &str) -> Option<Observation> {
    events
        .iter()
        .rev()
        .find_map(|node| read_observation(node).filter(|row| row.resource == resource))
}

#[cfg(any(test, target_arch = "wasm32"))]
fn current_observed_text(events: &[SurfaceNode], resource: &str) -> Option<String> {
    events.iter().rev().find_map(|node| {
        let row = read_observation(node)?;
        if row.resource != resource {
            return None;
        }
        node.text.split_once('\n').map(|(_, text)| text.to_string())
    })
}

/// Every version this file has been shown, lowest number first. A later read
/// of the same version keeps that version's text. A blank name or a host path
/// returns nothing. This list is not a grant and does not change the file.
#[cfg(any(test, target_arch = "wasm32"))]
fn version_list(events: &[SurfaceNode], resource: &str) -> Vec<(u64, String)> {
    if resource.is_empty() || host_path(resource) {
        return Vec::new();
    }
    let mut rows: Vec<(u64, String)> = Vec::new();
    for node in events {
        let Some(row) = read_observation(node) else {
            continue;
        };
        if row.resource != resource {
            continue;
        }
        let Some((_, text)) = node.text.split_once('\n') else {
            continue;
        };
        if let Some(existing) = rows.iter_mut().find(|(version, _)| *version == row.version) {
            existing.1 = text.to_string();
        } else {
            rows.push((row.version, text.to_string()));
        }
    }
    rows.sort_by_key(|(version, _)| *version);
    rows
}

/// Append a read. An empty resource, a resource with whitespace, or a host
/// path adds nothing. A higher version is a new read. An older version is allowed only when the
/// text still matches that version, so a reread can make it current again
/// without replacing the page. This does not start a series and does not
/// read a file.
#[cfg(any(test, target_arch = "wasm32"))]
fn observe(journal: &mut Journal, resource: &str, version: u64, text: &str) -> bool {
    if resource.is_empty() || resource.chars().any(char::is_whitespace) || host_path(resource) {
        return false;
    }
    if let Some(row) = current_observation(&journal.events, resource) {
        if version <= row.version
            && observed_text_at(&journal.events, resource, version).as_deref() != Some(text)
        {
            return false;
        }
    }
    let epoch = journal.epoch;
    journal.events.push(SurfaceNode {
        role: Role::User,
        text: observation_record(resource, version, text),
        source: NodeSource::Observation,
    });
    journal.epoch == epoch
}

#[cfg(any(test, target_arch = "wasm32"))]
fn empty_journal() -> Journal {
    Journal {
        events: Vec::new(),
        epoch: 0,
        steps: Vec::new(),
        turns: Vec::new(),
        markers: Vec::new(),
        compaction_open: false,
        compact_backup: None,
        compact_pending: None,
    }
}

/// Record a turn. The returned id counts turns. It does not read the epoch.
#[cfg(any(test, target_arch = "wasm32"))]
fn open_turn(journal: &mut Journal) -> u64 {
    let id = u64::try_from(journal.turns.len())
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    journal.turns.push(Turn {
        id,
        steps: Vec::new(),
    });
    journal.markers.push(SurfaceNode {
        role: Role::User,
        text: String::new(),
        source: NodeSource::TurnMarker,
    });
    id
}

/// Record a prepared step on an open turn. An unknown turn adds nothing.
#[cfg(any(test, target_arch = "wasm32"))]
fn open_step(journal: &mut Journal, turn_id: u64) -> Option<u64> {
    if !journal.turns.iter().any(|turn| turn.id == turn_id) {
        return None;
    }
    let id = propose_step(journal);
    let turn = journal.turns.iter_mut().find(|turn| turn.id == turn_id)?;
    turn.steps.push(id);
    journal.markers.push(SurfaceNode {
        role: Role::User,
        text: id.to_string(),
        source: NodeSource::StepMarker,
    });
    Some(id)
}

/// An earlier edit still has no result, so a later write waits.
#[cfg(any(test, target_arch = "wasm32"))]
fn earlier_write_is_open(journal: &Journal, step_id: u64) -> bool {
    let Some(step) = journal.steps.iter().find(|step| step.id == step_id) else {
        return false;
    };
    if !is_write(step.kind) {
        return false;
    }
    journal.steps.iter().any(|earlier| {
        earlier.id < step.id
            && is_write(earlier.kind)
            && !earlier.has_result
            && matches!(
                earlier.state,
                StepState::Prepared | StepState::Dispatched | StepState::SettlementUnknown
            )
    })
}

/// Append one tool result for a step. A missing step, a second result, or a
/// later write that is still waiting leaves the journal unchanged. This does
/// not run a tool and does not start a series.
#[cfg(any(test, target_arch = "wasm32"))]
fn record_tool_result(journal: &mut Journal, step_id: u64, text: &str) -> bool {
    let Some(index) = journal.steps.iter().position(|step| step.id == step_id) else {
        return false;
    };
    if journal.steps[index].has_result || earlier_write_is_open(journal, step_id) {
        return false;
    }
    journal.steps[index].has_result = true;
    journal.events.push(SurfaceNode {
        role: Role::ToolResult,
        text: text.to_string(),
        source: NodeSource::InHistory,
    });
    true
}

#[cfg(any(test, target_arch = "wasm32"))]
fn propose_step(journal: &mut Journal) -> u64 {
    let id = u64::try_from(journal.steps.len())
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    journal.steps.push(Step {
        id,
        state: StepState::Prepared,
        kind: ProposalKind::Unspecified,
        resource: String::new(),
        grant: None,
        effect_id: id,
        has_result: false,
        old: String::new(),
        new: String::new(),
        argv: Vec::new(),
        parent_id: None,
        seat: String::new(),
        seen_version: None,
        inbox: String::new(),
    });
    id
}

#[cfg(any(test, target_arch = "wasm32"))]
fn propose_read(journal: &mut Journal, resource: &str) -> u64 {
    let id = propose_step(journal);
    let step = journal
        .steps
        .iter_mut()
        .find(|step| step.id == id)
        .expect("just pushed");
    step.kind = ProposalKind::Read;
    step.resource = resource.to_string();
    id
}

/// Record an edit proposal. An unread target, a stale version, empty old
/// text, or old text that does not occur once creates no step. This does not write.
#[cfg(any(test, target_arch = "wasm32"))]
fn propose_edit(
    journal: &mut Journal,
    resource: &str,
    old: &str,
    new: &str,
    seen: Option<u64>,
) -> Result<u64, &'static str> {
    let Some(row) = current_observation(&journal.events, resource) else {
        return Err("not observed");
    };
    if seen != Some(row.version) {
        return Err("stale");
    }
    if old.is_empty() {
        return Err("empty");
    }
    let Some(text) = current_observed_text(&journal.events, resource) else {
        return Err("not observed");
    };
    if text.matches(old).count() != 1 {
        return Err("not unique");
    }
    let id = propose_step(journal);
    let step = journal
        .steps
        .iter_mut()
        .find(|step| step.id == id)
        .expect("just pushed");
    step.kind = ProposalKind::Edit;
    step.resource = resource.to_string();
    step.old = old.to_string();
    step.new = new.to_string();
    step.seen_version = Some(row.version);
    Ok(id)
}

/// Whether Runtime may be asked to write. A missing grant or a version that
/// is no longer current refuses the ask. This does not write, and a grant
/// string in the journal is not a Runtime grant.
#[cfg(any(test, target_arch = "wasm32"))]
fn provider_write_may_be_asked(journal: &Journal, step_id: u64, seen_version: u64) -> bool {
    let Some(step) = journal.steps.iter().find(|step| step.id == step_id) else {
        return false;
    };
    if !is_write(step.kind)
        || matches!(
            step.state,
            StepState::Denied
                | StepState::Cancelled
                | StepState::NotStarted
                | StepState::SettlementUnknown
        )
        || earlier_write_is_open(journal, step_id)
    {
        return false;
    }
    let Some(grant) = step.grant.as_deref() else {
        return false;
    };
    if grant.is_empty() {
        return false;
    }
    let Some(row) = current_observation(&journal.events, &step.resource) else {
        return false;
    };
    row.version == seen_version
}

/// Record that the provider wrote one granted edit. The new text becomes
/// the current read. A write that can never apply is denied, so it does not
/// keep later writes waiting. This does not write a file on the host, and a
/// grant string in the journal is not a Runtime grant.
#[cfg(any(test, target_arch = "wasm32"))]
fn note_provider_wrote(journal: &mut Journal, step_id: u64) -> bool {
    let Some(index) = journal.steps.iter().position(|step| step.id == step_id) else {
        return false;
    };
    let step = &journal.steps[index];
    if step.kind != ProposalKind::Edit
        || step.state != StepState::Dispatched
        || step.grant.as_deref().is_none_or(|grant| grant.is_empty())
        || step.has_result
        || earlier_write_is_open(journal, step_id)
    {
        return false;
    }
    let seen = step.seen_version;
    let resource = step.resource.clone();
    let old = step.old.clone();
    let new = step.new.clone();
    let text = current_observed_text(&journal.events, &resource);
    let version_now = current_observation(&journal.events, &resource).map(|row| row.version);
    let refused = host_path(&resource)
        || host_path(&old)
        || host_path(&new)
        || old.is_empty()
        || seen.is_none()
        || version_now != seen
        || text
            .as_deref()
            .is_none_or(|text| text.matches(&old).count() != 1);
    if refused {
        journal.steps[index].state = StepState::Denied;
        return false;
    }
    let text = text.expect("the old text was checked");
    let new_text = text.replacen(&old, &new, 1);
    let version = seen.expect("the version was checked").saturating_add(1);
    let recorded = new_text.clone();
    if !observe(journal, &resource, version, &new_text) {
        journal.steps[index].state = StepState::Denied;
        return false;
    }
    journal.steps[index].has_result = true;
    journal.events.push(SurfaceNode {
        role: Role::ToolResult,
        text: recorded,
        source: NodeSource::InHistory,
    });
    true
}

/// Record a run proposal. The resource is a `localhost://` project. Arguments
/// stay data. A host path creates no step. This does not start a process.
#[cfg(any(test, target_arch = "wasm32"))]
fn propose_run(
    journal: &mut Journal,
    resource: &str,
    argv: &[String],
) -> Result<u64, &'static str> {
    if !resource.starts_with("localhost://")
        || resource.chars().any(char::is_whitespace)
        || host_path(resource)
        || argv.iter().any(|arg| host_path(arg))
    {
        return Err("host path");
    }
    let id = propose_step(journal);
    let step = journal
        .steps
        .iter_mut()
        .find(|step| step.id == id)
        .expect("just pushed");
    step.kind = ProposalKind::Run;
    step.resource = resource.to_string();
    step.argv = argv.to_vec();
    step.seat = "microvm".to_string();
    Ok(id)
}

#[cfg(any(test, target_arch = "wasm32"))]
const RUN_LOG_BUDGET: usize = 4_000;

/// Current text of each file under a project. A host path produces nothing.
#[cfg(any(test, target_arch = "wasm32"))]
fn observed_project_files(events: &[SurfaceNode], project: &str) -> Option<Vec<(String, String)>> {
    let prefix = format!("{project}/");
    let mut files: Vec<(String, String)> = Vec::new();
    for node in events {
        let Some(row) = read_observation(node) else {
            continue;
        };
        let Some(relative) = row.resource.strip_prefix(&prefix) else {
            continue;
        };
        if relative.is_empty() || relative.starts_with('/') || host_path(relative) {
            return None;
        }
        let text = node.text.split_once('\n')?.1.to_string();
        if let Some(existing) = files.iter_mut().find(|(path, _)| path == relative) {
            existing.1 = text;
        } else {
            files.push((relative.to_string(), text));
        }
    }
    if files.is_empty() {
        None
    } else {
        Some(files)
    }
}

/// The log may name a project digest only when it is the digest of the
/// files read so far. An edit replaces that digest. An unread tree cannot
/// be quoted.
#[cfg(any(test, target_arch = "wasm32"))]
fn quoted_digest_matches(events: &[SurfaceNode], project: &str, log: &str) -> bool {
    let Some(quoted) = log
        .lines()
        .find_map(|line| line.strip_prefix("project demo "))
    else {
        return true;
    };
    let Some(files) = observed_project_files(events, project) else {
        return false;
    };
    let refs: Vec<(&str, &str)> = files
        .iter()
        .map(|(path, text)| (path.as_str(), text.as_str()))
        .collect();
    let Some(digest) = project_tree_hash(&refs) else {
        return false;
    };
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    quoted == hex
}

/// A `project note` line must be the current text of `notes.txt`.
/// A host path in that line is refused. Logs without the line are unchanged.
#[cfg(any(test, target_arch = "wasm32"))]
fn quoted_note_matches(events: &[SurfaceNode], project: &str, log: &str) -> bool {
    let notes = format!("{project}/notes.txt");
    for line in log.lines() {
        let Some(text) = line.strip_prefix("project note ") else {
            continue;
        };
        if text.is_empty() || host_path(text) {
            return false;
        }
        let Some(current) = current_observed_text(events, &notes) else {
            return false;
        };
        if text != current {
            return false;
        }
    }
    true
}

/// A file list must name every file this project has been shown, and no
/// other name. A host path, an unread name, or a missing shown file is
/// refused. A log with no file lines is left alone.
#[cfg(any(test, target_arch = "wasm32"))]
fn quoted_files_match(events: &[SurfaceNode], project: &str, log: &str) -> bool {
    let mut listed: Vec<&str> = Vec::new();
    for line in log.lines() {
        let Some(name) = line.strip_prefix("project file ") else {
            continue;
        };
        if name.is_empty() || name.starts_with('/') || host_path(name) || name.contains('/') {
            return false;
        }
        if !listed.contains(&name) {
            listed.push(name);
        }
    }
    if listed.is_empty() {
        return true;
    }
    let Some(files) = observed_project_files(events, project) else {
        return false;
    };
    listed.len() == files.len()
        && files
            .iter()
            .all(|(path, _)| listed.contains(&path.as_str()))
}

/// A Rust test line has to agree with its exit code. Other logs do not
/// carry that phrase, so they are left to the exit code itself.
#[cfg(any(test, target_arch = "wasm32"))]
fn exit_agrees_with_log(exit_code: i32, log: &str) -> bool {
    let ok = log.contains("test result: ok");
    let failed = log.contains("test result: FAILED");
    match (ok, failed) {
        (true, false) => exit_code == 0,
        (false, true) => exit_code == 101,
        (true, true) => false,
        (false, false) => true,
    }
}

/// `init: hello` belongs to `true`. `init: command failed` belongs to `false`.
/// Any other program must not carry those lines.
#[cfg(any(test, target_arch = "wasm32"))]
fn log_matches_argv(argv: &[String], log: &str) -> bool {
    let args: Vec<&str> = argv.iter().map(String::as_str).collect();
    let hello = log.contains("init: hello from vm smoke test");
    let failed = log.contains("init: command failed");
    let files = log.contains("project file ");
    let note = log.contains("project note ");
    let demo = log.contains("project demo ");
    let test_line = log.contains("test result:");
    if !(hello || failed || files || note || demo || test_line) {
        return true;
    }
    match args.as_slice() {
        ["true"] => hello && !failed && !files && !note && !demo && !test_line,
        ["false"] => failed && !hello && !files && !note && !demo && !test_line,
        ["files"] => files && !hello && !failed && !note && !demo && !test_line,
        ["note"] => note && !hello && !failed && !files && !demo && !test_line,
        ["vm-smoke", "tests::project_was_edited"] => {
            (note || demo || test_line) && !hello && !failed && !files
        }
        ["vm-smoke", "tests::project_is_ready"] | ["vm-smoke", "tests::a_missing_piece_fails"] => {
            (demo || test_line) && !hello && !failed && !files && !note
        }
        _ => !hello && !failed && !files && !note && !demo && !test_line,
    }
}

/// The programs the small machine can run. `cargo` is not one of them.
#[cfg(any(test, target_arch = "wasm32"))]
fn argv_can_run(argv: &[String]) -> bool {
    let args: Vec<&str> = argv.iter().map(String::as_str).collect();
    matches!(
        args.as_slice(),
        ["files"]
            | ["note"]
            | ["true"]
            | ["false"]
            | ["vm-smoke", "tests::project_is_ready"]
            | ["vm-smoke", "tests::a_missing_piece_fails"]
            | ["vm-smoke", "tests::project_was_edited"]
    )
}

/// Record the provider's run result. The step must be a dispatched `microvm`
/// run with a grant. The log and the artifact must fit the budget and must
/// not be a host path. A test line that disagrees with the exit code is
/// refused. This does not start a process.
#[cfg(any(test, target_arch = "wasm32"))]
fn record_run_result(
    journal: &mut Journal,
    step_id: u64,
    exit_code: i32,
    log: &str,
    artifact: &str,
) -> bool {
    let Some(index) = journal.steps.iter().position(|step| step.id == step_id) else {
        return false;
    };
    let step = &journal.steps[index];
    if step.kind != ProposalKind::Run
        || step.seat != "microvm"
        || step.state != StepState::Dispatched
        || step.grant.as_deref().is_none_or(|grant| grant.is_empty())
        || step.has_result
        || log.len().saturating_add(artifact.len()) > RUN_LOG_BUDGET
        || host_path(log)
        || host_path(artifact)
        || !exit_agrees_with_log(exit_code, log)
        || !quoted_digest_matches(&journal.events, &step.resource, log)
        || !quoted_note_matches(&journal.events, &step.resource, log)
        || !quoted_files_match(&journal.events, &step.resource, log)
        || !argv_can_run(&step.argv)
        || !log_matches_argv(&step.argv, log)
    {
        return false;
    }
    let body = format!("exit {exit_code}\n{log}\n{artifact}");
    journal.steps[index].has_result = true;
    journal.events.push(SurfaceNode {
        role: Role::ToolResult,
        text: body,
        source: NodeSource::InHistory,
    });
    true
}

/// Digest of a project tree. Paths are sorted. A host path produces nothing.
/// This is not the capsule admission hash. Admission still hashes the entrypoint.
#[cfg(any(test, target_arch = "wasm32"))]
fn project_tree_hash(files: &[(&str, &str)]) -> Option<[u8; 32]> {
    if files.is_empty()
        || files.iter().any(|(path, _)| {
            path.is_empty()
                || path.starts_with('/')
                || host_path(path)
                || path.chars().any(char::is_whitespace)
        })
    {
        return None;
    }
    let mut ordered = files.to_vec();
    ordered.sort_by(|left, right| left.0.cmp(right.0));
    let mut body = String::new();
    for (path, text) in ordered {
        body.push_str(path);
        body.push('\n');
        body.push_str(text);
        body.push('\n');
    }
    Some(sha256(body.as_bytes()))
}

/// Propose the first write of an empty observed file under a project.
/// Unread, stale, or already-present text creates no step. This does not write.
#[cfg(any(test, target_arch = "wasm32"))]
fn propose_scaffold(
    journal: &mut Journal,
    project_id: u64,
    relative: &str,
    text: &str,
    seen: Option<u64>,
) -> Result<u64, &'static str> {
    let Some(project) = journal.steps.iter().find(|step| step.id == project_id) else {
        return Err("no project");
    };
    if project.kind != ProposalKind::Init {
        return Err("no project");
    }
    if relative.is_empty()
        || relative.starts_with('/')
        || host_path(relative)
        || relative.chars().any(char::is_whitespace)
    {
        return Err("host path");
    }
    let resource = format!("{}/{relative}", project.resource);
    let Some(row) = current_observation(&journal.events, &resource) else {
        return Err("not observed");
    };
    if seen != Some(row.version) {
        return Err("stale");
    }
    let Some(observed) = current_observed_text(&journal.events, &resource) else {
        return Err("not observed");
    };
    if !observed.is_empty() {
        return Err("not empty");
    }
    if text.is_empty() {
        return Err("empty");
    }
    let id = propose_step(journal);
    let step = journal
        .steps
        .iter_mut()
        .find(|step| step.id == id)
        .expect("just pushed");
    step.kind = ProposalKind::Edit;
    step.resource = resource;
    step.new = text.to_string();
    Ok(id)
}

#[cfg(any(test, target_arch = "wasm32"))]
fn host_path(text: &str) -> bool {
    text.starts_with('/') || text.contains('\\') || text.split('/').any(|part| part == "..")
}

#[cfg(any(test, target_arch = "wasm32"))]
fn is_write(kind: ProposalKind) -> bool {
    matches!(kind, ProposalKind::Edit | ProposalKind::Restore)
}

#[cfg(any(test, target_arch = "wasm32"))]
fn observed_text_at(events: &[SurfaceNode], resource: &str, version: u64) -> Option<String> {
    events.iter().rev().find_map(|node| {
        let row = read_observation(node)?;
        if row.resource != resource || row.version != version {
            return None;
        }
        node.text.split_once('\n').map(|(_, text)| text.to_string())
    })
}

/// Propose restoring an observed version. An unknown version, or a version
/// that is no longer current, creates no step. This does not apply the text.
#[cfg(any(test, target_arch = "wasm32"))]
fn propose_restore(
    journal: &mut Journal,
    resource: &str,
    version: u64,
) -> Result<u64, &'static str> {
    let Some(text) = observed_text_at(&journal.events, resource, version) else {
        return Err("unknown");
    };
    let Some(current) = current_observation(&journal.events, resource) else {
        return Err("unknown");
    };
    if current.version != version {
        return Err("stale");
    }
    let id = propose_step(journal);
    let step = journal
        .steps
        .iter_mut()
        .find(|step| step.id == id)
        .expect("just pushed");
    step.kind = ProposalKind::Restore;
    step.resource = resource.to_string();
    step.new = text;
    Ok(id)
}

/// Record a hosted model proposal. The resource names the model. There is
/// no secret field. This does not call a provider.
#[cfg(any(test, target_arch = "wasm32"))]
fn propose_hosted(journal: &mut Journal, resource: &str) -> Result<u64, &'static str> {
    if !resource.starts_with("localhost://")
        || resource.chars().any(char::is_whitespace)
        || host_path(resource)
    {
        return Err("host path");
    }
    let id = propose_step(journal);
    let step = journal
        .steps
        .iter_mut()
        .find(|step| step.id == id)
        .expect("just pushed");
    step.kind = ProposalKind::Hosted;
    step.resource = resource.to_string();
    Ok(id)
}

/// A child is a separate step. Its resource must sit under the parent's
/// resource. It does not copy the parent's grant.
#[cfg(any(test, target_arch = "wasm32"))]
fn propose_child(
    journal: &mut Journal,
    parent_id: u64,
    resource: &str,
) -> Result<u64, &'static str> {
    let Some(parent) = journal.steps.iter().find(|step| step.id == parent_id) else {
        return Err("no parent");
    };
    if parent.resource.is_empty() || !narrower_resource(&parent.resource, resource) {
        return Err("not a subset");
    }
    let id = propose_step(journal);
    let step = journal
        .steps
        .iter_mut()
        .find(|step| step.id == id)
        .expect("just pushed");
    step.kind = ProposalKind::Child;
    step.resource = resource.to_string();
    step.parent_id = Some(parent_id);
    step.grant = None;
    Ok(id)
}

/// Record a project proposal. The resource is a `localhost://` project name.
/// A host path or a slash inside the root or the name creates no step.
#[cfg(any(test, target_arch = "wasm32"))]
fn propose_init(journal: &mut Journal, root: &str, name: &str) -> Result<u64, &'static str> {
    if root.is_empty()
        || name.is_empty()
        || root
            .chars()
            .any(|ch| ch.is_whitespace() || ch == '/' || ch == '\\')
        || name
            .chars()
            .any(|ch| ch.is_whitespace() || ch == '/' || ch == '\\')
        || host_path(root)
        || host_path(name)
    {
        return Err("host path");
    }
    let resource = format!("localhost://Users/{root}/Projects/{name}");
    let id = propose_step(journal);
    let step = journal
        .steps
        .iter_mut()
        .find(|step| step.id == id)
        .expect("just pushed");
    step.kind = ProposalKind::Init;
    step.resource = resource;
    Ok(id)
}

#[cfg(any(test, target_arch = "wasm32"))]
fn resource_covers(root: &str, object: &str) -> bool {
    !root.is_empty()
        && (object == root
            || object
                .strip_prefix(root)
                .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1 && !host_path(object)))
}

#[cfg(any(test, target_arch = "wasm32"))]
fn narrower_resource(parent: &str, child: &str) -> bool {
    let Some(rest) = child.strip_prefix(parent) else {
        return false;
    };
    rest.starts_with('/') && rest.len() > 1 && !host_path(child)
}

/// Give a child its own grant. The parent's grant string is refused, and the
/// child stays prepared. This does not start a process.
#[cfg(any(test, target_arch = "wasm32"))]
fn authorize_child(journal: &mut Journal, child_id: u64, grant: Option<&str>) -> bool {
    let Some(child) = journal.steps.iter().find(|step| step.id == child_id) else {
        return false;
    };
    if child.kind != ProposalKind::Child {
        return false;
    }
    let parent_grant = child.parent_id.and_then(|parent_id| {
        journal
            .steps
            .iter()
            .find(|step| step.id == parent_id)
            .and_then(|step| step.grant.clone())
    });
    if grant.is_none() || grant == Some("") || parent_grant.as_deref() == grant {
        return false;
    }
    authorize(journal, child_id, grant)
}

/// A child host is a second journal. It keeps the system head and does not
/// copy the parent's log or the parent's grant. This is not a second loaded
/// component, and it does not start a process.
#[cfg(any(test, target_arch = "wasm32"))]
fn open_child_host(
    parent: &Journal,
    parent_id: u64,
    resource: &str,
) -> Result<Journal, &'static str> {
    let Some(parent_step) = parent.steps.iter().find(|step| step.id == parent_id) else {
        return Err("no parent");
    };
    if parent_step.resource.is_empty() || !narrower_resource(&parent_step.resource, resource) {
        return Err("not a subset");
    }
    let mut child = empty_journal();
    admit_system(&mut child, SYSTEM_HEAD, true);
    propose_run(&mut child, resource, &["true".to_string()])?;
    if child.steps.iter().any(|step| step.grant.is_some()) {
        return Err("inherited");
    }
    Ok(child)
}

/// Give the child host its own grant. The parent's grant is refused.
#[cfg(any(test, target_arch = "wasm32"))]
fn grant_child_host(child: &mut Journal, parent_grant: Option<&str>, grant: Option<&str>) -> bool {
    if grant.is_none() || grant == Some("") || grant == parent_grant {
        return false;
    }
    let Some(id) = child
        .steps
        .iter()
        .find(|step| {
            step.kind == ProposalKind::Run
                && step.grant.is_none()
                && step.state == StepState::Prepared
        })
        .map(|step| step.id)
    else {
        return false;
    };
    authorize(child, id, grant)
}

/// The parent stores one result line. The child's log is not copied in.
/// A grant string in the result is refused.
#[cfg(any(test, target_arch = "wasm32"))]
fn record_child_result(parent: &mut Journal, child: &Journal, result: &str) -> bool {
    if result.is_empty()
        || host_path(result)
        || child
            .events
            .first()
            .is_none_or(|node| node.text != SYSTEM_HEAD)
    {
        return false;
    }
    if parent.steps.iter().chain(child.steps.iter()).any(|step| {
        step.grant
            .as_deref()
            .is_some_and(|grant| !grant.is_empty() && result.contains(grant))
    }) {
        return false;
    }
    let epoch = parent.epoch;
    let before = parent.events.len();
    admit_tool_result(parent, result);
    parent.epoch == epoch && parent.events.len() == before + 1
}

/// A missing grant denies the step. A grant id is recorded and does not run it.
#[cfg(any(test, target_arch = "wasm32"))]
fn authorize(journal: &mut Journal, id: u64, grant: Option<&str>) -> bool {
    let Some(step) = journal.steps.iter_mut().find(|step| step.id == id) else {
        return false;
    };
    if step.state != StepState::Prepared {
        return false;
    }
    match grant {
        None | Some("") => {
            step.state = StepState::Denied;
            step.grant = None;
            false
        }
        Some(grant_id) => {
            step.grant = Some(grant_id.to_string());
            true
        }
    }
}

/// An inbox answer. Allow once, allow for the session, and standing all fail
/// closed when no grant id was sent. The guest does not mint one. Deny stores
/// no grant. A second answer does not replace the first, and it does not
/// authorize another step. A child cannot be answered with the parent's
/// grant. The answer name is kept in the log. The grant string is not.
#[cfg(any(test, target_arch = "wasm32"))]
enum InboxAnswer {
    AllowOnce,
    AllowSession,
    Standing,
    Deny,
}

#[cfg(any(test, target_arch = "wasm32"))]
fn apply_inbox(journal: &mut Journal, id: u64, answer: InboxAnswer, grant: Option<&str>) -> bool {
    let (name, grant) = match answer {
        InboxAnswer::Deny => ("deny", None),
        InboxAnswer::AllowOnce => ("allow-once", grant.filter(|grant| !grant.is_empty())),
        InboxAnswer::AllowSession => ("allow-session", grant.filter(|grant| !grant.is_empty())),
        InboxAnswer::Standing => ("standing", grant.filter(|grant| !grant.is_empty())),
    };
    let (kind, parent_id) = {
        let Some(step) = journal.steps.iter_mut().find(|step| step.id == id) else {
            return false;
        };
        if step.state != StepState::Prepared || !step.inbox.is_empty() || step.grant.is_some() {
            return false;
        }
        (step.kind, step.parent_id)
    };
    if kind == ProposalKind::Child {
        let parent_grant = parent_id.and_then(|parent_id| {
            journal
                .steps
                .iter()
                .find(|parent| parent.id == parent_id)
                .and_then(|parent| parent.grant.clone())
        });
        if parent_grant
            .as_deref()
            .is_some_and(|parent| grant == Some(parent))
        {
            return false;
        }
    }
    if let Some(step) = journal.steps.iter_mut().find(|step| step.id == id) {
        step.inbox = name.to_string();
    }
    if journal
        .events
        .first()
        .is_some_and(|node| node.role == Role::System && node.source == NodeSource::Head)
    {
        journal.events.push(SurfaceNode {
            role: Role::User,
            text: format!("inbox\n{name}"),
            source: NodeSource::Person,
        });
    }
    authorize(journal, id, grant)
}

#[cfg(any(test, target_arch = "wasm32"))]
fn step_state(journal: &Journal, id: u64) -> Option<StepState> {
    journal
        .steps
        .iter()
        .find(|step| step.id == id)
        .map(|step| step.state)
}

/// Dispatch once, from `Prepared`, and only when a grant id is recorded.
/// A prepared step with no grant becomes `denied`.
#[cfg(any(test, target_arch = "wasm32"))]
/// The same command on the same project is already in flight. A finished,
/// cancelled, or different command does not hold this one.
#[cfg(any(test, target_arch = "wasm32"))]
fn same_run_is_open(journal: &Journal, id: u64) -> bool {
    let Some(step) = journal.steps.iter().find(|step| step.id == id) else {
        return false;
    };
    if step.kind != ProposalKind::Run {
        return false;
    }
    journal.steps.iter().any(|earlier| {
        earlier.id < step.id
            && earlier.kind == ProposalKind::Run
            && earlier.resource == step.resource
            && earlier.argv == step.argv
            && !earlier.has_result
            && matches!(
                earlier.state,
                StepState::Dispatched | StepState::SettlementUnknown
            )
    })
}

#[cfg(any(test, target_arch = "wasm32"))]
fn dispatch(journal: &mut Journal, id: u64) -> bool {
    if earlier_write_is_open(journal, id) || same_run_is_open(journal, id) {
        return false;
    }
    let Some(step) = journal.steps.iter_mut().find(|step| step.id == id) else {
        return false;
    };
    if step.state != StepState::Prepared || step.grant.is_none() {
        if step.state == StepState::Prepared {
            step.state = StepState::Denied;
        }
        return false;
    }
    step.state = StepState::Dispatched;
    true
}

/// Cancel only from `Prepared`. A step that already left is not rewritten.
#[cfg(any(test, target_arch = "wasm32"))]
fn cancel(journal: &mut Journal, id: u64) -> bool {
    let Some(step) = journal.steps.iter_mut().find(|step| step.id == id) else {
        return false;
    };
    match step.state {
        StepState::Prepared => {
            step.state = StepState::Cancelled;
            true
        }
        StepState::Dispatched
        | StepState::SettlementUnknown
        | StepState::Denied
        | StepState::Cancelled
        | StepState::NotStarted => false,
    }
}

/// A crash before dispatch stays `not started`. A crash after dispatch is
/// `settlement_unknown`. A stored result is left in place. A denied or
/// cancelled step stays where it is.
#[cfg(any(test, target_arch = "wasm32"))]
fn note_crash(journal: &mut Journal, id: u64) -> bool {
    let Some(step) = journal.steps.iter_mut().find(|step| step.id == id) else {
        return false;
    };
    if step.has_result {
        return false;
    }
    match step.state {
        StepState::Prepared | StepState::NotStarted => {
            step.state = StepState::NotStarted;
            true
        }
        StepState::Dispatched | StepState::SettlementUnknown => {
            step.state = StepState::SettlementUnknown;
            true
        }
        StepState::Denied | StepState::Cancelled => false,
    }
}

/// An agent id or a task id: ASCII letters, digits and `-`, 1 to 64 bytes.
#[cfg(any(test, target_arch = "wasm32"))]
fn journal_id_ok(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// The one place a task journal lives. The guest names only `Users/self`.
/// The Runtime scopes that to the launching person.
#[cfg(any(test, target_arch = "wasm32"))]
const JOURNAL_ROOT: &str = "localhost://Users/self/.AppData/Agents/";

#[cfg(any(test, target_arch = "wasm32"))]
fn journal_resource(agent_id: &str, task_id: &str) -> Result<String, &'static str> {
    if !journal_id_ok(agent_id) || !journal_id_ok(task_id) {
        return Err("journal id");
    }
    Ok(format!("{JOURNAL_ROOT}{agent_id}/tasks/{task_id}/journal"))
}

/// The grant the Runtime gave this guest at launch, for one journal and one
/// action. It is held in memory only: the journal format has no field for it,
/// and `Debug` does not print it.
#[cfg(any(test, target_arch = "wasm32"))]
struct LaunchGrant(String);

#[cfg(any(test, target_arch = "wasm32"))]
impl LaunchGrant {
    fn new(id: &str) -> Option<Self> {
        (!id.is_empty()).then(|| Self(id.to_string()))
    }

    fn id(&self) -> &str {
        &self.0
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
impl core::fmt::Debug for LaunchGrant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LaunchGrant(..)")
    }
}

/// An append that was sent and has no result the guest can trust.
#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingAppend {
    step_id: u64,
    sent_head: [u8; 32],
}

/// What the guest knows about the stored journal. `revision` is the Runtime's
/// revision of the last version the guest saw, or none before the first.
/// `head` is that version's head, or zeros. `pending` is an append whose
/// result is not known. The Runtime computes revisions; the guest only
/// repeats them.
#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct JournalCursor {
    resource: String,
    revision: Option<String>,
    head: [u8; 32],
    pending: Option<PendingAppend>,
}

#[cfg(any(test, target_arch = "wasm32"))]
fn journal_cursor(agent_id: &str, task_id: &str) -> Result<JournalCursor, &'static str> {
    Ok(JournalCursor {
        resource: journal_resource(agent_id, task_id)?,
        revision: None,
        head: [0; 32],
        pending: None,
    })
}

/// A Bus failure as the guest sees it. The Runtime refuses `denied` and
/// `invalid` before storage. Any other failure leaves the result unknown.
#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BusFailure {
    Denied,
    Invalid,
    Other,
}

/// The guest's one effect call. In WebAssembly it is `providers.invoke`. A
/// call always carries a grant: there is no way to send one without.
#[cfg(any(test, target_arch = "wasm32"))]
trait ResourceBus {
    fn invoke(
        &mut self,
        resource: &str,
        operation: &str,
        body: &[u8],
        grant: &str,
    ) -> Result<Vec<u8>, BusFailure>;
}

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AppendOutcome {
    /// The Runtime stored this version. The cursor moved to it.
    Written,
    /// The stored version was not the one the guest saw. Nothing was written.
    /// The guest must read again; it does not retry.
    Conflict,
    /// The Runtime refused before storage. Nothing was written.
    Refused,
    /// No answer the guest can trust. Resume reads the head back.
    Unknown,
    /// No grant. Nothing was sent.
    Denied,
    /// An earlier append has no result yet. Nothing was sent.
    Held,
    /// Over the journal cap. Nothing was sent.
    TooLarge,
}

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResumeOutcome {
    /// No append is waiting for a result.
    Nothing,
    /// The stored head is the head the guest sent.
    Written,
    /// The stored head is the parent: the append did not land. Propose again.
    NotWritten,
    /// Anything else. A person decides; the guest does not append.
    Unknown,
    /// No read grant. Nothing was sent.
    Denied,
}

/// An append records a step. It waits while an earlier append has no result,
/// so a lost reply is never followed by a second write.
#[cfg(any(test, target_arch = "wasm32"))]
fn propose_journal_append(
    journal: &mut Journal,
    cursor: &JournalCursor,
) -> Result<u64, &'static str> {
    if !cursor.resource.starts_with(JOURNAL_ROOT) || host_path(&cursor.resource) {
        return Err("host path");
    }
    let open = journal.steps.iter().any(|step| {
        step.kind == ProposalKind::JournalAppend
            && !step.has_result
            && matches!(
                step.state,
                StepState::Prepared | StepState::Dispatched | StepState::SettlementUnknown
            )
    });
    if cursor.pending.is_some() || open {
        return Err("held");
    }
    let id = propose_step(journal);
    let step = journal
        .steps
        .iter_mut()
        .find(|step| step.id == id)
        .expect("just pushed");
    step.kind = ProposalKind::JournalAppend;
    step.resource = cursor.resource.clone();
    step.old = cursor.revision.clone().unwrap_or_default();
    Ok(id)
}

/// The write body the Runtime bridge reads: the whole encoding as `content`,
/// and `create_only` for the first version or `if_revision` after that.
#[cfg(any(test, target_arch = "wasm32"))]
fn journal_write_body(bytes: &[u8], revision: Option<&str>) -> Vec<u8> {
    let body = match revision {
        None => serde_json::json!({ "content": bytes, "create_only": true }),
        Some(revision) => serde_json::json!({ "content": bytes, "if_revision": revision }),
    };
    body.to_string().into_bytes()
}

/// A provider result: `status` ok with its `data`, or error with its `code`.
#[cfg(any(test, target_arch = "wasm32"))]
enum ProviderReply {
    Ok(serde_json::Value),
    Error(String),
}

#[cfg(any(test, target_arch = "wasm32"))]
fn provider_reply(body: &[u8]) -> Option<ProviderReply> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    match value.get("status")?.as_str()? {
        "ok" => Some(ProviderReply::Ok(
            value
                .get("data")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )),
        "error" => Some(ProviderReply::Error(
            value.get("code")?.as_str()?.to_string(),
        )),
        _ => None,
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
fn reply_revision(data: &serde_json::Value) -> Option<String> {
    data.get("revision")?
        .as_str()
        .filter(|revision| !revision.is_empty())
        .map(str::to_string)
}

/// Close a journal append with its outcome word. It does not enter the model view.
#[cfg(any(test, target_arch = "wasm32"))]
fn close_journal_append(journal: &mut Journal, step_id: u64, word: &str) {
    if let Some(step) = journal.steps.iter_mut().find(|step| step.id == step_id) {
        step.has_result = true;
        step.new = word.to_string();
    }
}

/// Write the whole journal as the next version, with the launch grant.
/// No grant, an open append, or a journal over the cap sends nothing. The
/// stored copy shows this step as dispatched with no result.
#[cfg(any(test, target_arch = "wasm32"))]
fn append_journal(
    bus: &mut impl ResourceBus,
    journal: &mut Journal,
    cursor: &mut JournalCursor,
    grant: Option<&LaunchGrant>,
) -> AppendOutcome {
    let Ok(id) = propose_journal_append(journal, cursor) else {
        return AppendOutcome::Held;
    };
    if !authorize(journal, id, grant.map(LaunchGrant::id)) {
        return AppendOutcome::Denied;
    }
    let Some(grant) = grant else {
        return AppendOutcome::Denied;
    };
    let mut sent = journal.clone();
    if !dispatch(&mut sent, id) {
        *journal = sent;
        return AppendOutcome::Denied;
    }
    let Some(bytes) = encode_journal(&sent, &cursor.head) else {
        cancel(journal, id);
        return AppendOutcome::TooLarge;
    };
    *journal = sent;
    let mut sent_head = [0; 32];
    sent_head.copy_from_slice(&bytes[bytes.len() - 32..]);
    cursor.pending = Some(PendingAppend {
        step_id: id,
        sent_head,
    });
    let body = journal_write_body(&bytes, cursor.revision.as_deref());
    let reply = bus.invoke(&cursor.resource, "write", &body, grant.id());
    let refused = |journal: &mut Journal, cursor: &mut JournalCursor, word: &str| {
        close_journal_append(journal, id, word);
        cursor.pending = None;
    };
    match reply.as_deref().map(provider_reply) {
        Err(BusFailure::Denied | BusFailure::Invalid) => {
            refused(journal, cursor, "refused");
            AppendOutcome::Refused
        }
        Ok(Some(ProviderReply::Error(code))) if code == "revision_conflict" => {
            refused(journal, cursor, "conflict");
            AppendOutcome::Conflict
        }
        Ok(Some(ProviderReply::Ok(data))) if reply_revision(&data).is_some() => {
            close_journal_append(journal, id, "written");
            cursor.revision = reply_revision(&data);
            cursor.head = sent_head;
            cursor.pending = None;
            AppendOutcome::Written
        }
        _ => {
            note_crash(journal, id);
            AppendOutcome::Unknown
        }
    }
}

/// Settle an append with no trusted result by reading the stored head. The
/// sent head means it landed. The parent head means it did not; the revision
/// check then stops the old write and a new one from both landing. Anything
/// else stays unknown.
#[cfg(any(test, target_arch = "wasm32"))]
fn resume_journal(
    bus: &mut impl ResourceBus,
    journal: &mut Journal,
    cursor: &mut JournalCursor,
    grant: Option<&LaunchGrant>,
) -> ResumeOutcome {
    let Some(pending) = cursor.pending.clone() else {
        return ResumeOutcome::Nothing;
    };
    let Some(grant) = grant else {
        return ResumeOutcome::Denied;
    };
    let reply = bus.invoke(&cursor.resource, "read", b"{}", grant.id());
    let Ok(Some(ProviderReply::Ok(data))) = reply.as_deref().map(provider_reply) else {
        return ResumeOutcome::Unknown;
    };
    let content = data
        .get("content")
        .cloned()
        .and_then(|content| serde_json::from_value::<Vec<u8>>(content).ok());
    let (Some(content), Some(revision)) = (content, reply_revision(&data)) else {
        return ResumeOutcome::Unknown;
    };
    let Ok((_, _, head)) = decode_journal(&content) else {
        return ResumeOutcome::Unknown;
    };
    let (outcome, word) = if head == pending.sent_head {
        (ResumeOutcome::Written, "written")
    } else if head == cursor.head && cursor.revision.is_some() {
        (ResumeOutcome::NotWritten, "not written")
    } else {
        return ResumeOutcome::Unknown;
    };
    close_journal_append(journal, pending.step_id, word);
    cursor.revision = Some(revision);
    cursor.head = head;
    cursor.pending = None;
    outcome
}

/// The Runtime has no way yet to hand this guest its launch grant. The WIT
/// world has no launch argument, and the guest does not import
/// `capabilities`. Until it does, the id is empty, there is no grant, and
/// nothing is sent.
#[cfg(target_arch = "wasm32")]
const LAUNCH_GRANT_ID: &str = "";

#[cfg(target_arch = "wasm32")]
fn launch_grant() -> Option<LaunchGrant> {
    LaunchGrant::new(LAUNCH_GRANT_ID)
}

#[cfg(target_arch = "wasm32")]
struct WasmBus;

#[cfg(target_arch = "wasm32")]
impl ResourceBus for WasmBus {
    fn invoke(
        &mut self,
        resource: &str,
        operation: &str,
        body: &[u8],
        grant: &str,
    ) -> Result<Vec<u8>, BusFailure> {
        use elastos::bus::types::{BusError, InvokeRequest};
        let request = InvokeRequest {
            resource: resource.to_string(),
            operation: operation.to_string(),
            body: body.to_vec(),
            grant: Some(grant.to_string()),
        };
        match elastos::bus::providers::invoke(&request) {
            Ok(response) => Ok(response.body),
            Err(BusError::Denied(_)) => Err(BusFailure::Denied),
            Err(BusError::Invalid(_)) => Err(BusFailure::Invalid),
            Err(_) => Err(BusFailure::Other),
        }
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
fn one_turn() -> Journal {
    let mut journal = empty_journal();
    admit_system(&mut journal, SYSTEM_HEAD, true);
    admit_user(&mut journal, "hello");
    admit_system(&mut journal, "Reply in one short paragraph.", true);
    journal
}

/// Turn two appends. The first system node is not rewritten.
#[cfg(any(test, target_arch = "wasm32"))]
fn two_turns() -> Journal {
    let mut journal = one_turn();
    admit_user(&mut journal, "second turn");
    admit_system(&mut journal, "Keep the first system line unchanged.", true);
    journal
}

#[cfg(target_arch = "wasm32")]
struct AgentHost;

#[cfg(target_arch = "wasm32")]
impl exports::elastos::bus::lifecycle::Guest for AgentHost {
    fn run() -> Result<(), elastos::bus::types::BusError> {
        let runtime = elastos::bus::runtime::info();
        if runtime.abi != EXPECTED_RUNTIME_ABI {
            return Err(elastos::bus::types::BusError::Invalid(format!(
                "agent-host requires {EXPECTED_RUNTIME_ABI}, received {}",
                runtime.abi
            )));
        }
        let _identity = elastos::bus::identity::context();
        let mut journal = two_turns();
        let visible = derive(&journal.events);
        let head = system_head(&visible)
            .filter(|text| text.as_bytes() == SYSTEM_HEAD.as_bytes())
            .map(|text| text.to_string());
        let Some(head) = head else {
            return Err(elastos::bus::types::BusError::Invalid(
                "system head changed during the second turn".to_string(),
            ));
        };
        if journal.epoch != 1 || visible.len() != 5 {
            return Err(elastos::bus::types::BusError::Invalid(
                "the second turn started a new series".to_string(),
            ));
        }
        admit_tool_result(&mut journal, &"x".repeat(200));
        admit_tool_result(&mut journal, "ok");
        let summary_input = shadowed_summary_input(&journal);
        let long_result_shortened = prune_tool_results(&mut journal) == 1
            && journal.epoch == 1
            && journal.events[0].text == head
            && journal.events.iter().any(|node| {
                node.role == Role::ToolResult
                    && node.text.ends_with('…')
                    && node.text.chars().count() == 41
            })
            && journal
                .events
                .iter()
                .any(|node| node.role == Role::ToolResult && node.text == "ok")
            && summary_input.as_deref().is_some_and(|text| {
                text.starts_with(SYSTEM_HEAD)
                    && text.contains(&"x".repeat(200))
                    && !text.contains(COMPACTION_SUMMARY)
            });
        let after_prune = shadowed_summary_input(&journal);
        if !long_result_shortened
            || after_prune.as_deref().is_none_or(|text| {
                !text.starts_with(SYSTEM_HEAD)
                    || !text.contains('…')
                    || text.contains(&"x".repeat(200))
                    || !text.contains("ok")
                    || text.contains(COMPACTION_SUMMARY)
            })
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a large tool result was not shortened before the summary".to_string(),
            ));
        }
        if compact(&mut journal, "/tmp")
            || compact(&mut journal, "localhost://Users/self/../secret")
            || journal.epoch != 1
            || !compact(&mut journal, COMPACTION_SUMMARY)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "compaction did not shrink the journal".to_string(),
            ));
        }
        let visible = derive(&journal.events);
        let head_kept = visible
            .first()
            .is_some_and(|node| node.text.as_bytes() == head.as_bytes());
        let summary_follows = visible.get(1).is_some_and(|node| {
            node.role == Role::User
                && node.source == NodeSource::CompactionCheckpoint
                && node.text == COMPACTION_SUMMARY
        });
        if !(head_kept && summary_follows && visible.len() == 2 && journal.epoch == 2) {
            return Err(elastos::bus::types::BusError::Invalid(
                "compaction shadowed the system head".to_string(),
            ));
        }
        if compact(&mut journal, COMPACTION_SUMMARY) {
            return Err(elastos::bus::types::BusError::Invalid(
                "a second compaction changed the series".to_string(),
            ));
        }
        let epoch = journal.epoch;
        let before_read = model_bytes(&journal.events);
        let read_id = propose_read(&mut journal, "localhost://Users/self/Documents/note.txt");
        if authorize(&mut journal, read_id, None)
            || step_state(&journal, read_id) != Some(StepState::Denied)
            || dispatch(&mut journal, read_id)
            || journal.epoch != epoch
            || model_bytes(&journal.events).as_ref() != before_read.as_ref()
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a read with no grant was executed".to_string(),
            ));
        }
        let held = propose_step(&mut journal);
        if !cancel(&mut journal, held)
            || step_state(&journal, held) != Some(StepState::Cancelled)
            || cancel(&mut journal, held)
            || dispatch(&mut journal, held)
            || note_crash(&mut journal, held)
            || journal.epoch != epoch
            || model_bytes(&journal.events).as_ref() != before_read.as_ref()
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a cancelled step was dispatched".to_string(),
            ));
        }
        let len_before_snap = journal.events.len();
        if !admit_snapshot(
            &mut journal,
            "localhost://Users/self",
            "2026-10-12T13:44:00Z",
            "localhost://Users/self/Documents/note.txt",
        ) || journal.epoch != epoch
            || journal.events.first().map(|node| node.text.as_str()) != Some(head.as_str())
            || journal.events.first().map(|node| node.source) != Some(NodeSource::Head)
            || journal.events.len() != len_before_snap + 3
            || journal.events[len_before_snap..]
                .iter()
                .any(|node| node.role != Role::User || node.source != NodeSource::Snapshot)
            || admit_snapshot(&mut journal, "", "2026-10-12T13:44:00Z", "note")
            || admit_snapshot(
                &mut journal,
                "/tmp",
                "2026-10-12T13:44:00Z",
                "localhost://Users/self/Documents/note.txt",
            )
            || admit_snapshot(
                &mut journal,
                "localhost://Users/self",
                "2026-10-12T13:44:00Z",
                "/tmp/secret",
            )
            || journal.events.len() != len_before_snap + 3
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a snapshot rewrote the head".to_string(),
            ));
        }
        let saved = checkpoint(&journal).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid("checkpoint could not be recorded".to_string())
        })?;
        let pending = propose_step(&mut journal);
        if !cancel(&mut journal, pending)
            || dispatch(&mut journal, pending)
            || journal.epoch != epoch
            || model_bytes(&journal.events).as_ref() != Some(&saved)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "cancel after a checkpoint dispatched".to_string(),
            ));
        }
        let prepared = propose_step(&mut journal);
        let before_crash = checkpoint(&journal).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid("checkpoint could not be recorded".to_string())
        })?;
        if !note_crash(&mut journal, prepared)
            || step_state(&journal, prepared) != Some(StepState::NotStarted)
            || dispatch(&mut journal, prepared)
            || model_bytes(&journal.events).as_ref() != Some(&before_crash)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a crash before dispatch was retried".to_string(),
            ));
        }
        let sent = propose_step(&mut journal);
        let before_send = checkpoint(&journal).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid("checkpoint could not be recorded".to_string())
        })?;
        if !authorize(&mut journal, sent, Some("fixture-grant"))
            || !dispatch(&mut journal, sent)
            || cancel(&mut journal, sent)
            || step_state(&journal, sent) != Some(StepState::Dispatched)
            || !note_crash(&mut journal, sent)
            || step_state(&journal, sent) != Some(StepState::SettlementUnknown)
            || dispatch(&mut journal, sent)
            || model_bytes(&journal.events).as_ref() != Some(&before_send)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "settlement_unknown was retried".to_string(),
            ));
        }
        let len_before_skill = journal.events.len();
        let skill = "Prefer the Runtime grant.";
        if !admit_skill(&mut journal, skill)
            || journal.epoch != epoch
            || journal.events.first().map(|node| node.text.as_str()) != Some(head.as_str())
            || journal.events.len() != len_before_skill + 1
            || journal.events.last().map(|node| node.source) != Some(NodeSource::Skill)
            || admit_skill(&mut journal, "")
            || admit_skill(&mut journal, &"x".repeat(4_001))
            || admit_skill(&mut journal, "/tmp")
            || journal.events.len() != len_before_skill + 1
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a skill rewrote the head".to_string(),
            ));
        }
        let mut folded = journal.clone();
        let folded_epoch = folded.epoch;
        if compact(&mut folded, COMPACTION_SUMMARY)
            || folded.epoch != folded_epoch
            || folded.events.get(1).map(|node| node.role) != Some(Role::User)
            || folded.events.get(1).map(|node| node.source)
                != Some(NodeSource::CompactionCheckpoint)
            || folded.events.first().map(|node| node.text.as_str()) != Some(head.as_str())
            || !folded
                .events
                .iter()
                .any(|node| node.source == NodeSource::Skill && node.text == skill)
            || !folded.events.iter().any(|node| {
                node.source == NodeSource::Snapshot && node.text == "localhost://Users/self"
            })
            || !folded.events.iter().any(|node| {
                node.source == NodeSource::Snapshot && node.text == "2026-10-12T13:44:00Z"
            })
            || !folded.events.iter().any(|node| {
                node.source == NodeSource::Snapshot
                    && node.text == "localhost://Users/self/Documents/note.txt"
            })
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a workspace snapshot was summarised".to_string(),
            ));
        }
        let visible = derive(&journal.events);
        if journal.epoch != 2 || system_head(&visible) != Some(head.as_str()) {
            return Err(elastos::bus::types::BusError::Invalid(
                "a crash started a new series".to_string(),
            ));
        }
        let recorded = model_bytes(&visible).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid(
                "journal bytes could not be recorded".to_string(),
            )
        })?;
        let restored = replay(&recorded).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid("recorded journal did not replay".to_string())
        })?;
        if model_bytes(&restored).as_ref() != Some(&recorded)
            || restored.first().map(|node| node.text.as_str()) != Some(head.as_str())
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "replay changed the model bytes".to_string(),
            ));
        }
        let epoch_before_turn = journal.epoch;
        let turn_id = open_turn(&mut journal);
        if turn_id == epoch_before_turn
            || journal.epoch != epoch_before_turn
            || journal.turns.len() != 1
            || journal.turns[0].id != turn_id
            || !journal.turns[0].steps.is_empty()
            || model_bytes(&journal.events).as_ref() != Some(&recorded)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "opening a turn changed the series".to_string(),
            ));
        }
        let first_step = open_step(&mut journal, turn_id);
        let second_step = open_step(&mut journal, turn_id);
        let missing_turn = open_step(&mut journal, turn_id.saturating_add(1));
        let (Some(first_step), Some(second_step)) = (first_step, second_step) else {
            return Err(elastos::bus::types::BusError::Invalid(
                "a step opened without a turn".to_string(),
            ));
        };
        let mut mixed = journal.events.clone();
        mixed.extend(journal.markers.clone());
        let view = derive(&mixed);
        let marker_bytes = model_bytes(&journal.markers).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid("marker bytes could not be recorded".to_string())
        })?;
        let restored_markers = replay(&marker_bytes).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid("marker bytes did not replay".to_string())
        })?;
        if missing_turn.is_some()
            || first_step == second_step
            || journal.epoch != epoch_before_turn
            || journal.turns[0].steps != [first_step, second_step]
            || step_state(&journal, first_step) != Some(StepState::Prepared)
            || step_state(&journal, second_step) != Some(StepState::Prepared)
            || model_bytes(&journal.events).as_ref() != Some(&recorded)
            || view.len() != journal.events.len()
            || view
                .iter()
                .any(|node| matches!(node.source, NodeSource::TurnMarker | NodeSource::StepMarker))
            || !derive(&journal.markers).is_empty()
            || restored_markers != journal.markers
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a turn marker entered the model view".to_string(),
            ));
        }
        let epoch_before_roles = journal.epoch;
        let head_before_roles = journal.events.first().map(|node| node.text.clone());
        admit_assistant(&mut journal, "");
        admit_assistant(&mut journal, "The head stays.");
        admit_tool_result(&mut journal, "The result is recorded.");
        let role_bytes = model_bytes(&journal.events).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid("role bytes could not be recorded".to_string())
        })?;
        let restored_roles = replay(&role_bytes).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid("role bytes did not replay".to_string())
        })?;
        let assistants: Vec<&str> = restored_roles
            .iter()
            .filter(|node| node.role == Role::Assistant)
            .map(|node| node.text.as_str())
            .collect();
        let tool = restored_roles
            .iter()
            .find(|node| node.role == Role::ToolResult);
        let view = derive(&journal.events);
        let spoken: Vec<&str> = view
            .iter()
            .filter(|node| node.role == Role::Assistant)
            .map(|node| node.text.as_str())
            .collect();
        if journal.epoch != epoch_before_roles
            || journal.events.first().map(|node| node.text.as_str()) != head_before_roles.as_deref()
            || restored_roles != journal.events
            || assistants != ["", "The head stays."]
            || tool.is_none_or(|node| node.text != "The result is recorded.")
            || spoken != ["The head stays."]
            || !view.iter().any(|node| node.role == Role::ToolResult)
            || view
                .iter()
                .any(|node| node.role == Role::Assistant && node.text.is_empty())
            || !role_bytes.contains(&role_tag(Role::Assistant))
            || !role_bytes.contains(&role_tag(Role::ToolResult))
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "an empty assistant line entered the model view".to_string(),
            ));
        }
        let waiting = second_step;
        if !record_tool_result(&mut journal, first_step, "The step result is recorded.")
            || record_tool_result(&mut journal, first_step, "a second result")
            || record_tool_result(&mut journal, 0, "a missing step")
            || journal
                .steps
                .iter()
                .find(|step| step.id == waiting)
                .is_none_or(|step| step.has_result)
            || journal.epoch != epoch_before_roles
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a step with no result left the log".to_string(),
            ));
        }
        let result_bytes = model_bytes(&journal.events).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid(
                "tool result bytes could not be recorded".to_string(),
            )
        })?;
        let restored_results = replay(&result_bytes).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid("tool result bytes did not replay".to_string())
        })?;
        let result_view = derive(&journal.events);
        let mut mixed = journal.events.clone();
        mixed.extend(journal.markers.clone());
        if restored_results != journal.events
            || !result_view.iter().any(|node| {
                node.role == Role::ToolResult && node.text == "The step result is recorded."
            })
            || derive(&mixed)
                .iter()
                .any(|node| matches!(node.source, NodeSource::TurnMarker | NodeSource::StepMarker))
            || !journal.markers.iter().any(|node| {
                node.source == NodeSource::StepMarker && node.text == waiting.to_string()
            })
            || replay(&model_bytes(&journal.markers).unwrap_or_default()).as_ref()
                != Some(&journal.markers)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a step with no result entered the model view".to_string(),
            ));
        }
        let mut open = two_turns();
        let saved_events = open.events.clone();
        let saved_epoch = open.epoch;
        if !begin_compact(&mut open, COMPACTION_SUMMARY)
            || !open.compaction_open
            || open.events != saved_events
            || open.epoch != saved_epoch
            || !note_crash_during_compact(&mut open)
            || open.compaction_open
            || open.compact_backup.is_some()
            || open.compact_pending.is_some()
            || open.events != saved_events
            || open.epoch != saved_epoch
            || note_crash_during_compact(&mut open)
            || commit_compact(&mut open)
            || !begin_compact(&mut open, COMPACTION_SUMMARY)
            || !commit_compact(&mut open)
            || open.compaction_open
            || open.epoch != saved_epoch + 1
            || open.events.get(1).map(|node| node.source) != Some(NodeSource::CompactionCheckpoint)
            || commit_compact(&mut open)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a crash during compaction kept the summary".to_string(),
            ));
        }
        let resource = "localhost://Users/self/Documents/note.txt";
        let mut seen = empty_journal();
        if !observe(&mut seen, resource, 1, "one line")
            || observe(&mut seen, "", 1, "one line")
            || observe(
                &mut seen,
                "localhost://Users/self/Documents/a note.txt",
                1,
                "one line",
            )
            || seen.epoch != 0
            || seen.events.len() != 1
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "an observation rewrote the series".to_string(),
            ));
        }
        let seen_bytes = model_bytes(&seen.events).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid(
                "observation bytes could not be recorded".to_string(),
            )
        })?;
        let restored_seen = replay(&seen_bytes).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid("observation bytes did not replay".to_string())
        })?;
        if !observe(&mut seen, resource, 2, "two lines")
            || seen.events.len() != 2
            || current_observation(&restored_seen, resource)
                .is_none_or(|row| row.version != 1 || row.text_hash != sha256(b"one line"))
            || current_observation(&seen.events, resource).is_none_or(|row| row.version != 2)
            || !derive(&seen.events).is_empty()
            || replay(&model_bytes(&seen.events).unwrap_or_default()).as_ref() != Some(&seen.events)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "replay lost the observation".to_string(),
            ));
        }
        let before_edit = seen.events.clone();
        let epoch_before_edit = seen.epoch;
        if propose_edit(
            &mut seen,
            "localhost://Users/self/Documents/other.txt",
            "two",
            "three",
            Some(2),
        )
        .is_ok()
            || propose_edit(&mut seen, resource, "two", "three", Some(1)).is_ok()
            || propose_edit(&mut seen, resource, "two", "three", None).is_ok()
            || propose_edit(&mut seen, resource, "", "three", Some(2)).is_ok()
            || !seen.steps.is_empty()
            || seen.events != before_edit
            || seen.epoch != epoch_before_edit
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "an unread edit created a step".to_string(),
            ));
        }
        let edit = propose_edit(&mut seen, resource, "two", "three", Some(2)).map_err(|_| {
            elastos::bus::types::BusError::Invalid("a current edit was refused".to_string())
        })?;
        let step = seen
            .steps
            .iter()
            .find(|step| step.id == edit)
            .ok_or_else(|| {
                elastos::bus::types::BusError::Invalid("the edit step was not recorded".to_string())
            })?;
        if seen.steps.len() != 1
            || step.state != StepState::Prepared
            || step.kind != ProposalKind::Edit
            || step.resource != resource
            || step.old != "two"
            || step.new != "three"
            || step.has_result
            || seen.events != before_edit
            || seen.epoch != epoch_before_edit
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "an edit proposal wrote the resource".to_string(),
            ));
        }
        if !observe(&mut seen, resource, 3, "alpha alpha beta") {
            return Err(elastos::bus::types::BusError::Invalid(
                "a later observation was refused".to_string(),
            ));
        }
        let steps_before = seen.steps.len();
        let events_before = seen.events.clone();
        if propose_edit(&mut seen, resource, "alpha", "one", Some(3)).is_ok()
            || propose_edit(&mut seen, resource, "gamma", "one", Some(3)).is_ok()
            || seen.steps.len() != steps_before
            || seen.events != events_before
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "an edit whose old text was not unique created a step".to_string(),
            ));
        }
        let unique = propose_edit(&mut seen, resource, "beta", "one", Some(3)).map_err(|_| {
            elastos::bus::types::BusError::Invalid("a unique edit was refused".to_string())
        })?;
        let replayed = replay(&model_bytes(&seen.events).unwrap_or_default()).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid("observation bytes did not replay".to_string())
        })?;
        if seen.steps.len() != steps_before + 1
            || seen.events != events_before
            || step_state(&seen, unique) != Some(StepState::Prepared)
            || read_observation(replayed.first().unwrap_or(&seen.events[0]))
                .is_none_or(|row| row.version != 1)
            || current_observation(&replayed, resource).is_none_or(|row| row.version != 3)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "replay lost an older observation".to_string(),
            ));
        }
        let mut writes = empty_journal();
        let file = "localhost://Users/self/Documents/note.txt";
        if !observe(&mut writes, file, 1, "alpha beta") {
            return Err(elastos::bus::types::BusError::Invalid(
                "the write target was not observed".to_string(),
            ));
        }
        let first = propose_edit(&mut writes, file, "alpha", "one", Some(1)).map_err(|_| {
            elastos::bus::types::BusError::Invalid("the first write was refused".to_string())
        })?;
        let second = propose_edit(&mut writes, file, "beta", "two", Some(1)).map_err(|_| {
            elastos::bus::types::BusError::Invalid("the second write was refused".to_string())
        })?;
        let first_effect = writes
            .steps
            .iter()
            .find(|step| step.id == first)
            .map(|step| step.effect_id);
        let second_effect = writes
            .steps
            .iter()
            .find(|step| step.id == second)
            .map(|step| step.effect_id);
        let events_before = writes.events.clone();
        if first_effect != Some(first)
            || second_effect != Some(second)
            || first_effect == second_effect
            || dispatch(&mut writes, second)
            || step_state(&writes, second) != Some(StepState::Prepared)
            || !authorize(&mut writes, second, Some("fixture-grant"))
            || dispatch(&mut writes, second)
            || step_state(&writes, second) != Some(StepState::Prepared)
            || record_tool_result(&mut writes, second, "beta replaced")
            || writes.events != events_before
            || !record_tool_result(&mut writes, first, "alpha replaced")
            || !dispatch(&mut writes, second)
            || step_state(&writes, second) != Some(StepState::Dispatched)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a second write ran before the first result".to_string(),
            ));
        }
        let asked_events = writes.events.clone();
        let asked_text = current_observed_text(&writes.events, file);
        if provider_write_may_be_asked(&writes, first, 1)
            || provider_write_may_be_asked(&writes, second, 2)
            || !provider_write_may_be_asked(&writes, second, 1)
            || writes.events != asked_events
            || current_observed_text(&writes.events, file) != asked_text
            || writes
                .steps
                .iter()
                .find(|step| step.id == second)
                .is_none_or(|step| step.has_result)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a provider write changed the journal".to_string(),
            ));
        }
        let project = "localhost://Users/self/Projects/demo";
        let mut runs = empty_journal();
        let bytes_before = checkpoint(&runs).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid("the run checkpoint was missing".to_string())
        })?;
        if propose_run(&mut runs, "/tmp/demo", &[]).is_ok()
            || propose_run(&mut runs, project, &["/bin/sh".to_string()]).is_ok()
            || !runs.steps.is_empty()
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a host path became a run".to_string(),
            ));
        }
        let run = propose_run(
            &mut runs,
            project,
            &["cargo".to_string(), "test".to_string()],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("a project run was refused".to_string())
        })?;
        let held = checkpoint(&runs).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid("the run checkpoint was missing".to_string())
        })?;
        let recorded_argv = runs
            .steps
            .iter()
            .find(|step| step.id == run)
            .map(|step| step.argv.clone());
        if recorded_argv != Some(vec!["cargo".to_string(), "test".to_string()])
            || runs
                .steps
                .iter()
                .find(|step| step.id == run)
                .is_none_or(|step| step.kind != ProposalKind::Run || step.resource != project)
            || step_state(&runs, run) != Some(StepState::Prepared)
            || held != bytes_before
            || !cancel(&mut runs, run)
            || dispatch(&mut runs, run)
            || step_state(&runs, run) != Some(StepState::Cancelled)
            || checkpoint(&runs).as_ref() != Some(&held)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a cancelled run started".to_string(),
            ));
        }
        let mut restored = empty_journal();
        let file = "localhost://Users/self/Documents/note.txt";
        if propose_restore(&mut restored, file, 1).is_ok() || !restored.steps.is_empty() {
            return Err(elastos::bus::types::BusError::Invalid(
                "an unknown restore created a step".to_string(),
            ));
        }
        if !observe(&mut restored, file, 1, "one") || !observe(&mut restored, file, 2, "two") {
            return Err(elastos::bus::types::BusError::Invalid(
                "the restore target was not observed".to_string(),
            ));
        }
        let before_restore = restored.events.clone();
        if propose_restore(&mut restored, file, 9).is_ok()
            || propose_restore(&mut restored, file, 1).is_ok()
            || !restored.steps.is_empty()
            || restored.events != before_restore
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a stale restore created a step".to_string(),
            ));
        }
        let restore = propose_restore(&mut restored, file, 2).map_err(|_| {
            elastos::bus::types::BusError::Invalid("a current restore was refused".to_string())
        })?;
        let replayed =
            replay(&model_bytes(&restored.events).unwrap_or_default()).ok_or_else(|| {
                elastos::bus::types::BusError::Invalid("restore bytes did not replay".to_string())
            })?;
        if restored.events != before_restore
            || current_observed_text(&restored.events, file).as_deref() != Some("two")
            || restored
                .steps
                .iter()
                .find(|step| step.id == restore)
                .is_none_or(|step| {
                    step.kind != ProposalKind::Restore || step.new != "two" || step.has_result
                })
            || read_observation(replayed.first().unwrap_or(&restored.events[0]))
                .is_none_or(|row| row.version != 1)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a restore applied the old text".to_string(),
            ));
        }
        let mut hosted = empty_journal();
        let model = "localhost://Models/hosted";
        let hosted_id = propose_hosted(&mut hosted, model).map_err(|_| {
            elastos::bus::types::BusError::Invalid("a hosted proposal was refused".to_string())
        })?;
        let hosted_events = hosted.events.clone();
        if hosted
            .steps
            .iter()
            .find(|step| step.id == hosted_id)
            .is_none_or(|step| step.kind != ProposalKind::Hosted || step.grant.is_some())
            || authorize(&mut hosted, hosted_id, None)
            || step_state(&hosted, hosted_id) != Some(StepState::Denied)
            || dispatch(&mut hosted, hosted_id)
            || hosted.events != hosted_events
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a hosted proposal carried a secret or ran without a grant".to_string(),
            ));
        }
        let mut family = empty_journal();
        let parent = propose_run(
            &mut family,
            "localhost://Users/self/Projects/demo",
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("the parent run was refused".to_string())
        })?;
        if !authorize(&mut family, parent, Some("fixture-grant"))
            || propose_child(&mut family, parent, "localhost://Users/self/Projects/other").is_ok()
            || family.steps.len() != 1
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a child left the parent resource".to_string(),
            ));
        }
        let child = propose_child(
            &mut family,
            parent,
            "localhost://Users/self/Projects/demo/src",
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("a narrower child was refused".to_string())
        })?;
        let child_step = family
            .steps
            .iter()
            .find(|step| step.id == child)
            .ok_or_else(|| {
                elastos::bus::types::BusError::Invalid(
                    "the child step was not recorded".to_string(),
                )
            })?;
        if child_step.kind != ProposalKind::Child
            || child_step.grant.is_some()
            || child_step.parent_id != Some(parent)
            || child_step.effect_id == parent
            || authorize_child(&mut family, child, Some("fixture-grant"))
            || family
                .steps
                .iter()
                .find(|step| step.id == child)
                .is_none_or(|step| step.grant.is_some() || step.state != StepState::Prepared)
            || !authorize_child(&mut family, child, Some("child-grant"))
            || family
                .steps
                .iter()
                .find(|step| step.id == child)
                .is_none_or(|step| step.grant.as_deref() != Some("child-grant"))
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a child inherited the parent grant".to_string(),
            ));
        }
        let mut child_host =
            open_child_host(&family, parent, "localhost://Users/self/Projects/demo/src").map_err(
                |_| elastos::bus::types::BusError::Invalid("a child host was refused".to_string()),
            )?;
        let family_before = family.events.len();
        if open_child_host(&family, parent, "localhost://Users/self/Projects/other").is_ok()
            || child_host.events.len() != 1
            || child_host.events[0].text != SYSTEM_HEAD
            || child_host.steps.len() != 1
            || child_host.steps[0].grant.is_some()
            || grant_child_host(
                &mut child_host,
                Some("fixture-grant"),
                Some("fixture-grant"),
            )
            || child_host.steps[0].grant.is_some()
            || !grant_child_host(&mut child_host, Some("fixture-grant"), Some("child-grant"))
            || child_host.steps[0].grant.as_deref() != Some("child-grant")
            || record_child_result(&mut family, &child_host, "fixture-grant")
            || !record_child_result(&mut family, &child_host, "child result ok")
            || family.events.len() != family_before + 1
            || family
                .events
                .last()
                .is_none_or(|node| node.role != Role::ToolResult || node.text != "child result ok")
            || child_host.events.len() != 1
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a child host shared the parent log".to_string(),
            ));
        }
        let mut project = empty_journal();
        if propose_init(&mut project, "/tmp", "demo").is_ok()
            || propose_init(&mut project, "self", "demo/app").is_ok()
            || !project.steps.is_empty()
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a host path became a project".to_string(),
            ));
        }
        let init = propose_init(&mut project, "self", "demo").map_err(|_| {
            elastos::bus::types::BusError::Invalid("a project proposal was refused".to_string())
        })?;
        if project
            .steps
            .iter()
            .find(|step| step.id == init)
            .is_none_or(|step| {
                step.kind != ProposalKind::Init
                    || step.resource != "localhost://Users/self/Projects/demo"
                    || step.resource.starts_with('/')
            })
            || step_state(&project, init) != Some(StepState::Prepared)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a project proposal stored a host path".to_string(),
            ));
        }
        let file = format!("{}/index.html", "localhost://Users/self/Projects/demo");
        if propose_scaffold(&mut project, init, "index.html", "<h1>demo</h1>", Some(1)).is_ok()
            || observe(&mut project, "/tmp/secret", 1, "no")
            || !observe(&mut project, &file, 1, "")
            || propose_scaffold(
                &mut project,
                init,
                "../index.html",
                "<h1>demo</h1>",
                Some(1),
            )
            .is_ok()
            || propose_scaffold(&mut project, init, "index.html", "<h1>demo</h1>", Some(2)).is_ok()
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a scaffold skipped the version rules".to_string(),
            ));
        }
        let before_scaffold = project.events.clone();
        let scaffold = propose_scaffold(&mut project, init, "index.html", "<h1>demo</h1>", Some(1))
            .map_err(|_| {
                elastos::bus::types::BusError::Invalid("an empty scaffold was refused".to_string())
            })?;
        let entry = project_tree_hash(&[("index.html", "<h1>demo</h1>"), ("style.css", "body{}")])
            .ok_or_else(|| {
                elastos::bus::types::BusError::Invalid(
                    "the project tree hash was missing".to_string(),
                )
            })?;
        let changed = project_tree_hash(&[("index.html", "<h1>demo</h1>"), ("style.css", "h1{}")])
            .ok_or_else(|| {
                elastos::bus::types::BusError::Invalid(
                    "the project tree hash was missing".to_string(),
                )
            })?;
        if project.events != before_scaffold
            || current_observed_text(&project.events, &file).as_deref() != Some("")
            || project
                .steps
                .iter()
                .find(|step| step.id == scaffold)
                .is_none_or(|step| step.new != "<h1>demo</h1>" || step.has_result)
            || entry == changed
            || project_tree_hash(&[("/tmp/style.css", "body{}")]).is_some()
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a scaffold write applied the file".to_string(),
            ));
        }
        let run = propose_run(
            &mut project,
            "localhost://Users/self/Projects/demo",
            &["true".to_string()],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("the run seat was refused".to_string())
        })?;
        if project
            .steps
            .iter()
            .find(|step| step.id == run)
            .is_none_or(|step| step.seat != "microvm")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a run used a seat other than microvm".to_string(),
            ));
        }
        let events_before_result = project.events.clone();
        if record_run_result(&mut project, run, 0, "ok", "")
            || !authorize(&mut project, run, Some("fixture-grant"))
            || record_run_result(&mut project, run, 0, "ok", "")
            || !dispatch(&mut project, run)
            || record_run_result(&mut project, run, 0, "ok", "/tmp/out")
            || record_run_result(&mut project, run, 0, &"x".repeat(RUN_LOG_BUDGET + 1), "")
            || !record_run_result(&mut project, run, 0, "init: hello from vm smoke test", "")
            || record_run_result(&mut project, run, 0, "again", "")
            || project.events.last().is_none_or(|node| {
                node.role != Role::ToolResult
                    || node.text != "exit 0\ninit: hello from vm smoke test\n"
            })
            || project.events.len() != events_before_result.len() + 1
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a run result was recorded without a granted dispatch".to_string(),
            ));
        }
        let failed = propose_run(
            &mut project,
            "localhost://Users/self/Projects/demo",
            &["false".to_string()],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("a failed command was refused".to_string())
        })?;
        if !authorize(&mut project, failed, Some("fixture-grant"))
            || !dispatch(&mut project, failed)
            || !record_run_result(&mut project, failed, 1, "init: command failed", "")
            || project.events.len() != events_before_result.len() + 2
            || project
                .events
                .iter()
                .rev()
                .nth(1)
                .is_none_or(|node| node.text != "exit 0\ninit: hello from vm smoke test\n")
            || project.events.last().is_none_or(|node| {
                node.role != Role::ToolResult || node.text != "exit 1\ninit: command failed\n"
            })
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a failed command was recorded as success".to_string(),
            ));
        }
        let tested = propose_run(
            &mut project,
            "localhost://Users/self/Projects/demo",
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("a rust test result was refused".to_string())
        })?;
        let broken = propose_run(
            &mut project,
            "localhost://Users/self/Projects/demo",
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("a rust test result was refused".to_string())
        })?;
        if observe(
            &mut project,
            "localhost://Users/self/Projects/demo/index.html",
            1,
            "<h1>demo</h1>",
        ) || !observe(
            &mut project,
            "localhost://Users/self/Projects/demo/index.html",
            2,
            "<h1>demo</h1>",
        ) || !observe(
            &mut project,
            "localhost://Users/self/Projects/demo/style.css",
            1,
            "body{}",
        ) || !observe(
            &mut project,
            "localhost://Users/self/Projects/demo/notes.txt",
            1,
            "hello from the project",
        ) || !authorize(&mut project, tested, Some("fixture-grant"))
            || !dispatch(&mut project, tested)
            || !record_run_result(
                &mut project,
                tested,
                0,
                "project demo a1097f0d6ed225ad16b19f19d6a260816af54c74bfe82b11e4ce2020233497f1\ntest result: ok",
                "",
            )
            || !authorize(&mut project, broken, Some("fixture-grant"))
            || !dispatch(&mut project, broken)
            || !record_run_result(&mut project, broken, 101, "test result: FAILED", "")
            || project.events.iter().rev().nth(1).is_none_or(|node| {
                    node.text != "exit 0\nproject demo a1097f0d6ed225ad16b19f19d6a260816af54c74bfe82b11e4ce2020233497f1\ntest result: ok\n"
            })
            || project.events.last().is_none_or(|node| {
                node.role != Role::ToolResult || node.text != "exit 101\ntest result: FAILED\n"
            })
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a rust test result was recorded as the wrong exit".to_string(),
            ));
        }
        let mismatch = propose_run(
            &mut project,
            "localhost://Users/self/Projects/demo",
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("a mismatched exit was refused".to_string())
        })?;
        let before_mismatch = project.events.len();
        if !authorize(&mut project, mismatch, Some("fixture-grant"))
            || !dispatch(&mut project, mismatch)
            || record_run_result(&mut project, mismatch, 0, "test result: FAILED", "")
            || project.events.len() != before_mismatch
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a mismatched exit was recorded".to_string(),
            ));
        }
        let mut edited = empty_journal();
        let style = "localhost://Users/self/Projects/demo/style.css";
        let page = "localhost://Users/self/Projects/demo/index.html";
        if !observe(&mut edited, page, 1, "<h1>demo</h1>")
            || !observe(&mut edited, style, 1, "body{}")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the project was not read".to_string(),
            ));
        }
        let edit = propose_edit(&mut edited, style, "body{}", "h1{}", Some(1)).map_err(|_| {
            elastos::bus::types::BusError::Invalid("the stylesheet edit was refused".to_string())
        })?;
        if note_provider_wrote(&mut edited, edit)
            || !authorize(&mut edited, edit, Some("fixture-grant"))
            || !dispatch(&mut edited, edit)
            || !note_provider_wrote(&mut edited, edit)
            || note_crash(&mut edited, edit)
            || current_observed_text(&edited.events, style).as_deref() != Some("h1{}")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a granted edit did not become the current text".to_string(),
            ));
        }
        let bytes = model_bytes(&edited.events).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid("the edit log could not be saved".to_string())
        })?;
        let restored = replay(&bytes).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid("the edit log could not be resumed".to_string())
        })?;
        if current_observed_text(&restored, style).as_deref() != Some("h1{}") {
            return Err(elastos::bus::types::BusError::Invalid(
                "the edit did not survive resume".to_string(),
            ));
        }
        let mut crashed = empty_journal();
        let notes = "localhost://Users/self/Projects/demo/notes.txt";
        if !observe(&mut crashed, notes, 1, "hello from the project") {
            return Err(elastos::bus::types::BusError::Invalid(
                "the note was not read".to_string(),
            ));
        }
        let pending = propose_edit(
            &mut crashed,
            notes,
            "hello from the project",
            "hello again",
            Some(1),
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("the note edit was refused".to_string())
        })?;
        if !authorize(&mut crashed, pending, Some("fixture-grant"))
            || !dispatch(&mut crashed, pending)
            || !note_crash(&mut crashed, pending)
            || note_provider_wrote(&mut crashed, pending)
            || current_observed_text(&crashed.events, notes).as_deref()
                != Some("hello from the project")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a crash applied the note".to_string(),
            ));
        }
        let mut stopped = empty_journal();
        if !observe(
            &mut stopped,
            "localhost://Users/self/Projects/demo/notes.txt",
            1,
            "hello from the project",
        ) {
            return Err(elastos::bus::types::BusError::Invalid(
                "the note was not read".to_string(),
            ));
        }
        let held = propose_edit(
            &mut stopped,
            "localhost://Users/self/Projects/demo/notes.txt",
            "hello from the project",
            "hello again",
            Some(1),
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("the note edit was refused".to_string())
        })?;
        if !cancel(&mut stopped, held)
            || note_provider_wrote(&mut stopped, held)
            || dispatch(&mut stopped, held)
            || current_observed_text(&stopped.events, notes).as_deref()
                != Some("hello from the project")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a cancel applied the note".to_string(),
            ));
        }
        let listed = propose_run(
            &mut project,
            "localhost://Users/self/Projects/demo",
            &["files".to_string()],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("the file list was refused".to_string())
        })?;
        let doubled = "project file index.html\nproject file index.html\nproject file notes.txt\nproject file notes.txt\nproject file style.css\nproject file style.css";
        if !authorize(&mut project, listed, Some("fixture-grant"))
            || !dispatch(&mut project, listed)
            || record_run_result(
                &mut project,
                listed,
                0,
                "project file index.html\nproject file style.css",
                "",
            )
            || record_run_result(
                &mut project,
                listed,
                0,
                &format!(
                    "{doubled}\nproject demo a1097f0d6ed225ad16b19f19d6a260816af54c74bfe82b11e4ce2020233497f1\ntest result: ok"
                ),
                "",
            )
            || !record_run_result(&mut project, listed, 0, doubled, "")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a doubled file list was refused".to_string(),
            ));
        }
        let noted = propose_run(
            &mut project,
            "localhost://Users/self/Projects/demo",
            &["note".to_string()],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("the note read was refused".to_string())
        })?;
        let listed_effect = project
            .steps
            .iter()
            .find(|step| step.id == listed)
            .map(|step| step.effect_id);
        let noted_effect = project
            .steps
            .iter()
            .find(|step| step.id == noted)
            .map(|step| step.effect_id);
        if listed_effect.is_none()
            || listed_effect == noted_effect
            || !authorize(&mut project, noted, Some("fixture-grant"))
            || !dispatch(&mut project, noted)
            || record_run_result(&mut project, noted, 0, doubled, "")
            || !record_run_result(
                &mut project,
                noted,
                0,
                "project note hello from the project",
                "",
            )
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a file list was stored as the note".to_string(),
            ));
        }
        let blocked = propose_edit(
            &mut project,
            "localhost://Users/self/Projects/demo/notes.txt",
            "hello from the project",
            "hello again",
            Some(1),
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("the note rewrite was refused".to_string())
        })?;
        if !authorize(&mut project, blocked, Some("fixture-grant"))
            || dispatch(&mut project, blocked)
            || note_provider_wrote(&mut project, blocked)
            || current_observed_text(
                &project.events,
                "localhost://Users/self/Projects/demo/notes.txt",
            )
            .as_deref()
                != Some("hello from the project")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a note rewrite passed an open scaffold".to_string(),
            ));
        }
        let reread = propose_run(
            &mut project,
            "localhost://Users/self/Projects/demo",
            &["note".to_string()],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("the rewritten note was refused".to_string())
        })?;
        if !cancel(&mut project, scaffold)
            || current_observed_text(
                &project.events,
                "localhost://Users/self/Projects/demo/notes.txt",
            )
            .as_deref()
                != Some("hello from the project")
            || !dispatch(&mut project, blocked)
            || !note_provider_wrote(&mut project, blocked)
            || !authorize(&mut project, reread, Some("fixture-grant"))
            || !dispatch(&mut project, reread)
            || record_run_result(
                &mut project,
                reread,
                0,
                "project note hello from the project",
                "",
            )
            || !record_run_result(&mut project, reread, 0, "project note hello again", "")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a cancelled scaffold still blocked the note".to_string(),
            ));
        }
        let earlier = propose_run(
            &mut project,
            "localhost://Users/self/Projects/demo",
            &["note".to_string()],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("the earlier note was refused".to_string())
        })?;
        let pending = propose_edit(
            &mut project,
            "localhost://Users/self/Projects/demo/notes.txt",
            "hello again",
            "hello once more",
            Some(2),
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("the rewritten edit was refused".to_string())
        })?;
        if observe(
            &mut project,
            "localhost://Users/self/Projects/demo/notes.txt",
            1,
            "hello again",
        ) || !observe(
            &mut project,
            "localhost://Users/self/Projects/demo/notes.txt",
            1,
            "hello from the project",
        ) || !authorize(&mut project, pending, Some("fixture-grant"))
            || !dispatch(&mut project, pending)
            || note_provider_wrote(&mut project, pending)
            || step_state(&project, pending) != Some(StepState::Denied)
            || current_observed_text(
                &project.events,
                "localhost://Users/self/Projects/demo/notes.txt",
            )
            .as_deref()
                != Some("hello from the project")
            || !authorize(&mut project, earlier, Some("fixture-grant"))
            || !dispatch(&mut project, earlier)
            || record_run_result(&mut project, earlier, 0, "project note hello again", "")
            || !record_run_result(
                &mut project,
                earlier,
                0,
                "project note hello from the project",
                "",
            )
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the rewritten note stayed current after the older read".to_string(),
            ));
        }
        let fresh = propose_edit(
            &mut project,
            "localhost://Users/self/Projects/demo/notes.txt",
            "hello from the project",
            "hello again",
            Some(1),
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("the current note edit was refused".to_string())
        })?;
        let quoted = propose_run(
            &mut project,
            "localhost://Users/self/Projects/demo",
            &["note".to_string()],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("the current note edit was refused".to_string())
        })?;
        if !authorize(&mut project, fresh, Some("fixture-grant"))
            || !dispatch(&mut project, fresh)
            || !note_provider_wrote(&mut project, fresh)
            || current_observed_text(
                &project.events,
                "localhost://Users/self/Projects/demo/notes.txt",
            )
            .as_deref()
                != Some("hello again")
            || !authorize(&mut project, quoted, Some("fixture-grant"))
            || !dispatch(&mut project, quoted)
            || record_run_result(
                &mut project,
                quoted,
                0,
                "project note hello from the project",
                "",
            )
            || !record_run_result(&mut project, quoted, 0, "project note hello again", "")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the current note edit was refused".to_string(),
            ));
        }
        let saved = model_bytes(&project.events).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid("resume lost the current note".to_string())
        })?;
        let Some(resumed) = replay(&saved) else {
            return Err(elastos::bus::types::BusError::Invalid(
                "resume lost the current note".to_string(),
            ));
        };
        if current_observed_text(&resumed, "localhost://Users/self/Projects/demo/notes.txt")
            .as_deref()
            != Some("hello again")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "resume lost the current note".to_string(),
            ));
        }
        let mut page = empty_journal();
        let page_init = propose_init(&mut page, "self", "demo").map_err(|_| {
            elastos::bus::types::BusError::Invalid("the empty page was refused".to_string())
        })?;
        let page_file = "localhost://Users/self/Projects/demo/index.html";
        if !observe(&mut page, page_file, 1, "") {
            return Err(elastos::bus::types::BusError::Invalid(
                "the empty page was refused".to_string(),
            ));
        }
        let filling =
            propose_scaffold(&mut page, page_init, "index.html", "<h1>demo</h1>", Some(1))
                .map_err(|_| {
                    elastos::bus::types::BusError::Invalid("the empty page was refused".to_string())
                })?;
        if let Some(step) = page.steps.iter_mut().find(|step| step.id == filling) {
            step.seen_version = Some(1);
        }
        if !observe(
            &mut page,
            "localhost://Users/self/Projects/demo/notes.txt",
            1,
            "hello from the project",
        ) {
            return Err(elastos::bus::types::BusError::Invalid(
                "the empty page was refused".to_string(),
            ));
        }
        let follow = propose_edit(
            &mut page,
            "localhost://Users/self/Projects/demo/notes.txt",
            "hello from the project",
            "hello again",
            Some(1),
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid(
                "a refused scaffold blocked the note".to_string(),
            )
        })?;
        if !authorize(&mut page, filling, Some("fixture-grant"))
            || !dispatch(&mut page, filling)
            || note_provider_wrote(&mut page, filling)
            || step_state(&page, filling) != Some(StepState::Denied)
            || current_observed_text(&page.events, page_file).as_deref() != Some("")
            || !authorize(&mut page, follow, Some("fixture-grant"))
            || !dispatch(&mut page, follow)
            || !note_provider_wrote(&mut page, follow)
            || current_observed_text(
                &page.events,
                "localhost://Users/self/Projects/demo/notes.txt",
            )
            .as_deref()
                != Some("hello again")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a refused scaffold blocked the note".to_string(),
            ));
        }
        let mut folded = two_turns();
        if !observe(
            &mut folded,
            "localhost://Users/self/Projects/demo/notes.txt",
            1,
            "hello again",
        ) || !compact(&mut folded, COMPACTION_SUMMARY)
            || current_observed_text(
                &folded.events,
                "localhost://Users/self/Projects/demo/notes.txt",
            )
            .as_deref()
                != Some("hello again")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a shorter log dropped the current note".to_string(),
            ));
        }
        let quoted = propose_run(
            &mut folded,
            "localhost://Users/self/Projects/demo",
            &["note".to_string()],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid(
                "a shorter log refused the current note".to_string(),
            )
        })?;
        let follow = propose_edit(
            &mut folded,
            "localhost://Users/self/Projects/demo/notes.txt",
            "hello again",
            "hello once more",
            Some(1),
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid(
                "a shorter log refused the current note".to_string(),
            )
        })?;
        if !authorize(&mut folded, quoted, Some("fixture-grant"))
            || !dispatch(&mut folded, quoted)
            || record_run_result(
                &mut folded,
                quoted,
                0,
                "project note hello from the project",
                "",
            )
            || !record_run_result(&mut folded, quoted, 0, "project note hello again", "")
            || !authorize(&mut folded, follow, Some("fixture-grant"))
            || !dispatch(&mut folded, follow)
            || !note_provider_wrote(&mut folded, follow)
            || current_observed_text(
                &folded.events,
                "localhost://Users/self/Projects/demo/notes.txt",
            )
            .as_deref()
                != Some("hello once more")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a shorter log refused the current note".to_string(),
            ));
        }
        let mut crashed = folded.clone();
        if !begin_compact(&mut crashed, COMPACTION_SUMMARY)
            || !note_crash_during_compact(&mut crashed)
            || crashed.compaction_open
            || commit_compact(&mut crashed)
            || current_observed_text(
                &crashed.events,
                "localhost://Users/self/Projects/demo/notes.txt",
            )
            .as_deref()
                != Some("hello once more")
            || observed_text_at(
                &crashed.events,
                "localhost://Users/self/Projects/demo/notes.txt",
                1,
            )
            .as_deref()
                != Some("hello again")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a crash during shortening dropped the note".to_string(),
            ));
        }
        if !compact(&mut folded, COMPACTION_SUMMARY)
            || current_observed_text(
                &folded.events,
                "localhost://Users/self/Projects/demo/notes.txt",
            )
            .as_deref()
                != Some("hello once more")
            || observe(
                &mut folded,
                "localhost://Users/self/Projects/demo/notes.txt",
                1,
                "hello once more",
            )
            || !observe(
                &mut folded,
                "localhost://Users/self/Projects/demo/notes.txt",
                1,
                "hello again",
            )
            || current_observed_text(
                &folded.events,
                "localhost://Users/self/Projects/demo/notes.txt",
            )
            .as_deref()
                != Some("hello again")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a second shorter log dropped the older note".to_string(),
            ));
        }
        let mut tree = two_turns();
        if !admit_skill(&mut tree, "Prefer the Runtime grant.")
            || !observe(
                &mut tree,
                "localhost://Users/self/Projects/demo/index.html",
                1,
                "<h1>demo</h1>",
            )
            || !observe(
                &mut tree,
                "localhost://Users/self/Projects/demo/style.css",
                1,
                "body{}",
            )
            || !observe(
                &mut tree,
                "localhost://Users/self/Projects/demo/notes.txt",
                1,
                "hello from the project",
            )
            || !compact(&mut tree, COMPACTION_SUMMARY)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a shorter log dropped the project".to_string(),
            ));
        }
        let listed = propose_run(
            &mut tree,
            "localhost://Users/self/Projects/demo",
            &["files".to_string()],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("a shorter log dropped the project".to_string())
        })?;
        let checked = propose_run(
            &mut tree,
            "localhost://Users/self/Projects/demo",
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("a shorter log dropped the project".to_string())
        })?;
        if !tree.events.iter().any(|node| {
            node.source == NodeSource::Skill && node.text == "Prefer the Runtime grant."
        }) || !authorize(&mut tree, listed, Some("fixture-grant"))
            || !dispatch(&mut tree, listed)
            || record_run_result(
                &mut tree,
                listed,
                0,
                "project file index.html\nproject file style.css",
                "",
            )
            || !record_run_result(
                &mut tree,
                listed,
                0,
                "project file index.html\nproject file notes.txt\nproject file style.css",
                "",
            )
            || !authorize(&mut tree, checked, Some("fixture-grant"))
            || !dispatch(&mut tree, checked)
            || !record_run_result(
                &mut tree,
                checked,
                0,
                "project demo a1097f0d6ed225ad16b19f19d6a260816af54c74bfe82b11e4ce2020233497f1\ntest result: ok",
                "",
            )
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a shorter log dropped the project".to_string(),
            ));
        }
        let mut workspace = two_turns();
        if !admit_snapshot(
            &mut workspace,
            "localhost://Users/self",
            "2026-10-13T01:29:00Z",
            "localhost://Users/self/Projects/demo/notes.txt",
        ) || !compact(&mut workspace, COMPACTION_SUMMARY)
            || !workspace.events.iter().any(|node| {
                node.source == NodeSource::Snapshot && node.text == "localhost://Users/self"
            })
            || !workspace.events.iter().any(|node| {
                node.source == NodeSource::Snapshot && node.text == "2026-10-13T01:29:00Z"
            })
            || !workspace.events.iter().any(|node| {
                node.source == NodeSource::Snapshot
                    && node.text == "localhost://Users/self/Projects/demo/notes.txt"
            })
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a shorter log dropped the workspace".to_string(),
            ));
        }
        let mut goal = two_turns();
        let goal_steps = goal.steps.len();
        if record_visible(&mut goal, VisibleRecord::Goal, "")
            || record_visible(&mut goal, VisibleRecord::Goal, "/tmp")
            || !record_visible(&mut goal, VisibleRecord::Goal, "finish the note")
            || !record_visible(&mut goal, VisibleRecord::Todo, "keep the note current")
            || !record_visible(&mut goal, VisibleRecord::PlanEntered, "edit the note")
            || !record_visible(&mut goal, VisibleRecord::PlanExitAsked, "the note is ready")
            || !record_visible(&mut goal, VisibleRecord::SpillPointer, "notes.txt")
            || goal.epoch != 1
            || goal.steps.len() != goal_steps
            || !compact(&mut goal, COMPACTION_SUMMARY)
            || goal.events.iter().any(|node| node.text == "second turn")
            || !goal.events.iter().any(|node| {
                node.source == NodeSource::Person && node.text == "goal\nfinish the note"
            })
            || !goal.events.iter().any(|node| {
                node.source == NodeSource::Person
                    && node.text == "plan-exit-asked\nthe note is ready"
            })
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a shorter log dropped the goal".to_string(),
            ));
        }
        let mut inbox = two_turns();
        let denied = propose_step(&mut inbox);
        let missing = propose_step(&mut inbox);
        let session = propose_step(&mut inbox);
        let standing = propose_step(&mut inbox);
        if apply_inbox(&mut inbox, denied, InboxAnswer::Deny, Some("fixture-grant"))
            || step_state(&inbox, denied) != Some(StepState::Denied)
            || inbox
                .steps
                .iter()
                .find(|step| step.id == denied)
                .is_none_or(|step| step.grant.is_some() || step.inbox != "deny")
            || apply_inbox(&mut inbox, missing, InboxAnswer::AllowOnce, None)
            || step_state(&inbox, missing) != Some(StepState::Denied)
            || apply_inbox(&mut inbox, session, InboxAnswer::AllowSession, Some(""))
            || step_state(&inbox, session) != Some(StepState::Denied)
            || !apply_inbox(
                &mut inbox,
                standing,
                InboxAnswer::Standing,
                Some("fixture-grant"),
            )
            || step_state(&inbox, standing) != Some(StepState::Prepared)
            || inbox
                .steps
                .iter()
                .find(|step| step.id == standing)
                .is_none_or(|step| {
                    step.grant.as_deref() != Some("fixture-grant") || step.inbox != "standing"
                })
            || model_bytes(&inbox.events).is_none_or(|bytes| {
                !bytes
                    .windows(b"inbox\nstanding".len())
                    .any(|window| window == b"inbox\nstanding")
                    || bytes
                        .windows(b"fixture-grant".len())
                        .any(|window| window == b"fixture-grant")
            })
            || !compact(&mut inbox, COMPACTION_SUMMARY)
            || !inbox
                .events
                .iter()
                .any(|node| node.source == NodeSource::Person && node.text == "inbox\nstanding")
            || model_bytes(&inbox.events).is_none_or(|bytes| {
                bytes
                    .windows(b"fixture-grant".len())
                    .any(|window| window == b"fixture-grant")
            })
            || apply_inbox(&mut inbox, standing, InboxAnswer::Deny, Some("other-grant"))
            || inbox
                .steps
                .iter()
                .find(|step| step.id == standing)
                .is_none_or(|step| {
                    step.grant.as_deref() != Some("fixture-grant") || step.inbox != "standing"
                })
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "an inbox answer minted a grant".to_string(),
            ));
        }
        let held = propose_step(&mut inbox);
        let other = propose_step(&mut inbox);
        if !apply_inbox(
            &mut inbox,
            held,
            InboxAnswer::Standing,
            Some("fixture-grant"),
        ) || !cancel(&mut inbox, held)
            || dispatch(&mut inbox, held)
            || step_state(&inbox, held) != Some(StepState::Cancelled)
            || !inbox
                .events
                .iter()
                .any(|node| node.source == NodeSource::Person && node.text == "inbox\nstanding")
            || step_state(&inbox, other) != Some(StepState::Prepared)
            || inbox
                .steps
                .iter()
                .find(|step| step.id == other)
                .is_none_or(|step| step.grant.is_some() || !step.inbox.is_empty())
            || !dispatch(&mut inbox, standing)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "an inbox answer minted a grant".to_string(),
            ));
        }
        if let Some(step) = inbox.steps.iter_mut().find(|step| step.id == standing) {
            step.resource = "localhost://Users/self/Projects/demo".to_string();
        }
        let notes = "localhost://Users/self/Projects/demo/notes.txt";
        if !observe(&mut inbox, notes, 1, "hello from the project")
            || spill_pointer(&mut inbox, standing, "/tmp/secret")
            || spill_pointer(
                &mut inbox,
                standing,
                "localhost://Users/self/Projects/demo/style.css",
            )
            || spill_pointer(&mut inbox, other, notes)
            || !spill_pointer(&mut inbox, standing, notes)
            || current_observed_text(&inbox.events, notes).as_deref()
                != Some("hello from the project")
            || spill_pointer(&mut inbox, standing, notes)
            || !inbox.events.iter().any(|node| {
                node.role == Role::ToolResult && node.text == format!("spill\n{notes}\n1")
            })
            || !compact(&mut inbox, COMPACTION_SUMMARY)
            || current_observed_text(&inbox.events, notes).as_deref()
                != Some("hello from the project")
            || !inbox.events.iter().any(|node| {
                node.source == NodeSource::Person && node.text == format!("spill\n{notes}\n1")
            })
            || model_bytes(&inbox.events).is_none_or(|bytes| {
                bytes
                    .windows(b"fixture-grant".len())
                    .any(|window| window == b"fixture-grant")
            })
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a spill pointer replaced the file".to_string(),
            ));
        }
        let moved = propose_edit(
            &mut inbox,
            notes,
            "hello from the project",
            "hello again",
            Some(1),
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid(
                "a later edit moved the spill pointer".to_string(),
            )
        })?;
        if !authorize(&mut inbox, moved, Some("fixture-grant"))
            || !dispatch(&mut inbox, moved)
            || !note_provider_wrote(&mut inbox, moved)
            || current_observed_text(&inbox.events, notes).as_deref() != Some("hello again")
            || observed_text_at(&inbox.events, notes, 1).as_deref()
                != Some("hello from the project")
            || text_at_spill(&inbox.events, notes).as_deref() != Some("hello from the project")
            || !inbox.events.iter().any(|node| {
                node.source == NodeSource::Person && node.text == format!("spill\n{notes}\n1")
            })
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a later edit moved the spill pointer".to_string(),
            ));
        }
        let again = propose_run(
            &mut inbox,
            "localhost://Users/self/Projects/demo",
            &["note".to_string()],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid(
                "the newer spill pointer was ignored".to_string(),
            )
        })?;
        if !authorize(&mut inbox, again, Some("fixture-grant"))
            || !dispatch(&mut inbox, again)
            || !spill_pointer(&mut inbox, again, notes)
            || text_at_spill(&inbox.events, notes).as_deref() != Some("hello again")
            || observed_text_at(&inbox.events, notes, 1).as_deref()
                != Some("hello from the project")
            || !inbox.events.iter().any(|node| {
                node.source == NodeSource::Person && node.text == format!("spill\n{notes}\n1")
            })
            || !inbox.events.iter().any(|node| {
                node.source == NodeSource::Person && node.text == format!("spill\n{notes}\n2")
            })
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the newer spill pointer was ignored".to_string(),
            ));
        }
        let style = "localhost://Users/self/Projects/demo/style.css";
        let styled = propose_run(
            &mut inbox,
            "localhost://Users/self/Projects/demo",
            &["files".to_string()],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("a spill pointer crossed files".to_string())
        })?;
        if !observe(&mut inbox, style, 1, "body{}")
            || spill_pointer(&mut inbox, again, style)
            || !authorize(&mut inbox, styled, Some("fixture-grant"))
            || !dispatch(&mut inbox, styled)
            || !spill_pointer(&mut inbox, styled, style)
            || text_at_spill(&inbox.events, notes).as_deref() != Some("hello again")
            || text_at_spill(&inbox.events, style).as_deref() != Some("body{}")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a spill pointer crossed files".to_string(),
            ));
        }
        inbox.events.push(SurfaceNode {
            role: Role::User,
            text: format!("spill\n{notes}\n9"),
            source: NodeSource::Person,
        });
        if text_at_spill(&inbox.events, notes).as_deref() != Some("hello again") {
            return Err(elastos::bus::types::BusError::Invalid(
                "a missing spill version hid the earlier pointer".to_string(),
            ));
        }
        let mut family = two_turns();
        let parent = propose_run(
            &mut family,
            "localhost://Users/self/Projects/demo",
            &["note".to_string()],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("a child took the parent grant".to_string())
        })?;
        let child = propose_child(
            &mut family,
            parent,
            "localhost://Users/self/Projects/demo/src",
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("a child took the parent grant".to_string())
        })?;
        let standing_lines = |events: &[SurfaceNode]| {
            events
                .iter()
                .filter(|node| node.source == NodeSource::Person && node.text == "inbox\nstanding")
                .count()
        };
        if !apply_inbox(
            &mut family,
            parent,
            InboxAnswer::Standing,
            Some("fixture-grant"),
        ) || standing_lines(&family.events) != 1
            || apply_inbox(
                &mut family,
                child,
                InboxAnswer::Standing,
                Some("fixture-grant"),
            )
            || standing_lines(&family.events) != 1
            || family
                .steps
                .iter()
                .find(|step| step.id == child)
                .is_none_or(|step| step.grant.is_some() || !step.inbox.is_empty())
            || !apply_inbox(
                &mut family,
                child,
                InboxAnswer::Standing,
                Some("child-grant"),
            )
            || standing_lines(&family.events) != 2
            || family
                .steps
                .iter()
                .find(|step| step.id == child)
                .is_none_or(|step| {
                    step.grant.as_deref() != Some("child-grant") || step.inbox != "standing"
                })
            || !dispatch(&mut family, child)
            || step_state(&family, parent) != Some(StepState::Prepared)
            || family
                .steps
                .iter()
                .find(|step| step.id == parent)
                .is_none_or(|step| step.grant.as_deref() != Some("fixture-grant"))
            || model_bytes(&family.events).is_none_or(|bytes| {
                bytes
                    .windows(b"fixture-grant".len())
                    .any(|window| window == b"fixture-grant")
                    || bytes
                        .windows(b"child-grant".len())
                        .any(|window| window == b"child-grant")
            })
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a child took the parent grant".to_string(),
            ));
        }
        let held = propose_child(
            &mut family,
            parent,
            "localhost://Users/self/Projects/demo/lib",
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid(
                "cancelling the child cancelled the parent".to_string(),
            )
        })?;
        if !apply_inbox(
            &mut family,
            held,
            InboxAnswer::Standing,
            Some("child-grant"),
        ) || standing_lines(&family.events) != 3
            || !cancel(&mut family, held)
            || dispatch(&mut family, held)
            || step_state(&family, held) != Some(StepState::Cancelled)
            || step_state(&family, parent) != Some(StepState::Prepared)
            || step_state(&family, child) != Some(StepState::Dispatched)
            || standing_lines(&family.events) != 3
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "cancelling the child cancelled the parent".to_string(),
            ));
        }
        let sent = propose_child(
            &mut family,
            parent,
            "localhost://Users/self/Projects/demo/tests",
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid(
                "a crash of the child moved the parent".to_string(),
            )
        })?;
        if !apply_inbox(
            &mut family,
            sent,
            InboxAnswer::Standing,
            Some("child-grant"),
        ) || !dispatch(&mut family, sent)
            || !note_crash(&mut family, sent)
            || step_state(&family, sent) != Some(StepState::SettlementUnknown)
            || dispatch(&mut family, sent)
            || step_state(&family, parent) != Some(StepState::Prepared)
            || step_state(&family, child) != Some(StepState::Dispatched)
            || standing_lines(&family.events) != 4
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a crash of the child moved the parent".to_string(),
            ));
        }
        let main = "localhost://Users/self/Projects/demo/src/main.rs";
        if !observe(&mut family, main, 1, "fn main() {}")
            || !spill_pointer(&mut family, child, main)
            || note_crash(&mut family, child)
            || step_state(&family, child) != Some(StepState::Dispatched)
            || text_at_spill(&family.events, main).as_deref() != Some("fn main() {}")
            || step_state(&family, parent) != Some(StepState::Prepared)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a crash erased the child's result".to_string(),
            ));
        }
        let saved = model_bytes(&family.events).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid("resume lost the child's file".to_string())
        })?;
        let Some(resumed) = replay(&saved) else {
            return Err(elastos::bus::types::BusError::Invalid(
                "resume lost the child's file".to_string(),
            ));
        };
        if text_at_spill(&resumed, main).as_deref() != Some("fn main() {}")
            || !compact(&mut family, COMPACTION_SUMMARY)
            || text_at_spill(&family.events, main).as_deref() != Some("fn main() {}")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "resume lost the child's file".to_string(),
            ));
        }
        let mut repeats = empty_journal();
        let project = "localhost://Users/self/Projects/demo";
        let first = propose_run(&mut repeats, project, &["note".to_string()]).map_err(|_| {
            elastos::bus::types::BusError::Invalid("the same command ran twice".to_string())
        })?;
        let second = propose_run(&mut repeats, project, &["files".to_string()]).map_err(|_| {
            elastos::bus::types::BusError::Invalid("the same command ran twice".to_string())
        })?;
        let third = propose_run(&mut repeats, project, &["note".to_string()]).map_err(|_| {
            elastos::bus::types::BusError::Invalid("the same command ran twice".to_string())
        })?;
        let other = propose_run(
            &mut repeats,
            "localhost://Users/self/Projects/other",
            &["note".to_string()],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("the same command ran twice".to_string())
        })?;
        if !authorize(&mut repeats, first, Some("fixture-grant"))
            || !authorize(&mut repeats, second, Some("fixture-grant"))
            || !authorize(&mut repeats, third, Some("fixture-grant"))
            || !authorize(&mut repeats, other, Some("fixture-grant"))
            || !dispatch(&mut repeats, first)
            || dispatch(&mut repeats, third)
            || !dispatch(&mut repeats, other)
            || step_state(&repeats, third) != Some(StepState::Prepared)
            || !dispatch(&mut repeats, second)
            || !record_run_result(&mut repeats, first, 0, "ok", "")
            || !dispatch(&mut repeats, third)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the same command ran twice".to_string(),
            ));
        }
        let ready = propose_run(
            &mut repeats,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid(
                "different tests were treated as one command".to_string(),
            )
        })?;
        let missing = propose_run(
            &mut repeats,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::a_missing_piece_fails".to_string(),
            ],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid(
                "different tests were treated as one command".to_string(),
            )
        })?;
        let ready_again = propose_run(
            &mut repeats,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid(
                "different tests were treated as one command".to_string(),
            )
        })?;
        if !authorize(&mut repeats, ready, Some("fixture-grant"))
            || !authorize(&mut repeats, missing, Some("fixture-grant"))
            || !authorize(&mut repeats, ready_again, Some("fixture-grant"))
            || !dispatch(&mut repeats, ready)
            || !dispatch(&mut repeats, missing)
            || dispatch(&mut repeats, ready_again)
            || step_state(&repeats, ready_again) != Some(StepState::Prepared)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "different tests were treated as one command".to_string(),
            ));
        }
        let missing_again = propose_run(
            &mut repeats,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::a_missing_piece_fails".to_string(),
            ],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("the other test closed with it".to_string())
        })?;
        if !record_run_result(&mut repeats, ready, 0, "test result: ok", "")
            || !dispatch(&mut repeats, ready_again)
            || !repeats.steps.iter().any(|step| {
                step.id == missing && step.state == StepState::Dispatched && !step.has_result
            })
            || !authorize(&mut repeats, missing_again, Some("fixture-grant"))
            || dispatch(&mut repeats, missing_again)
            || step_state(&repeats, missing_again) != Some(StepState::Prepared)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the other test closed with it".to_string(),
            ));
        }
        if !note_crash(&mut repeats, missing)
            || record_run_result(&mut repeats, missing, 101, "test result: FAILED", "")
            || dispatch(&mut repeats, missing_again)
            || step_state(&repeats, missing) != Some(StepState::SettlementUnknown)
            || step_state(&repeats, missing_again) != Some(StepState::Prepared)
            || !repeats.steps.iter().any(|step| {
                step.id == ready_again && step.state == StepState::Dispatched && !step.has_result
            })
            || note_crash(&mut repeats, ready)
            || !repeats
                .steps
                .iter()
                .any(|step| step.id == ready && step.has_result)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a crash of one test held the other".to_string(),
            ));
        }
        let ready_third = propose_run(
            &mut repeats,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid(
                "finishing one test freed the crashed name".to_string(),
            )
        })?;
        if !record_run_result(&mut repeats, ready_again, 0, "test result: ok", "")
            || !authorize(&mut repeats, ready_third, Some("fixture-grant"))
            || !dispatch(&mut repeats, ready_third)
            || dispatch(&mut repeats, missing_again)
            || step_state(&repeats, missing) != Some(StepState::SettlementUnknown)
            || step_state(&repeats, missing_again) != Some(StepState::Prepared)
            || !repeats
                .steps
                .iter()
                .any(|step| step.id == ready && step.has_result)
            || !repeats
                .steps
                .iter()
                .any(|step| step.id == ready_again && step.has_result)
            || !repeats
                .steps
                .iter()
                .any(|step| step.id == missing && !step.has_result)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "finishing one test freed the crashed name".to_string(),
            ));
        }
        let missing_third = propose_run(
            &mut repeats,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::a_missing_piece_fails".to_string(),
            ],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid(
                "cancelling the waiting copy freed the crash".to_string(),
            )
        })?;
        if cancel(&mut repeats, missing)
            || step_state(&repeats, missing) != Some(StepState::SettlementUnknown)
            || !cancel(&mut repeats, missing_again)
            || dispatch(&mut repeats, missing_again)
            || step_state(&repeats, missing_again) != Some(StepState::Cancelled)
            || !authorize(&mut repeats, missing_third, Some("fixture-grant"))
            || dispatch(&mut repeats, missing_third)
            || step_state(&repeats, missing_third) != Some(StepState::Prepared)
            || !repeats.steps.iter().any(|step| {
                step.id == ready_third && step.state == StepState::Dispatched && !step.has_result
            })
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "cancelling the waiting copy freed the crash".to_string(),
            ));
        }
        let elsewhere = propose_run(
            &mut repeats,
            "localhost://Users/self/Projects/other",
            &[
                "vm-smoke".to_string(),
                "tests::a_missing_piece_fails".to_string(),
            ],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("the other project freed this crash".to_string())
        })?;
        if !authorize(&mut repeats, elsewhere, Some("fixture-grant"))
            || !dispatch(&mut repeats, elsewhere)
            || !record_run_result(&mut repeats, elsewhere, 101, "test result: FAILED", "")
            || dispatch(&mut repeats, missing_third)
            || step_state(&repeats, missing) != Some(StepState::SettlementUnknown)
            || step_state(&repeats, missing_third) != Some(StepState::Prepared)
            || !repeats.steps.iter().any(|step| {
                step.id == ready_third && step.state == StepState::Dispatched && !step.has_result
            })
            || !repeats
                .steps
                .iter()
                .any(|step| step.id == elsewhere && step.has_result)
            || !repeats
                .steps
                .iter()
                .any(|step| step.id == missing && !step.has_result)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the other project freed this crash".to_string(),
            ));
        }
        let saved = model_bytes(&repeats.events).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid("the grant was written into the log".to_string())
        })?;
        let Some(resumed) = replay(&saved) else {
            return Err(elastos::bus::types::BusError::Invalid(
                "the grant was written into the log".to_string(),
            ));
        };
        let elsewhere_again = propose_run(
            &mut repeats,
            "localhost://Users/self/Projects/other",
            &[
                "vm-smoke".to_string(),
                "tests::a_missing_piece_fails".to_string(),
            ],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid(
                "the other project's next copy stayed held".to_string(),
            )
        })?;
        if saved
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant")
            || !resumed
                .iter()
                .any(|node| node.text == "exit 101\ntest result: FAILED\n")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the grant was written into the log".to_string(),
            ));
        }
        if !authorize(&mut repeats, elsewhere_again, Some("fixture-grant"))
            || !dispatch(&mut repeats, elsewhere_again)
            || dispatch(&mut repeats, missing_third)
            || step_state(&repeats, missing) != Some(StepState::SettlementUnknown)
            || step_state(&repeats, missing_third) != Some(StepState::Prepared)
            || !repeats.steps.iter().any(|step| {
                step.id == ready_third && step.state == StepState::Dispatched && !step.has_result
            })
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the other project's next copy stayed held".to_string(),
            ));
        }
        let elsewhere_third = propose_run(
            &mut repeats,
            "localhost://Users/self/Projects/other",
            &[
                "vm-smoke".to_string(),
                "tests::a_missing_piece_fails".to_string(),
            ],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid(
                "a crash on the other project held this one".to_string(),
            )
        })?;
        if !note_crash(&mut repeats, elsewhere_again)
            || record_run_result(
                &mut repeats,
                elsewhere_again,
                101,
                "test result: FAILED",
                "",
            )
            || cancel(&mut repeats, elsewhere_again)
            || step_state(&repeats, elsewhere_again) != Some(StepState::SettlementUnknown)
            || !authorize(&mut repeats, elsewhere_third, Some("fixture-grant"))
            || dispatch(&mut repeats, elsewhere_third)
            || step_state(&repeats, elsewhere_third) != Some(StepState::Prepared)
            || step_state(&repeats, missing) != Some(StepState::SettlementUnknown)
            || step_state(&repeats, missing_third) != Some(StepState::Prepared)
            || !repeats.steps.iter().any(|step| {
                step.id == ready_third && step.state == StepState::Dispatched && !step.has_result
            })
            || !repeats
                .steps
                .iter()
                .any(|step| step.id == elsewhere && step.has_result)
            || !repeats
                .events
                .iter()
                .any(|node| node.text == "exit 101\ntest result: FAILED\n")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a crash on the other project held this one".to_string(),
            ));
        }
        let ready_fourth = propose_run(
            &mut repeats,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid(
                "a result on this project freed the other crash".to_string(),
            )
        })?;
        if !record_run_result(&mut repeats, ready_third, 0, "test result: ok", "")
            || !authorize(&mut repeats, ready_fourth, Some("fixture-grant"))
            || !dispatch(&mut repeats, ready_fourth)
            || dispatch(&mut repeats, missing_third)
            || dispatch(&mut repeats, elsewhere_third)
            || step_state(&repeats, missing) != Some(StepState::SettlementUnknown)
            || step_state(&repeats, elsewhere_again) != Some(StepState::SettlementUnknown)
            || step_state(&repeats, missing_third) != Some(StepState::Prepared)
            || step_state(&repeats, elsewhere_third) != Some(StepState::Prepared)
            || !repeats
                .steps
                .iter()
                .any(|step| step.id == ready_third && step.has_result)
            || !repeats
                .events
                .iter()
                .any(|node| node.text == "exit 0\ntest result: ok\n")
            || !repeats
                .events
                .iter()
                .any(|node| node.text == "exit 101\ntest result: FAILED\n")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a result on this project freed the other crash".to_string(),
            ));
        }
        let saved_both = model_bytes(&repeats.events).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid(
                "a result on this project freed the other crash".to_string(),
            )
        })?;
        if saved_both
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a result on this project freed the other crash".to_string(),
            ));
        }
        let demo_true =
            propose_run(&mut repeats, project, &["true".to_string()]).map_err(|_| {
                elastos::bus::types::BusError::Invalid(
                    "a different program freed a crash".to_string(),
                )
            })?;
        let other_true = propose_run(
            &mut repeats,
            "localhost://Users/self/Projects/other",
            &["true".to_string()],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("a different program freed a crash".to_string())
        })?;
        let demo_true_again =
            propose_run(&mut repeats, project, &["true".to_string()]).map_err(|_| {
                elastos::bus::types::BusError::Invalid(
                    "a different program freed a crash".to_string(),
                )
            })?;
        if !authorize(&mut repeats, demo_true, Some("fixture-grant"))
            || !authorize(&mut repeats, other_true, Some("fixture-grant"))
            || !authorize(&mut repeats, demo_true_again, Some("fixture-grant"))
            || !dispatch(&mut repeats, demo_true)
            || dispatch(&mut repeats, demo_true_again)
            || step_state(&repeats, demo_true_again) != Some(StepState::Prepared)
            || !dispatch(&mut repeats, other_true)
            || !record_run_result(
                &mut repeats,
                demo_true,
                0,
                "init: hello from vm smoke test",
                "",
            )
            || !dispatch(&mut repeats, demo_true_again)
            || !record_run_result(
                &mut repeats,
                other_true,
                0,
                "init: hello from vm smoke test",
                "",
            )
            || dispatch(&mut repeats, missing_third)
            || dispatch(&mut repeats, elsewhere_third)
            || step_state(&repeats, missing) != Some(StepState::SettlementUnknown)
            || step_state(&repeats, elsewhere_again) != Some(StepState::SettlementUnknown)
            || step_state(&repeats, missing_third) != Some(StepState::Prepared)
            || step_state(&repeats, elsewhere_third) != Some(StepState::Prepared)
            || !repeats.steps.iter().any(|step| {
                step.id == ready_fourth && step.state == StepState::Dispatched && !step.has_result
            })
            || !repeats
                .events
                .iter()
                .any(|node| node.text == "exit 0\ninit: hello from vm smoke test\n")
            || !repeats
                .events
                .iter()
                .any(|node| node.text == "exit 0\ntest result: ok\n")
            || !repeats
                .events
                .iter()
                .any(|node| node.text == "exit 101\ntest result: FAILED\n")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a different program freed a crash".to_string(),
            ));
        }
        let saved_hello = model_bytes(&repeats.events).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid("a different program freed a crash".to_string())
        })?;
        if saved_hello
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a different program freed a crash".to_string(),
            ));
        }
        let demo_false =
            propose_run(&mut repeats, project, &["false".to_string()]).map_err(|_| {
                elastos::bus::types::BusError::Invalid("a failed program freed a crash".to_string())
            })?;
        let other_false = propose_run(
            &mut repeats,
            "localhost://Users/self/Projects/other",
            &["false".to_string()],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("a failed program freed a crash".to_string())
        })?;
        let demo_false_again =
            propose_run(&mut repeats, project, &["false".to_string()]).map_err(|_| {
                elastos::bus::types::BusError::Invalid("a failed program freed a crash".to_string())
            })?;
        if !authorize(&mut repeats, demo_false, Some("fixture-grant"))
            || !authorize(&mut repeats, other_false, Some("fixture-grant"))
            || !authorize(&mut repeats, demo_false_again, Some("fixture-grant"))
            || !dispatch(&mut repeats, demo_false)
            || dispatch(&mut repeats, demo_false_again)
            || step_state(&repeats, demo_false_again) != Some(StepState::Prepared)
            || !dispatch(&mut repeats, other_false)
            || record_run_result(
                &mut repeats,
                demo_false,
                0,
                "init: hello from vm smoke test",
                "",
            )
            || record_run_result(&mut repeats, demo_true_again, 1, "init: command failed", "")
            || !record_run_result(&mut repeats, demo_false, 1, "init: command failed", "")
            || !dispatch(&mut repeats, demo_false_again)
            || !record_run_result(&mut repeats, other_false, 1, "init: command failed", "")
            || dispatch(&mut repeats, missing_third)
            || dispatch(&mut repeats, elsewhere_third)
            || step_state(&repeats, missing) != Some(StepState::SettlementUnknown)
            || step_state(&repeats, elsewhere_again) != Some(StepState::SettlementUnknown)
            || step_state(&repeats, missing_third) != Some(StepState::Prepared)
            || step_state(&repeats, elsewhere_third) != Some(StepState::Prepared)
            || !repeats.steps.iter().any(|step| {
                step.id == ready_fourth && step.state == StepState::Dispatched && !step.has_result
            })
            || !repeats.steps.iter().any(|step| {
                step.id == demo_true_again
                    && step.state == StepState::Dispatched
                    && !step.has_result
            })
            || !repeats
                .events
                .iter()
                .any(|node| node.text == "exit 1\ninit: command failed\n")
            || !repeats
                .events
                .iter()
                .any(|node| node.text == "exit 0\ninit: hello from vm smoke test\n")
            || !repeats
                .events
                .iter()
                .any(|node| node.text == "exit 0\ntest result: ok\n")
            || !repeats
                .events
                .iter()
                .any(|node| node.text == "exit 101\ntest result: FAILED\n")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a failed program freed a crash".to_string(),
            ));
        }
        let saved_failed = model_bytes(&repeats.events).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid("a failed program freed a crash".to_string())
        })?;
        if saved_failed
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a failed program freed a crash".to_string(),
            ));
        }
        let edited = propose_run(
            &mut repeats,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_was_edited".to_string(),
            ],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid(
                "an unread note closed the edited test".to_string(),
            )
        })?;
        let edited_again = propose_run(
            &mut repeats,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_was_edited".to_string(),
            ],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid(
                "an unread note closed the edited test".to_string(),
            )
        })?;
        if !authorize(&mut repeats, edited, Some("fixture-grant"))
            || !authorize(&mut repeats, edited_again, Some("fixture-grant"))
            || !dispatch(&mut repeats, edited)
            || dispatch(&mut repeats, edited_again)
            || step_state(&repeats, edited_again) != Some(StepState::Prepared)
            || record_run_result(
                &mut repeats,
                edited,
                0,
                "project note hello from the project\ntest result: ok",
                "",
            )
            || record_run_result(
                &mut repeats,
                ready_fourth,
                0,
                "project note hello from the project\ntest result: ok",
                "",
            )
            || !record_run_result(&mut repeats, edited, 0, "test result: ok", "")
            || !dispatch(&mut repeats, edited_again)
            || dispatch(&mut repeats, missing_third)
            || dispatch(&mut repeats, elsewhere_third)
            || step_state(&repeats, missing) != Some(StepState::SettlementUnknown)
            || step_state(&repeats, elsewhere_again) != Some(StepState::SettlementUnknown)
            || step_state(&repeats, missing_third) != Some(StepState::Prepared)
            || step_state(&repeats, elsewhere_third) != Some(StepState::Prepared)
            || !repeats.steps.iter().any(|step| {
                step.id == ready_fourth && step.state == StepState::Dispatched && !step.has_result
            })
            || !repeats.steps.iter().any(|step| {
                step.id == demo_true_again
                    && step.state == StepState::Dispatched
                    && !step.has_result
            })
            || !repeats.steps.iter().any(|step| {
                step.id == demo_false_again
                    && step.state == StepState::Dispatched
                    && !step.has_result
            })
            || !repeats
                .steps
                .iter()
                .any(|step| step.id == edited && step.has_result)
            || repeats
                .events
                .iter()
                .any(|node| node.text.contains("hello from the project"))
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "an unread note closed the edited test".to_string(),
            ));
        }
        let saved_edited = model_bytes(&repeats.events).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid(
                "an unread note closed the edited test".to_string(),
            )
        })?;
        if saved_edited
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "an unread note closed the edited test".to_string(),
            ));
        }
        let notes = format!("{project}/notes.txt");
        if !observe(&mut repeats, &notes, 1, "hello from the project")
            || record_run_result(
                &mut repeats,
                edited_again,
                0,
                "project note hello again\ntest result: ok",
                "",
            )
            || record_run_result(
                &mut repeats,
                edited_again,
                0,
                "project note /tmp/out\ntest result: ok",
                "",
            )
            || !record_run_result(
                &mut repeats,
                edited_again,
                0,
                "project note hello from the project\ntest result: ok",
                "",
            )
            || dispatch(&mut repeats, missing_third)
            || dispatch(&mut repeats, elsewhere_third)
            || step_state(&repeats, missing) != Some(StepState::SettlementUnknown)
            || step_state(&repeats, missing_third) != Some(StepState::Prepared)
            || !repeats.steps.iter().any(|step| {
                step.id == ready_fourth && step.state == StepState::Dispatched && !step.has_result
            })
            || !repeats
                .steps
                .iter()
                .any(|step| step.id == edited_again && step.has_result)
            || current_observed_text(&repeats.events, &notes).as_deref()
                != Some("hello from the project")
            || !repeats.events.iter().any(|node| {
                node.text == "exit 0\nproject note hello from the project\ntest result: ok\n"
            })
            || repeats
                .events
                .iter()
                .any(|node| node.text.contains("hello again") || node.text.contains("/tmp"))
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a read note was refused".to_string(),
            ));
        }
        let saved_note = model_bytes(&repeats.events).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid("a read note was refused".to_string())
        })?;
        if saved_note
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a read note was refused".to_string(),
            ));
        }
        let files_again =
            propose_run(&mut repeats, project, &["files".to_string()]).map_err(|_| {
                elastos::bus::types::BusError::Invalid(
                    "the file list named a file that was not read".to_string(),
                )
            })?;
        let other_files = propose_run(
            &mut repeats,
            "localhost://Users/self/Projects/other",
            &["files".to_string()],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid(
                "the file list named a file that was not read".to_string(),
            )
        })?;
        if !authorize(&mut repeats, files_again, Some("fixture-grant"))
            || !authorize(&mut repeats, other_files, Some("fixture-grant"))
            || dispatch(&mut repeats, files_again)
            || step_state(&repeats, files_again) != Some(StepState::Prepared)
            || !dispatch(&mut repeats, other_files)
            || record_run_result(&mut repeats, second, 0, "project file style.css", "")
            || record_run_result(&mut repeats, second, 0, "project file /tmp/out", "")
            || record_run_result(
                &mut repeats,
                second,
                0,
                "project file notes.txt\nproject note hello from the project",
                "",
            )
            || record_run_result(&mut repeats, other_files, 0, "project file notes.txt", "")
            || !record_run_result(&mut repeats, second, 0, "project file notes.txt", "")
            || !dispatch(&mut repeats, files_again)
            || dispatch(&mut repeats, missing_third)
            || step_state(&repeats, missing) != Some(StepState::SettlementUnknown)
            || step_state(&repeats, missing_third) != Some(StepState::Prepared)
            || !repeats.steps.iter().any(|step| {
                step.id == ready_fourth && step.state == StepState::Dispatched && !step.has_result
            })
            || !repeats.steps.iter().any(|step| {
                step.id == other && step.state == StepState::Dispatched && !step.has_result
            })
            || !repeats.steps.iter().any(|step| {
                step.id == other_files && step.state == StepState::Dispatched && !step.has_result
            })
            || !repeats
                .steps
                .iter()
                .any(|step| step.id == second && step.has_result)
            || current_observed_text(&repeats.events, &notes).as_deref()
                != Some("hello from the project")
            || !repeats
                .events
                .iter()
                .any(|node| node.text == "exit 0\nproject file notes.txt\n")
            || repeats.events.iter().any(|node| {
                node.text.contains("style.css")
                    || node.text.contains("/tmp")
                    || node.text.contains("hello again")
            })
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the file list named a file that was not read".to_string(),
            ));
        }
        let saved_files = model_bytes(&repeats.events).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid(
                "the file list named a file that was not read".to_string(),
            )
        })?;
        if saved_files
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the file list named a file that was not read".to_string(),
            ));
        }
        let style = format!("{project}/style.css");
        if !observe(&mut repeats, &style, 1, "body{}")
            || record_run_result(&mut repeats, files_again, 0, "project file notes.txt", "")
            || record_run_result(&mut repeats, files_again, 0, "project file style.css", "")
            || record_run_result(&mut repeats, files_again, 0, "project file /tmp/out", "")
            || record_run_result(
                &mut repeats,
                other_files,
                0,
                "project file notes.txt\nproject file style.css",
                "",
            )
            || !record_run_result(
                &mut repeats,
                files_again,
                0,
                "project file notes.txt\nproject file style.css",
                "",
            )
            || dispatch(&mut repeats, missing_third)
            || step_state(&repeats, missing) != Some(StepState::SettlementUnknown)
            || step_state(&repeats, missing_third) != Some(StepState::Prepared)
            || !repeats.steps.iter().any(|step| {
                step.id == ready_fourth && step.state == StepState::Dispatched && !step.has_result
            })
            || !repeats.steps.iter().any(|step| {
                step.id == other_files && step.state == StepState::Dispatched && !step.has_result
            })
            || !repeats
                .steps
                .iter()
                .any(|step| step.id == files_again && step.has_result)
            || current_observed_text(&repeats.events, &notes).as_deref()
                != Some("hello from the project")
            || current_observed_text(&repeats.events, &style).as_deref() != Some("body{}")
            || !repeats
                .events
                .iter()
                .any(|node| node.text == "exit 0\nproject file notes.txt\nproject file style.css\n")
            || repeats
                .events
                .iter()
                .any(|node| node.text.contains("/tmp") || node.text.contains("hello again"))
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the file list dropped a file that was read".to_string(),
            ));
        }
        let saved_both_files = model_bytes(&repeats.events).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid(
                "the file list dropped a file that was read".to_string(),
            )
        })?;
        if saved_both_files
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the file list dropped a file that was read".to_string(),
            ));
        }
        let other_ready = propose_run(
            &mut repeats,
            "localhost://Users/self/Projects/other",
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid(
                "the ready test quoted an unread tree".to_string(),
            )
        })?;
        if !authorize(&mut repeats, other_ready, Some("fixture-grant"))
            || !dispatch(&mut repeats, other_ready)
            || record_run_result(
                &mut repeats,
                other_ready,
                0,
                "project demo f607cd5605c6829e1174580603daee9e7001676e56f4ab9b8dcd080349ca0c5b\ntest result: ok",
                "",
            )
            || record_run_result(
                &mut repeats,
                ready_fourth,
                0,
                "project demo 157af2e20c421bfaf3ac59d51f059bd9b8fb1cf2e40a2b45e8b898771ff938f5\ntest result: ok",
                "",
            )
            || record_run_result(
                &mut repeats,
                ready_fourth,
                0,
                "project demo a1097f0d6ed225ad16b19f19d6a260816af54c74bfe82b11e4ce2020233497f1\ntest result: ok",
                "",
            )
            || !record_run_result(
                &mut repeats,
                ready_fourth,
                0,
                "project demo f607cd5605c6829e1174580603daee9e7001676e56f4ab9b8dcd080349ca0c5b\ntest result: ok",
                "",
            )
            || dispatch(&mut repeats, missing_third)
            || step_state(&repeats, missing) != Some(StepState::SettlementUnknown)
            || step_state(&repeats, missing_third) != Some(StepState::Prepared)
            || !repeats.steps.iter().any(|step| {
                step.id == other_ready && step.state == StepState::Dispatched && !step.has_result
            })
            || !repeats
                .steps
                .iter()
                .any(|step| step.id == ready_fourth && step.has_result)
            || current_observed_text(&repeats.events, &notes).as_deref()
                != Some("hello from the project")
            || current_observed_text(&repeats.events, &style).as_deref() != Some("body{}")
            || !repeats.events.iter().any(|node| {
                node.text == "exit 0\nproject demo f607cd5605c6829e1174580603daee9e7001676e56f4ab9b8dcd080349ca0c5b\ntest result: ok\n"
            })
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the ready test quoted an unread tree".to_string(),
            ));
        }
        let saved_digest = model_bytes(&repeats.events).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid(
                "the ready test quoted an unread tree".to_string(),
            )
        })?;
        if saved_digest
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the ready test quoted an unread tree".to_string(),
            ));
        }
        let ready_fifth = propose_run(
            &mut repeats,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid(
                "the old digest survived the stylesheet".to_string(),
            )
        })?;
        if !observe(&mut repeats, &style, 2, "h1{}")
            || !authorize(&mut repeats, ready_fifth, Some("fixture-grant"))
            || !dispatch(&mut repeats, ready_fifth)
            || record_run_result(
                &mut repeats,
                ready_fifth,
                0,
                "project demo f607cd5605c6829e1174580603daee9e7001676e56f4ab9b8dcd080349ca0c5b\ntest result: ok",
                "",
            )
            || !record_run_result(
                &mut repeats,
                ready_fifth,
                0,
                "project demo d2cfc9d2f96f98ccb4eb283d6bb1ae49bb9ce7e3cdd7463eb190085ab6eedae1\ntest result: ok",
                "",
            )
            || dispatch(&mut repeats, missing_third)
            || step_state(&repeats, missing) != Some(StepState::SettlementUnknown)
            || step_state(&repeats, missing_third) != Some(StepState::Prepared)
            || !repeats
                .steps
                .iter()
                .any(|step| step.id == ready_fifth && step.has_result)
            || current_observed_text(&repeats.events, &notes).as_deref()
                != Some("hello from the project")
            || current_observed_text(&repeats.events, &style).as_deref() != Some("h1{}")
            || !repeats.events.iter().any(|node| {
                node.text == "exit 0\nproject demo d2cfc9d2f96f98ccb4eb283d6bb1ae49bb9ce7e3cdd7463eb190085ab6eedae1\ntest result: ok\n"
            })
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the old digest survived the stylesheet".to_string(),
            ));
        }
        let saved_style = model_bytes(&repeats.events).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid(
                "the old digest survived the stylesheet".to_string(),
            )
        })?;
        if saved_style
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the old digest survived the stylesheet".to_string(),
            ));
        }
        let files_after =
            propose_run(&mut repeats, project, &["files".to_string()]).map_err(|_| {
                elastos::bus::types::BusError::Invalid(
                    "the file list dropped the rewritten stylesheet".to_string(),
                )
            })?;
        if !authorize(&mut repeats, files_after, Some("fixture-grant"))
            || !dispatch(&mut repeats, files_after)
            || record_run_result(&mut repeats, files_after, 0, "project file notes.txt", "")
            || !record_run_result(
                &mut repeats,
                files_after,
                0,
                "project file notes.txt\nproject file style.css",
                "",
            )
            || dispatch(&mut repeats, missing_third)
            || step_state(&repeats, missing) != Some(StepState::SettlementUnknown)
            || current_observed_text(&repeats.events, &style).as_deref() != Some("h1{}")
            || !repeats
                .steps
                .iter()
                .any(|step| step.id == files_after && step.has_result)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the file list dropped the rewritten stylesheet".to_string(),
            ));
        }
        let files_unread =
            propose_run(&mut repeats, project, &["files".to_string()]).map_err(|_| {
                elastos::bus::types::BusError::Invalid(
                    "an unread file entered the list".to_string(),
                )
            })?;
        if !authorize(&mut repeats, files_unread, Some("fixture-grant"))
            || !dispatch(&mut repeats, files_unread)
            || record_run_result(
                &mut repeats,
                files_unread,
                0,
                "project file notes.txt\nproject file style.css\nproject file index.html",
                "",
            )
            || record_run_result(
                &mut repeats,
                other_files,
                0,
                "project file notes.txt\nproject file style.css",
                "",
            )
            || !record_run_result(
                &mut repeats,
                files_unread,
                0,
                "project file notes.txt\nproject file style.css",
                "",
            )
            || dispatch(&mut repeats, missing_third)
            || step_state(&repeats, missing) != Some(StepState::SettlementUnknown)
            || !repeats.steps.iter().any(|step| {
                step.id == other_files && step.state == StepState::Dispatched && !step.has_result
            })
            || !repeats
                .steps
                .iter()
                .any(|step| step.id == files_unread && step.has_result)
            || current_observed_text(&repeats.events, &style).as_deref() != Some("h1{}")
            || repeats
                .events
                .iter()
                .any(|node| node.text.contains("index.html"))
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "an unread file entered the list".to_string(),
            ));
        }
        let page = format!("{project}/index.html");
        let files_page =
            propose_run(&mut repeats, project, &["files".to_string()]).map_err(|_| {
                elastos::bus::types::BusError::Invalid(
                    "the page was read and left out of the list".to_string(),
                )
            })?;
        let ready_page = propose_run(
            &mut repeats,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid(
                "the page was read and left out of the list".to_string(),
            )
        })?;
        if !observe(&mut repeats, &page, 1, "<h1>demo</h1>")
            || !authorize(&mut repeats, files_page, Some("fixture-grant"))
            || !authorize(&mut repeats, ready_page, Some("fixture-grant"))
            || !dispatch(&mut repeats, files_page)
            || !dispatch(&mut repeats, ready_page)
            || record_run_result(
                &mut repeats,
                files_page,
                0,
                "project file notes.txt\nproject file style.css",
                "",
            )
            || record_run_result(
                &mut repeats,
                other_files,
                0,
                "project file notes.txt\nproject file style.css\nproject file index.html",
                "",
            )
            || !record_run_result(
                &mut repeats,
                files_page,
                0,
                "project file notes.txt\nproject file style.css\nproject file index.html",
                "",
            )
            || record_run_result(
                &mut repeats,
                ready_page,
                0,
                "project demo d2cfc9d2f96f98ccb4eb283d6bb1ae49bb9ce7e3cdd7463eb190085ab6eedae1\ntest result: ok",
                "",
            )
            || !record_run_result(
                &mut repeats,
                ready_page,
                0,
                "project demo e618ccee1e4be1e381946ef2476120157c4002b8f75895ed0d4c63c54d4ce79a\ntest result: ok",
                "",
            )
            || dispatch(&mut repeats, missing_third)
            || step_state(&repeats, missing) != Some(StepState::SettlementUnknown)
            || !repeats.steps.iter().any(|step| {
                step.id == other_files && step.state == StepState::Dispatched && !step.has_result
            })
            || !repeats
                .steps
                .iter()
                .any(|step| step.id == files_page && step.has_result)
            || !repeats
                .steps
                .iter()
                .any(|step| step.id == ready_page && step.has_result)
            || current_observed_text(&repeats.events, &page).as_deref() != Some("<h1>demo</h1>")
            || current_observed_text(&repeats.events, &style).as_deref() != Some("h1{}")
            || current_observed_text(&repeats.events, &notes).as_deref()
                != Some("hello from the project")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the page was read and left out of the list".to_string(),
            ));
        }
        let saved_page = model_bytes(&repeats.events).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid(
                "the page was read and left out of the list".to_string(),
            )
        })?;
        if saved_page
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the page was read and left out of the list".to_string(),
            ));
        }
        let ready_next = propose_run(
            &mut repeats,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid(
                "the rewritten page kept the old digest".to_string(),
            )
        })?;
        let files_next =
            propose_run(&mut repeats, project, &["files".to_string()]).map_err(|_| {
                elastos::bus::types::BusError::Invalid(
                    "the rewritten page kept the old digest".to_string(),
                )
            })?;
        if !observe(&mut repeats, &page, 2, "<h1>next</h1>")
            || !authorize(&mut repeats, ready_next, Some("fixture-grant"))
            || !authorize(&mut repeats, files_next, Some("fixture-grant"))
            || !dispatch(&mut repeats, ready_next)
            || !dispatch(&mut repeats, files_next)
            || record_run_result(
                &mut repeats,
                ready_next,
                0,
                "project demo e618ccee1e4be1e381946ef2476120157c4002b8f75895ed0d4c63c54d4ce79a\ntest result: ok",
                "",
            )
            || record_run_result(
                &mut repeats,
                files_next,
                0,
                "project file notes.txt\nproject file style.css",
                "",
            )
            || !record_run_result(
                &mut repeats,
                files_next,
                0,
                "project file notes.txt\nproject file style.css\nproject file index.html",
                "",
            )
            || !record_run_result(
                &mut repeats,
                ready_next,
                0,
                "project demo c96eb153a09434c8ed7149a8fd9044711a5215a20197f06179113a1b1530f761\ntest result: ok",
                "",
            )
            || dispatch(&mut repeats, missing_third)
            || step_state(&repeats, missing) != Some(StepState::SettlementUnknown)
            || current_observed_text(&repeats.events, &page).as_deref() != Some("<h1>next</h1>")
            || current_observed_text(&repeats.events, &notes).as_deref()
                != Some("hello from the project")
            || current_observed_text(&repeats.events, &style).as_deref() != Some("h1{}")
            || !repeats
                .steps
                .iter()
                .any(|step| step.id == ready_next && step.has_result)
            || !repeats
                .steps
                .iter()
                .any(|step| step.id == files_next && step.has_result)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the rewritten page kept the old digest".to_string(),
            ));
        }
        let saved_next = model_bytes(&repeats.events).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid(
                "the rewritten page kept the old digest".to_string(),
            )
        })?;
        if saved_next
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the rewritten page kept the old digest".to_string(),
            ));
        }
        let ready_older = propose_run(
            &mut repeats,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid(
                "the older page did not become current".to_string(),
            )
        })?;
        if observe(&mut repeats, &page, 2, "<h1>other</h1>")
            || current_observed_text(&repeats.events, &page).as_deref() != Some("<h1>next</h1>")
            || !observe(&mut repeats, &page, 1, "<h1>demo</h1>")
            || !authorize(&mut repeats, ready_older, Some("fixture-grant"))
            || !dispatch(&mut repeats, ready_older)
            || record_run_result(
                &mut repeats,
                ready_older,
                0,
                "project demo c96eb153a09434c8ed7149a8fd9044711a5215a20197f06179113a1b1530f761\ntest result: ok",
                "",
            )
            || !record_run_result(
                &mut repeats,
                ready_older,
                0,
                "project demo e618ccee1e4be1e381946ef2476120157c4002b8f75895ed0d4c63c54d4ce79a\ntest result: ok",
                "",
            )
            || dispatch(&mut repeats, missing_third)
            || step_state(&repeats, missing) != Some(StepState::SettlementUnknown)
            || current_observed_text(&repeats.events, &page).as_deref() != Some("<h1>demo</h1>")
            || observed_text_at(&repeats.events, &page, 2).as_deref() != Some("<h1>next</h1>")
            || current_observed_text(&repeats.events, &notes).as_deref()
                != Some("hello from the project")
            || !repeats
                .steps
                .iter()
                .any(|step| step.id == ready_older && step.has_result)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the older page did not become current".to_string(),
            ));
        }
        let saved_older = model_bytes(&repeats.events).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid(
                "the older page did not become current".to_string(),
            )
        })?;
        if saved_older
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the older page did not become current".to_string(),
            ));
        }
        let Some(resumed) = replay(&saved_older) else {
            return Err(elastos::bus::types::BusError::Invalid(
                "reading the log back lost the current page".to_string(),
            ));
        };
        if current_observed_text(&resumed, &page).as_deref() != Some("<h1>demo</h1>")
            || observed_text_at(&resumed, &page, 2).as_deref() != Some("<h1>next</h1>")
            || current_observed_text(&resumed, &notes).as_deref() != Some("hello from the project")
            || current_observed_text(&resumed, &style).as_deref() != Some("h1{}")
            || saved_older
                .windows(b"fixture-grant".len())
                .any(|window| window == b"fixture-grant")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "reading the log back lost the current page".to_string(),
            ));
        }
        let before_refusal = model_bytes(&repeats.events).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid("a host path joined the project".to_string())
        })?;
        if observe(&mut repeats, "/tmp/page.html", 1, "<h1>no</h1>")
            || observe(
                &mut repeats,
                "localhost://Users/self/Projects/demo/../index.html",
                1,
                "<h1>no</h1>",
            )
            || observe(
                &mut repeats,
                "localhost://Users/self/Projects/demo/my page",
                1,
                "<h1>no</h1>",
            )
            || observe(&mut repeats, "", 1, "<h1>no</h1>")
            || model_bytes(&repeats.events).as_ref() != Some(&before_refusal)
            || current_observed_text(&repeats.events, &page).as_deref() != Some("<h1>demo</h1>")
            || observed_text_at(&repeats.events, &page, 2).as_deref() != Some("<h1>next</h1>")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a host path joined the project".to_string(),
            ));
        }
        let files_clean =
            propose_run(&mut repeats, project, &["files".to_string()]).map_err(|_| {
                elastos::bus::types::BusError::Invalid("a host path joined the project".to_string())
            })?;
        let ready_clean = propose_run(
            &mut repeats,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid("a host path joined the project".to_string())
        })?;
        if !authorize(&mut repeats, files_clean, Some("fixture-grant"))
            || !authorize(&mut repeats, ready_clean, Some("fixture-grant"))
            || !dispatch(&mut repeats, files_clean)
            || !dispatch(&mut repeats, ready_clean)
            || record_run_result(&mut repeats, files_clean, 0, "project file /tmp/out", "")
            || record_run_result(
                &mut repeats,
                files_clean,
                0,
                "project file notes.txt\nproject file style.css",
                "",
            )
            || record_run_result(
                &mut repeats,
                ready_clean,
                0,
                "project demo c96eb153a09434c8ed7149a8fd9044711a5215a20197f06179113a1b1530f761\ntest result: ok",
                "",
            )
            || !record_run_result(
                &mut repeats,
                files_clean,
                0,
                "project file notes.txt\nproject file style.css\nproject file index.html",
                "",
            )
            || !record_run_result(
                &mut repeats,
                ready_clean,
                0,
                "project demo e618ccee1e4be1e381946ef2476120157c4002b8f75895ed0d4c63c54d4ce79a\ntest result: ok",
                "",
            )
            || compact(&mut repeats, COMPACTION_SUMMARY)
            || compact(&mut repeats, "/tmp/summary")
            || dispatch(&mut repeats, missing_third)
            || step_state(&repeats, missing) != Some(StepState::SettlementUnknown)
            || current_observed_text(&repeats.events, &page).as_deref() != Some("<h1>demo</h1>")
            || current_observed_text(&repeats.events, &notes).as_deref()
                != Some("hello from the project")
            || current_observed_text(&repeats.events, &style).as_deref() != Some("h1{}")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a host path joined the project".to_string(),
            ));
        }
        let saved_clean = model_bytes(&repeats.events).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid("a host path joined the project".to_string())
        })?;
        let Some(resumed_clean) = replay(&saved_clean) else {
            return Err(elastos::bus::types::BusError::Invalid(
                "a host path joined the project".to_string(),
            ));
        };
        if current_observed_text(&resumed_clean, &page).as_deref() != Some("<h1>demo</h1>")
            || observed_text_at(&resumed_clean, &page, 2).as_deref() != Some("<h1>next</h1>")
            || saved_clean
                .windows(b"fixture-grant".len())
                .any(|window| window == b"fixture-grant")
            || saved_clean
                .windows(b"/tmp".len())
                .any(|window| window == b"/tmp")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a host path joined the project".to_string(),
            ));
        }
        let epoch_before = repeats.epoch;
        admit_system(&mut repeats, SYSTEM_HEAD, false);
        if system_head(&repeats.events) != Some(SYSTEM_HEAD)
            || repeats
                .events
                .first()
                .is_none_or(|node| node.role != Role::System || node.source != NodeSource::Head)
            || repeats.epoch <= epoch_before
            || !compact(&mut repeats, COMPACTION_SUMMARY)
            || system_head(&repeats.events) != Some(SYSTEM_HEAD)
            || compact(&mut repeats, COMPACTION_SUMMARY)
            || compact(&mut repeats, "")
            || compact(&mut repeats, "/tmp/summary")
            || current_observed_text(&repeats.events, &page).as_deref() != Some("<h1>demo</h1>")
            || observed_text_at(&repeats.events, &page, 2).as_deref() != Some("<h1>next</h1>")
            || current_observed_text(&repeats.events, &notes).as_deref()
                != Some("hello from the project")
            || current_observed_text(&repeats.events, &style).as_deref() != Some("h1{}")
            || step_state(&repeats, missing) != Some(StepState::SettlementUnknown)
            || dispatch(&mut repeats, missing_third)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "shortening dropped the current page".to_string(),
            ));
        }
        let files_kept =
            propose_run(&mut repeats, project, &["files".to_string()]).map_err(|_| {
                elastos::bus::types::BusError::Invalid(
                    "shortening dropped the current page".to_string(),
                )
            })?;
        let ready_kept = propose_run(
            &mut repeats,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .map_err(|_| {
            elastos::bus::types::BusError::Invalid(
                "shortening dropped the current page".to_string(),
            )
        })?;
        if !authorize(&mut repeats, files_kept, Some("fixture-grant"))
            || !authorize(&mut repeats, ready_kept, Some("fixture-grant"))
            || !dispatch(&mut repeats, files_kept)
            || !dispatch(&mut repeats, ready_kept)
            || record_run_result(
                &mut repeats,
                files_kept,
                0,
                "project file notes.txt\nproject file style.css",
                "",
            )
            || record_run_result(
                &mut repeats,
                ready_kept,
                0,
                "project demo c96eb153a09434c8ed7149a8fd9044711a5215a20197f06179113a1b1530f761\ntest result: ok",
                "",
            )
            || !record_run_result(
                &mut repeats,
                files_kept,
                0,
                "project file notes.txt\nproject file style.css\nproject file index.html",
                "",
            )
            || !record_run_result(
                &mut repeats,
                ready_kept,
                0,
                "project demo e618ccee1e4be1e381946ef2476120157c4002b8f75895ed0d4c63c54d4ce79a\ntest result: ok",
                "",
            )
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "shortening dropped the current page".to_string(),
            ));
        }
        let saved_short = model_bytes(&repeats.events).ok_or_else(|| {
            elastos::bus::types::BusError::Invalid(
                "shortening dropped the current page".to_string(),
            )
        })?;
        let Some(resumed_short) = replay(&saved_short) else {
            return Err(elastos::bus::types::BusError::Invalid(
                "shortening dropped the current page".to_string(),
            ));
        };
        if system_head(&resumed_short) != Some(SYSTEM_HEAD)
            || current_observed_text(&resumed_short, &page).as_deref() != Some("<h1>demo</h1>")
            || observed_text_at(&resumed_short, &page, 2).as_deref() != Some("<h1>next</h1>")
            || saved_short
                .windows(b"fixture-grant".len())
                .any(|window| window == b"fixture-grant")
            || saved_short
                .windows(b"/tmp".len())
                .any(|window| window == b"/tmp")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "shortening dropped the current page".to_string(),
            ));
        }
        let epoch_for_list = repeats.epoch;
        let listed = version_list(&repeats.events, &page);
        if listed
            != [
                (1, "<h1>demo</h1>".to_string()),
                (2, "<h1>next</h1>".to_string()),
            ]
            || !version_list(&repeats.events, "/tmp/page.html").is_empty()
            || !version_list(&repeats.events, "").is_empty()
            || repeats.epoch != epoch_for_list
            || propose_restore(&mut repeats, &page, 2) != Err("stale")
            || current_observed_text(&repeats.events, &page).as_deref() != Some("<h1>demo</h1>")
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the version list granted a restore".to_string(),
            ));
        }
        let restore = propose_restore(&mut repeats, &page, 1).map_err(|_| {
            elastos::bus::types::BusError::Invalid("the version list granted a restore".to_string())
        })?;
        if !repeats.steps.iter().any(|step| {
            step.id == restore
                && step.kind == ProposalKind::Restore
                && step.new == "<h1>demo</h1>"
                && step.grant.is_none()
                && step.state == StepState::Prepared
        }) || dispatch(&mut repeats, restore)
            || step_state(&repeats, restore) != Some(StepState::Denied)
            || current_observed_text(&repeats.events, &page).as_deref() != Some("<h1>demo</h1>")
            || observed_text_at(&repeats.events, &page, 2).as_deref() != Some("<h1>next</h1>")
            || step_state(&repeats, missing) != Some(StepState::SettlementUnknown)
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "the version list granted a restore".to_string(),
            ));
        }
        let stored = encode_journal(&journal, &[0; 32]);
        let resumed = stored.as_deref().map(decode_journal);
        if !matches!(
            &resumed,
            Some(Ok((back, prev, _))) if *back == without_grants(&journal) && *prev == [0; 32]
        ) {
            return Err(elastos::bus::types::BusError::Invalid(
                "the journal did not round-trip through format 1".to_string(),
            ));
        }
        // With no launch grant, the append is denied and nothing is sent.
        let mut cursor = journal_cursor("agent-host", "demo").map_err(|_| {
            elastos::bus::types::BusError::Invalid("the journal id was refused".to_string())
        })?;
        let grant = launch_grant();
        let appended = append_journal(&mut WasmBus, &mut journal, &mut cursor, grant.as_ref());
        if appended != AppendOutcome::Denied
            || resume_journal(&mut WasmBus, &mut journal, &mut cursor, grant.as_ref())
                != ResumeOutcome::Nothing
            || cursor.pending.is_some()
            || cursor.revision.is_some()
            || !journal.steps.last().is_some_and(|step| {
                step.kind == ProposalKind::JournalAppend && step.state == StepState::Denied
            })
        {
            return Err(elastos::bus::types::BusError::Invalid(
                "a journal append without a launch grant was sent".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
export!(AgentHost);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_turn_returns_a_turn_id_and_leaves_the_epoch() {
        let mut journal = empty_journal();
        let before = model_bytes(&journal.events);
        let first = open_turn(&mut journal);
        let second = open_turn(&mut journal);
        assert_eq!(first, 1);
        assert_eq!(second, 2);
        assert_eq!(journal.epoch, 0);
        assert_ne!(first, journal.epoch);
        assert!(journal.turns.iter().all(|turn| turn.steps.is_empty()));
        assert_eq!(model_bytes(&journal.events).as_ref(), before.as_ref());

        let mut folded = two_turns();
        assert!(compact(&mut folded, COMPACTION_SUMMARY));
        let epoch = folded.epoch;
        let bytes = model_bytes(&folded.events);
        let turn_id = open_turn(&mut folded);
        assert_eq!(turn_id, 1);
        assert_ne!(turn_id, folded.epoch);
        assert_eq!(folded.epoch, epoch);
        assert_eq!(model_bytes(&folded.events).as_ref(), bytes.as_ref());
    }

    #[test]
    fn two_steps_in_one_turn_share_the_epoch_and_derive_omits_the_markers() {
        let mut journal = two_turns();
        let epoch = journal.epoch;
        let before = model_bytes(&journal.events).unwrap();
        let turn_id = open_turn(&mut journal);
        let first = open_step(&mut journal, turn_id).unwrap();
        let second = open_step(&mut journal, turn_id).unwrap();
        assert!(open_step(&mut journal, 99).is_none());
        assert_eq!(journal.turns[0].steps, vec![first, second]);
        assert_eq!(journal.epoch, epoch);
        assert_eq!(model_bytes(&journal.events).unwrap(), before);
        assert_eq!(step_state(&journal, first), Some(StepState::Prepared));
        assert_eq!(step_state(&journal, second), Some(StepState::Prepared));

        let mut mixed = journal.events.clone();
        mixed.extend(journal.markers.clone());
        let view = derive(&mixed);
        assert_eq!(view, journal.events);
        assert!(derive(&journal.markers).is_empty());
        let marker_bytes = model_bytes(&journal.markers).unwrap();
        assert_eq!(replay(&marker_bytes).unwrap(), journal.markers);
        assert_ne!(marker_bytes, before);
    }

    #[test]
    fn assistant_and_tool_result_tags_replay_together() {
        let mut journal = two_turns();
        let epoch = journal.epoch;
        let head = journal.events[0].text.clone();
        admit_assistant(&mut journal, "");
        admit_assistant(&mut journal, "The head stays.");
        admit_tool_result(&mut journal, "The result is recorded.");
        assert_eq!(journal.epoch, epoch);
        assert_eq!(journal.events[0].text, head);
        let bytes = model_bytes(&journal.events).unwrap();
        let restored = replay(&bytes).unwrap();
        assert_eq!(restored, journal.events);
        let view = derive(&journal.events);
        assert_eq!(
            view.iter()
                .filter(|node| node.role == Role::Assistant)
                .map(|node| node.text.as_str())
                .collect::<Vec<_>>(),
            vec!["The head stays."]
        );
        assert!(view.iter().any(|node| node.role == Role::ToolResult));
        assert!(bytes.contains(&role_tag(Role::Assistant)));
        assert!(bytes.contains(&role_tag(Role::ToolResult)));
        assert_eq!(
            restored
                .iter()
                .filter(|node| node.role == Role::Assistant)
                .map(|node| node.text.as_str())
                .collect::<Vec<_>>(),
            vec!["", "The head stays."]
        );
        assert_eq!(
            restored
                .iter()
                .find(|node| node.role == Role::ToolResult)
                .map(|node| node.text.as_str()),
            Some("The result is recorded.")
        );
        assert!(replay(&[5, 2, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn a_tool_result_enters_the_view_and_a_step_without_one_stays_in_the_log() {
        let mut journal = two_turns();
        let epoch = journal.epoch;
        let before = model_bytes(&journal.events).unwrap();
        let turn_id = open_turn(&mut journal);
        let done = open_step(&mut journal, turn_id).unwrap();
        let waiting = open_step(&mut journal, turn_id).unwrap();
        assert_eq!(model_bytes(&journal.events).unwrap(), before);
        assert_eq!(
            replay(&model_bytes(&journal.markers).unwrap()).unwrap(),
            journal.markers
        );
        assert!(derive(&journal.markers).is_empty());
        assert!(record_tool_result(
            &mut journal,
            done,
            "note.txt has one line."
        ));
        let after_one = journal.events.clone();
        assert!(!record_tool_result(&mut journal, done, "a second result"));
        assert!(!record_tool_result(&mut journal, 0, "a missing step"));
        assert_eq!(journal.events, after_one);
        assert_eq!(journal.epoch, epoch);
        assert!(journal
            .steps
            .iter()
            .find(|step| step.id == done)
            .is_some_and(|step| step.has_result));
        assert!(journal
            .steps
            .iter()
            .find(|step| step.id == waiting)
            .is_some_and(|step| !step.has_result));
        let bytes = model_bytes(&journal.events).unwrap();
        assert_eq!(replay(&bytes).unwrap(), journal.events);
        assert!(derive(&journal.events).iter().any(|node| {
            node.role == Role::ToolResult && node.text == "note.txt has one line."
        }));
        assert!(journal.markers.iter().any(|node| {
            node.source == NodeSource::StepMarker && node.text == waiting.to_string()
        }));
        let mut mixed = journal.events.clone();
        mixed.extend(journal.markers.clone());
        assert!(derive(&mixed).iter().all(|node| {
            !matches!(node.source, NodeSource::TurnMarker | NodeSource::StepMarker)
        }));
    }

    #[test]
    fn an_empty_assistant_stays_in_the_log_and_drops_out_of_the_view() {
        let mut journal = two_turns();
        let before = journal.events.clone();
        admit_assistant(&mut journal, "");
        admit_tool_result(&mut journal, "");
        admit_assistant(&mut journal, "Still visible.");
        let bytes = model_bytes(&journal.events).unwrap();
        assert_eq!(replay(&bytes).unwrap(), journal.events);
        let view = derive(&journal.events);
        assert_eq!(&view[..before.len()], before.as_slice());
        assert_eq!(view.len(), journal.events.len() - 1);
        assert!(view
            .iter()
            .any(|node| { node.role == Role::ToolResult && node.text.is_empty() }));
        assert!(view
            .iter()
            .any(|node| node.role == Role::Assistant && node.text == "Still visible."));
        assert!(view
            .iter()
            .all(|node| !(node.role == Role::Assistant && node.text.is_empty())));
    }

    #[test]
    fn user_text_leaves_the_system_head_unchanged() {
        let journal = one_turn();
        let head = system_head(&journal.events).unwrap().to_string();
        let mut extended = journal.clone();
        admit_user(&mut extended, "and another line");
        assert_eq!(system_head(&extended.events), Some(head.as_str()));
        assert_eq!(derive(&extended.events).len(), 4);
        assert_eq!(extended.epoch, 1);
    }

    #[test]
    fn an_in_history_prompt_appends_after_the_head() {
        let journal = one_turn();
        assert_eq!(system_head(&journal.events), Some(SYSTEM_HEAD));
        assert_eq!(journal.events.len(), 3);
        assert_eq!(journal.epoch, 1);
        assert_eq!(journal.events[2].role, Role::System);
        assert_eq!(journal.events[2].text, "Reply in one short paragraph.");
    }

    #[test]
    fn a_second_turn_appends_and_keeps_the_system_head() {
        let first = one_turn();
        let second = two_turns();
        assert_eq!(
            second.events[0].text.as_bytes(),
            first.events[0].text.as_bytes()
        );
        assert_eq!(second.events[0].text, SYSTEM_HEAD);
        assert_eq!(second.epoch, first.epoch);
        assert_eq!(derive(&second.events).len(), 5);
        assert_eq!(second.events[3].role, Role::User);
        assert_eq!(second.events[3].text, "second turn");
        assert_eq!(second.events[4].role, Role::System);
        assert_eq!(
            second.events[4].text,
            "Keep the first system line unchanged."
        );
    }

    #[test]
    fn the_same_head_text_does_not_start_a_new_series() {
        let mut journal = one_turn();
        admit_system(&mut journal, SYSTEM_HEAD, false);
        assert_eq!(journal.epoch, 1);
        assert_eq!(journal.events.len(), 3);
        assert_eq!(system_head(&journal.events), Some(SYSTEM_HEAD));
    }

    #[test]
    fn an_incapable_prompt_rewrites_the_head_and_starts_a_series() {
        let mut journal = one_turn();
        admit_system(&mut journal, "Replacement head.", false);
        assert_eq!(system_head(&journal.events), Some("Replacement head."));
        assert_eq!(journal.epoch, 2);
        assert_eq!(
            journal
                .events
                .iter()
                .filter(|event| event.role == Role::System)
                .count(),
            2
        );
    }

    #[test]
    fn compaction_keeps_node_zero_and_starts_a_new_series() {
        let mut journal = two_turns();
        let head = journal.events[0].text.clone();
        assert!(compact(&mut journal, COMPACTION_SUMMARY));
        assert_eq!(journal.events[0].text.as_bytes(), head.as_bytes());
        assert_eq!(journal.events.len(), 2);
        assert_eq!(journal.events[1].role, Role::User);
        assert_eq!(journal.events[1].source, NodeSource::CompactionCheckpoint);
        assert_eq!(journal.events[1].text, COMPACTION_SUMMARY);
        assert_eq!(journal.epoch, 2);
    }

    #[test]
    fn compaction_summary_is_a_user_checkpoint() {
        let mut journal = two_turns();
        let head = journal.events[0].clone();
        assert!(compact(&mut journal, COMPACTION_SUMMARY));
        assert_eq!(journal.events[0], head);
        assert_eq!(journal.events[1].role, Role::User);
        assert_eq!(journal.events[1].source, NodeSource::CompactionCheckpoint);
        let recorded = model_bytes(&journal.events).unwrap();
        let restored = replay(&recorded).unwrap();
        assert_eq!(restored, journal.events);
        assert_eq!(derive(&journal.events), journal.events);
        assert_eq!(
            derive(&journal.events)[1].source,
            NodeSource::CompactionCheckpoint
        );
    }

    #[test]
    fn a_crash_during_compaction_restores_the_saved_bytes() {
        let mut journal = two_turns();
        let skill = "Prefer the Runtime grant.";
        assert!(admit_skill(&mut journal, skill));
        let before = journal.clone();
        assert!(begin_compact(&mut journal, COMPACTION_SUMMARY));
        assert!(journal.compaction_open);
        assert_eq!(journal.events, before.events);
        assert_eq!(journal.epoch, before.epoch);
        assert!(!begin_compact(&mut journal, COMPACTION_SUMMARY));
        assert_eq!(journal.events, before.events);
        assert!(note_crash_during_compact(&mut journal));
        assert!(!journal.compaction_open);
        assert!(journal.compact_backup.is_none());
        assert!(journal.compact_pending.is_none());
        assert_eq!(journal.events, before.events);
        assert_eq!(journal.epoch, before.epoch);
        assert!(!note_crash_during_compact(&mut journal));
        assert!(!commit_compact(&mut journal));
        assert_eq!(journal.events, before.events);

        assert!(begin_compact(&mut journal, COMPACTION_SUMMARY));
        assert!(commit_compact(&mut journal));
        assert!(!journal.compaction_open);
        assert_eq!(journal.epoch, before.epoch + 1);
        assert_eq!(journal.events[0], before.events[0]);
        assert_eq!(journal.events[1].source, NodeSource::CompactionCheckpoint);
        assert!(journal
            .events
            .iter()
            .any(|node| { node.source == NodeSource::Skill && node.text == skill }));
        assert!(!commit_compact(&mut journal));
    }

    #[test]
    fn an_observation_stays_in_the_log_and_out_of_the_view() {
        assert_eq!(
            sha256(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
        assert_eq!(
            sha256(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
        let resource = "localhost://Users/self/Documents/note.txt";
        let mut journal = empty_journal();
        assert!(!observe(&mut journal, "", 1, "one line"));
        assert!(!observe(&mut journal, "/tmp/secret", 1, "one line"));
        assert!(!observe(
            &mut journal,
            "localhost://Users/self/../Documents/note.txt",
            1,
            "one line"
        ));
        assert!(!observe(
            &mut journal,
            "localhost://Users/self/Documents/a note.txt",
            1,
            "one line"
        ));
        assert!(journal.events.is_empty());
        assert!(observe(&mut journal, resource, 1, "one line"));
        assert!(!observe(&mut journal, resource, 1, "replaced"));
        assert_eq!(
            current_observed_text(&journal.events, resource).as_deref(),
            Some("one line")
        );
        assert_eq!(journal.epoch, 0);
        let first = model_bytes(&journal.events).unwrap();
        assert_eq!(replay(&first).unwrap(), journal.events);
        assert!(derive(&journal.events).is_empty());
        assert_eq!(
            current_observation(&replay(&first).unwrap(), resource).unwrap(),
            Observation {
                resource: resource.to_string(),
                version: 1,
                text_hash: sha256(b"one line"),
            }
        );
        assert!(observe(&mut journal, resource, 2, "two lines"));
        assert_eq!(journal.events.len(), 2);
        assert_eq!(
            current_observation(&journal.events, resource)
                .unwrap()
                .version,
            2
        );
        assert_eq!(read_observation(&journal.events[0]).unwrap().version, 1);
        assert!(derive(&journal.events).is_empty());
    }

    #[test]
    fn an_unread_or_stale_edit_creates_no_step() {
        let resource = "localhost://Users/self/Documents/note.txt";
        let mut journal = empty_journal();
        let before = journal.clone();
        assert_eq!(
            propose_edit(&mut journal, resource, "one", "two", Some(1)),
            Err("not observed")
        );
        assert_eq!(journal, before);
        assert!(observe(&mut journal, resource, 1, "one line"));
        assert!(observe(&mut journal, resource, 2, "two lines"));
        let observed = journal.clone();
        assert_eq!(
            propose_edit(&mut journal, resource, "two", "three", Some(1)),
            Err("stale")
        );
        assert_eq!(
            propose_edit(&mut journal, resource, "two", "three", None),
            Err("stale")
        );
        assert_eq!(
            propose_edit(&mut journal, resource, "", "three", Some(2)),
            Err("empty")
        );
        assert_eq!(journal, observed);
        let id = propose_edit(&mut journal, resource, "two", "three", Some(2)).unwrap();
        let step = journal.steps.iter().find(|step| step.id == id).unwrap();
        assert_eq!(step.kind, ProposalKind::Edit);
        assert_eq!(step.state, StepState::Prepared);
        assert_eq!(step.resource, resource);
        assert_eq!(step.old, "two");
        assert_eq!(step.new, "three");
        assert!(!step.has_result);
        assert_eq!(journal.events, observed.events);
        assert_eq!(journal.epoch, observed.epoch);
        assert_eq!(step_state(&journal, id), Some(StepState::Prepared));
    }

    #[test]
    fn an_edit_requires_the_old_text_once_and_replay_keeps_the_observation() {
        let resource = "localhost://Users/self/Documents/note.txt";
        let mut journal = empty_journal();
        assert!(observe(&mut journal, resource, 1, "alpha alpha beta"));
        let before = journal.clone();
        assert_eq!(
            propose_edit(&mut journal, resource, "alpha", "one", Some(1)),
            Err("not unique")
        );
        assert_eq!(
            propose_edit(&mut journal, resource, "gamma", "one", Some(1)),
            Err("not unique")
        );
        assert_eq!(journal, before);
        let id = propose_edit(&mut journal, resource, "beta", "one", Some(1)).unwrap();
        assert_eq!(journal.steps.len(), 1);
        assert_eq!(journal.events, before.events);
        assert_eq!(step_state(&journal, id), Some(StepState::Prepared));
        assert!(observe(&mut journal, resource, 2, "beta once"));
        let restored = replay(&model_bytes(&journal.events).unwrap()).unwrap();
        assert_eq!(restored, journal.events);
        assert_eq!(read_observation(&restored[0]).unwrap().version, 1);
        assert_eq!(current_observation(&restored, resource).unwrap().version, 2);
        assert_eq!(
            current_observation(&restored, resource).unwrap().text_hash,
            sha256(b"beta once")
        );
    }

    #[test]
    fn a_second_write_stays_prepared_until_the_first_has_a_result() {
        let resource = "localhost://Users/self/Documents/note.txt";
        let mut journal = empty_journal();
        assert!(observe(&mut journal, resource, 1, "alpha beta"));
        let first = propose_edit(&mut journal, resource, "alpha", "one", Some(1)).unwrap();
        let second = propose_edit(&mut journal, resource, "beta", "two", Some(1)).unwrap();
        let first_step = journal.steps.iter().find(|step| step.id == first).unwrap();
        let second_step = journal.steps.iter().find(|step| step.id == second).unwrap();
        assert_eq!(first_step.effect_id, first);
        assert_eq!(second_step.effect_id, second);
        assert_ne!(first_step.effect_id, second_step.effect_id);
        let events = journal.events.clone();
        assert!(!dispatch(&mut journal, second));
        assert_eq!(step_state(&journal, second), Some(StepState::Prepared));
        assert!(authorize(&mut journal, second, Some("fixture-grant")));
        assert!(!dispatch(&mut journal, second));
        assert_eq!(step_state(&journal, second), Some(StepState::Prepared));
        assert!(!record_tool_result(&mut journal, second, "beta replaced"));
        assert_eq!(journal.events, events);
        assert!(record_tool_result(&mut journal, first, "alpha replaced"));
        assert!(dispatch(&mut journal, second));
        assert_eq!(step_state(&journal, second), Some(StepState::Dispatched));
    }

    #[test]
    fn a_provider_write_needs_a_grant_and_the_current_version() {
        let resource = "localhost://Users/self/Documents/note.txt";
        let mut journal = empty_journal();
        assert!(observe(&mut journal, resource, 1, "alpha beta"));
        let id = propose_edit(&mut journal, resource, "alpha", "one", Some(1)).unwrap();
        let before = journal.clone();
        assert!(!provider_write_may_be_asked(&journal, id, 1));
        assert!(authorize(&mut journal, id, Some("fixture-grant")));
        assert!(!provider_write_may_be_asked(&journal, id, 2));
        assert!(provider_write_may_be_asked(&journal, id, 1));
        assert_eq!(journal.events, before.events);
        assert_eq!(
            current_observed_text(&journal.events, resource).as_deref(),
            Some("alpha beta")
        );
        assert!(
            !journal
                .steps
                .iter()
                .find(|step| step.id == id)
                .unwrap()
                .has_result
        );
        let read = propose_read(&mut journal, resource);
        assert!(authorize(&mut journal, read, Some("fixture-grant")));
        assert!(!provider_write_may_be_asked(&journal, read, 1));
    }

    #[test]
    fn a_run_proposal_keeps_arguments_as_data_and_a_cancelled_run_does_not_start() {
        let project = "localhost://Users/self/Projects/demo";
        let mut journal = empty_journal();
        let before = checkpoint(&journal).unwrap();
        assert_eq!(
            propose_run(&mut journal, "/tmp/demo", &[]),
            Err("host path")
        );
        assert_eq!(
            propose_run(&mut journal, project, &["/bin/sh".to_string()]),
            Err("host path")
        );
        assert_eq!(
            propose_run(&mut journal, "localhost://Users/self/../Projects/demo", &[]),
            Err("host path")
        );
        assert!(journal.steps.is_empty());
        let argv = vec!["cargo".to_string(), "test".to_string()];
        let id = propose_run(&mut journal, project, &argv).unwrap();
        let step = journal.steps.iter().find(|step| step.id == id).unwrap();
        assert_eq!(step.kind, ProposalKind::Run);
        assert_eq!(step.state, StepState::Prepared);
        assert_eq!(step.resource, project);
        assert_eq!(step.argv, argv);
        assert_eq!(checkpoint(&journal).unwrap(), before);
        assert!(cancel(&mut journal, id));
        assert!(!dispatch(&mut journal, id));
        assert_eq!(step_state(&journal, id), Some(StepState::Cancelled));
        assert_eq!(checkpoint(&journal).unwrap(), before);
        let blocked = propose_run(&mut journal, project, &argv).unwrap();
        assert!(authorize(&mut journal, blocked, Some("fixture-grant")));
        assert!(dispatch(&mut journal, blocked));
        assert!(!record_run_result(&mut journal, blocked, 0, "ok", ""));
        assert!(
            !journal
                .steps
                .iter()
                .find(|step| step.id == blocked)
                .unwrap()
                .has_result
        );
    }

    #[test]
    fn a_restore_proposes_an_observed_version_and_does_not_apply_it() {
        let resource = "localhost://Users/self/Documents/note.txt";
        let mut journal = empty_journal();
        assert_eq!(propose_restore(&mut journal, resource, 1), Err("unknown"));
        assert!(journal.steps.is_empty());
        assert!(observe(&mut journal, resource, 1, "one"));
        assert!(observe(&mut journal, resource, 2, "two"));
        let before = journal.clone();
        assert_eq!(propose_restore(&mut journal, resource, 9), Err("unknown"));
        assert_eq!(propose_restore(&mut journal, resource, 1), Err("stale"));
        assert_eq!(journal, before);
        let id = propose_restore(&mut journal, resource, 2).unwrap();
        let step = journal.steps.iter().find(|step| step.id == id).unwrap();
        assert_eq!(step.kind, ProposalKind::Restore);
        assert_eq!(step.state, StepState::Prepared);
        assert_eq!(step.new, "two");
        assert!(!step.has_result);
        assert_eq!(journal.events, before.events);
        assert_eq!(
            current_observed_text(&journal.events, resource).as_deref(),
            Some("two")
        );
        let replayed = replay(&model_bytes(&journal.events).unwrap()).unwrap();
        assert_eq!(read_observation(&replayed[0]).unwrap().version, 1);
        assert!(!observe(&mut journal, resource, 1, "replaced"));
        assert_eq!(
            current_observed_text(&journal.events, resource).as_deref(),
            Some("two")
        );
        assert!(observe(&mut journal, resource, 1, "one"));
        let reread = propose_restore(&mut journal, resource, 1).unwrap();
        assert_eq!(
            journal
                .steps
                .iter()
                .find(|step| step.id == reread)
                .unwrap()
                .new,
            "one"
        );
        assert_eq!(
            current_observed_text(&journal.events, resource).as_deref(),
            Some("one")
        );
    }

    #[test]
    fn a_hosted_proposal_must_name_a_localhost_resource() {
        let mut journal = two_turns();
        let before = journal.clone();
        for refused in ["https://api.example.com/v1/model", "qwen2.5-1.5b"] {
            assert_eq!(propose_hosted(&mut journal, refused), Err("host path"));
            assert_eq!(journal, before);
        }
        let id = propose_hosted(&mut journal, "localhost://Models/hosted").unwrap();
        assert_eq!(step_state(&journal, id), Some(StepState::Prepared));
        assert_eq!(journal.events, before.events);
    }

    #[test]
    fn a_hosted_proposal_has_no_secret_and_a_missing_grant_is_denied() {
        let model = "localhost://Models/hosted";
        let mut journal = empty_journal();
        assert_eq!(propose_hosted(&mut journal, "/tmp/model"), Err("host path"));
        assert!(journal.steps.is_empty());
        let id = propose_hosted(&mut journal, model).unwrap();
        let step = journal.steps.iter().find(|step| step.id == id).unwrap();
        assert_eq!(step.kind, ProposalKind::Hosted);
        assert_eq!(step.resource, model);
        assert_eq!(step.grant, None);
        assert_eq!(step.state, StepState::Prepared);
        let events = journal.events.clone();
        assert!(!authorize(&mut journal, id, None));
        assert_eq!(step_state(&journal, id), Some(StepState::Denied));
        assert!(!dispatch(&mut journal, id));
        assert_eq!(journal.events, events);
        let mut shared = two_turns();
        let project = "localhost://Users/self/Projects/demo";
        let argv = [
            "vm-smoke".to_string(),
            "tests::project_is_ready".to_string(),
        ];
        let tool_once = propose_run(&mut shared, project, &argv).unwrap();
        let host_once = propose_hosted(&mut shared, model).unwrap();
        assert!(!apply_inbox(
            &mut shared,
            tool_once,
            InboxAnswer::AllowOnce,
            None
        ));
        assert!(!apply_inbox(
            &mut shared,
            host_once,
            InboxAnswer::AllowOnce,
            None
        ));
        assert_eq!(step_state(&shared, tool_once), Some(StepState::Denied));
        assert_eq!(step_state(&shared, host_once), Some(StepState::Denied));
        assert!(shared.steps.iter().any(|step| {
            step.id == tool_once && step.inbox == "allow-once" && step.grant.is_none()
        }));
        assert!(shared.steps.iter().any(|step| {
            step.id == host_once && step.inbox == "allow-once" && step.grant.is_none()
        }));
        let tool_session = propose_run(&mut shared, project, &argv).unwrap();
        let host_session = propose_hosted(&mut shared, model).unwrap();
        assert!(!apply_inbox(
            &mut shared,
            tool_session,
            InboxAnswer::AllowSession,
            Some("")
        ));
        assert!(!apply_inbox(
            &mut shared,
            host_session,
            InboxAnswer::AllowSession,
            Some("")
        ));
        assert_eq!(step_state(&shared, tool_session), Some(StepState::Denied));
        assert_eq!(step_state(&shared, host_session), Some(StepState::Denied));
        assert!(shared.steps.iter().any(|step| {
            step.id == tool_session && step.inbox == "allow-session" && step.grant.is_none()
        }));
        assert!(shared.steps.iter().any(|step| {
            step.id == host_session && step.inbox == "allow-session" && step.grant.is_none()
        }));
        let tool_standing = propose_run(&mut shared, project, &argv).unwrap();
        let host_standing = propose_hosted(&mut shared, model).unwrap();
        assert!(apply_inbox(
            &mut shared,
            tool_standing,
            InboxAnswer::Standing,
            Some("fixture-grant")
        ));
        assert!(apply_inbox(
            &mut shared,
            host_standing,
            InboxAnswer::Standing,
            Some("fixture-grant")
        ));
        assert_eq!(
            step_state(&shared, tool_standing),
            Some(StepState::Prepared)
        );
        assert_eq!(
            step_state(&shared, host_standing),
            Some(StepState::Prepared)
        );
        assert!(shared.steps.iter().any(|step| {
            step.id == tool_standing
                && step.inbox == "standing"
                && step.grant.as_deref() == Some("fixture-grant")
                && step.resource == project
        }));
        assert!(shared.steps.iter().any(|step| {
            step.id == host_standing
                && step.inbox == "standing"
                && step.grant.as_deref() == Some("fixture-grant")
                && step.resource == model
        }));
        let bytes = model_bytes(&shared.events).unwrap();
        assert!(!bytes
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant"));
        assert!(bytes
            .windows(b"inbox\nallow-once".len())
            .any(|window| window == b"inbox\nallow-once"));
        assert!(bytes
            .windows(b"inbox\nallow-session".len())
            .any(|window| window == b"inbox\nallow-session"));
        assert!(bytes
            .windows(b"inbox\nstanding".len())
            .any(|window| window == b"inbox\nstanding"));
        assert!(shared
            .events
            .iter()
            .all(|node| !node.text.contains("upload")));
    }

    #[test]
    fn a_child_grant_is_narrower_and_does_not_inherit_the_parent_grant() {
        let mut journal = empty_journal();
        let parent = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        assert!(authorize(&mut journal, parent, Some("fixture-grant")));
        assert_eq!(
            propose_child(
                &mut journal,
                parent,
                "localhost://Users/self/Projects/other"
            ),
            Err("not a subset")
        );
        assert_eq!(journal.steps.len(), 1);
        let child = propose_child(
            &mut journal,
            parent,
            "localhost://Users/self/Projects/demo/src",
        )
        .unwrap();
        let child_step = journal.steps.iter().find(|step| step.id == child).unwrap();
        assert_eq!(child_step.kind, ProposalKind::Child);
        assert_eq!(child_step.parent_id, Some(parent));
        assert_eq!(child_step.grant, None);
        assert_ne!(child_step.effect_id, parent);
        assert!(!authorize_child(&mut journal, child, Some("fixture-grant")));
        assert_eq!(
            journal
                .steps
                .iter()
                .find(|step| step.id == child)
                .unwrap()
                .grant,
            None
        );
        assert_eq!(step_state(&journal, child), Some(StepState::Prepared));
        assert!(authorize_child(&mut journal, child, Some("child-grant")));
        let mut child_host =
            open_child_host(&journal, parent, "localhost://Users/self/Projects/demo/src").unwrap();
        assert_eq!(
            open_child_host(&journal, parent, "localhost://Users/self/Projects/other"),
            Err("not a subset")
        );
        assert_eq!(child_host.events.len(), 1);
        assert_eq!(child_host.events[0].text, SYSTEM_HEAD);
        assert_ne!(child_host.events.as_ptr(), journal.events.as_ptr());
        assert!(child_host.steps.iter().all(|step| step.grant.is_none()));
        assert!(!grant_child_host(
            &mut child_host,
            Some("fixture-grant"),
            Some("fixture-grant")
        ));
        assert!(child_host.steps.iter().all(|step| step.grant.is_none()));
        assert!(grant_child_host(
            &mut child_host,
            Some("fixture-grant"),
            Some("child-grant")
        ));
        let parent_events = journal.events.len();
        assert!(!record_child_result(&mut journal, &child_host, ""));
        assert!(!record_child_result(&mut journal, &child_host, "/tmp/out"));
        assert!(!record_child_result(
            &mut journal,
            &child_host,
            "saw fixture-grant"
        ));
        assert!(record_child_result(
            &mut journal,
            &child_host,
            "child result ok"
        ));
        assert_eq!(journal.events.len(), parent_events + 1);
        assert_eq!(journal.events.last().unwrap().text, "child result ok");
        assert_eq!(child_host.events.len(), 1);
        let parent_bytes = model_bytes(&journal.events).unwrap();
        let child_bytes = model_bytes(&child_host.events).unwrap();
        assert!(!parent_bytes
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant"));
        assert!(!parent_bytes
            .windows(b"child-grant".len())
            .any(|window| window == b"child-grant"));
        assert!(!child_bytes
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant"));
        assert_eq!(replay(&parent_bytes).unwrap(), journal.events);
        assert_eq!(
            journal
                .steps
                .iter()
                .find(|step| step.id == child)
                .unwrap()
                .grant
                .as_deref(),
            Some("child-grant")
        );
        let inbox_child = propose_child(
            &mut journal,
            parent,
            "localhost://Users/self/Projects/demo/notes.txt",
        )
        .unwrap();
        assert!(!apply_inbox(
            &mut journal,
            inbox_child,
            InboxAnswer::Standing,
            Some("fixture-grant")
        ));
        assert!(journal
            .steps
            .iter()
            .find(|step| step.id == inbox_child)
            .is_some_and(|step| step.grant.is_none() && step.inbox.is_empty()));
        assert!(apply_inbox(
            &mut journal,
            inbox_child,
            InboxAnswer::Standing,
            Some("child-grant")
        ));
        assert!(journal
            .steps
            .iter()
            .find(|step| step.id == inbox_child)
            .is_some_and(|step| {
                step.grant.as_deref() == Some("child-grant") && step.inbox == "standing"
            }));
        assert!(journal
            .steps
            .iter()
            .find(|step| step.id == parent)
            .is_some_and(|step| step.grant.as_deref() == Some("fixture-grant")));
        let mut logged = two_turns();
        let logged_parent = propose_run(
            &mut logged,
            "localhost://Users/self/Projects/demo",
            &["note".to_string()],
        )
        .unwrap();
        let logged_child = propose_child(
            &mut logged,
            logged_parent,
            "localhost://Users/self/Projects/demo/src",
        )
        .unwrap();
        let standing_lines = |events: &[SurfaceNode]| {
            events
                .iter()
                .filter(|node| node.source == NodeSource::Person && node.text == "inbox\nstanding")
                .count()
        };
        assert!(apply_inbox(
            &mut logged,
            logged_parent,
            InboxAnswer::Standing,
            Some("fixture-grant")
        ));
        assert_eq!(standing_lines(&logged.events), 1);
        assert!(!apply_inbox(
            &mut logged,
            logged_child,
            InboxAnswer::Standing,
            Some("fixture-grant")
        ));
        assert_eq!(standing_lines(&logged.events), 1);
        assert!(apply_inbox(
            &mut logged,
            logged_child,
            InboxAnswer::Standing,
            Some("child-grant")
        ));
        assert_eq!(standing_lines(&logged.events), 2);
        assert!(dispatch(&mut logged, logged_child));
        assert_eq!(
            step_state(&logged, logged_parent),
            Some(StepState::Prepared)
        );
        let held = propose_child(
            &mut logged,
            logged_parent,
            "localhost://Users/self/Projects/demo/lib",
        )
        .unwrap();
        assert!(apply_inbox(
            &mut logged,
            held,
            InboxAnswer::Standing,
            Some("child-grant")
        ));
        assert_eq!(standing_lines(&logged.events), 3);
        assert!(cancel(&mut logged, held));
        assert!(!dispatch(&mut logged, held));
        assert_eq!(step_state(&logged, held), Some(StepState::Cancelled));
        assert_eq!(
            step_state(&logged, logged_parent),
            Some(StepState::Prepared)
        );
        assert_eq!(
            step_state(&logged, logged_child),
            Some(StepState::Dispatched)
        );
        assert_eq!(standing_lines(&logged.events), 3);
        let sent = propose_child(
            &mut logged,
            logged_parent,
            "localhost://Users/self/Projects/demo/tests",
        )
        .unwrap();
        assert!(apply_inbox(
            &mut logged,
            sent,
            InboxAnswer::Standing,
            Some("child-grant")
        ));
        assert!(dispatch(&mut logged, sent));
        assert!(note_crash(&mut logged, sent));
        assert_eq!(
            step_state(&logged, sent),
            Some(StepState::SettlementUnknown)
        );
        assert!(!dispatch(&mut logged, sent));
        assert_eq!(
            step_state(&logged, logged_parent),
            Some(StepState::Prepared)
        );
        assert_eq!(
            step_state(&logged, logged_child),
            Some(StepState::Dispatched)
        );
        assert_eq!(standing_lines(&logged.events), 4);
        let saved = model_bytes(&logged.events).unwrap();
        assert!(!saved
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant"));
        assert!(!saved
            .windows(b"child-grant".len())
            .any(|window| window == b"child-grant"));
    }

    #[test]
    fn a_child_must_sit_strictly_under_its_parent() {
        let demo = "localhost://Users/self/Projects/demo";
        assert!(!narrower_resource(
            demo,
            "localhost://Users/self/Projects/demo2"
        ));
        assert!(!narrower_resource(
            demo,
            "localhost://Users/self/Projects/demo-old"
        ));
        assert!(!narrower_resource(demo, demo));
        assert!(!narrower_resource(
            demo,
            "localhost://Users/self/Projects/demo/"
        ));
        assert!(narrower_resource(
            demo,
            "localhost://Users/self/Projects/demo/x"
        ));
        let mut journal = empty_journal();
        let parent = propose_run(&mut journal, demo, &["true".to_string()]).unwrap();
        for refused in [
            "localhost://Users/self/Projects/demo2",
            "localhost://Users/self/Projects/demo-old",
            demo,
            "localhost://Users/self/Projects/demo/",
        ] {
            assert_eq!(
                propose_child(&mut journal, parent, refused),
                Err("not a subset")
            );
            assert!(open_child_host(&journal, parent, refused).is_err());
        }
        assert_eq!(journal.steps.len(), 1);
        let child = propose_child(
            &mut journal,
            parent,
            "localhost://Users/self/Projects/demo/x",
        )
        .unwrap();
        let child_step = journal.steps.iter().find(|step| step.id == child).unwrap();
        assert_eq!(child_step.kind, ProposalKind::Child);
        assert_eq!(child_step.parent_id, Some(parent));
        assert_eq!(journal.steps.len(), 2);
    }

    #[test]
    fn a_project_resource_is_not_a_host_path() {
        let mut journal = empty_journal();
        assert_eq!(propose_init(&mut journal, "/tmp", "demo"), Err("host path"));
        assert_eq!(
            propose_init(&mut journal, "self", "demo/app"),
            Err("host path")
        );
        assert_eq!(propose_init(&mut journal, "self", ".."), Err("host path"));
        assert!(journal.steps.is_empty());
        let id = propose_init(&mut journal, "self", "demo").unwrap();
        let step = journal.steps.iter().find(|step| step.id == id).unwrap();
        assert_eq!(step.kind, ProposalKind::Init);
        assert_eq!(step.resource, "localhost://Users/self/Projects/demo");
        assert!(!step.resource.starts_with('/'));
        assert_eq!(step.state, StepState::Prepared);
        assert!(journal.events.is_empty());
    }

    #[test]
    fn local_model_cache_and_idle_release_stay_as_they_are() {
        let llama = include_str!("../../../capsules/model-provider/src/local_llama.rs");
        let adapters = include_str!("../../../capsules/model-provider/src/adapters.rs");
        assert!(llama.contains("const IDLE_RELEASE_DELAY: Duration = Duration::from_secs(60);"));
        assert!(llama.contains("Admission covers the live context only, without cached prompts."));
        let cache_at = llama
            .find("\"--cache-ram\"")
            .expect("local engine cache flag");
        let zero_at = llama[cache_at..]
            .find("\"0\"")
            .expect("local engine cache value");
        assert!(zero_at < 80);
        assert!(adapters.contains("{api_url}/input_tokens"));
        assert!(adapters.contains("exceeds context"));
    }

    #[test]
    fn a_non_entrypoint_change_changes_the_project_tree_hash() {
        let entry = "index.html";
        let style = "style.css";
        let first = project_tree_hash(&[(entry, "<h1>demo</h1>"), (style, "body{}")]).unwrap();
        let reordered = project_tree_hash(&[(style, "body{}"), (entry, "<h1>demo</h1>")]).unwrap();
        assert_eq!(first, reordered);
        let style_changed =
            project_tree_hash(&[(entry, "<h1>demo</h1>"), (style, "h1{}")]).unwrap();
        let entry_changed =
            project_tree_hash(&[(entry, "<h1>other</h1>"), (style, "body{}")]).unwrap();
        assert_ne!(first, style_changed);
        assert_ne!(first, entry_changed);
        let hex: String = first.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex,
            "157af2e20c421bfaf3ac59d51f059bd9b8fb1cf2e40a2b45e8b898771ff938f5"
        );
        let with_note = project_tree_hash(&[
            ("index.html", "<h1>demo</h1>"),
            ("notes.txt", "hello from the project"),
            ("style.css", "body{}"),
        ])
        .unwrap();
        let note_hex: String = with_note.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            note_hex,
            "a1097f0d6ed225ad16b19f19d6a260816af54c74bfe82b11e4ce2020233497f1"
        );
        assert!(project_tree_hash(&[("/tmp/style.css", "body{}")]).is_none());
        assert!(project_tree_hash(&[]).is_none());
        let signer = include_str!("../../../elastos/crates/elastos-server/src/runtime.rs");
        assert!(signer.contains("Compute content hash (hash the entrypoint file)"));
    }

    #[test]
    fn a_scaffold_write_uses_the_version_rules_and_does_not_apply() {
        let mut journal = empty_journal();
        let project = propose_init(&mut journal, "self", "demo").unwrap();
        let file = "localhost://Users/self/Projects/demo/index.html";
        assert_eq!(
            propose_scaffold(
                &mut journal,
                project,
                "index.html",
                "<h1>demo</h1>",
                Some(1)
            ),
            Err("not observed")
        );
        assert!(observe(&mut journal, file, 1, ""));
        assert_eq!(
            propose_scaffold(
                &mut journal,
                project,
                "../index.html",
                "<h1>demo</h1>",
                Some(1)
            ),
            Err("host path")
        );
        assert_eq!(
            propose_scaffold(
                &mut journal,
                project,
                "index.html",
                "<h1>demo</h1>",
                Some(2)
            ),
            Err("stale")
        );
        let before = journal.events.clone();
        let id = propose_scaffold(
            &mut journal,
            project,
            "index.html",
            "<h1>demo</h1>",
            Some(1),
        )
        .unwrap();
        let step = journal.steps.iter().find(|step| step.id == id).unwrap();
        assert_eq!(step.kind, ProposalKind::Edit);
        assert_eq!(step.new, "<h1>demo</h1>");
        assert!(!step.has_result);
        assert_eq!(journal.events, before);
        assert_eq!(
            current_observed_text(&journal.events, file).as_deref(),
            Some("")
        );
        assert!(observe(&mut journal, file, 2, "<h1>demo</h1>"));
        assert_eq!(
            propose_scaffold(
                &mut journal,
                project,
                "index.html",
                "<h1>next</h1>",
                Some(2)
            ),
            Err("not empty")
        );
    }

    #[test]
    fn a_run_seat_is_the_microvm() {
        let mut journal = empty_journal();
        let id = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        let step = journal.steps.iter().find(|step| step.id == id).unwrap();
        assert_eq!(step.seat, "microvm");
        assert_ne!(step.seat, "browser");
        assert_ne!(step.seat, "terminal");
        assert_eq!(step.state, StepState::Prepared);
    }

    #[test]
    fn a_run_result_is_an_exit_code_and_a_capped_log() {
        let mut journal = empty_journal();
        let id = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        assert!(!record_run_result(&mut journal, id, 0, "ok", ""));
        assert!(cancel(&mut journal, id));
        assert!(!record_run_result(&mut journal, id, 0, "ok", ""));
        let again = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        assert!(authorize(&mut journal, again, Some("fixture-grant")));
        assert!(!record_run_result(&mut journal, again, 0, "ok", ""));
        assert!(dispatch(&mut journal, again));
        assert!(!record_run_result(&mut journal, again, 0, "ok", "/tmp/out"));
        assert!(!record_run_result(
            &mut journal,
            again,
            0,
            &"x".repeat(RUN_LOG_BUDGET + 1),
            ""
        ));
        let before = journal.events.len();
        assert!(record_run_result(
            &mut journal,
            again,
            1,
            "cargo test: failed",
            ""
        ));
        assert!(!record_run_result(&mut journal, again, 0, "again", ""));
        assert_eq!(journal.events.len(), before + 1);
        assert!(journal.events.last().unwrap().text.starts_with("exit 1\n"));
        assert!(
            journal
                .steps
                .iter()
                .find(|step| step.id == again)
                .unwrap()
                .has_result
        );
    }

    #[test]
    fn the_vm_hello_line_is_recorded_after_a_granted_dispatch() {
        let mut journal = empty_journal();
        let id = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &["true".to_string()],
        )
        .unwrap();
        assert!(authorize(&mut journal, id, Some("fixture-grant")));
        assert!(dispatch(&mut journal, id));
        let before = model_bytes(&journal.events);
        assert!(record_run_result(
            &mut journal,
            id,
            0,
            "init: hello from vm smoke test",
            ""
        ));
        assert_eq!(
            journal.events.last().unwrap().text,
            "exit 0\ninit: hello from vm smoke test\n"
        );
        assert_ne!(model_bytes(&journal.events).as_ref(), before.as_ref());
        assert!(
            journal
                .steps
                .iter()
                .find(|step| step.id == id)
                .unwrap()
                .has_result
        );
    }

    #[test]
    fn a_failed_command_is_recorded_as_exit_one() {
        let mut journal = empty_journal();
        let id = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &["false".to_string()],
        )
        .unwrap();
        assert!(authorize(&mut journal, id, Some("fixture-grant")));
        assert!(dispatch(&mut journal, id));
        assert!(record_run_result(
            &mut journal,
            id,
            1,
            "init: command failed",
            ""
        ));
        assert_eq!(
            journal.events.last().unwrap().text,
            "exit 1\ninit: command failed\n"
        );
        assert_ne!(journal.events.last().unwrap().text, "exit 0\n");
        let wrong = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        assert!(authorize(&mut journal, wrong, Some("fixture-grant")));
        assert!(dispatch(&mut journal, wrong));
        assert!(!record_run_result(
            &mut journal,
            wrong,
            0,
            "init: hello from vm smoke test",
            ""
        ));
        assert!(!record_run_result(
            &mut journal,
            wrong,
            1,
            "init: command failed",
            ""
        ));
    }

    #[test]
    fn a_rust_test_result_keeps_its_exit_code() {
        let mut journal = empty_journal();
        let passed = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        assert!(observe(
            &mut journal,
            "localhost://Users/self/Projects/demo/index.html",
            1,
            "<h1>demo</h1>",
        ));
        assert!(observe(
            &mut journal,
            "localhost://Users/self/Projects/demo/style.css",
            1,
            "body{}",
        ));
        assert!(observe(
            &mut journal,
            "localhost://Users/self/Projects/demo/notes.txt",
            1,
            "hello from the project",
        ));
        assert!(authorize(&mut journal, passed, Some("fixture-grant")));
        assert!(dispatch(&mut journal, passed));
        assert!(record_run_result(
            &mut journal,
            passed,
            0,
            "project demo a1097f0d6ed225ad16b19f19d6a260816af54c74bfe82b11e4ce2020233497f1\ntest result: ok",
            ""
        ));
        let failed = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        assert!(authorize(&mut journal, failed, Some("fixture-grant")));
        assert!(dispatch(&mut journal, failed));
        assert!(record_run_result(
            &mut journal,
            failed,
            101,
            "test result: FAILED",
            ""
        ));
        assert_eq!(
            journal.events.iter().rev().nth(1).unwrap().text,
            "exit 0\nproject demo a1097f0d6ed225ad16b19f19d6a260816af54c74bfe82b11e4ce2020233497f1\ntest result: ok\n"
        );
        assert_eq!(
            journal.events.last().unwrap().text,
            "exit 101\ntest result: FAILED\n"
        );
        let before = journal.events.len();
        assert!(!record_run_result(
            &mut journal,
            failed,
            0,
            "test result: FAILED",
            ""
        ));
        let crossed = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        assert!(authorize(&mut journal, crossed, Some("fixture-grant")));
        assert!(dispatch(&mut journal, crossed));
        assert!(!record_run_result(
            &mut journal,
            crossed,
            0,
            "test result: FAILED",
            ""
        ));
        assert!(!record_run_result(
            &mut journal,
            crossed,
            101,
            "test result: ok",
            ""
        ));
        assert_eq!(journal.events.len(), before);
    }

    #[test]
    fn an_edited_stylesheet_requires_a_new_digest() {
        let old = "157af2e20c421bfaf3ac59d51f059bd9b8fb1cf2e40a2b45e8b898771ff938f5";
        let edited = project_tree_hash(&[("index.html", "<h1>demo</h1>"), ("style.css", "h1{}")])
            .expect("edited digest");
        let new_hex: String = edited.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            new_hex,
            "5ff4215e2135fbfa327187523ad3a6ffb536fec2d893526d9a271b36f95c72b7"
        );
        let mut journal = empty_journal();
        let first = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        assert!(observe(
            &mut journal,
            "localhost://Users/self/Projects/demo/index.html",
            1,
            "<h1>demo</h1>",
        ));
        assert!(observe(
            &mut journal,
            "localhost://Users/self/Projects/demo/style.css",
            1,
            "body{}",
        ));
        assert!(authorize(&mut journal, first, Some("fixture-grant")));
        assert!(dispatch(&mut journal, first));
        assert!(record_run_result(
            &mut journal,
            first,
            0,
            &format!("project demo {old}\ntest result: ok"),
            ""
        ));
        assert!(observe(
            &mut journal,
            "localhost://Users/self/Projects/demo/style.css",
            2,
            "h1{}",
        ));
        let second = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        assert!(authorize(&mut journal, second, Some("fixture-grant")));
        assert!(dispatch(&mut journal, second));
        assert!(!record_run_result(
            &mut journal,
            second,
            0,
            &format!("project demo {old}\ntest result: ok"),
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            second,
            0,
            &format!("project demo {new_hex}\ntest result: ok"),
            ""
        ));
    }

    #[test]
    fn a_granted_edit_becomes_the_current_text_and_does_not_write_a_host_file() {
        let mut journal = empty_journal();
        let style = "localhost://Users/self/Projects/demo/style.css";
        let page = "localhost://Users/self/Projects/demo/index.html";
        assert!(observe(&mut journal, page, 1, "<h1>demo</h1>"));
        assert!(observe(&mut journal, style, 1, "body{}"));
        let edit = propose_edit(&mut journal, style, "body{}", "h1{}", Some(1)).unwrap();
        assert!(!note_provider_wrote(&mut journal, edit));
        assert_eq!(
            current_observed_text(&journal.events, style).as_deref(),
            Some("body{}")
        );
        assert!(authorize(&mut journal, edit, Some("fixture-grant")));
        assert!(dispatch(&mut journal, edit));
        assert!(note_provider_wrote(&mut journal, edit));
        assert!(!note_provider_wrote(&mut journal, edit));
        assert_eq!(
            current_observed_text(&journal.events, style).as_deref(),
            Some("h1{}")
        );
        let bytes = model_bytes(&journal.events).expect("log bytes");
        let restored = replay(&bytes).expect("resume");
        assert_eq!(
            current_observed_text(&restored, style).as_deref(),
            Some("h1{}")
        );
        let old = "157af2e20c421bfaf3ac59d51f059bd9b8fb1cf2e40a2b45e8b898771ff938f5";
        let new_hex = "5ff4215e2135fbfa327187523ad3a6ffb536fec2d893526d9a271b36f95c72b7";
        let run = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        assert!(authorize(&mut journal, run, Some("fixture-grant")));
        assert!(dispatch(&mut journal, run));
        assert!(!record_run_result(
            &mut journal,
            run,
            0,
            &format!("project demo {old}\ntest result: ok"),
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            run,
            0,
            &format!("project demo {new_hex}\ntest result: ok"),
            ""
        ));
    }

    #[test]
    fn a_retyped_note_changes_the_digest() {
        let old = "a1097f0d6ed225ad16b19f19d6a260816af54c74bfe82b11e4ce2020233497f1";
        let edited = project_tree_hash(&[
            ("index.html", "<h1>demo</h1>"),
            ("notes.txt", "hello again"),
            ("style.css", "body{}"),
        ])
        .unwrap();
        let new_hex: String = edited.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            new_hex,
            "8256365b5a513111b73d3ee3b646a78d58c821c9f3cba1346f6f27c0f38dd36d"
        );
        let mut journal = empty_journal();
        let page = "localhost://Users/self/Projects/demo/index.html";
        let style = "localhost://Users/self/Projects/demo/style.css";
        let notes = "localhost://Users/self/Projects/demo/notes.txt";
        assert!(observe(&mut journal, page, 1, "<h1>demo</h1>"));
        assert!(observe(&mut journal, style, 1, "body{}"));
        assert!(observe(&mut journal, notes, 1, "hello from the project"));
        let shown = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &["note".to_string()],
        )
        .unwrap();
        assert!(authorize(&mut journal, shown, Some("fixture-grant")));
        assert!(dispatch(&mut journal, shown));
        assert!(record_run_result(
            &mut journal,
            shown,
            0,
            "project note hello from the project",
            ""
        ));
        let hidden = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &["note".to_string()],
        )
        .unwrap();
        assert!(authorize(&mut journal, hidden, Some("fixture-grant")));
        assert!(dispatch(&mut journal, hidden));
        assert!(!record_run_result(
            &mut journal,
            hidden,
            0,
            "project note hello again",
            ""
        ));
        assert!(!record_run_result(
            &mut journal,
            hidden,
            0,
            "project note /tmp/out",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            hidden,
            0,
            "project note hello from the project",
            ""
        ));
        let edit = propose_edit(
            &mut journal,
            notes,
            "hello from the project",
            "hello again",
            Some(1),
        )
        .unwrap();
        assert!(!note_provider_wrote(&mut journal, edit));
        assert_eq!(
            current_observed_text(&journal.events, notes).as_deref(),
            Some("hello from the project")
        );
        assert!(authorize(&mut journal, edit, Some("fixture-grant")));
        assert!(dispatch(&mut journal, edit));
        assert!(note_provider_wrote(&mut journal, edit));
        assert_eq!(
            current_observed_text(&journal.events, notes).as_deref(),
            Some("hello again")
        );
        let run = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        assert!(authorize(&mut journal, run, Some("fixture-grant")));
        assert!(dispatch(&mut journal, run));
        assert!(!record_run_result(
            &mut journal,
            run,
            0,
            &format!("project demo {old}\ntest result: ok"),
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            run,
            0,
            &format!("project demo {new_hex}\ntest result: ok"),
            ""
        ));
        let bytes = model_bytes(&journal.events).expect("log bytes");
        let restored = replay(&bytes).expect("resume");
        assert_eq!(
            current_observed_text(&restored, notes).as_deref(),
            Some("hello again")
        );
        let spoken = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &["note".to_string()],
        )
        .unwrap();
        assert!(authorize(&mut journal, spoken, Some("fixture-grant")));
        assert!(dispatch(&mut journal, spoken));
        assert!(!record_run_result(
            &mut journal,
            spoken,
            0,
            "project note hello from the project",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            spoken,
            0,
            "project note hello again",
            ""
        ));
        let listed = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &["files".to_string()],
        )
        .unwrap();
        assert!(authorize(&mut journal, listed, Some("fixture-grant")));
        assert!(dispatch(&mut journal, listed));
        let names = "project file index.html\nproject file notes.txt\nproject file style.css";
        assert!(!record_run_result(
            &mut journal,
            listed,
            0,
            &format!("{names}\nproject demo {old}\ntest result: ok"),
            ""
        ));
        assert!(record_run_result(&mut journal, listed, 0, names, ""));
        let edited_run = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &[
                "vm-smoke".to_string(),
                "tests::project_was_edited".to_string(),
            ],
        )
        .unwrap();
        assert!(authorize(&mut journal, edited_run, Some("fixture-grant")));
        assert!(dispatch(&mut journal, edited_run));
        assert!(!record_run_result(
            &mut journal,
            edited_run,
            0,
            &format!("project note hello again\nproject demo {old}\ntest result: ok"),
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            edited_run,
            0,
            &format!("project note hello again\nproject demo {new_hex}\ntest result: ok"),
            ""
        ));
    }

    #[test]
    fn a_file_list_names_only_files_the_project_has_been_shown() {
        let mut journal = empty_journal();
        let project = "localhost://Users/self/Projects/demo";
        assert!(observe(
            &mut journal,
            "localhost://Users/self/Projects/demo/index.html",
            1,
            "<h1>demo</h1>",
        ));
        assert!(observe(
            &mut journal,
            "localhost://Users/self/Projects/demo/style.css",
            1,
            "body{}",
        ));
        let run = propose_run(&mut journal, project, &["files".to_string()]).unwrap();
        assert!(authorize(&mut journal, run, Some("fixture-grant")));
        assert!(dispatch(&mut journal, run));
        assert!(record_run_result(
            &mut journal,
            run,
            0,
            "project file index.html\nproject file style.css",
            ""
        ));
        let unread = propose_run(&mut journal, project, &["files".to_string()]).unwrap();
        assert!(authorize(&mut journal, unread, Some("fixture-grant")));
        assert!(dispatch(&mut journal, unread));
        assert!(!record_run_result(
            &mut journal,
            unread,
            0,
            "project file notes.txt",
            ""
        ));
        assert!(!record_run_result(
            &mut journal,
            unread,
            0,
            "project file /tmp/secret",
            ""
        ));
        assert!(observe(
            &mut journal,
            "localhost://Users/self/Projects/demo/notes.txt",
            1,
            "hello from the project",
        ));
        assert!(!record_run_result(
            &mut journal,
            unread,
            0,
            "project file notes.txt",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            unread,
            0,
            "project file index.html\nproject file index.html\nproject file style.css\nproject file style.css\nproject file notes.txt\nproject file notes.txt",
            ""
        ));
    }

    #[test]
    fn one_grant_runs_three_programs_and_their_results_stay_apart() {
        let mut journal = empty_journal();
        let project = "localhost://Users/self/Projects/demo";
        assert!(observe(
            &mut journal,
            "localhost://Users/self/Projects/demo/index.html",
            1,
            "<h1>demo</h1>",
        ));
        assert!(observe(
            &mut journal,
            "localhost://Users/self/Projects/demo/style.css",
            1,
            "body{}",
        ));
        assert!(observe(
            &mut journal,
            "localhost://Users/self/Projects/demo/notes.txt",
            1,
            "hello from the project",
        ));
        let files = propose_run(&mut journal, project, &["files".to_string()]).unwrap();
        let note = propose_run(&mut journal, project, &["note".to_string()]).unwrap();
        let tested = propose_run(
            &mut journal,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        for id in [files, note, tested] {
            assert!(authorize(&mut journal, id, Some("fixture-grant")));
            assert!(dispatch(&mut journal, id));
        }
        let effect = |id: u64| {
            journal
                .steps
                .iter()
                .find(|step| step.id == id)
                .unwrap()
                .effect_id
        };
        assert_ne!(effect(files), effect(note));
        assert_ne!(effect(note), effect(tested));
        let names = "project file index.html\nproject file notes.txt\nproject file style.css";
        assert!(!record_run_result(&mut journal, note, 0, names, ""));
        assert!(!record_run_result(
            &mut journal,
            files,
            0,
            "project note hello from the project",
            ""
        ));
        assert!(record_run_result(&mut journal, files, 0, names, ""));
        assert!(record_run_result(
            &mut journal,
            note,
            0,
            "project note hello from the project",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            tested,
            0,
            "project demo a1097f0d6ed225ad16b19f19d6a260816af54c74bfe82b11e4ce2020233497f1\ntest result: ok",
            ""
        ));
    }

    #[test]
    fn a_version_that_moved_after_the_proposal_is_not_written() {
        let mut journal = empty_journal();
        let style = "localhost://Users/self/Projects/demo/style.css";
        assert!(observe(&mut journal, style, 1, "body{}"));
        let edit = propose_edit(&mut journal, style, "body{}", "h1{}", Some(1)).unwrap();
        assert!(observe(&mut journal, style, 2, "body{}\n/* touched */"));
        assert!(authorize(&mut journal, edit, Some("fixture-grant")));
        assert!(dispatch(&mut journal, edit));
        assert!(!note_provider_wrote(&mut journal, edit));
        assert_eq!(step_state(&journal, edit), Some(StepState::Denied));
        assert_eq!(
            current_observed_text(&journal.events, style).as_deref(),
            Some("body{}\n/* touched */")
        );
        assert!(
            !journal
                .steps
                .iter()
                .find(|step| step.id == edit)
                .unwrap()
                .has_result
        );
        let follow = propose_edit(
            &mut journal,
            style,
            "body{}\n/* touched */",
            "body{}",
            Some(2),
        )
        .unwrap();
        assert!(authorize(&mut journal, follow, Some("fixture-grant")));
        assert!(dispatch(&mut journal, follow));
        assert!(note_provider_wrote(&mut journal, follow));
        assert_eq!(
            current_observed_text(&journal.events, style).as_deref(),
            Some("body{}")
        );
    }

    #[test]
    fn a_crash_after_dispatch_does_not_apply_the_note() {
        let mut journal = empty_journal();
        let notes = "localhost://Users/self/Projects/demo/notes.txt";
        assert!(observe(&mut journal, notes, 1, "hello from the project"));
        let edit = propose_edit(
            &mut journal,
            notes,
            "hello from the project",
            "hello again",
            Some(1),
        )
        .unwrap();
        assert!(authorize(&mut journal, edit, Some("fixture-grant")));
        assert!(dispatch(&mut journal, edit));
        assert!(note_crash(&mut journal, edit));
        assert_eq!(
            journal
                .steps
                .iter()
                .find(|step| step.id == edit)
                .unwrap()
                .state,
            StepState::SettlementUnknown
        );
        assert!(!note_provider_wrote(&mut journal, edit));
        assert_eq!(
            current_observed_text(&journal.events, notes).as_deref(),
            Some("hello from the project")
        );
        let run = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &["note".to_string()],
        )
        .unwrap();
        assert!(authorize(&mut journal, run, Some("fixture-grant")));
        assert!(dispatch(&mut journal, run));
        assert!(!record_run_result(
            &mut journal,
            run,
            0,
            "project note hello again",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            run,
            0,
            "project note hello from the project",
            ""
        ));
        let bytes = model_bytes(&journal.events).expect("log bytes");
        let restored = replay(&bytes).expect("resume");
        assert_eq!(
            current_observed_text(&restored, notes).as_deref(),
            Some("hello from the project")
        );
    }

    #[test]
    fn a_cancel_before_send_keeps_the_note_and_a_cancel_after_send_does_not_unsend_it() {
        let mut journal = empty_journal();
        let page = "localhost://Users/self/Projects/demo/index.html";
        let style = "localhost://Users/self/Projects/demo/style.css";
        let notes = "localhost://Users/self/Projects/demo/notes.txt";
        assert!(observe(&mut journal, page, 1, "<h1>demo</h1>"));
        assert!(observe(&mut journal, style, 1, "body{}"));
        assert!(observe(&mut journal, notes, 1, "hello from the project"));
        let held = propose_edit(
            &mut journal,
            notes,
            "hello from the project",
            "hello again",
            Some(1),
        )
        .unwrap();
        assert!(cancel(&mut journal, held));
        assert!(!dispatch(&mut journal, held));
        assert!(!note_provider_wrote(&mut journal, held));
        assert_eq!(
            current_observed_text(&journal.events, notes).as_deref(),
            Some("hello from the project")
        );
        let run = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        assert!(authorize(&mut journal, run, Some("fixture-grant")));
        assert!(dispatch(&mut journal, run));
        let old = "a1097f0d6ed225ad16b19f19d6a260816af54c74bfe82b11e4ce2020233497f1";
        let rewritten = "8256365b5a513111b73d3ee3b646a78d58c821c9f3cba1346f6f27c0f38dd36d";
        assert!(!record_run_result(
            &mut journal,
            run,
            0,
            &format!("project demo {rewritten}\ntest result: ok"),
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            run,
            0,
            &format!("project demo {old}\ntest result: ok"),
            ""
        ));
        let sent = propose_edit(
            &mut journal,
            notes,
            "hello from the project",
            "hello again",
            Some(1),
        )
        .unwrap();
        assert!(authorize(&mut journal, sent, Some("fixture-grant")));
        assert!(dispatch(&mut journal, sent));
        assert!(!cancel(&mut journal, sent));
        assert_eq!(
            journal
                .steps
                .iter()
                .find(|step| step.id == sent)
                .unwrap()
                .state,
            StepState::Dispatched
        );
        assert!(note_provider_wrote(&mut journal, sent));
        assert_eq!(
            current_observed_text(&journal.events, notes).as_deref(),
            Some("hello again")
        );
    }

    #[test]
    fn a_crash_after_the_result_does_not_erase_it() {
        let mut journal = empty_journal();
        let notes = "localhost://Users/self/Projects/demo/notes.txt";
        assert!(observe(&mut journal, notes, 1, "hello from the project"));
        let edit = propose_edit(
            &mut journal,
            notes,
            "hello from the project",
            "hello again",
            Some(1),
        )
        .unwrap();
        assert!(authorize(&mut journal, edit, Some("fixture-grant")));
        assert!(dispatch(&mut journal, edit));
        assert!(note_provider_wrote(&mut journal, edit));
        assert!(!note_crash(&mut journal, edit));
        assert_eq!(step_state(&journal, edit), Some(StepState::Dispatched));
        assert_eq!(
            current_observed_text(&journal.events, notes).as_deref(),
            Some("hello again")
        );
        let bytes = model_bytes(&journal.events).expect("log bytes");
        let restored = replay(&bytes).expect("resume");
        assert_eq!(
            current_observed_text(&restored, notes).as_deref(),
            Some("hello again")
        );
    }

    #[test]
    fn a_later_note_read_uses_the_rewritten_sentence() {
        let mut journal = empty_journal();
        let project = "localhost://Users/self/Projects/demo";
        let notes = "localhost://Users/self/Projects/demo/notes.txt";
        assert!(observe(
            &mut journal,
            "localhost://Users/self/Projects/demo/index.html",
            1,
            "<h1>demo</h1>",
        ));
        assert!(observe(
            &mut journal,
            "localhost://Users/self/Projects/demo/style.css",
            1,
            "body{}",
        ));
        assert!(observe(&mut journal, notes, 1, "hello from the project"));
        let edit = propose_edit(
            &mut journal,
            notes,
            "hello from the project",
            "hello again",
            Some(1),
        )
        .unwrap();
        assert!(authorize(&mut journal, edit, Some("fixture-grant")));
        assert!(dispatch(&mut journal, edit));
        assert!(note_provider_wrote(&mut journal, edit));
        let reread = propose_run(&mut journal, project, &["note".to_string()]).unwrap();
        assert!(authorize(&mut journal, reread, Some("fixture-grant")));
        assert!(dispatch(&mut journal, reread));
        assert!(!record_run_result(
            &mut journal,
            reread,
            0,
            "project note hello from the project",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            reread,
            0,
            "project note hello again",
            ""
        ));
        let checked = propose_run(
            &mut journal,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_was_edited".to_string(),
            ],
        )
        .unwrap();
        assert!(authorize(&mut journal, checked, Some("fixture-grant")));
        assert!(dispatch(&mut journal, checked));
        assert!(!record_run_result(
            &mut journal,
            checked,
            0,
            "project note hello again\nproject demo a1097f0d6ed225ad16b19f19d6a260816af54c74bfe82b11e4ce2020233497f1\ntest result: ok",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            checked,
            0,
            "project note hello again\nproject demo 8256365b5a513111b73d3ee3b646a78d58c821c9f3cba1346f6f27c0f38dd36d\ntest result: ok",
            ""
        ));
        let pending = propose_edit(
            &mut journal,
            notes,
            "hello again",
            "hello once more",
            Some(2),
        )
        .unwrap();
        assert!(authorize(&mut journal, pending, Some("fixture-grant")));
        assert!(!observe(&mut journal, notes, 1, "hello again"));
        assert_eq!(
            current_observed_text(&journal.events, notes).as_deref(),
            Some("hello again")
        );
        assert!(observe(&mut journal, notes, 1, "hello from the project"));
        assert!(dispatch(&mut journal, pending));
        assert!(!note_provider_wrote(&mut journal, pending));
        assert_eq!(step_state(&journal, pending), Some(StepState::Denied));
        assert_eq!(
            current_observed_text(&journal.events, notes).as_deref(),
            Some("hello from the project")
        );
        assert_eq!(
            propose_edit(
                &mut journal,
                notes,
                "hello again",
                "hello once more",
                Some(2)
            ),
            Err("stale")
        );
        let fresh = propose_edit(
            &mut journal,
            notes,
            "hello from the project",
            "hello again",
            Some(1),
        )
        .unwrap();
        assert!(authorize(&mut journal, fresh, Some("fixture-grant")));
        assert!(dispatch(&mut journal, fresh));
        assert!(note_provider_wrote(&mut journal, fresh));
        assert_eq!(
            current_observed_text(&journal.events, notes).as_deref(),
            Some("hello again")
        );
        let earlier = propose_run(&mut journal, project, &["note".to_string()]).unwrap();
        assert!(authorize(&mut journal, earlier, Some("fixture-grant")));
        assert!(dispatch(&mut journal, earlier));
        assert!(!record_run_result(
            &mut journal,
            earlier,
            0,
            "project note hello from the project",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            earlier,
            0,
            "project note hello again",
            ""
        ));
        let restored = propose_run(
            &mut journal,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        assert!(authorize(&mut journal, restored, Some("fixture-grant")));
        assert!(dispatch(&mut journal, restored));
        assert!(!record_run_result(
            &mut journal,
            restored,
            0,
            "project demo a1097f0d6ed225ad16b19f19d6a260816af54c74bfe82b11e4ce2020233497f1\ntest result: ok",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            restored,
            0,
            "project demo 8256365b5a513111b73d3ee3b646a78d58c821c9f3cba1346f6f27c0f38dd36d\ntest result: ok",
            ""
        ));
        let saved = model_bytes(&journal.events).unwrap();
        let resumed = replay(&saved).unwrap();
        assert_eq!(
            current_observed_text(&resumed, notes).as_deref(),
            Some("hello again")
        );
    }

    #[test]
    fn a_cancelled_scaffold_lets_the_note_rewrite_land() {
        let mut journal = empty_journal();
        let project = "localhost://Users/self/Projects/demo";
        let index = "localhost://Users/self/Projects/demo/index.html";
        let notes = "localhost://Users/self/Projects/demo/notes.txt";
        let init = propose_init(&mut journal, "self", "demo").unwrap();
        assert!(observe(&mut journal, index, 1, ""));
        let scaffold =
            propose_scaffold(&mut journal, init, "index.html", "<h1>demo</h1>", Some(1)).unwrap();
        assert!(observe(&mut journal, notes, 1, "hello from the project"));
        let rewrite = propose_edit(
            &mut journal,
            notes,
            "hello from the project",
            "hello again",
            Some(1),
        )
        .unwrap();
        assert!(authorize(&mut journal, rewrite, Some("fixture-grant")));
        assert!(!dispatch(&mut journal, rewrite));
        assert_eq!(
            current_observed_text(&journal.events, notes).as_deref(),
            Some("hello from the project")
        );
        assert!(cancel(&mut journal, scaffold));
        assert_eq!(
            current_observed_text(&journal.events, notes).as_deref(),
            Some("hello from the project")
        );
        assert!(dispatch(&mut journal, rewrite));
        assert!(note_provider_wrote(&mut journal, rewrite));
        let reread = propose_run(&mut journal, project, &["note".to_string()]).unwrap();
        assert!(authorize(&mut journal, reread, Some("fixture-grant")));
        assert!(dispatch(&mut journal, reread));
        assert!(!record_run_result(
            &mut journal,
            reread,
            0,
            "project note hello from the project",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            reread,
            0,
            "project note hello again",
            ""
        ));
    }

    #[test]
    fn a_scaffold_stays_empty_after_it_is_sent() {
        let mut journal = empty_journal();
        let index = "localhost://Users/self/Projects/demo/index.html";
        let init = propose_init(&mut journal, "self", "demo").unwrap();
        assert!(observe(&mut journal, index, 1, ""));
        let scaffold =
            propose_scaffold(&mut journal, init, "index.html", "<h1>demo</h1>", Some(1)).unwrap();
        journal
            .steps
            .iter_mut()
            .find(|step| step.id == scaffold)
            .unwrap()
            .seen_version = Some(1);
        assert!(authorize(&mut journal, scaffold, Some("fixture-grant")));
        assert!(dispatch(&mut journal, scaffold));
        assert!(!note_provider_wrote(&mut journal, scaffold));
        assert_eq!(step_state(&journal, scaffold), Some(StepState::Denied));
        assert!(!provider_write_may_be_asked(&journal, scaffold, 1));
        assert_eq!(
            current_observed_text(&journal.events, index).as_deref(),
            Some("")
        );
        assert!(
            !journal
                .steps
                .iter()
                .find(|step| step.id == scaffold)
                .unwrap()
                .has_result
        );
        let notes = "localhost://Users/self/Projects/demo/notes.txt";
        assert!(observe(&mut journal, notes, 1, "hello from the project"));
        let follow = propose_edit(
            &mut journal,
            notes,
            "hello from the project",
            "hello again",
            Some(1),
        )
        .unwrap();
        assert!(authorize(&mut journal, follow, Some("fixture-grant")));
        assert!(dispatch(&mut journal, follow));
        assert!(note_provider_wrote(&mut journal, follow));
        assert_eq!(
            current_observed_text(&journal.events, notes).as_deref(),
            Some("hello again")
        );
        assert_eq!(
            current_observed_text(&journal.events, index).as_deref(),
            Some("")
        );
    }

    #[test]
    fn compaction_refuses_a_summary_that_does_not_shrink() {
        let mut journal = two_turns();
        let before = journal.clone();
        assert!(!compact(&mut journal, &"x".repeat(10_000)));
        assert_eq!(journal, before);
        assert!(!compact(&mut journal, ""));
        assert_eq!(journal, before);
        assert!(!compact(&mut journal, "/tmp"));
        assert_eq!(journal, before);
        assert!(!compact(&mut journal, "localhost://Users/self/../secret"));
        assert_eq!(journal, before);
    }

    #[test]
    fn a_crash_before_dispatch_stays_not_started() {
        let mut journal = two_turns();
        let id = propose_step(&mut journal);
        assert_eq!(step_state(&journal, id), Some(StepState::Prepared));
        assert!(note_crash(&mut journal, id));
        assert_eq!(step_state(&journal, id), Some(StepState::NotStarted));
        assert!(!dispatch(&mut journal, id));
        assert_eq!(step_state(&journal, id), Some(StepState::NotStarted));
        assert!(!note_crash(&mut journal, 0));
    }

    #[test]
    fn a_crash_after_dispatch_is_settlement_unknown() {
        let mut journal = two_turns();
        let id = propose_step(&mut journal);
        assert!(authorize(&mut journal, id, Some("fixture-grant")));
        assert!(dispatch(&mut journal, id));
        assert!(!dispatch(&mut journal, id));
        assert!(note_crash(&mut journal, id));
        assert_eq!(step_state(&journal, id), Some(StepState::SettlementUnknown));
        assert!(!dispatch(&mut journal, id));
        assert!(note_crash(&mut journal, id));
        assert_eq!(step_state(&journal, id), Some(StepState::SettlementUnknown));
    }

    #[test]
    fn a_crash_does_not_start_a_new_series() {
        let mut journal = two_turns();
        let before = derive(&journal.events);
        let epoch = journal.epoch;
        let id = propose_step(&mut journal);
        assert!(note_crash(&mut journal, id));
        assert_eq!(derive(&journal.events), before);
        assert_eq!(journal.epoch, epoch);
    }

    #[test]
    fn a_recorded_journal_replays_to_the_same_bytes() {
        let journal = two_turns();
        let visible = derive(&journal.events);
        let recorded = model_bytes(&visible).unwrap();
        let restored = replay(&recorded).unwrap();
        assert_eq!(model_bytes(&restored).unwrap(), recorded);
        assert_eq!(restored, visible);
        assert!(replay(&recorded[..recorded.len().saturating_sub(1)]).is_none());
        assert!(replay(&[9, 0, 0, 0, 0]).is_none());
    }

    /// Every journal field is set: turns, markers, steps of several kinds and
    /// states, an observation, a snapshot, a skill, an empty assistant line,
    /// and an open compaction with its backup and pending copies.
    fn a_rich_journal() -> Journal {
        let mut journal = two_turns();
        admit_user(&mut journal, &"a long person line ".repeat(20));
        assert!(admit_snapshot(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            "2026-10-20T01:00:00Z",
            "localhost://Users/self/Projects/demo/index.html",
        ));
        assert!(admit_skill(&mut journal, "Prefer the Runtime grant."));
        admit_assistant(&mut journal, "");
        let note = "localhost://Users/self/Projects/demo/notes.txt";
        assert!(observe(&mut journal, note, 1, "hello from the project"));
        let turn = open_turn(&mut journal);
        open_step(&mut journal, turn).unwrap();
        let read = propose_read(&mut journal, "localhost://Users/self/Documents/note.txt");
        assert!(cancel(&mut journal, read));
        let edit = propose_edit(&mut journal, note, "hello", "hi", Some(1)).unwrap();
        assert!(note_crash(&mut journal, edit));
        let run = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        apply_inbox(&mut journal, run, InboxAnswer::Deny, None);
        propose_child(
            &mut journal,
            run,
            "localhost://Users/self/Projects/demo/src",
        )
        .unwrap();
        let mut cursor = journal_cursor("demo-agent", "task-1").unwrap();
        cursor.revision = Some("fixture-revision".to_string());
        let append = propose_journal_append(&mut journal, &cursor).unwrap();
        assert!(note_crash(&mut journal, append));
        assert!(begin_compact(&mut journal, COMPACTION_SUMMARY));
        journal
    }

    #[test]
    fn a_journal_round_trips_through_format_one() {
        let journal = a_rich_journal();
        assert!(journal.compaction_open);
        assert!(journal.compact_backup.is_some() && journal.compact_pending.is_some());
        assert!(!journal.markers.is_empty() && !journal.turns.is_empty());
        assert!(journal.steps.len() >= 4);
        assert!(journal.steps.iter().all(|step| step.grant.is_none()));
        let bytes = encode_journal(&journal, &[0; 32]).unwrap();
        let (back, prev, head) = decode_journal(&bytes).unwrap();
        assert_eq!(back, journal);
        assert_eq!(prev, [0; 32]);
        assert_eq!(head[..], bytes[bytes.len() - 32..]);
        assert_eq!(encode_journal(&back, &[0; 32]).unwrap(), bytes);
        let mut committed = journal.clone();
        assert!(commit_compact(&mut committed));
        assert!(committed.compact_backup.is_none() && committed.compact_pending.is_none());
        let bytes = encode_journal(&committed, &[0; 32]).unwrap();
        assert_eq!(decode_journal(&bytes).unwrap().0, committed);
    }

    #[test]
    fn decoding_keeps_the_replay_bytes() {
        let journal = a_rich_journal();
        let bytes = encode_journal(&journal, &[0; 32]).unwrap();
        let back = decode_journal(&bytes).unwrap().0;
        let before = model_bytes(&journal.events).unwrap();
        assert_eq!(model_bytes(&back.events).unwrap(), before);
        assert_eq!(replay(&before).unwrap(), back.events);
        assert_eq!(derive(&back.events), derive(&journal.events));
        assert!(back
            .events
            .iter()
            .any(|node| node.role == Role::Assistant && node.text.is_empty()));
    }

    #[test]
    fn every_flipped_byte_is_refused() {
        let bytes = encode_journal(&a_rich_journal(), &[0; 32]).unwrap();
        for index in 0..bytes.len() {
            for bit in [0x01, 0x80] {
                let mut flipped = bytes.clone();
                flipped[index] ^= bit;
                assert!(decode_journal(&flipped).is_err(), "byte {index} bit {bit}");
            }
        }
    }

    #[test]
    fn a_wrong_format_version_is_refused() {
        let bytes = encode_journal(&two_turns(), &[0; 32]).unwrap();
        for version in [0u16, 2, u16::MAX] {
            let mut other = bytes.clone();
            other[4..6].copy_from_slice(&version.to_le_bytes());
            assert_eq!(decode_journal(&other).unwrap_err(), "format version");
        }
        let mut magic = bytes.clone();
        magic[0] = b'X';
        assert_eq!(decode_journal(&magic).unwrap_err(), "not a journal");
    }

    #[test]
    fn every_truncation_is_refused() {
        let bytes = encode_journal(&a_rich_journal(), &[0; 32]).unwrap();
        for len in 0..bytes.len() {
            assert_eq!(
                decode_journal(&bytes[..len]).unwrap_err(),
                "truncated",
                "length {len}"
            );
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(decode_journal(&longer).unwrap_err(), "trailing bytes");
    }

    #[test]
    fn node_zero_and_the_epoch_survive_a_round_trip() {
        let journal = two_turns();
        let back = decode_journal(&encode_journal(&journal, &[0; 32]).unwrap())
            .unwrap()
            .0;
        assert_eq!(back.epoch, 1);
        assert_eq!(back.events[0], journal.events[0]);
        assert_eq!(back.events[0].text, SYSTEM_HEAD);
        let mut compacted = a_rich_journal();
        assert!(commit_compact(&mut compacted));
        assert_eq!(compacted.epoch, 2);
        let back = decode_journal(&encode_journal(&compacted, &[0; 32]).unwrap())
            .unwrap()
            .0;
        assert_eq!(back.epoch, 2);
        assert_eq!(back.events[0].text, SYSTEM_HEAD);
        assert_eq!(back.events[0].source, NodeSource::Head);
    }

    #[test]
    fn a_grant_is_never_stored() {
        let mut journal = a_rich_journal();
        let read = propose_read(&mut journal, "localhost://Users/self/Documents/note.txt");
        assert!(authorize(&mut journal, read, Some("fixture-grant")));
        let standing = propose_read(&mut journal, "localhost://Users/self/Documents/other.txt");
        assert!(apply_inbox(
            &mut journal,
            standing,
            InboxAnswer::Standing,
            Some("fixture-grant")
        ));
        let bytes = encode_journal(&journal, &[0; 32]).unwrap();
        assert!(!bytes
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant"));
        assert!(bytes
            .windows(b"standing".len())
            .any(|window| window == b"standing"));
        let mut back = decode_journal(&bytes).unwrap().0;
        assert_eq!(back, without_grants(&journal));
        assert_ne!(back, journal);
        assert!(back.steps.iter().all(|step| step.grant.is_none()));
        assert_eq!(step_state(&back, read), Some(StepState::Prepared));
        assert!(!dispatch(&mut back, read));
        assert_eq!(step_state(&back, read), Some(StepState::Denied));
    }

    #[test]
    fn a_journal_over_the_cap_is_refused() {
        let mut journal = two_turns();
        admit_user(&mut journal, &"x".repeat(JOURNAL_CAP));
        assert_eq!(encode_journal(&journal, &[0; 32]), None);
        assert_eq!(
            decode_journal(&vec![0; JOURNAL_CAP + 1]).unwrap_err(),
            "too large"
        );
        let mut near = two_turns();
        admit_user(&mut near, &"x".repeat(JOURNAL_CAP - 4096));
        let bytes = encode_journal(&near, &[0; 32]).unwrap();
        assert!(bytes.len() <= JOURNAL_CAP);
        assert_eq!(decode_journal(&bytes).unwrap().0, near);
    }

    /// The bridge carries bytes as a JSON number array, up to four characters per
    /// byte. The cap, at worst, must leave room for the envelope inside the frame,
    /// and the bridge test that writes a worst-case journal must use the same cap.
    #[test]
    fn the_cap_fits_the_runtime_frame_at_four_bytes_per_byte() {
        let bridge = include_str!("../../../elastos/crates/elastos-server/src/resource_bridge.rs");
        assert!(bridge.contains("const MAX_RESOURCE_FRAME_BYTES: usize = 1_048_576;"));
        assert!(bridge.contains(&format!(
            "const JOURNAL_CAP_BYTES: usize = {} * 1024;",
            JOURNAL_CAP / 1024
        )));
        const { assert!(JOURNAL_CAP * 4 + 64 * 1024 <= 1_048_576) };
    }

    #[test]
    fn the_cap_holds_at_the_last_byte() {
        let base = encode_journal(&two_turns(), &[0; 32]).unwrap().len();
        let mut fits = two_turns();
        let text = JOURNAL_CAP - base - 4 - 2 - 32 - 1 - 4;
        admit_user(&mut fits, &"x".repeat(text));
        let exact = encode_journal(&fits, &[0; 32]).unwrap();
        assert_eq!(exact.len(), JOURNAL_CAP);
        assert_eq!(decode_journal(&exact).unwrap().0, fits);
        let mut over = two_turns();
        admit_user(&mut over, &"x".repeat(text + 1));
        assert_eq!(encode_journal(&over, &[0; 32]), None);
    }

    /// Split format 1 bytes into the header and the records.
    fn journal_records(bytes: &[u8]) -> (Vec<u8>, Vec<(u8, Vec<u8>)>) {
        let header = bytes[..JOURNAL_HEADER].to_vec();
        let mut records = Vec::new();
        let mut at = JOURNAL_HEADER;
        while at + 32 < bytes.len() {
            let tag = bytes[at];
            let len = u32::from_le_bytes(bytes[at + 1..at + 5].try_into().unwrap()) as usize;
            records.push((tag, bytes[at + 5..at + 5 + len].to_vec()));
            at += 5 + len + 32;
        }
        (header, records)
    }

    /// Build format 1 bytes with every link and the head recomputed. The hash
    /// chain has no key, so anyone who can write the object can do this.
    fn relinked(mut header: Vec<u8>, records: &[(u8, Vec<u8>)]) -> Vec<u8> {
        header[JOURNAL_HEADER - 4..].copy_from_slice(&(records.len() as u32).to_le_bytes());
        let mut link = sha256(&header);
        let mut out = header;
        for (tag, payload) in records {
            link = journal_link(&link, *tag, payload).unwrap();
            out.push(*tag);
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(payload);
            out.extend_from_slice(&link);
        }
        out.extend_from_slice(&link);
        out
    }

    #[test]
    fn a_relinked_but_malformed_journal_is_refused() {
        let mut journal = two_turns();
        propose_step(&mut journal);
        let bytes = encode_journal(&journal, &[0; 32]).unwrap();
        let (header, records) = journal_records(&bytes);
        assert_eq!(relinked(header.clone(), &records), bytes);
        let step_at = records.iter().position(|(tag, _)| *tag == 3).unwrap();
        let mut reordered = records.clone();
        let event = reordered.remove(0);
        reordered.insert(step_at, event);
        assert_eq!(
            decode_journal(&relinked(header.clone(), &reordered)).unwrap_err(),
            "record"
        );
        // Step payload of an empty step: has_result at 22, parent flag at 35, parent value at 36.
        for (offset, value) in [(22, 2u8), (35, 2), (36, 5)] {
            let mut bad = records.clone();
            bad[step_at].1[offset] = value;
            assert_eq!(
                decode_journal(&relinked(header.clone(), &bad)).unwrap_err(),
                "record",
                "offset {offset}"
            );
        }
        for tag in [5u8, 6, 7, 0] {
            let mut extra = records.clone();
            extra.push((tag, node_payload(&journal.events[0]).unwrap()));
            assert_eq!(
                decode_journal(&relinked(header.clone(), &extra)).unwrap_err(),
                "record",
                "tag {tag}"
            );
        }
        // Header: compaction_open at 14, backup flag at 15, backup epoch at 16.
        for (offset, value) in [(14, 2u8), (15, 2), (16, 7)] {
            let mut bad_header = header.clone();
            bad_header[offset] = value;
            assert_eq!(
                decode_journal(&relinked(bad_header, &records)).unwrap_err(),
                "record",
                "header offset {offset}"
            );
        }
    }

    #[test]
    fn the_previous_head_links_two_versions() {
        let mut journal = two_turns();
        let first = encode_journal(&journal, &[0; 32]).unwrap();
        let (_, _, first_head) = decode_journal(&first).unwrap();
        admit_user(&mut journal, "third turn");
        let second = encode_journal(&journal, &first_head).unwrap();
        let (back, prev, second_head) = decode_journal(&second).unwrap();
        assert_eq!(prev, first_head);
        assert_ne!(second_head, first_head);
        assert_eq!(back, journal);
    }

    #[test]
    fn a_head_rewrite_and_a_step_change_different_records() {
        let journal = two_turns();
        let original = model_bytes(&journal.events).unwrap();
        let mut rewritten = journal.clone();
        admit_system(&mut rewritten, "Replacement head.", false);
        assert_ne!(model_bytes(&rewritten.events).unwrap(), original);
        let mut with_step = journal.clone();
        let _id = propose_step(&mut with_step);
        assert_eq!(model_bytes(&with_step.events).unwrap(), original);
    }

    #[test]
    fn compaction_replays_the_same_head() {
        let journal = two_turns();
        let head = journal.events[0].text.clone();
        let before = model_bytes(&journal.events).unwrap();
        let mut compacted = journal.clone();
        assert!(compact(&mut compacted, COMPACTION_SUMMARY));
        let recorded = model_bytes(&compacted.events).unwrap();
        assert_ne!(recorded, before);
        let restored = replay(&recorded).unwrap();
        assert_eq!(restored[0].text.as_bytes(), head.as_bytes());
        assert_eq!(model_bytes(&restored).unwrap(), recorded);
    }

    #[test]
    fn a_read_with_no_grant_is_denied() {
        let mut journal = two_turns();
        let id = propose_read(&mut journal, "localhost://Users/self/Documents/note.txt");
        assert!(!authorize(&mut journal, id, None));
        assert_eq!(step_state(&journal, id), Some(StepState::Denied));
        assert!(!dispatch(&mut journal, id));
        assert!(!note_crash(&mut journal, id));
        assert_eq!(step_state(&journal, id), Some(StepState::Denied));
        let empty = propose_read(&mut journal, "localhost://Users/self/Documents/note.txt");
        assert!(!authorize(&mut journal, empty, Some("")));
        assert_eq!(step_state(&journal, empty), Some(StepState::Denied));
    }

    #[test]
    fn a_second_authorize_stays_denied() {
        let mut journal = two_turns();
        let id = propose_read(&mut journal, "localhost://Users/self/Documents/note.txt");
        assert!(!authorize(&mut journal, id, None));
        assert!(!authorize(&mut journal, id, Some("fixture-grant")));
        assert_eq!(step_state(&journal, id), Some(StepState::Denied));
        assert!(!dispatch(&mut journal, id));
        assert_eq!(step_state(&journal, id), Some(StepState::Denied));
    }

    #[test]
    fn dispatch_without_a_grant_is_denied_even_without_authorize() {
        let mut journal = two_turns();
        let before = model_bytes(&journal.events).unwrap();
        let id = propose_read(&mut journal, "localhost://Users/self/Documents/note.txt");
        assert!(!dispatch(&mut journal, id));
        assert_eq!(step_state(&journal, id), Some(StepState::Denied));
        let step = journal.steps.iter().find(|step| step.id == id).unwrap();
        assert_eq!(step.grant, None);
        assert!(!dispatch(&mut journal, id));
        assert_eq!(model_bytes(&journal.events).unwrap(), before);
        let granted = propose_read(&mut journal, "localhost://Users/self/Documents/note.txt");
        assert!(authorize(&mut journal, granted, Some("fixture-grant")));
        assert!(dispatch(&mut journal, granted));
        assert_eq!(step_state(&journal, granted), Some(StepState::Dispatched));
    }

    #[test]
    fn a_read_proposal_does_not_change_model_bytes() {
        let mut journal = two_turns();
        let before = model_bytes(&journal.events).unwrap();
        let epoch = journal.epoch;
        let id = propose_read(&mut journal, "localhost://Users/self/Documents/note.txt");
        assert_eq!(step_state(&journal, id), Some(StepState::Prepared));
        let step = journal.steps.iter().find(|step| step.id == id).unwrap();
        assert_eq!(step.kind, ProposalKind::Read);
        assert_eq!(step.resource, "localhost://Users/self/Documents/note.txt");
        assert_eq!(step.grant, None);
        assert_eq!(step.effect_id, id);
        assert_eq!(model_bytes(&journal.events).unwrap(), before);
        assert_eq!(journal.epoch, epoch);
    }

    #[test]
    fn cancel_before_dispatch_never_dispatches() {
        let mut journal = two_turns();
        let id = propose_step(&mut journal);
        assert!(cancel(&mut journal, id));
        assert_eq!(step_state(&journal, id), Some(StepState::Cancelled));
        assert!(!cancel(&mut journal, id));
        assert!(!dispatch(&mut journal, id));
        assert!(!note_crash(&mut journal, id));
        assert_eq!(step_state(&journal, id), Some(StepState::Cancelled));
        assert!(!cancel(&mut journal, 0));
    }

    #[test]
    fn cancel_after_dispatch_is_not_success() {
        let mut journal = two_turns();
        let id = propose_step(&mut journal);
        assert!(authorize(&mut journal, id, Some("fixture-grant")));
        assert!(dispatch(&mut journal, id));
        assert!(!cancel(&mut journal, id));
        assert_eq!(step_state(&journal, id), Some(StepState::Dispatched));
        assert!(note_crash(&mut journal, id));
        assert!(!cancel(&mut journal, id));
        assert_eq!(step_state(&journal, id), Some(StepState::SettlementUnknown));
    }

    #[test]
    fn cancel_leaves_the_epoch_and_model_bytes() {
        let mut journal = two_turns();
        let before = model_bytes(&journal.events).unwrap();
        let epoch = journal.epoch;
        let id = propose_step(&mut journal);
        assert!(cancel(&mut journal, id));
        assert_eq!(model_bytes(&journal.events).unwrap(), before);
        assert_eq!(journal.epoch, epoch);
        let denied = propose_read(&mut journal, "localhost://Users/self/Documents/note.txt");
        assert!(!authorize(&mut journal, denied, None));
        assert!(!cancel(&mut journal, denied));
        assert_eq!(step_state(&journal, denied), Some(StepState::Denied));
    }

    #[test]
    fn a_snapshot_appends_without_moving_the_head() {
        let mut journal = two_turns();
        let head = journal.events[0].text.clone();
        let epoch = journal.epoch;
        assert!(admit_snapshot(
            &mut journal,
            "localhost://Users/self",
            "2026-10-12T13:44:00Z",
            "localhost://Users/self/Documents/note.txt",
        ));
        assert_eq!(journal.events[0].text, head);
        assert_eq!(journal.events[0].source, NodeSource::Head);
        assert_eq!(journal.epoch, epoch);
        let start = journal.events.len() - 3;
        assert_eq!(journal.events[start].text, "localhost://Users/self");
        assert_eq!(journal.events[start + 1].text, "2026-10-12T13:44:00Z");
        assert_eq!(
            journal.events[start + 2].text,
            "localhost://Users/self/Documents/note.txt"
        );
        assert!(journal.events[start..]
            .iter()
            .all(|node| { node.role == Role::User && node.source == NodeSource::Snapshot }));
        let len = journal.events.len();
        assert!(admit_snapshot(
            &mut journal,
            "localhost://Users/self",
            "2026-10-12T13:45:00Z",
            "",
        ));
        assert_eq!(journal.events.len(), len + 2);
        assert_eq!(journal.epoch, epoch);
        assert_eq!(journal.events[0].text, head);
        let before = journal.clone();
        assert!(!admit_snapshot(
            &mut journal,
            "/tmp",
            "2026-10-12T13:46:00Z",
            "localhost://Users/self/Documents/note.txt",
        ));
        assert!(!admit_snapshot(
            &mut journal,
            "localhost://Users/self/../secret",
            "2026-10-12T13:46:00Z",
            "",
        ));
        assert!(!admit_snapshot(
            &mut journal,
            "localhost://Users/self",
            "2026-10-12T13:46:00Z",
            "/tmp/secret",
        ));
        assert_eq!(journal, before);
    }

    #[test]
    fn an_empty_snapshot_leaves_the_journal_unchanged() {
        let mut journal = two_turns();
        let before = journal.clone();
        assert!(!admit_snapshot(
            &mut journal,
            "",
            "2026-10-12T13:44:00Z",
            "note",
        ));
        assert_eq!(journal, before);
        assert!(!admit_snapshot(
            &mut journal,
            "localhost://Users/self",
            "",
            "note"
        ));
        assert_eq!(journal, before);
        let mut empty = empty_journal();
        assert!(!admit_snapshot(
            &mut empty,
            "localhost://Users/self",
            "2026-10-12T13:44:00Z",
            "note",
        ));
        assert!(empty.events.is_empty());
    }

    #[test]
    fn a_snapshot_replays_with_its_source() {
        let mut journal = two_turns();
        assert!(admit_snapshot(
            &mut journal,
            "localhost://Users/self",
            "2026-10-12T13:44:00Z",
            "localhost://Users/self/Documents/note.txt",
        ));
        let recorded = model_bytes(&journal.events).unwrap();
        let restored = replay(&recorded).unwrap();
        assert_eq!(restored, journal.events);
        assert_eq!(restored.last().unwrap().source, NodeSource::Snapshot);
        assert!(replay(&[1, 10, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn cancel_after_a_checkpoint_does_not_dispatch() {
        let mut journal = two_turns();
        let saved = checkpoint(&journal).unwrap();
        let epoch = journal.epoch;
        let id = propose_step(&mut journal);
        assert!(cancel(&mut journal, id));
        assert!(!dispatch(&mut journal, id));
        assert_eq!(step_state(&journal, id), Some(StepState::Cancelled));
        assert_eq!(model_bytes(&journal.events).unwrap(), saved);
        assert_eq!(journal.epoch, epoch);
    }

    #[test]
    fn a_crash_after_a_checkpoint_keeps_the_settlement_words() {
        let mut journal = two_turns();
        let before_crash = checkpoint(&journal).unwrap();
        let prepared = propose_step(&mut journal);
        assert!(note_crash(&mut journal, prepared));
        assert_eq!(step_state(&journal, prepared), Some(StepState::NotStarted));
        assert!(!dispatch(&mut journal, prepared));
        assert_eq!(model_bytes(&journal.events).unwrap(), before_crash);
        let before_send = checkpoint(&journal).unwrap();
        let sent = propose_step(&mut journal);
        assert!(authorize(&mut journal, sent, Some("fixture-grant")));
        assert!(dispatch(&mut journal, sent));
        assert!(note_crash(&mut journal, sent));
        assert_eq!(
            step_state(&journal, sent),
            Some(StepState::SettlementUnknown)
        );
        assert!(!dispatch(&mut journal, sent));
        assert!(!cancel(&mut journal, sent));
        assert_eq!(model_bytes(&journal.events).unwrap(), before_send);
    }

    #[test]
    fn an_over_budget_skill_leaves_the_journal_unchanged() {
        let mut journal = two_turns();
        let before = journal.clone();
        assert!(!admit_skill(&mut journal, ""));
        assert_eq!(journal, before);
        assert!(!admit_skill(&mut journal, "/tmp"));
        assert_eq!(journal, before);
        assert!(!admit_skill(&mut journal, &"x".repeat(4_001)));
        assert_eq!(journal, before);
        assert!(admit_skill(&mut journal, &"x".repeat(SKILL_BUDGET)));
        assert_eq!(journal.events.last().unwrap().text.len(), SKILL_BUDGET);
        assert_eq!(journal.events.last().unwrap().source, NodeSource::Skill);
        assert_eq!(journal.epoch, before.epoch);
        assert_eq!(journal.events[0].text, before.events[0].text);
        let mut empty = empty_journal();
        assert!(!admit_skill(&mut empty, "Prefer the Runtime grant."));
        assert!(empty.events.is_empty());
    }

    #[test]
    fn compaction_keeps_a_skill_node() {
        let mut journal = two_turns();
        let skill = "Prefer the Runtime grant.";
        let head = journal.events[0].text.clone();
        assert!(admit_skill(&mut journal, skill));
        assert!(compact(&mut journal, COMPACTION_SUMMARY));
        assert_eq!(journal.events[0].text, head);
        assert_eq!(journal.events[0].source, NodeSource::Head);
        assert_eq!(journal.events[1].role, Role::User);
        assert_eq!(journal.events[1].source, NodeSource::CompactionCheckpoint);
        assert_eq!(journal.events[1].text, COMPACTION_SUMMARY);
        assert_eq!(journal.epoch, 2);
        assert!(journal.events.iter().any(|node| {
            node.source == NodeSource::Skill && node.role == Role::User && node.text == skill
        }));
    }

    #[test]
    fn compaction_keeps_the_current_note() {
        let mut journal = two_turns();
        let notes = "localhost://Users/self/Projects/demo/notes.txt";
        assert!(observe(&mut journal, notes, 1, "hello again"));
        assert!(compact(&mut journal, COMPACTION_SUMMARY));
        assert_eq!(
            current_observed_text(&journal.events, notes).as_deref(),
            Some("hello again")
        );
        let saved = model_bytes(&journal.events).unwrap();
        let resumed = replay(&saved).unwrap();
        assert_eq!(
            current_observed_text(&resumed, notes).as_deref(),
            Some("hello again")
        );
        let project = "localhost://Users/self/Projects/demo";
        let quoted = propose_run(&mut journal, project, &["note".to_string()]).unwrap();
        assert!(authorize(&mut journal, quoted, Some("fixture-grant")));
        assert!(dispatch(&mut journal, quoted));
        assert!(!record_run_result(
            &mut journal,
            quoted,
            0,
            "project note hello from the project",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            quoted,
            0,
            "project note hello again",
            ""
        ));
        let follow = propose_edit(
            &mut journal,
            notes,
            "hello again",
            "hello once more",
            Some(1),
        )
        .unwrap();
        assert!(authorize(&mut journal, follow, Some("fixture-grant")));
        assert!(dispatch(&mut journal, follow));
        assert!(note_provider_wrote(&mut journal, follow));
        assert_eq!(
            current_observed_text(&journal.events, notes).as_deref(),
            Some("hello once more")
        );
        let mut crashed = journal.clone();
        assert!(begin_compact(&mut crashed, COMPACTION_SUMMARY));
        assert!(note_crash_during_compact(&mut crashed));
        assert!(!crashed.compaction_open);
        assert!(!commit_compact(&mut crashed));
        assert_eq!(
            current_observed_text(&crashed.events, notes).as_deref(),
            Some("hello once more")
        );
        assert_eq!(
            observed_text_at(&crashed.events, notes, 1).as_deref(),
            Some("hello again")
        );
        assert!(compact(&mut journal, COMPACTION_SUMMARY));
        assert_eq!(
            current_observed_text(&journal.events, notes).as_deref(),
            Some("hello once more")
        );
        assert!(!observe(&mut journal, notes, 1, "hello once more"));
        assert!(observe(&mut journal, notes, 1, "hello again"));
        assert_eq!(
            current_observed_text(&journal.events, notes).as_deref(),
            Some("hello again")
        );
    }

    #[test]
    fn compaction_keeps_the_project_tree() {
        let mut journal = two_turns();
        let project = "localhost://Users/self/Projects/demo";
        assert!(admit_skill(&mut journal, "Prefer the Runtime grant."));
        assert!(observe(
            &mut journal,
            "localhost://Users/self/Projects/demo/index.html",
            1,
            "<h1>demo</h1>",
        ));
        assert!(observe(
            &mut journal,
            "localhost://Users/self/Projects/demo/style.css",
            1,
            "body{}",
        ));
        assert!(observe(
            &mut journal,
            "localhost://Users/self/Projects/demo/notes.txt",
            1,
            "hello from the project",
        ));
        assert!(compact(&mut journal, COMPACTION_SUMMARY));
        assert!(journal.events.iter().any(|node| {
            node.source == NodeSource::Skill && node.text == "Prefer the Runtime grant."
        }));
        let listed = propose_run(&mut journal, project, &["files".to_string()]).unwrap();
        assert!(authorize(&mut journal, listed, Some("fixture-grant")));
        assert!(dispatch(&mut journal, listed));
        assert!(!record_run_result(
            &mut journal,
            listed,
            0,
            "project file index.html\nproject file style.css",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            listed,
            0,
            "project file index.html\nproject file notes.txt\nproject file style.css",
            ""
        ));
        let checked = propose_run(
            &mut journal,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        assert!(authorize(&mut journal, checked, Some("fixture-grant")));
        assert!(dispatch(&mut journal, checked));
        assert!(record_run_result(
            &mut journal,
            checked,
            0,
            "project demo a1097f0d6ed225ad16b19f19d6a260816af54c74bfe82b11e4ce2020233497f1\ntest result: ok",
            ""
        ));
    }

    #[test]
    fn compaction_keeps_the_workspace_snapshot() {
        let mut journal = two_turns();
        let head = journal.events[0].text.clone();
        assert!(admit_snapshot(
            &mut journal,
            "localhost://Users/self",
            "2026-10-13T01:29:00Z",
            "localhost://Users/self/Projects/demo/notes.txt",
        ));
        assert!(compact(&mut journal, COMPACTION_SUMMARY));
        assert_eq!(journal.events[0].text, head);
        assert_eq!(journal.events[0].source, NodeSource::Head);
        for text in [
            "localhost://Users/self",
            "2026-10-13T01:29:00Z",
            "localhost://Users/self/Projects/demo/notes.txt",
        ] {
            assert!(journal
                .events
                .iter()
                .any(|node| node.source == NodeSource::Snapshot && node.text == text));
        }
        let saved = model_bytes(&journal.events).unwrap();
        assert_eq!(replay(&saved).unwrap(), journal.events);
    }

    #[test]
    fn a_goal_survives_shortening_and_does_not_grant() {
        let mut journal = two_turns();
        let epoch = journal.epoch;
        let steps = journal.steps.len();
        assert!(!record_visible(&mut journal, VisibleRecord::Goal, ""));
        assert!(!record_visible(&mut journal, VisibleRecord::Goal, "/tmp"));
        assert!(record_visible(
            &mut journal,
            VisibleRecord::Goal,
            "finish the note"
        ));
        assert!(record_visible(
            &mut journal,
            VisibleRecord::Todo,
            "keep the note current"
        ));
        assert!(record_visible(
            &mut journal,
            VisibleRecord::PlanEntered,
            "edit the note"
        ));
        assert!(record_visible(
            &mut journal,
            VisibleRecord::PlanExitAsked,
            "the note is ready"
        ));
        assert!(record_visible(
            &mut journal,
            VisibleRecord::SpillPointer,
            "notes.txt"
        ));
        assert_eq!(journal.epoch, epoch);
        assert_eq!(journal.steps.len(), steps);
        assert!(compact(&mut journal, COMPACTION_SUMMARY));
        assert!(journal.events.iter().all(|node| node.text != "second turn"));
        assert!(journal.events.iter().any(|node| {
            node.source == NodeSource::Person && node.text == "goal\nfinish the note"
        }));
        assert!(journal.events.iter().any(|node| {
            node.source == NodeSource::Person && node.text == "todo\nkeep the note current"
        }));
        assert!(journal.events.iter().any(|node| {
            node.source == NodeSource::Person && node.text == "plan-entered\nedit the note"
        }));
        assert!(journal.events.iter().any(|node| {
            node.source == NodeSource::Person && node.text == "plan-exit-asked\nthe note is ready"
        }));
        assert!(journal
            .events
            .iter()
            .any(|node| node.source == NodeSource::Person && node.text == "spill\nnotes.txt"));
        assert_eq!(journal.steps.len(), steps);
        let denied = propose_step(&mut journal);
        assert!(!apply_inbox(
            &mut journal,
            denied,
            InboxAnswer::Deny,
            Some("fixture-grant")
        ));
        assert_eq!(step_state(&journal, denied), Some(StepState::Denied));
        assert!(journal
            .steps
            .iter()
            .find(|step| step.id == denied)
            .is_some_and(|step| step.grant.is_none() && step.inbox == "deny"));
        let once = propose_step(&mut journal);
        assert!(!apply_inbox(
            &mut journal,
            once,
            InboxAnswer::AllowOnce,
            None
        ));
        assert_eq!(step_state(&journal, once), Some(StepState::Denied));
        let session = propose_step(&mut journal);
        assert!(!apply_inbox(
            &mut journal,
            session,
            InboxAnswer::AllowSession,
            Some("")
        ));
        assert_eq!(step_state(&journal, session), Some(StepState::Denied));
        let standing = propose_step(&mut journal);
        assert!(apply_inbox(
            &mut journal,
            standing,
            InboxAnswer::Standing,
            Some("fixture-grant")
        ));
        assert_eq!(step_state(&journal, standing), Some(StepState::Prepared));
        assert!(journal
            .steps
            .iter()
            .find(|step| step.id == standing)
            .is_some_and(
                |step| step.grant.as_deref() == Some("fixture-grant") && step.inbox == "standing"
            ));
        assert!(!apply_inbox(
            &mut journal,
            standing,
            InboxAnswer::Deny,
            Some("other-grant")
        ));
        assert!(journal
            .steps
            .iter()
            .find(|step| step.id == standing)
            .is_some_and(
                |step| step.grant.as_deref() == Some("fixture-grant") && step.inbox == "standing"
            ));
        let other = propose_step(&mut journal);
        assert_eq!(step_state(&journal, other), Some(StepState::Prepared));
        assert!(journal
            .steps
            .iter()
            .find(|step| step.id == other)
            .is_some_and(|step| step.grant.is_none() && step.inbox.is_empty()));
        let held = propose_step(&mut journal);
        assert!(apply_inbox(
            &mut journal,
            held,
            InboxAnswer::Standing,
            Some("fixture-grant")
        ));
        assert!(cancel(&mut journal, held));
        assert!(!dispatch(&mut journal, held));
        assert_eq!(step_state(&journal, held), Some(StepState::Cancelled));
        assert!(journal
            .events
            .iter()
            .any(|node| { node.source == NodeSource::Person && node.text == "inbox\nstanding" }));
        let saved = model_bytes(&journal.events).unwrap();
        assert!(saved
            .windows(b"inbox\nstanding".len())
            .any(|window| window == b"inbox\nstanding"));
        assert!(!saved
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant"));
        let saved = model_bytes(&journal.events).unwrap();
        assert_eq!(replay(&saved).unwrap(), journal.events);
    }

    #[test]
    fn a_spill_pointer_keeps_the_file_text() {
        let mut journal = two_turns();
        let notes = "localhost://Users/self/Projects/demo/notes.txt";
        assert!(observe(&mut journal, notes, 1, "hello from the project"));
        let id = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &["note".to_string()],
        )
        .unwrap();
        assert!(!spill_pointer(&mut journal, id, notes));
        assert!(authorize(&mut journal, id, Some("fixture-grant")));
        assert!(!spill_pointer(&mut journal, id, notes));
        assert!(dispatch(&mut journal, id));
        assert!(!spill_pointer(&mut journal, id, "/tmp/secret"));
        assert!(!spill_pointer(
            &mut journal,
            id,
            "localhost://Users/self/Projects/demo/style.css"
        ));
        assert!(spill_pointer(&mut journal, id, notes));
        assert_eq!(
            current_observed_text(&journal.events, notes).as_deref(),
            Some("hello from the project")
        );
        assert!(!spill_pointer(&mut journal, id, notes));
        assert!(journal.events.iter().any(|node| {
            node.role == Role::ToolResult && node.text == format!("spill\n{notes}\n1")
        }));
        assert!(compact(&mut journal, COMPACTION_SUMMARY));
        assert_eq!(
            current_observed_text(&journal.events, notes).as_deref(),
            Some("hello from the project")
        );
        assert!(journal.events.iter().any(|node| {
            node.source == NodeSource::Person && node.text == format!("spill\n{notes}\n1")
        }));
        let moved = propose_edit(
            &mut journal,
            notes,
            "hello from the project",
            "hello again",
            Some(1),
        )
        .unwrap();
        assert!(authorize(&mut journal, moved, Some("fixture-grant")));
        assert!(dispatch(&mut journal, moved));
        assert!(note_provider_wrote(&mut journal, moved));
        assert_eq!(
            current_observed_text(&journal.events, notes).as_deref(),
            Some("hello again")
        );
        assert_eq!(
            observed_text_at(&journal.events, notes, 1).as_deref(),
            Some("hello from the project")
        );
        assert_eq!(
            text_at_spill(&journal.events, notes).as_deref(),
            Some("hello from the project")
        );
        let again = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &["note".to_string()],
        )
        .unwrap();
        assert!(authorize(&mut journal, again, Some("fixture-grant")));
        assert!(dispatch(&mut journal, again));
        assert!(spill_pointer(&mut journal, again, notes));
        assert_eq!(
            text_at_spill(&journal.events, notes).as_deref(),
            Some("hello again")
        );
        assert_eq!(
            observed_text_at(&journal.events, notes, 1).as_deref(),
            Some("hello from the project")
        );
        assert!(journal.events.iter().any(|node| {
            node.source == NodeSource::Person && node.text == format!("spill\n{notes}\n1")
        }));
        assert!(journal.events.iter().any(|node| {
            node.source == NodeSource::Person && node.text == format!("spill\n{notes}\n2")
        }));
        let style = "localhost://Users/self/Projects/demo/style.css";
        assert!(observe(&mut journal, style, 1, "body{}"));
        assert!(!spill_pointer(&mut journal, again, style));
        let styled = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &["files".to_string()],
        )
        .unwrap();
        assert!(authorize(&mut journal, styled, Some("fixture-grant")));
        assert!(dispatch(&mut journal, styled));
        assert!(spill_pointer(&mut journal, styled, style));
        assert_eq!(
            text_at_spill(&journal.events, notes).as_deref(),
            Some("hello again")
        );
        assert_eq!(
            text_at_spill(&journal.events, style).as_deref(),
            Some("body{}")
        );
        let main = "localhost://Users/self/Projects/demo/src/main.rs";
        assert!(observe(&mut journal, main, 1, "fn main() {}"));
        let parent = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/demo",
            &["note".to_string()],
        )
        .unwrap();
        assert!(authorize(&mut journal, parent, Some("fixture-grant")));
        let child = propose_child(
            &mut journal,
            parent,
            "localhost://Users/self/Projects/demo/src",
        )
        .unwrap();
        assert!(authorize(&mut journal, child, Some("child-grant")));
        assert!(dispatch(&mut journal, child));
        assert!(!spill_pointer(&mut journal, child, notes));
        assert!(spill_pointer(&mut journal, child, main));
        assert_eq!(
            text_at_spill(&journal.events, notes).as_deref(),
            Some("hello again")
        );
        assert_eq!(
            text_at_spill(&journal.events, main).as_deref(),
            Some("fn main() {}")
        );
        assert!(!note_crash(&mut journal, child));
        assert_eq!(step_state(&journal, child), Some(StepState::Dispatched));
        assert_eq!(
            text_at_spill(&journal.events, main).as_deref(),
            Some("fn main() {}")
        );
        let saved_main = model_bytes(&journal.events).unwrap();
        let resumed_main = replay(&saved_main).unwrap();
        assert_eq!(
            text_at_spill(&resumed_main, main).as_deref(),
            Some("fn main() {}")
        );
        assert!(compact(&mut journal, COMPACTION_SUMMARY));
        assert_eq!(
            text_at_spill(&journal.events, main).as_deref(),
            Some("fn main() {}")
        );
        journal.events.push(SurfaceNode {
            role: Role::User,
            text: format!("spill\n{notes}\n9"),
            source: NodeSource::Person,
        });
        assert_eq!(
            text_at_spill(&journal.events, notes).as_deref(),
            Some("hello again")
        );
        let saved = model_bytes(&journal.events).unwrap();
        assert!(!saved
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant"));
    }

    #[test]
    fn the_same_command_waits_until_the_first_has_a_result() {
        let mut journal = empty_journal();
        let project = "localhost://Users/self/Projects/demo";
        let first = propose_run(&mut journal, project, &["note".to_string()]).unwrap();
        let second = propose_run(&mut journal, project, &["files".to_string()]).unwrap();
        let third = propose_run(&mut journal, project, &["note".to_string()]).unwrap();
        assert!(authorize(&mut journal, first, Some("fixture-grant")));
        assert!(authorize(&mut journal, second, Some("fixture-grant")));
        assert!(authorize(&mut journal, third, Some("fixture-grant")));
        assert!(dispatch(&mut journal, first));
        assert!(!dispatch(&mut journal, third));
        let other = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/other",
            &["note".to_string()],
        )
        .unwrap();
        assert!(authorize(&mut journal, other, Some("fixture-grant")));
        assert!(dispatch(&mut journal, other));
        assert_eq!(step_state(&journal, third), Some(StepState::Prepared));
        assert!(journal
            .steps
            .iter()
            .find(|step| step.id == third)
            .is_some_and(|step| step.grant.as_deref() == Some("fixture-grant")));
        assert!(dispatch(&mut journal, second));
        assert!(record_run_result(&mut journal, first, 0, "ok", ""));
        assert!(dispatch(&mut journal, third));
        assert!(record_run_result(&mut journal, third, 0, "ok", ""));
        let crashed = propose_run(&mut journal, project, &["note".to_string()]).unwrap();
        let waiting = propose_run(&mut journal, project, &["note".to_string()]).unwrap();
        assert!(authorize(&mut journal, crashed, Some("fixture-grant")));
        assert!(authorize(&mut journal, waiting, Some("fixture-grant")));
        assert!(dispatch(&mut journal, crashed));
        assert!(!dispatch(&mut journal, waiting));
        assert!(note_crash(&mut journal, crashed));
        assert!(!dispatch(&mut journal, waiting));
        assert_eq!(step_state(&journal, waiting), Some(StepState::Prepared));
        let ready = propose_run(
            &mut journal,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        let missing = propose_run(
            &mut journal,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::a_missing_piece_fails".to_string(),
            ],
        )
        .unwrap();
        let ready_again = propose_run(
            &mut journal,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        assert!(authorize(&mut journal, ready, Some("fixture-grant")));
        assert!(authorize(&mut journal, missing, Some("fixture-grant")));
        assert!(authorize(&mut journal, ready_again, Some("fixture-grant")));
        assert!(dispatch(&mut journal, ready));
        assert!(dispatch(&mut journal, missing));
        assert!(!dispatch(&mut journal, ready_again));
        assert_eq!(step_state(&journal, ready_again), Some(StepState::Prepared));
        let missing_again = propose_run(
            &mut journal,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::a_missing_piece_fails".to_string(),
            ],
        )
        .unwrap();
        assert!(record_run_result(
            &mut journal,
            ready,
            0,
            "test result: ok",
            ""
        ));
        assert!(dispatch(&mut journal, ready_again));
        assert!(journal.steps.iter().any(|step| {
            step.id == missing && step.state == StepState::Dispatched && !step.has_result
        }));
        assert!(authorize(
            &mut journal,
            missing_again,
            Some("fixture-grant")
        ));
        assert!(!dispatch(&mut journal, missing_again));
        assert_eq!(
            step_state(&journal, missing_again),
            Some(StepState::Prepared)
        );
        assert!(note_crash(&mut journal, missing));
        assert!(!record_run_result(
            &mut journal,
            missing,
            101,
            "test result: FAILED",
            ""
        ));
        assert!(!dispatch(&mut journal, missing_again));
        assert_eq!(
            step_state(&journal, missing),
            Some(StepState::SettlementUnknown)
        );
        assert_eq!(
            step_state(&journal, missing_again),
            Some(StepState::Prepared)
        );
        assert!(journal.steps.iter().any(|step| {
            step.id == ready_again && step.state == StepState::Dispatched && !step.has_result
        }));
        assert!(!note_crash(&mut journal, ready));
        assert!(journal
            .steps
            .iter()
            .any(|step| step.id == ready && step.has_result));
        let ready_third = propose_run(
            &mut journal,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        assert!(record_run_result(
            &mut journal,
            ready_again,
            0,
            "test result: ok",
            ""
        ));
        assert!(authorize(&mut journal, ready_third, Some("fixture-grant")));
        assert!(dispatch(&mut journal, ready_third));
        assert!(!dispatch(&mut journal, missing_again));
        assert_eq!(
            step_state(&journal, missing),
            Some(StepState::SettlementUnknown)
        );
        assert_eq!(
            step_state(&journal, missing_again),
            Some(StepState::Prepared)
        );
        assert!(journal
            .steps
            .iter()
            .any(|step| step.id == ready && step.has_result));
        assert!(journal
            .steps
            .iter()
            .any(|step| step.id == ready_again && step.has_result));
        assert!(journal
            .steps
            .iter()
            .any(|step| step.id == missing && !step.has_result));
        let missing_third = propose_run(
            &mut journal,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::a_missing_piece_fails".to_string(),
            ],
        )
        .unwrap();
        assert!(!cancel(&mut journal, missing));
        assert_eq!(
            step_state(&journal, missing),
            Some(StepState::SettlementUnknown)
        );
        assert!(cancel(&mut journal, missing_again));
        assert!(!dispatch(&mut journal, missing_again));
        assert_eq!(
            step_state(&journal, missing_again),
            Some(StepState::Cancelled)
        );
        assert!(authorize(
            &mut journal,
            missing_third,
            Some("fixture-grant")
        ));
        assert!(!dispatch(&mut journal, missing_third));
        assert_eq!(
            step_state(&journal, missing_third),
            Some(StepState::Prepared)
        );
        assert!(journal.steps.iter().any(|step| {
            step.id == ready_third && step.state == StepState::Dispatched && !step.has_result
        }));
        let elsewhere = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/other",
            &[
                "vm-smoke".to_string(),
                "tests::a_missing_piece_fails".to_string(),
            ],
        )
        .unwrap();
        assert!(authorize(&mut journal, elsewhere, Some("fixture-grant")));
        assert!(dispatch(&mut journal, elsewhere));
        assert!(record_run_result(
            &mut journal,
            elsewhere,
            101,
            "test result: FAILED",
            ""
        ));
        assert!(!dispatch(&mut journal, missing_third));
        assert_eq!(
            step_state(&journal, missing),
            Some(StepState::SettlementUnknown)
        );
        assert_eq!(
            step_state(&journal, missing_third),
            Some(StepState::Prepared)
        );
        assert!(journal.steps.iter().any(|step| {
            step.id == ready_third && step.state == StepState::Dispatched && !step.has_result
        }));
        assert!(journal
            .steps
            .iter()
            .any(|step| step.id == elsewhere && step.has_result));
        assert!(journal
            .steps
            .iter()
            .any(|step| step.id == missing && !step.has_result));
        let saved = model_bytes(&journal.events).unwrap();
        let resumed = replay(&saved).unwrap();
        assert!(!saved
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant"));
        assert!(resumed
            .iter()
            .any(|node| node.text == "exit 101\ntest result: FAILED\n"));
        let elsewhere_again = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/other",
            &[
                "vm-smoke".to_string(),
                "tests::a_missing_piece_fails".to_string(),
            ],
        )
        .unwrap();
        assert!(authorize(
            &mut journal,
            elsewhere_again,
            Some("fixture-grant")
        ));
        assert!(dispatch(&mut journal, elsewhere_again));
        assert!(!dispatch(&mut journal, missing_third));
        assert_eq!(
            step_state(&journal, missing),
            Some(StepState::SettlementUnknown)
        );
        assert_eq!(
            step_state(&journal, missing_third),
            Some(StepState::Prepared)
        );
        assert!(journal.steps.iter().any(|step| {
            step.id == ready_third && step.state == StepState::Dispatched && !step.has_result
        }));
        let elsewhere_third = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/other",
            &[
                "vm-smoke".to_string(),
                "tests::a_missing_piece_fails".to_string(),
            ],
        )
        .unwrap();
        assert!(note_crash(&mut journal, elsewhere_again));
        assert!(!record_run_result(
            &mut journal,
            elsewhere_again,
            101,
            "test result: FAILED",
            ""
        ));
        assert!(!cancel(&mut journal, elsewhere_again));
        assert_eq!(
            step_state(&journal, elsewhere_again),
            Some(StepState::SettlementUnknown)
        );
        assert!(authorize(
            &mut journal,
            elsewhere_third,
            Some("fixture-grant")
        ));
        assert!(!dispatch(&mut journal, elsewhere_third));
        assert_eq!(
            step_state(&journal, elsewhere_third),
            Some(StepState::Prepared)
        );
        assert_eq!(
            step_state(&journal, missing),
            Some(StepState::SettlementUnknown)
        );
        assert_eq!(
            step_state(&journal, missing_third),
            Some(StepState::Prepared)
        );
        assert!(journal.steps.iter().any(|step| {
            step.id == ready_third && step.state == StepState::Dispatched && !step.has_result
        }));
        assert!(journal
            .steps
            .iter()
            .any(|step| step.id == elsewhere && step.has_result));
        assert!(journal
            .events
            .iter()
            .any(|node| node.text == "exit 101\ntest result: FAILED\n"));
        let ready_fourth = propose_run(
            &mut journal,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        assert!(record_run_result(
            &mut journal,
            ready_third,
            0,
            "test result: ok",
            ""
        ));
        assert!(authorize(&mut journal, ready_fourth, Some("fixture-grant")));
        assert!(dispatch(&mut journal, ready_fourth));
        assert!(!dispatch(&mut journal, missing_third));
        assert!(!dispatch(&mut journal, elsewhere_third));
        assert_eq!(
            step_state(&journal, missing),
            Some(StepState::SettlementUnknown)
        );
        assert_eq!(
            step_state(&journal, elsewhere_again),
            Some(StepState::SettlementUnknown)
        );
        assert_eq!(
            step_state(&journal, missing_third),
            Some(StepState::Prepared)
        );
        assert_eq!(
            step_state(&journal, elsewhere_third),
            Some(StepState::Prepared)
        );
        assert!(journal
            .steps
            .iter()
            .any(|step| step.id == ready_third && step.has_result));
        assert!(journal
            .events
            .iter()
            .any(|node| node.text == "exit 0\ntest result: ok\n"));
        assert!(journal
            .events
            .iter()
            .any(|node| node.text == "exit 101\ntest result: FAILED\n"));
        let saved_both = model_bytes(&journal.events).unwrap();
        assert!(!saved_both
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant"));
        let demo_true = propose_run(&mut journal, project, &["true".to_string()]).unwrap();
        let other_true = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/other",
            &["true".to_string()],
        )
        .unwrap();
        let demo_true_again = propose_run(&mut journal, project, &["true".to_string()]).unwrap();
        assert!(authorize(&mut journal, demo_true, Some("fixture-grant")));
        assert!(authorize(&mut journal, other_true, Some("fixture-grant")));
        assert!(authorize(
            &mut journal,
            demo_true_again,
            Some("fixture-grant")
        ));
        assert!(dispatch(&mut journal, demo_true));
        assert!(!dispatch(&mut journal, demo_true_again));
        assert_eq!(
            step_state(&journal, demo_true_again),
            Some(StepState::Prepared)
        );
        assert!(dispatch(&mut journal, other_true));
        assert!(record_run_result(
            &mut journal,
            demo_true,
            0,
            "init: hello from vm smoke test",
            ""
        ));
        assert!(dispatch(&mut journal, demo_true_again));
        assert!(record_run_result(
            &mut journal,
            other_true,
            0,
            "init: hello from vm smoke test",
            ""
        ));
        assert!(!dispatch(&mut journal, missing_third));
        assert!(!dispatch(&mut journal, elsewhere_third));
        assert_eq!(
            step_state(&journal, missing),
            Some(StepState::SettlementUnknown)
        );
        assert_eq!(
            step_state(&journal, elsewhere_again),
            Some(StepState::SettlementUnknown)
        );
        assert_eq!(
            step_state(&journal, missing_third),
            Some(StepState::Prepared)
        );
        assert_eq!(
            step_state(&journal, elsewhere_third),
            Some(StepState::Prepared)
        );
        assert!(journal.steps.iter().any(|step| {
            step.id == ready_fourth && step.state == StepState::Dispatched && !step.has_result
        }));
        assert!(journal
            .events
            .iter()
            .any(|node| node.text == "exit 0\ninit: hello from vm smoke test\n"));
        assert!(journal
            .events
            .iter()
            .any(|node| node.text == "exit 0\ntest result: ok\n"));
        assert!(journal
            .events
            .iter()
            .any(|node| node.text == "exit 101\ntest result: FAILED\n"));
        let saved_hello = model_bytes(&journal.events).unwrap();
        assert!(!saved_hello
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant"));
        let demo_false = propose_run(&mut journal, project, &["false".to_string()]).unwrap();
        let other_false = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/other",
            &["false".to_string()],
        )
        .unwrap();
        let demo_false_again = propose_run(&mut journal, project, &["false".to_string()]).unwrap();
        assert!(authorize(&mut journal, demo_false, Some("fixture-grant")));
        assert!(authorize(&mut journal, other_false, Some("fixture-grant")));
        assert!(authorize(
            &mut journal,
            demo_false_again,
            Some("fixture-grant")
        ));
        assert!(dispatch(&mut journal, demo_false));
        assert!(!dispatch(&mut journal, demo_false_again));
        assert_eq!(
            step_state(&journal, demo_false_again),
            Some(StepState::Prepared)
        );
        assert!(dispatch(&mut journal, other_false));
        assert!(!record_run_result(
            &mut journal,
            demo_false,
            0,
            "init: hello from vm smoke test",
            ""
        ));
        assert!(!record_run_result(
            &mut journal,
            demo_true_again,
            1,
            "init: command failed",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            demo_false,
            1,
            "init: command failed",
            ""
        ));
        assert!(dispatch(&mut journal, demo_false_again));
        assert!(record_run_result(
            &mut journal,
            other_false,
            1,
            "init: command failed",
            ""
        ));
        assert!(!dispatch(&mut journal, missing_third));
        assert!(!dispatch(&mut journal, elsewhere_third));
        assert_eq!(
            step_state(&journal, missing),
            Some(StepState::SettlementUnknown)
        );
        assert_eq!(
            step_state(&journal, elsewhere_again),
            Some(StepState::SettlementUnknown)
        );
        assert_eq!(
            step_state(&journal, missing_third),
            Some(StepState::Prepared)
        );
        assert_eq!(
            step_state(&journal, elsewhere_third),
            Some(StepState::Prepared)
        );
        assert!(journal.steps.iter().any(|step| {
            step.id == ready_fourth && step.state == StepState::Dispatched && !step.has_result
        }));
        assert!(journal.steps.iter().any(|step| {
            step.id == demo_true_again && step.state == StepState::Dispatched && !step.has_result
        }));
        assert!(journal
            .events
            .iter()
            .any(|node| node.text == "exit 1\ninit: command failed\n"));
        assert!(journal
            .events
            .iter()
            .any(|node| node.text == "exit 0\ninit: hello from vm smoke test\n"));
        assert!(journal
            .events
            .iter()
            .any(|node| node.text == "exit 0\ntest result: ok\n"));
        assert!(journal
            .events
            .iter()
            .any(|node| node.text == "exit 101\ntest result: FAILED\n"));
        let saved_failed = model_bytes(&journal.events).unwrap();
        assert!(!saved_failed
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant"));
        let edited = propose_run(
            &mut journal,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_was_edited".to_string(),
            ],
        )
        .unwrap();
        let edited_again = propose_run(
            &mut journal,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_was_edited".to_string(),
            ],
        )
        .unwrap();
        assert!(authorize(&mut journal, edited, Some("fixture-grant")));
        assert!(authorize(&mut journal, edited_again, Some("fixture-grant")));
        assert!(dispatch(&mut journal, edited));
        assert!(!dispatch(&mut journal, edited_again));
        assert_eq!(
            step_state(&journal, edited_again),
            Some(StepState::Prepared)
        );
        assert!(!record_run_result(
            &mut journal,
            edited,
            0,
            "project note hello from the project\ntest result: ok",
            ""
        ));
        assert!(!record_run_result(
            &mut journal,
            ready_fourth,
            0,
            "project note hello from the project\ntest result: ok",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            edited,
            0,
            "test result: ok",
            ""
        ));
        assert!(dispatch(&mut journal, edited_again));
        assert!(!dispatch(&mut journal, missing_third));
        assert!(!dispatch(&mut journal, elsewhere_third));
        assert_eq!(
            step_state(&journal, missing),
            Some(StepState::SettlementUnknown)
        );
        assert_eq!(
            step_state(&journal, elsewhere_again),
            Some(StepState::SettlementUnknown)
        );
        assert_eq!(
            step_state(&journal, missing_third),
            Some(StepState::Prepared)
        );
        assert_eq!(
            step_state(&journal, elsewhere_third),
            Some(StepState::Prepared)
        );
        assert!(journal.steps.iter().any(|step| {
            step.id == ready_fourth && step.state == StepState::Dispatched && !step.has_result
        }));
        assert!(journal.steps.iter().any(|step| {
            step.id == demo_true_again && step.state == StepState::Dispatched && !step.has_result
        }));
        assert!(journal.steps.iter().any(|step| {
            step.id == demo_false_again && step.state == StepState::Dispatched && !step.has_result
        }));
        assert!(journal
            .steps
            .iter()
            .any(|step| step.id == edited && step.has_result));
        assert!(!journal
            .events
            .iter()
            .any(|node| node.text.contains("hello from the project")));
        let saved_edited = model_bytes(&journal.events).unwrap();
        assert!(!saved_edited
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant"));
        let notes = format!("{project}/notes.txt");
        assert!(observe(&mut journal, &notes, 1, "hello from the project"));
        assert!(!record_run_result(
            &mut journal,
            edited_again,
            0,
            "project note hello again\ntest result: ok",
            ""
        ));
        assert!(!record_run_result(
            &mut journal,
            edited_again,
            0,
            "project note /tmp/out\ntest result: ok",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            edited_again,
            0,
            "project note hello from the project\ntest result: ok",
            ""
        ));
        assert!(!dispatch(&mut journal, missing_third));
        assert!(!dispatch(&mut journal, elsewhere_third));
        assert_eq!(
            step_state(&journal, missing),
            Some(StepState::SettlementUnknown)
        );
        assert_eq!(
            step_state(&journal, missing_third),
            Some(StepState::Prepared)
        );
        assert!(journal.steps.iter().any(|step| {
            step.id == ready_fourth && step.state == StepState::Dispatched && !step.has_result
        }));
        assert!(journal
            .steps
            .iter()
            .any(|step| step.id == edited_again && step.has_result));
        assert_eq!(
            current_observed_text(&journal.events, &notes).as_deref(),
            Some("hello from the project")
        );
        assert!(journal.events.iter().any(|node| {
            node.text == "exit 0\nproject note hello from the project\ntest result: ok\n"
        }));
        assert!(!journal
            .events
            .iter()
            .any(|node| node.text.contains("hello again") || node.text.contains("/tmp")));
        let saved_note = model_bytes(&journal.events).unwrap();
        assert!(!saved_note
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant"));
        let files_again = propose_run(&mut journal, project, &["files".to_string()]).unwrap();
        let other_files = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/other",
            &["files".to_string()],
        )
        .unwrap();
        assert!(authorize(&mut journal, files_again, Some("fixture-grant")));
        assert!(authorize(&mut journal, other_files, Some("fixture-grant")));
        assert!(!dispatch(&mut journal, files_again));
        assert_eq!(step_state(&journal, files_again), Some(StepState::Prepared));
        assert!(dispatch(&mut journal, other_files));
        assert!(!record_run_result(
            &mut journal,
            second,
            0,
            "project file style.css",
            ""
        ));
        assert!(!record_run_result(
            &mut journal,
            second,
            0,
            "project file /tmp/out",
            ""
        ));
        assert!(!record_run_result(
            &mut journal,
            second,
            0,
            "project file notes.txt\nproject note hello from the project",
            ""
        ));
        assert!(!record_run_result(
            &mut journal,
            other_files,
            0,
            "project file notes.txt",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            second,
            0,
            "project file notes.txt",
            ""
        ));
        assert!(dispatch(&mut journal, files_again));
        assert!(!dispatch(&mut journal, missing_third));
        assert_eq!(
            step_state(&journal, missing),
            Some(StepState::SettlementUnknown)
        );
        assert_eq!(
            step_state(&journal, missing_third),
            Some(StepState::Prepared)
        );
        assert_eq!(step_state(&journal, waiting), Some(StepState::Prepared));
        assert!(journal.steps.iter().any(|step| {
            step.id == ready_fourth && step.state == StepState::Dispatched && !step.has_result
        }));
        assert!(journal.steps.iter().any(|step| {
            step.id == other && step.state == StepState::Dispatched && !step.has_result
        }));
        assert!(journal.steps.iter().any(|step| {
            step.id == other_files && step.state == StepState::Dispatched && !step.has_result
        }));
        assert!(journal
            .steps
            .iter()
            .any(|step| step.id == second && step.has_result));
        assert_eq!(
            current_observed_text(&journal.events, &notes).as_deref(),
            Some("hello from the project")
        );
        assert!(journal
            .events
            .iter()
            .any(|node| node.text == "exit 0\nproject file notes.txt\n"));
        assert!(!journal.events.iter().any(|node| {
            node.text.contains("style.css")
                || node.text.contains("/tmp")
                || node.text.contains("hello again")
        }));
        let saved_files = model_bytes(&journal.events).unwrap();
        assert!(!saved_files
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant"));
        let style = format!("{project}/style.css");
        assert!(observe(&mut journal, &style, 1, "body{}"));
        assert!(!record_run_result(
            &mut journal,
            files_again,
            0,
            "project file notes.txt",
            ""
        ));
        assert!(!record_run_result(
            &mut journal,
            files_again,
            0,
            "project file style.css",
            ""
        ));
        assert!(!record_run_result(
            &mut journal,
            files_again,
            0,
            "project file /tmp/out",
            ""
        ));
        assert!(!record_run_result(
            &mut journal,
            other_files,
            0,
            "project file notes.txt\nproject file style.css",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            files_again,
            0,
            "project file notes.txt\nproject file style.css",
            ""
        ));
        assert!(!dispatch(&mut journal, missing_third));
        assert_eq!(
            step_state(&journal, missing),
            Some(StepState::SettlementUnknown)
        );
        assert_eq!(
            step_state(&journal, missing_third),
            Some(StepState::Prepared)
        );
        assert!(journal.steps.iter().any(|step| {
            step.id == ready_fourth && step.state == StepState::Dispatched && !step.has_result
        }));
        assert!(journal.steps.iter().any(|step| {
            step.id == other_files && step.state == StepState::Dispatched && !step.has_result
        }));
        assert!(journal
            .steps
            .iter()
            .any(|step| step.id == files_again && step.has_result));
        assert_eq!(
            current_observed_text(&journal.events, &notes).as_deref(),
            Some("hello from the project")
        );
        assert_eq!(
            current_observed_text(&journal.events, &style).as_deref(),
            Some("body{}")
        );
        assert!(journal.events.iter().any(|node| {
            node.text == "exit 0\nproject file notes.txt\nproject file style.css\n"
        }));
        assert!(!journal
            .events
            .iter()
            .any(|node| node.text.contains("/tmp") || node.text.contains("hello again")));
        let saved_both_files = model_bytes(&journal.events).unwrap();
        assert!(!saved_both_files
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant"));
        let other_ready = propose_run(
            &mut journal,
            "localhost://Users/self/Projects/other",
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        assert!(authorize(&mut journal, other_ready, Some("fixture-grant")));
        assert!(dispatch(&mut journal, other_ready));
        assert!(!record_run_result(
            &mut journal,
            other_ready,
            0,
            "project demo f607cd5605c6829e1174580603daee9e7001676e56f4ab9b8dcd080349ca0c5b\ntest result: ok",
            ""
        ));
        assert!(!record_run_result(
            &mut journal,
            ready_fourth,
            0,
            "project demo 157af2e20c421bfaf3ac59d51f059bd9b8fb1cf2e40a2b45e8b898771ff938f5\ntest result: ok",
            ""
        ));
        assert!(!record_run_result(
            &mut journal,
            ready_fourth,
            0,
            "project demo a1097f0d6ed225ad16b19f19d6a260816af54c74bfe82b11e4ce2020233497f1\ntest result: ok",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            ready_fourth,
            0,
            "project demo f607cd5605c6829e1174580603daee9e7001676e56f4ab9b8dcd080349ca0c5b\ntest result: ok",
            ""
        ));
        assert!(!dispatch(&mut journal, missing_third));
        assert_eq!(
            step_state(&journal, missing),
            Some(StepState::SettlementUnknown)
        );
        assert_eq!(
            step_state(&journal, missing_third),
            Some(StepState::Prepared)
        );
        assert!(journal.steps.iter().any(|step| {
            step.id == other_ready && step.state == StepState::Dispatched && !step.has_result
        }));
        assert!(journal
            .steps
            .iter()
            .any(|step| step.id == ready_fourth && step.has_result));
        assert_eq!(
            current_observed_text(&journal.events, &notes).as_deref(),
            Some("hello from the project")
        );
        assert_eq!(
            current_observed_text(&journal.events, &style).as_deref(),
            Some("body{}")
        );
        assert!(journal.events.iter().any(|node| {
            node.text == "exit 0\nproject demo f607cd5605c6829e1174580603daee9e7001676e56f4ab9b8dcd080349ca0c5b\ntest result: ok\n"
        }));
        let saved_digest = model_bytes(&journal.events).unwrap();
        assert!(!saved_digest
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant"));
        let ready_fifth = propose_run(
            &mut journal,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        assert!(observe(&mut journal, &style, 2, "h1{}"));
        assert!(authorize(&mut journal, ready_fifth, Some("fixture-grant")));
        assert!(dispatch(&mut journal, ready_fifth));
        assert!(!record_run_result(
            &mut journal,
            ready_fifth,
            0,
            "project demo f607cd5605c6829e1174580603daee9e7001676e56f4ab9b8dcd080349ca0c5b\ntest result: ok",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            ready_fifth,
            0,
            "project demo d2cfc9d2f96f98ccb4eb283d6bb1ae49bb9ce7e3cdd7463eb190085ab6eedae1\ntest result: ok",
            ""
        ));
        assert!(!dispatch(&mut journal, missing_third));
        assert_eq!(
            step_state(&journal, missing),
            Some(StepState::SettlementUnknown)
        );
        assert_eq!(
            step_state(&journal, missing_third),
            Some(StepState::Prepared)
        );
        assert!(journal
            .steps
            .iter()
            .any(|step| step.id == ready_fifth && step.has_result));
        assert_eq!(
            current_observed_text(&journal.events, &notes).as_deref(),
            Some("hello from the project")
        );
        assert_eq!(
            current_observed_text(&journal.events, &style).as_deref(),
            Some("h1{}")
        );
        assert!(journal.events.iter().any(|node| {
            node.text == "exit 0\nproject demo d2cfc9d2f96f98ccb4eb283d6bb1ae49bb9ce7e3cdd7463eb190085ab6eedae1\ntest result: ok\n"
        }));
        let saved_style = model_bytes(&journal.events).unwrap();
        assert!(!saved_style
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant"));
        let files_after = propose_run(&mut journal, project, &["files".to_string()]).unwrap();
        assert!(authorize(&mut journal, files_after, Some("fixture-grant")));
        assert!(dispatch(&mut journal, files_after));
        assert!(!record_run_result(
            &mut journal,
            files_after,
            0,
            "project file notes.txt",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            files_after,
            0,
            "project file notes.txt\nproject file style.css",
            ""
        ));
        assert!(!dispatch(&mut journal, missing_third));
        assert_eq!(
            step_state(&journal, missing),
            Some(StepState::SettlementUnknown)
        );
        assert_eq!(
            current_observed_text(&journal.events, &style).as_deref(),
            Some("h1{}")
        );
        assert!(journal
            .steps
            .iter()
            .any(|step| step.id == files_after && step.has_result));
        let files_unread = propose_run(&mut journal, project, &["files".to_string()]).unwrap();
        assert!(authorize(&mut journal, files_unread, Some("fixture-grant")));
        assert!(dispatch(&mut journal, files_unread));
        assert!(!record_run_result(
            &mut journal,
            files_unread,
            0,
            "project file notes.txt\nproject file style.css\nproject file index.html",
            ""
        ));
        assert!(!record_run_result(
            &mut journal,
            other_files,
            0,
            "project file notes.txt\nproject file style.css",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            files_unread,
            0,
            "project file notes.txt\nproject file style.css",
            ""
        ));
        assert!(!dispatch(&mut journal, missing_third));
        assert_eq!(
            step_state(&journal, missing),
            Some(StepState::SettlementUnknown)
        );
        assert!(journal.steps.iter().any(|step| {
            step.id == other_files && step.state == StepState::Dispatched && !step.has_result
        }));
        assert!(journal
            .steps
            .iter()
            .any(|step| step.id == files_unread && step.has_result));
        assert_eq!(
            current_observed_text(&journal.events, &style).as_deref(),
            Some("h1{}")
        );
        assert!(!journal
            .events
            .iter()
            .any(|node| node.text.contains("index.html")));
        let page = format!("{project}/index.html");
        let files_page = propose_run(&mut journal, project, &["files".to_string()]).unwrap();
        let ready_page = propose_run(
            &mut journal,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        assert!(observe(&mut journal, &page, 1, "<h1>demo</h1>"));
        assert!(authorize(&mut journal, files_page, Some("fixture-grant")));
        assert!(authorize(&mut journal, ready_page, Some("fixture-grant")));
        assert!(dispatch(&mut journal, files_page));
        assert!(dispatch(&mut journal, ready_page));
        assert!(!record_run_result(
            &mut journal,
            files_page,
            0,
            "project file notes.txt\nproject file style.css",
            ""
        ));
        assert!(!record_run_result(
            &mut journal,
            other_files,
            0,
            "project file notes.txt\nproject file style.css\nproject file index.html",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            files_page,
            0,
            "project file notes.txt\nproject file style.css\nproject file index.html",
            ""
        ));
        assert!(!record_run_result(
            &mut journal,
            ready_page,
            0,
            "project demo d2cfc9d2f96f98ccb4eb283d6bb1ae49bb9ce7e3cdd7463eb190085ab6eedae1\ntest result: ok",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            ready_page,
            0,
            "project demo e618ccee1e4be1e381946ef2476120157c4002b8f75895ed0d4c63c54d4ce79a\ntest result: ok",
            ""
        ));
        assert!(!dispatch(&mut journal, missing_third));
        assert_eq!(
            step_state(&journal, missing),
            Some(StepState::SettlementUnknown)
        );
        assert!(journal.steps.iter().any(|step| {
            step.id == other_files && step.state == StepState::Dispatched && !step.has_result
        }));
        assert!(journal
            .steps
            .iter()
            .any(|step| step.id == files_page && step.has_result));
        assert!(journal
            .steps
            .iter()
            .any(|step| step.id == ready_page && step.has_result));
        assert_eq!(
            current_observed_text(&journal.events, &page).as_deref(),
            Some("<h1>demo</h1>")
        );
        assert_eq!(
            current_observed_text(&journal.events, &style).as_deref(),
            Some("h1{}")
        );
        assert_eq!(
            current_observed_text(&journal.events, &notes).as_deref(),
            Some("hello from the project")
        );
        let saved_page = model_bytes(&journal.events).unwrap();
        assert!(!saved_page
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant"));
        let ready_next = propose_run(
            &mut journal,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        let files_next = propose_run(&mut journal, project, &["files".to_string()]).unwrap();
        assert!(observe(&mut journal, &page, 2, "<h1>next</h1>"));
        assert!(authorize(&mut journal, ready_next, Some("fixture-grant")));
        assert!(authorize(&mut journal, files_next, Some("fixture-grant")));
        assert!(dispatch(&mut journal, ready_next));
        assert!(dispatch(&mut journal, files_next));
        assert!(!record_run_result(
            &mut journal,
            ready_next,
            0,
            "project demo e618ccee1e4be1e381946ef2476120157c4002b8f75895ed0d4c63c54d4ce79a\ntest result: ok",
            ""
        ));
        assert!(!record_run_result(
            &mut journal,
            files_next,
            0,
            "project file notes.txt\nproject file style.css",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            files_next,
            0,
            "project file notes.txt\nproject file style.css\nproject file index.html",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            ready_next,
            0,
            "project demo c96eb153a09434c8ed7149a8fd9044711a5215a20197f06179113a1b1530f761\ntest result: ok",
            ""
        ));
        assert!(!dispatch(&mut journal, missing_third));
        assert_eq!(
            step_state(&journal, missing),
            Some(StepState::SettlementUnknown)
        );
        assert_eq!(
            current_observed_text(&journal.events, &page).as_deref(),
            Some("<h1>next</h1>")
        );
        assert_eq!(
            current_observed_text(&journal.events, &notes).as_deref(),
            Some("hello from the project")
        );
        assert_eq!(
            current_observed_text(&journal.events, &style).as_deref(),
            Some("h1{}")
        );
        assert!(journal
            .steps
            .iter()
            .any(|step| step.id == ready_next && step.has_result));
        assert!(journal
            .steps
            .iter()
            .any(|step| step.id == files_next && step.has_result));
        let saved_next = model_bytes(&journal.events).unwrap();
        assert!(!saved_next
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant"));
        let ready_older = propose_run(
            &mut journal,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        assert!(!observe(&mut journal, &page, 2, "<h1>other</h1>"));
        assert_eq!(
            current_observed_text(&journal.events, &page).as_deref(),
            Some("<h1>next</h1>")
        );
        assert!(observe(&mut journal, &page, 1, "<h1>demo</h1>"));
        assert!(authorize(&mut journal, ready_older, Some("fixture-grant")));
        assert!(dispatch(&mut journal, ready_older));
        assert!(!record_run_result(
            &mut journal,
            ready_older,
            0,
            "project demo c96eb153a09434c8ed7149a8fd9044711a5215a20197f06179113a1b1530f761\ntest result: ok",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            ready_older,
            0,
            "project demo e618ccee1e4be1e381946ef2476120157c4002b8f75895ed0d4c63c54d4ce79a\ntest result: ok",
            ""
        ));
        assert!(!dispatch(&mut journal, missing_third));
        assert_eq!(
            step_state(&journal, missing),
            Some(StepState::SettlementUnknown)
        );
        assert_eq!(
            current_observed_text(&journal.events, &page).as_deref(),
            Some("<h1>demo</h1>")
        );
        assert_eq!(
            observed_text_at(&journal.events, &page, 2).as_deref(),
            Some("<h1>next</h1>")
        );
        assert_eq!(
            current_observed_text(&journal.events, &notes).as_deref(),
            Some("hello from the project")
        );
        assert!(journal
            .steps
            .iter()
            .any(|step| step.id == ready_older && step.has_result));
        let saved_older = model_bytes(&journal.events).unwrap();
        assert!(!saved_older
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant"));
        let resumed = replay(&saved_older).unwrap();
        assert_eq!(
            current_observed_text(&resumed, &page).as_deref(),
            Some("<h1>demo</h1>")
        );
        assert_eq!(
            observed_text_at(&resumed, &page, 2).as_deref(),
            Some("<h1>next</h1>")
        );
        assert_eq!(
            current_observed_text(&resumed, &notes).as_deref(),
            Some("hello from the project")
        );
        assert_eq!(
            current_observed_text(&resumed, &style).as_deref(),
            Some("h1{}")
        );
        let before_refusal = model_bytes(&journal.events).unwrap();
        assert!(!observe(&mut journal, "/tmp/page.html", 1, "<h1>no</h1>"));
        assert!(!observe(
            &mut journal,
            "localhost://Users/self/Projects/demo/../index.html",
            1,
            "<h1>no</h1>"
        ));
        assert!(!observe(
            &mut journal,
            "localhost://Users/self/Projects/demo/my page",
            1,
            "<h1>no</h1>"
        ));
        assert!(!observe(&mut journal, "", 1, "<h1>no</h1>"));
        assert_eq!(model_bytes(&journal.events).as_ref(), Some(&before_refusal));
        assert_eq!(
            current_observed_text(&journal.events, &page).as_deref(),
            Some("<h1>demo</h1>")
        );
        assert_eq!(
            observed_text_at(&journal.events, &page, 2).as_deref(),
            Some("<h1>next</h1>")
        );
        let files_clean = propose_run(&mut journal, project, &["files".to_string()]).unwrap();
        let ready_clean = propose_run(
            &mut journal,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        assert!(authorize(&mut journal, files_clean, Some("fixture-grant")));
        assert!(authorize(&mut journal, ready_clean, Some("fixture-grant")));
        assert!(dispatch(&mut journal, files_clean));
        assert!(dispatch(&mut journal, ready_clean));
        assert!(!record_run_result(
            &mut journal,
            files_clean,
            0,
            "project file /tmp/out",
            ""
        ));
        assert!(!record_run_result(
            &mut journal,
            files_clean,
            0,
            "project file notes.txt\nproject file style.css",
            ""
        ));
        assert!(!record_run_result(
            &mut journal,
            ready_clean,
            0,
            "project demo c96eb153a09434c8ed7149a8fd9044711a5215a20197f06179113a1b1530f761\ntest result: ok",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            files_clean,
            0,
            "project file notes.txt\nproject file style.css\nproject file index.html",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            ready_clean,
            0,
            "project demo e618ccee1e4be1e381946ef2476120157c4002b8f75895ed0d4c63c54d4ce79a\ntest result: ok",
            ""
        ));
        let before_compact = model_bytes(&journal.events).unwrap();
        assert!(!compact(&mut journal, COMPACTION_SUMMARY));
        assert!(!compact(&mut journal, "/tmp/summary"));
        assert_eq!(model_bytes(&journal.events).as_ref(), Some(&before_compact));
        assert!(!dispatch(&mut journal, missing_third));
        assert_eq!(
            step_state(&journal, missing),
            Some(StepState::SettlementUnknown)
        );
        assert_eq!(
            current_observed_text(&journal.events, &page).as_deref(),
            Some("<h1>demo</h1>")
        );
        assert_eq!(
            current_observed_text(&journal.events, &notes).as_deref(),
            Some("hello from the project")
        );
        assert_eq!(
            current_observed_text(&journal.events, &style).as_deref(),
            Some("h1{}")
        );
        let saved_clean = model_bytes(&journal.events).unwrap();
        let resumed_clean = replay(&saved_clean).unwrap();
        assert_eq!(
            current_observed_text(&resumed_clean, &page).as_deref(),
            Some("<h1>demo</h1>")
        );
        assert_eq!(
            observed_text_at(&resumed_clean, &page, 2).as_deref(),
            Some("<h1>next</h1>")
        );
        assert!(!saved_clean
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant"));
        assert!(!saved_clean
            .windows(b"/tmp".len())
            .any(|window| window == b"/tmp"));
        let epoch_before = journal.epoch;
        admit_system(&mut journal, SYSTEM_HEAD, false);
        assert_eq!(system_head(&journal.events), Some(SYSTEM_HEAD));
        assert!(journal
            .events
            .first()
            .is_some_and(|node| { node.role == Role::System && node.source == NodeSource::Head }));
        assert!(journal.epoch > epoch_before);
        assert!(compact(&mut journal, COMPACTION_SUMMARY));
        assert_eq!(system_head(&journal.events), Some(SYSTEM_HEAD));
        assert!(!compact(&mut journal, COMPACTION_SUMMARY));
        assert!(!compact(&mut journal, ""));
        assert!(!compact(&mut journal, "/tmp/summary"));
        assert_eq!(
            current_observed_text(&journal.events, &page).as_deref(),
            Some("<h1>demo</h1>")
        );
        assert_eq!(
            observed_text_at(&journal.events, &page, 2).as_deref(),
            Some("<h1>next</h1>")
        );
        assert_eq!(
            current_observed_text(&journal.events, &notes).as_deref(),
            Some("hello from the project")
        );
        assert_eq!(
            current_observed_text(&journal.events, &style).as_deref(),
            Some("h1{}")
        );
        assert_eq!(
            step_state(&journal, missing),
            Some(StepState::SettlementUnknown)
        );
        assert!(!dispatch(&mut journal, missing_third));
        let files_kept = propose_run(&mut journal, project, &["files".to_string()]).unwrap();
        let ready_kept = propose_run(
            &mut journal,
            project,
            &[
                "vm-smoke".to_string(),
                "tests::project_is_ready".to_string(),
            ],
        )
        .unwrap();
        assert!(authorize(&mut journal, files_kept, Some("fixture-grant")));
        assert!(authorize(&mut journal, ready_kept, Some("fixture-grant")));
        assert!(dispatch(&mut journal, files_kept));
        assert!(dispatch(&mut journal, ready_kept));
        assert!(!record_run_result(
            &mut journal,
            files_kept,
            0,
            "project file notes.txt\nproject file style.css",
            ""
        ));
        assert!(!record_run_result(
            &mut journal,
            ready_kept,
            0,
            "project demo c96eb153a09434c8ed7149a8fd9044711a5215a20197f06179113a1b1530f761\ntest result: ok",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            files_kept,
            0,
            "project file notes.txt\nproject file style.css\nproject file index.html",
            ""
        ));
        assert!(record_run_result(
            &mut journal,
            ready_kept,
            0,
            "project demo e618ccee1e4be1e381946ef2476120157c4002b8f75895ed0d4c63c54d4ce79a\ntest result: ok",
            ""
        ));
        let saved_short = model_bytes(&journal.events).unwrap();
        let resumed_short = replay(&saved_short).unwrap();
        assert_eq!(system_head(&resumed_short), Some(SYSTEM_HEAD));
        assert_eq!(
            current_observed_text(&resumed_short, &page).as_deref(),
            Some("<h1>demo</h1>")
        );
        assert_eq!(
            observed_text_at(&resumed_short, &page, 2).as_deref(),
            Some("<h1>next</h1>")
        );
        assert!(!saved_short
            .windows(b"fixture-grant".len())
            .any(|window| window == b"fixture-grant"));
        assert!(!saved_short
            .windows(b"/tmp".len())
            .any(|window| window == b"/tmp"));
        let epoch_for_list = journal.epoch;
        assert_eq!(
            version_list(&journal.events, &page),
            vec![
                (1, "<h1>demo</h1>".to_string()),
                (2, "<h1>next</h1>".to_string()),
            ]
        );
        assert!(version_list(&journal.events, "/tmp/page.html").is_empty());
        assert!(version_list(&journal.events, "").is_empty());
        let saved_versions = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("file-versions.json"),
        )
        .unwrap();
        assert_eq!(saved_versions, home_file_versions(&page));
        assert!(!saved_versions.contains("fixture-grant"));
        assert!(!saved_versions.contains("/tmp"));
        assert_eq!(journal.epoch, epoch_for_list);
        assert_eq!(propose_restore(&mut journal, &page, 2), Err("stale"));
        assert_eq!(
            current_observed_text(&journal.events, &page).as_deref(),
            Some("<h1>demo</h1>")
        );
        let restore = propose_restore(&mut journal, &page, 1).unwrap();
        assert!(journal.steps.iter().any(|step| {
            step.id == restore
                && step.kind == ProposalKind::Restore
                && step.new == "<h1>demo</h1>"
                && step.grant.is_none()
                && step.state == StepState::Prepared
        }));
        assert!(!dispatch(&mut journal, restore));
        assert_eq!(step_state(&journal, restore), Some(StepState::Denied));
        assert_eq!(
            current_observed_text(&journal.events, &page).as_deref(),
            Some("<h1>demo</h1>")
        );
        assert_eq!(
            observed_text_at(&journal.events, &page, 2).as_deref(),
            Some("<h1>next</h1>")
        );
        assert_eq!(
            step_state(&journal, missing),
            Some(StepState::SettlementUnknown)
        );
    }

    fn home_file_versions(resource: &str) -> String {
        format!(
            "{{\n  \"resource\": \"{resource}\",\n  \"observations\": [\n    {{\"resource\": \"{resource}\", \"version\": 1, \"text\": \"<h1>demo</h1>\"}},\n    {{\"resource\": \"{resource}\", \"version\": 2, \"text\": \"<h1>next</h1>\"}},\n    {{\"resource\": \"{resource}\", \"version\": 1, \"text\": \"<h1>demo</h1>\"}}\n  ]\n}}\n"
        )
    }

    #[test]
    fn a_model_sentence_shortens_the_log_and_replays() {
        let summary =
            "The person greeted, the page was read as a demo, and the test result was okay.";
        let mut journal = two_turns();
        let head = journal.events[0].text.clone();
        let before = model_bytes(&journal.events).unwrap();
        assert!(before.len() > summary.len());
        assert!(compact(&mut journal, summary));
        assert_eq!(journal.events[0].text, head);
        assert!(journal.events.iter().any(|node| node.text == summary));
        let saved = model_bytes(&journal.events).unwrap();
        assert!(saved.len() < before.len());
        assert_eq!(replay(&saved).unwrap(), journal.events);
    }

    #[test]
    fn a_large_tool_result_is_shortened_before_a_summary() {
        let mut journal = two_turns();
        let epoch = journal.epoch;
        let head = journal.events[0].text.clone();
        admit_tool_result(&mut journal, &"x".repeat(200));
        admit_tool_result(&mut journal, "ok");
        assert!(admit_skill(&mut journal, "Prefer the Runtime grant."));
        let before = shadowed_summary_input(&journal).unwrap();
        assert!(before.starts_with(SYSTEM_HEAD));
        assert!(before.contains(&"x".repeat(200)));
        assert!(!before.contains("Prefer the Runtime grant."));
        assert_eq!(prune_tool_results(&mut journal), 1);
        assert_eq!(journal.epoch, epoch);
        assert_eq!(journal.events[0].text, head);
        assert!(journal.events.iter().any(|node| {
            node.role == Role::ToolResult
                && node.text.ends_with('…')
                && node.text.chars().count() == 41
        }));
        assert!(journal
            .events
            .iter()
            .any(|node| node.role == Role::ToolResult && node.text == "ok"));
        assert!(journal
            .events
            .iter()
            .any(|node| node.text == "Prefer the Runtime grant."));
        let after = shadowed_summary_input(&journal).unwrap();
        assert!(after.starts_with(SYSTEM_HEAD));
        assert!(after.contains('…'));
        assert!(after.contains("ok"));
        assert!(!after.contains(&"x".repeat(200)));
        assert!(!after.contains("Prefer the Runtime grant."));
        assert!(journal
            .events
            .iter()
            .all(|node| node.text != COMPACTION_SUMMARY));
        assert!(!after.contains(COMPACTION_SUMMARY));
    }

    #[test]
    fn a_skill_replays_with_its_source() {
        let mut journal = two_turns();
        assert!(admit_skill(&mut journal, "Prefer the Runtime grant."));
        let recorded = model_bytes(&journal.events).unwrap();
        let restored = replay(&recorded).unwrap();
        assert_eq!(restored, journal.events);
        assert_eq!(restored.last().unwrap().source, NodeSource::Skill);
    }

    const WRITE_GRANT: &str = "fixture-journal-write-grant";
    const READ_GRANT: &str = "fixture-journal-read-grant";

    fn fake_revision(bytes: &[u8]) -> String {
        sha256(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// A stand-in for the Runtime bridge with its journal rules: one write
    /// grant and one read grant for one resource, a precondition on every
    /// write, a compare-and-swap, and the bridge's reply shapes. The bridge
    /// itself is tested in `resource_bridge.rs`.
    struct FakeRuntime {
        resource: String,
        stored: Option<Vec<u8>>,
        calls: Vec<(String, String)>,
        /// Store the write, then give no answer.
        lose_reply: bool,
        /// Give no answer and store nothing.
        drop_write: bool,
    }

    impl ResourceBus for FakeRuntime {
        fn invoke(
            &mut self,
            resource: &str,
            operation: &str,
            body: &[u8],
            grant: &str,
        ) -> Result<Vec<u8>, BusFailure> {
            self.calls.push((
                operation.to_string(),
                String::from_utf8_lossy(body).into_owned(),
            ));
            if resource != self.resource {
                return Err(BusFailure::Invalid);
            }
            let request: serde_json::Value =
                serde_json::from_slice(body).map_err(|_| BusFailure::Invalid)?;
            let reply = match operation {
                "write" => {
                    if grant != WRITE_GRANT {
                        return Err(BusFailure::Denied);
                    }
                    let content: Vec<u8> = serde_json::from_value(request["content"].clone())
                        .map_err(|_| BusFailure::Other)?;
                    let create_only = request["create_only"].as_bool().unwrap_or(false);
                    let if_revision = request["if_revision"].as_str();
                    if create_only == if_revision.is_some() {
                        return Err(BusFailure::Other);
                    }
                    if self.drop_write {
                        return Err(BusFailure::Other);
                    }
                    let current = self.stored.as_deref().map(fake_revision);
                    if current.as_deref() != if_revision {
                        serde_json::json!({ "status": "error", "code": "revision_conflict" })
                    } else {
                        let revision = fake_revision(&content);
                        let written = content.len();
                        self.stored = Some(content);
                        if self.lose_reply {
                            return Err(BusFailure::Other);
                        }
                        serde_json::json!({
                            "status": "ok",
                            "data": { "bytes_written": written, "revision": revision },
                        })
                    }
                }
                "read" => {
                    if grant != READ_GRANT {
                        return Err(BusFailure::Denied);
                    }
                    match &self.stored {
                        Some(bytes) => serde_json::json!({
                            "status": "ok",
                            "data": {
                                "content": bytes,
                                "size": bytes.len(),
                                "revision": fake_revision(bytes),
                            },
                        }),
                        None => serde_json::json!({ "status": "error", "code": "read_failed" }),
                    }
                }
                _ => return Err(BusFailure::Invalid),
            };
            Ok(reply.to_string().into_bytes())
        }
    }

    fn fake_runtime() -> (FakeRuntime, JournalCursor) {
        let cursor = journal_cursor("demo-agent", "task-1").unwrap();
        let runtime = FakeRuntime {
            resource: cursor.resource.clone(),
            stored: None,
            calls: Vec::new(),
            lose_reply: false,
            drop_write: false,
        };
        (runtime, cursor)
    }

    fn write_grant() -> LaunchGrant {
        LaunchGrant::new(WRITE_GRANT).unwrap()
    }

    fn read_grant() -> LaunchGrant {
        LaunchGrant::new(READ_GRANT).unwrap()
    }

    /// The journal as the guest sent it: the append step dispatched, with no
    /// result and no grant.
    fn as_sent(journal: &Journal, step_id: u64) -> Journal {
        let mut sent = without_grants(journal);
        let step = sent
            .steps
            .iter_mut()
            .find(|step| step.id == step_id)
            .unwrap();
        step.state = StepState::Dispatched;
        step.has_result = false;
        step.new.clear();
        sent
    }

    fn last_step(journal: &Journal) -> &Step {
        journal.steps.last().unwrap()
    }

    fn body(call: &(String, String)) -> serde_json::Value {
        serde_json::from_str(&call.1).unwrap()
    }

    #[test]
    fn a_journal_append_without_a_grant_sends_nothing() {
        let (mut runtime, mut cursor) = fake_runtime();
        let fresh = cursor.clone();
        let mut journal = two_turns();
        assert_eq!(
            append_journal(&mut runtime, &mut journal, &mut cursor, None),
            AppendOutcome::Denied
        );
        assert!(runtime.calls.is_empty());
        assert!(runtime.stored.is_none());
        assert_eq!(cursor, fresh);
        let step = last_step(&journal);
        assert_eq!(step.kind, ProposalKind::JournalAppend);
        assert_eq!(step.state, StepState::Denied);
        assert!(step.grant.is_none());
        assert!(LaunchGrant::new("").is_none());
    }

    #[test]
    fn the_first_append_creates_the_journal_and_the_next_names_its_revision() {
        let (mut runtime, mut cursor) = fake_runtime();
        let mut journal = two_turns();
        assert_eq!(
            append_journal(
                &mut runtime,
                &mut journal,
                &mut cursor,
                Some(&write_grant())
            ),
            AppendOutcome::Written
        );
        let first_id = last_step(&journal).id;
        let first = runtime.stored.clone().unwrap();
        let (back, prev, head) = decode_journal(&first).unwrap();
        assert_eq!(back, as_sent(&journal, first_id));
        assert_eq!(prev, [0; 32]);
        assert_eq!(cursor.head, head);
        assert_eq!(
            cursor.revision.as_deref(),
            Some(fake_revision(&first).as_str())
        );
        assert!(cursor.pending.is_none());
        assert_eq!(runtime.calls.len(), 1);
        assert_eq!(runtime.calls[0].0, "write");
        assert_eq!(body(&runtime.calls[0])["create_only"], true);
        assert!(body(&runtime.calls[0]).get("if_revision").is_none());
        let step = last_step(&journal);
        assert!(step.has_result);
        assert_eq!(step.new, "written");
        assert_eq!(step.old, "");

        admit_user(&mut journal, "third turn");
        assert_eq!(
            append_journal(
                &mut runtime,
                &mut journal,
                &mut cursor,
                Some(&write_grant())
            ),
            AppendOutcome::Written
        );
        assert_eq!(
            body(&runtime.calls[1])["if_revision"],
            fake_revision(&first).as_str()
        );
        assert!(body(&runtime.calls[1]).get("create_only").is_none());
        let second = runtime.stored.clone().unwrap();
        let (back, prev, _) = decode_journal(&second).unwrap();
        assert_eq!(prev, head);
        assert_eq!(back, as_sent(&journal, last_step(&journal).id));
        assert_eq!(last_step(&journal).old, fake_revision(&first));
    }

    #[test]
    fn a_stale_journal_revision_is_refused_and_nothing_is_written() {
        let (mut runtime, mut cursor) = fake_runtime();
        let mut journal = two_turns();
        assert_eq!(
            append_journal(
                &mut runtime,
                &mut journal,
                &mut cursor,
                Some(&write_grant())
            ),
            AppendOutcome::Written
        );
        let seen = cursor.clone();
        let mut other = two_turns();
        admit_user(&mut other, "another writer");
        let other_bytes = encode_journal(&other, &cursor.head).unwrap();
        runtime.stored = Some(other_bytes.clone());

        admit_user(&mut journal, "third turn");
        assert_eq!(
            append_journal(
                &mut runtime,
                &mut journal,
                &mut cursor,
                Some(&write_grant())
            ),
            AppendOutcome::Conflict
        );
        assert_eq!(runtime.stored.as_deref(), Some(other_bytes.as_slice()));
        assert_eq!(runtime.calls.len(), 2);
        assert_eq!(cursor, seen);
        let step = last_step(&journal);
        assert!(step.has_result);
        assert_eq!(step.new, "conflict");
    }

    #[test]
    fn a_crash_between_append_and_result_is_settlement_unknown_and_not_retried() {
        let (mut runtime, mut cursor) = fake_runtime();
        runtime.lose_reply = true;
        let mut journal = two_turns();
        assert_eq!(
            append_journal(
                &mut runtime,
                &mut journal,
                &mut cursor,
                Some(&write_grant())
            ),
            AppendOutcome::Unknown
        );
        let id = last_step(&journal).id;
        assert_eq!(step_state(&journal, id), Some(StepState::SettlementUnknown));
        assert!(!last_step(&journal).has_result);
        assert!(cursor.pending.is_some());
        assert_eq!(runtime.calls.len(), 1);

        runtime.lose_reply = false;
        admit_user(&mut journal, "third turn");
        let before = journal.clone();
        assert_eq!(
            append_journal(
                &mut runtime,
                &mut journal,
                &mut cursor,
                Some(&write_grant())
            ),
            AppendOutcome::Held
        );
        assert_eq!(journal, before);
        assert_eq!(propose_journal_append(&mut journal, &cursor), Err("held"));
        assert!(!dispatch(&mut journal, id));
        assert!(note_crash(&mut journal, id));
        assert_eq!(step_state(&journal, id), Some(StepState::SettlementUnknown));
        assert_eq!(runtime.calls.len(), 1);
    }

    #[test]
    fn resume_reads_back_the_same_bytes() {
        let (mut runtime, mut cursor) = fake_runtime();
        runtime.lose_reply = true;
        let mut journal = two_turns();
        assert_eq!(
            append_journal(
                &mut runtime,
                &mut journal,
                &mut cursor,
                Some(&write_grant())
            ),
            AppendOutcome::Unknown
        );
        let id = last_step(&journal).id;
        let sent = as_sent(&journal, id);
        assert_eq!(
            resume_journal(&mut runtime, &mut journal, &mut cursor, Some(&read_grant())),
            ResumeOutcome::Written
        );
        let stored = runtime.stored.clone().unwrap();
        let (back, prev, head) = decode_journal(&stored).unwrap();
        assert_eq!(back, sent);
        assert_eq!(prev, [0; 32]);
        assert_eq!(cursor.head, head);
        assert_eq!(
            cursor.revision.as_deref(),
            Some(fake_revision(&stored).as_str())
        );
        assert!(cursor.pending.is_none());
        assert_eq!(last_step(&journal).new, "written");
        assert_eq!(runtime.calls[1].0, "read");

        runtime.lose_reply = false;
        admit_user(&mut journal, "third turn");
        assert_eq!(
            append_journal(
                &mut runtime,
                &mut journal,
                &mut cursor,
                Some(&write_grant())
            ),
            AppendOutcome::Written
        );
        assert_eq!(
            body(&runtime.calls[2])["if_revision"],
            fake_revision(&stored).as_str()
        );
    }

    #[test]
    fn resume_on_the_parent_head_lets_the_append_be_proposed_again() {
        let (mut runtime, mut cursor) = fake_runtime();
        let mut journal = two_turns();
        assert_eq!(
            append_journal(
                &mut runtime,
                &mut journal,
                &mut cursor,
                Some(&write_grant())
            ),
            AppendOutcome::Written
        );
        let parent = cursor.clone();
        runtime.drop_write = true;
        admit_user(&mut journal, "third turn");
        assert_eq!(
            append_journal(
                &mut runtime,
                &mut journal,
                &mut cursor,
                Some(&write_grant())
            ),
            AppendOutcome::Unknown
        );
        assert_eq!(
            resume_journal(&mut runtime, &mut journal, &mut cursor, Some(&read_grant())),
            ResumeOutcome::NotWritten
        );
        assert_eq!(last_step(&journal).new, "not written");
        assert!(last_step(&journal).has_result);
        assert_eq!(cursor, parent);

        runtime.drop_write = false;
        assert_eq!(
            append_journal(
                &mut runtime,
                &mut journal,
                &mut cursor,
                Some(&write_grant())
            ),
            AppendOutcome::Written
        );
        let last = runtime.calls.last().unwrap();
        assert_eq!(body(last)["if_revision"], parent.revision.unwrap().as_str());
    }

    #[test]
    fn resume_on_another_head_stays_unknown_and_holds_appends() {
        let (mut runtime, mut cursor) = fake_runtime();
        let mut journal = two_turns();
        assert_eq!(
            append_journal(
                &mut runtime,
                &mut journal,
                &mut cursor,
                Some(&write_grant())
            ),
            AppendOutcome::Written
        );
        runtime.drop_write = true;
        admit_user(&mut journal, "third turn");
        assert_eq!(
            append_journal(
                &mut runtime,
                &mut journal,
                &mut cursor,
                Some(&write_grant())
            ),
            AppendOutcome::Unknown
        );
        let waiting = cursor.clone();
        let id = last_step(&journal).id;
        let mut other = two_turns();
        admit_user(&mut other, "another writer");
        runtime.stored = Some(encode_journal(&other, &cursor.head).unwrap());
        assert_eq!(
            resume_journal(&mut runtime, &mut journal, &mut cursor, Some(&read_grant())),
            ResumeOutcome::Unknown
        );
        let mut flipped = runtime.stored.clone().unwrap();
        flipped[JOURNAL_HEADER + 9] ^= 1;
        runtime.stored = Some(flipped);
        assert_eq!(
            resume_journal(&mut runtime, &mut journal, &mut cursor, Some(&read_grant())),
            ResumeOutcome::Unknown
        );
        assert_eq!(cursor, waiting);
        assert_eq!(step_state(&journal, id), Some(StepState::SettlementUnknown));
        assert!(!last_step(&journal).has_result);
        runtime.drop_write = false;
        assert_eq!(
            append_journal(
                &mut runtime,
                &mut journal,
                &mut cursor,
                Some(&write_grant())
            ),
            AppendOutcome::Held
        );
    }

    #[test]
    fn a_lost_first_append_with_nothing_stored_stays_unknown() {
        let (mut runtime, mut cursor) = fake_runtime();
        runtime.drop_write = true;
        let mut journal = two_turns();
        assert_eq!(
            append_journal(
                &mut runtime,
                &mut journal,
                &mut cursor,
                Some(&write_grant())
            ),
            AppendOutcome::Unknown
        );
        assert_eq!(
            resume_journal(&mut runtime, &mut journal, &mut cursor, Some(&read_grant())),
            ResumeOutcome::Unknown
        );
        assert!(cursor.pending.is_some());
    }

    #[test]
    fn resume_without_a_read_grant_sends_nothing() {
        let (mut runtime, mut cursor) = fake_runtime();
        runtime.lose_reply = true;
        let mut journal = two_turns();
        assert_eq!(
            append_journal(
                &mut runtime,
                &mut journal,
                &mut cursor,
                Some(&write_grant())
            ),
            AppendOutcome::Unknown
        );
        let waiting = cursor.clone();
        assert_eq!(
            resume_journal(&mut runtime, &mut journal, &mut cursor, None),
            ResumeOutcome::Denied
        );
        assert_eq!(runtime.calls.len(), 1);
        assert_eq!(
            resume_journal(
                &mut runtime,
                &mut journal,
                &mut cursor,
                Some(&write_grant())
            ),
            ResumeOutcome::Unknown
        );
        assert_eq!(cursor, waiting);
        let mut idle = journal_cursor("demo-agent", "task-2").unwrap();
        assert_eq!(
            resume_journal(&mut runtime, &mut journal, &mut idle, Some(&read_grant())),
            ResumeOutcome::Nothing
        );
        assert_eq!(runtime.calls.len(), 2);
    }

    #[test]
    fn a_refused_append_is_closed_and_not_sent_again() {
        let (mut runtime, mut cursor) = fake_runtime();
        let fresh = cursor.clone();
        let mut journal = two_turns();
        let other = LaunchGrant::new("fixture-another-tasks-grant").unwrap();
        assert_eq!(
            append_journal(&mut runtime, &mut journal, &mut cursor, Some(&other)),
            AppendOutcome::Refused
        );
        assert!(runtime.stored.is_none());
        assert_eq!(runtime.calls.len(), 1);
        assert_eq!(cursor, fresh);
        let step = last_step(&journal);
        assert!(step.has_result);
        assert_eq!(step.new, "refused");
    }

    #[test]
    fn an_append_over_the_cap_is_not_sent() {
        let (mut runtime, mut cursor) = fake_runtime();
        let fresh = cursor.clone();
        let mut journal = two_turns();
        admit_user(&mut journal, &"x".repeat(JOURNAL_CAP));
        assert_eq!(
            append_journal(
                &mut runtime,
                &mut journal,
                &mut cursor,
                Some(&write_grant())
            ),
            AppendOutcome::TooLarge
        );
        assert!(runtime.calls.is_empty());
        assert_eq!(cursor, fresh);
        assert_eq!(last_step(&journal).state, StepState::Cancelled);
    }

    #[test]
    fn a_journal_id_is_letters_digits_and_dashes() {
        assert_eq!(
            journal_resource("demo-agent", "task-1").unwrap(),
            "localhost://Users/self/.AppData/Agents/demo-agent/tasks/task-1/journal"
        );
        assert!(journal_resource("A9-", &"x".repeat(64)).is_ok());
        for bad in [
            "",
            &"x".repeat(65),
            "a/b",
            "..",
            "a b",
            "a.b",
            "\u{e9}",
            "a\\b",
            "self/../other",
        ] {
            assert_eq!(
                journal_resource(bad, "task-1"),
                Err("journal id"),
                "{bad:?}"
            );
            assert_eq!(
                journal_resource("demo-agent", bad),
                Err("journal id"),
                "{bad:?}"
            );
        }
        let (mut runtime, mut cursor) = fake_runtime();
        let mut journal = two_turns();
        for resource in [
            "localhost://Users/other/.AppData/Agents/demo-agent/tasks/task-1/journal",
            "localhost://Users/self/.AppData/Agents/../../Documents/journal",
            "/Users/sash/journal",
        ] {
            cursor.resource = resource.to_string();
            assert_eq!(
                propose_journal_append(&mut journal, &cursor),
                Err("host path")
            );
            assert_eq!(
                append_journal(
                    &mut runtime,
                    &mut journal,
                    &mut cursor,
                    Some(&write_grant())
                ),
                AppendOutcome::Held
            );
        }
        assert!(runtime.calls.is_empty());
        assert_eq!(journal, two_turns());
    }

    #[test]
    fn a_launch_grant_is_held_in_memory_only() {
        let grant = write_grant();
        assert!(!format!("{grant:?}").contains(WRITE_GRANT));
        let (mut runtime, mut cursor) = fake_runtime();
        let mut journal = two_turns();
        assert_eq!(
            append_journal(&mut runtime, &mut journal, &mut cursor, Some(&grant)),
            AppendOutcome::Written
        );
        let stored = runtime.stored.clone().unwrap();
        assert!(!stored
            .windows(WRITE_GRANT.len())
            .any(|window| window == WRITE_GRANT.as_bytes()));
        assert!(!runtime.calls[0].1.contains(WRITE_GRANT));
        let (back, _, _) = decode_journal(&stored).unwrap();
        assert!(back.steps.iter().all(|step| step.grant.is_none()));
    }

    /// The guest's request and reply shapes are the ones the bridge reads and
    /// writes. A rename on either side fails here.
    #[test]
    fn the_write_body_is_what_the_bridge_reads() {
        assert_eq!(
            journal_write_body(&[0, 255], None),
            br#"{"content":[0,255],"create_only":true}"#
        );
        assert_eq!(
            journal_write_body(&[7], Some("rev")),
            br#"{"content":[7],"if_revision":"rev"}"#
        );
        let bridge = include_str!("../../../elastos/crates/elastos-server/src/resource_bridge.rs");
        for text in [
            r#"request.get("content")"#,
            r#"request.get("create_only")"#,
            r#"request.get("if_revision")"#,
            r#""content": bytes,"#,
            r#""revision": revision,"#,
            r#""revision": crate::auth::principal_root_object_revision("#,
            r#""data": data,"#,
            r#""code": code,"#,
            r#"provider_error_result("revision_conflict""#,
        ] {
            assert!(bridge.contains(text), "{text}");
        }
        let host =
            include_str!("../../../elastos/crates/elastos-compute/src/providers/component.rs");
        assert!(host.contains("let body = serde_json::to_vec(&result)"));
    }

    /// Gives one fixed reply to every call, after the write it was asked for.
    struct ScriptedBus(Vec<u8>);

    impl ResourceBus for ScriptedBus {
        fn invoke(
            &mut self,
            _resource: &str,
            _operation: &str,
            _body: &[u8],
            _grant: &str,
        ) -> Result<Vec<u8>, BusFailure> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn only_an_ok_reply_with_a_revision_counts_as_written() {
        for reply in [
            r#"{"status":"ok","data":{"bytes_written":10}}"#,
            r#"{"status":"ok","data":{"bytes_written":10,"revision":""}}"#,
            r#"{"status":"ok"}"#,
            r#"{"status":"error","code":"write_failed"}"#,
            r#"{"status":"pending"}"#,
            "not json",
        ] {
            let mut bus = ScriptedBus(reply.as_bytes().to_vec());
            let mut cursor = journal_cursor("demo-agent", "task-1").unwrap();
            let mut journal = two_turns();
            assert_eq!(
                append_journal(&mut bus, &mut journal, &mut cursor, Some(&write_grant())),
                AppendOutcome::Unknown,
                "{reply}"
            );
            assert!(cursor.pending.is_some(), "{reply}");
            assert!(cursor.revision.is_none(), "{reply}");
            assert_eq!(last_step(&journal).state, StepState::SettlementUnknown);
        }
    }
}
